"""
defense/detectors/gg_t3_polling.py

GG-T3 Worker Polling and Mailbox Semantics detectors.

Implements:
  GG-T3.1.1  Sensor Cadence Divergence          (poll interval vs expected)
  GG-T3.1.2  Boomer Cadence Divergence
  GG-T3.2.1  Delayed Delivery Anomaly           (enqueue-to-deliver > max)
  GG-T3.2.2  Queue Loss on Restart              (messages dropped across restart)

Inputs:
  - TransmissionEvent stream for Sensor:Get Tasks / Boomer:Get Tasks
    and the corresponding response/enqueue events.
  - Optional StateSnapshot pair for restart-diff of queue_ids.

Cadence defaults match the source-range observation of ~1 Hz polling;
competition-specific values should be passed explicitly via argument.

artifact_id:    gildedguardian-ctf-defense-gg-t3
created:        2026-04-13T23:00Z
last_modified:  2026-04-13T23:00Z
stale_after:    2026-04-27T00:00Z
"""
from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Iterable
from itertools import pairwise

from shared.events import StateSnapshot, TransmissionEvent
from shared.findings import HIGH, MEDIUM, Finding
from shared.transmission import (
    BOOMER_ENGAGE_REQUEST,
    BOOMER_GET_TASKS,
    SENSOR_GET_TASKS,
    SENSOR_TRACK_UPDATE,
)

# ---------- cadence helpers ----------

def _intervals(timestamps: list[float]) -> list[float]:
    if len(timestamps) < 2:
        return []
    s = sorted(timestamps)
    return [b - a for a, b in pairwise(s)]


def _is_periodic(intervals: list[float],
                 expected_period: float,
                 tolerance: float) -> tuple[bool, dict]:
    """
    Returns (is_periodic, stats). A poll stream is periodic when the
    mean interval is within `tolerance` of the expected period AND the
    coefficient of variation stays below 0.5 (half the mean).
    """
    if not intervals:
        return True, {"sample_count": 0}
    mean = statistics.fmean(intervals)
    stdev = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
    cv = (stdev / mean) if mean > 0 else float("inf")
    drift = abs(mean - expected_period)
    ok = drift <= tolerance and cv < 0.5
    return ok, {
        "sample_count": len(intervals),
        "mean_s":       round(mean,  4),
        "stdev_s":      round(stdev, 4),
        "cv":           round(cv,    4),
        "drift_s":      round(drift, 4),
        "expected_s":   expected_period,
        "tolerance_s":  tolerance,
    }


# ---------- GG-T3.1.1 Sensor Cadence Divergence ----------

def detect_sensor_cadence_divergence(
    events: Iterable[TransmissionEvent],
    *, location_period_s: float = 1.0,
    track_period_s: float = 0.5,
    tolerance_s: float = 0.5,
) -> list[Finding]:
    """
    Per-sensor rhythm check. Sensors are expected to emit Get Tasks at
    the location period and Track Updates at the track period. Either
    stream drifting outside tolerance fires.
    """
    by_sensor_get:   dict[str, list[float]] = defaultdict(list)
    by_sensor_track: dict[str, list[float]] = defaultdict(list)
    for ev in events:
        if ev.tx.msg_type == SENSOR_GET_TASKS:
            by_sensor_get[ev.tx.source].append(ev.observed_at)
        elif ev.tx.msg_type == SENSOR_TRACK_UPDATE:
            by_sensor_track[ev.tx.source].append(ev.observed_at)

    findings: list[Finding] = []
    all_sensors = set(by_sensor_get) | set(by_sensor_track)
    for sensor in sorted(all_sensors):
        for (stream_name, stream, period) in (
            ("location_updates", by_sensor_get.get(sensor, []),   location_period_s),
            ("track_updates",    by_sensor_track.get(sensor, []), track_period_s),
        ):
            ivs = _intervals(stream)
            if len(ivs) < 3:
                continue   # too few samples to assert divergence
            ok, stats = _is_periodic(ivs, period, tolerance_s)
            if ok:
                continue
            findings.append(Finding(
                technique="GG-T3.1.1",
                title=f"sensor {stream_name} cadence divergence",
                severity=MEDIUM,
                detector="detect_sensor_cadence_divergence",
                evidence={"sensor": sensor, "stream": stream_name, **stats},
                occurred_at=stream[-1] if stream else 0.0,
            ))
    return findings


# ---------- GG-T3.1.2 Boomer Cadence Divergence ----------

def detect_boomer_cadence_divergence(
    events: Iterable[TransmissionEvent],
    *, task_period_s: float = 1.0,
    tolerance_s: float = 0.5,
) -> list[Finding]:
    by_boomer: dict[str, list[float]] = defaultdict(list)
    for ev in events:
        if ev.tx.msg_type == BOOMER_GET_TASKS:
            by_boomer[ev.tx.source].append(ev.observed_at)

    findings: list[Finding] = []
    for boomer, stream in sorted(by_boomer.items()):
        ivs = _intervals(stream)
        if len(ivs) < 3:
            continue
        ok, stats = _is_periodic(ivs, task_period_s, tolerance_s)
        if ok:
            continue
        findings.append(Finding(
            technique="GG-T3.1.2",
            title="boomer polling divergence",
            severity=MEDIUM,
            detector="detect_boomer_cadence_divergence",
            evidence={"boomer": boomer, **stats},
            occurred_at=stream[-1] if stream else 0.0,
        ))
    return findings


# ---------- GG-T3.2.1 Delayed Delivery Anomaly ----------

def detect_delayed_delivery(
    enqueue_events: Iterable[TransmissionEvent],
    delivery_events: Iterable[TransmissionEvent],
    *, max_latency_s: float = 2.0,
) -> list[Finding]:
    """
    Pair every enqueue (controller-side Boomer:Engage Request) with its
    earliest downstream delivery on the boomer side. Late or missing
    deliveries emit findings.

    Matching rule: (destination_uuid, track_id) pair. Uses track_id from
    the Engage Request payload. A delivery on the worker side is the
    same message observed with direction="egress" or on the worker
    side of a socket tap. In a single-host tap, we match on the
    envelope's (destination, msg_type, track_id) tuple appearing on both
    sides of the queue boundary.
    """
    enq_index: dict[tuple[str, str], float] = {}
    for ev in enqueue_events:
        if ev.tx.msg_type != BOOMER_ENGAGE_REQUEST:
            continue
        payload, _ = ev.tx.decode_payload()
        if not isinstance(payload, dict):
            continue
        tid = payload.get("track_id") or payload.get("track")
        if tid is None:
            continue
        key = (ev.tx.destination, str(tid))
        if key not in enq_index:
            enq_index[key] = ev.observed_at

    deliv_index: dict[tuple[str, str], float] = {}
    for ev in delivery_events:
        if ev.tx.msg_type != BOOMER_ENGAGE_REQUEST:
            continue
        payload, _ = ev.tx.decode_payload()
        if not isinstance(payload, dict):
            continue
        tid = payload.get("track_id") or payload.get("track")
        if tid is None:
            continue
        key = (ev.tx.destination, str(tid))
        if key in enq_index and key not in deliv_index:
            deliv_index[key] = ev.observed_at

    findings: list[Finding] = []
    for key, t_enq in enq_index.items():
        t_del = deliv_index.get(key)
        dst, tid = key
        if t_del is None:
            findings.append(Finding(
                technique="GG-T3.2.1",
                title="undelivered queued task",
                severity=HIGH,
                detector="detect_delayed_delivery",
                evidence={
                    "destination": dst,
                    "track_id":    tid,
                    "enqueued_at": t_enq,
                    "max_latency_s": max_latency_s,
                },
                occurred_at=t_enq,
            ))
            continue
        latency = t_del - t_enq
        if latency > max_latency_s:
            findings.append(Finding(
                technique="GG-T3.2.1",
                title="late task delivery",
                severity=MEDIUM,
                detector="detect_delayed_delivery",
                evidence={
                    "destination": dst,
                    "track_id":    tid,
                    "enqueued_at": t_enq,
                    "delivered_at": t_del,
                    "latency_s":   round(latency, 3),
                    "max_latency_s": max_latency_s,
                },
                occurred_at=t_del,
            ))
    return findings


# ---------- GG-T3.2.2 Queue Loss on Restart ----------

def detect_queue_loss_on_restart(
    pre:  StateSnapshot,
    post: StateSnapshot,
) -> list[Finding]:
    """
    Set difference of queue_ids across a restart. Any message ID present
    pre-restart and missing post-restart is counted as lost.
    """
    pre_set  = set(pre.queue_ids or [])
    post_set = set(post.queue_ids or [])
    lost = sorted(pre_set - post_set)
    if not lost:
        return []
    return [Finding(
        technique="GG-T3.2.2",
        title="queue loss on restart",
        severity=HIGH,
        detector="detect_queue_loss_on_restart",
        evidence={
            "node":       pre.node,
            "lost_count": len(lost),
            "lost_ids":   lost[:20],
            "pre_count":  len(pre_set),
            "post_count": len(post_set),
        },
        node=pre.node,
        occurred_at=post.observed_at,
    )]
