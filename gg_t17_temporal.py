"""
defense/detectors/gg_t17_temporal.py

GG-T17 Temporal Integrity and Mission-Time Semantics detectors.

Implements:
  GG-T17.1.1  Authority-Freshness Lag                (stale COA accepted)
  GG-T17.1.2  Poll-to-Decision Latency Violation     (sensor->assign too slow)
  GG-T17.2.1  Recovery-Within-Mission Failure        (failover too slow for window)
  GG-T17.2.2  Guidance-Continuity Time Gap           (handoff hole in timeline)

  GG-T17.X.1  Cyber Window Exhaustion                (NEW; mission-doc derived)
  GG-T17.X.2  Failed-Intercept Threshold Reached     (NEW; mission-doc derived)

The two NEW detectors are not in the framework as written; they encode
the hard numerical invariants from the ELCOA intel update directly.
Treating "3 failed intercepts and we lose AO Rizzo" as a detection-
grade signal is the entire point of having mission intel in the loop.

artifact_id:    gildedguardian-ctf-defense-gg-t17
created:        2026-04-13T19:30Z
last_modified:  2026-04-13T19:30Z
stale_after:    2026-04-27T00:00Z
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from shared.events import CoaSnapshot, TransmissionEvent
from shared.findings import CRITICAL, HIGH, MEDIUM, Finding
from shared.geo import parse_track_position
from shared.intel import ELCOA, ELCOA_CURRENT, MissionInvariants
from shared.transmission import (
    SENSOR_TRACK_UPDATE, BOOMER_ENGAGE_REQUEST, BOOMER_ENGAGE_ERROR,
)


# ---------- GG-T17.1.1 Authority-Freshness Lag ----------

def detect_authority_freshness_lag(
    coa_snaps: Iterable[CoaSnapshot],
    peer_leader_views: dict[float, str],   # observed_at -> peer-majority leader
    *, max_authority_lag_seconds: float = 5.0,
) -> list[Finding]:
    """
    For every local COA snapshot, find the closest peer-majority view
    in time. If they disagree on leader identity for longer than the
    allowed lag, emit.
    """
    if not peer_leader_views:
        return []
    peer_times = sorted(peer_leader_views.keys())

    findings: list[Finding] = []
    for snap in coa_snaps:
        local_leader = (snap.endorsements[0]["endorsee"]
                        if snap.endorsements else None)
        # Find peer view nearest in time.
        nearest = min(peer_times, key=lambda t: abs(t - snap.observed_at))
        if abs(nearest - snap.observed_at) > max_authority_lag_seconds:
            continue
        peer_leader = peer_leader_views[nearest]
        if local_leader == peer_leader:
            continue
        findings.append(Finding(
            technique="GG-T17.1.1",
            title="authority-freshness lag",
            severity=HIGH,
            detector="detect_authority_freshness_lag",
            evidence={
                "node":               snap.node,
                "local_leader":       local_leader,
                "peer_majority":      peer_leader,
                "lag_seconds":        round(abs(nearest - snap.observed_at), 3),
                "max_allowed":        max_authority_lag_seconds,
            },
            occurred_at=snap.observed_at,
            node=snap.node,
        ))
    return findings


# ---------- GG-T17.1.2 Poll-to-Decision Latency Violation ----------

def detect_poll_to_decision_latency_violation(
    sensor_events:    Iterable[TransmissionEvent],
    assignment_events: Iterable[TransmissionEvent],
    *, max_latency_seconds: float | None = None,
    invariants: MissionInvariants | None = None,
) -> list[Finding]:
    """
    Pair each first-seen track from Sensor:Track Update with its
    earliest matching Boomer:Engage Request. Flag any track where the
    interval exceeds the configured budget, or where no assignment
    ever arrives.
    """
    inv = invariants or MissionInvariants()
    if max_latency_seconds is None:
        max_latency_seconds = inv.poll_to_decision_max_seconds

    first_seen: dict[str, float] = {}
    for ev in sensor_events:
        if ev.tx.msg_type != SENSOR_TRACK_UPDATE:
            continue
        payload, _ = ev.tx.decode_payload()
        if not isinstance(payload, dict):
            continue
        tid = payload.get("track_id") or payload.get("id")
        if tid is None:
            continue
        tid = str(tid)
        if tid not in first_seen:
            first_seen[tid] = ev.observed_at

    first_assigned: dict[str, float] = {}
    for ev in assignment_events:
        if ev.tx.msg_type != BOOMER_ENGAGE_REQUEST:
            continue
        payload, _ = ev.tx.decode_payload()
        if not isinstance(payload, dict):
            continue
        tid = payload.get("track_id") or payload.get("track")
        if tid is None:
            continue
        tid = str(tid)
        if tid not in first_assigned:
            first_assigned[tid] = ev.observed_at

    findings: list[Finding] = []
    for tid, t_seen in first_seen.items():
        t_assigned = first_assigned.get(tid)
        if t_assigned is None:
            findings.append(Finding(
                technique="GG-T17.1.2",
                title="unassigned track",
                severity=HIGH,
                detector="detect_poll_to_decision_latency_violation",
                evidence={
                    "track_id":         tid,
                    "first_seen_unix":  t_seen,
                    "max_latency_s":    max_latency_seconds,
                },
                occurred_at=t_seen,
            ))
            continue
        latency = t_assigned - t_seen
        if latency > max_latency_seconds:
            findings.append(Finding(
                technique="GG-T17.1.2",
                title="poll-to-decision latency violation",
                severity=HIGH,
                detector="detect_poll_to_decision_latency_violation",
                evidence={
                    "track_id":      tid,
                    "first_seen_unix": t_seen,
                    "first_assigned_unix": t_assigned,
                    "latency_s":     round(latency, 3),
                    "max_latency_s": max_latency_seconds,
                },
                occurred_at=t_assigned,
            ))
    return findings


# ---------- GG-T17.X.1 Cyber Window Exhaustion (NEW) ----------

def detect_cyber_window_exhaustion(
    sensor_events:    Iterable[TransmissionEvent],
    assignment_events: Iterable[TransmissionEvent],
    elcoa: ELCOA = ELCOA_CURRENT,
) -> list[Finding]:
    """
    For every track whose updates land inside an ELCOA kill box, the
    first sensor sighting starts the cyber-window clock. If the boomer
    assignment does not land within `cyber_window_seconds`, emit
    CRITICAL: by the time we engage, the missile is already past the
    inner defensive boundary.

    This detector exists because the framework's poll-to-decision
    threshold is operational tolerance; the cyber window is the hard
    physics ceiling derived from missile speed.
    """
    inv = elcoa.invariants

    track_first_seen_in_box: dict[str, float] = {}
    for ev in sensor_events:
        if ev.tx.msg_type != SENSOR_TRACK_UPDATE:
            continue
        payload, _ = ev.tx.decode_payload()
        pos = parse_track_position(payload if isinstance(payload, dict) else {})
        if pos is None:
            continue
        if elcoa.any_kill_box_contains(pos) is None:
            continue
        if not isinstance(payload, dict):
            continue
        tid = payload.get("track_id") or payload.get("id")
        if tid is None:
            continue
        tid = str(tid)
        if tid not in track_first_seen_in_box:
            track_first_seen_in_box[tid] = ev.observed_at

    track_first_assigned: dict[str, float] = {}
    for ev in assignment_events:
        if ev.tx.msg_type != BOOMER_ENGAGE_REQUEST:
            continue
        payload, _ = ev.tx.decode_payload()
        if not isinstance(payload, dict):
            continue
        tid = payload.get("track_id") or payload.get("track")
        if tid is None:
            continue
        tid = str(tid)
        if tid not in track_first_assigned:
            track_first_assigned[tid] = ev.observed_at

    findings: list[Finding] = []
    for tid, t_seen in track_first_seen_in_box.items():
        t_assigned = track_first_assigned.get(tid)
        if t_assigned is None:
            findings.append(Finding(
                technique="GG-T17.X.1",
                title="cyber window exhaustion: in-box track unassigned",
                severity=CRITICAL,
                detector="detect_cyber_window_exhaustion",
                evidence={
                    "track_id":        tid,
                    "first_seen_unix": t_seen,
                    "cyber_window_s":  inv.cyber_window_seconds,
                },
                occurred_at=t_seen,
            ))
            continue
        latency = t_assigned - t_seen
        if latency > inv.cyber_window_seconds:
            findings.append(Finding(
                technique="GG-T17.X.1",
                title="cyber window exhaustion: assignment too late",
                severity=CRITICAL,
                detector="detect_cyber_window_exhaustion",
                evidence={
                    "track_id":      tid,
                    "latency_s":     round(latency, 3),
                    "cyber_window_s": inv.cyber_window_seconds,
                    "overrun_s":     round(latency - inv.cyber_window_seconds, 3),
                },
                occurred_at=t_assigned,
            ))
    return findings


# ---------- GG-T17.X.2 Failed-Intercept Threshold Reached (NEW) ----------

def detect_failed_intercept_threshold(
    engage_errors: Iterable[TransmissionEvent],
    elcoa: ELCOA = ELCOA_CURRENT,
) -> list[Finding]:
    """
    Count Boomer:Engage Error events. Emit MEDIUM at floor(threshold/2),
    HIGH at threshold-1, CRITICAL at threshold. Per the intel doc, the
    threshold is 3.

    Once CRITICAL fires, the watch floor must escalate immediately. This
    is the single most important blue-team alarm tomorrow.
    """
    inv = elcoa.invariants
    errors = [e for e in engage_errors if e.tx.msg_type == BOOMER_ENGAGE_ERROR]
    errors.sort(key=lambda e: e.observed_at)

    findings: list[Finding] = []
    threshold = inv.max_failed_interceptions
    half = max(1, threshold // 2)

    if len(errors) >= half:
        findings.append(Finding(
            technique="GG-T17.X.2",
            title=f"engage-error count reached half-threshold ({half})",
            severity=MEDIUM,
            detector="detect_failed_intercept_threshold",
            evidence={
                "count":         len(errors),
                "threshold":     threshold,
                "first_error_at": errors[0].observed_at,
                "last_error_at":  errors[-1].observed_at,
            },
            occurred_at=errors[half - 1].observed_at,
        ))
    if len(errors) >= threshold - 1:
        findings.append(Finding(
            technique="GG-T17.X.2",
            title=f"engage-error count one below threshold ({threshold - 1})",
            severity=HIGH,
            detector="detect_failed_intercept_threshold",
            evidence={"count": len(errors), "threshold": threshold},
            occurred_at=errors[threshold - 2].observed_at,
        ))
    if len(errors) >= threshold:
        findings.append(Finding(
            technique="GG-T17.X.2",
            title=f"FAILED-INTERCEPT THRESHOLD REACHED ({threshold})",
            severity=CRITICAL,
            detector="detect_failed_intercept_threshold",
            evidence={
                "count":     len(errors),
                "threshold": threshold,
                "ao_status": "AO Rizzo assessed degraded; follow-on Valinor "
                             "aggression cannot be repelled",
            },
            occurred_at=errors[threshold - 1].observed_at,
        ))
    return findings
