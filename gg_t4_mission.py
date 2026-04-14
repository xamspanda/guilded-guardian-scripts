"""
defense/detectors/gg_t4_mission.py

GG-T4 Mission Logic and Targeting Integrity detectors.

Implements:
  GG-T4.1.1  Orphan Track Update                (track update without prior registration)
  GG-T4.1.2  Mission-Box Plausibility Violation (track outside any ELCOA kill box)
  GG-T4.2.1  Non-Geodesic Assignment Divergence (squared euclid vs haversine)
  GG-T4.2.2  Assignment Churn                   (track-to-boomer thrash)

Inputs:
  - TransmissionEvent stream filtered to sensor and boomer families.
  - shared.intel.ELCOA_CURRENT for kill-box geometry.

The GG-T4.1.2 detector is the headline mission-aware finding for the
competition. Any track admitted by control whose position is outside
all three ELCOA kill boxes is either a sensor error, a spoof, or a
distractor; in all three cases it warrants immediate analyst attention.

artifact_id:    gildedguardian-ctf-defense-gg-t4
created:        2026-04-13T19:15Z
last_modified:  2026-04-13T19:15Z
stale_after:    2026-04-27T00:00Z
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from shared.events import TransmissionEvent
from shared.findings import CRITICAL, HIGH, MEDIUM, LOW, Finding
from shared.geo import (
    GeoPoint, haversine_km, parse_track_position,
    closest_kill_box,
)
from shared.intel import ELCOA, ELCOA_CURRENT
from shared.transmission import (
    SENSOR_GET_TASKS, SENSOR_TRACK_UPDATE, SENSOR_TRACK_REQUEST,
    SENSOR_TRACK_RESPONSE, BOOMER_ENGAGE_REQUEST,
)


# ---------- GG-T4.1.1 Orphan Track Update ----------

def detect_orphan_track_update(
    events: Iterable[TransmissionEvent],
) -> list[Finding]:
    """
    A Sensor:Track Update arriving from a sensor that never registered
    via Sensor:Get Tasks. Implementation: sweep the stream in time
    order; remember every sensor that emits a Get Tasks; flag any
    Track Update from a sensor not in the registry.
    """
    findings: list[Finding] = []
    registry: set[str] = set()
    ordered = sorted(events, key=lambda e: e.observed_at)
    for ev in ordered:
        if ev.tx.msg_type == SENSOR_GET_TASKS:
            registry.add(ev.tx.source)
            continue
        if ev.tx.msg_type != SENSOR_TRACK_UPDATE:
            continue
        if ev.tx.source in registry:
            continue
        findings.append(Finding(
            technique="GG-T4.1.1",
            title="orphan track update",
            severity=HIGH,
            detector="detect_orphan_track_update",
            evidence={
                "sensor":      ev.tx.source,
                "destination": ev.tx.destination,
                "registered_sensors": sorted(registry),
            },
            occurred_at=ev.observed_at,
        ))
    return findings


# ---------- GG-T4.1.2 Mission-Box Plausibility Violation ----------

def detect_mission_box_plausibility_violation(
    events: Iterable[TransmissionEvent],
    elcoa: ELCOA = ELCOA_CURRENT,
) -> list[Finding]:
    """
    Walk every Sensor:Track Update; decode the position payload; if the
    position is outside every ELCOA kill box, emit a finding.

    Severity ladder:
      - position inside any kill box  ->  no finding (expected)
      - within 50 km of any kill box  ->  MEDIUM (track may yet enter box)
      - 50 - 200 km from nearest box  ->  HIGH   (off-axis sensor noise)
      - > 200 km from nearest box     ->  CRITICAL (likely spoof)
    """
    findings: list[Finding] = []
    boxes = elcoa.all_kill_boxes()
    for ev in events:
        if ev.tx.msg_type != SENSOR_TRACK_UPDATE:
            continue
        payload, perr = ev.tx.decode_payload()
        pos = parse_track_position(payload)
        if pos is None:
            continue
        hit = elcoa.any_kill_box_contains(pos)
        if hit is not None:
            continue
        nearest_box, distance = closest_kill_box(pos, boxes)
        if distance < 50.0:
            sev = MEDIUM
        elif distance < 200.0:
            sev = HIGH
        else:
            sev = CRITICAL
        findings.append(Finding(
            technique="GG-T4.1.2",
            title="out-of-box telemetry",
            severity=sev,
            detector="detect_mission_box_plausibility_violation",
            evidence={
                "sensor":            ev.tx.source,
                "track_lat":         pos.lat,
                "track_lon":         pos.lon,
                "distance_km_to_nearest_box": round(distance, 2),
                "nearest_box_centre_lat":     nearest_box.centre.lat,
                "nearest_box_centre_lon":     nearest_box.centre.lon,
            },
            occurred_at=ev.observed_at,
        ))
    return findings


# ---------- GG-T4.2.1 Non-Geodesic Assignment Divergence ----------

def _squared_euclid(a: GeoPoint, b: GeoPoint) -> float:
    """Naive degree-space squared Euclidean. The "wrong" metric on Earth."""
    return (a.lat - b.lat) ** 2 + (a.lon - b.lon) ** 2


def detect_non_geodesic_assignment_divergence(
    tracks:  dict[str, GeoPoint],          # track_id -> position
    boomers: dict[str, GeoPoint],          # boomer_id -> position
    actual_assignment: dict[str, str],     # track_id -> boomer_id (control's choice)
    *, divergence_threshold: float = 0.25,
) -> list[Finding]:
    """
    Compare control's actual assignment (assumed to use squared Euclidean
    in lat/lon space, per the source-range Controller.md observation)
    against a haversine-optimal greedy assignment. Emit if the fraction
    of tracks that would be assigned differently exceeds the threshold.
    """
    if not tracks or not boomers:
        return []

    geodesic_assignment: dict[str, str] = {}
    available = dict(boomers)
    for tid, tpos in tracks.items():
        if not available:
            break
        chosen = min(available.items(), key=lambda kv: haversine_km(tpos, kv[1]))
        geodesic_assignment[tid] = chosen[0]
        del available[chosen[0]]

    differing = sum(
        1 for tid in tracks
        if (tid in actual_assignment
            and tid in geodesic_assignment
            and actual_assignment[tid] != geodesic_assignment[tid])
    )
    total = sum(1 for tid in tracks if tid in actual_assignment)
    if total == 0:
        return []
    ratio = differing / total
    if ratio < divergence_threshold:
        return []
    return [Finding(
        technique="GG-T4.2.1",
        title="assignment metric fragility",
        severity=MEDIUM,
        detector="detect_non_geodesic_assignment_divergence",
        evidence={
            "differing_assignments": differing,
            "total_assignments":     total,
            "divergence_ratio":      round(ratio, 4),
            "threshold":             divergence_threshold,
        },
    )]


# ---------- GG-T4.2.2 Assignment Churn ----------

def detect_assignment_churn(
    engage_events: Iterable[TransmissionEvent],
    *, window_seconds: float = 30.0,
    reassignments_threshold: int = 2,
) -> list[Finding]:
    """
    Boomer:Engage Request payloads carry the (track_id, boomer_id) pair.
    Count distinct (track_id -> boomer_id) transitions per track over
    the rolling window. Threshold > 2 reassignments inside the window
    is a churn finding.
    """
    findings: list[Finding] = []
    by_track: dict[str, list[tuple[float, str]]] = defaultdict(list)

    for ev in engage_events:
        if ev.tx.msg_type != BOOMER_ENGAGE_REQUEST:
            continue
        payload, _ = ev.tx.decode_payload()
        if not isinstance(payload, dict):
            continue
        tid = payload.get("track_id") or payload.get("track")
        bid = payload.get("boomer_id") or ev.tx.destination
        if tid is None or bid is None:
            continue
        by_track[str(tid)].append((ev.observed_at, str(bid)))

    for tid, hits in by_track.items():
        hits.sort()
        i = 0
        for j in range(1, len(hits)):
            while hits[j][0] - hits[i][0] > window_seconds:
                i += 1
            distinct_boomers = len({b for _, b in hits[i:j+1]})
            if distinct_boomers - 1 >= reassignments_threshold:
                findings.append(Finding(
                    technique="GG-T4.2.2",
                    title="assignment churn",
                    severity=MEDIUM,
                    detector="detect_assignment_churn",
                    evidence={
                        "track_id":    tid,
                        "reassignments": distinct_boomers - 1,
                        "window_s":    window_seconds,
                        "boomers":     sorted({b for _, b in hits[i:j+1]}),
                        "first_at":    hits[i][0],
                        "last_at":     hits[j][0],
                    },
                    occurred_at=hits[j][0],
                ))
                # Advance past this window to avoid double-reporting.
                i = j + 1
                if i >= len(hits):
                    break
    return findings
