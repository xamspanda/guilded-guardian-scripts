"""
defense/detectors/gg_t1_authority.py

GG-T1 Leadership and Authority Control detectors.

Implements:
  GG-T1.1.1  Term Monotonicity Violation       (term rollback / churn)
  GG-T1.1.2  Quorum Evidence Divergence        (peer view disagreement)
  GG-T1.2.1  COA Presentation Drift            (local vs peer-majority)
  GG-T1.2.2  Endorsement Freshness Failure     (stale endorsement accepted)

Inputs:
  - TransmissionEvent stream filtered to election-family msgs (for term
    observations carried in payloads).
  - CoaSnapshot stream from the local election sampler.
  - Optional peer_views: dict[node_uuid, leader_uuid] derived from peer
    HTTP /status polls or from cross-node coa snapshots.

Why these are highest-confidence: every one of the five competition
attack scripts trips at least one of these. win_election.py uses
HIGH_TERM=99999 (T1.1.1), replace_election_socket.py forces a local
COA inconsistent with peers (T1.2.1), and any captured-then-replayed
COA past its expiration window (T1.2.2).

artifact_id:    gildedguardian-ctf-defense-gg-t1
created:        2026-04-13T16:00Z
last_modified:  2026-04-13T16:00Z
stale_after:    2026-04-27T00:00Z
"""
from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict
from typing import Iterable, Optional

from shared.events import CoaSnapshot, TransmissionEvent
from shared.findings import CRITICAL, HIGH, MEDIUM, Finding
from shared.transmission import (
    ELECTION_VOTE_REQUEST, ELECTION_VOTE_RESPONSE,
    ELECTION_ENDORSE_REQUEST, ELECTION_ENDORSE_RESPONSE,
)


# ---------- helpers ----------

def _parse_rfc3339(ts: str) -> Optional[dt.datetime]:
    if not ts:
        return None
    # Handle trailing Z; Python 3.11+ accepts it natively.
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return dt.datetime.fromisoformat(ts)
    except ValueError:
        return None


def _term_from_election_payload(ev: TransmissionEvent) -> Optional[int]:
    if ev.tx.msg_type not in (
        ELECTION_VOTE_REQUEST, ELECTION_VOTE_RESPONSE,
        ELECTION_ENDORSE_REQUEST, ELECTION_ENDORSE_RESPONSE,
    ):
        return None
    payload, _ = ev.tx.decode_payload()
    if not isinstance(payload, dict):
        return None
    t = payload.get("term")
    return int(t) if isinstance(t, int) else None


# ---------- GG-T1.1.1 Term Monotonicity Violation ----------

def detect_term_monotonicity_violation(
    events: Iterable[TransmissionEvent],
    *, max_jump: int = 10,
    leader_change_baseline_per_window: int = 3,
    window_seconds: float = 60.0,
) -> list[Finding]:
    """
    Scan election-family transmissions in observed-time order. Emit:
      - "term rollback" if any term value goes backward
      - "implausible term jump" if the delta exceeds max_jump
      - "election churn" if leader-claim changes per window exceed baseline
    """
    findings: list[Finding] = []
    ordered = sorted(
        (e for e in events if e.tx.is_election()),
        key=lambda e: e.observed_at,
    )

    prev_term: Optional[int] = None
    prev_event: Optional[TransmissionEvent] = None
    leader_changes_per_window: dict[int, set[str]] = defaultdict(set)

    for ev in ordered:
        term = _term_from_election_payload(ev)
        if term is None:
            continue

        if prev_term is not None:
            if term < prev_term:
                findings.append(Finding(
                    technique="GG-T1.1.1",
                    title="term rollback",
                    severity=HIGH,
                    detector="detect_term_monotonicity_violation",
                    evidence={
                        "prev_term": prev_term,
                        "curr_term": term,
                        "prev_source": prev_event.tx.source if prev_event else None,
                        "curr_source": ev.tx.source,
                    },
                    occurred_at=ev.observed_at,
                ))
            elif term - prev_term > max_jump:
                findings.append(Finding(
                    technique="GG-T1.1.1",
                    title="implausible term jump",
                    severity=HIGH,
                    detector="detect_term_monotonicity_violation",
                    evidence={
                        "prev_term": prev_term,
                        "curr_term": term,
                        "delta":     term - prev_term,
                        "max_jump":  max_jump,
                        "source":    ev.tx.source,
                    },
                    occurred_at=ev.observed_at,
                ))

        # Track leader claims per window for churn detection. Only
        # vote-request and endorse-request carry a "leader" field; we
        # use the source as a proxy for "node claiming leadership."
        bucket = int(ev.observed_at // window_seconds)
        if ev.tx.msg_type in (ELECTION_VOTE_REQUEST, ELECTION_ENDORSE_REQUEST):
            leader_changes_per_window[bucket].add(ev.tx.source)

        prev_term = term
        prev_event = ev

    for bucket, leaders in leader_changes_per_window.items():
        if len(leaders) > leader_change_baseline_per_window:
            findings.append(Finding(
                technique="GG-T1.1.1",
                title="election churn",
                severity=MEDIUM,
                detector="detect_term_monotonicity_violation",
                evidence={
                    "window_start_unix": bucket * window_seconds,
                    "distinct_claimants": sorted(leaders),
                    "baseline":           leader_change_baseline_per_window,
                },
                occurred_at=bucket * window_seconds,
            ))

    return findings


# ---------- GG-T1.1.2 Quorum Evidence Divergence ----------

def detect_quorum_evidence_divergence(
    peer_views: dict[str, Optional[str]],
    *, tolerated_fraction: float = 0.0,
) -> list[Finding]:
    """
    peer_views maps observing-node UUID -> the leader UUID it currently
    sees (or None). Emit if more than `tolerated_fraction` of nodes
    disagree with the modal leader claim.
    """
    if not peer_views:
        return []

    counts = Counter(peer_views.values())
    modal_leader, modal_count = counts.most_common(1)[0]
    disagreement = 1.0 - (modal_count / len(peer_views))
    if disagreement <= tolerated_fraction:
        return []

    dissenters = {n: ldr for n, ldr in peer_views.items() if ldr != modal_leader}
    return [Finding(
        technique="GG-T1.1.2",
        title="quorum evidence divergence",
        severity=HIGH,
        detector="detect_quorum_evidence_divergence",
        evidence={
            "modal_leader":      modal_leader,
            "modal_count":       modal_count,
            "total_nodes":       len(peer_views),
            "disagreement_rate": round(disagreement, 4),
            "dissenters":        dissenters,
        },
    )]


# ---------- GG-T1.2.1 COA Presentation Drift ----------

def detect_coa_presentation_drift(
    local_snap: CoaSnapshot,
    peer_leader_views: dict[str, Optional[str]],
) -> list[Finding]:
    """
    Compare locally presented leader against the peer-majority view.
    The local "leader claim" derives from the first endorsement's
    endorsee field; an empty endorsement list means "we are not leader."

    This is the signature trip for replace_election_socket.py: the
    fake socket presents endorsements that name us as endorsee, while
    the peer majority continues to see the real leader.
    """
    local_leader = local_snap.endorsements[0]["endorsee"] if local_snap.endorsements else None
    if not peer_leader_views:
        return []

    counts = Counter(peer_leader_views.values())
    peer_majority, _ = counts.most_common(1)[0]
    if local_leader == peer_majority:
        return []

    return [Finding(
        technique="GG-T1.2.1",
        title="COA presentation drift",
        severity=CRITICAL,
        detector="detect_coa_presentation_drift",
        evidence={
            "local_leader_claim": local_leader,
            "peer_majority":      peer_majority,
            "peer_views":         peer_leader_views,
            "local_endorsement_count": len(local_snap.endorsements),
        },
        occurred_at=local_snap.observed_at,
        node=local_snap.node,
    )]


# ---------- GG-T1.2.2 Endorsement Freshness Failure ----------

def detect_endorsement_freshness_failure(
    snaps: Iterable[CoaSnapshot],
    *, max_age_seconds: float = 30.0,
) -> list[Finding]:
    """
    Walk every endorsement in every snapshot; flag any whose expiration
    is in the past relative to the snapshot's observation time, or whose
    valid_after window has not yet started.

    The replay-attack primitive used in the combined takeover relies on
    keeping a captured COA alive past its window. If the implementation
    ever accepts an expired endorsement, this detector fires.
    """
    findings: list[Finding] = []
    for snap in snaps:
        observed = dt.datetime.fromtimestamp(snap.observed_at, tz=dt.timezone.utc)
        for e in snap.endorsements:
            exp = _parse_rfc3339(e.get("expiration", ""))
            valid_after = _parse_rfc3339(e.get("valid_after", ""))
            if exp is not None and exp < observed:
                age = (observed - exp).total_seconds()
                findings.append(Finding(
                    technique="GG-T1.2.2",
                    title="stale endorsement accepted",
                    severity=HIGH,
                    detector="detect_endorsement_freshness_failure",
                    evidence={
                        "endorser":      e.get("endorser"),
                        "endorsee":      e.get("endorsee"),
                        "expiration":    e.get("expiration"),
                        "observed_at":   observed.isoformat(),
                        "age_past_exp":  round(age, 3),
                        "max_age_seconds": max_age_seconds,
                    },
                    occurred_at=snap.observed_at,
                    node=snap.node,
                ))
            if valid_after is not None and valid_after > observed:
                findings.append(Finding(
                    technique="GG-T1.2.2",
                    title="endorsement accepted before valid_after",
                    severity=HIGH,
                    detector="detect_endorsement_freshness_failure",
                    evidence={
                        "endorser":     e.get("endorser"),
                        "endorsee":     e.get("endorsee"),
                        "valid_after":  e.get("valid_after"),
                        "observed_at":  observed.isoformat(),
                    },
                    occurred_at=snap.observed_at,
                    node=snap.node,
                ))
    return findings
