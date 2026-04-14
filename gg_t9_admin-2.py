"""
defense/detectors/gg_t9_admin.py

GG-T9 Administrative Message and Safety Semantics detectors.

Implements:
  GG-T9.1.1  Administrative Message Without Elevated Authorization
  GG-T9.1.2  Empty-Payload Destructive Action
  GG-T9.2.1  Administrative Queue Burst
  GG-T9.2.2  Safety-Critical Poll Return without secondary confirmation

This module is the single most important defensive surface for the
competition. The kill_swarm.py script trips every one of these
detectors. If GG-T9.1.2 fires and the response is to drop the message,
the swarm survives.

Inputs:
  - TransmissionEvent stream (live tap or replay).
  - policy: ElevatedAuthPolicy describing what "elevated" means for
    administrative msg types. Default: requires non-empty payload AND
    a quorum-sized authority object (>= ceil(N_controllers / 2) + 1
    endorsements when controller count is known).
  - confirmation_log: optional callable returning True iff a given
    delivery has a matching out-of-band confirmation. Default returns
    False (no confirmations exist), so every poll-returned admin trips
    GG-T9.2.2.

artifact_id:    gildedguardian-ctf-defense-gg-t9
created:        2026-04-13T16:30Z
last_modified:  2026-04-13T16:30Z
stale_after:    2026-04-27T00:00Z
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from shared.events import TransmissionEvent
from shared.findings import CRITICAL, HIGH, Finding
from shared.transmission import (
    ADMIN_TYPES,
    DESTRUCTIVE_TYPES,
)


@dataclass
class ElevatedAuthPolicy:
    """
    What it means for an administrative message to carry "elevated
    authorization." For the Gilded Guardian protocol:
      - quorum_endorsements: minimum endorsement count to count as
        elevated (default 0 means ANY endorsements; set to ceil(N/2)+1
        for stricter regimes).
      - require_signed: if True, the msg_sig field must be non-empty.
      - require_nonce: if True, the nonce field must be non-empty.
      - require_non_empty_payload: if True, msg must decode to a
        non-empty object.
    """
    quorum_endorsements: int  = 1
    require_signed: bool      = True
    require_nonce: bool       = False
    require_non_empty_payload: bool = True


def has_elevated_authorization(ev: TransmissionEvent, policy: ElevatedAuthPolicy) -> tuple[bool, list[str]]:
    fails: list[str] = []
    if len(ev.tx.authority.endorsements) < policy.quorum_endorsements:
        fails.append(
            f"endorsements={len(ev.tx.authority.endorsements)} "
            f"< required={policy.quorum_endorsements}"
        )
    if policy.require_signed and not ev.tx.msg_sig:
        fails.append("msg_sig missing")
    if policy.require_nonce and not ev.tx.nonce:
        fails.append("nonce missing")
    if policy.require_non_empty_payload:
        payload, err = ev.tx.decode_payload()
        if err is not None or payload in (None, {}, "", []):
            fails.append("payload empty or undecodable")
    return (len(fails) == 0, fails)


# ---------- GG-T9.1.1 Weak Administrative Authorization ----------

def detect_weak_administrative_authorization(
    events: Iterable[TransmissionEvent],
    policy: ElevatedAuthPolicy | None = None,
) -> list[Finding]:
    pol = policy or ElevatedAuthPolicy()
    findings: list[Finding] = []
    for ev in events:
        if ev.tx.msg_type not in ADMIN_TYPES:
            continue
        ok, fails = has_elevated_authorization(ev, pol)
        if ok:
            continue
        findings.append(Finding(
            technique="GG-T9.1.1",
            title="administrative action lacks elevated authorization",
            severity=CRITICAL if ev.tx.msg_type in DESTRUCTIVE_TYPES else HIGH,
            detector="detect_weak_administrative_authorization",
            evidence={
                "msg_type":     ev.tx.msg_type,
                "source":       ev.tx.source,
                "destination":  ev.tx.destination,
                "endorsements": len(ev.tx.authority.endorsements),
                "msg_sig_present": bool(ev.tx.msg_sig),
                "policy_failures": fails,
            },
            occurred_at=ev.observed_at,
        ))
    return findings


# ---------- GG-T9.1.2 Empty-Payload Destructive Action ----------

def _is_empty_object(msg: str) -> bool:
    """True iff msg decodes (raw or base64) to an empty object."""
    if msg in ("", "{}"):
        return True
    # Try base64({}). binascii.Error covers malformed input; ValueError covers
    # non-ASCII. We explicitly swallow those because is_empty_object is a
    # best-effort heuristic.
    import base64
    import binascii
    import contextlib
    with contextlib.suppress(binascii.Error, ValueError):
        if base64.b64decode(msg, validate=True) == b"{}":
            return True
    return False


def detect_empty_payload_destructive_action(
    events: Iterable[TransmissionEvent],
) -> list[Finding]:
    """
    Direct match for kill_swarm.py. Any Shutdown (or any other
    destructive type added later) carrying an empty {} payload, in
    either base64 or raw form, gets flagged CRITICAL.
    """
    findings: list[Finding] = []
    for ev in events:
        if ev.tx.msg_type not in DESTRUCTIVE_TYPES:
            continue
        if not _is_empty_object(ev.tx.msg):
            continue
        findings.append(Finding(
            technique="GG-T9.1.2",
            title="destructive action with empty payload",
            severity=CRITICAL,
            detector="detect_empty_payload_destructive_action",
            evidence={
                "msg_type":    ev.tx.msg_type,
                "source":      ev.tx.source,
                "destination": ev.tx.destination,
                "msg_raw":     ev.tx.msg[:64],
                "endorsements": len(ev.tx.authority.endorsements),
            },
            occurred_at=ev.observed_at,
        ))
    return findings


# ---------- GG-T9.2.1 Administrative Queue Burst ----------

def detect_administrative_queue_burst(
    events: Iterable[TransmissionEvent],
    *, window_seconds: float = 5.0,
    threshold: int = 3,
) -> list[Finding]:
    """
    Bucket admin-typed events by source over rolling windows. Any
    source that issues more than `threshold` admin messages in any
    window gets flagged.

    kill_swarm.py issues one Shutdown per worker in a tight loop; with
    a 21-worker swarm and 5-second windows, threshold=3 catches it
    immediately.
    """
    findings: list[Finding] = []
    by_source: dict[str, list[TransmissionEvent]] = defaultdict(list)
    for ev in events:
        if ev.tx.msg_type in ADMIN_TYPES:
            by_source[ev.tx.source].append(ev)

    for src, evs in by_source.items():
        evs.sort(key=lambda e: e.observed_at)
        # Sliding window
        i = 0
        for j in range(len(evs)):
            while evs[j].observed_at - evs[i].observed_at > window_seconds:
                i += 1
            count = j - i + 1
            if count > threshold:
                findings.append(Finding(
                    technique="GG-T9.2.1",
                    title="administrative queue burst",
                    severity=CRITICAL,
                    detector="detect_administrative_queue_burst",
                    evidence={
                        "source":      src,
                        "count":       count,
                        "window_s":    window_seconds,
                        "threshold":   threshold,
                        "first_at":    evs[i].observed_at,
                        "last_at":     evs[j].observed_at,
                        "msg_types":   sorted({e.tx.msg_type for e in evs[i:j+1]}),
                        "destinations": sorted({e.tx.destination for e in evs[i:j+1]})[:10],
                    },
                    occurred_at=evs[j].observed_at,
                ))
                # Don't double-count overlapping windows; advance to
                # next non-overlap.
                i = j + 1
                if i >= len(evs):
                    break
    return findings


# ---------- GG-T9.2.2 Safety-Critical Poll Return ----------

def detect_unsafe_poll_returned_admin(
    deliveries: Iterable[TransmissionEvent],
    confirmation_log: Callable[[TransmissionEvent], bool] | None = None,
) -> list[Finding]:
    """
    Every administrative-typed delivery that lacks a matching
    out-of-band confirmation. Default policy: there are no
    confirmations, so every poll-returned admin trips this.

    The "delivery" stream is the worker-facing side of the comms
    socket: the moment a Shutdown is dequeued and handed back as a
    poll response. In a controller-side replay, a TransmissionEvent
    where direction == "egress" and destination is a worker is the
    same observation.
    """
    confirm = confirmation_log or (lambda _ev: False)
    findings: list[Finding] = []
    for ev in deliveries:
        if ev.tx.msg_type not in ADMIN_TYPES:
            continue
        if confirm(ev):
            continue
        findings.append(Finding(
            technique="GG-T9.2.2",
            title="unsafe poll-returned administrative action",
            severity=HIGH,
            detector="detect_unsafe_poll_returned_admin",
            evidence={
                "msg_type":     ev.tx.msg_type,
                "worker_id":    ev.tx.destination,
                "source":       ev.tx.source,
                "secondary_confirmation": False,
            },
            occurred_at=ev.observed_at,
        ))
    return findings
