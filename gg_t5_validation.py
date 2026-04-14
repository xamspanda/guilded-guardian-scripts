"""
defense/detectors/gg_t5_validation.py

GG-T5 Message Validation and Identity Assurance detectors.

Implements:
  GG-T5.1.1  Validation Policy Inconsistency   (paths use different rules)
  GG-T5.1.2  UUID-Only Identity Acceptance     (identity = config UUID, no binding)
  GG-T5.2.1  Payload-Encoding Anomaly          (msg encoding != expected for type)
  GG-T5.2.2  Envelope-Authority Mismatch       (claimed src/dst/type vs authority)

Inputs:
  - TransmissionEvent stream (live or replayed).
  - ConfigSnapshot per node (for verify_signatures policy comparison).
  - authority_rules: predicate or rule table that defines which
    (source, destination, msg_type, authority) combinations are valid.

Competition trip-wires:
  - kill_swarm.py sends Shutdown with both base64({}) and raw {} to be
    safe: GG-T5.2.1 fires on whichever encoding the implementation
    does not natively expect.
  - Any node with verify_signatures: false in a cluster where peers
    have it true: GG-T5.1.1.
  - Any Shutdown whose authority field carries endorsements that name
    a different endorsee than the source: GG-T5.2.2.

artifact_id:    gildedguardian-ctf-defense-gg-t5
created:        2026-04-13T16:15Z
last_modified:  2026-04-13T16:15Z
stale_after:    2026-04-27T00:00Z
"""
from __future__ import annotations

import base64
import binascii
import json
from typing import Callable, Iterable, Optional

from shared.events import ConfigSnapshot, TransmissionEvent
from shared.findings import HIGH, MEDIUM, LOW, Finding
from shared.transmission import ELECTION_TYPES


# ---------- GG-T5.1.1 Validation Policy Inconsistency ----------

def detect_validation_policy_inconsistency(
    snapshots: Iterable[ConfigSnapshot],
) -> list[Finding]:
    """
    Compare verify_signatures across the controller plane (and across
    workers within a swarm). Any node out of step with the modal value
    is flagged. The reference rule: in a swarm with verify_signatures:
    true, a single node with verify_signatures: false is the entire
    failure class.
    """
    rules: dict[str, list[ConfigSnapshot]] = {}
    for s in snapshots:
        v = s.raw.get("verify_signatures")
        key = "true" if v is True else "false" if v is False else "absent"
        rules.setdefault(key, []).append(s)

    if len(rules) <= 1:
        return []

    modal_key = max(rules, key=lambda k: len(rules[k]))
    findings: list[Finding] = []
    for key, snaps in rules.items():
        if key == modal_key:
            continue
        for s in snaps:
            findings.append(Finding(
                technique="GG-T5.1.1",
                title="validation policy inconsistency",
                severity=HIGH,
                detector="detect_validation_policy_inconsistency",
                evidence={
                    "node":               s.node,
                    "role":               s.role,
                    "verify_signatures":  s.raw.get("verify_signatures"),
                    "modal_value":        modal_key,
                    "modal_node_count":   len(rules[modal_key]),
                },
                occurred_at=s.observed_at,
                node=s.node,
            ))
    return findings


# ---------- GG-T5.1.2 UUID-Only Identity Acceptance ----------

def detect_uuid_only_identity_acceptance(
    events: Iterable[TransmissionEvent],
) -> list[Finding]:
    """
    A transmission whose only identity proof is the source UUID in the
    envelope (no msg_sig, no nonce, and no peer cred binding). The Go
    Transmission.Validate() method is intentionally lenient here, so
    detection is observational.

    Heuristic: ingress events with empty msg_sig AND empty nonce on a
    socket where SO_PEERCRED produced no pid (i.e., crossed a
    network-mediated path before reaching us) get flagged.
    """
    findings: list[Finding] = []
    for ev in events:
        if ev.direction != "ingress":
            continue
        if ev.tx.msg_sig:
            continue
        if ev.tx.nonce:
            continue
        if ev.pid is not None:
            # Local writer; covered by GG-T2.x detectors
            continue
        findings.append(Finding(
            technique="GG-T5.1.2",
            title="weak identity binding",
            severity=MEDIUM,
            detector="detect_uuid_only_identity_acceptance",
            evidence={
                "source":   ev.tx.source,
                "msg_type": ev.tx.msg_type,
                "binding":  "uuid_config_only",
            },
            occurred_at=ev.observed_at,
        ))
    return findings


# ---------- GG-T5.2.1 Payload-Encoding Anomaly ----------

def _looks_base64(s: str) -> bool:
    """True iff s decodes as strict base64 to non-empty bytes."""
    if not s:
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def _is_raw_json(s: str) -> bool:
    if not s:
        return False
    try:
        json.loads(s)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def detect_payload_encoding_anomaly(
    events: Iterable[TransmissionEvent],
) -> list[Finding]:
    """
    Election traffic: msg MUST decode as base64 -> JSON.
    Non-election traffic (sensor / boomer / Shutdown): msg MUST be raw
    JSON.

    Either-side asymmetry is the GG-T5.2.1 finding. The kill_swarm.py
    "Round 2" raw {} payload is detected here when the implementation
    expects base64; the "Round 1" base64({}) is flagged when the
    implementation expects raw.

    For Shutdown specifically: the canonical encoding is raw "{}". Any
    base64-wrapped Shutdown payload is suspect because the only known
    sender that does that is the attack script.
    """
    findings: list[Finding] = []
    for ev in events:
        msg = ev.tx.msg
        is_election = ev.tx.is_election()

        if is_election:
            # expect base64(JSON)
            if not _looks_base64(msg):
                findings.append(Finding(
                    technique="GG-T5.2.1",
                    title="payload encoding anomaly: election msg not base64",
                    severity=HIGH,
                    detector="detect_payload_encoding_anomaly",
                    evidence={
                        "msg_type":    ev.tx.msg_type,
                        "source":      ev.tx.source,
                        "destination": ev.tx.destination,
                        "msg_prefix":  msg[:64],
                    },
                    occurred_at=ev.observed_at,
                ))
                continue
            # decode and re-check inner is JSON
            try:
                inner = base64.b64decode(msg, validate=True).decode("utf-8")
                if not _is_raw_json(inner):
                    findings.append(Finding(
                        technique="GG-T5.2.1",
                        title="payload encoding anomaly: election inner not JSON",
                        severity=MEDIUM,
                        detector="detect_payload_encoding_anomaly",
                        evidence={
                            "msg_type":   ev.tx.msg_type,
                            "inner_prefix": inner[:64],
                        },
                        occurred_at=ev.observed_at,
                    ))
            except (binascii.Error, UnicodeDecodeError):
                pass

        else:
            # expect raw JSON
            if not _is_raw_json(msg):
                # If it looks like base64 of a JSON, that's the
                # offensive encoding-confusion case.
                base64_jsonish = False
                if _looks_base64(msg):
                    try:
                        inner = base64.b64decode(msg, validate=True).decode("utf-8")
                        base64_jsonish = _is_raw_json(inner)
                    except (binascii.Error, UnicodeDecodeError):
                        pass
                findings.append(Finding(
                    technique="GG-T5.2.1",
                    title="payload encoding anomaly: non-election msg not raw JSON",
                    severity=HIGH if base64_jsonish else MEDIUM,
                    detector="detect_payload_encoding_anomaly",
                    evidence={
                        "msg_type":         ev.tx.msg_type,
                        "source":           ev.tx.source,
                        "destination":      ev.tx.destination,
                        "looks_base64":     _looks_base64(msg),
                        "base64_wraps_json": base64_jsonish,
                        "msg_prefix":       msg[:64],
                    },
                    occurred_at=ev.observed_at,
                ))
    return findings


# ---------- GG-T5.2.2 Envelope-Authority Mismatch ----------

# Default rule: for any non-election transmission carrying authority
# endorsements, the source UUID MUST equal the endorsee in every
# endorsement. (The leader sends; the leader is named by the COA.)
def _default_authority_consistency(
    source: str, destination: str, msg_type: str, authority,
) -> tuple[bool, str]:
    if msg_type in ELECTION_TYPES:
        return True, "election traffic does not require authority binding"
    if not authority.endorsements:
        return True, "no authority attached"
    bad = [e for e in authority.endorsements if e.endorsee != source]
    if bad:
        return False, f"{len(bad)} endorsement(s) endorsee != source"
    return True, ""


def detect_envelope_authority_mismatch(
    events: Iterable[TransmissionEvent],
    consistency_fn: Optional[Callable] = None,
) -> list[Finding]:
    """
    Apply the (source, destination, msg_type, authority) consistency
    rule to every event. Default rule encodes the leader-only-claims
    invariant; override consistency_fn for stricter rules.
    """
    fn = consistency_fn or _default_authority_consistency
    findings: list[Finding] = []
    for ev in events:
        ok, reason = fn(ev.tx.source, ev.tx.destination, ev.tx.msg_type, ev.tx.authority)
        if ok:
            continue
        findings.append(Finding(
            technique="GG-T5.2.2",
            title="envelope-authority mismatch",
            severity=HIGH,
            detector="detect_envelope_authority_mismatch",
            evidence={
                "source":      ev.tx.source,
                "destination": ev.tx.destination,
                "msg_type":    ev.tx.msg_type,
                "endorsement_count": len(ev.tx.authority.endorsements),
                "endorsees":   [e.endorsee for e in ev.tx.authority.endorsements],
                "reason":      reason,
            },
            occurred_at=ev.observed_at,
        ))
    return findings
