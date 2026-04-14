"""
defense/detectors/gg_t10_trust_surface.py

GG-T10 Configuration, Identity, and Trust Material Exposure detectors.

Implements:
  GG-T10.1.1  Identity Inventory Exposure        (config carries full inventory)
  GG-T10.1.2  Validation Policy Drift            (verify_signatures varies)
  GG-T10.2.1  Broker-Signed Origin Ambiguity     (signature proves comms, not author)
  GG-T10.2.2  Trust Material Exposure            (key.pem readable outside owner)

Inputs:
  - ConfigSnapshot per node (from defense/collectors/config_audit.py).
  - FilePermEvent per scanned trust path.
  - TransmissionEvent stream tagged with peer pid/uid for GG-T10.2.1.

These detectors are static-audit shaped: they fire even before the
attacker does anything, which makes them useful as a posture check
before the competition window opens.

artifact_id:    gildedguardian-ctf-defense-gg-t10
created:        2026-04-13T16:45Z
last_modified:  2026-04-13T16:45Z
stale_after:    2026-04-27T00:00Z
"""
from __future__ import annotations

import stat
from typing import Iterable, Optional

from shared.events import ConfigSnapshot, FilePermEvent, TransmissionEvent
from shared.findings import HIGH, MEDIUM, LOW, Finding
from .gg_t2_ipc import identity_from_pid


# ---------- GG-T10.1.1 Identity Inventory Exposure ----------

def detect_identity_inventory_exposure(
    snap: ConfigSnapshot,
    *,
    controller_threshold: int = 3,
    sensor_threshold: int = 4,
    boomer_threshold: int = 8,
) -> list[Finding]:
    """
    A single config.yaml that lists every controller, sensor, and
    boomer in the swarm is the entire trust topology in one file.
    Threshold defaults are tuned to the source range's per-swarm
    counts (5 / 6 / 15) so anything close to "complete inventory"
    fires.
    """
    cfg = snap.raw
    n_ctrl = len(cfg.get("controllers", []) or [])
    n_sens = len(cfg.get("sensors", []) or [])
    n_boom = len(cfg.get("boomers", []) or [])

    findings: list[Finding] = []
    if n_ctrl > controller_threshold or n_sens > sensor_threshold or n_boom > boomer_threshold:
        findings.append(Finding(
            technique="GG-T10.1.1",
            title="high-value identity inventory exposure",
            severity=HIGH,
            detector="detect_identity_inventory_exposure",
            evidence={
                "config_path":    snap.raw.get("__path__", "?"),
                "node":           snap.node,
                "controllers":    n_ctrl,
                "sensors":        n_sens,
                "boomers":        n_boom,
                "thresholds": {
                    "controllers": controller_threshold,
                    "sensors":     sensor_threshold,
                    "boomers":     boomer_threshold,
                },
            },
            occurred_at=snap.observed_at,
            node=snap.node,
        ))

    # Per-peer "complete record" exposure: any peer entry that carries
    # uuid + endpoint + public_key together is a one-stop shop for
    # impersonation prep.
    for peer in (cfg.get("controllers") or []):
        if isinstance(peer, dict) and peer.get("uuid") and peer.get("ip") and peer.get("public_key"):
            findings.append(Finding(
                technique="GG-T10.1.1",
                title="complete peer trust record exposed",
                severity=MEDIUM,
                detector="detect_identity_inventory_exposure",
                evidence={
                    "peer_uuid": peer.get("uuid"),
                    "node":      snap.node,
                },
                occurred_at=snap.observed_at,
                node=snap.node,
            ))
    return findings


# ---------- GG-T10.1.2 Validation Policy Drift ----------

def detect_validation_policy_drift(
    snapshots: Iterable[ConfigSnapshot],
) -> list[Finding]:
    """
    Cross-node comparison: any node whose verify_signatures setting
    differs from the canonical (modal) value of the swarm.

    This overlaps GG-T5.1.1 by design; T5.1.1 frames it as message
    validation, T10.1.2 frames it as configuration drift. Both should
    fire because both response paths matter (incident response vs
    config remediation).
    """
    by_value: dict[Optional[bool], list[ConfigSnapshot]] = {}
    snaps_list = list(snapshots)
    for s in snaps_list:
        v = s.raw.get("verify_signatures")
        by_value.setdefault(v, []).append(s)

    if len(by_value) <= 1:
        return []

    canonical = max(by_value, key=lambda k: len(by_value[k]))
    findings: list[Finding] = []
    for v, snaps in by_value.items():
        if v == canonical:
            continue
        for s in snaps:
            findings.append(Finding(
                technique="GG-T10.1.2",
                title="validation policy drift",
                severity=HIGH,
                detector="detect_validation_policy_drift",
                evidence={
                    "node":               s.node,
                    "role":               s.role,
                    "verify_signatures":  v,
                    "canonical_value":    canonical,
                    "canonical_count":    len(by_value[canonical]),
                    "drift_count":        len(snaps),
                },
                occurred_at=s.observed_at,
                node=s.node,
            ))
    return findings


# ---------- GG-T10.2.1 Broker-Signed Origin Ambiguity ----------

def detect_broker_signed_origin_ambiguity(
    events: Iterable[TransmissionEvent],
    approved_origin_identities: set[str],
) -> list[Finding]:
    """
    Egress events whose comms-side originating process is outside the
    approved set, but the message has been signed by the comms daemon
    so peers will accept it as authentic. The signature attests "comms
    sent this," not "comms attests this is from controlDaemon."

    Distinct from GG-T2.2.1 in framing: T2.2.1 is the broker-trust
    primitive (an architectural invariant), T10.2.1 is per-message
    runtime detection.
    """
    findings: list[Finding] = []
    for ev in events:
        if ev.direction != "egress":
            continue
        if not ev.tx.msg_sig:
            continue
        identity = identity_from_pid(ev.pid)
        if identity in approved_origin_identities:
            continue
        findings.append(Finding(
            technique="GG-T10.2.1",
            title="broker-signed origin ambiguity",
            severity=HIGH,
            detector="detect_broker_signed_origin_ambiguity",
            evidence={
                "origin_identity": identity,
                "pid":             ev.pid,
                "msg_type":        ev.tx.msg_type,
                "msg_sig_present": True,
                "approved_origins": sorted(approved_origin_identities),
            },
            occurred_at=ev.observed_at,
        ))
    return findings


# ---------- GG-T10.2.2 Trust Material Exposure ----------

def detect_trust_material_exposure(
    perm_events: Iterable[FilePermEvent],
    approved_owners: set[str],
) -> list[Finding]:
    """
    Any signing-material file readable by anyone outside its approved
    owner set. The reference rule: key.pem must be 0600 owned by the
    role-appropriate daemon user (commsDaemon, sensorDaemon, or
    boomerDaemon per Turn 17 identity module).
    """
    findings: list[Finding] = []
    for ev in perm_events:
        if not ev.is_signing_material:
            continue
        too_open = bool(ev.mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH))
        wrong_owner = ev.owner not in approved_owners
        if not (too_open or wrong_owner or ev.readers_outside_owner):
            continue
        findings.append(Finding(
            technique="GG-T10.2.2",
            title="trust material exposure",
            severity=HIGH,
            detector="detect_trust_material_exposure",
            evidence={
                "path":   ev.path,
                "mode":   oct(ev.mode),
                "owner":  ev.owner,
                "group":  ev.group,
                "approved_owners":      sorted(approved_owners),
                "readers_outside_owner": ev.readers_outside_owner,
            },
            occurred_at=ev.observed_at,
        ))
    return findings
