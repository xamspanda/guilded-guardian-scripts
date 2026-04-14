"""
defense/detectors/gg_t2_ipc.py

GG-T2 Local IPC and Broker Trust detectors.

Implements:
  GG-T2.1.1  Unauthorized Local Writer        (process outside set writes)
  GG-T2.1.2  Unauthorized Local Reader        (process outside set reads)
  GG-T2.2.1  Unsafeguarded Broker Signing     (broker signs without origin proof)
  GG-T2.2.2  Single-Oracle Leadership Dependence (no cross-validation)

Inputs:
  - SocketOpenEvent stream (auditd or /proc walk).
  - TransmissionEvent stream tagged with peer pid/uid via SO_PEERCRED.
  - approved_identities: set of identity strings (systemd unit names or
    binary paths) that are permitted to open privileged sockets.

The competition trip-wires:
  - win_election.py opens /run/commsDaemon/comms.sock as a non-comms
    process: GG-T2.1.1.
  - sniff_comms.py opens it for read: GG-T2.1.2.
  - replace_election_socket.py creates and writes a new server socket
    in /run/electionDaemon/ as not-the-electionDaemon: GG-T2.1.1
    (privileged-path write).
  - Every signed message that emerges from the comms daemon under our
    control is broker-signed without independent origin proof:
    GG-T2.2.1.

artifact_id:    gildedguardian-ctf-defense-gg-t2
created:        2026-04-13T16:00Z
last_modified:  2026-04-13T16:00Z
stale_after:    2026-04-27T00:00Z
"""
from __future__ import annotations

from collections import Counter
from typing import Iterable, Optional

from shared.events import SocketOpenEvent, TransmissionEvent
from shared.findings import CRITICAL, HIGH, MEDIUM, Finding


# ---------- GG-T2.1.1 / GG-T2.1.2 Privileged Socket Exposure ----------

def detect_unauthorized_local_writer(
    socket_open_events: Iterable[SocketOpenEvent],
    approved_identities: set[str],
) -> list[Finding]:
    findings: list[Finding] = []
    for ev in socket_open_events:
        if ev.mode in ("write", "readwrite") and ev.identity not in approved_identities:
            findings.append(Finding(
                technique="GG-T2.1.1",
                title="unauthorized local writer",
                severity=CRITICAL,
                detector="detect_unauthorized_local_writer",
                evidence={
                    "identity":     ev.identity,
                    "pid":          ev.pid,
                    "uid":          ev.uid,
                    "socket_path":  ev.socket_path,
                    "mode":         ev.mode,
                    "approved_set_size": len(approved_identities),
                },
                occurred_at=ev.observed_at,
            ))
    return findings


def detect_unauthorized_local_reader(
    socket_open_events: Iterable[SocketOpenEvent],
    approved_identities: set[str],
) -> list[Finding]:
    findings: list[Finding] = []
    for ev in socket_open_events:
        if ev.mode in ("read", "readwrite") and ev.identity not in approved_identities:
            findings.append(Finding(
                technique="GG-T2.1.2",
                title="unauthorized local reader",
                severity=HIGH,
                detector="detect_unauthorized_local_reader",
                evidence={
                    "identity":    ev.identity,
                    "pid":         ev.pid,
                    "uid":         ev.uid,
                    "socket_path": ev.socket_path,
                    "mode":        ev.mode,
                },
                occurred_at=ev.observed_at,
            ))
    return findings


# Helper: derive identity from pid via /proc/<pid>/comm (Linux only).
def identity_from_pid(pid: Optional[int]) -> str:
    if pid is None:
        return "unknown"
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except OSError:
        return f"pid:{pid}"


# Convenience: build SocketOpenEvent records from a TransmissionEvent
# stream when SO_PEERCRED is the only signal available. Used by the
# socket_tap collector to bridge into the unauthorized-writer detector.
def socket_opens_from_transmissions(
    events: Iterable[TransmissionEvent],
) -> list[SocketOpenEvent]:
    out: list[SocketOpenEvent] = []
    seen: set[tuple[int, str]] = set()
    for ev in events:
        if ev.pid is None:
            continue
        key = (ev.pid, ev.socket_path)
        if key in seen:
            continue
        seen.add(key)
        out.append(SocketOpenEvent(
            socket_path=ev.socket_path,
            mode="readwrite",
            pid=ev.pid,
            uid=ev.uid or -1,
            identity=identity_from_pid(ev.pid),
            observed_at=ev.observed_at,
        ))
    return out


# ---------- GG-T2.2.1 Unsafeguarded Broker Signing ----------

def detect_unsafeguarded_broker_signing(
    events: Iterable[TransmissionEvent],
    approved_origin_identities: set[str],
) -> list[Finding]:
    """
    A signed message whose comms-side originating process is not in the
    approved set. The transmission appears valid downstream because the
    comms daemon's signature is intact, but the origin is suspect.

    "Approved origins" must be a tight set: typically just
    {"controlDaemon", "electionDaemon"} on a controller. Any other
    process that wrote to /run/commsDaemon/comms.sock and got its
    message signed by comms is the GG-T2.2.1 case.
    """
    findings: list[Finding] = []
    for ev in events:
        if ev.direction != "egress":
            continue
        if not ev.tx.msg_sig:
            continue
        identity = identity_from_pid(ev.pid)
        if identity not in approved_origin_identities:
            findings.append(Finding(
                technique="GG-T2.2.1",
                title="broker-signed message lacks independent origin proof",
                severity=CRITICAL,
                detector="detect_unsafeguarded_broker_signing",
                evidence={
                    "origin_identity": identity,
                    "pid":             ev.pid,
                    "msg_type":        ev.tx.msg_type,
                    "destination":     ev.tx.destination,
                    "approved_origins": sorted(approved_origin_identities),
                    "msg_sig_present": True,
                },
                occurred_at=ev.observed_at,
            ))
    return findings


# ---------- GG-T2.2.2 Single-Oracle Leadership Dependence ----------

def detect_single_oracle_leadership_dependence(
    local_oracle_reads: int,
    peer_state_reads: int,
    *, dependency_threshold: int = 10,
    cross_validation_floor: int = 1,
) -> list[Finding]:
    """
    If a daemon has consulted the local election socket many times in
    the observation window but has not consulted any peer leadership
    state at all, the leadership view is single-oracle.

    Caller is expected to roll up read counts per daemon over a window
    (e.g., 60s) before invoking this detector.
    """
    if local_oracle_reads < dependency_threshold:
        return []
    if peer_state_reads >= cross_validation_floor:
        return []
    return [Finding(
        technique="GG-T2.2.2",
        title="single-oracle leadership dependence",
        severity=MEDIUM,
        detector="detect_single_oracle_leadership_dependence",
        evidence={
            "local_oracle_reads":      local_oracle_reads,
            "peer_state_reads":        peer_state_reads,
            "dependency_threshold":    dependency_threshold,
            "cross_validation_floor":  cross_validation_floor,
        },
    )]


# ---------- Aggregation helper for run_all.py ----------

def summarize_writer_distribution(
    socket_open_events: Iterable[SocketOpenEvent],
) -> dict[str, Counter]:
    """Per-socket histogram of opening identities, useful for triage."""
    out: dict[str, Counter] = {}
    for ev in socket_open_events:
        out.setdefault(ev.socket_path, Counter())[ev.identity] += 1
    return out
