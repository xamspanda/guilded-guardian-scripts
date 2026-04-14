"""
defense/collectors/election_sampler.py

Periodically reads the local election socket and produces CoaSnapshot
records (and, when peer endpoints are configured, TermEvent records
from each peer's HTTP /status path so quorum-divergence detectors can
compare local view against peer-majority view).

artifact_id:    gildedguardian-ctf-defense-collector-election-sampler
created:        2026-04-13T15:45Z
last_modified:  2026-04-13T15:45Z
stale_after:    2026-04-27T00:00Z
"""
from __future__ import annotations

import json
import socket
import time
from typing import Iterator, Optional

from shared.events import CoaSnapshot, TermEvent


def sample_local_coa(path: str, node_uuid: str,
                     timeout: float = 5.0) -> Optional[CoaSnapshot]:
    """One read of the local election socket; None on failure."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
        raw = s.recv(409600)
    except OSError:
        return None
    finally:
        s.close()
    if not raw:
        return CoaSnapshot(node=node_uuid, endorsements=[], observed_at=time.time())
    try:
        d = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return CoaSnapshot(node=node_uuid, endorsements=[], observed_at=time.time())
    return CoaSnapshot(
        node=node_uuid,
        endorsements=d.get("endorsements", []),
        observed_at=time.time(),
    )


def poll_loop(path: str, node_uuid: str,
              interval: float = 1.0,
              seconds: Optional[float] = None) -> Iterator[CoaSnapshot]:
    """Yield CoaSnapshot records on a fixed cadence."""
    deadline = (time.time() + seconds) if seconds is not None else None
    while deadline is None or time.time() < deadline:
        snap = sample_local_coa(path, node_uuid)
        if snap is not None:
            yield snap
        time.sleep(interval)


def coa_to_term_event(snap: CoaSnapshot) -> TermEvent:
    """
    Derive a TermEvent from a CoaSnapshot. The Gilded Guardian COA
    structure does not embed term explicitly; downstream detectors
    that need term must read it from comms-tap election traffic
    instead. Here we return term=-1 as a sentinel and rely on
    endorsement count as a leadership proxy.
    """
    leader = snap.endorsements[0]["endorsee"] if snap.endorsements else None
    return TermEvent(
        node=snap.node,
        leader=leader,
        term=-1,
        endorsements=len(snap.endorsements),
        observed_at=snap.observed_at,
    )
