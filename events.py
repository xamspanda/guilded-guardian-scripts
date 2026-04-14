"""
shared/events.py

Event records detectors consume. The collectors in defense/collectors/
produce these; detectors read sequences of them and emit Findings.

Keeping the event taxonomy small and explicit means a new detector can
list the exact event types it depends on at the top of its module.

artifact_id:    gildedguardian-ctf-shared-events
created:        2026-04-13T15:00Z
last_modified:  2026-04-13T15:00Z
stale_after:    2026-04-27T00:00Z
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    from .transmission import Transmission
except ImportError:
    from transmission import Transmission


@dataclass
class TransmissionEvent:
    """A single message observed on a local Unix socket."""
    tx:           Transmission
    socket_path:  str                          # which socket it came from
    direction:    str                          # "ingress" | "egress" | "broadcast"
    pid:          Optional[int]      = None    # peer pid via SO_PEERCRED
    uid:          Optional[int]      = None    # peer uid  via SO_PEERCRED
    gid:          Optional[int]      = None
    observed_at:  float              = field(default_factory=time.time)


@dataclass
class SocketOpenEvent:
    """A process opening a Unix socket. Sourced from auditd / fanotify."""
    socket_path:  str
    mode:         str                          # "read" | "write" | "readwrite"
    pid:          int
    uid:          int
    identity:     str                          # /proc/<pid>/comm or systemd unit
    observed_at:  float = field(default_factory=time.time)


@dataclass
class TermEvent:
    """A controller term observation. Sourced from election socket polls."""
    node:         str                          # observing node UUID
    leader:       Optional[str]                # leader UUID, may be None
    term:         int
    endorsements: int                          # count, not the full list
    observed_at:  float = field(default_factory=time.time)


@dataclass
class CoaSnapshot:
    """A point-in-time read of the local election socket COA."""
    node:         str
    endorsements: list[dict]                   # raw Endorsement dicts
    observed_at:  float = field(default_factory=time.time)


@dataclass
class FilePermEvent:
    """Filesystem trust-material audit observation."""
    path:           str
    mode:           int                        # st_mode & 0o777
    owner:          str
    group:          str
    is_signing_material: bool                  # heuristic from caller
    readers_outside_owner: list[str] = field(default_factory=list)
    observed_at:    float = field(default_factory=time.time)


@dataclass
class ConfigSnapshot:
    """Parsed config.yaml from a node."""
    node:         str                          # hostname
    role:         str                          # controller | sensor | boomer
    raw:          dict[str, Any]
    observed_at:  float = field(default_factory=time.time)


@dataclass
class DaemonHealth:
    """Per-daemon up/down/lag observation."""
    node:        str
    daemon:      str                           # comms | election | control | hw
    status:      str                           # up | down | unknown
    last_seen:   float
    observed_at: float = field(default_factory=time.time)
