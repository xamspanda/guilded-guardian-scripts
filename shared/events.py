from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from transmission import Transmission


@dataclass
class TransmissionEvent:
    tx: Transmission
    socket_path: str
    direction: str
    pid: Optional[int] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    observed_at: float = 0.0


@dataclass
class SocketOpenEvent:
    socket_path: str
    mode: str
    pid: int
    uid: int
    identity: str
    observed_at: float = 0.0


@dataclass
class TermEvent:
    node: str
    leader: Optional[str]
    term: int
    endorsements: int
    observed_at: float = 0.0


@dataclass
class CoaSnapshot:
    node: str
    endorsements: list[dict]
    observed_at: float = 0.0


@dataclass
class FilePermEvent:
    path: str
    mode: int
    owner: str
    group: str
    is_signing_material: bool
    readers_outside_owner: list[str] = field(default_factory=list)
    observed_at: float = 0.0


@dataclass
class ConfigSnapshot:
    node: str
    role: str
    raw: dict[str, Any]
    observed_at: float = 0.0


@dataclass
class DaemonHealth:
    node: str
    daemon: str
    status: str
    last_seen: float
    observed_at: float = 0.0
