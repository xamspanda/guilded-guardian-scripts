from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Transmission:
    """Minimal shared transmission record for defense-side event schemas.

    This fallback keeps the local script kit importable even when the
    original package layout is unavailable on the attack station.
    """

    source: str = ""
    destination: str = ""
    msg: str = ""
    msg_type: str = ""
    msg_sig: str = ""
    nonce: str = ""
    authority: dict[str, Any] = field(default_factory=dict)
