"""
defense/collectors/config_audit.py

Snapshots the per-node controller config and the on-disk permissions
of trust material (key.pem and friends). Produces ConfigSnapshot and
FilePermEvent records consumed by gg_t10_trust_surface and
gg_t15_topology detectors.

Static (no live process attachment), so safe to run repeatedly during
the competition without disturbing the cluster.

artifact_id:    gildedguardian-ctf-defense-collector-config-audit
created:        2026-04-13T15:45Z
last_modified:  2026-04-13T15:45Z
stale_after:    2026-04-27T00:00Z
"""
from __future__ import annotations

import grp
import os
import pwd
import socket
import stat
import time
from pathlib import Path
from typing import Optional

from shared.events import ConfigSnapshot, FilePermEvent

# Heuristic file lists: anything in these globs is considered signing
# material until proven otherwise.
SIGNING_MATERIAL_HINTS = (
    "key.pem", "private.pem", "id_ed25519", "id_rsa",
)


def _looks_like_signing_material(path: Path) -> bool:
    name = path.name.lower()
    return any(h in name for h in SIGNING_MATERIAL_HINTS)


def _owner_group(st: os.stat_result) -> tuple[str, str]:
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return owner, group


def parse_config_yaml(path: str) -> dict:
    """
    Same minimal YAML reader as offense/10_config_recon.py kept inline
    here so the defense package has zero external deps. Re-implemented
    rather than imported across the offense/defense boundary on
    purpose: defenders never want their detectors to fail because an
    attacker tampered with a sibling file in /tmp.
    """
    out: dict = {}
    current_list_key: Optional[str] = None
    text = Path(path).read_text()
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line.startswith(" ") or line.startswith("\t"):
            stripped = line.strip()
            if current_list_key and stripped.startswith("- "):
                inner = stripped[2:].strip()
                if inner.startswith("{") and inner.endswith("}"):
                    item: dict = {}
                    for p in inner[1:-1].split(","):
                        if ":" in p:
                            k, v = p.split(":", 1)
                            item[k.strip()] = v.strip().strip('"').strip("'")
                    out.setdefault(current_list_key, []).append(item)
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip(), v.strip()
            if v == "":
                current_list_key = k
                out.setdefault(k, [])
            else:
                current_list_key = None
                v_clean = v.strip('"').strip("'")
                if v_clean.lower() in ("true", "false"):
                    out[k] = (v_clean.lower() == "true")
                else:
                    try:
                        out[k] = int(v_clean)
                    except ValueError:
                        out[k] = v_clean
    return out


def snapshot_config(path: str, role: str,
                    hostname: Optional[str] = None) -> ConfigSnapshot:
    raw = parse_config_yaml(path)
    return ConfigSnapshot(
        node=hostname or socket.gethostname(),
        role=role,
        raw=raw,
        observed_at=time.time(),
    )


def audit_path(target: str) -> Optional[FilePermEvent]:
    """Stat one path and produce a FilePermEvent if it exists."""
    p = Path(target)
    if not p.exists():
        return None
    st = p.stat()
    owner, group = _owner_group(st)
    mode = stat.S_IMODE(st.st_mode)

    # World-readable trust material with non-zero "other" read bit is
    # the bright-line case the GG-T10.2.2 detector flags.
    readers_outside_owner: list[str] = []
    if _looks_like_signing_material(p):
        if mode & stat.S_IROTH:
            readers_outside_owner.append("world")
        if mode & stat.S_IRGRP:
            readers_outside_owner.append(f"group:{group}")

    return FilePermEvent(
        path=str(p),
        mode=mode,
        owner=owner, group=group,
        is_signing_material=_looks_like_signing_material(p),
        readers_outside_owner=readers_outside_owner,
        observed_at=time.time(),
    )


def audit_paths(targets: list[str]) -> list[FilePermEvent]:
    out: list[FilePermEvent] = []
    for t in targets:
        ev = audit_path(t)
        if ev is not None:
            out.append(ev)
    return out
