#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

RECV_BUF = 409600
DEFAULT_RECON_PATH = "/tmp/recon.json"
DEFAULT_COA_PATH = "/tmp/captured_coa.json"

SHUTDOWN = "Shutdown"
ELECTION_VOTE_REQUEST = "Election:Vote Request"
ELECTION_VOTE_RESPONSE = "Election:Vote Response"
ELECTION_ENDORSE_REQUEST = "Election:Endorsement Request"
ELECTION_ENDORSE_RESPONSE = "Election:Endorsement Response"


@dataclass
class Endorsement:
    endorser: str = ""
    endorsee: str = ""
    valid_after: str = ""
    expiration: str = ""

    @classmethod
    def from_dict(cls, data: dict | None) -> "Endorsement":
        data = data or {}
        return cls(
            endorser=str(data.get("endorser", "")),
            endorsee=str(data.get("endorsee", "")),
            valid_after=str(data.get("valid_after", "")),
            expiration=str(data.get("expiration", "")),
        )

    def to_dict(self) -> dict:
        return {
            "endorser": self.endorser,
            "endorsee": self.endorsee,
            "valid_after": self.valid_after,
            "expiration": self.expiration,
        }


@dataclass
class Authority:
    endorsements: list[Endorsement] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict | None) -> "Authority":
        data = data or {}
        return cls([
            Endorsement.from_dict(item)
            for item in (data.get("endorsements", []) or [])
            if isinstance(item, dict)
        ])

    def to_dict(self) -> dict:
        return {"endorsements": [e.to_dict() for e in self.endorsements]}

    def is_empty(self) -> bool:
        return len(self.endorsements) == 0


@dataclass
class Transmission:
    source: str = ""
    destination: str = ""
    msg: str = ""
    msg_type: str = ""
    msg_sig: str = ""
    nonce: str = ""
    authority: Authority = field(default_factory=Authority)

    @classmethod
    def from_dict(cls, data: dict) -> "Transmission":
        return cls(
            source=str(data.get("source", "")),
            destination=str(data.get("destination", "")),
            msg=str(data.get("msg", "")),
            msg_type=str(data.get("msg_type", "")),
            msg_sig=str(data.get("msg_sig", "")),
            nonce=str(data.get("nonce", "")),
            authority=Authority.from_dict(data.get("authority", {})),
        )

    @classmethod
    def from_json_bytes(cls, data: bytes) -> "Transmission":
        return cls.from_dict(json.loads(data.decode("utf-8")))

    def to_dict(self) -> dict:
        out = {
            "source": self.source,
            "destination": self.destination,
            "msg": self.msg,
            "msg_type": self.msg_type,
        }
        if self.msg_sig:
            out["msg_sig"] = self.msg_sig
        if self.nonce:
            out["nonce"] = self.nonce
        if not self.authority.is_empty():
            out["authority"] = self.authority.to_dict()
        return out

    def to_json_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), separators=(",", ":")).encode("utf-8")

    def decode_payload(self) -> tuple[object | None, str | None]:
        if self.msg == "":
            return None, None
        candidates = [self.msg]
        try:
            decoded = base64.b64decode(self.msg).decode("utf-8")
            candidates.insert(0, decoded)
        except Exception:
            pass
        for candidate in candidates:
            try:
                return json.loads(candidate), None
            except Exception:
                continue
        return None, "payload is not valid JSON"


def iter_ndjson(buf: bytes) -> Iterator[bytes]:
    start = 0
    while True:
        idx = buf.find(b"\n", start)
        if idx == -1:
            break
        line = buf[start:idx].strip()
        start = idx + 1
        if line:
            yield line


def parse_yaml_minimal(text: str) -> dict:
    out: dict = {}
    current_list_key: str | None = None
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
                    for part in inner[1:-1].split(","):
                        if ":" not in part:
                            continue
                        key, value = part.split(":", 1)
                        item[key.strip()] = value.strip().strip('"').strip("'")
                    out.setdefault(current_list_key, []).append(item)
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if value == "":
            current_list_key = key
            out.setdefault(key, [])
            continue
        current_list_key = None
        clean = value.strip('"').strip("'")
        if clean.lower() in ("true", "false"):
            out[key] = clean.lower() == "true"
        else:
            try:
                out[key] = int(clean)
            except ValueError:
                try:
                    out[key] = float(clean)
                except ValueError:
                    out[key] = clean
    return out


def detect_role() -> str:
    has_election = os.path.isdir("/run/electionDaemon")
    has_comms = os.path.isdir("/run/commsDaemon")
    has_hw = os.path.isdir("/run/hwDaemon")
    if has_election and has_comms:
        return "controller"
    if has_comms and has_hw and not has_election:
        if os.path.exists("/etc/sensor/config.yaml"):
            return "sensor"
        if os.path.exists("/etc/boomer/config.yaml"):
            return "boomer"
        return "worker-unknown"
    return "unknown"


def find_config(role: str) -> str:
    preferred = {
        "controller": "/etc/controller/config.yaml",
        "sensor": "/etc/sensor/config.yaml",
        "boomer": "/etc/boomer/config.yaml",
    }
    preferred_path = preferred.get(role, "")
    if preferred_path and os.path.exists(preferred_path):
        return preferred_path
    for candidate in preferred.values():
        if os.path.exists(candidate):
            return candidate
    return ""


def _ensure_mapping(data: Any, *, path: str, label: str) -> dict:
    if not isinstance(data, dict):
        raise SystemExit(f"[!] {label} at {path} must contain a JSON object at the top level")
    return data


def _read_json_file(path: str, *, label: str) -> dict:
    p = Path(path)
    if not p.exists():
        hint = "run 10_config_recon.py or 00_one_shot.py first" if label == "recon" else "win the election first"
        raise SystemExit(f"[!] {label} file not found: {path}; {hint}")
    try:
        raw = p.read_text()
    except OSError as e:
        raise SystemExit(f"[!] cannot read {label} file {path}: {e}") from e
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise SystemExit(f"[!] invalid JSON in {label} file {path}: line {e.lineno}, column {e.colno}: {e.msg}") from e
    return _ensure_mapping(data, path=path, label=label)


def _write_json_file(path: str, payload: dict, *, label: str) -> None:
    try:
        Path(path).write_text(json.dumps(payload, indent=2))
    except OSError as e:
        raise SystemExit(f"[!] cannot write {label} file {path}: {e}") from e


def format_socket_error(path: str, error: OSError, *, action: str) -> str:
    return f"[!] cannot {action} unix socket {path}: {error.__class__.__name__}: {error}"


def die(message: str, *, code: int = 1) -> int:
    print(message)
    return code


def run_main(main_fn) -> int:
    try:
        return int(main_fn())
    except SystemExit as e:
        if isinstance(e.code, str):
            print(e.code, flush=True)
            return 1
        if e.code is None:
            return 0
        return int(e.code)
    except KeyboardInterrupt:
        print("[!] interrupted by user")
        return 130
    except BrokenPipeError:
        return 141
    except OSError as e:
        print(f"[!] operating system error: {e.__class__.__name__}: {e}")
        return 1
    except Exception as e:
        print(f"[!] unexpected error: {e.__class__.__name__}: {e}")
        return 1


def do_recon(out_path: str = DEFAULT_RECON_PATH) -> dict:
    role = detect_role()
    if role == "unknown":
        raise SystemExit("[!] cannot determine role from /run/*Daemon layout; aborting")
    cfg_path = find_config(role)
    if not cfg_path:
        raise SystemExit(f"[!] no config.yaml found for inferred role={role}; checked /etc/controller, /etc/sensor, and /etc/boomer")
    try:
        cfg_text = Path(cfg_path).read_text()
    except OSError as e:
        raise SystemExit(f"[!] cannot read config file {cfg_path}: {e}") from e
    cfg = parse_yaml_minimal(cfg_text)
    summary = {
        "hostname": socket.gethostname(),
        "role": role,
        "role_inferred": role,
        "config_path": cfg_path,
        "our_uuid": cfg.get("id", ""),
        "comms_socket": cfg.get("comms_socket_path", ""),
        "election_socket": cfg.get("election_socket_path", ""),
        "key_path": cfg.get("key_path", ""),
        "verify_signatures": cfg.get("verify_signatures", None),
        "listen_port": cfg.get("listen_port", None),
        "peer_controllers": cfg.get("controllers", []) or [],
        "sensors": cfg.get("sensors", []) or [],
        "boomers": cfg.get("boomers", []) or [],
    }
    _write_json_file(out_path, summary, label="recon")
    return summary


def load_recon(path: str = DEFAULT_RECON_PATH) -> dict:
    return _read_json_file(path, label="recon")


def load_coa(path: str = DEFAULT_COA_PATH) -> Authority:
    return Authority.from_dict(_read_json_file(path, label="COA"))


def save_coa(coa: Authority, path: str = DEFAULT_COA_PATH) -> None:
    _write_json_file(path, coa.to_dict(), label="COA")


def read_coa(election_sock: str) -> Authority:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5.0)
    try:
        s.connect(election_sock)
        raw = s.recv(RECV_BUF)
    except OSError as e:
        raise SystemExit(format_socket_error(election_sock, e, action="read from")) from e
    finally:
        s.close()
    if not raw:
        return Authority()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise SystemExit(f"[!] election socket {election_sock} returned invalid JSON: {e}") from e
    return Authority.from_dict(_ensure_mapping(data, path=election_sock, label="election socket response"))


def b64_json(obj: dict) -> str:
    return base64.b64encode(json.dumps(obj).encode("utf-8")).decode("ascii")


def make_tx(source: str, destination: str, msg_type: str, msg: str, authority: Authority | None = None) -> Transmission:
    return Transmission(
        source=source,
        destination=destination,
        msg=msg,
        msg_type=msg_type,
        authority=authority or Authority(),
    )


def make_election_tx(source: str, destination: str, msg_type: str, payload: dict) -> bytes:
    return make_tx(source, destination, msg_type, b64_json(payload)).to_json_bytes() + b"\n"


def make_shutdown_tx(source: str, destination: str, authority: Authority, b64_payload: bool) -> bytes:
    msg_field = base64.b64encode(b"{}").decode("ascii") if b64_payload else "{}"
    return make_tx(source, destination, SHUTDOWN, msg_field, authority=authority).to_json_bytes() + b"\n"


def worker_uuids(recon: dict) -> list[str]:
    out: list[str] = []
    for item in (recon.get("sensors", []) or []) + (recon.get("boomers", []) or []):
        if isinstance(item, dict) and item.get("uuid"):
            out.append(str(item["uuid"]))
    return out


def peer_controller_uuids(recon: dict) -> list[str]:
    out: list[str] = []
    for item in recon.get("peer_controllers", []) or []:
        if isinstance(item, dict) and item.get("uuid"):
            out.append(str(item["uuid"]))
    return out
