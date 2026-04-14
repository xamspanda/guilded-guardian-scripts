#!/usr/bin/env python3
"""check_leader.py - auto-config election-socket leader check.

Per Controller.md §election Socket Semantics: a local client reads one
CertificateOfAuthority JSON payload from the socket. The CoA is the
leader oracle for every other local daemon (comms, control). Non-empty
`endorsements` => this node is leader.

Discovery order (matches mantis.py; needs one of these to be present):
  1. CONTROLLER_CONFIG_PATH / SENSOR_CONFIG_PATH / BOOMER_CONFIG_PATH env var
  2. /etc/controller/config.yaml / /etc/sensor/config.yaml / /etc/boomer/config.yaml
  3. glob /etc/*/config.yaml that exposes election_socket_path

Exit codes:
  0  = leader            (use in shell guard: `if python3 check_leader.py; then ...`)
  1  = not leader        (socket reachable, endorsements empty)
  2  = error             (config missing, socket missing, unreachable, non-JSON)

Note: exit 2 on non-JSON is deliberate. A teammate running
replace_election_socket.py serves valid JSON, so a non-JSON response
always indicates a broken state, not a friendly replacement.
"""
import glob
import json
import os
import re
import socket
import sys

ENV_KEYS = ("CONTROLLER_CONFIG_PATH", "SENSOR_CONFIG_PATH",
            "BOOMER_CONFIG_PATH", "CONFIG_PATH")


def _scalar(v):
    v = v.strip().strip('"').strip("'")
    low = v.lower()
    if low in ("null", "~", "none", ""): return None
    if low == "true":  return True
    if low == "false": return False
    if re.fullmatch(r"-?\d+", v): return int(v)
    if re.fullmatch(r"-?\d*\.\d+([eE][+-]?\d+)?", v):
        try: return float(v)
        except ValueError: return v
    if re.fullmatch(r"-?\d+[eE][+-]?\d+", v):
        try: return float(v)
        except ValueError: return v
    return v


def _parse_yaml(text):
    """Minimal YAML sufficient for Mantis configs — scalars only at top
    level is all we need here (the election_socket_path field)."""
    out = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("- "):
            continue
        if ":" in s:
            k, _, v = s.partition(":")
            v = v.strip()
            if v:
                out[k.strip()] = _scalar(v)
    return out


def _load_cfg():
    for k in ENV_KEYS:
        p = os.environ.get(k)
        if p and os.path.exists(p):
            try:
                return _parse_yaml(open(p).read()), p
            except Exception:
                pass
    for p in ("/etc/controller/config.yaml",
              "/etc/sensor/config.yaml",
              "/etc/boomer/config.yaml"):
        if os.path.exists(p):
            try:
                return _parse_yaml(open(p).read()), p
            except Exception:
                pass
    for p in glob.glob("/etc/*/config.yaml"):
        try:
            cfg = _parse_yaml(open(p).read())
            if cfg.get("election_socket_path"):
                return cfg, p
        except Exception:
            continue
    return None, None


def main():
    cfg, cfg_path = _load_cfg()
    if not cfg:
        print("ERROR: no config found "
              "(checked $*_CONFIG_PATH + /etc/*/config.yaml)",
              file=sys.stderr)
        sys.exit(2)

    es = cfg.get("election_socket_path")
    if not es:
        print(f"ERROR: election_socket_path missing from {cfg_path}",
              file=sys.stderr)
        sys.exit(2)
    if not os.path.exists(es):
        print(f"ERROR: election socket does not exist: {es}",
              file=sys.stderr)
        sys.exit(2)

    s = None
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(es)
        buf = bytearray()
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf.extend(chunk)
        except socket.timeout:
            pass
    except (ConnectionRefusedError, FileNotFoundError) as e:
        print(f"ERROR: election socket not accepting connections: {e}",
              file=sys.stderr)
        sys.exit(2)
    except PermissionError as e:
        print(f"ERROR: no permission to connect to {es}: {e}",
              file=sys.stderr)
        sys.exit(2)
    except OSError as e:
        print(f"ERROR: cannot read election socket: {e}", file=sys.stderr)
        sys.exit(2)
    finally:
        if s is not None:
            try: s.close()
            except OSError: pass

    if not buf:
        print("ERROR: election socket returned empty response "
              "(daemon may be starting up or was killed without replacement)",
              file=sys.stderr)
        sys.exit(2)

    try:
        coa = json.loads(buf.decode())
    except (ValueError, UnicodeDecodeError) as e:
        print(f"ERROR: election socket returned non-JSON: {e}",
              file=sys.stderr)
        sys.exit(2)

    if not isinstance(coa, dict):
        print("ERROR: election socket payload is not a JSON object",
              file=sys.stderr)
        sys.exit(2)

    endorsements = coa.get("endorsements") or []
    if endorsements:
        print(f"LEADER: YES ({len(endorsements)} endorsements)")
        for e in endorsements:
            if not isinstance(e, dict):
                continue
            endorser = str(e.get("endorser", "?"))
            endorsee = str(e.get("endorsee", "?"))
            exp      = e.get("expiration", "?")
            print(f"  endorser={endorser[:8]}"
                  f"  endorsee={endorsee[:8]}"
                  f"  exp={exp}")
        sys.exit(0)

    print("LEADER: NO (election socket reachable, endorsements empty)")
    sys.exit(1)


if __name__ == "__main__":
    main()
