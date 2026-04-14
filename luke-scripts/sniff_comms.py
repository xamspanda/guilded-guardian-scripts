"""sniff_comms.py - read-only intel tool for the local comms socket.

Per Controller.md §comms Socket Semantics: messages read by a local
client are copies of inbound traffic that arrived through the HTTP
server, broadcast to every subscribed local daemon connection.
Connecting to the comms socket therefore subscribes us to the full
inbound multicast: election traffic from peer controllers,
Sensor:Get Tasks, Sensor:Track Update, Boomer:Get Tasks,
Boomer:Engage Error, etc.

Use this BEFORE kill/divert to:
  - enumerate live sensor IDs and the track_ids they're reporting
  - see which controllers are voting / granting / endorsing
  - spot the current leader by watching endorsement traffic

This script never writes to the socket. Purely passive.

If no traffic appears in the sniff window, possible causes:
  1. We are a follower — comms HTTP ingress rejects non-controller
     polls (Controller.md §Worker Message Flow). Workers poll a peer
     instead, so no inbound traffic hits our Received() fan-out.
     Run check_leader.py to confirm.
  2. Network partition or the comms daemon has crashed.
  3. The swarm is already dead (kill succeeded).

Usage:
    python3 sniff_comms.py           # sniff 30 seconds, print, exit
    python3 sniff_comms.py 120       # sniff 120 seconds
    python3 sniff_comms.py 0         # sniff until Ctrl-C
"""
import base64
import glob
import json
import os
import re
import socket
import sys
import time

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


MAX_BUF_BYTES = 16 * 1024 * 1024   # 16 MiB cap so a malformed stream
                                    # cannot grow buf without bound.


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


def _load_comms_path():
    for k in ENV_KEYS:
        p = os.environ.get(k)
        if p and os.path.exists(p):
            try:
                cfg = _parse_yaml(open(p).read())
                if cfg.get("comms_socket_path"):
                    return cfg["comms_socket_path"]
            except Exception:
                pass
    for p in (["/etc/controller/config.yaml",
               "/etc/sensor/config.yaml",
               "/etc/boomer/config.yaml"] +
              glob.glob("/etc/*/config.yaml")):
        if not os.path.exists(p):
            continue
        try:
            cfg = _parse_yaml(open(p).read())
            if cfg.get("comms_socket_path"):
                return cfg["comms_socket_path"]
        except Exception:
            continue
    return None


def _decode_payload(msg, msg_type):
    """Per transmission.go: Election: messages are base64(JSON); others
    are plain JSON. Receiver's ParseMsg is tolerant of either, so try
    plain first, base64 second."""
    if not msg:
        return None
    try:
        return json.loads(msg)
    except Exception:
        pass
    try:
        return json.loads(base64.b64decode(msg).decode())
    except Exception:
        return None


def _fmt(payload, msg_type):
    if payload is None:
        return ""
    # Compact the track list (can be huge)
    if msg_type == "Sensor:Track Update":
        tracks = payload.get("tracks") or []
        ids = [t.get("track_id") for t in tracks if isinstance(t, dict)]
        return f" tracks={len(tracks)} ids={ids[:5]}"
    if msg_type.startswith("Election:"):
        keys = {"leader", "term", "vote_granted", "endorsement"}
        shown = {k: v for k, v in payload.items() if k in keys}
        return f" {json.dumps(shown)}"
    return f" {json.dumps(payload)[:120]}"


def main():
    duration = 30.0
    if len(sys.argv) > 1:
        try:
            duration = float(sys.argv[1])
        except ValueError:
            print(f"[!] bad duration: {sys.argv[1]}", file=sys.stderr)
            sys.exit(2)

    cs = _load_comms_path()
    if not cs:
        print("ERROR: comms_socket_path not found in any config",
              file=sys.stderr)
        sys.exit(2)
    if not os.path.exists(cs):
        print(f"ERROR: comms socket does not exist: {cs}", file=sys.stderr)
        sys.exit(2)

    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect(cs)
    except Exception as e:
        print(f"ERROR: connect({cs}): {e}", file=sys.stderr)
        sys.exit(2)

    label = f"{duration:.0f}s" if duration > 0 else "until Ctrl-C"
    print(f"[*] Subscribing to {cs} ({label})")
    print(f"[*] type                          src      dst      payload")

    deadline = time.time() + duration if duration > 0 else float("inf")
    buf = bytearray()
    counts = {}
    sensor_ids = set()
    track_ids = set()

    try:
        while time.time() < deadline:
            try:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf.extend(chunk)
                if len(buf) > MAX_BUF_BYTES:
                    print(f"[!] buffer exceeded {MAX_BUF_BYTES} bytes — "
                          "dropping head (malformed stream?)")
                    del buf[:len(buf) // 2]
            except socket.timeout:
                continue
            except OSError as e:
                print(f"[!] recv error: {e}")
                break

            while True:
                # Assume newline-delimited JSON per observed framing.
                nl = buf.find(b"\n")
                raw = None
                if nl >= 0:
                    raw = bytes(buf[:nl])
                    del buf[:nl + 1]
                else:
                    # Try to parse a single object from the head of buf.
                    try:
                        obj, idx = json.JSONDecoder().raw_decode(
                            buf.decode("utf-8", errors="replace"))
                        raw = json.dumps(obj).encode()
                        del buf[:idx]
                    except ValueError:
                        break

                if not raw.strip():
                    continue
                try:
                    msg = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(msg, dict):
                    continue

                mt  = msg.get("msg_type", "?")
                src = str(msg.get("source", "?"))[:8]
                dst = str(msg.get("destination", "?"))[:8]
                payload = _decode_payload(msg.get("msg", ""), mt)
                counts[mt] = counts.get(mt, 0) + 1

                if mt == "Sensor:Get Tasks" or mt == "Sensor:Track Update":
                    sid = msg.get("source", "")
                    if sid:
                        sensor_ids.add(sid)
                if mt == "Sensor:Track Update" and isinstance(payload, dict):
                    for t in payload.get("tracks") or []:
                        if isinstance(t, dict) and t.get("track_id"):
                            track_ids.add(t["track_id"])

                print(f"  {mt:<32} {src}  {dst}  {_fmt(payload, mt)}")
    except KeyboardInterrupt:
        print("\n[+] Interrupted.")
    finally:
        try: s.close()
        except OSError: pass

    if not counts:
        print("\n[!] No messages observed in window.")
        print("    Possible causes (Controller.md §Worker Message Flow):")
        print("      - we are a follower; workers are rejected at our")
        print("        HTTP ingress and never reach Received() fan-out")
        print("      - comms daemon is down or network partitioned")
        print("      - swarm is already dead")
        print("    Run:  python3 check_leader.py   to disambiguate.")

    print(f"\n[+] summary:")
    for k, v in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"    {v:>4}  {k}")
    if sensor_ids:
        print(f"\n[+] sensor IDs seen ({len(sensor_ids)}):")
        for sid in sorted(sensor_ids):
            print(f"    {sid}")
    if track_ids:
        print(f"\n[+] track IDs seen ({len(track_ids)}):")
        for tid in sorted(track_ids):
            print(f"    {tid}")


if __name__ == "__main__":
    main()
