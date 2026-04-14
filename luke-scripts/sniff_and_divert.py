"""
sniff_and_divert.py - ELCOA-aware intel + auto divert.

1. Sniffs comms socket for live track positions.
2. Matches track positions against ELCOA kill boxes to identify
   which option (A/B/C) is active.
3. Selects divert coords near the LAUNCH POINT for that option —
   boomer burns fuel flying away from target fast instead of
   drifting to a distant ocean dump.
4. Launches mantis_sensor_fast.py with the optimal coords.

Usage:
    python3 sniff_and_divert.py          # sniff 15s then auto-divert
    python3 sniff_and_divert.py --sniff  # sniff only, print intel
    python3 sniff_and_divert.py --time 30  # longer sniff window
"""

import base64
import glob
import json
import math
import os
import re
import socket
import subprocess
import sys
import time

# ============================================================================
#  ELCOA GEOMETRY (RRII ELCOA MANTIS DTG 101200EDT APR 2026)
# ============================================================================

ELCOA = {
    "A": {
        "name":       "Option A — Northern Long-Range",
        "threat":     "MODERATE",
        "launch_lat":  51.7479,
        "launch_lon": -55.9452,
        "box_centre_lat":  49.25816,
        "box_centre_lon": -61.89061,
        "box_tr": (49.34113, -61.81444),
        "box_bl": (49.17519, -61.96677),
        # Divert: midpoint between launch and kill box — boomer
        # turns around and heads back toward launch, burns fuel fast.
        "divert_lat":  50.50,
        "divert_lon": -58.92,
    },
    "B": {
        "name":       "Option B — Southern Oblique",
        "threat":     "HIGH",
        "launch_lat":  46.1508,
        "launch_lon": -56.8084,
        "box_centre_lat":  49.15372,
        "box_centre_lon": -61.76423,
        "box_tr": (49.19543, -61.71626),
        "box_bl": (49.11200, -61.81220),
        "divert_lat":  47.65,
        "divert_lon": -59.29,
    },
    "C": {
        "name":       "Option C — Central Direct Strike",
        "threat":     "CRITICAL",
        "launch_lat":  50.1402,
        "launch_lon": -55.1881,
        "box_centre_lat":  49.3161,
        "box_centre_lon": -62.0149,
        "box_tr": (49.3676, -61.9719),
        "box_bl": (49.2646, -62.0578),
        "divert_lat":  49.73,
        "divert_lon": -58.60,
    },
}

# ============================================================================
#  GEO
# ============================================================================

def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0
    dl = math.radians(lat2 - lat1)
    dg = math.radians(lon2 - lon1)
    a = (math.sin(dl/2)**2 +
         math.cos(math.radians(lat1)) *
         math.cos(math.radians(lat2)) *
         math.sin(dg/2)**2)
    return R * 2 * math.asin(math.sqrt(a))


def point_in_box(lat, lon, tr, bl):
    """Bounding box check (tr=top-right, bl=bottom-left)."""
    return (bl[0] <= lat <= tr[0] and tr[1] <= lon <= bl[1])


def match_elcoa(lat, lon):
    """Return (option_key, elcoa_dict, dist_km) for nearest kill box."""
    best_key  = None
    best_data = None
    best_dist = float("inf")
    for key, e in ELCOA.items():
        if point_in_box(lat, lon, e["box_tr"], e["box_bl"]):
            return key, e, 0.0
        d = haversine_km(lat, lon, e["box_centre_lat"], e["box_centre_lon"])
        if d < best_dist:
            best_dist = d
            best_key  = key
            best_data = e
    return best_key, best_data, best_dist

# ============================================================================
#  CONFIG / SOCKET
# ============================================================================

ENV_KEYS = ("CONTROLLER_CONFIG_PATH", "SENSOR_CONFIG_PATH",
            "BOOMER_CONFIG_PATH", "CONFIG_PATH")

def _scalar(v):
    v = v.strip().strip('"').strip("'")
    low = v.lower()
    if low in ("null", "~", "none", ""): return None
    if low == "true":  return True
    if low == "false": return False
    try: return int(v)
    except ValueError: pass
    try: return float(v)
    except ValueError: pass
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

def find_comms_socket():
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

# ============================================================================
#  DECODE
# ============================================================================

def decode_payload(msg):
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

# ============================================================================
#  SNIFF
# ============================================================================

def sniff(cs, duration=15.0):
    """Returns dict with track observations, sensor IDs, boomer IDs."""
    print(f"[*] Sniffing {cs} for {duration:.0f}s...")

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(1.0)
    s.connect(cs)

    deadline = time.time() + duration
    buf      = bytearray()
    counts   = {}
    tracks   = {}   # track_id -> (lat, lon, sensor_id)
    sensors  = set()
    boomers  = set()

    try:
        while time.time() < deadline:
            try:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf.extend(chunk)
            except socket.timeout:
                continue
            except OSError:
                break

            while True:
                nl = buf.find(b"\n")
                if nl >= 0:
                    raw = bytes(buf[:nl])
                    del buf[:nl+1]
                else:
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
                src = msg.get("source", "")
                counts[mt] = counts.get(mt, 0) + 1

                if mt in ("Sensor:Get Tasks", "Sensor:Track Update"):
                    if src:
                        sensors.add(src)

                if mt == "Boomer:Get Tasks":
                    if src:
                        boomers.add(src)

                if mt == "Sensor:Track Update":
                    payload = decode_payload(msg.get("msg", ""))
                    if isinstance(payload, dict):
                        for t in payload.get("tracks") or []:
                            if not isinstance(t, dict):
                                continue
                            tid = t.get("track_id")
                            lat = t.get("latitude")
                            lon = t.get("longitude")
                            if tid and lat is not None and lon is not None:
                                tracks[tid] = (float(lat), float(lon), src)

    except KeyboardInterrupt:
        pass
    finally:
        try: s.close()
        except OSError: pass

    return {
        "counts":  counts,
        "tracks":  tracks,
        "sensors": sensors,
        "boomers": boomers,
    }

# ============================================================================
#  INTEL PRINT
# ============================================================================

def print_intel(result):
    print("\n" + "="*60)
    print("  COMMS INTEL")
    print("="*60)

    print(f"\nMessage counts:")
    for k, v in sorted(result["counts"].items(), key=lambda x: -x[1]):
        print(f"  {v:>4}  {k}")

    print(f"\nSensors seen ({len(result['sensors'])}):")
    for s in sorted(result["sensors"]):
        print(f"  {s}")

    print(f"\nBoomers seen ({len(result['boomers'])}):")
    for b in sorted(result["boomers"]):
        print(f"  {b}")

    print(f"\nTracks ({len(result['tracks'])}):")
    for tid, (lat, lon, src) in result["tracks"].items():
        key, e, dist = match_elcoa(lat, lon)
        in_box = "IN BOX" if dist == 0.0 else f"{dist:.0f}km from box"
        print(f"  {str(tid):<36}  {lat:.4f}, {lon:.4f}  "
              f"-> {key} ({in_box})  sensor={str(src)[:8]}")

# ============================================================================
#  ELCOA DETECTION
# ============================================================================

def detect_active_elcoa(tracks):
    """Vote on which ELCOA is active based on track positions."""
    votes = {"A": 0, "B": 0, "C": 0}
    for tid, (lat, lon, _) in tracks.items():
        key, e, dist = match_elcoa(lat, lon)
        if dist < 200.0:   # within 200km of a kill box = credible vote
            votes[key] += 1

    if not any(votes.values()):
        return None, None

    winner = max(votes, key=lambda k: votes[k])
    return winner, ELCOA[winner]

# ============================================================================
#  MAIN
# ============================================================================

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--sniff",  action="store_true", help="intel only, no divert")
    ap.add_argument("--time",   type=float, default=15.0, help="sniff window seconds")
    ap.add_argument("--socket", default=None, help="explicit comms socket path")
    args = ap.parse_args()

    cs = args.socket or find_comms_socket()
    if not cs:
        print("[!] comms socket not found in any config")
        sys.exit(2)
    if not os.path.exists(cs):
        print(f"[!] comms socket missing: {cs}")
        sys.exit(2)

    result = sniff(cs, args.time)
    print_intel(result)

    option, elcoa = detect_active_elcoa(result["tracks"])

    if not option:
        print("\n[!] Could not determine active ELCOA from track positions.")
        print("    No tracks observed or all >200km from kill boxes.")
        print("    Run with longer --time window, or check if you are leader.")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  ACTIVE ELCOA: {option}  —  {elcoa['name']}")
    print(f"  Threat level: {elcoa['threat']}")
    print(f"  Launch point: {elcoa['launch_lat']}N / {elcoa['launch_lon']}W")
    print(f"  Kill box:     {elcoa['box_centre_lat']}N / {elcoa['box_centre_lon']}W")
    print(f"  Divert to:    {elcoa['divert_lat']}N / {elcoa['divert_lon']}W")
    print(f"  (midpoint toward launch — boomer burns fuel heading back)")
    print(f"{'='*60}")

    dist_to_launch = haversine_km(
        elcoa["box_centre_lat"], elcoa["box_centre_lon"],
        elcoa["divert_lat"],     elcoa["divert_lon"],
    )
    print(f"\n  Divert point is {dist_to_launch:.0f}km from kill box centre")
    print(f"  Boomer will turn ~180 degrees and head away from target\n")

    if args.sniff:
        print("[*] --sniff mode. Not launching divert.")
        return

    # Launch mantis_sensor_fast.py with optimal coords
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "mantis_sensor_fast.py")
    if not os.path.exists(script):
        print(f"[!] mantis_sensor_fast.py not found at {script}")
        print(f"    Run manually:")
        print(f"    python3 mantis_sensor_fast.py "
              f"--lat {elcoa['divert_lat']} --lon {elcoa['divert_lon']}")
        return

    python = sys.executable
    cmd = [
        python, script,
        "--lat", str(elcoa["divert_lat"]),
        "--lon", str(elcoa["divert_lon"]),
    ]
    print(f"[*] Launching: {' '.join(cmd)}")
    os.execv(python, cmd)   # replace this process — no orphan


if __name__ == "__main__":
    main()
