#!/usr/bin/env python3
"""
offense/20_mission_aware_kill.py

Variant of kill_swarm.py that orders boomer Shutdowns by available
position data in recon.json. If no coordinates are present, falls back
to alphabetical order. This version is self-contained and does not rely
on missing shared geo/intel modules.
"""
from __future__ import annotations

import argparse
import math
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gg_core  # noqa: E402


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def boomer_priority(boomer: dict) -> tuple[int, float, str]:
    lat = boomer.get("lat")
    lon = boomer.get("lon")
    uuid = str(boomer.get("uuid", ""))
    if lat is None or lon is None:
        return (2, 1e9, uuid)
    try:
        lat_f = float(lat)
        lon_f = float(lon)
    except (TypeError, ValueError):
        return (2, 1e9, uuid)
    dist = haversine_km(lat_f, lon_f, 0.0, 0.0)
    return (0, dist, uuid)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--recon", default=gg_core.DEFAULT_RECON_PATH)
    ap.add_argument("--coa", default=gg_core.DEFAULT_COA_PATH)
    ap.add_argument("--dwell", type=float, default=0.0, help="seconds to sleep between sends")
    args = ap.parse_args()

    recon = gg_core.load_recon(args.recon)
    coa = gg_core.load_coa(args.coa)
    if coa.is_empty():
        raise SystemExit("[!] COA empty; cannot send authorized Shutdown")
    comms_sock = recon.get("comms_socket", "")
    src = recon.get("our_uuid", "")
    if not comms_sock or not src:
        print("[!] recon is missing our_uuid or comms_socket", file=sys.stderr)
        return 2

    sensors = list(recon.get("sensors", []) or [])
    boomers = list(recon.get("boomers", []) or [])
    boomers_sorted = sorted(boomers, key=boomer_priority)

    print("[plan] boomer kill order (rank, distance_km, uuid):")
    for boomer in boomers_sorted[:10]:
        rank, dist, uuid = boomer_priority(boomer)
        marker = " <- coordinates present" if rank == 0 else ""
        print(f"  rank={rank}  dist={dist:7.1f}  {uuid[:8]}...{marker}")
    if len(boomers_sorted) > 10:
        print(f"  ... and {len(boomers_sorted) - 10} more")

    comms = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        comms.connect(comms_sock)
    except OSError as e:
        print(gg_core.format_socket_error(comms_sock, e, action="connect to"), file=sys.stderr)
        comms.close()
        return 2
    sent = 0
    for item in boomers_sorted + sensors:
        uuid = item.get("uuid")
        if not uuid:
            continue
        comms.sendall(gg_core.make_shutdown_tx(src, uuid, coa, b64_payload=True))
        comms.sendall(gg_core.make_shutdown_tx(src, uuid, coa, b64_payload=False))
        sent += 1
        if args.dwell:
            time.sleep(args.dwell)
    comms.close()
    print(f"[kill] sent prioritized Shutdowns to {sent} workers ({len(boomers_sorted)} boomers, {len(sensors)} sensors)")
    return 0


if __name__ == "__main__":
    sys.exit(gg_core.run_main(main))
