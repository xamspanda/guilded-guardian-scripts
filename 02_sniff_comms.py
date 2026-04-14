#!/usr/bin/env python3
"""
offense/02_sniff_comms.py

Reads the local comms Unix socket and prints decoded transmissions.
Defaults to the comms socket from /tmp/recon.json when available.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gg_core  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--recon", default=gg_core.DEFAULT_RECON_PATH)
    ap.add_argument("--socket", default="")
    ap.add_argument("--seconds", type=int, default=15)
    ap.add_argument("--filter", default="", help="only print msg_types containing this substring")
    args = ap.parse_args()

    comms_sock = args.socket
    if not comms_sock:
        recon = gg_core.load_recon(args.recon)
        comms_sock = recon.get("comms_socket", "")
    if not comms_sock:
        print("ERROR: comms socket path not provided and not present in recon", file=sys.stderr)
        return 2

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect(comms_sock)
    except OSError as e:
        print(gg_core.format_socket_error(comms_sock, e, action="connect to"), file=sys.stderr)
        s.close()
        return 2

    print(f"Listening on {comms_sock} for {args.seconds}s (filter={args.filter!r})...")
    deadline = time.time() + args.seconds
    buf = b""

    try:
        while time.time() < deadline:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            buf += chunk
            consumed = 0
            for line in gg_core.iter_ndjson(buf):
                consumed += len(line) + 1
                try:
                    tx = gg_core.Transmission.from_json_bytes(line)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if args.filter and args.filter not in tx.msg_type:
                    continue
                payload, perr = tx.decode_payload()
                marker = "" if not perr else f"  [PAYLOAD-ERR: {perr}]"
                print(
                    f"[{tx.msg_type}] src={tx.source} dst={tx.destination}"
                    f"  endorsements={len(tx.authority.endorsements)}{marker}"
                )
                if payload is not None:
                    print(f"  payload={json.dumps(payload, sort_keys=True)}")
            buf = buf[consumed:]
    finally:
        s.close()

    print("\nDone sniffing.")
    return 0


if __name__ == "__main__":
    sys.exit(gg_core.run_main(main))
