#!/usr/bin/env python3
# USAGE ON SWARM NODES (NixOS):
#   Upload to /tmp/payloads/01_check_leader.py, then run it with the full Python path:
#     /run/current-system/sw/bin/python3 /tmp/payloads/01_check_leader.py [args]
#   If launching through Sliver, use:
#     execute -o /run/current-system/sw/bin/python3 -- /tmp/payloads/01_check_leader.py [args]
#   Common helper binaries are also under /run/current-system/sw/bin/, e.g.:
#     /run/current-system/sw/bin/cat
#     /run/current-system/sw/bin/ls
#     /run/current-system/sw/bin/bash
"""
offense/01_check_leader.py

Reads the local election Unix socket and reports whether the current
node holds leadership. Defaults to values from /tmp/recon.json when
available so no placeholder edits are required.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gg_core  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--recon", default=gg_core.DEFAULT_RECON_PATH)
    ap.add_argument("--socket", default="")
    args = ap.parse_args()

    election_sock = args.socket
    if not election_sock:
        recon = gg_core.load_recon(args.recon)
        election_sock = recon.get("election_socket", "")
    if not election_sock:
        print("ERROR: election socket path not provided and not present in recon", file=sys.stderr)
        return 2

    try:
        coa = gg_core.read_coa(election_sock)
    except OSError as e:
        print(f"ERROR: cannot reach {election_sock}: {e}", file=sys.stderr)
        return 2

    if coa.is_empty():
        print("LEADER: NO")
        return 1

    print(f"LEADER: YES ({len(coa.endorsements)} endorsements)")
    for e in coa.endorsements:
        print(
            f"  endorser={e.endorser}  endorsee={e.endorsee}  "
            f"valid_after={e.valid_after}  expires={e.expiration}"
        )
    print()
    print("Full COA:")
    print(json.dumps(coa.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(gg_core.run_main(main))
