#!/usr/bin/env python3
# USAGE ON SWARM NODES (NixOS):
#   Upload to /tmp/payloads/10_config_recon.py, then run it with the full Python path:
#     /run/current-system/sw/bin/python3 /tmp/payloads/10_config_recon.py [args]
#   If launching through Sliver, use:
#     execute -o /run/current-system/sw/bin/python3 -- /tmp/payloads/10_config_recon.py [args]
#   Common helper binaries are also under /run/current-system/sw/bin/, e.g.:
#     /run/current-system/sw/bin/cat
#     /run/current-system/sw/bin/ls
#     /run/current-system/sw/bin/bash
"""
offense/10_config_recon.py

Pre-flight reconnaissance: dumps the active node config.yaml, infers
node role from the daemon/socket layout, and emits a machine-readable
summary for downstream scripts.
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
    ap.add_argument("--out", default="-", help="output JSON path; - for stdout")
    args = ap.parse_args()

    out_path = gg_core.DEFAULT_RECON_PATH if args.out == "-" else args.out
    summary = gg_core.do_recon(out_path=out_path)
    payload = json.dumps(summary, indent=2)
    if args.out == "-":
        print(payload)
    else:
        print(f"[+] wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(gg_core.run_main(main))
