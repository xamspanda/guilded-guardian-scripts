#!/usr/bin/env python3
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
