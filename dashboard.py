#!/usr/bin/env python3
"""
defense/dashboard.py

Live terminal dashboard for the blue-team watch floor. Reads NDJSON
findings from stdin (typically piped from `run_all.py live`), keeps a
rolling severity histogram, and shows the most recent CRITICAL/HIGH
events with mission-context highlights.

Zero external deps; pure curses. If the terminal does not support
curses (headless CI), falls back to line-mode summary every N seconds.

Usage:
    python3 -m defense.run_all live --findings-out - ... | \\
        python3 -m defense.dashboard

artifact_id:    gildedguardian-ctf-defense-dashboard
created:        2026-04-13T20:15Z
last_modified:  2026-04-13T20:15Z
stale_after:    2026-04-27T00:00Z
"""
from __future__ import annotations

import argparse
import collections
import curses
import json
import os
import select
import sys
import time
from typing import Any


SEVERITY_COLOR = {
    "CRITICAL": 1,   # red
    "HIGH":     2,   # yellow
    "MEDIUM":   3,   # cyan
    "LOW":      4,   # green
    "INFO":     5,   # white
}


def _setup_colors() -> None:
    if not curses.has_colors():
        return
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_RED,    -1)
    curses.init_pair(2, curses.COLOR_YELLOW, -1)
    curses.init_pair(3, curses.COLOR_CYAN,   -1)
    curses.init_pair(4, curses.COLOR_GREEN,  -1)
    curses.init_pair(5, curses.COLOR_WHITE,  -1)


def _read_one_finding(timeout: float = 0.1) -> dict[str, Any] | None:
    r, _, _ = select.select([sys.stdin], [], [], timeout)
    if not r:
        return None
    line = sys.stdin.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def _draw(stdscr, state: dict) -> None:
    stdscr.erase()
    h, w = stdscr.getmaxyx()

    # Header
    title = " GILDED GUARDIAN BLUE-TEAM WATCH FLOOR "
    stdscr.addstr(0, 0, title.center(w, "="), curses.A_BOLD)
    elapsed = int(time.time() - state["started"])
    stdscr.addstr(1, 0, f" runtime: {elapsed:5d}s   total findings: "
                        f"{state['total']:5d}   ingest rate: "
                        f"{state['rate']:.1f}/s ")

    # Severity histogram
    stdscr.addstr(3, 0, " severity histogram:", curses.A_BOLD)
    row = 4
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = state["hist"].get(sev, 0)
        bar = "#" * min(40, n)
        line = f"  {sev:9s} {n:5d}  {bar}"
        attr = curses.color_pair(SEVERITY_COLOR[sev]) | (
            curses.A_BOLD if sev == "CRITICAL" and n > 0 else 0
        )
        stdscr.addstr(row, 0, line[:w-1], attr)
        row += 1

    # Mission flags
    row += 1
    stdscr.addstr(row, 0, " mission status:", curses.A_BOLD)
    row += 1
    intercept_count = state["engage_errors"]
    cyber_window_breaches = state["cyber_window_breaches"]
    in_box_findings = state["in_box_findings"]

    intercept_attr = curses.color_pair(1) | curses.A_BOLD if intercept_count >= 3 else (
        curses.color_pair(2) if intercept_count >= 2 else 0)
    stdscr.addstr(row, 0, f"  failed intercepts:        {intercept_count}/3",
                  intercept_attr)
    row += 1
    stdscr.addstr(row, 0, f"  cyber window breaches:    {cyber_window_breaches}",
                  curses.color_pair(1) if cyber_window_breaches else 0)
    row += 1
    stdscr.addstr(row, 0, f"  in-box telemetry events:  {in_box_findings}")
    row += 2

    # Recent CRITICAL/HIGH
    stdscr.addstr(row, 0, " recent CRITICAL / HIGH (newest first):",
                  curses.A_BOLD)
    row += 1
    for f in state["recent"]:
        if row >= h - 1:
            break
        sev = f.get("severity", "INFO")
        tech = f.get("technique", "?")
        title = f.get("title", "")
        ts = f.get("occurred_at", 0)
        ago = max(0, int(time.time() - ts))
        line = f"  {ago:4d}s ago  {sev:9s}  {tech:12s}  {title}"
        stdscr.addstr(row, 0, line[:w-1],
                      curses.color_pair(SEVERITY_COLOR.get(sev, 5)))
        row += 1

    # Footer
    stdscr.addstr(h - 1, 0, " ctrl-c to exit ".ljust(w - 1, " "),
                  curses.A_REVERSE)
    stdscr.refresh()


def _update_state(state: dict, f: dict) -> None:
    state["total"] += 1
    sev = f.get("severity", "INFO")
    state["hist"][sev] = state["hist"].get(sev, 0) + 1

    # Mission tracking
    tech = f.get("technique", "")
    ev   = f.get("evidence", {}) or {}
    if tech == "GG-T17.X.2":
        # Use the highest count seen
        state["engage_errors"] = max(state["engage_errors"],
                                     int(ev.get("count", 0)))
    if tech == "GG-T17.X.1":
        state["cyber_window_breaches"] += 1
    if ev.get("_mission_overlay_bumped_for"):
        if "position_in_kill_box" in ev["_mission_overlay_bumped_for"]:
            state["in_box_findings"] += 1
    if tech == "GG-T4.1.2":
        state["in_box_findings"] += 1

    if sev in ("CRITICAL", "HIGH"):
        state["recent"].appendleft(f)


def _curses_main(stdscr, args) -> int:
    curses.curs_set(0)
    stdscr.nodelay(True)
    _setup_colors()
    state = {
        "started":  time.time(),
        "total":    0,
        "hist":     {},
        "recent":   collections.deque(maxlen=args.recent),
        "engage_errors":         0,
        "cyber_window_breaches": 0,
        "in_box_findings":       0,
        "rate":     0.0,
        "_window_start": time.time(),
        "_window_count": 0,
    }
    last_draw = 0.0
    try:
        while True:
            f = _read_one_finding(timeout=0.05)
            if f is not None:
                _update_state(state, f)
                state["_window_count"] += 1
            now = time.time()
            window_age = now - state["_window_start"]
            if window_age >= 1.0:
                state["rate"] = state["_window_count"] / window_age
                state["_window_start"] = now
                state["_window_count"] = 0
            if now - last_draw >= 0.2:
                _draw(stdscr, state)
                last_draw = now
            try:
                ch = stdscr.getch()
                if ch in (ord("q"), ord("Q"), 27):
                    return 0
            except curses.error:
                pass
    except KeyboardInterrupt:
        return 0


def _line_main(args) -> int:
    """Fallback when no TTY: print histogram every N seconds."""
    started = time.time()
    hist: dict[str, int] = {}
    last_print = 0.0
    print(f"[dashboard] line-mode (no TTY); summary every {args.line_interval}s",
          file=sys.stderr)
    try:
        while True:
            f = _read_one_finding(timeout=0.5)
            if f is not None:
                sev = f.get("severity", "INFO")
                hist[sev] = hist.get(sev, 0) + 1
            now = time.time()
            if now - last_print >= args.line_interval:
                elapsed = int(now - started)
                parts = " ".join(f"{s}={hist.get(s,0)}"
                                 for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"))
                print(f"[t+{elapsed}s] {parts}", file=sys.stderr)
                last_print = now
    except KeyboardInterrupt:
        return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--recent",         type=int, default=15)
    ap.add_argument("--line-interval",  type=int, default=5)
    args = ap.parse_args()

    if not sys.stdout.isatty() or os.environ.get("TERM") in (None, "dumb"):
        return _line_main(args)
    try:
        return curses.wrapper(_curses_main, args)
    except curses.error:
        return _line_main(args)


if __name__ == "__main__":
    sys.exit(main())
