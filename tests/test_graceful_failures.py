from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent
ACTIVE_SCRIPTS = [
    "00_one_shot.py",
    "01_check_leader.py",
    "02_sniff_comms.py",
    "03_win_election.py",
    "04_replace_election_socket.py",
    "05_kill_swarm.py",
    "06_takeover_combined.py",
    "10_config_recon.py",
    "20_mission_aware_kill.py",
]


def run_script(name: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / name), *args],
        text=True,
        capture_output=True,
        cwd=SCRIPTS_DIR,
    )


def test_active_scripts_report_errors_without_tracebacks(tmp_path: Path):
    bad_recon = tmp_path / "bad_recon.json"
    bad_recon.write_text("{not valid json")

    cases = [
        ("00_one_shot.py", []),
        ("01_check_leader.py", ["--recon", str(bad_recon)]),
        ("02_sniff_comms.py", ["--recon", str(bad_recon)]),
        ("03_win_election.py", ["--recon", str(bad_recon)]),
        ("04_replace_election_socket.py", ["--recon", str(bad_recon)]),
        ("05_kill_swarm.py", ["--recon", str(bad_recon)]),
        ("06_takeover_combined.py", ["--recon", str(bad_recon)]),
        ("10_config_recon.py", []),
        ("20_mission_aware_kill.py", ["--recon", str(bad_recon)]),
    ]

    offenders: list[tuple[str, int, str]] = []
    for name, extra in cases:
        proc = run_script(name, *extra)
        combined = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode == 0 or "Traceback (most recent call last):" in combined:
            offenders.append((name, proc.returncode, combined))

    assert offenders == []


def test_bad_coa_file_reports_clear_error_without_traceback(tmp_path: Path):
    recon = tmp_path / "recon.json"
    recon.write_text(
        '{"our_uuid": "ctrl-1", "comms_socket": "/tmp/missing-comms.sock", '
        '"election_socket": "/tmp/missing-election.sock", "sensors": [], "boomers": []}'
    )
    bad_coa = tmp_path / "bad_coa.json"
    bad_coa.write_text("{not valid json")

    cases = [
        ("04_replace_election_socket.py", ["--socket", "/tmp/test-election.sock", "--coa", str(bad_coa)]),
        ("05_kill_swarm.py", ["--recon", str(recon), "--coa-file", str(bad_coa)]),
        ("06_takeover_combined.py", ["--recon", str(recon), "--coa", str(bad_coa)]),
        ("20_mission_aware_kill.py", ["--recon", str(recon), "--coa", str(bad_coa)]),
    ]

    offenders: list[tuple[str, int, str]] = []
    for name, extra in cases:
        proc = run_script(name, *extra)
        combined = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode == 0 or "Traceback (most recent call last):" in combined or "coa" not in combined.lower():
            offenders.append((name, proc.returncode, combined))

    assert offenders == []


def test_socket_failures_are_reported_without_tracebacks(tmp_path: Path):
    recon = tmp_path / "recon.json"
    recon.write_text(
        '{"our_uuid": "ctrl-1", "comms_socket": "/tmp/definitely-missing-comms.sock", '
        '"election_socket": "/tmp/definitely-missing-election.sock", '
        '"peer_controllers": [{"uuid": "ctrl-2"}], "sensors": [{"uuid": "s1"}], "boomers": [{"uuid": "b1"}]}'
    )
    coa = tmp_path / "coa.json"
    coa.write_text('{"endorsements": [{"endorser": "ctrl-2", "endorsee": "ctrl-1"}]}')

    cases = [
        ("02_sniff_comms.py", ["--recon", str(recon)]),
        ("03_win_election.py", ["--recon", str(recon)]),
        ("05_kill_swarm.py", ["--recon", str(recon), "--coa-file", str(coa)]),
        ("06_takeover_combined.py", ["--recon", str(recon), "--coa", str(coa), "--serve-s", "0"]),
        ("20_mission_aware_kill.py", ["--recon", str(recon), "--coa", str(coa)]),
    ]

    offenders: list[tuple[str, int, str]] = []
    for name, extra in cases:
        proc = run_script(name, *extra)
        combined = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode == 0 or "Traceback (most recent call last):" in combined or "sock" not in combined.lower():
            offenders.append((name, proc.returncode, combined))

    assert offenders == []
