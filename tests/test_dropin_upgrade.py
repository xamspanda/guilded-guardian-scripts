from __future__ import annotations

import importlib.util
import json
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


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_gg_core_module_exists_and_parses_minimal_yaml(tmp_path: Path):
    gg_core = load_module("gg_core", SCRIPTS_DIR / "gg_core.py")
    parsed = gg_core.parse_yaml_minimal(
        "\n".join(
            [
                'id: "controller-1"',
                'verify_signatures: false',
                'listen_port: 10000',
                'controllers:',
                '  - {uuid: "c2", ip: "172.20.1.2"}',
                'sensors:',
                '  - {uuid: "s1"}',
                'boomers:',
                '  - {uuid: "b1"}',
            ]
        )
    )

    assert parsed["id"] == "controller-1"
    assert parsed["verify_signatures"] is False
    assert parsed["listen_port"] == 10000
    assert parsed["controllers"] == [{"uuid": "c2", "ip": "172.20.1.2"}]
    assert parsed["sensors"] == [{"uuid": "s1"}]
    assert parsed["boomers"] == [{"uuid": "b1"}]


def test_gg_core_loads_recon_and_derives_workers(tmp_path: Path):
    gg_core = load_module("gg_core", SCRIPTS_DIR / "gg_core.py")
    recon_path = tmp_path / "recon.json"
    recon_path.write_text(
        json.dumps(
            {
                "our_uuid": "ctrl-1",
                "comms_socket": "/run/commsDaemon/comms.sock",
                "election_socket": "/run/electionDaemon/election.sock",
                "peer_controllers": [{"uuid": "ctrl-2", "ip": "172.20.1.2"}],
                "sensors": [{"uuid": "sens-1"}],
                "boomers": [{"uuid": "boom-1"}, {"uuid": "boom-2"}],
            }
        )
    )

    recon = gg_core.load_recon(str(recon_path))
    assert recon["our_uuid"] == "ctrl-1"
    assert gg_core.worker_uuids(recon) == ["sens-1", "boom-1", "boom-2"]
    assert gg_core.peer_controller_uuids(recon) == ["ctrl-2"]


def test_active_scripts_no_longer_require_placeholder_substitution():
    offenders = []
    for name in ACTIVE_SCRIPTS:
        text = (SCRIPTS_DIR / name).read_text()
        has_placeholder = any(token in text for token in [
            "__OUR_UUID__",
            "__COMMS_SOCKET_PATH__",
            "__ELECTION_SOCKET_PATH__",
            "__PEER_LIST__",
            "__SENSOR_LIST__",
            "__BOOMER_LIST__",
        ])
        if has_placeholder or "from shared." in text:
            offenders.append(name)
    assert offenders == []
