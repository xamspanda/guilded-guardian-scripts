# guilded-guardian-scripts

Guilded Guardian script kit for team sharing and collaborative improvement.

## Contents

- Offensive workflow scripts:
  - `00_one_shot.py`
  - `01_check_leader.py`
  - `02_sniff_comms.py`
  - `03_win_election.py`
  - `04_replace_election_socket.py`
  - `05_kill_swarm.py`
  - `06_takeover_combined.py`
  - `10_config_recon.py`
  - `20_mission_aware_kill.py`
- Shared helpers:
  - `gg_core.py`
  - `transmission.py`
  - `events.py`
  - `shared/`
- Support/defense utilities:
  - `config_audit.py`
  - `dashboard.py`
  - `election_sampler.py`
- Regression tests:
  - `tests/test_dropin_upgrade.py`
  - `tests/test_graceful_failures.py`

## Quick start

Clone the repo:

```bash
git clone git@github.com:xamspanda/guilded-guardian-scripts.git
cd guilded-guardian-scripts
```

Run the regression tests with `uv`:

```bash
uv run --with pytest python -m pytest tests/test_dropin_upgrade.py tests/test_graceful_failures.py -q
```

## Team workflow

1. Pull the latest changes before editing.
2. Make focused commits with clear messages.
3. Re-run the tests before pushing.
4. Push to your branch or directly to `main`, depending on your team policy.

A more detailed setup/commit walkthrough can be shared separately with the team.
