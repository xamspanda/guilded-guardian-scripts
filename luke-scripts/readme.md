# Mantis Toolkit — Team Quick Reference

---

## `mantis.py` — One-Shot Takedown *(run first)*

Auto-detects node type (controller / sensor / boomer), recons it, runs the appropriate kill chain or divert primitive.

**Modes:** `recon` | `kill` | `divert` | `auto` *(default)*

**Good output:** `Node type: controller`, `Leader confirmed (N endorsements)`, `shutdowns=21/21`, `pulse N: X/Y via sqlite`

| Error | Cause | Fix |
|---|---|---|
| `No Mantis config found` | Not on a Mantis node, or wrong config path | `CONTROLLER_CONFIG_PATH=/x/y python3 mantis.py` |
| `Never observed leadership` | RAFT hardened | Escalate to `replace_election_socket.py` |
| `No gps_db_path found` | Sensor config missing DB path | `ls -la /var/lib/*/tracks.db` and `cat $SENSOR_CONFIG_PATH` |
| `Comms socket unreachable` | Daemon crashed or permission issue | Run recon first, don't kill |

> If kill chain reports success but scoreboard still shows live workers → survivors aren't polling us. Move to another controller/sensor.

---

## `check_leader.py` — 5-Second Leader Verification

Connects to the election Unix socket, prints leader status. Exit codes: `0`=leader, `1`=not-leader, `2`=error.

**Good output:** `LEADER: YES (3 endorsements)` with endorser UUIDs

| Output | Meaning |
|---|---|
| `LEADER: NO` | We're a follower — kill won't work yet |
| `election socket does not exist` | Wrong node type (sensor/boomer have none) |
| `non-JSON response` | Socket already replaced by a teammate |

**Shell usage:**
```bash
if python3 check_leader.py; then python3 mantis.py kill; fi
```
Also use after `replace_election_socket.py` to confirm forged COA is being served.

---

## `replace_election_socket.py` — RAFT-Hardened Fallback

Kills the local election daemon, binds our server on its socket path, serves a forged Certificate of Authority. Makes local comms think we're leader.

**Run when:** `mantis.py kill` reports `Never observed leadership`

**Prereq:** `pkill -f election` first (it holds the bind)

**Good output:** `Serving forged COA on /path/to/socket` → `Now run: python3 mantis.py kill`

| Error | Fix |
|---|---|
| `permission denied on unlink` | Election daemon still running — pkill it |
| `bind failed` | Socket path still held — wait 2s, retry |

> Leave running in background (`&` or Sliver background task), then re-run `mantis.py kill` in a new session. Ctrl-C when done.

---

## `sniff_comms.py` — Passive Intel Tap

Subscribes to local comms socket, prints all inbound messages. **Read-only.**

**Usage:** `python3 sniff_comms.py [seconds]` — default 30s, `0` = until Ctrl-C

**Good output:** Live stream of `msg_type src dst payload`, then summary of sensor IDs and track IDs seen.

**What it tells you:**
- Which controller is currently leader (watch `Election:Endorsement Response`)
- Live track IDs (divert targets) and sensor UUIDs
- Whether workers are polling us (if we see `Get Tasks`, we're their leader)

| Error | Meaning |
|---|---|
| `comms socket does not exist` | Wrong node type or daemon dead |
| No traffic in 30s | Network partition, or comms killed by mistake |

> Run **before** kill/divert to confirm targets. Run **after** to confirm silence.

---

## Overall Playbook

```
1. python3 mantis.py recon          # orient
2. python3 sniff_comms.py 20        # observe
3. python3 mantis.py auto           # execute
4. If RAFT resists:
     pkill -f election && python3 replace_election_socket.py &
     python3 mantis.py kill         # retry
5. python3 check_leader.py          # confirm
   → scoreboard to validate kill
```