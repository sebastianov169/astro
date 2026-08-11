#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
live_xp_probe.py - Sonda REAL de XP de gema (inventory slot=5) para investigar
la cadencia de credito de XP del server de MitosisOG.

Uso:
  python live_xp_probe.py check <cuenta>   # smoke: login + 1 lectura
  python live_xp_probe.py idle <cuenta>    # 3 lecturas separadas 60s, SIN spawn TCP
  python live_xp_probe.py ffa <cuenta>     # FFA spawn TCP + lecturas en vivo + HvZ

Login 100% Python (KNOCK -> LIM M2XC -> EH) con el PEM de atestacion FAKE del
device (mismo que usa la app Astro: %LOCALAPPDATA%/Astro/fake_tpm/<md5(did)16>.pem).
La cuenta sale siempre en lobby CTF al terminar (igual que el refresh de la app).
"""
import os, sys, json, time, hashlib, base64, random, urllib.parse, threading, importlib.util, socket, struct

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(SCRIPT_DIR)
if REPO_DIR not in sys.path:
    sys.path.insert(0, REPO_DIR)

# --- importar tcp_full + full_login_and_api (ya se importan entre si) ---
spec = importlib.util.spec_from_file_location("tcp_full", os.path.join(REPO_DIR, "tcp_full.py"))
tcp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tcp)

api_full = tcp.api_full
eb = api_full.eb
m2xc_encrypt_full = api_full.m2xc_encrypt_full
m2xc_decrypt_full = api_full.m2xc_decrypt_full
m2xc_fmt = api_full.m2xc_fmt
parse_m2xc_blob = api_full.parse_m2xc_blob
build_dtf = api_full.build_dtf
build_proof = api_full.build_proof
build_mid = api_full.build_mid
str_dest = api_full.str_dest
ENGINE = tcp.ENGINE
VER = tcp.VER
CHARSET = tcp.CHARSET
M = tcp.M
DESKTOP = tcp.DESKTOP

# --- silenciar el TrafficLogger de tcp_full (solo lineas clave) ---
KEEP = ("SPAWNED", "suffix", "SUFFIX", "No greeting", "ERROR", "spawned=", "No server/token",
        "TCP CONNECT FAILED", "Got PLAYER_ID")
def _qlog(msg):
    if any(k.lower() in str(msg).lower() for k in KEEP):
        print("[tcp] %s" % msg, flush=True)
    with open(os.path.join(SCRIPT_DIR, "live_xp_probe_tcp.log"), "a", encoding="utf-8") as f:
        f.write("%s %s\n" % (time.strftime("%H:%M:%S"), msg))
def _qhex(label, data, extra=""):
    pass
def _qsave(*a, **k):
    pass
def _qlogudp(label, data, extra=""):
    pass
tcp.TL.log = _qlog
tcp.TL.log_hex = _qhex
tcp.TL.log_udp = _qlogudp
tcp.TL.save_packet = _qsave

# ============================================================
# log local
# ============================================================
def log(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    with open(os.path.join(SCRIPT_DIR, "live_xp_probe.log"), "a", encoding="utf-8") as f:
        f.write(line + "\n")

# ============================================================
# cuentas (accounts.json de la app) + PEM fake_tpm del device
# ============================================================
ACCOUNTS_JSON = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Astro", "accounts.json")

def load_account(name):
    with open(ACCOUNTS_JSON, encoding="utf-8") as f:
        accs = json.load(f)
    for a in accs:
        if a.get("name", "").lower() == name.lower():
            return a
    raise SystemExit("cuenta '%s' no encontrada en %s" % (name, ACCOUNTS_JSON))

def pem_for_device(device):
    md5 = hashlib.md5(device.encode("utf-8")).hexdigest()[:16]
    p = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Astro", "fake_tpm", md5 + ".pem")
    if not os.path.exists(p):
        raise SystemExit("PEM de atestacion no existe: %s" % p)
    return p

# ============================================================
# login con device + PEM propios (mismo flujo que la app)
# ============================================================
def load_app_pem(path):
    """Carga la PEM PKCS#1 que escribe la app. La app genera qinv como p^-1 mod q
    (valor del blob BCrypt ANTES de su swap p/q) y `cryptography` (estricto) exige
    qinv == q^-1 mod p: se reconstruye la clave con el qinv corregido. La clave
    publica (n, e) queda identica -> mismo MID/proof que usa la app."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
    with open(path, "rb") as f:
        data = f.read()
    try:
        return serialization.load_pem_private_key(data, password=None)
    except Exception:
        pass
    lines = [l for l in data.split(b"\n") if l and not l.startswith(b"-----")]
    der = base64.b64decode(b"".join(lines))

    def rlen(d, i):
        l = d[i + 1]
        if l & 0x80:
            n = l & 0x7F
            l = int.from_bytes(d[i + 2:i + 2 + n], "big")
            return i + 2 + n, l
        return i + 2, l

    i, _ = rlen(der, 0)
    comps = {}
    for k in ("ver", "n", "e", "d", "p", "q", "dp", "dq", "qinv"):
        i, l = rlen(der, i)
        comps[k] = int.from_bytes(der[i:i + l], "big")
        i += l
    p, q = comps["p"], comps["q"]
    if p < q:
        p, q = q, p
        comps["dp"], comps["dq"] = comps["dq"], comps["dp"]
    qinv = pow(q, -1, p)  # qinv corregido: q^-1 mod p
    nums = RSAPrivateNumbers(
        p=p, q=q, d=comps["d"], dmp1=comps["dp"], dmq1=comps["dq"], iqmp=qinv,
        public_numbers=RSAPublicNumbers(e=comps["e"], n=comps["n"]))
    return nums.private_key()

def login_device(device, pem_path):
    ak = load_app_pem(pem_path)
    s = __import__("requests").Session()
    s.headers["User-Agent"] = "libcurl-agent/1.0"
    r = s.get(ENGINE + "?do=knock&rndx=" + api_full.rndx(), verify=False).json()
    if r.get("result") != "ok":
        raise SystemExit("KNOCK FAIL: %s" % str(r)[:200])
    token = r["data"]["token"]
    log("KNOCK OK token=%dc" % len(token))
    p0, _ = str_dest(token)
    edid = m2xc_fmt(m2xc_encrypt_full(eb(device), eb(p0), 0xBC461A49, 0x7C2359AB))
    chk = hashlib.md5(("_chk91822" + device + "l.o.x").encode()).hexdigest()
    qs = urllib.parse.urlencode([
        ("rus", "1"), ("loc", "es_CO"), ("ver", VER), ("dds", "1920x1080"),
        ("do", "lim"), ("t", token), ("ddd", DESKTOP), ("fmt", "tbt"),
        ("chk", chk), ("did", edid), ("rndx", api_full.rndx()),
    ])
    r = s.get(ENGINE + "?" + qs, verify=False).json()
    if r.get("result") != "ok":
        raise SystemExit("LIM FAIL: %s" % str(r)[:300])
    dk_key = hashlib.md5((token + device).encode()).hexdigest()
    dm_key = hashlib.md5((device + token).encode()).hexdigest()
    sk = m2xc_decrypt_full(parse_m2xc_blob(r["data"]["dk"]), eb(dk_key)).decode()
    rk = m2xc_decrypt_full(parse_m2xc_blob(r["data"]["dm"]), eb(dm_key)).decode()
    log("LIM OK sk=%s..." % sk[:16])
    magic = "".join(random.choices(CHARSET, k=64))
    dtf = build_dtf(sk)
    pf = build_proof(ak, dtf, device)
    mid = build_mid(ak)
    dd_json = json.dumps({"proof": pf, "mid": mid, "ver": VER, "host": "app.mitos.is"}, separators=(",", ":"))
    R10 = (int(time.time() * 1000) ^ random.randint(0, M)) & M
    dd_raw = m2xc_encrypt_full(eb(dd_json), eb(magic), R10, random.randint(0, M))
    dd = m2xc_fmt(dd_raw)
    from cryptography.hazmat.primitives import serialization as ser2
    from cryptography.hazmat.primitives.asymmetric import padding as pad
    pub = ser2.load_pem_public_key(rk.encode())
    ms = base64.b64encode(pub.encrypt(magic.encode(), padding=pad.PKCS1v15())).decode()
    params = [
        ("go", "0"), ("dd", dd), ("de", "desktop"), ("gi", "0"),
        ("ver", VER), ("it", "1"), ("do", "eh"), ("im", "0"),
        ("di", DESKTOP), ("dtf", dtf), ("ms", ms), ("rndx", api_full.rndx()),
    ]
    r = s.get(ENGINE + "?" + urllib.parse.urlencode(params), verify=False)
    if r.status_code != 200 or not r.text or '"result":"ok"' not in r.text:
        raise SystemExit("EH FAIL: %s" % r.text[:300])
    log("EH OK")
    return sk, magic, s

# ============================================================
# API + lectura de XP de gema
# ============================================================
def api(session, sk, magic, payload):
    body_json = json.dumps(payload, separators=(",", ":"))
    enc = m2xc_encrypt_full(eb(body_json), eb(magic), 0, 0)
    body = m2xc_fmt(enc)
    url = ENGINE + "?_sid=" + urllib.parse.quote(sk, safe="") + "&rndx=" + api_full.rndx()
    r = session.post(url, data=body, verify=False, timeout=20)
    t = r.text
    if not t:
        return {}
    if t.startswith("tBB,"):
        b64 = t[12:]
        padded = b64 + '=' * (4 - len(b64) % 4) if len(b64) % 4 else b64
        blob = base64.b64decode(padded)
        if blob[:4] == b"M2XC":
            dec = m2xc_decrypt_full(blob, eb(magic))
            try:
                return json.loads(dec)
            except Exception:
                return {"_raw": dec.decode("utf-8", errors="replace")[:200]}
        try:
            dec = api_full.decrypt_v5oh2(blob, magic)
            text = dec.decode("utf-8", errors="replace").rstrip('\x00')
            try:
                return json.loads(text)
            except Exception:
                return {"_raw": text[:200]}
        except Exception:
            return {"_raw": t[:200]}
    try:
        return json.loads(t)
    except Exception:
        return {"_raw": t[:200]}

def read_gem_xp(session, sk, magic, label):
    """inventory slot=5 -> (cexp, exp, current, n_items, raw)"""
    inv = api(session, sk, magic, {"do": "inventory", "slot": 5})
    data = inv.get("data") if isinstance(inv, dict) else None
    if not isinstance(data, dict):
        log("%s: inventory NO OBJECT: %s" % (label, json.dumps(inv)[:160]))
        return None
    items = data.get("items") or []
    cur = data.get("current", -1)
    target = None
    for it in items:
        if isinstance(it, dict) and it.get("id") == cur:
            target = it
            break
    if target is None and items:
        target = items[0] if isinstance(items[0], dict) else None
    cexp = exp = None
    if target:
        cexp = target.get("cexp")
        exp = target.get("exp")
    log("%s: cexp=%s exp=%s current=%s items=%d inv=%s" % (
        label, cexp, exp, cur, len(items), json.dumps(inv)[:220]))
    return cexp, exp, cur, len(items)

# ============================================================
# flujo HTTP de modos (igual que refreshXp de la app)
# ============================================================
def http_ffa(session, sk, magic, i):
    api(session, sk, magic, {"do": "i18n", "update": int(time.time()), "locale": "es_CO"})
    conn = api(session, sk, magic, {"do": "connect", "invite": False, "defered": True,
                                    "i": i, "gm": 0, "retrying": False, "locale": "es_CO"})
    api(session, sk, magic, {"do": "gamemode", "index": 1, "mode": 0})
    server = (conn.get("data") or {}).get("server", "")
    token = (conn.get("data") or {}).get("token", "")
    log("FFA connect gm=0 i=%d -> server=%s token=%s" % (i, server, "ok" if token else "EMPTY"))
    return server, token

def http_hvz(session, sk, magic, i):
    api(session, sk, magic, {"do": "i18n", "update": int(time.time()), "locale": "es_CO"})
    api(session, sk, magic, {"do": "connect", "invite": False, "defered": True,
                             "i": i, "gm": 7, "retrying": False, "locale": "es_CO"})
    api(session, sk, magic, {"do": "gamemode", "index": 2, "mode": 7})
    time.sleep(1.5)

def http_ctf(session, sk, magic, i):
    api(session, sk, magic, {"do": "gamemode", "index": 1, "mode": 3})
    api(session, sk, magic, {"do": "i18n", "update": int(time.time()), "locale": "es_CO"})
    conn = api(session, sk, magic, {"do": "connect", "invite": False, "defered": True,
                                    "i": i, "gm": -1, "retrying": False, "locale": "es_CO"})
    log("CTF restore connect gm=-1 i=%d ok" % i)

# ============================================================
# modos
# ============================================================
def mode_check(acc):
    device = acc["device"]
    sk, magic, session = login_device(device, pem_for_device(device))
    read_gem_xp(session, sk, magic, "check")

def mode_idle(acc):
    device = acc["device"]
    log("=== IDLE probe: %s (gem %s) ===" % (acc["name"], acc.get("equippedGemId")))
    sk, magic, session = login_device(device, pem_for_device(device))
    r0 = read_gem_xp(session, sk, magic, "t+0s")
    time.sleep(60)
    r1 = read_gem_xp(session, sk, magic, "t+60s")
    time.sleep(60)
    r2 = read_gem_xp(session, sk, magic, "t+120s")
    for i, (a, b, t0, t1) in enumerate([(r0, r1, 0, 60), (r1, r2, 60, 120), (r0, r2, 0, 120)]):
        if a and b:
            dc = (b[0] - a[0]) if (a[0] is not None and b[0] is not None) else "?"
            de = (b[1] - a[1]) if (a[1] is not None and b[1] is not None) else "?"
            log("IDLE delta %d-%ds: cexp %s exp %s" % (t0, t1, dc, de))
    log("=== IDLE probe done ===")

def mode_ffa(acc):
    import mitosis_client as mc
    import importlib as _il
    # mitosis_client es un modulo del repo raiz
    mc_mod = _il.import_module("mitosis_client")
    device = acc["device"]
    log("=== FFA probe: %s (gem %s) ===" % (acc["name"], acc.get("equippedGemId")))
    ak = load_app_pem(pem_for_device(device))

    # monkeypatch: device, clave de atestacion y firmante del PROOF = los de la app
    api_full.DEVICE_ID_OVERRIDE = device
    mc_mod.load_attest_key = lambda: ak
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    mc_mod.tpm_sign_pkcs1_sha256 = lambda msg: ak.sign(
        hashlib.sha256(msg).digest(), _pad.PKCS1v15(), _hashes.SHA256())
    mc_mod.load_device_id = lambda: device

    captured = {}
    orig_login = mc_mod.do_login

    def my_login():
        sk, magic, s, name = orig_login()
        captured.update(sk=sk, magic=magic, session=s, name=name)
        return sk, magic, s, name
    mc_mod.do_login = my_login

    result = {"spawned": False}
    def run():
        try:
            st = mc_mod.run_client(duration=100, region="europe", mode=0,
                                   send_proof=True, send_pong=True,
                                   auth_mode="m2xc", ctf_mode=False)
            result["spawned"] = bool(st and getattr(st, "spawned", False))
        except Exception as e:
            log("run_client ERROR: %s" % e)

    t = threading.Thread(target=run, daemon=True)
    t0 = time.time()
    t.start()
    # lecturas de inventory slot=5 en vivo mientras el cliente juega
    last = None
    for wait in (12, 30, 25, 25, 10):
        time.sleep(wait)
        if not captured.get("sk"):
            continue
        r = read_gem_xp(captured["session"], captured["sk"], captured["magic"],
                        "IN-GAME t+%.0fs" % (time.time() - t0))
        if r:
            if last:
                dc = (r[0] - last[0]) if (last[0] is not None and r[0] is not None) else "?"
                de = (r[1] - last[1]) if (last[1] is not None and r[1] is not None) else "?"
                log("IN-GAME delta: cexp %s exp %s" % (dc, de))
            last = r
        if wait == 12:
            ue = api(captured["session"], captured["sk"], captured["magic"], {"do": "updateexp"})
            log("updateexp in-game: %s" % json.dumps(ue)[:200])
    t.join(timeout=30)
    # cierre: restore a lobby CTF por HTTP (dejar la cuenta limpia)
    try:
        http_ctf(captured["session"], captured["sk"], captured["magic"], 3)
    except Exception as e:
        log("restore CTF err: %s" % e)
    ra = read_gem_xp(captured["session"], captured["sk"], captured["magic"], "final lobby CTF")
    log("FFA probe spawned=%s | in-game total: %s" % (result["spawned"],
        "sin datos" if not last or not ra else "cexp %s exp %s" % (ra[0] - last[0], ra[1] - last[1])))
    log("=== FFA probe done ===")

def mode_ctf(acc, duration=120):
    """CTF spawn (como el farm de la app) con PING/MOVE proactivos: verifica si
    la XP de la gema crece con la cuenta EN PARTIDA activa."""
    import importlib as _il
    mc_mod = _il.import_module("mitosis_client")
    device = acc["device"]
    log("=== CTF probe: %s (gem %s) ===" % (acc["name"], acc.get("equippedGemId")))
    ak = load_app_pem(pem_for_device(device))

    api_full.DEVICE_ID_OVERRIDE = device
    mc_mod.load_attest_key = lambda: ak
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    mc_mod.tpm_sign_pkcs1_sha256 = lambda msg: ak.sign(
        hashlib.sha256(msg).digest(), _pad.PKCS1v15(), _hashes.SHA256())
    mc_mod.load_device_id = lambda: device

    captured = {}
    orig_login = mc_mod.do_login

    def my_login():
        sk, magic, s, name = orig_login()
        captured.update(sk=sk, magic=magic, session=s, name=name)
        return sk, magic, s, name
    mc_mod.do_login = my_login

    result = {"spawned": False}
    def run():
        try:
            st = mc_mod.run_client(duration=duration, region="europe", mode=3,
                                   send_proof=True, send_pong=False,
                                   auth_mode="m2xc", ctf_mode=True)
            result["spawned"] = bool(st and getattr(st, "spawned", False))
        except Exception as e:
            log("run_client ERROR: %s" % e)

    t = threading.Thread(target=run, daemon=True)
    t0 = time.time()
    t.start()
    last = None
    for wait in (15, 30, 30, 30, 15):
        time.sleep(wait)
        if not captured.get("sk"):
            continue
        r = read_gem_xp(captured["session"], captured["sk"], captured["magic"],
                        "IN-GAME t+%.0fs" % (time.time() - t0))
        if r:
            if last:
                dc = (r[0] - last[0]) if (last[0] is not None and r[0] is not None) else "?"
                de = (r[1] - last[1]) if (last[1] is not None and r[1] is not None) else "?"
                log("IN-GAME delta: cexp %s exp %s" % (dc, de))
            last = r
    t.join(timeout=20)
    try:
        http_ctf(captured["session"], captured["sk"], captured["magic"], 3)
    except Exception as e:
        log("restore CTF err: %s" % e)
    ra = read_gem_xp(captured["session"], captured["sk"], captured["magic"], "final lobby CTF")
    if last and ra:
        log("=== RESUMEN CTF: cexp %s exp %s (%.0fs en partida) ===" % (
            (ra[0] - last[0]) if (last[0] is not None and ra[0] is not None) else "?",
            (ra[1] - last[1]) if (last[1] is not None and ra[1] is not None) else "?",
            time.time() - t0))
    log("=== CTF probe done ===")

def mode_spawn(acc, dwell=75):
    """Spawn TCP EXACTO del refreshXp de la app (greeting -> AUTH ext:495 + HTTP ->
    LISTENER -> mmm -> [4] -> [52] PROOF TPM -> [53/40] inventory+READY -> [20] ->
    keepalive con PONG+MOVE) y lectura de inventory slot=5 durante la espera."""
    import importlib as _il
    mc = _il.import_module("mitosis_client")
    device = acc["device"]
    log("=== SPAWN probe: %s (gem %s) ===" % (acc["name"], acc.get("equippedGemId")))
    ak = load_app_pem(pem_for_device(device))

    api_full.DEVICE_ID_OVERRIDE = device
    mc.load_attest_key = lambda: ak
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    mc.tpm_sign_pkcs1_sha256 = lambda msg: ak.sign(
        hashlib.sha256(msg).digest(), _pad.PKCS1v15(), _hashes.SHA256())
    mc.load_device_id = lambda: device

    sk, magic, session = login_device(device, pem_for_device(device))
    # pre-flow: loginifneeded + chattoken (uid para el mmm)
    li = api(session, sk, magic, {"do": "loginifneeded", "at": "", "wt": "", "usertoken": None})
    uid = (li.get("data") or {}).get("uid")
    ct = api(session, sk, magic, {"do": "chattoken"})
    ct_token = ((ct.get("data") or {}).get("token")) or ""
    log("uid=%s ct_token=%s..." % (uid, ct_token[:8]))
    # FFA connect HTTP: i18n -> servers change -> connect -> gamemode mode=0
    api(session, sk, magic, {"do": "i18n", "update": int(time.time()), "locale": "es_CO"})
    api(session, sk, magic, {"do": "servers", "change": "europe"})
    conn = api(session, sk, magic, {"do": "connect", "invite": False, "defered": True,
                                    "i": 1, "gm": -1, "retrying": False, "locale": "es_CO"})
    api(session, sk, magic, {"do": "gamemode", "index": 1, "mode": 0})
    server = (conn.get("data") or {}).get("server", "")
    token = (conn.get("data") or {}).get("token", "")
    if not server or not token:
        raise SystemExit("FFA connect sin server/token: %s" % json.dumps(conn)[:200])
    host = server.split(":")[0]
    port = int(server.split(":")[1]) if ":" in server else 443
    log("FFA connect gm=0 OK -> %s:%d" % (host, port))

    sock = socket.create_connection((host, port), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    # UDP (MOVE cada 1s como el farm de la app)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    udp_prefix = mc.make_udp_prefix()
    udp_seq = 1
    try:
        udp_sock.sendto(mc.make_udp_init_packet(udp_prefix), (host, 3724))
    except Exception:
        pass
    # greeting -> suffix (igual que la app: el string empieza con 8 digitos de
    # longitud y el SUFFIX son los ULTIMOS 8 chars, p.ej. 'eWzy-k6e')
    suffix = ""
    for attempt in range(2):
        if attempt > 0:
            log("Reintento de greeting (attempt 2)...")
            try:
                sock.close()
            except Exception:
                pass
            try:
                udp_sock.close()
            except Exception:
                pass
            sock = socket.create_connection((host, port), timeout=10)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            try:
                udp_sock.sendto(mc.make_udp_init_packet(udp_prefix), (host, 3724))
            except Exception:
                pass
        deadline = time.time() + 15
        while not suffix and time.time() < deadline:
            length, flag, payload = mc.recv_frame(sock, 2)
            if length is None:
                continue
            try:
                v, dec, seed_used, method = mc.full_decode_frame(payload, [0], None)
                if isinstance(v, str) and len(v) >= 8 and v[:8].isdigit():
                    suffix = v[-8:]
            except Exception:
                pass
        if suffix:
            break
    if not suffix:
        log("SPAWN probe: NO GREETING (suffix) en 2 intentos")
        sock.close()
        return
    log("Suffix: %s" % suffix)
    mt = mc.MersenneTwister(mc.get_str_key(suffix))
    seed = 0
    server_seed = mt.next_val() % 99999
    # AUTH ext:495 + HTTP del AUTH
    auth_frame, auth_body = mc.make_auth_frame(host, suffix, token, 0, ext_id=495)
    try:
        url = ENGINE + "?_sid=" + urllib.parse.quote(sk, safe="") + "&rndx=" + api_full.rndx()
        session.post(url, data=auth_body.encode("ascii"), verify=False, timeout=15)
    except Exception as e:
        log("AUTH-HTTP err: %s" % e)
    mc.send_frame(sock, auth_frame)
    log("AUTH ext:495 enviado")
    # IRC gates (talk003.mitos.is:443, TCP plano, formato del binario): OPTIONS IRC ->
    # AUTH RandomGate -> AUTH UserGate S -> AUTH UserGate GGID -> USERSTATUS ONLINE
    irc_sock = None
    irc_buf = b""
    def make_irc_frame(text):
        # formato EXACTO del binario (verificado): amfString + pad a 4 + resturple(0)
        logical = mc.amf_string(text)
        payload = logical + b"\x00" * ((4 - len(logical) % 4) % 4)
        chk = tcp.get_byte_key(logical) & 0x3F
        return tcp.make_client_frame(payload, len(logical), chk, 0)
    try:
        irc_sock = socket.create_connection(("talk003.mitos.is", 443), timeout=8)
        irc_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        irc_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789;_-"
        def random48():
            return "".join(random.choice(irc_chars) for _ in range(48))
        def irc_send(text):
            mc.send_frame(irc_sock, make_irc_frame(text))
        def irc_read_lines(timeout=1.0):
            # header IRC del server: [4B len][1B flag][payload]; payload =
            # desturple(0) con dec[0]==0x06 (string AMF3) o AMF3 plano si flag=1
            nonlocal irc_buf
            irc_sock.settimeout(timeout)
            try:
                data = irc_sock.recv(4096)
            except Exception:
                return ""
            if not data:
                return ""
            irc_buf += data
            out_lines = []
            while len(irc_buf) >= 5:
                ilen = int.from_bytes(irc_buf[0:4], "big")
                iflag = irc_buf[4]
                if ilen == 0:
                    irc_buf = irc_buf[5:]
                    continue
                if len(irc_buf) < 5 + ilen:
                    break
                payload = irc_buf[5:5 + ilen]
                irc_buf = irc_buf[5 + ilen:]
                try:
                    dec = tcp.bytearray_desturple(payload, 0)
                    if len(dec) and dec[0] == 0x06:
                        d = tcp.Amf3Decoder(dec)
                        val = d.read_value()
                        if isinstance(val, str):
                            out_lines.append(val)
                except Exception:
                    pass
            return "\n".join(out_lines)
        def irc_wait(needles, timeout=6):
            t0 = time.time()
            acc = ""
            while time.time() - t0 < timeout:
                acc += "\n" + irc_read_lines(1.0)
                for n in needles:
                    if n in acc:
                        return True
            return False
        irc_send("OPTIONS IRC")
        if not irc_wait(["AUTH RandomGate", "801 "], 4):
            log("IRC sin RandomGate")
        irc_send("AUTH UserGate S :" + random48())
        if not irc_wait(["AUTH UserGate S :OK"], 6):
            log("IRC sin OK S")
        irc_send("AUTH UserGate GGID 0 S :" + (ct_token or random48()))
        if not irc_wait(["001 "], 6):
            log("IRC sin 001")
        irc_send("USERSTATUS ONLINE")
        log("IRC chat conectado (talk003)")
    except Exception as e:
        log("IRC unavailable: %s" % e)
    # LISTENER + mmm
    try:
        server_ip = socket.gethostbyname(host)
    except Exception:
        server_ip = host
    try:
        mc.send_listener(session, sk, suffix, server_ip)
    except Exception as e:
        log("LISTENER err: %s" % e)
    if uid:
        try:
            mc.send_halted(session, sk, magic, tag=1, mode=0, index=1, uid=uid)
        except Exception as e:
            log("mmm err: %s" % e)
    # bucle de handshake (app-exacto). El seed de ENCODE es el seed del frame
    # recibido (seed_used): si un PING avanzo el MT, ese es el seed del server.
    player_id = None
    resume_key = None
    spawned_t = None
    ready_sent = False
    spawned = False
    ping_count = 0
    next_move = time.time() + 2
    spawn_deadline = time.time() + 45
    # lector HTTP concurrente: inventory slot=5 cada ~25s mientras dura la sesion
    reads = []
    def reader():
        while True:
            try:
                r = read_gem_xp(session, sk, magic, "SPAWN t+%.0fs" % (time.time() - t0_all))
                reads.append((time.time(), r))
            except Exception:
                pass
            if not spawned or (spawned and time.time() < spawned_t + dwell):
                time.sleep(25)
            else:
                return
    rt = threading.Thread(target=reader, daemon=True)
    rt.start()
    log("Handshake TCP...")
    def _run_handshake():
        nonlocal spawned, spawned_t, player_id, seed, ping_count, ready_sent, resume_key
        while time.time() < spawn_deadline + dwell and not (spawned and time.time() > spawned_t + dwell):
            length, flag, payload = mc.recv_frame(sock, 0.3)
            if length is None or not payload:
                continue
            # decodificar
            v = None
            if flag == 1 and payload and payload[0] <= 0x09:
                try:
                    d = mc.Amf3Decoder(payload)
                    v = d.read_value()
                except Exception:
                    v = None
            elif flag != 1:
                try:
                    seeds = [0, server_seed, seed]
                    v, dec, seed_used, method = mc.full_decode_frame(payload, seeds, mt)
                    if seed_used and seed_used != seed:
                        seed = seed_used
                except Exception:
                    v = None
            if not (isinstance(v, list) and v and isinstance(v[0], (int, float))):
                log("FRAME undecodable flag=%d len=%d hex=%s" % (flag, len(payload), payload[:24].hex()))
                continue
            op = int(v[0])
            log("FRAME op=%d seed=%d val=%s" % (op, seed, json.dumps(v, default=str)[:120]))
            if op == 1:
                # PING -> PONG real [10001.0, ts, seed%100]
                ping_count += 1
                if (ping_count - 1) % 10 == 0:
                    seed = mt.next_val() % 99999
                ping_ts = v[1] if len(v) > 1 and isinstance(v[1], (int, float)) else time.time() * 1000
                mc.send_frame(sock, mc.make_real_ping_frame(seed, float(ping_ts)))
            elif op == 4 and len(v) > 1:
                player_id = v[1]
                log("PLAYER_ID=%s" % player_id)
            elif op == 52 and len(v) > 1:
                log("SECURE_CHALLENGE -> PROOF TPM (seed=%d)" % seed)
                challenge_str = str(v[1])
                # roundtrip HTTP del challenge (como el binario): POST del challenge
                # al engine -> respuesta tBB (M2XC/v5oh2 con magic) con el plaintext
                nonce_override = None
                try:
                    url = ENGINE + "?_sid=" + urllib.parse.quote(sk, safe="") + "&rndx=" + api_full.rndx()
                    r = session.post(url, data=challenge_str.encode("ascii"), verify=False, timeout=10)
                    t = r.text.strip()
                    if len(t) == 8:
                        nonce_override = t
                        log("Challenge roundtrip plain: %s" % t)
                    elif t.startswith("tBB,"):
                        b64 = t[12:]
                        padded = b64 + '=' * (4 - len(b64) % 4) if len(b64) % 4 else b64
                        blob = base64.b64decode(padded)
                        dec = None
                        if blob[:4] == b"M2XC":
                            dec = m2xc_decrypt_full(blob, eb(magic))
                        else:
                            try:
                                dec = api_full.decrypt_v5oh2(blob, magic)
                            except Exception:
                                pass
                        if dec:
                            dec_txt = dec.decode("utf-8", errors="replace").rstrip("\x00")
                            if len(dec_txt) == 8:
                                nonce_override = dec_txt
                                log("Challenge roundtrip tBB-> %s" % dec_txt)
                            else:
                                log("Challenge roundtrip tBB no 8ch: %r" % dec_txt[:60])
                    else:
                        log("Challenge roundtrip no 8ch: %r" % t[:60])
                except Exception as e:
                    log("Challenge roundtrip err: %s" % e)
                local_dec = None
                try:
                    local_dec = mc.decrypt_challenge(challenge_str, suffix).decode("utf-8", "replace")
                except Exception:
                    pass
                log("Local decrypt: %s (roundtrip=%s)" % (local_dec, nonce_override))
                # firmar el plaintext del roundtrip (o el decrypt local si falla)
                try:
                    nonce = nonce_override if nonce_override else local_dec
                    if nonce is None:
                        raise RuntimeError("sin nonce para el proof")
                    msg = nonce.encode("ascii") + b"|" + device.encode("ascii") + b"|100"
                    sig = ak.sign(hashlib.sha256(msg).digest(), _pad.PKCS1v15(), _hashes.SHA256())
                    proof_str = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
                    logical = mc.amf_array([mc.amf_int(10035), mc.amf_string(proof_str)])
                    padded = logical + b"\x00"
                    half = len(padded) // 2
                    wire = mc.m2xc_tcp_enc(mc.xor_step(mc.interleave(padded, half, seed & 1), seed), seed, 100)
                    chk = seed % 63
                    frame = struct.pack(">I", len(wire)) + struct.pack(">I", len(logical)) + bytes([chk]) + wire
                    mc.send_frame(sock, frame)
                    log("PROOF enviado (%d chars, nonce=%s)" % (len(proof_str), nonce))
                except Exception as e:
                    log("PROOF err: %s" % e)
                # httpPlay + NATIVE_PLAY tras el PROOF (el server continua con 53/40
                # tras el play; validado en el flujo m2xc de mitosis_client)
                try:
                    pr = api(session, sk, magic, {"do": "play", "usertoken": None})
                    log("play -> %s" % json.dumps(pr)[:120])
                except Exception as e:
                    log("play err: %s" % e)
                try:
                    nonce = "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") for _ in range(8))
                    blob = m2xc_encrypt_full(eb(nonce), eb(suffix), 0, 0)
                    challenge5 = m2xc_fmt(blob)
                    logical = mc.amf_array([mc.amf_int(5), mc.amf_array([mc.amf_string(challenge5), mc.amf_bool(False)])])
                    padded = logical + b"\x00" * ((2 - len(logical) % 2) % 2)
                    wire = mc.m2xc_tcp_enc(mc.xor_step(mc.interleave(padded, len(padded) // 2, seed & 1), seed), seed, 100)
                    chk = seed % 63
                    frame5 = struct.pack(">I", len(wire)) + struct.pack(">I", len(logical)) + bytes([chk]) + wire
                    mc.send_frame(sock, frame5)
                    log("NATIVE_PLAY (op 5) enviado")
                except Exception as e:
                    log("NATIVE_PLAY err: %s" % e)
                try:
                    api(session, sk, magic, {"do": "gamemode", "index": 1, "mode": 0})
                except Exception:
                    pass
            elif op in (53, 40):
                if op == 40:
                    resume_key = v
                    log("RESUME_KEY (40) recibido")
                if not ready_sent:
                    ready_sent = True
                    try:
                        api(session, sk, magic, {"do": "inventory", "ingame": True, "slot": 3})
                    except Exception:
                        pass
                    mc.send_frame(sock, mc.make_ready_frame(seed))
                    log("READY enviado (tras op %d)" % op)
            elif op == 20:
                if not spawned:
                    spawned = True
                    spawned_t = time.time()
                    log("*** SPAWNED [20] recibido ***")
                    try:
                        api(session, sk, magic, {"do": "play", "usertoken": None})
                    except Exception:
                        pass
                    mc.send_frame(sock, mc.make_native_play_frame(seed))
    try:
        _run_handshake()
    except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
        log("Handshake cortado (%s) - reintento..." % e)
        try:
            sock.close()
        except Exception:
            pass
        try:
            udp_sock.close()
        except Exception:
            pass
        time.sleep(1)
        # reintento completo (segundo socket, como la app)
        try:
            sock = socket.create_connection((host, port), timeout=10)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            try:
                udp_sock.sendto(mc.make_udp_init_packet(udp_prefix), (host, 3724))
            except Exception:
                pass
            suffix2 = ""
            deadline = time.time() + 15
            while not suffix2 and time.time() < deadline:
                length, flag, payload = mc.recv_frame(sock, 2)
                if length is None:
                    continue
                try:
                    v, dec, seed_used, method = mc.full_decode_frame(payload, [0], None)
                    if isinstance(v, str) and len(v) >= 8 and v[:8].isdigit():
                        suffix2 = v[-8:]
                except Exception:
                    pass
            if not suffix2:
                log("Reintento: NO GREETING")
            else:
                log("Reintento Suffix: %s" % suffix2)
                mt = mc.MersenneTwister(mc.get_str_key(suffix2))
                seed = 0
                server_seed = mt.next_val() % 99999
                auth_frame, auth_body = mc.make_auth_frame(host, suffix2, token, 0, ext_id=495)
                try:
                    url = ENGINE + "?_sid=" + urllib.parse.quote(sk, safe="") + "&rndx=" + api_full.rndx()
                    session.post(url, data=auth_body.encode("ascii"), verify=False, timeout=15)
                except Exception:
                    pass
                mc.send_frame(sock, auth_frame)
                try:
                    mc.send_listener(session, sk, suffix2, server_ip)
                except Exception:
                    pass
                if uid:
                    try:
                        mc.send_halted(session, sk, magic, tag=1, mode=0, index=1, uid=uid)
                    except Exception:
                        pass
                player_id = resume_key = None
                ready_sent = False
                spawned = False
                spawned_t = None
                ping_count = 0
                _run_handshake()
        except Exception as e2:
            log("Reintento fallido: %s" % e2)
    # cierre
    sock.close()
    try:
        udp_sock.close()
    except Exception:
        pass
    time.sleep(1)
    log("SPAWN probe: spawned=%s player_id=%s (%.0fs en partida)" % (spawned, player_id, time.time() - spawned_t if spawned_t else 0))
    # resumen de deltas de las lecturas en vivo
    prev = None
    for ts, r in reads:
        if r:
            if prev:
                log("SPAWN delta: cexp %s exp %s" % (
                    (r[0] - prev[0]) if (prev[0] is not None and r[0] is not None) else "?",
                    (r[1] - prev[1]) if (prev[1] is not None and r[1] is not None) else "?"))
            prev = r
    http_ctf(session, sk, magic, 3)
    log("=== SPAWN probe done ===")

t0_all = time.time()

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "check"
    name = sys.argv[2] if len(sys.argv) > 2 else "Meet"
    acc = load_account(name)
    log("Cuenta: %s | device %s... | gem %s" % (acc["name"], acc["device"][:14], acc.get("equippedGemId")))
    if mode == "idle":
        mode_idle(acc)
    elif mode == "ffa":
        mode_ffa(acc)
    elif mode == "ctf":
        mode_ctf(acc)
    elif mode == "spawn":
        mode_spawn(acc)
    else:
        mode_check(acc)
    log("=== probe %s terminado en %.0fs ===" % (mode, time.time() - t0_all))
