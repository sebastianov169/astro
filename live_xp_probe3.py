#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
live_xp_probe3.py - CONFIRMACION del mecanismo de credito de XP de gema:
la XP se materializa en inventory slot=5 cuando la sesion TCP termina (settle).

Flujo: login -> V0 -> spawn TCP FFA (app-exact) -> dwell N s (PONG+MOVE, lecturas
cada 15s) -> ABORT del socket (fin de sesion) -> POLL cada 10s hasta 75s -> V1.

Uso:
  python live_xp_probe3.py <cuenta> [dwell_s]
"""
import os, sys, json, time, hashlib, base64, random, urllib.parse, threading, importlib.util, socket, struct

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(SCRIPT_DIR)
if REPO_DIR not in sys.path:
    sys.path.insert(0, REPO_DIR)

spec = importlib.util.spec_from_file_location("live_xp_probe", os.path.join(SCRIPT_DIR, "live_xp_probe.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

load_account = probe.load_account
pem_for_device = probe.pem_for_device
login_device = probe.login_device
read_gem_xp = probe.read_gem_xp
api = probe.api
t0_all = time.time()

import mitosis_client as mc
import importlib as _il
mc_mod = _il.import_module("mitosis_client")

def log(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    with open(os.path.join(SCRIPT_DIR, "live_xp_probe3.log"), "a", encoding="utf-8") as f:
        f.write(line + "\n")

def read_v(session, sk, magic, label):
    return read_gem_xp(session, sk, magic, label)

def main():
    name = sys.argv[1] if len(sys.argv) > 1 else "James"
    dwell = float(sys.argv[2]) if len(sys.argv) > 2 else 75.0
    acc = load_account(name)
    device = acc["device"]
    log("Cuenta: %s | device %s... | gem %s | dwell=%ss" % (
        acc["name"], device[:14], acc.get("equippedGemId"), dwell))
    ak = probe.load_app_pem(pem_for_device(device))

    api_full = probe.api_full
    api_full.DEVICE_ID_OVERRIDE = device
    mc_mod.load_attest_key = lambda: ak
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    mc_mod.tpm_sign_pkcs1_sha256 = lambda msg: ak.sign(
        hashlib.sha256(msg).digest(), _pad.PKCS1v15(), _hashes.SHA256())
    mc_mod.load_device_id = lambda: device

    sk, magic, session = login_device(device, pem_for_device(device))
    # pre-flow
    li = api(session, sk, magic, {"do": "loginifneeded", "at": "", "wt": "", "usertoken": None})
    uid = (li.get("data") or {}).get("uid")
    ct = api(session, sk, magic, {"do": "chattoken"})
    ct_token = ((ct.get("data") or {}).get("token")) or ""
    log("uid=%s ct=%s..." % (uid, ct_token[:8]))

    # FFA connect HTTP
    api(session, sk, magic, {"do": "i18n", "update": int(time.time()), "locale": "es_CO"})
    api(session, sk, magic, {"do": "servers", "change": "europe"})
    conn = api(session, sk, magic, {"do": "connect", "invite": False, "defered": True,
                                    "i": 1, "gm": 0, "retrying": False, "locale": "es_CO"})
    api(session, sk, magic, {"do": "gamemode", "index": 1, "mode": 0})
    server = (conn.get("data") or {}).get("server", "")
    token = (conn.get("data") or {}).get("token", "")
    if not server or not token:
        raise SystemExit("FFA connect sin server/token")
    host = server.split(":")[0]
    port = int(server.split(":")[1]) if ":" in server else 443
    log("FFA connect gm=0 OK -> %s:%d" % (host, port))

    V0 = read_v(session, sk, magic, "V0 antes de spawn")

    sock = socket.create_connection((host, port), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    udp_prefix = mc.make_udp_prefix()
    try:
        udp_sock.sendto(mc.make_udp_init_packet(udp_prefix), (host, 3724))
    except Exception:
        pass

    # greeting
    suffix = ""
    for attempt in range(2):
        if attempt > 0:
            log("Reintento greeting...")
            try: sock.close()
            except Exception: pass
            try: udp_sock.close()
            except Exception: pass
            sock = socket.create_connection((host, port), timeout=10)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            try:
                udp_sock.sendto(mc.make_udp_init_packet(udp_prefix), (host, 3724))
            except Exception:
                pass
        deadline = time.time() + 15
        while not suffix and time.time() < deadline:
            try:
                length, flag, payload = mc.recv_frame(sock, 2)
            except Exception:
                break
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
        log("NO GREETING en 2 intentos")
        return
    log("Suffix: %s" % suffix)
    mt = mc.MersenneTwister(mc.get_str_key(suffix))
    seed = 0
    server_seed = mt.next_val() % 99999

    auth_frame, auth_body = mc.make_auth_frame(host, suffix, token, 0, ext_id=495)
    try:
        url = probe.ENGINE + "?_sid=" + urllib.parse.quote(sk, safe="") + "&rndx=" + api_full.rndx()
        session.post(url, data=auth_body.encode("ascii"), verify=False, timeout=15)
    except Exception as e:
        log("AUTH-HTTP err: %s" % e)
    mc.send_frame(sock, auth_frame)
    log("AUTH enviado")

    # IRC gate (talk003.mitos.is:443) - REQUERIDO por el server para aceptar la
    # sesion del juego (el flujo del binario: OPTIONS IRC -> RandomGate -> S ->
    # GGID(ct_token) -> USERSTATUS ONLINE)
    try:
        irc_sock = socket.create_connection(("talk003.mitos.is", 443), timeout=8)
        irc_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        irc_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789;_-"
        def random48():
            return "".join(random.choice(irc_chars) for _ in range(48))
        def irc_send(text):
            logical = mc.amf_string(text)
            payload = logical + b"\x00" * ((4 - len(logical) % 4) % 4)
            chk = probe.tcp.get_byte_key(logical) & 0x3F
            mc.send_frame(irc_sock, probe.tcp.make_client_frame(payload, len(logical), chk, 0))
        def irc_read(timeout=1.0):
            irc_sock.settimeout(timeout)
            try:
                data = irc_sock.recv(4096)
            except Exception:
                return ""
            if not data:
                return ""
            out = []
            buf = data
            while len(buf) >= 5:
                ilen = int.from_bytes(buf[0:4], "big")
                iflag = buf[4]
                if ilen == 0:
                    buf = buf[5:]
                    continue
                if len(buf) < 5 + ilen:
                    break
                payload = buf[5:5 + ilen]
                buf = buf[5 + ilen:]
                try:
                    dec = probe.tcp.bytearray_desturple(payload, 0)
                    if len(dec) and dec[0] == 0x06:
                        val = probe.tcp.Amf3Decoder(dec).read_value()
                        if isinstance(val, str):
                            out.append(val)
                except Exception:
                    pass
            return "\n".join(out)
        def irc_wait(needles, timeout=6):
            t0 = time.time()
            acc = ""
            while time.time() - t0 < timeout:
                acc += "\n" + irc_read(1.0)
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

    # handshake
    player_id = None
    ready_sent = False
    spawned_t = None
    spawned = False
    ping_count = 0
    spawn_deadline = time.time() + 45
    next_move = time.time() + 2
    udp_seq = 1

    def _run_handshake():
        nonlocal spawned, spawned_t, player_id, seed, ping_count, ready_sent
        while time.time() < spawn_deadline and not spawned:
            length, flag, payload = mc.recv_frame(sock, 0.3)
            if length is None or not payload:
                continue
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
                continue
            op = int(v[0])
            if op == 1:
                ping_count += 1
                if (ping_count - 1) % 10 == 0:
                    seed = mt.next_val() % 99999
                ping_ts = v[1] if len(v) > 1 and isinstance(v[1], (int, float)) else time.time() * 1000
                mc.send_frame(sock, mc.make_real_ping_frame(seed, float(ping_ts)))
            elif op == 4 and len(v) > 1:
                player_id = v[1]
            elif op == 52 and len(v) > 1:
                challenge_str = str(v[1])
                nonce_override = None
                try:
                    url = probe.ENGINE + "?_sid=" + urllib.parse.quote(sk, safe="") + "&rndx=" + api_full.rndx()
                    r = session.post(url, data=challenge_str.encode("ascii"), verify=False, timeout=10)
                    t = r.text.strip()
                    if len(t) == 8:
                        nonce_override = t
                    elif t.startswith("tBB,"):
                        b64 = t[12:]
                        padded = b64 + '=' * (4 - len(b64) % 4) if len(b64) % 4 else b64
                        blob = base64.b64decode(padded)
                        dec = None
                        if blob[:4] == b"M2XC":
                            dec = api_full.m2xc_decrypt_full(blob, probe.eb(magic))
                        else:
                            try:
                                dec = api_full.decrypt_v5oh2(blob, magic)
                            except Exception:
                                pass
                        if dec:
                            dec_txt = dec.decode("utf-8", errors="replace").rstrip("\x00")
                            if len(dec_txt) == 8:
                                nonce_override = dec_txt
                except Exception:
                    pass
                local_dec = None
                try:
                    local_dec = mc.decrypt_challenge(challenge_str, suffix).decode("utf-8", "replace")
                except Exception:
                    pass
                try:
                    nonce = nonce_override if nonce_override else local_dec
                    if nonce is None:
                        raise RuntimeError("sin nonce")
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
                    log("PROOF enviado (nonce=%s)" % nonce)
                except Exception as e:
                    log("PROOF err: %s" % e)
                try:
                    api(session, sk, magic, {"do": "play", "usertoken": None})
                except Exception:
                    pass
                try:
                    nonce5 = "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") for _ in range(8))
                    blob5 = api_full.m2xc_encrypt_full(probe.eb(nonce5), probe.eb(suffix), 0, 0)
                    challenge5 = api_full.m2xc_fmt(blob5)
                    logical5 = mc.amf_array([mc.amf_int(5), mc.amf_array([mc.amf_string(challenge5), mc.amf_bool(False)])])
                    padded5 = logical5 + b"\x00" * ((2 - len(logical5) % 2) % 2)
                    wire5 = mc.m2xc_tcp_enc(mc.xor_step(mc.interleave(padded5, len(padded5) // 2, seed & 1), seed), seed, 100)
                    chk5 = seed % 63
                    frame5 = struct.pack(">I", len(wire5)) + struct.pack(">I", len(logical5)) + bytes([chk5]) + wire5
                    mc.send_frame(sock, frame5)
                except Exception:
                    pass
                try:
                    api(session, sk, magic, {"do": "gamemode", "index": 1, "mode": 0})
                except Exception:
                    pass
            elif op in (53, 40):
                if not ready_sent:
                    ready_sent = True
                    try:
                        api(session, sk, magic, {"do": "inventory", "ingame": True, "slot": 3})
                    except Exception:
                        pass
                    mc.send_frame(sock, mc.make_ready_frame(seed))
            elif op == 20:
                spawned = True
                spawned_t = time.time()
                log("*** SPAWNED [20] ***")
                try:
                    api(session, sk, magic, {"do": "play", "usertoken": None})
                except Exception:
                    pass
                mc.send_frame(sock, mc.make_native_play_frame(seed))

    t_spawn = time.time()
    while time.time() - t_spawn < 45 and not spawned:
        try:
            _run_handshake()
        except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
            log("Handshake cortado: %s" % e)
            break
        time.sleep(0.05)
    if not spawned:
        log("NO SPAWNED [20] (%.0fs)" % (time.time() - t_spawn))
        return

    # DWELL: mantener viva la sesion (PONG + MOVE UDP), leer cada 15s
    dwell_end = time.time() + dwell
    last_read = 0
    while time.time() < dwell_end:
        # PONG keepalive
        try:
            length, flag, payload = mc.recv_frame(sock, 0.2)
            if length is not None and payload:
                v = None
                if flag == 1 and payload and payload[0] <= 0x09:
                    try:
                        v = mc.Amf3Decoder(payload).read_value()
                    except Exception:
                        v = None
                elif flag != 1:
                    try:
                        seeds = [0, server_seed, seed]
                        v, dec, seed_used, method = mc.full_decode_frame(payload, seeds, mt)
                        if seed_used:
                            seed = seed_used
                    except Exception:
                        v = None
                if isinstance(v, list) and v and int(v[0]) == 1:
                    ping_count += 1
                    if (ping_count - 1) % 10 == 0:
                        seed = mt.next_val() % 99999
                    ping_ts = v[1] if len(v) > 1 and isinstance(v[1], (int, float)) else time.time() * 1000
                    try:
                        mc.send_frame(sock, mc.make_real_ping_frame(seed, float(ping_ts)))
                    except Exception:
                        pass
        except Exception:
            break
        # MOVE UDP cada 1s
        if time.time() >= next_move:
            try:
                mc.send_frame(udp_sock, mc.make_udp_move_packet(udp_prefix, udp_seq))
                udp_seq += 1
            except Exception:
                pass
            next_move = time.time() + 1
        if time.time() - last_read >= 15:
            last_read = time.time()
            read_v(session, sk, magic, "IN-GAME t+%.0fs" % (time.time() - t_spawn))
    log("Dwell terminado (%.0fs en partida)" % (time.time() - t_spawn))

    # ABORT: fin de sesion -> settle
    try:
        sock.close()
    except Exception:
        pass
    try:
        udp_sock.close()
    except Exception:
        pass
    log(">>> SESSION ABORTED - polling settle...")
    prev = None
    for k in range(1, 9):
        time.sleep(10)
        r = read_v(session, sk, magic, "SETTLE t+%ds" % (10 * k))
        if r and prev is not None:
            dc = (r[0] - prev[0]) if (prev[0] is not None and r[0] is not None) else "?"
            log(">>> delta vs anterior: cexp %s exp %s" % (dc, (r[1] - prev[1]) if (prev[1] is not None and r[1] is not None) else "?"))
        if r:
            prev = r
    # restore CTF
    try:
        api(session, sk, magic, {"do": "gamemode", "index": 1, "mode": 3})
        api(session, sk, magic, {"do": "i18n", "update": int(time.time()), "locale": "es_CO"})
        api(session, sk, magic, {"do": "connect", "invite": False, "defered": True,
                                 "i": 2, "gm": -1, "retrying": False, "locale": "es_CO"})
        log("CTF restore OK")
    except Exception as e:
        log("CTF restore err: %s" % e)
    read_v(session, sk, magic, "final")
    log("=== probe3 %s terminado en %.0fs ===" % (name, time.time() - t0_all))

if __name__ == "__main__":
    main()
