#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
live_xp_probe2.py - Sonda DECISIVA de cadencia de credito de XP de gema.
Mide CUANDO se actualiza el valor de inventory slot=5 (cexp/exp) respecto a:
  1. sesion de farm estable (lecturas cada 15s, sin tocar nada)
  2. el kick del cambio de modo HTTP (FFA gm=0) que hace el refresh de la app
  3. el cambio a HvZ (gm=7) y la vuelta a CTF (gm=-1)

Uso:
  python live_xp_probe2.py <cuenta>   # flujo completo (~3 min)
"""
import os, sys, json, time, hashlib, base64, random, urllib.parse, importlib.util

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(SCRIPT_DIR)
if REPO_DIR not in sys.path:
    sys.path.insert(0, REPO_DIR)

# --- importar live_xp_probe (login + API + lecturas ya funcionando) ---
spec = importlib.util.spec_from_file_location("live_xp_probe", os.path.join(SCRIPT_DIR, "live_xp_probe.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

load_account = probe.load_account
pem_for_device = probe.pem_for_device
login_device = probe.login_device
read_gem_xp = probe.read_gem_xp
api = probe.api
t0_all = time.time()

LOG_PATH = os.path.join(SCRIPT_DIR, "live_xp_probe2.log")

def log(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def read_v(session, sk, magic, label):
    r = read_gem_xp(session, sk, magic, label)
    return r  # (cexp, exp, current, n_items) o None

def switch_ffa(session, sk, magic, i):
    """Cambio a FFA por HTTP EXACTO del refreshXp: i18n -> connect gm=0 -> gamemode mode=0."""
    api(session, sk, magic, {"do": "i18n", "update": int(time.time()), "locale": "es_CO"})
    conn = api(session, sk, magic, {"do": "connect", "invite": False, "defered": True,
                                    "i": i + 1, "gm": 0, "retrying": False, "locale": "es_CO"})
    api(session, sk, magic, {"do": "gamemode", "index": 1, "mode": 0})
    return conn

def switch_hvz(session, sk, magic, i):
    api(session, sk, magic, {"do": "i18n", "update": int(time.time()), "locale": "es_CO"})
    api(session, sk, magic, {"do": "connect", "invite": False, "defered": True,
                             "i": i + 2, "gm": 7, "retrying": False, "locale": "es_CO"})
    api(session, sk, magic, {"do": "gamemode", "index": 2, "mode": 7})

def switch_ctf(session, sk, magic, i):
    api(session, sk, magic, {"do": "gamemode", "index": 1, "mode": 3})
    api(session, sk, magic, {"do": "i18n", "update": int(time.time()), "locale": "es_CO"})
    api(session, sk, magic, {"do": "connect", "invite": False, "defered": True,
                             "i": i + 3, "gm": -1, "retrying": False, "locale": "es_CO"})

def main():
    name = sys.argv[1] if len(sys.argv) > 1 else "James"
    acc = load_account(name)
    device = acc["device"]
    log("Cuenta: %s | device %s... | gem %s" % (acc["name"], device[:14], acc.get("equippedGemId")))
    sk, magic, session = login_device(device, pem_for_device(device))
    connect_i = 0

    # FASE 0: linea base con el farm jugando (sin tocar nada), lecturas cada 15s
    r0 = read_v(session, sk, magic, "BASE t+0s")
    for k in range(1, 5):
        time.sleep(15)
        read_v(session, sk, magic, "BASE t+%ds" % (15 * k))
    time.sleep(5)

    # FASE 1: kick FFA (cambio de modo HTTP, lo que hace el refresh) + lecturas cada 10s
    log(">>> FASE 1: switch FFA (gm=0) kick")
    switch_ffa(session, sk, magic, connect_i); connect_i += 1
    prev = r0
    for k in range(1, 9):
        time.sleep(10)
        r = read_v(session, sk, magic, "FFA t+%ds" % (10 * k))
        if r and prev:
            dc = (r[0] - prev[0]) if (prev[0] is not None and r[0] is not None) else "?"
            de = (r[1] - prev[1]) if (prev[1] is not None and r[1] is not None) else "?"
            log(">>> delta vs anterior: cexp %s exp %s" % (dc, de))
        if r:
            prev = r

    # FASE 2: HvZ (gm=7) + lectura
    log(">>> FASE 2: switch HvZ (gm=7)")
    switch_hvz(session, sk, magic, connect_i); connect_i += 1
    time.sleep(3)
    r = read_v(session, sk, magic, "HvZ t+3s")
    if r and prev:
        dc = (r[0] - prev[0]) if (prev[0] is not None and r[0] is not None) else "?"
        log(">>> delta vs anterior: cexp %s" % dc)
    if r:
        prev = r
    time.sleep(30)
    read_v(session, sk, magic, "HvZ t+33s")

    # FASE 3: vuelta a CTF (gm=-1) + lectura final
    log(">>> FASE 3: restore CTF (gm=-1)")
    switch_ctf(session, sk, magic, connect_i); connect_i += 1
    time.sleep(3)
    read_v(session, sk, magic, "CTF final")
    log("=== probe2 %s terminado en %.0fs ===" % (name, time.time() - t0_all))

if __name__ == "__main__":
    main()
