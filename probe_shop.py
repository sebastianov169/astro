#!/usr/bin/env python3
# probe_shop.py - login real con una cuenta de Astro y sondeo de endpoints de
# tienda (shop) contra el server real de mitos.is. SOLO LECTURA: no compra nada.
import sys, os, json, time, random, hashlib, struct, base64, urllib.parse, urllib.request, ssl
sys.path.insert(0, r"C:\Users\ren\Desktop\og mito\mito_client")
from full_login_and_api import (eb, rndx, fmix, fmix2, ror, rol, keystream_xxtea,
    swfinalize_passa, swfinalize_passb, transform1, transform2, m2xc_encrypt_full,
    inverse_transform1, inverse_transform2, m2xc_decrypt_full, m2xc_fmt, parse_m2xc_blob,
    _dtf_mix, build_dtf, str_dest, build_proof, build_mid)

DEVICE = "3Ui-UoF5Gc5f^-x0q-N^6Z-LOSd;bIz4q-ts,0hxKdyKicOt2,;x1GcFEbrTNQda"  # akardego
ENGINE = "https://app.mitos.is/engine_beta.php"
VER = "1.4.8"
DESKTOP = "1908"
CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
M = 0xFFFFFFFF
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# clave fake TPM de Astro: fake_tpm/<md5(device).left(16)>.pem
md5h = hashlib.md5(DEVICE.encode()).hexdigest()[:16]
pem_path = os.path.join(os.environ["LOCALAPPDATA"], "Astro", "fake_tpm", md5h + ".pem")
print("PEM:", pem_path, os.path.exists(pem_path))
from cryptography.hazmat.primitives import serialization
with open(pem_path, "rb") as f:
    ak = serialization.load_pem_private_key(f.read(), password=None)

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "libcurl-agent/1.0"})
    with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
        return r.read().decode("utf-8", errors="replace")

def post(url, body):
    req = urllib.request.Request(url, data=body, headers={"User-Agent": "libcurl-agent/1.0"})
    with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
        return r.read().decode("utf-8", errors="replace")

# 1. KNOCK
r = json.loads(get(ENGINE + "?do=knock&rndx=" + rndx()))
assert r["result"] == "ok", r
token = r["data"]["token"]
print("[1] KNOCK ok")

# 2. LIM
p0, _ = str_dest(token)
edid = m2xc_fmt(m2xc_encrypt_full(eb(DEVICE), eb(p0), 0xBC461A49, 0x7C2359AB))
chk = hashlib.md5(("_chk91822" + DEVICE + "l.o.x").encode()).hexdigest()
qs = urllib.parse.urlencode([
    ("rus", "1"), ("loc", "es_CO"), ("ver", VER), ("dds", "1920x1080"),
    ("do", "lim"), ("t", token), ("ddd", DESKTOP), ("fmt", "tbt"),
    ("chk", chk), ("did", edid), ("rndx", rndx()),
])
r = json.loads(get(ENGINE + "?" + qs))
if r["result"] != "ok":
    print("[2] LIM FAIL", json.dumps(r)[:300]); sys.exit(1)
dk_blob = parse_m2xc_blob(r["data"]["dk"]); dm_blob = parse_m2xc_blob(r["data"]["dm"])
sk = m2xc_decrypt_full(dk_blob, eb(hashlib.md5((token + DEVICE).encode()).hexdigest())).decode()
rk = m2xc_decrypt_full(dm_blob, eb(hashlib.md5((DEVICE + token).encode()).hexdigest())).decode()
print("[2] LIM ok sk=%s..." % sk[:16])

# 3. EH
magic = "".join(random.choices(CHARSET, k=64))
dtf = build_dtf(sk)
pf = build_proof(ak, dtf, DEVICE)
mid = build_mid(ak)
dd_json = json.dumps({"proof": pf, "mid": mid, "ver": VER, "host": "app.mitos.is"}, separators=(",", ":"))
R10 = (int(time.time() * 1000) ^ random.randint(0, M)) & M
dd = m2xc_fmt(m2xc_encrypt_full(eb(dd_json), eb(magic), R10, random.randint(0, M)))
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes as asym_hashes
pub = serialization.load_pem_public_key(rk.encode())
ms = base64.b64encode(pub.encrypt(magic.encode(), asym_padding.PKCS1v15())).decode()
params = [("go", "0"), ("dd", dd), ("de", "desktop"), ("gi", "0"), ("ver", VER),
          ("it", "1"), ("do", "eh"), ("im", "0"), ("di", DESKTOP), ("dtf", dtf),
          ("ms", ms), ("rndx", rndx())]
t = get(ENGINE + "?" + urllib.parse.urlencode(params))
print("[3] EH", t[:60])

# 4. API helper (igual que la referencia)
def api(payload):
    body_json = json.dumps(payload, separators=(",", ":"))
    enc = m2xc_encrypt_full(eb(body_json), eb(magic), 0, 0)
    body = m2xc_fmt(enc)
    url = ENGINE + "?_sid=" + urllib.parse.quote(sk, safe="") + "&rndx=" + rndx()
    t = post(url, body.encode())
    if not t: return {}
    if t.startswith("tBB,"):
        blob = base64.b64decode(t[4 + 8:])
        if blob[:4] == b"M2XC":
            dec = m2xc_decrypt_full(blob, eb(magic))
            try: return json.loads(dec)
            except: return {"_raw": dec.decode("utf-8", errors="replace")[:200]}
        return {"_raw": t[:200]}
    try: return json.loads(t)
    except: return {"_raw": t[:200]}

# 5. SONDEO DE SHOP (solo lectura)
print("\n-- SONDEO SHOP --")
candidates = [
    {"do": "shop"},
    {"do": "shop", "cat": 10},
    {"do": "gemshop"},
    {"do": "store"},
    {"do": "market"},
    {"do": "shop", "category": 10},
    {"do": "inventory", "slot": 10},
    {"do": "inventory", "slot": 0},
    {"do": "catalog"},
    {"do": "gemstore"},
    {"do": "shop", "type": "gems"},
]
for p in candidates:
    try:
        r = api(p)
        s = json.dumps(r, ensure_ascii=False)[:220]
        print("  %-38s -> %s" % (json.dumps(p)[:38], s))
    except Exception as e:
        print("  %-38s -> EXC %s" % (json.dumps(p)[:38], e))

# 6. Inventory slot=5 (baseline: gemas actuales de la cuenta)
r = api({"do": "inventory", "slot": 5})
print("\n-- INVENTORY slot=5 (baseline) --")
print(" ", json.dumps(r, ensure_ascii=False)[:400])
