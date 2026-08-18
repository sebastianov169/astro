// mito_client.js - Login KNOCK/LIM/EH + API cifrada (port de login.cpp)
import {
  md5Hex, m2xcEncryptFull, m2xcDecryptFull, m2xcFmt, parseM2xcBlob,
  b64Encode, b64Decode, urlB64EncodeNoPad,
  rsaSignPkcs1Sha256, rsaPublicJwk, rsaEncryptPkcs1, b64urlToBytes,
  buildDtf, stringDesturple, genMagic, rndx, urlEncode,
  deriveAesKey, deriveCustomAesKey, aesCbcCrypt,
} from "./mito_crypto.js";

const K_ENGINE = "https://app.mitos.is/engine_beta.php";
const K_VERSION = "10.1.8";
const K_DESKTOP = "Dell Inc.;XPS 15 9530;Microsoft Windows 11 Pro;Windows;10.0.22631;x64;1920;1080";

async function httpGet(url) {
  const resp = await fetch(url, { headers: { "User-Agent": "libcurl-agent/1.0" } });
  return new Uint8Array(await resp.arrayBuffer());
}

async function httpPost(url, body) {
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      "User-Agent": "libcurl-agent/1.0",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });
  return new Uint8Array(await resp.arrayBuffer());
}

export class MitosClient {
  constructor(deviceId, pem) {
    this.deviceId = deviceId;
    this.pem = pem;
    this.sessionKey = "";
    this.magic = "";
  }

  // Usa la sesion guardada si el server la acepta; si no, hace login completo.
  // Devuelve {sessionKey, magic} para persistir (o null si no hay sesion).
  async loginIfNeeded(savedSessionKey, savedMagic) {
    if (savedSessionKey && savedMagic) {
      this.sessionKey = savedSessionKey;
      this.magic = savedMagic;
      try {
        // probe barato: loginifneeded con la sesion guardada
        const r = await this.postEncrypted({ do: "loginifneeded", at: "", wt: "", usertoken: null });
        if (r.result === "ok" && r.data) {
          return { sessionKey: savedSessionKey, magic: savedMagic };
        }
      } catch (e) {}
      // sesion invalida -> login completo
      this.sessionKey = "";
      this.magic = "";
    }
    await this.login();
    return { sessionKey: this.sessionKey, magic: this.magic };
  }

  async login() {
    // KNOCK
    const chk = md5Hex("_chk91822" + this.deviceId + "l.o.x");
    const q = "do=knock&rndx=" + rndx();
    const knockResp = await httpGet(K_ENGINE + "?" + q);
    const knock = JSON.parse(new TextDecoder().decode(knockResp));
    const token = knock?.data?.token || "";
    if (!token) throw new Error("KNOCK failed: " + JSON.stringify(knock).slice(0, 120));

    // LIM
    const parts = stringDesturple(token);
    const edidBlob = m2xcEncryptFull(new TextEncoder().encode(this.deviceId),
      new TextEncoder().encode(parts[0]), 0xBC461A49, 0x7C2359AB);
    const edid = m2xcFmt(edidBlob);
    const limParams = [
      ["rus", "1"], ["loc", "es_CO"], ["ver", K_VERSION], ["dds", "1920x1080"],
      ["do", "lim"], ["t", token], ["ddd", K_DESKTOP], ["fmt", "tbt"],
      ["chk", chk], ["did", edid], ["rndx", rndx()],
    ];
    const limUrl = K_ENGINE + "?" + limParams.map(([k, v]) => k + "=" + urlEncode(v, false)).join("&");
    const limResp = await httpGet(limUrl);
    const lim = JSON.parse(new TextDecoder().decode(limResp));
    if (lim.result !== "ok") throw new Error("LIM failed: " + (lim.message || ""));
    const dk = lim.data.dk;
    const dm = lim.data.dm;
    const dkKey = md5Hex(token + this.deviceId);
    const dmKey = md5Hex(this.deviceId + token);
    const skBlob = m2xcDecryptFull(parseM2xcBlob(dk), new TextEncoder().encode(dkKey));
    const rkBlob = m2xcDecryptFull(parseM2xcBlob(dm), new TextEncoder().encode(dmKey));
    if (skBlob.length === 0) throw new Error("LIM: could not decrypt sk/rk");
    this.sessionKey = new TextDecoder().decode(skBlob);
    const rsaPublicKey = new TextDecoder().decode(rkBlob);

    // EH
    this.magic = genMagic(64);
    const dtf = buildDtf(this.sessionKey);
    const chMsg = new TextEncoder().encode(dtf + "|" + this.deviceId + "|100");
    const sig = await rsaSignPkcs1Sha256(this.pem, chMsg);
    const jwk = await rsaPublicJwk(this.pem);
    const mid = await buildMid(jwk);
    const proof = urlB64EncodeNoPad(sig);
    const ddJson = JSON.stringify({ proof, mid, ver: K_VERSION, host: "app.mitos.is" });
    const r10 = ((Math.random() * 0x100000000) ^ (Math.random() * 0x100000000)) >>> 0;
    const ddH2 = (Math.random() * 0x100000000) >>> 0;
    const ddBlob = m2xcEncryptFull(new TextEncoder().encode(ddJson),
      new TextEncoder().encode(this.magic), r10, ddH2);
    const dd = m2xcFmt(ddBlob);
    const ms = await rsaEncryptPkcs1Base64(rsaPublicKey, this.magic);
    const ehParams = [
      ["go", "0"], ["dd", dd], ["de", "desktop"], ["gi", "0"],
      ["ver", K_VERSION], ["it", "1"], ["do", "eh"], ["im", "0"],
      ["di", K_DESKTOP], ["dtf", dtf], ["ms", ms], ["rndx", rndx()],
    ];
    const ehUrl = K_ENGINE + "?" + ehParams.map(([k, v]) => k + "=" + urlEncode(v, true)).join("&");
    const eh = await httpGet(ehUrl);
    const ehText = new TextDecoder().decode(eh);
    if (!ehText.includes("ok")) throw new Error("EH failed: " + ehText.slice(0, 120));
    return true;
  }

  async postEncrypted(body) {
    const url = K_ENGINE + "?_sid=" + urlEncode(this.sessionKey, false) + "&rndx=" + rndx();
    const bodyJson = JSON.stringify(body);
    const enc = m2xcEncryptFull(new TextEncoder().encode(bodyJson),
      new TextEncoder().encode(this.magic), 0, 0);
    const resp = await httpPost(url, m2xcFmt(enc));
    return this.decodeResponse(resp);
  }

  async decodeResponse(resp) {
    const t = new TextDecoder().decode(resp);
    let payload = resp;
    if (t.startsWith("tBB,")) {
      const blob = b64Decode(t.slice(12));
      if (blob.length >= 4 && blob[0] === 0x4d && blob[1] === 0x32 && blob[2] === 0x58 && blob[3] === 0x43) {
        payload = m2xcDecryptFull(blob, new TextEncoder().encode(this.magic));
      } else {
        // intento 1: clave custom offset 100 (loginifneeded)
        let dec = aesCbcCrypt(blob, deriveCustomAesKey(this.magic, 100), false);
        while (dec.length > 0 && dec[dec.length - 1] === 0) dec = dec.slice(0, -1);
        payload = dec;
        try {
          JSON.parse(new TextDecoder().decode(payload));
        } catch (e) {
          // intento 2: clave plana (v5oh2)
          dec = aesCbcCrypt(blob, deriveAesKey(this.magic), false);
          while (dec.length > 0 && dec[dec.length - 1] === 0) dec = dec.slice(0, -1);
          payload = dec;
        }
      }
    }
    return JSON.parse(new TextDecoder().decode(payload));
  }

  async fetchName() {
    try {
      const r = await this.postEncrypted({ do: "loginifneeded", at: "", wt: "", usertoken: null });
      const d = r.data || {};
      return d.username || d.nickname ||
        (d.userinfo && (d.userinfo.username || d.userinfo.nickname || d.userinfo.display)) || "";
    } catch (e) {
      return "";
    }
  }

  // Nombre + coins reales (loginifneeded devuelve el balance actual)
  async fetchAccount() {
    try {
      const r = await this.postEncrypted({ do: "loginifneeded", at: "", wt: "", usertoken: null });
      const d = r.data || {};
      const ui = d.userinfo || {};
      const name = d.username || d.nickname || ui.username || ui.nickname || ui.display || "";
      const coins = ui.coins !== undefined ? Number(ui.coins) : null;
      return { name, coins };
    } catch (e) {
      return { name: "", coins: null };
    }
  }

  async laboratory() { return this.postEncrypted({ do: "laboratory" }); }
  async craft(slot, itemId) { return this.postEncrypted({ do: "laboratory", slot, cmd: "craft", item: itemId }); }
  async pick(slot) { return this.postEncrypted({ do: "laboratory", slot, cmd: "pick" }); }
  async news() { return this.postEncrypted({ do: "news" }); }
  async achievements() { return this.postEncrypted({ do: "achievements", user: null }); }
  async getReward(achievementId) { return this.postEncrypted({ do: "getreward", achievement: achievementId }); }
  async openChest(chestId) { return this.postEncrypted({ do: "openchest", id: chestId }); }
  async buy(itemId, packs) { return this.postEncrypted({ do: "buy", item: itemId, packs: packs || 1 }); }
  // inventario de pociones (slot 3/4): id -> durability (cantidad)
  async potionStock() {
    const stock = {};
    for (const slot of [3, 4]) {
      const r = await this.postEncrypted({ do: "inventory", slot });
      const items = (r.data || {}).items || [];
      for (const it of items) {
        const id = Number(it.id || 0);
        const qty = Number(it.durability || 0);
        if (id > 0 && qty > 0) stock[id] = qty;
      }
    }
    return stock;
  }
  // catalogo de la tienda (category 6): id -> multiple (tamano de pack)
  async storeMultiples() {
    const mult = {};
    const r = await this.postEncrypted({ do: "store", category: 6 });
    const items = (r.data || {}).items || [];
    for (const it of items) {
      const id = Number(it.id || 0);
      const m = Number(it.multiple || 0);
      if (id > 0 && m > 0) mult[id] = m;
    }
    return mult;
  }
}

function buildMid(jwk) {
  // rsa1 = "RSA1" + u32le(bits) + u32le(lenE) + u32le(lenN) + 0 + 0 + e + n
  const e = b64urlToBytes(jwk.e);
  const n = b64urlToBytes(jwk.n);
  const bits = n.length * 8;
  const rsa1 = [];
  rsa1.push(0x52, 0x53, 0x41, 0x31); // RSA1
  const le = (v) => [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
  rsa1.push(...le(bits), ...le(e.length), ...le(n.length), ...le(0), ...le(0));
  for (const b of e) rsa1.push(b);
  for (const b of n) rsa1.push(b);
  // frame = "MID2" + 1 + 1 + u16be(len) + rsa1 + sha256(0x01 + rsa1)
  const frame = [];
  frame.push(0x4d, 0x49, 0x44, 0x32, 1, 1);
  frame.push((rsa1.length >>> 8) & 0xff, rsa1.length & 0xff);
  for (const b of rsa1) frame.push(b);
  // sha256(0x01 + rsa1)
  const shaInput = new Uint8Array([1, ...rsa1]);
  const digestPromise = crypto.subtle.digest("SHA-256", shaInput);
  // sincrono no es posible; el caller debe await. Se devuelve promesa.
  return (async () => {
    const digest = new Uint8Array(await digestPromise);
    const full = new Uint8Array([...frame, ...digest]);
    return "M2." + urlB64EncodeNoPad(full);
  })();
}

async function rsaEncryptPkcs1Base64(publicKeyPem, plain) {
  // importar clave publica PEM -> jwk n/e
  const der = pemToDer(publicKeyPem);
  const key = await crypto.subtle.importKey("spki", der, {
    name: "RSASSA-PKCS1-v1_5", hash: "SHA-256",
  }, true, ["verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", key);
  const n = b64urlToBytes(jwk.n);
  const e = b64urlToBytes(jwk.e);
  let nBig = 0n, eBig = 0n;
  for (const b of n) nBig = (nBig << 8n) | BigInt(b);
  for (const b of e) eBig = (eBig << 8n) | BigInt(b);
  const k = n.length;
  const ct = rsaEncryptPkcs1(new TextEncoder().encode(plain), nBig, eBig, k);
  return b64Encode(ct);
}

function pemToDer(pem) {
  const lines = pem.split(/\r?\n/).filter(l => l.trim() && !l.includes("-----"));
  return b64Decode(lines.join(""));
}
