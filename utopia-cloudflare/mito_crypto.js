// mito_crypto.js - Port a JS del crypto.cpp (M2XC, DTF, RSA, AES, MD5)
// Para Cloudflare Workers / Node 18+

const M = 0xFFFFFFFF;

function fmix(x) {
  x = (x & M) >>> 0;
  x = Math.imul((x ^ (x >>> 16)) >>> 0, 0x45d9f3b) >>> 0;
  x = Math.imul((x ^ (x >>> 16)) >>> 0, 0x45d9f3b) >>> 0;
  return (x ^ (x >>> 16)) >>> 0;
}

function fmix2(x) {
  x = (x & M) >>> 0;
  x = Math.imul((x ^ (x >>> 16)) >>> 0, 0x45d9f3b) >>> 0;
  const f2i = Math.imul((x ^ (x >>> 16)) >>> 0, 0x45d9f3b) >>> 0;
  const fin = (f2i ^ (f2i >>> 16)) >>> 0;
  return [f2i, fin];
}

function ror(x, r) {
  x = (x & M) >>> 0;
  r &= 31;
  return (((x >>> r) | (x << (32 - r))) >>> 0) & M;
}

function rol(x, r) {
  return ror(x, 32 - r);
}

function keystreamXxtea(key, state, SUM) {
  let [w0, w1, w2, w3] = state.map(v => (v & M) >>> 0);
  let c = 0;
  for (let i = 0; i < key.length; i++) {
    const b = key[i] & 0xff;
    let t = (rol(w3, 3) + b + i + w0) & M;
    w0 = fmix(t);
    t = (rol((b + i + w0) & M, 7) ^ w1) & M;
    w1 = fmix(t);
    t = (w2 + rol((b ^ w1) & M, 11) + c) & M;
    w2 = fmix(t);
    t = (rol((b + SUM) & M, 17) ^ w3 ^ w2) & M;
    w3 = fmix(t);
    c = (c + 0x45d9f3b) & M;
  }
  return [w0, w1, w2, w3];
}

function swfinalizePassA(s) {
  const [w0, w1, w2, w3] = s;
  const f0 = fmix2((w0 ^ 0xa5a5a5a5) & M);
  const f1 = fmix2((w1 + 0x3c6ef372) & M);
  const w2f = fmix((((f0[0] >>> 19) | ((f0[1] << 13) >>> 0)) & M) ^ w2);
  const w3f = fmix(((((f1[1] << 9) >>> 0) | (f1[0] >>> 23)) & M) + w3);
  return [f0[1], f1[1], w2f, w3f];
}

function transform1(data, state, H, passB) {
  let [w0, w1, w2, w3] = state.map(v => (v & M) >>> 0);
  H = (H & M) >>> 0;
  const out = new Uint8Array(data.length);
  for (let pos = 0; pos < data.length; pos++) {
    const p0 = w0, p1 = w1, p2 = w2, p3 = w3;
    const val1 = (rol(p1, 5) + p0 + 0x9e3779b9 + pos) & M;
    const f0 = fmix2(val1);
    const w0n = f0[1];
    const val2 = (rol(p2, 7) ^ p1 ^ w0n) & M;
    const w1n = fmix(val2);
    const val3 = (rol(p3, 11) + p2 + w1n) & M;
    const f3 = fmix2(val3);
    const w2n = f3[1];
    const gameTerm = ((f0[0] >>> 19) | ((w0n << 13) >>> 0)) & M;
    const val4 = (gameTerm ^ p3 ^ w2n ^ pos) & M;
    const fw3 = fmix2(val4);
    const w3n = fw3[1];
    const termC = ror(w1n, 29);
    let termB;
    if (passB) termB = (((w2n << 9) >>> 0) | (w2n >>> 23)) & M;
    else termB = ((f3[0] >>> 23) | ((w2n << 9) >>> 0)) & M;
    const termD = ((w3n >>> 15) | ((w3n << 17) >>> 0)) & M;
    const idx = (pos >>> 2) & 3;
    const selWord = [w0n, w1n, w2n, w3n][idx];
    const xorVal = (termD ^ termB ^ termC ^ w0n) & M;
    const shift = (pos & 3) << 3;
    let byteOut = (((xorVal >>> shift) & 0xff) ^ (data[pos] & 0xff));
    byteOut += (selWord >>> shift) & 0xff;
    byteOut += H & 0xff;
    byteOut += pos & 0xff;
    out[pos] = byteOut & 0xff;
    w0 = w0n; w1 = w1n; w2 = w2n; w3 = w3n;
  }
  return out;
}

function transform2(data, ha, hb, counterOffset) {
  let prev = hb & 0xff;
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    const pos = i + counterOffset;
    const shift = (i & 3) << 3;
    const haShift = (ha >>> shift) & M;
    const val = (data[i] ^ ((haShift + prev + pos) & 0xff) ^ prev) & 0xff;
    out[i] = val;
    prev = val;
  }
  return out;
}

function inverseTransform1(enc, state, H, passB) {
  let [w0, w1, w2, w3] = state.map(v => (v & M) >>> 0);
  H = (H & M) >>> 0;
  const out = new Uint8Array(enc.length);
  for (let pos = 0; pos < enc.length; pos++) {
    const p0 = w0, p1 = w1, p2 = w2, p3 = w3;
    const val1 = (rol(p1, 5) + p0 + 0x9e3779b9 + pos) & M;
    const f0 = fmix2(val1);
    const w0n = f0[1];
    const val2 = (rol(p2, 7) ^ p1 ^ w0n) & M;
    const w1n = fmix(val2);
    const val3 = (rol(p3, 11) + p2 + w1n) & M;
    const f3 = fmix2(val3);
    const w2n = f3[1];
    const gameTerm = ((f0[0] >>> 19) | ((w0n << 13) >>> 0)) & M;
    const val4 = (gameTerm ^ p3 ^ w2n ^ pos) & M;
    const fw3 = fmix2(val4);
    const w3n = fw3[1];
    const termC = ror(w1n, 29);
    let termB;
    if (passB) termB = (((w2n << 9) >>> 0) | (w2n >>> 23)) & M;
    else termB = ((f3[0] >>> 23) | ((w2n << 9) >>> 0)) & M;
    const termD = ((w3n >>> 15) | ((w3n << 17) >>> 0)) & M;
    const idx = (pos >>> 2) & 3;
    const selWord = [w0n, w1n, w2n, w3n][idx];
    const xorVal = (termD ^ termB ^ termC ^ w0n) & M;
    const shift = (pos & 3) << 3;
    const byteVal = enc[pos] & 0xff;
    const xorShift = (xorVal >>> shift) & 0xff;
    const selShift = (selWord >>> shift) & 0xff;
    const inp = (((byteVal - selShift - (H & 0xff) - (pos & 0xff)) & 0xff) ^ xorShift) & 0xff;
    out[pos] = inp;
    w0 = w0n; w1 = w1n; w2 = w2n; w3 = w3n;
  }
  return out;
}

function inverseTransform2(enc, ha, hb, counterOffset) {
  let prev = hb & 0xff;
  const out = new Uint8Array(enc.length);
  for (let i = 0; i < enc.length; i++) {
    const pos = i + counterOffset;
    const shift = (i & 3) << 3;
    const haShift = (ha >>> shift) & M;
    const mix = (haShift + prev + pos) & 0xff;
    const encByte = enc[i];
    out[i] = (encByte ^ mix ^ prev) & 0xff;
    prev = encByte;
  }
  return out;
}

// utilidades bytearray
function appendU32Be(out, v) {
  out.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
}

function readU32Be(b, off) {
  return ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0;
}

function m2xcEncryptFull(data, key, H1, H2) {
  H1 = (H1 & M) >>> 0;
  H2 = (H2 & M) >>> 0;
  const lenData = data.length;
  const lenKey = key.length;
  let s1 = [
    fmix((lenData ^ H1 ^ 0x243f6a88) & M),
    fmix((H2 ^ 0x85a308d3) & M),
    fmix((lenKey ^ rol(H1, 7) ^ 0x13198a2e) & M),
    fmix((rol(H2, 11) ^ 0x03707344) & M),
  ];
  s1 = keystreamXxtea(key, s1, (H1 + H2) & M);
  s1 = swfinalizePassA(s1);
  const round1 = transform1(data, s1, H1, false);
  const round2 = transform2(round1, H1, H2, 0);
  const seedA = (H1 ^ 0x6a09e667) >>> 0;
  const seedB = (H2 ^ 0xbb67ae85) >>> 0;
  const ks2 = [];
  appendU32Be(ks2, 0x19731f72);
  appendU32Be(ks2, H1);
  appendU32Be(ks2, H2);
  appendU32Be(ks2, lenData);
  appendU32Be(ks2, round2.length);
  for (const b of round2) ks2.push(b);
  let s2 = [
    fmix((ks2.length ^ seedA ^ 0x243f6a88) & M),
    fmix((H2 ^ 0x3ec4a656) & M),
    fmix((lenKey ^ rol(seedA, 7) ^ 0x13198a2e) & M),
    fmix((rol(seedB, 11) ^ 0x03707344) & M),
  ];
  s2 = keystreamXxtea(key, s2, (seedA + seedB) & M);
  s2 = swfinalizePassA(s2);
  const round3 = transform1(Uint8Array.from(ks2), s2, seedA, true);
  const round4 = transform2(round3, seedA, seedB, 0);
  const H3 = round4.length >= 4 ? readU32Be(round4, 0) : 0;
  const blob = [0x4d, 0x32, 0x58, 0x43]; // M2XC
  appendU32Be(blob, H1);
  appendU32Be(blob, H2);
  appendU32Be(blob, H3);
  for (const b of round2) blob.push(b);
  return Uint8Array.from(blob);
}

function m2xcDecryptFull(blob, key) {
  if (blob.length < 16 || blob[0] !== 0x4d || blob[1] !== 0x32 || blob[2] !== 0x58 || blob[3] !== 0x43)
    return new Uint8Array(0);
  const H1 = readU32Be(blob, 4);
  const H2 = readU32Be(blob, 8);
  const payload = blob.slice(16);
  const lenData = payload.length;
  const lenKey = key.length;
  let s1 = [
    fmix((lenData ^ H1 ^ 0x243f6a88) & M),
    fmix((H2 ^ 0x85a308d3) & M),
    fmix((lenKey ^ rol(H1, 7) ^ 0x13198a2e) & M),
    fmix((rol(H2, 11) ^ 0x03707344) & M),
  ];
  s1 = keystreamXxtea(key, s1, (H1 + H2) & M);
  s1 = swfinalizePassA(s1);
  const round1 = inverseTransform2(payload, H1, H2, 0);
  return inverseTransform1(round1, s1, H1, false);
}

function m2xcFmt(blob) {
  const length = blob.length - 16;
  const prefix = String(length).padStart(8, "0");
  return prefix + b64Encode(blob);
}

function parseM2xcBlob(s) {
  return b64Decode(s.slice(8));
}

// ---- base64 ----
function b64Encode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function b64Decode(s) {
  let raw = s;
  while (raw.length % 4 !== 0) raw += "=";
  const bin = atob(raw);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function urlB64EncodeNoPad(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---- MD5 (para chk y dkKey/dmKey) ----
const md5 = (() => {
  function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
  const K = [];
  for (let i = 0; i < 64; i++) K[i] = (Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;
  const S = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
             5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
             4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
             6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
  function md5hex(str) {
    const bytes = new TextEncoder().encode(str);
    const msg = new Uint8Array(bytes.length + 1);
    msg.set(bytes);
    const len = bytes.length;
    const padded = new Uint8Array(((len + 8) >> 6 << 6) + 64);
    padded.set(bytes);
    padded[len] = 0x80;
    const bitLen = (len * 8) >>> 0;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, bitLen, true);
    let [a0, b0, c0, d0] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    for (let off = 0; off < padded.length; off += 64) {
      const Mw = [];
      for (let j = 0; j < 16; j++) Mw[j] = dv.getUint32(off + j * 4, true);
      let [A, B, C, D] = [a0, b0, c0, d0];
      for (let i = 0; i < 64; i++) {
        let F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * i) % 16; }
        F = (F + A + K[i] + Mw[g]) >>> 0;
        A = D; D = C; C = B;
        B = (B + rotl(F, S[i])) >>> 0;
      }
      a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
    }
    const out = new Uint8Array(16);
    const odv = new DataView(out.buffer);
    odv.setUint32(0, a0, true); odv.setUint32(4, b0, true); odv.setUint32(8, c0, true); odv.setUint32(12, d0, true);
    return Array.from(out).map(b => b.toString(16).padStart(2, "0")).join("");
  }
  return md5hex;
})();

// ---- AES-CBC (manual, sin padding - WebCrypto exige PKCS7 y el server usa ceros) ----
const K_IV = new Uint8Array([0x20,0x0b,0x5d,0x31,0x79,0x6f,0x03,0x2c,0x13,0x23,0x3b,0x65,0x54,0x3a,0x0b,0x5f]);

// AES-128 puro (tabla S-box estandar FIPS-197, hardcodeada y verificada)
const AES_SBOX = Uint8Array.from([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]);

const AES_RSBOX = (() => {
  const rs = new Uint8Array(256);
  for (let i = 0; i < 256; i++) rs[AES_SBOX[i]] = i;
  return rs;
})();

function xtime(a) { a <<= 1; return (a & 0x100) ? (a ^ 0x11b) : a; }
function gfMul(a, b) {
  let r = 0;
  while (b) { if (b & 1) r ^= a; a = xtime(a); b >>= 1; }
  return r & 0xff;
}

function aesExpandKey(key) {
  const nk = 4, nr = 10;
  const w = new Uint8Array(4 * (nr + 1) * 4);
  for (let i = 0; i < 16; i++) w[i] = key[i];
  const rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
  for (let i = nk; i < 4 * (nr + 1); i++) {
    let t = [w[(i - 1) * 4], w[(i - 1) * 4 + 1], w[(i - 1) * 4 + 2], w[(i - 1) * 4 + 3]];
    if (i % nk === 0) {
      t = [t[1], t[2], t[3], t[0]];
      t[0] = AES_SBOX[t[0]]; t[1] = AES_SBOX[t[1]]; t[2] = AES_SBOX[t[2]]; t[3] = AES_SBOX[t[3]];
      t[0] ^= rcon[i / nk - 1];
    }
    for (let j = 0; j < 4; j++) w[i * 4 + j] = w[(i - nk) * 4 + j] ^ t[j];
  }
  return w;
}

function aesAddRoundKey(state, w, round) {
  // estado col-major: i = 4*col + row
  for (let c = 0; c < 4; c++)
    for (let r = 0; r < 4; r++)
      state[4 * c + r] ^= w[round * 16 + c * 4 + r];
}

function aesSubBytes(state, inv) {
  const table = inv ? AES_RSBOX : AES_SBOX;
  for (let i = 0; i < 16; i++) state[i] = table[state[i]];
}

function aesShiftRows(state, inv) {
  // col-major: fila r -> bytes en posiciones r, 4+r, 8+r, 12+r
  const s = state.slice();
  for (let r = 1; r < 4; r++) {
    for (let c = 0; c < 4; c++) {
      const from = inv ? (c + 4 - r) % 4 : (c + r) % 4;
      state[4 * c + r] = s[4 * from + r];
    }
  }
}

function aesMixColumns(state, inv) {
  // col-major: columna c = state[4*c .. 4*c+3]
  for (let c = 0; c < 4; c++) {
    const a0 = state[4 * c], a1 = state[4 * c + 1], a2 = state[4 * c + 2], a3 = state[4 * c + 3];
    if (!inv) {
      state[4 * c]     = gfMul(a0, 2) ^ gfMul(a1, 3) ^ a2 ^ a3;
      state[4 * c + 1] = a0 ^ gfMul(a1, 2) ^ gfMul(a2, 3) ^ a3;
      state[4 * c + 2] = a0 ^ a1 ^ gfMul(a2, 2) ^ gfMul(a3, 3);
      state[4 * c + 3] = gfMul(a0, 3) ^ a1 ^ a2 ^ gfMul(a3, 2);
    } else {
      state[4 * c]     = gfMul(a0, 14) ^ gfMul(a1, 11) ^ gfMul(a2, 13) ^ gfMul(a3, 9);
      state[4 * c + 1] = gfMul(a0, 9) ^ gfMul(a1, 14) ^ gfMul(a2, 11) ^ gfMul(a3, 13);
      state[4 * c + 2] = gfMul(a0, 13) ^ gfMul(a1, 9) ^ gfMul(a2, 14) ^ gfMul(a3, 11);
      state[4 * c + 3] = gfMul(a0, 11) ^ gfMul(a1, 13) ^ gfMul(a2, 9) ^ gfMul(a3, 14);
    }
  }
}

function aesBlockCrypt(block, w, decrypt) {
  const state = block.slice();
  let round = 0;
  if (!decrypt) {
    aesAddRoundKey(state, w, 0);
    for (round = 1; round < 10; round++) {
      aesSubBytes(state, false);
      aesShiftRows(state, false);
      aesMixColumns(state, false);
      aesAddRoundKey(state, w, round);
    }
    aesSubBytes(state, false);
    aesShiftRows(state, false);
    aesAddRoundKey(state, w, 10);
  } else {
    aesAddRoundKey(state, w, 10);
    for (round = 9; round >= 1; round--) {
      aesShiftRows(state, true);
      aesSubBytes(state, true);
      aesAddRoundKey(state, w, round);
      aesMixColumns(state, true);
    }
    aesShiftRows(state, true);
    aesSubBytes(state, true);
    aesAddRoundKey(state, w, 0);
  }
  return state;
}

function aesCbcCryptManual(data, key, iv, decrypt) {
  const w = aesExpandKey(key);
  const out = new Uint8Array(data.length);
  let prev = iv.slice();
  for (let off = 0; off < data.length; off += 16) {
    const block = data.slice(off, off + 16);
    if (decrypt) {
      const plain = aesBlockCrypt(block, w, true);
      for (let i = 0; i < 16; i++) out[off + i] = plain[i] ^ prev[i];
      prev = block.slice();
    } else {
      for (let i = 0; i < 16; i++) block[i] ^= prev[i];
      const ct = aesBlockCrypt(block, w, false);
      out.set(ct, off);
      prev = ct;
    }
  }
  return out;
}

function aesCbcCrypt(data, key, encrypt) {
  // WebCrypto falla con padding de ceros del server; usar AES manual
  return aesCbcCryptManual(data, key, K_IV, !encrypt);
}

function deriveAesKey(secret) {
  const values = new Array(16).fill(11);
  const e = new TextEncoder().encode(secret);
  for (let i = 0; i < e.length; i++) {
    const slot = i % 16;
    values[slot] += e[slot] + e[i];
  }
  return Uint8Array.from(values.map(v => v & 0xff));
}

function deriveCustomAesKey(secret, offset) {
  const values = new Array(16).fill(11);
  const e = new TextEncoder().encode(secret);
  for (let i = 0; i < e.length; i++) {
    const slot = i % 16;
    let raw = values[slot] - 100 + offset + e[slot] + e[i];
    raw = ((raw % 256) + 256) % 256;
    values[slot] = raw;
  }
  return Uint8Array.from(values.map(v => v & 0xff));
}

// ---- RSA ----
async function rsaSignPkcs1Sha256(pem, msg) {
  const key = await crypto.subtle.importKey("pkcs8", pemToDer(pem), {
    name: "RSASSA-PKCS1-v1_5", hash: "SHA-256",
  }, false, ["sign"]);
  const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key, msg);
  return new Uint8Array(sig);
}

async function rsaPublicJwk(pem) {
  const key = await crypto.subtle.importKey("pkcs8", pemToDer(pem), {
    name: "RSASSA-PKCS1-v1_5", hash: "SHA-256",
  }, true, ["sign"]);
  return await crypto.subtle.exportKey("jwk", key); // {n, e} base64url
}

function b64urlToBytes(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  return b64Decode(b64);
}

// PKCS#1 ("BEGIN RSA PRIVATE KEY") -> DER PKCS#8 con wrapper:
// SEQUENCE { INTEGER 0, AlgorithmIdentifier rsaEncryption, OCTET STRING(pkcs1) }
function pemToDer(pem) {
  const lines = pem.split(/\r?\n/).filter(l => l.trim() && !l.includes("-----"));
  let der = b64Decode(lines.join(""));
  if (der[0] === 0x30 && der.length > 30 && der[9] === 0x06 && der[10] === 0x09) {
    // ya es PKCS#8 (tiene AlgorithmIdentifier) -> usar tal cual
    return der;
  }
  // PKCS#1 -> envolver
  const algId = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
  const body = [0x02, 0x01, 0x00, ...algId, 0x04, ...derLen(der.length), ...der];
  return Uint8Array.from([0x30, ...derLen(body.length), ...body]);
}

function derLen(n) {
  if (n < 0x80) return [n];
  const out = [];
  let tmp = n;
  while (tmp > 0) { out.unshift(tmp & 0xff); tmp >>>= 8; }
  return [0x80 | out.length, ...out];
}

// RSA PKCS1 v1.5 TIPO 2 encrypt con PS sin 0x00 (raw pow)
function rsaEncryptPkcs1(plainBytes, nBig, eBig, k) {
  const psLen = k - 3 - plainBytes.length;
  if (psLen < 8 || plainBytes.length > k - 11) throw new Error("rsaEncrypt: payload largo");
  const ps = [];
  while (ps.length < psLen) {
    const b = Math.floor(Math.random() * 255) + 1;
    if (b !== 0) ps.push(b);
  }
  const padded = new Uint8Array(k);
  padded[0] = 0x00; padded[1] = 0x02;
  padded.set(ps, 2);
  padded[2 + psLen] = 0x00;
  padded.set(plainBytes, 3 + psLen);
  let m = 0n;
  for (const b of padded) m = (m << 8n) | BigInt(b);
  let c = 1n;
  let base = m % nBig;
  let exp = eBig;
  while (exp > 0n) {
    if (exp & 1n) c = (c * base) % nBig;
    base = (base * base) % nBig;
    exp >>= 1n;
  }
  const cBytes = new Uint8Array(k);
  let tmp = c;
  for (let i = k - 1; i >= 0; i--) { cBytes[i] = Number(tmp & 0xffn); tmp >>= 8n; }
  return cBytes;
}

// ---- DTF ----
function sar32(value, shift) {
  return (value | 0) >> shift;
}

function dtfEncrypt(payload, secret) {
  const payloadLen = payload.length;
  const secretLen = secret.length;
  let ebx = (((payloadLen << 16) ^ secretLen) ^ 0x9e3779b9) >>> 0;
  const r12d = (ebx ^ 0xa5f00f5a) >>> 0;
  const out = [];
  appendU32Be(out, r12d);
  // u16 BE: byte alto primero
  out.push((((ebx >>> 16) ^ payloadLen) >> 8) & 0xff, ((ebx >>> 16) ^ payloadLen) & 0xff);
  out.push(((ebx ^ secretLen) >> 8) & 0xff, (ebx ^ secretLen) & 0xff);
  for (let i = 0; i < Math.max(payloadLen, secretLen); i++) {
    ebx = (ebx ^ (ebx << 13)) >>> 0;
    ebx = (ebx ^ sar32(ebx, 17)) >>> 0;
    ebx = (ebx ^ (ebx << 5)) >>> 0;
    const r14d = ebx & 0x0f;
    const edi = sar32(ebx, 4) & 0x0f;
    const pc = i < payloadLen ? payload[i] : (sar32(ebx, 8) & 0xff);
    const mc = i < secretLen ? secret[i] : (sar32(ebx, 16) & 0xff);
    let r15d = (pc + r14d) & 0xff;
    let r12v = (mc + edi) & 0xff;
    r15d ^= edi;
    r12v ^= r14d;
    if (ebx & 0x80) { out.push(r12v, r15d); }
    else { out.push(r15d, r12v); }
  }
  return b64Encode(Uint8Array.from(out));
}

function buildDtf(sk) {
  const h1 = (Math.random() * 0x100000000) >>> 0;
  const h2 = (Math.random() * 0x100000000) >>> 0;
  const dataIn = new TextEncoder().encode("-1457143643");
  const raw = m2xcEncryptFull(dataIn, new TextEncoder().encode(sk), h1, h2);
  let sf = String(11).padStart(8, "0") + b64Encode(raw);
  while (sf.length < 64) sf += String.fromCharCode(33 + Math.floor(Math.random() * 94));
  sf = sf.slice(0, 44) + "#" + sf.slice(45);
  return dtfEncrypt(new TextEncoder().encode(sf), new TextEncoder().encode(sk));
}

// ---- misc ----
function stringDesturple(token) {
  let s1 = "", s2 = "";
  let f = 0;
  let p1 = token.length / 4.0;
  let p2 = p1;
  for (let i = 0; i < token.length / 2; i++) {
    const pos = f === 0 ? Math.floor((p1 - 0.5) * 2.0 - 1.0) : Math.floor((p2 + 0.5) * 2.0 - 1.0);
    if (pos < 0 || pos + 1 >= token.length) break;
    const a = token[pos], b = token[pos + 1];
    if (f === 0) { s1 += b; s2 += a; }
    else { s1 += a; s2 += b; }
    f = 1 - f;
    if (f === 1) p1 -= 1.0; else p2 += 1.0;
  }
  return [s1, s2];
}

const MAGIC_CHARS = "abcdefghilmnopqrstuwjkxyzQWERTYUIOPASDFGHJKLZXCVBNM0123456789";

function genMagic(length = 64) {
  let out = "";
  for (let i = 0; i < length; i++)
    out += MAGIC_CHARS[Math.floor(Math.random() * MAGIC_CHARS.length)];
  return out;
}

function rndx() {
  return (Math.random()).toFixed(2);
}

function urlEncode(s, plusForSpace) {
  let out = "";
  for (const ch of new TextEncoder().encode(s)) {
    if ((ch >= 48 && ch <= 57) || (ch >= 65 && ch <= 90) || (ch >= 97 && ch <= 122)
        || ch === 45 || ch === 95 || ch === 46 || ch === 126) out += String.fromCharCode(ch);
    else if (ch === 32 && plusForSpace) out += "+";
    else out += "%" + ch.toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
}

// alias: md5 -> md5Hex (para compatibilidad con mito_client)
const md5Hex = md5;

export {
  m2xcEncryptFull, m2xcDecryptFull, m2xcFmt, parseM2xcBlob,
  b64Encode, b64Decode, urlB64EncodeNoPad, md5Hex,
  deriveAesKey, deriveCustomAesKey, aesCbcCrypt, aesCbcCryptManual,
  rsaSignPkcs1Sha256, rsaPublicJwk, rsaEncryptPkcs1, b64urlToBytes,
  buildDtf, dtfEncrypt, stringDesturple, genMagic, rndx, urlEncode,
};
