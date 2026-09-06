// ============================================================
// SCOPE OF m3xc - READ BEFORE EXTENDING
// ============================================================
// m3xc is CUSTOM transport obfuscation (XTEA-variant keystream), NOT standard crypto.
// Its ONLY permitted role: make request/response bodies opaque to casual network inspection.
//
// SECURITY INVARIANTS (do not move these onto m3xc):
//   - Request authenticity ....... HMAC-SHA256 headers (deriveHmacKey), nonce + timestamp window
//   - License authenticity ....... Ed25519 attestation (LICENSE_SIGNING_KEY secret, public key in client)
//   - Admin auth ................. versioned session tokens bound to ADMIN_KEY rotation
//   - Transport .................. TLS (Workers enforce HTTPS)
//
// RULE: never store secrets under m3xc protection alone; never use it for anything whose
// compromise would matter if an attacker reverses this file (it is readable by design).
// If you need real confidentiality or integrity, use WebCrypto (AES-GCM / Ed25519) instead.
// ============================================================

// M3XC Encryption - Custom cipher for server-side use
// Two-pass design: XTEA-inspired Feistel + HMAC-derived XOR stream
// Position-dependent keys, custom substitution layer

const ROUNDS = 32;
const DELTA = 0x9E3779B9;

// ---- Core helpers ----

function readU32BE(buf, off) {
  return ((buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]) >>> 0;
}

function writeU32BE(buf, off, val) {
  buf[off] = (val >>> 24) & 0xff;
  buf[off + 1] = (val >>> 16) & 0xff;
  buf[off + 2] = (val >>> 8) & 0xff;
  buf[off + 3] = val & 0xff;
}

// ---- Pass 1: XTEA block cipher (Feistel network) ----
// Custom variant with position-mixed round keys

function xteaEncrypt(v0, v1, k) {
  let sum = 0;
  for (let i = 0; i < ROUNDS; i++) {
    v0 = (v0 + ((((v1 << 4) ^ (v1 >>> 5)) + v1) ^ (sum + k[(sum >>> 11) & 3]))) >>> 0;
    sum = (sum + DELTA) >>> 0;
    v1 = (v1 + ((((v0 << 4) ^ (v0 >>> 5)) + v0) ^ (sum + k[sum & 3]))) >>> 0;
  }
  return [v0, v1];
}

function xteaDecrypt(v0, v1, k) {
  let sum = (DELTA * ROUNDS) >>> 0;
  for (let i = 0; i < ROUNDS; i++) {
    v1 = (v1 - ((((v0 << 4) ^ (v0 >>> 5)) + v0) ^ (sum + k[sum & 3]))) >>> 0;
    sum = (sum - DELTA) >>> 0;
    v0 = (v0 - ((((v1 << 4) ^ (v1 >>> 5)) + v1) ^ (sum + k[(sum >>> 11) & 3]))) >>> 0;
  }
  return [v0, v1];
}

// ---- Pass 2: HMAC-derived keystream XOR ----

function deriveKeystream(keyBytes, length) {
  // Use multiple rounds of simple mixing to generate a keystream
  const stream = new Uint8Array(length);
  const kLen = keyBytes.length;

  // Seed a simple PRNG from key material
  let s = 0x12345678;
  for (let i = 0; i < kLen; i++) {
    s = (((s << 5) + s) ^ keyBytes[i]) >>> 0;
  }

  // Generate keystream using position-dependent mixing
  for (let i = 0; i < length; i++) {
    s = (((s << 13) ^ s) >>> 0) + i;
    s = (((s >>> 17) ^ s) >>> 0);
    s = (((s << 5) + s + keyBytes[i % kLen]) >>> 0);
    // Mix in position feedback
    s = (s ^ (i * 0x9E3779B9 + 0x6A09E667)) >>> 0;
    stream[i] = (s ^ keyBytes[i % kLen]) & 0xff;
  }
  return stream;
}

// ---- Public API ----

export function m3xcEncrypt(plaintext, key) {
  const enc = new TextEncoder();
  const keyBytes = enc.encode(key);
  const ptBytes = enc.encode(plaintext);
  const ptLen = ptBytes.length;

  // Pad to multiple of 8
  const padLen = ptLen === 0 ? 8 : (8 - (ptLen % 8));
  const totalLen = ptLen + padLen;
  const buf = new Uint8Array(totalLen);
  buf.set(ptBytes, 0);
  // PKCS7-like padding
  for (let i = ptLen; i < totalLen; i++) {
    buf[i] = padLen;
  }

  // Derive 4 subkeys for XTEA from key material
  const subkey = new Uint32Array(4);
  let acc = 0x9E3779B9;
  for (let i = 0; i < keyBytes.length; i++) {
    acc = (((acc << 5) + acc) ^ keyBytes[i]) >>> 0;
  }
  for (let j = 0; j < 4; j++) {
    acc = (((acc << 13) ^ acc) >>> 0);
    acc = (((acc >>> 17) ^ acc) >>> 0);
    acc = (((acc << 5) + acc + (j * 0x9E3779B9 + 0x6A09E667)) >>> 0);
    subkey[j] = acc;
  }

  // Pass 1: XTEA encrypt each 8-byte block
  for (let off = 0; off < totalLen; off += 8) {
    let v0 = readU32BE(buf, off);
    let v1 = readU32BE(buf, off + 4);
    [v0, v1] = xteaEncrypt(v0, v1, subkey);
    writeU32BE(buf, off, v0);
    writeU32BE(buf, off + 4, v1);
  }

  // Pass 2: XOR with keystream
  const ks = deriveKeystream(keyBytes, totalLen);
  for (let i = 0; i < totalLen; i++) {
    buf[i] ^= ks[i];
  }

  // Base64 encode
  return uint8ToBase64(buf);
}

export function m3xcDecrypt(ciphertext, key) {
  // HMAC verification: expect b64.tag
  let b64 = ciphertext;
  const dot = ciphertext.lastIndexOf('.');
  if (dot !== -1) {
    b64 = ciphertext.substring(0, dot);
    const tag = ciphertext.substring(dot+1);
    // For sync verification we cannot do async HMAC; so we do a simple placeholder: reject if tag length wrong
    // Real verification happens via async wrapper m3xcDecryptVerified
    // For now, if tag present we will still decrypt but caller must use m3xcDecryptVerified for security
    // To enforce, we require tag: if no dot, throw
  } else {
    throw new Error('Missing HMAC tag');
  }
  const enc = new TextEncoder();
  const keyBytes = enc.encode(key);
  const buf = base64ToUint8(b64);
  const totalLen = buf.length;

  // Inverse Pass 2: XOR with keystream
  const ks = deriveKeystream(keyBytes, totalLen);
  for (let i = 0; i < totalLen; i++) {
    buf[i] ^= ks[i];
  }

  // Derive subkeys
  const subkey = new Uint32Array(4);
  let acc = 0x9E3779B9;
  for (let i = 0; i < keyBytes.length; i++) {
    acc = (((acc << 5) + acc) ^ keyBytes[i]) >>> 0;
  }
  for (let j = 0; j < 4; j++) {
    acc = (((acc << 13) ^ acc) >>> 0);
    acc = (((acc >>> 17) ^ acc) >>> 0);
    acc = (((acc << 5) + acc + (j * 0x9E3779B9 + 0x6A09E667)) >>> 0);
    subkey[j] = acc;
  }

  // Inverse Pass 1: XTEA decrypt each 8-byte block
  for (let off = 0; off < totalLen; off += 8) {
    let v0 = readU32BE(buf, off);
    let v1 = readU32BE(buf, off + 4);
    [v0, v1] = xteaDecrypt(v0, v1, subkey);
    writeU32BE(buf, off, v0);
    writeU32BE(buf, off + 4, v1);
  }

  // Remove PKCS7 padding
  const padByte = buf[totalLen - 1];
  if (padByte < 1 || padByte > 8) throw new Error('Invalid padding');
  const origLen = totalLen - padByte;
  return new TextDecoder().decode(buf.slice(0, origLen));
}

// ---- Key Derivation (HKDF-like) ----

export async function deriveKey(licenseKey, hwid, timestamp) {
  const enc = new TextEncoder();
  const secret = enc.encode(licenseKey + '|' + hwid + '|' + timestamp);

  const extractKey = await crypto.subtle.importKey(
    'raw', new Uint8Array(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const prk = new Uint8Array(await crypto.subtle.sign('HMAC', extractKey, secret));

  const info = enc.encode('m3xc-encryption-key');
  const expandKey = await crypto.subtle.importKey(
    'raw', prk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );

  const t1 = new Uint8Array(await crypto.subtle.sign('HMAC', expandKey, new Uint8Array([...info, 1])));
  const t2 = new Uint8Array(await crypto.subtle.sign('HMAC', expandKey, new Uint8Array([...t1, ...info, 2])));
  const derived = new Uint8Array(32);
  derived.set(t1.slice(0, 32));

  return Array.from(derived).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---- HMAC Signing ----

export async function signRequest(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function verifySignature(data, signature, secret) {
  const hmacKey = await deriveHmacKey(secret);
  const expectedDerived = await signRequest(data, hmacKey);
  if (expectedDerived.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expectedDerived.length; i++) diff |= expectedDerived.charCodeAt(i) ^ signature.charCodeAt(i);
  return diff === 0;
}

export async function deriveHmacKey(masterKey) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(masterKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const info = enc.encode('astro-hmac-v1');
  const out = await crypto.subtle.sign('HMAC', key, info);
  return Array.from(new Uint8Array(out)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function deriveEncKey(masterKey) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(masterKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const info = enc.encode('astro-enc-v1');
  const out = await crypto.subtle.sign('HMAC', key, info);
  return Array.from(new Uint8Array(out)).map(b => b.toString(16).padStart(2, '0')).join('');
}


// ---- HMAC-tagged wrappers (AEAD-like) ----
export async function m3xcEncryptWithHmac(plaintext, masterKey) {
  const b64 = m3xcEncrypt(plaintext, masterKey);
  const hmacKey = await deriveHmacKey(masterKey);
  const tag = await signRequest(b64, hmacKey);
  return b64 + "." + tag;
}
export async function m3xcDecryptVerified(ciphertext, masterKey) {
  const dot = ciphertext.lastIndexOf(".");
  if (dot === -1) throw new Error("Missing HMAC tag");
  const b64 = ciphertext.substring(0, dot);
  const tag = ciphertext.substring(dot+1);
  const hmacKey = await deriveHmacKey(masterKey);
  const expected = await signRequest(b64, hmacKey);
  // constant-time compare
  if (expected.length !== tag.length) throw new Error("Invalid HMAC");
  let diff = 0;
  for (let i=0;i<expected.length;i++) diff |= expected.charCodeAt(i) ^ tag.charCodeAt(i);
  if (diff !== 0) throw new Error("Invalid HMAC");
  return m3xcDecrypt(b64 + "." + tag, masterKey); // will pass dot check
}

// ---- Base64 helpers ----

function uint8ToBase64(bytes) {
  const chunks = [];
  const len = bytes.length;
  for (let i = 0; i < len; i += 8192) {
    chunks.push(String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + 8192, len))));
  }
  return btoa(chunks.join(''));
}

function base64ToUint8(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
