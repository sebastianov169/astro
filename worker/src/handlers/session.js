import { jsonResponse, errorResponse } from '../utils.js';
import { isValidLicenseKey, isValidHwid } from '../utils.js';
import { m3xcDecryptVerified as m3xcDecrypt, verifySignature } from './encryption.js';
import { licenseSignature } from './license_signing.js';

// Session tokens: single-use, short-lived handshake between loader and Astro.exe
// Table: session_tokens(token TEXT PRIMARY KEY, license_key TEXT, hwid TEXT, created_at TEXT, expires_at TEXT, used INTEGER DEFAULT 0)

async function ensureSessionSchema(env) {
  try { await env.DB.prepare("SELECT token FROM session_tokens LIMIT 1").first(); } catch {
    try {
      await env.DB.prepare(`CREATE TABLE IF NOT EXISTS session_tokens (
        token TEXT PRIMARY KEY,
        license_key TEXT NOT NULL,
        hwid TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL,
        used INTEGER DEFAULT 0
      )`).run();
    } catch {}
    try { await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_session_license ON session_tokens(license_key)").run(); } catch {}
  }
  // purge expired every call (cheap)
  try { await env.DB.prepare("DELETE FROM session_tokens WHERE datetime(expires_at) < datetime('now')").run(); } catch {}
}

// SECURITY FIX: HMAC mandatory for session endpoints (was missing)
// Without this, anyone with the static m3xc key could forge session tokens
async function verifySessionHmac(request, env, expectedPath) {
  const signature = request.headers.get('X-Signature');
  const timestamp = request.headers.get('X-Timestamp');
  if (!signature || !timestamp) return false;
  const ts = parseInt(timestamp, 10);
  if (isNaN(ts) || Math.abs(Date.now() / 1000 - ts) > 300) return false;
  // NOTE: nonce KV cache removed - the daily free-tier KV write quota (1000/day) dies
  // with per-request writes. Replay is already bounded by the 5-min timestamp window +
  // HMAC over body; session tokens are one-time anyway.
  const url = new URL(request.url);
  const path = expectedPath || url.pathname;
  const body = await request.clone().text();
  const payload = `${request.method}:${path}:${timestamp}:${body}`;
  return verifySignature(payload, signature, env.ENCRYPTION_KEY);
}

export async function createSession(request, env) {
  if (!env.ENCRYPTION_KEY) return errorResponse('Server misconfigured', 500);
  await ensureSessionSchema(env);
  // HMAC required
  if (!await verifySessionHmac(request, env, '/api/session')) return errorResponse('Invalid request signature', 403);
  let body;
  try { body = await request.json(); } catch { return errorResponse('Invalid JSON'); }
  // ENCRYPTED ONLY - no plain fallback
  if (!body.encrypted) return errorResponse('Encrypted payload required', 401);
  let inner;
  try {
    const dec = await m3xcDecrypt(body.encrypted, env.ENCRYPTION_KEY);
    inner = JSON.parse(dec);
  } catch { return errorResponse('Invalid encrypted payload', 400); }
  const license_key = inner.license_key || inner.key;
  const hwid = inner.hwid;
  const token = inner.token;
  if (!license_key || !hwid || !token) return errorResponse('Missing fields');
  if (!isValidLicenseKey(license_key)) return errorResponse('Invalid license key');
  if (!isValidHwid(hwid)) return errorResponse('Invalid HWID');
  if (typeof token !== 'string' || token.length < 32 || token.length > 128 || !/^[a-f0-9]+$/i.test(token)) return errorResponse('Invalid token');

  // verify license is active
  let lic;
  try { lic = await env.DB.prepare("SELECT * FROM licenses WHERE license_key = ?").bind(license_key).first(); } catch {}
  if (!lic || lic.is_revoked || lic.status !== 'active') return errorResponse('License not active', 403);
  if (lic.hwid_hash && lic.hwid_hash !== hwid) return errorResponse('HWID mismatch', 403);
  if (lic.expires_at && new Date(lic.expires_at) < new Date()) return errorResponse('License expired', 403);

  // R2 version info (fail-open, nunca romper la sesion por esto)
  let respVersion;
  let respAstroSha256;
  let respLoaderSha256;
  try {
    if (env.STORAGE) {
      const obj = await env.STORAGE.get('version.json');
      if (obj) {
        const txt = await obj.text();
        const data = JSON.parse(txt);
        if (data && typeof data.version === 'string' && typeof data.astro_sha256 === 'string') {
          respVersion = data.version;
          respAstroSha256 = data.astro_sha256;
        }
        if (data && typeof data.loader_sha256 === 'string') {
          respLoaderSha256 = data.loader_sha256;
        }
      }
    }
  } catch {}

  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5 min
  try {
    await env.DB.prepare("INSERT INTO session_tokens(token, license_key, hwid, expires_at) VALUES(?,?,?,?)")
      .bind(token.toLowerCase(), license_key, hwid, expiresAt).run();
  } catch (e) {
    const msg = String(e && e.message || e);
    if (msg.includes('UNIQUE') || msg.includes('PRIMARYKEY')) return errorResponse('Token already exists', 409);
    return errorResponse('Failed to create session', 500);
  }
  const resp = { success: true, expires_at: expiresAt };
  if (respVersion && respAstroSha256) {
    resp.version = respVersion;
    resp.astro_sha256 = respAstroSha256;
  }
  if (respLoaderSha256) resp.loader_sha256 = respLoaderSha256;
  return jsonResponse(resp);
}

export async function validateSession(request, env) {
  if (!env.ENCRYPTION_KEY) return errorResponse('Server misconfigured', 500);
  await ensureSessionSchema(env);
  if (!await verifySessionHmac(request, env, '/api/session/validate')) return errorResponse('Invalid request signature', 403);
  let body;
  try { body = await request.json(); } catch { return errorResponse('Invalid JSON'); }
  if (!body.encrypted) return errorResponse('Encrypted payload required', 401);
  let inner;
  try {
    const dec = await m3xcDecrypt(body.encrypted, env.ENCRYPTION_KEY);
    inner = JSON.parse(dec);
  } catch { return errorResponse('Invalid encrypted payload', 400); }
  const license_key = inner.license_key || inner.key;
  const hwid = inner.hwid;
  const token = inner.token;
  if (!license_key || !hwid || !token) return errorResponse('Missing fields');
  const row = await env.DB.prepare("SELECT * FROM session_tokens WHERE token = ?").bind(token.toLowerCase()).first();
  if (!row) return jsonResponse({ valid: false, error: 'Invalid session token' }, 403);
  if (row.used) return jsonResponse({ valid: false, error: 'Token already used' }, 403);
  if (new Date(row.expires_at) < new Date()) return jsonResponse({ valid: false, error: 'Token expired' }, 403);
  if (row.license_key !== license_key || row.hwid !== hwid) return jsonResponse({ valid: false, error: 'Token mismatch' }, 403);
  // also verify license still active
  const lic = await env.DB.prepare("SELECT * FROM licenses WHERE license_key = ?").bind(license_key).first();
  if (!lic || lic.is_revoked || lic.status !== 'active') return jsonResponse({ valid: false, error: 'License not active' }, 403);
  // mark used (one-time, atomic: only one concurrent consumer wins)
  let consume;
  try {
    consume = await env.DB.prepare("UPDATE session_tokens SET used = 1 WHERE token = ? AND used = 0").bind(token.toLowerCase()).run();
  } catch {
    return errorResponse('Failed to validate session', 500);
  }
  const affected = Number(consume?.meta?.changes ?? consume?.changes ?? 0);
  if (!affected) return jsonResponse({ valid: false, error: 'Token already used' }, 403);
  // SECURITY: challenge-response. The attestation now covers the client_nonce the
  // loader generated for THIS session, so a captured (sig, token) pair cannot be
  // replayed against another session - even with all symmetric keys extracted.
  let licSig = '';
  let licSigPlain = '';   // sin nonce: atestacion estable para license.dat bootstrap
  let expiryEpoch = '';
  try {
    const t = Date.parse(lic.expires_at);
    if (!isNaN(t)) expiryEpoch = Math.floor(t / 1000);
    licSig = await licenseSignature(env, license_key, lic.hwid_hash, lic.tier, lic.expires_at, inner.client_nonce || '');
    licSigPlain = await licenseSignature(env, license_key, lic.hwid_hash, lic.tier, lic.expires_at);
  } catch {}
  return jsonResponse({ valid: true, tier: lic.tier, expires_at: lic.expires_at,
                        expiry_epoch: expiryEpoch, sig: licSig, sig_lic: licSigPlain,
                        hwid_hash: lic.hwid_hash, client_nonce: inner.client_nonce || '' });
}
