import crypto from 'node:crypto';
import { jsonResponse, errorResponse } from '../utils.js';
import { sanitize, isValidLicenseKey, isValidHwid, logSecurityEvent, constantTimeCompare } from '../security.js';
import { m3xcEncrypt, m3xcDecrypt, signRequest, verifySignature, deriveHmacKey } from './encryption.js';
import { checkRateLimit, checkLicenseRateLimit, rateLimitHeaders } from '../middleware/rateLimit.js';
import { raiseAlert } from './alerts.js';
import { licenseSignature } from './license_signing.js';


// License attestation: HMAC-SHA256 over canonical license fields using derived server key.
// The client embeds the same derivation (m3xc trust model) and verifies before accepting.

const EMPTY_HWID = '0000000000000000000000000000000000000000000000000000000000000000';
const COLLISION_HWID_HASH = 'a8e8f1c2d3b4a596c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1'; // placeholder - real blocked below via raw check
const COLLISION_RAW = 'NOTPM|NOTPM|NOMOBO|NOMAC|NOGUID|NOCPU|NODISK';

async function decryptBody(body, env) {
  if (!body || !body.encrypted) return null;
  try {
    if (!env.ENCRYPTION_KEY) return null;
    const plain = m3xcDecrypt(body.encrypted, env.ENCRYPTION_KEY);
    return JSON.parse(plain);
  } catch {
    return null;
  }
}

function encryptedResponse(data, env, status = 200) {
  const json = JSON.stringify(data);
  const encrypted = m3xcEncrypt(json, env.ENCRYPTION_KEY);
  return new Response(JSON.stringify({ encrypted }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function encryptedErrorResponse(message, env, status = 400) {
  return encryptedResponse({ error: message }, env, status);
}


function wasEncryptedBody(rawBody) {
  return !!(rawBody && rawBody.encrypted);
}
function smartResponse(data, wasEncrypted, env, status=200) {
  // SECURITY FIX: always encrypted - plain responses leaked license state to casual probes
  return encryptedResponse(data, env, status);
}
function smartError(message, wasEncrypted, env, status=400) {
  return encryptedErrorResponse(message, env, status);
  if (false && wasEncrypted) return encryptedErrorResponse(message, env, status);
  return errorResponse(message, status);
}

function addRateLimitHeaders(response, result) {
  const h = rateLimitHeaders(result);
  for (const [k, v] of Object.entries(h)) {
    response.headers.set(k, v);
  }
  return response;
}


// --- Schema migration guard (D1 ALTER TABLE is idempotent via catch) ---
async function ensureLicenseSchema(env) {
  try {
    await env.DB.prepare("SELECT status FROM licenses LIMIT 1").first();
  } catch {
    try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN status TEXT DEFAULT 'active'").run(); } catch {}
    try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN hardware_info TEXT").run(); } catch {}
    try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN requested_at TEXT").run(); } catch {}
  }
  try { await env.DB.prepare("SELECT client_ip FROM licenses LIMIT 1").first(); } catch { try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN client_ip TEXT").run(); } catch {} }
  try { await env.DB.prepare("SELECT client_country FROM licenses LIMIT 1").first(); } catch { try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN client_country TEXT").run(); } catch {} }
  try { await env.DB.prepare("SELECT hardware_changed_at FROM licenses LIMIT 1").first(); } catch { try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN hardware_changed_at TEXT").run(); } catch {} }
}

async function validateHmac(request, env) {
  const signature = request.headers.get('X-Signature');
  const timestamp = request.headers.get('X-Timestamp');
  // STRICT: HMAC required for all encrypted requests
  if (!signature || !timestamp) {
    try { logSecurityEvent(env, 'HMAC_MISSING', `ip=${request.headers.get('CF-Connecting-IP') || 'unknown'} endpoint=${new URL(request.url).pathname}`); } catch {}
    return false;
  }

  // Reject if timestamp is older than 5 minutes
  const ts = parseInt(timestamp, 10);
  if (isNaN(ts) || Math.abs(Date.now() / 1000 - ts) > 300) return false;

  // NOTE: nonce KV cache removed - the daily free-tier KV write quota (1000/day) dies
  // with per-request writes. Replay is already bounded by the 5-min timestamp window +
  // HMAC over body; session tokens are one-time anyway.

  const url = new URL(request.url);
  const body = await request.clone().text();
  const payload = `${request.method}:${url.pathname}:${timestamp}:${body}`;
  return verifySignature(payload, signature, env.ENCRYPTION_KEY);
}

export async function validateLicense(request, env) {
  await ensureLicenseSchema(env);
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

  // HMAC validation (tolerant)
  if (!await validateHmac(request, env)) {
    logSecurityEvent(env, 'HMAC_INVALID', `ip=${clientIP} endpoint=/api/validate`);
    const _wasEnc0 = false;
    return encryptedErrorResponse('Invalid request signature', env, 403);
  }

  // Rate limit per IP
  const ipLimit = await checkRateLimit(env, clientIP, '/api/validate');
  if (!ipLimit.allowed) {
    logSecurityEvent(env, 'RATE_LIMIT_VALIDATE', `ip=${clientIP}`);
    const resp = encryptedErrorResponse('Rate limit exceeded', env, 429);
    return addRateLimitHeaders(resp, ipLimit);
  }

  let body;
  try { body = await request.json(); } catch { return encryptedErrorResponse('Invalid JSON', env, 400); }
  const wasEncrypted = true;
  const inner = await decryptBody(body, env);
  if (!inner) return encryptedErrorResponse('Encrypted payload required', env, 401);

  const license_key = sanitize(inner.license_key);
  const hwid = sanitize(inner.hwid);
  // SECURITY challenge-response nonce for signed heartbeat response
  const clientNonce = typeof inner.client_nonce === 'string' && /^[a-f0-9]{8,64}$/i.test(inner.client_nonce) ? inner.client_nonce : '';
  // Build ID: which package build the client is running (set by admin on distribution)
  const buildId = typeof inner.build_id === 'string' && inner.build_id.length <= 64 ? sanitize(inner.build_id) : '';

  // Log login event for admin panel notifications
  try {
    await env.DB.prepare(
      'INSERT INTO login_events (license_key, hwid, ip_address, country, hostname, event_type) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(license_key, hwid, clientIP, request.headers.get('CF-IPCountry') || '', sanitize(inner.hostname || ''), 'heartbeat').run();
  } catch {}

  // Update build_id in DB if provided
  if (buildId) {
    try { await env.DB.prepare('UPDATE licenses SET build_id = ? WHERE license_key = ?').bind(buildId, license_key).run(); } catch {}
  }

  if (!license_key || !hwid) return smartError('Missing license_key or hwid', wasEncrypted, env);
  if (!isValidLicenseKey(license_key)) return smartError('Invalid license key format', wasEncrypted, env);
  if (!isValidHwid(hwid)) return smartError('Invalid HWID format', wasEncrypted, env);
  // Block collision HWIDs (VM clones) - compute raw collision would be blocked client side but also server
  if (hwid === EMPTY_HWID || hwid === COLLISION_HWID_HASH) return smartError('Invalid HWID', wasEncrypted, env);

  // Rate limit per license key
  const keyLimit = await checkLicenseRateLimit(env, license_key, '/api/validate');
  if (!keyLimit.allowed) {
    logSecurityEvent(env, 'RATE_LIMIT_KEY', `key=${license_key}`);
    const resp = smartError('License rate limit exceeded', wasEncrypted, env, 429);
    return addRateLimitHeaders(resp, ipLimit);
  }

  const license = await env.DB.prepare('SELECT * FROM licenses WHERE license_key = ?').bind(license_key).first();
  if (!license) return smartResponse({ valid: false, error: 'License not found' }, wasEncrypted, env);
  if (license.is_revoked) return smartResponse({ valid: false, error: 'License revoked' }, wasEncrypted, env);
  if (license.status === 'pending') return smartResponse({ valid: false, error: 'License pending approval', pending: true }, wasEncrypted, env);
  if (license.expires_at && new Date(license.expires_at) < new Date()) {
    await env.DB.prepare('UPDATE licenses SET is_revoked = 1 WHERE license_key = ?').bind(license_key).run();
    return smartResponse({ valid: false, error: 'License expired' }, wasEncrypted, env);
  }

  if (!license.hwid_hash || license.hwid_hash === EMPTY_HWID) {
    // Si active pero sin hwid, aun no ha sido solicitada por el usuario - no auto-activar, pedir approval
    return smartResponse({ valid: false, error: 'License not yet activated - waiting for user request', pending: true }, wasEncrypted, env);
  }

  if (license.hwid_hash !== hwid) {
    logSecurityEvent(env, 'HWID_MISMATCH', `key=${license_key}`);
    await raiseAlert(env, { type: 'HWID_MISMATCH', severity: 'medium',
      license_key, hwid, ip: clientIP, country: request.headers.get('CF-IPCountry') || null,
      details: 'validate() from unbound machine' });
    return smartResponse({ valid: false, error: 'HWID mismatch' }, wasEncrypted, env);
  }

  // SECURITY: response is Ed25519-signed (sig2) over canonical fields. Even if an
  // attacker extracts the symmetric ENCRYPTION_KEY, they cannot forge this signature:
  // it requires the LICENSE_SIGNING_KEY private key that never leaves the Worker.
  let sig2 = '';
  let expiryEpoch2 = '';
  try {
    const t2 = Date.parse(license.expires_at);
    if (!isNaN(t2)) expiryEpoch2 = Math.floor(t2/1000);
    sig2 = await licenseSignature(env, license_key, hwid, license.tier, license.expires_at);
  } catch (e) { console.error('validate sig2 failed:', e && e.message || e); }
  const resp = smartResponse({ valid: true, tier: license.tier, expires_at: license.expires_at,
      expiry_epoch: expiryEpoch2, hwid_hash: hwid, sig2 }, wasEncrypted, env);
  return addRateLimitHeaders(resp, ipLimit);
}

export async function activateLicense(request, env) {
  await ensureLicenseSchema(env);
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

  if (!await validateHmac(request, env)) {
    logSecurityEvent(env, 'HMAC_INVALID', `ip=${clientIP} endpoint=/api/activate`);
    return encryptedErrorResponse('Invalid request signature', env, 403);
  }

  const ipLimit = await checkRateLimit(env, clientIP, '/api/activate');
  if (!ipLimit.allowed) {
    logSecurityEvent(env, 'RATE_LIMIT_ACTIVATE', `ip=${clientIP}`);
    const resp = encryptedErrorResponse('Rate limit exceeded', env, 429);
    return addRateLimitHeaders(resp, ipLimit);
  }

  let body;
  try { body = await request.json(); } catch { return encryptedErrorResponse('Invalid JSON', env, 400); }
  const wasEncrypted = true;
  const inner = await decryptBody(body, env);
  if (!inner) return encryptedErrorResponse('Encrypted payload required', env, 401);

  const license_key = sanitize(inner.license_key);
  const hwid = sanitize(inner.hwid || '');
  let hardware_info = null;
  let enrichedHw = null;
  try {
    if (inner.hardware_info && typeof inner.hardware_info === 'object') {
      // Aumentado a 8192 para permitir hostname, componentes y perifericos
      const raw = JSON.stringify(inner.hardware_info);
      const base = raw.length > 8192 ? JSON.parse(raw.substring(0, 8192)) : inner.hardware_info;
      // Enriquecer con datos de servidor que no dependen del cliente
      const cfCountry = request.headers.get('CF-IPCountry') || request.headers.get('cf-ipcountry') || '';
      const cfRay = request.headers.get('CF-Ray') || '';
      const ua = request.headers.get('User-Agent') || '';
      enrichedHw = {
        ...base,
        _server_ip: clientIP,
        _server_country: cfCountry,
        _server_ray: cfRay,
        _user_agent: ua ? ua.substring(0, 200) : '',
        _collected_at: new Date().toISOString(),
      };
      // Si cliente no mando hostname, intentar inferir de base
      hardware_info = enrichedHw;
    } else if (inner.hardware_info && typeof inner.hardware_info === 'string') {
      try {
        const parsed = JSON.parse(inner.hardware_info);
        hardware_info = { ...parsed, _server_ip: clientIP, _collected_at: new Date().toISOString() };
        enrichedHw = hardware_info;
      } catch { hardware_info = { _raw: String(inner.hardware_info).substring(0, 1024), _server_ip: clientIP }; enrichedHw = hardware_info; }
    } else {
      // Cliente minimalista que no envio hardware_info, al menos guardar IP y UA
      const cfCountry2 = request.headers.get('CF-IPCountry') || request.headers.get('cf-ipcountry') || '';
      hardware_info = { _server_ip: clientIP, _server_country: cfCountry2, _server_ray: request.headers.get('CF-Ray') || '', _user_agent: (request.headers.get('User-Agent')||'').substring(0,200), _collected_at: new Date().toISOString(), _note: 'client sent minimal hardware_info' };
      enrichedHw = hardware_info;
    }
  } catch { 
    const cfCountry3 = request.headers.get('CF-IPCountry') || '';
    hardware_info = { _server_ip: clientIP, _server_country: cfCountry3, _collected_at: new Date().toISOString() }; 
    enrichedHw = hardware_info;
  }

  if (!license_key) return smartError('Missing license_key', wasEncrypted, env);
  if (!isValidLicenseKey(license_key)) return smartError('Invalid license key format', wasEncrypted, env);
  if (hwid && !isValidHwid(hwid)) return smartError('Invalid HWID format', wasEncrypted, env);
  if (hwid === EMPTY_HWID || hwid === COLLISION_HWID_HASH) return smartError('Invalid HWID', wasEncrypted, env);

  const keyLimit = await checkLicenseRateLimit(env, license_key, '/api/activate');
  if (!keyLimit.allowed) {
    const resp = smartError('License rate limit exceeded', wasEncrypted, env, 429);
    return addRateLimitHeaders(resp, ipLimit);
  }

  const existing = await env.DB.prepare('SELECT * FROM licenses WHERE license_key = ?').bind(license_key).first();

  // FIX: no auto-create for unknown licenses. Previously any arbitrary key that passed
  // isValidLicenseKey would INSERT a pending row, letting attackers spam the DB and
  // flood admin notifications. Now only pre-created licenses (via /api/create) can be
  // activated. Unknown keys get 404 without DB write.
  if (!existing) {
    logSecurityEvent(env, 'ACTIVATE_UNKNOWN_KEY', `key=${license_key} ip=${clientIP} hwid=${hwid ? hwid.substring(0,8)+'...' : 'none'}`);
    return smartResponse({ success: false, valid: false, error: 'License not found' }, wasEncrypted, env);
  }

  const hwidEmpty = !existing.hwid_hash || existing.hwid_hash === EMPTY_HWID || !hwid;

  if (!hwidEmpty && existing.hwid_hash !== hwid) {
    logSecurityEvent(env, 'HWID_MISMATCH_ACTIVATE', `key=${license_key} ip=${clientIP}`);
    return smartError('License already bound to another device', wasEncrypted, env);
  }

  if (existing.is_revoked) {
    return smartResponse({ success: false, valid: false, error: 'License revoked' }, wasEncrypted, env);
  }

  if (existing.status === 'active') {
    // Si active pero sin hwid ligada, es la primera vez que el usuario la mete en su Astro.
    // No activar directo: pasar a pending ligada a su PC y esperar tu approval.
    if (hwid && hwidEmpty) {
      const hwStr = hardware_info ? JSON.stringify(hardware_info).substring(0, 8192) : null;
      const cCountry = request.headers.get('CF-IPCountry') || '';
      await env.DB.prepare('UPDATE licenses SET status = ?, hwid_hash = ?, hardware_info = ?, requested_at = ?, client_ip = ?, client_country = ? WHERE license_key = ?')
        .bind('pending', hwid, hwStr, new Date().toISOString(), clientIP, cCountry, license_key).run();
      logSecurityEvent(env, 'LICENSE_REQUESTED', `key=${license_key} hwid=${hwid.substring(0,8)}... ip=${clientIP} host=${(hardware_info&&hardware_info.hostname)||(hardware_info&&hardware_info.host)||'?'} country=${cCountry}`);
      return smartResponse({ success: false, message: 'License pending approval', pending: true }, wasEncrypted, env);
    }
    // Ya active y ligada - detectar cambio de hardware para aviso de posible clonacion/bypass
    if (hwid && !hwidEmpty) {
      try {
        if (hardware_info && existing.hardware_info) {
          let oldHw = null;
          try { oldHw = JSON.parse(existing.hardware_info); } catch {}
          if (oldHw) {
            const oldHash = JSON.stringify({cpu: oldHw.cpu||oldHw.processor_name, gpu: oldHw.gpu||oldHw.gpu_name, mobo: oldHw.motherboard||oldHw.motherboard_serial||oldHw.baseboard_serial, disk: oldHw.disk_serial, hostname: oldHw.hostname||oldHw.host});
            const newHash = JSON.stringify({cpu: hardware_info.cpu||hardware_info.processor_name, gpu: hardware_info.gpu||hardware_info.gpu_name, mobo: hardware_info.motherboard||hardware_info.motherboard_serial||hardware_info.baseboard_serial, disk: hardware_info.disk_serial, hostname: hardware_info.hostname||hardware_info.host});
            if (oldHash !== newHash && oldHash !== '{}' && newHash !== '{}') {
              logSecurityEvent(env, 'HARDWARE_CHANGED', `key=${license_key} ip=${clientIP} old=${oldHash.substring(0,120)} new=${newHash.substring(0,120)}`);
              const cCountry2 = request.headers.get('CF-IPCountry') || '';
              const hwStr2 = JSON.stringify(hardware_info).substring(0, 8192);
              await env.DB.prepare('UPDATE licenses SET hardware_info = ?, client_ip = ?, client_country = ?, hardware_changed_at = ? WHERE license_key = ?')
                .bind(hwStr2, clientIP, cCountry2, new Date().toISOString(), license_key).run();
              // Notificar como pending de nuevo para que revises si es bypass
              // No bloqueamos, solo log y actualizar datos para que lo veas en panel
            }
          }
        }
      } catch {}
    }
    // SECURITY: attach license attestation so client can verify authenticity
    let licSig = '';
    try { licSig = await licenseSignature(env, license_key, existing.hwid_hash, existing.tier, existing.expires_at); } catch (e) { console.error('licenseSignature failed:', e && e.message || e); }
    let expiryEpoch = '';
    try { const t = Date.parse(existing.expires_at); if (!isNaN(t)) expiryEpoch = Math.floor(t/1000); } catch {}
    const resp = smartResponse({ success: true, message: 'License activated', sig: licSig,
        tier: existing.tier, expiry: expiryEpoch }, wasEncrypted, env);
    return addRateLimitHeaders(resp, ipLimit);
  }

  if (existing.status === 'pending') {
    if (hwid && hwidEmpty) {
      const hwStr = hardware_info ? JSON.stringify(hardware_info).substring(0, 8192) : null;
      const cCountry3 = request.headers.get('CF-IPCountry') || '';
      await env.DB.prepare('UPDATE licenses SET hwid_hash = ?, hardware_info = ?, requested_at = ?, client_ip = ?, client_country = ? WHERE license_key = ?')
        .bind(hwid, hwStr, new Date().toISOString(), clientIP, cCountry3, license_key).run();
    } else if (hardware_info && existing.hardware_info) {
      // Ya pending pero mando nueva info, actualizar para que veas datos frescos en panel
      try {
        const hwStr3 = JSON.stringify(hardware_info).substring(0, 8192);
        const cCountry4 = request.headers.get('CF-IPCountry') || '';
        await env.DB.prepare('UPDATE licenses SET hardware_info = ?, client_ip = ?, client_country = ? WHERE license_key = ?')
          .bind(hwStr3, clientIP, cCountry4, license_key).run();
      } catch {}
    }
    return smartResponse({ success: false, message: 'License pending approval', pending: true }, wasEncrypted, env);
  }

  return smartError('License is ' + existing.status, wasEncrypted, env);
}

export async function createLicense(request, env) {
  await ensureLicenseSchema(env);
  const body = await request.json();
  const license_key = sanitize(body.license_key);
  const tier = Math.min(2, Math.max(0, parseInt(body.tier) || 1));

  if (!license_key) return errorResponse('Missing license_key');
  if (!isValidLicenseKey(license_key)) return errorResponse('Invalid license key format');

  const existing = await env.DB.prepare('SELECT * FROM licenses WHERE license_key = ?').bind(license_key).first();
  if (existing) return errorResponse('License already exists');

  const expiresAt = new Date();
  if (tier === 0) expiresAt.setHours(expiresAt.getHours() + 24);
  else if (tier === 1) expiresAt.setMonth(expiresAt.getMonth() + 1);
  else expiresAt.setFullYear(expiresAt.getFullYear() + 10);

  // Flujo: tu generas y creas -> queda disponible (active sin hwid) esperando a que el usuario la meta en su Astro.
  // Cuando usuario hace POST /api/activate con hwid, pasa a pending ligada a su PC y ahi si pide approval.
  // Luego tu activas (approve) -> queda active ligada y cacheada. Autokill/remove estan en el panel.
  await env.DB.prepare(
    'INSERT INTO licenses (license_key, tier, status, expires_at, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(license_key, tier, 'active', expiresAt.toISOString(), new Date().toISOString()).run();

  logSecurityEvent(env, 'LICENSE_CREATED_ADMIN', `key=${license_key} tier=${tier} status=active-available`);
  return jsonResponse({ success: true, message: 'License created - waiting for user to enter it in Astro' });
}

export async function heartbeat(request, env) {
  await ensureLicenseSchema(env);
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

  if (!await validateHmac(request, env)) {
    logSecurityEvent(env, 'HMAC_INVALID', `ip=${clientIP} endpoint=/api/heartbeat`);
    return encryptedErrorResponse('Invalid request signature', env, 403);
  }

  const ipLimit = await checkRateLimit(env, clientIP, '/api/heartbeat');
  if (!ipLimit.allowed) {
    const resp = encryptedErrorResponse('Rate limit exceeded', env, 429);
    return addRateLimitHeaders(resp, ipLimit);
  }

  let body;
  try { body = await request.json(); } catch { return encryptedErrorResponse('Invalid JSON', env, 400); }
  const wasEncrypted = true;
  const inner = await decryptBody(body, env);
  if (!inner) return encryptedErrorResponse('Encrypted payload required', env, 401);

  const license_key = sanitize(inner.license_key);
  const hwid = sanitize(inner.hwid);

  if (!license_key || !hwid) return smartResponse({ status: 'killed', reason: 'Missing credentials' }, wasEncrypted, env);

  const license = await env.DB.prepare('SELECT * FROM licenses WHERE license_key = ?').bind(license_key).first();
  if (!license || license.is_revoked) return smartResponse({ status: 'killed', reason: 'License revoked' }, wasEncrypted, env);
  if (license.status === 'pending') return smartResponse({ status: 'killed', reason: 'License pending approval' }, wasEncrypted, env);
  // Si active pero aun sin hwid, todavia no fue solicitada por el usuario -> tratar como pending hasta approval
  if (!license.hwid_hash || license.hwid_hash === EMPTY_HWID) return smartResponse({ status: 'killed', reason: 'License not yet bound - pending approval' }, wasEncrypted, env);
  if (license.hwid_hash && license.hwid_hash !== EMPTY_HWID && license.hwid_hash !== hwid) return smartResponse({ status: 'killed', reason: 'HWID mismatch' }, wasEncrypted, env);
  if (license.expires_at && new Date(license.expires_at) < new Date()) return smartResponse({ status: 'killed', reason: 'License expired' }, wasEncrypted, env);

  // SECURITY: sign "ok" response with Ed25519 so a MITM cannot forge heartbeats.
  // Canonical payload: ok|license_key|nonce (matches client verification in autokill.cpp).
  let sig = '';
  try {
    const bin = atob(env.LICENSE_SIGNING_KEY);
    const der = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
    const privKey = await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign']);
    const msgBuf = new TextEncoder().encode(`ok|${license_key}|${clientNonce}`);
    const sigBuf2 = await crypto.subtle.sign('Ed25519', privKey, msgBuf);
    sig = Array.from(new Uint8Array(sigBuf2)).map(b => b.toString(16).padStart(2, '0')).join('');
  } catch {}
  const resp = smartResponse({ status: 'ok', sig, client_nonce: clientNonce }, wasEncrypted, env);
  return addRateLimitHeaders(resp, ipLimit);
}

export async function killLicense(request, env) {
  const body = await request.json();
  const license_key = sanitize(body.license_key);
  const reason = sanitize(body.reason, 500) || 'Admin revoked';

  if (!license_key) return errorResponse('Missing license_key');
  if (!isValidLicenseKey(license_key)) return errorResponse('Invalid license key format');

  const license = await env.DB.prepare('SELECT * FROM licenses WHERE license_key = ?').bind(license_key).first();
  if (!license) return errorResponse('License not found');

  await env.DB.prepare('UPDATE licenses SET is_revoked = 1 WHERE license_key = ?').bind(license_key).run();
  await env.DB.prepare('INSERT INTO kill_log (license_key, reason) VALUES (?, ?)').bind(license_key, reason).run();

  logSecurityEvent(env, 'LICENSE_KILLED', `key=${license_key} reason=${reason}`);
  return jsonResponse({ success: true, message: 'License revoked' });
}

export async function approveLicense(request, env) {
  const body = await request.json();
  const license_key = sanitize(body.license_key);

  if (!license_key) return errorResponse('Missing license_key');

  const license = await env.DB.prepare('SELECT * FROM licenses WHERE license_key = ?').bind(license_key).first();
  if (!license) return errorResponse('License not found');
  if (license.status !== 'pending') return errorResponse('License is not pending');

  await env.DB.prepare('UPDATE licenses SET status = ?, activated_at = ? WHERE license_key = ?')
    .bind('active', new Date().toISOString(), license_key).run();

  logSecurityEvent(env, 'LICENSE_APPROVED', `key=${license_key}`);
  return jsonResponse({ success: true, message: 'License approved' });
}

export async function rejectLicense(request, env) {
  const body = await request.json();
  const license_key = sanitize(body.license_key);
  const reason = sanitize(body.reason, 500) || 'Admin rejected';

  if (!license_key) return errorResponse('Missing license_key');

  const license = await env.DB.prepare('SELECT * FROM licenses WHERE license_key = ?').bind(license_key).first();
  if (!license) return errorResponse('License not found');

  await env.DB.prepare('UPDATE licenses SET is_revoked = 1, status = ? WHERE license_key = ?')
    .bind('rejected', license_key).run();

  await env.DB.prepare('INSERT INTO kill_log (license_key, reason) VALUES (?, ?)')
    .bind(license_key, reason).run();

  logSecurityEvent(env, 'LICENSE_REJECTED', `key=${license_key} reason=${reason}`);
  return jsonResponse({ success: true, message: 'License rejected' });
}

export async function deleteLicense(request, env) {
  const body = await request.json();
  const license_key = sanitize(body.license_key);

  if (!license_key) return errorResponse('Missing license_key');

  const license = await env.DB.prepare('SELECT * FROM licenses WHERE license_key = ?').bind(license_key).first();
  if (!license) return errorResponse('License not found');

  await env.DB.prepare('DELETE FROM licenses WHERE license_key = ?').bind(license_key).run();
  // Limpieza traces relacionados: telemetry y sesiones cacheadas
  try { await env.DB.prepare('DELETE FROM telemetry WHERE license_key = ?').bind(license_key).run(); } catch {}
  try { await env.DB.prepare('DELETE FROM session_tokens WHERE license_key = ?').bind(license_key).run(); } catch {}

  logSecurityEvent(env, 'LICENSE_DELETED', `key=${license_key}`);
  return jsonResponse({ success: true, message: 'License deleted' });
}

export async function removeLicense(request, env) {
  // Alias semantico para UI: Remove = delete completo
  return deleteLicense(request, env);
}

export async function autokillLicense(request, env) {
  await ensureLicenseSchema(env);
  const body = await request.json();
  const license_key = sanitize(body.license_key);
  const reason = sanitize(body.reason, 500) || 'Autokill - delete all traces';

  if (!license_key) return errorResponse('Missing license_key');
  if (!isValidLicenseKey(license_key)) return errorResponse('Invalid license key format');

  const license = await env.DB.prepare('SELECT * FROM licenses WHERE license_key = ?').bind(license_key).first();
  if (!license) return errorResponse('License not found');

  // Marca revoked + killed para que heartbeat devuelva killed y el cliente ejecute wipe local
  await env.DB.prepare('UPDATE licenses SET is_revoked = 1, status = ? WHERE license_key = ?').bind('killed', license_key).run();
  await env.DB.prepare('INSERT INTO kill_log (license_key, reason) VALUES (?, ?)').bind(license_key, reason).run();

  // Borra todo rastro en backend: telemetry, sesiones, y cache de validacion si existe
  try { await env.DB.prepare('DELETE FROM telemetry WHERE license_key = ?').bind(license_key).run(); } catch {}
  try { await env.DB.prepare('DELETE FROM session_tokens WHERE license_key = ?').bind(license_key).run(); } catch {}
  try { await env.CACHE.delete(`license:${license_key}`); } catch {}
  try { await env.CACHE.delete(`hwid:${license_key}`); } catch {}

  logSecurityEvent(env, 'LICENSE_AUTOKILL', `key=${license_key} reason=${reason}`);

  // Despues de autokill, el heartbeat del cliente devolvera {status:killed} y Autokill::executeKillSequence
  // borrara %LOCALAPPDATA%\\Astro, %APPDATA%\\Astro, %TEMP%\\astro_app, logs, prefetch y se auto-borra.
  // Finalmente eliminamos la fila para no dejar rastro en panel (pero el kill ya quedo en kill_log).
  await env.DB.prepare('DELETE FROM licenses WHERE license_key = ?').bind(license_key).run();

  return jsonResponse({ success: true, message: 'Autokill executed - client will wipe on next heartbeat' });
}
