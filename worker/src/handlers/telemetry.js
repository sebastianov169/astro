import { jsonResponse, errorResponse } from '../utils.js';
import { sanitize, isValidLicenseKey, isValidHwid, logSecurityEvent } from '../security.js';
import { m3xcDecrypt } from './encryption.js';
import { checkRateLimit, rateLimitHeaders } from '../middleware/rateLimit.js';

async function decryptBody(body, env) {
  if (!body || !body.encrypted) return null;
  try {
    if (!env.ENCRYPTION_KEY) return null;
    const plain = m3xcDecrypt(body.encrypted, env.ENCRYPTION_KEY);
    return JSON.parse(plain);
  } catch { return null; }
}

async function validateHmacTelemetry(request, env) {
  const sig = request.headers.get('X-Signature');
  const ts = request.headers.get('X-Timestamp');
  if (!sig || !ts) return false;
  const tsi = parseInt(ts, 10);
  if (isNaN(tsi) || Math.abs(Date.now()/1000 - tsi) > 300) return false;
  // NOTE: nonce KV cache removed - free-tier KV write quota (1000/day) dies with
  // per-request writes. Replay bounded by the 5-min timestamp window + HMAC.
  const url = new URL(request.url);
  const body = await request.clone().text();
  const payload = `${request.method}:${url.pathname}:${ts}:${body}`;
  const { verifySignature } = await import('./encryption.js');
  return verifySignature(payload, sig, env.ENCRYPTION_KEY);
}

export async function logTelemetry(request, env) {
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

  // SECURITY FIX: HMAC mandatory - legacy plain tolerance removed after key rotation.
  if (!await validateHmacTelemetry(request, env)) {
    logSecurityEvent(env, 'TELEMETRY_HMAC_INVALID', `ip=${clientIP}`);
    return errorResponse('Invalid request signature', 403);
  }

  const ipLimit = await checkRateLimit(env, clientIP, '/api/telemetry');
  if (!ipLimit.allowed) {
    const resp = errorResponse('Rate limit exceeded', 429);
    for (const [k,v] of Object.entries(rateLimitHeaders(ipLimit))) resp.headers.set(k,v);
    return resp;
  }

  let body;
  try { body = await request.json(); } catch { return errorResponse('Invalid JSON', 400); }
  // Encrypted-only: plain payloads rejected
  const inner = await decryptBody(body, env);
  if (!inner) return errorResponse('Encrypted payload required', 401);

  const license_key = sanitize(inner.license_key);
  const hwid = sanitize(inner.hwid);
  const components = inner.components || {};

  if (!license_key || !hwid) return errorResponse('Missing license_key or hwid');
  if (!isValidLicenseKey(license_key)) return errorResponse('Invalid license key format');
  if (!isValidHwid(hwid)) return errorResponse('Invalid HWID format');

  // Only log telemetry for known licenses - prevents DB spam with arbitrary keys
  const lic = await env.DB.prepare('SELECT license_key FROM licenses WHERE license_key = ?').bind(license_key).first();
  if (!lic) {
    logSecurityEvent(env, 'TELEMETRY_UNKNOWN_KEY', `key=${license_key} ip=${clientIP}`);
    // Return success to not leak existence, but don't insert
    return jsonResponse({ success: true });
  }

  let compStr = '{}';
  try {
    const raw = JSON.stringify(components);
    compStr = raw.length > 4096 ? raw.substring(0, 4096) : raw;
  } catch { compStr = '{}'; }

  await env.DB.prepare(
    'INSERT INTO telemetry (license_key, hwid, ip_address, components) VALUES (?, ?, ?, ?)'
  ).bind(license_key, hwid, clientIP, compStr).run();

  const resp = jsonResponse({ success: true });
  for (const [k,v] of Object.entries(rateLimitHeaders(ipLimit))) resp.headers.set(k,v);
  return resp;
}
