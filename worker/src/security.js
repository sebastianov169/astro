// Security middleware for the worker

// Simple in-memory rate limiter (per IP)
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX = 60; // 60 requests per minute per IP

export function checkRateLimit(ip) {
  const now = Date.now();
  const record = rateLimitMap.get(ip);
  
  if (!record || now - record.start > RATE_LIMIT_WINDOW) {
    rateLimitMap.set(ip, { start: now, count: 1 });
    return true;
  }
  
  record.count++;
  if (record.count > RATE_LIMIT_MAX) {
    return false;
  }
  return true;
}

// Sanitize string input - remove null bytes, control chars, limit length
export function sanitize(str, maxLen = 256) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // control chars
    .substring(0, maxLen)
    .trim();
}

// Validate license key format (alphanumeric + dashes, 16-128 chars)
export function isValidLicenseKey(key) {
  if (!key || typeof key !== 'string') return false;
  return key.length >= 16 && key.length <= 128 && /^[A-Za-z0-9\-]+$/.test(key);
}

// Validate HWID format (hex, 16-128 chars)
export function isValidHwid(hwid) {
  if (!hwid || typeof hwid !== 'string') return false;
  return hwid.length >= 16 && hwid.length <= 128 && /^[a-f0-9]+$/i.test(hwid);
}

// Constant-time string comparison to prevent timing attacks
export function constantTimeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// Verify admin key - constant-time comparison
export function verifyAdminKey(providedKey, actualKey) {
  if (!providedKey || !actualKey) return false;
  return constantTimeCompare(providedKey, actualKey);
}

// Generate a session token for admin
export function generateSessionToken() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Stateless admin session - HMAC signed, no KV (fixes eventual-consistency race)
// Token = timestamp_hex + "." + hmac_hex(timestamp, ADMIN_KEY)
// Valid for 1 year, no IP binding
// SECURITY FIX: 8h TTL (was 365 days). Token binds to a key-version derived from ADMIN_KEY,
// so rotating the admin key instantly invalidates every outstanding session.
const SESSION_TTL_MS = 8*60*60*1000;

async function hmacHex(key, msg) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey('raw', enc.encode(key), {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(msg));
  return Array.from(new Uint8Array(sig)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function keyVersion(env) {
  // Short digest of ADMIN_KEY so sessions die when the key rotates
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('astro-admin-v1:' + env.ADMIN_KEY));
  return Array.from(new Uint8Array(d)).slice(0,4).map(b=>b.toString(16).padStart(2,'0')).join('');
}

export async function createAdminSession(env) {
  const ts = Date.now().toString(16);
  const ver = await keyVersion(env);
  const sig = await hmacHex(env.ADMIN_KEY, ts + ':' + ver);
  return ts + '.' + ver + '.' + sig;
}

export async function isValidAdminSession(env, token) {
  if (!token || !token.includes('.')) return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [tsHex, ver, sig] = parts;
  if (!tsHex || !ver || !sig) return false;
  const ts = parseInt(tsHex, 16);
  if (isNaN(ts) || Date.now() - ts > SESSION_TTL_MS) return false;
  // Reject sessions minted under a different (older rotated-out) admin key
  const currentVer = await keyVersion(env);
  if (ver !== currentVer) return false;
  const expected = await hmacHex(env.ADMIN_KEY, tsHex + ':' + ver);
  // constant-time compare
  if (expected.length !== sig.length) return false;
  let diff = 0;
  for (let i=0;i<expected.length;i++) diff |= expected.charCodeAt(i) ^ sig.charCodeAt(i);
  return diff === 0;
}

// Security headers
export function securityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
  };
}

// Log security events
export function logSecurityEvent(env, event, details) {
  const timestamp = new Date().toISOString();
  console.log(`[SECURITY] ${timestamp} | ${event} | ${details}`);
}
