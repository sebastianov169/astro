// KV-backed rate limiting per IP and per license key
// Limits defined per endpoint, block for 5 minutes if exceeded

const LIMITS = {
  '/api/activate':  { max: 10, window: 60, blockTtl: 300 },  // 10/min, block 5m
  '/api/download':  { max: 20, window: 3600, blockTtl: 600 }, // 20/hour, block 10m
  '/api/validate':  { max: 30, window: 60, blockTtl: 300 },  // 30/min, block 5m
  '/api/heartbeat': { max: 30, window: 60, blockTtl: 300 },  // 30/min, block 5m
  '/api/telemetry': { max: 20, window: 60, blockTtl: 300 },  // 20/min, block 5m - prevents spam flood
  '/api/session': { max: 10, window: 60, blockTtl: 300 },  // 10/min - anti brute-force session creation
  '/api/session/validate': { max: 30, window: 60, blockTtl: 300 },  // 30/min - one-time use anyway
};

const DEFAULT_LIMIT = { max: 60, window: 60, blockTtl: 300 };

// Endpoints excludedos del contador KV: el free tier tiene 1000 writes/dia y estos
// endpoints se llaman cada minuto por cliente activo (heartbeat 1440/dia => quema la
// quota sola). Su proteccion real es la firma HMAC + logica one-time; el limite duro
// se reserva para los endpoints caros/sensibles (download, activate).
const NO_KV_ENDPOINTS = new Set(['/api/validate', '/api/heartbeat', '/api/telemetry', '/api/session']);

function getLimitForEndpoint(path) {
  return LIMITS[path] || DEFAULT_LIMIT;
}

function kvKey(type, identifier, endpoint) {
  return `rl:${type}:${identifier}:${endpoint}`;
}

function blockKey(type, identifier) {
  return `rlblk:${type}:${identifier}`;
}

/**
 * Check rate limit for an IP on a given endpoint.
 * Returns { allowed, remaining, retryAfter, limit }
 */
export async function checkRateLimit(env, ip, endpoint) {
  if (NO_KV_ENDPOINTS.has(endpoint)) return { allowed: true, remaining: 0, retryAfter: 0, limit: 0 };
  const limit = getLimitForEndpoint(endpoint);
  const nowSec = Math.floor(Date.now() / 1000);

  // Check if IP is blocked
  const blocked = await env.CACHE.get(blockKey('ip', ip));
  if (blocked) {
    const blockedAt = parseInt(blocked, 10);
    const retryAfter = blockedAt + limit.blockTtl - nowSec;
    if (retryAfter > 0) {
      return { allowed: false, remaining: 0, retryAfter, limit: limit.max };
    }
    // Block expired, remove it
    await env.CACHE.delete(blockKey('ip', ip));
  }

  const key = kvKey('ip', ip, endpoint);
  const raw = await env.CACHE.get(key, 'json');

  let count = 0;
  let windowStart = nowSec;

  if (raw && (nowSec - raw.start) < limit.window) {
    count = raw.count;
    windowStart = raw.start;
  }

  count++;

  if (count > limit.max) {
    // Block this IP (KV put wrapped: degrade to deny-open if quota exhausted)
    try {
      await env.CACHE.put(blockKey('ip', ip), String(nowSec), { expirationTtl: limit.blockTtl });
    } catch (e) {}
    const retryAfter = windowStart + limit.window - nowSec;
    return { allowed: false, remaining: 0, retryAfter: Math.max(retryAfter, limit.blockTtl), limit: limit.max };
  }

  // Update counter (set TTL to remaining window + buffer)
  // KV put wrapped: if the daily KV write quota is exhausted, degrade gracefully
  // (allow the request, skip the counter update) instead of 500ing every endpoint.
  const ttl = limit.window + 10;
  try {
    await env.CACHE.put(key, JSON.stringify({ start: windowStart, count }), { expirationTtl: ttl });
  } catch (e) {
    return { allowed: true, remaining: 0, retryAfter: 0, limit: limit.max };
  }

  return { allowed: true, remaining: limit.max - count, retryAfter: 0, limit: limit.max };
}

/**
 * Check rate limit for a license key on a given endpoint.
 * Returns { allowed, remaining, retryAfter, limit }
 */
export async function checkLicenseRateLimit(env, licenseKey, endpoint) {
  if (NO_KV_ENDPOINTS.has(endpoint)) return { allowed: true, remaining: 0, retryAfter: 0, limit: 0 };
  const limit = getLimitForEndpoint(endpoint);
  const nowSec = Math.floor(Date.now() / 1000);

  // Check if key is blocked
  const blocked = await env.CACHE.get(blockKey('key', licenseKey));
  if (blocked) {
    const blockedAt = parseInt(blocked, 10);
    const retryAfter = blockedAt + limit.blockTtl - nowSec;
    if (retryAfter > 0) {
      return { allowed: false, remaining: 0, retryAfter, limit: limit.max };
    }
    await env.CACHE.delete(blockKey('key', licenseKey));
  }

  const key = kvKey('key', licenseKey, endpoint);
  const raw = await env.CACHE.get(key, 'json');

  let count = 0;
  let windowStart = nowSec;

  if (raw && (nowSec - raw.start) < limit.window) {
    count = raw.count;
    windowStart = raw.start;
  }

  count++;

  if (count > limit.max) {
    try {
      await env.CACHE.put(blockKey('key', licenseKey), String(nowSec), { expirationTtl: limit.blockTtl });
    } catch (e) {}
    const retryAfter = windowStart + limit.window - nowSec;
    return { allowed: false, remaining: 0, retryAfter: Math.max(retryAfter, limit.blockTtl), limit: limit.max };
  }

  const ttl = limit.window + 10;
  try {
    await env.CACHE.put(key, JSON.stringify({ start: windowStart, count }), { expirationTtl: ttl });
  } catch (e) {
    return { allowed: true, remaining: 0, retryAfter: 0, limit: limit.max };
  }

  return { allowed: true, remaining: limit.max - count, retryAfter: 0, limit: limit.max };
}

/**
 * Build rate limit response headers
 */
export function rateLimitHeaders(result) {
  const headers = {};
  headers['X-RateLimit-Limit'] = String(result.limit);
  headers['X-RateLimit-Remaining'] = String(result.remaining);
  if (!result.allowed) {
    headers['Retry-After'] = String(result.retryAfter);
  }
  return headers;
}
