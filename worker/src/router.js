import { validateLicense, activateLicense, heartbeat, killLicense, approveLicense, rejectLicense, createLicense, deleteLicense, removeLicense, autokillLicense } from './handlers/license.js';
import { downloadBackend, downloadManifest } from './handlers/download.js';
import { checkUpdate, uploadUpdate } from './handlers/update.js';
import { logTelemetry } from './handlers/telemetry.js';
import { getStats, getPendingLicenses, getLoginEvents } from './handlers/stats.js';
import { createSession, validateSession } from './handlers/session.js';
import { serveFrontend } from './handlers/frontend.js';
import { adminLogin } from './handlers/admin.js';
import { jsonResponse, errorResponse } from './utils.js';
import { checkRateLimit as legacyRateLimit, isValidAdminSession, logSecurityEvent } from './security.js';
import { getAlerts, markAlertsSeen } from './handlers/alerts.js';
import { checkRateLimit as kvRateLimit, rateLimitHeaders } from './middleware/rateLimit.js';

const SUSPICIOUS_AGENTS = /bot|crawl|spider|scan|nikto|sqlmap|nmap|masscan|zgrab|httpclient|python|go-http/i;

const BLOCKED_PATHS = new Set([
  '/wp-admin', '/wp-login.php', '/xmlrpc.php', '/.env',
  '/phpmyadmin', '/admin/config', '/.git/config',
]);

function getClientIP(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

function logRequest(request, env, path, clientIP) {
  const ua = request.headers.get('User-Agent') || 'unknown';
  const country = request.headers.get('CF-IPCountry') || '??';
  console.log(`[REQ] ${request.method} ${path} | ip=${clientIP} country=${country} ua=${ua}`);
}

export async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const clientIP = getClientIP(request);

  // --- Anti-abuse: block known scanner/attack paths ---
  if (BLOCKED_PATHS.has(path)) {
    logSecurityEvent(env, 'BLOCKED_PATH', `ip=${clientIP} path=${path}`);
    return errorResponse('Not found', 404);
  }

  // --- Anti-abuse: suspicious user-agents ---
  const ua = request.headers.get('User-Agent') || '';
  if (SUSPICIOUS_AGENTS.test(ua) && !path.startsWith('/api/health')) {
    logSecurityEvent(env, 'SUSPICIOUS_UA', `ip=${clientIP} ua=${ua}`);
    // Don't block outright, but log and add delay
    await new Promise(r => setTimeout(r, 2000));
  }

  // --- Anti-abuse: block non-browser requests to admin paths ---
  if (path.startsWith('/admin') && !path.startsWith('/api/admin')) {
    if (!ua.includes('Mozilla')) {
      logSecurityEvent(env, 'ADMIN_NON_BROWSER', `ip=${clientIP} path=${path}`);
    }
  }

  // --- Log all requests ---
  logRequest(request, env, path, clientIP);

  // --- Legacy rate limit (in-memory, fast) ---
  // Admin panel polls stats+alerts every 3s from one IP; exempting session-authenticated
  // admin paths avoids 429 toast spam while keeping the limit for anonymous traffic.
  const isAdminPath = path.startsWith('/api/admin') || path === '/api/stats' ||
                      path === '/api/pending' || path === '/api/alerts' || path === '/api/alerts/seen';
  if (!isAdminPath && !legacyRateLimit(clientIP)) {
    logSecurityEvent(env, 'RATE_LIMIT_EXCEEDED', `ip=${clientIP}`);
    return errorResponse('Rate limit exceeded', 429);
  }

  // --- Frontend ---
  if (path === '/' || path === '/admin') {
    return serveFrontend();
  }

  // --- Admin login (no session required) ---
  if (path === '/api/admin/login' && method === 'POST') {
    return adminLogin(request, env);
  }

  // --- Admin-only endpoints (require valid session) ---
  const adminGet = ['/api/stats', '/api/pending'];
  if (path === '/api/login-events' && method === 'GET') {
    const sessionToken = request.headers.get('X-Session-Token');
    if (!await isValidAdminSession(env, sessionToken)) {
      return errorResponse('Unauthorized', 401);
    }
    return getLoginEvents(request, env);
  }
  const adminPost = ['/api/kill', '/api/approve', '/api/reject', '/api/update', '/api/create', '/api/delete', '/api/remove', '/api/autokill'];

  if (adminGet.includes(path) && method === 'GET') {
    const sessionToken = request.headers.get('X-Session-Token');
    if (!await isValidAdminSession(env, sessionToken)) {
      return errorResponse('Unauthorized', 401);
    }
  }

  if (adminPost.includes(path) && method === 'POST') {
    const sessionToken = request.headers.get('X-Session-Token');
    if (!await isValidAdminSession(env, sessionToken)) {
      return errorResponse('Unauthorized', 401);
    }
  }

  // --- Public API routes (KV rate limiting applied inside handlers) ---
  if (path === '/api/validate' && method === 'POST') {
    return validateLicense(request, env);
  }

  if (path === '/api/activate' && method === 'POST') {
    return activateLicense(request, env);
  }

  if (path === '/api/heartbeat' && method === 'POST') {
    return heartbeat(request, env);
  }

  if (path === '/api/download' && method === 'GET') {
    return downloadBackend(request, env);
  }

  if (path === '/api/download' && method === 'POST') {
    return downloadManifest(request, env);
  }

  if (path === '/api/telemetry' && method === 'POST') {
    return logTelemetry(request, env);
  }

  if (path === '/api/update' && method === 'GET') {
    return checkUpdate(request, env);
  }

  // --- Session handshake (loader -> astro) --- HARDENED: rate limit + HMAC enforced in handler
  if (path === '/api/session' && method === 'POST') {
    const ipLimit = await kvRateLimit(env, clientIP, '/api/session');
    if (!ipLimit.allowed) {
      const resp = errorResponse('Rate limit exceeded', 429);
      for (const [k,v] of Object.entries(rateLimitHeaders(ipLimit))) resp.headers.set(k,v);
      return resp;
    }
    const r = await createSession(request, env);
    for (const [k,v] of Object.entries(rateLimitHeaders(ipLimit))) r.headers.set(k,v);
    return r;
  }
  if (path === '/api/session/validate' && method === 'POST') {
    const ipLimit = await kvRateLimit(env, clientIP, '/api/session/validate');
    if (!ipLimit.allowed) {
      const resp = errorResponse('Rate limit exceeded', 429);
      for (const [k,v] of Object.entries(rateLimitHeaders(ipLimit))) resp.headers.set(k,v);
      return resp;
    }
    const r = await validateSession(request, env);
    for (const [k,v] of Object.entries(rateLimitHeaders(ipLimit))) r.headers.set(k,v);
    return r;
  }

  // --- Admin routes ---
  if (path === '/api/stats' && method === 'GET') {
    return getStats(request, env);
  }

  if (path === '/api/pending' && method === 'GET') {
    return getPendingLicenses(request, env);
  }

  if (path === '/api/alerts' && method === 'GET') {
    const url2 = new URL(request.url);
    const limit = Math.min(parseInt(url2.searchParams.get('limit') || '100', 10) || 100, 500);
    const unseenOnly = url2.searchParams.get('unseen') === '1';
    const alerts = await getAlerts(env, { limit, unseenOnly });
    return jsonResponse({ success: true, alerts, count: alerts.length });
  }

  if (path === '/api/alerts/seen' && method === 'POST') {
    let ids = null;
    try { const b = await request.json(); if (Array.isArray(b.ids)) ids = b.ids; } catch {}
    return jsonResponse(await markAlertsSeen(env, ids));
  }

  if (path === '/api/create' && method === 'POST') {
    return createLicense(request, env);
  }

  if (path === '/api/kill' && method === 'POST') {
    return killLicense(request, env);
  }

  if (path === '/api/approve' && method === 'POST') {
    return approveLicense(request, env);
  }

  if (path === '/api/reject' && method === 'POST') {
    return rejectLicense(request, env);
  }
  
  if (path === '/api/delete' && method === 'POST') {
    return deleteLicense(request, env);
  }
  if (path === '/api/remove' && method === 'POST') {
    return removeLicense(request, env);
  }
  if (path === '/api/autokill' && method === 'POST') {
    return autokillLicense(request, env);
  }
  
  if (path === '/api/update' && method === 'POST') {
    return uploadUpdate(request, env);
  }

  if (path === '/api/health') {
    return jsonResponse({ status: 'ok', timestamp: Date.now() });
  }

  // --- Unknown path: log and reject ---
  logSecurityEvent(env, 'UNKNOWN_PATH', `ip=${clientIP} path=${path} method=${method}`);
  return errorResponse('Not found', 404);
}
