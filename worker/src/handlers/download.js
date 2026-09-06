import { errorResponse } from '../utils.js';
import { logSecurityEvent } from '../security.js';
import { checkRateLimit, rateLimitHeaders } from '../middleware/rateLimit.js';
import { decryptBody, encryptedResponse } from './license_shared.js';

const BACKEND_FILE = 'astro_backend.dll';
const BACKEND_VERSION = 1;

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

async function sha256Hex(data) {
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Deriva key AES-GCM igual que el cliente: sha256(license_key + hwid) (concat directo)
async function deriveKeyBytes(licenseKey, hwid) {
  const enc = new TextEncoder();
  const material = enc.encode(licenseKey + hwid);
  const digest = await crypto.subtle.digest('SHA-256', material);
  return new Uint8Array(digest);
}

// Cifra raw DLL como IV(16) || ct || tag(16) con AES-256-GCM
async function encryptForUser(rawBytes, licenseKey, hwid) {
  const keyBytes = await deriveKeyBytes(licenseKey, hwid);
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const ctWithTag = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 }, key, rawBytes));
  // WebCrypto devuelve ct||tag juntos; el formato del cliente es IV||ct||tag
  const tag = ctWithTag.slice(ctWithTag.length - 16);
  const ct = ctWithTag.slice(0, ctWithTag.length - 16);
  const out = new Uint8Array(16 + ct.length + 16);
  out.set(iv, 0);
  out.set(ct, 16);
  out.set(tag, 16 + ct.length);
  return out;
}

async function validateLicenseForDownload(env, licenseKey, hwid, clientIP) {
  const license = await env.DB.prepare('SELECT * FROM licenses WHERE license_key = ?').bind(licenseKey).first();
  if (!license) {
    logSecurityEvent(env, 'DOWNLOAD_UNAUTHORIZED', 'key=' + licenseKey);
    return { error: 'License not found', status: 403 };
  }
  if (license.is_revoked) {
    logSecurityEvent(env, 'DOWNLOAD_REVOKED', 'key=' + licenseKey);
    return { error: 'License revoked', status: 403 };
  }
  if (license.status && license.status !== 'active') {
    logSecurityEvent(env, 'DOWNLOAD_NOT_ACTIVE', 'key=' + licenseKey + ' status=' + license.status);
    return { error: 'License not active: ' + license.status, status: 403 };
  }
  if (license.hwid_hash && license.hwid_hash !== hwid) {
    logSecurityEvent(env, 'DOWNLOAD_HWID_MISMATCH', 'key=' + licenseKey);
    return { error: 'HWID mismatch', status: 403 };
  }
  return { license };
}

// POST /api/download - action=manifest
// Devuelve { url, sha256, version, size } del backend cifrado para ese usuario.
export async function downloadManifest(request, env) {
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

  let body;
  try { body = await request.json(); } catch { return errorResponse('Invalid JSON', 400); }

  const inner = await decryptBody(body, env);
  if (!inner) return encryptedResponse({ error: 'Encrypted payload required' }, env, 401);

  const licenseKey = inner.license_key;
  const hwid = inner.hwid;
  if (!licenseKey || !hwid) return encryptedResponse({ error: 'Missing license_key or hwid' }, env, 400);

  const ipLimit = await checkRateLimit(env, clientIP, '/api/download');
  if (!ipLimit.allowed) {
    logSecurityEvent(env, 'RATE_LIMIT_DOWNLOAD', 'ip=' + clientIP);
    return encryptedResponse({ error: 'Rate limit exceeded' }, env, 429);
  }

  const check = await validateLicenseForDownload(env, licenseKey, hwid, clientIP);
  if (check.error) return encryptedResponse({ error: check.error }, env, check.status);

  if (!env.STORAGE) return encryptedResponse({ error: 'Storage not configured' }, env, 500);

  const object = await env.STORAGE.get(BACKEND_FILE);
  if (!object) return encryptedResponse({ error: 'Backend not deployed yet' }, env, 404);

  // sha256 del BLOB CIFRADO no se conoce sin cifrar; el cliente verifica el DLL
  // descifrado por estructura PE + firma interna, y el canal ya va autenticado.
  // Igual computamos sha256 del raw para integridad de referencia.
  const data = new Uint8Array(await object.arrayBuffer());
  const rawHash = await sha256Hex(data);

  logSecurityEvent(env, 'DOWNLOAD_MANIFEST', 'key=' + licenseKey + ' v=' + BACKEND_VERSION);

  const origin = new URL(request.url).origin;
  const url = origin + '/api/download?license_key=' + encodeURIComponent(licenseKey)
            + '&hwid=' + encodeURIComponent(hwid) + '&file=' + BACKEND_FILE;

  return encryptedResponse({
    url,
    sha256: rawHash,
    version: BACKEND_VERSION,
    size: data.length,
  }, env, 200);
}

// GET /api/download?license_key=..&hwid=..&file=astro_backend.dll
// Sirve la DLL cifrada IV||ct||tag para ese usuario (AES-256-GCM).
export async function downloadBackend(request, env) {
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const url = new URL(request.url);

  const ipLimit = await checkRateLimit(env, clientIP, '/api/download');
  if (!ipLimit.allowed) {
    logSecurityEvent(env, 'RATE_LIMIT_DOWNLOAD', 'ip=' + clientIP);
    const resp = errorResponse('Rate limit exceeded', 429);
    for (const [k, v] of Object.entries(rateLimitHeaders(ipLimit))) resp.headers.set(k, v);
    return resp;
  }

  const licenseKey = url.searchParams.get('license_key');
  const hwid = url.searchParams.get('hwid');
  const file = url.searchParams.get('file') || 'astro_package.zip';

  if (!licenseKey || !hwid) return errorResponse('Missing license_key or hwid');

  const check = await validateLicenseForDownload(env, licenseKey, hwid, clientIP);
  if (check.error) return errorResponse(check.error, check.status);

  if (!env.STORAGE) return errorResponse('Storage not configured', 500);

  const object = await env.STORAGE.get(file);
  if (!object) return errorResponse('File not found: ' + file, 404);

  const data = new Uint8Array(await object.arrayBuffer());

  // Zip legacy + loader: servir plano con sha256 (flujo del loader).
  // El .exe del loader no es secreto por usuario: se verifica por hash.
  if (file.endsWith('.zip') || file === 'AstroLoader.exe') {
    const hash = await sha256Hex(data);
    logSecurityEvent(env, 'DOWNLOAD_SUCCESS', 'key=' + licenseKey + ' file=' + file);
    return new Response(data, {
      headers: {
        'Content-Type': 'application/zip',
        'X-Sha256': hash,
        'Cache-Control': 'no-store',
      },
    });
  }

  // DLL del backend: cifrar on-the-fly para el usuario (IV||ct||tag)
  let encrypted;
  try {
    encrypted = await encryptForUser(data, licenseKey, hwid);
  } catch (e) {
    logSecurityEvent(env, 'DOWNLOAD_ENCRYPT_ERROR', 'file=' + file + ' err=' + (e && e.message || 'unknown'));
    return errorResponse('Encryption failed', 500);
  }

  logSecurityEvent(env, 'DOWNLOAD_SUCCESS', 'key=' + licenseKey + ' file=' + file + ' enc=gcm');
  return new Response(encrypted, {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Cache-Control': 'no-store',
    },
  });
}
