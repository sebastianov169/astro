// AES-256-GCM encryption (using Web Crypto API)
export async function encrypt(data, key) {
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await crypto.subtle.importKey(
    'raw', encoder.encode(key), { name: 'AES-GCM' }, false, ['encrypt']
  );
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, cryptoKey, encoder.encode(data)
  );
  return {
    iv: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''),
    data: Array.from(new Uint8Array(encrypted)).map(b => b.toString(16).padStart(2, '0')).join('')
  };
}

export async function decrypt(encryptedHex, key, ivHex) {
  const encoder = new TextEncoder();
  const iv = new Uint8Array(ivHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
  const data = new Uint8Array(encryptedHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
  const cryptoKey = await crypto.subtle.importKey(
    'raw', encoder.encode(key), { name: 'AES-GCM' }, false, ['decrypt']
  );
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv }, cryptoKey, data
  );
  return new TextDecoder().decode(decrypted);
}

// SHA-256 hash
export async function sha256(data) {
  const encoder = new TextEncoder();
  const hash = await crypto.subtle.digest('SHA-256', encoder.encode(data));
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// HMAC-SHA256
export async function hmacSha256(data, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Validate license key format (flexible - allows any reasonable key)
export function isValidLicenseKey(key) {
  return key && key.length >= 16 && key.length <= 128 && /^[A-Za-z0-9\-]+$/.test(key);
}

// Validate HWID format (flexible - allows hex strings of various lengths)
export function isValidHwid(hwid) {
  return hwid && hwid.length >= 16 && hwid.length <= 128 && /^[a-f0-9]+$/.test(hwid);
}

// CORS headers
export const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Key, Authorization, X-Signature, X-Timestamp, X-Session-Token',
};

// JSON response helpers
export function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}
