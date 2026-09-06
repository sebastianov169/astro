// Shared Ed25519 license attestation (used by license.js and session.js)
// Signs canonical payload `license_key|hwid_hash|tier|expiryEpoch` with LICENSE_SIGNING_KEY.
export async function licenseSignature(env, license_key, hwid_hash, tier, expiry, client_nonce = '') {
  let expiryEpoch = '';
  if (expiry) {
    const t = Date.parse(expiry);
    if (!isNaN(t)) expiryEpoch = Math.floor(t / 1000);
    else expiryEpoch = String(expiry);
  }
  // client_nonce (challenge-response): when present it binds this attestation to the
  // specific session that requested it - captured responses cannot be replayed.
  const payload = `${license_key}|${hwid_hash || ''}|${tier ?? ''}|${expiryEpoch}` + (client_nonce ? `|${client_nonce}` : '');
  const bin = atob(env.LICENSE_SIGNING_KEY);
  const der = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
  const privKey = await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('Ed25519', privKey, new TextEncoder().encode(payload));
  return Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
