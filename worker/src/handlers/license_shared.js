// Funciones compartidas de cifrado m3xc para handlers (extraidas de license.js)
import { m3xcEncrypt, m3xcDecrypt } from './encryption.js';

export async function decryptBody(body, env) {
  if (!body || !body.encrypted) return null;
  try {
    if (!env.ENCRYPTION_KEY) return null;
    const plain = m3xcDecrypt(body.encrypted, env.ENCRYPTION_KEY);
    return JSON.parse(plain);
  } catch {
    return null;
  }
}

export function encryptedResponse(data, env, status = 200) {
  const json = JSON.stringify(data);
  const encrypted = m3xcEncrypt(json, env.ENCRYPTION_KEY);
  return new Response(JSON.stringify({ encrypted }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
