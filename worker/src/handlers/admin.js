import { jsonResponse, errorResponse } from '../utils.js';
import { verifyAdminKey, createAdminSession, logSecurityEvent } from '../security.js';

export async function adminLogin(request, env) {
  let body;
  try {
    const text = await request.text();
    const clean = text.replace(/^\uFEFF/, '');
    body = JSON.parse(clean);
  } catch (e) {
    return errorResponse('Invalid JSON', 400);
  }
  const adminKey = body.admin_key;

  if (!adminKey) {
    return errorResponse('Missing admin_key');
  }

  // Verify admin key with constant-time comparison
  if (!verifyAdminKey(adminKey, env.ADMIN_KEY)) {
    logSecurityEvent(env, 'FAILED_LOGIN_ATTEMPT', `ip=${request.headers.get('CF-Connecting-IP')}`);
    // Delay response to slow down brute force
    await new Promise(r => setTimeout(r, 1000));
    return errorResponse('Invalid admin key', 401);
  }

  // Create session token
  const sessionToken = await createAdminSession(env);
  
  logSecurityEvent(env, 'ADMIN_LOGIN', `ip=${request.headers.get('CF-Connecting-IP')}`);
  
  return jsonResponse({ 
    success: true, 
    session_token: sessionToken,
    expires_in: 28800
  });
}
