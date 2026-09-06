import { jsonResponse, errorResponse, sha256 } from '../utils.js';
import { isValidAdminSession } from '../security.js';

export async function checkUpdate(request, env) {
  const url = new URL(request.url);
  const currentVersion = url.searchParams.get('version') || '0.0.0';
  const platform = url.searchParams.get('platform') || 'win-x64';

  // Get latest update from D1
  const update = await env.DB.prepare(
    'SELECT * FROM updates WHERE platform = ? ORDER BY created_at DESC LIMIT 1'
  ).bind(platform).first();

  if (!update) {
    return jsonResponse({ update_available: false });
  }

  // Compare versions
  const current = currentVersion.split('.').map(Number);
  const latest = update.version.split('.').map(Number);
  
  let updateAvailable = false;
  for (let i = 0; i < 3; i++) {
    if (latest[i] > current[i]) {
      updateAvailable = true;
      break;
    } else if (latest[i] < current[i]) {
      break;
    }
  }

  return jsonResponse({
    update_available: updateAvailable,
    version: update.version,
    sha256: update.sha256,
    signature: update.signature,
    url: update.file_url,
  });
}

export async function uploadUpdate(request, env) {
  // Admin only - session token required (router double-checks; legacy X-Admin-Key removed for security)
  const sessionToken = request.headers.get('X-Session-Token');
  if (!await isValidAdminSession(env, sessionToken)) {
    return errorResponse('Unauthorized', 401);
  }

  const body = await request.json();
  const { version, platform, sha256, signature, file_url } = body;

  if (!version || !platform || !sha256 || !file_url) {
    return errorResponse('Missing required fields');
  }

  await env.DB.prepare(
    'INSERT INTO updates (version, platform, sha256, signature, file_url) VALUES (?, ?, ?, ?, ?)'
  ).bind(version, platform, sha256, signature || '', file_url).run();

  return jsonResponse({ success: true, message: 'Update registered' });
}
