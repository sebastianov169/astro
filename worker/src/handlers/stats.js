import { jsonResponse, errorResponse } from '../utils.js';

export async function getStats(request, env) {
  // Ensure login_events table exists
  try { await env.DB.prepare("SELECT id FROM login_events LIMIT 1").first(); } catch {
    try {
      await env.DB.prepare("CREATE TABLE IF NOT EXISTS login_events (id INTEGER PRIMARY KEY AUTOINCREMENT, license_key TEXT NOT NULL, hwid TEXT, ip_address TEXT, country TEXT, hostname TEXT, event_type TEXT DEFAULT 'login', created_at TEXT DEFAULT (datetime('now')))").run();
      await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_login_events_created ON login_events(created_at)").run();
    } catch {}
  }
  // Ensure schema exists (migration for old DBs)
  try { await env.DB.prepare("SELECT status FROM licenses LIMIT 1").first(); } catch {
    try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN status TEXT DEFAULT 'active'").run(); } catch {}
    try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN hardware_info TEXT").run(); } catch {}
    try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN requested_at TEXT").run(); } catch {}
  }
  try { await env.DB.prepare("SELECT client_ip FROM licenses LIMIT 1").first(); } catch { try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN client_ip TEXT").run(); } catch {} }
  try { await env.DB.prepare("SELECT client_country FROM licenses LIMIT 1").first(); } catch { try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN client_country TEXT").run(); } catch {} }
  try { await env.DB.prepare("SELECT hardware_changed_at FROM licenses LIMIT 1").first(); } catch { try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN hardware_changed_at TEXT").run(); } catch {} }
  try { await env.DB.prepare("SELECT build_id FROM licenses LIMIT 1").first(); } catch { try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN build_id TEXT DEFAULT ''").run(); } catch {} }
  try { await env.DB.prepare("SELECT owner_name FROM licenses LIMIT 1").first(); } catch { try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN owner_name TEXT DEFAULT ''").run(); } catch {} }
  try {
    const totalLicenses = await env.DB.prepare('SELECT COUNT(*) as count FROM licenses').first();
    let activeLicenses, revokedLicenses, pendingLicenses;
    try {
      activeLicenses = await env.DB.prepare('SELECT COUNT(*) as count FROM licenses WHERE is_revoked = 0 AND status = ?').bind('active').first();
      pendingLicenses = await env.DB.prepare('SELECT COUNT(*) as count FROM licenses WHERE status = ? AND is_revoked = 0').bind('pending').first();
    } catch {
      // Fallback if status column still missing
      activeLicenses = await env.DB.prepare('SELECT COUNT(*) as count FROM licenses WHERE is_revoked = 0').first();
      pendingLicenses = { count: 0 };
    }
    const revokedLicensesTmp = await env.DB.prepare('SELECT COUNT(*) as count FROM licenses WHERE is_revoked = 1').first();
    revokedLicenses = revokedLicensesTmp;
    const recentTelemetry = await env.DB.prepare('SELECT COUNT(*) as count FROM telemetry WHERE timestamp > datetime("now", "-1 day")').first();

    let recentLicenses;
    try {
      recentLicenses = await env.DB.prepare(
        'SELECT license_key, hwid_hash, tier, status, is_revoked, expires_at, activated_at, hardware_info, requested_at, client_ip, client_country, hardware_changed_at, build_id, owner_name FROM licenses ORDER BY id DESC LIMIT 50'
      ).all();
    } catch {
      recentLicenses = await env.DB.prepare(
        'SELECT license_key, hwid_hash, tier, is_revoked, expires_at, activated_at FROM licenses ORDER BY id DESC LIMIT 50'
      ).all();
      // Normalize to expected shape
      if (recentLicenses.results) recentLicenses.results = recentLicenses.results.map(r => ({ ...r, status: r.is_revoked ? 'revoked' : 'active', hardware_info: null, requested_at: null, client_ip: null, client_country: null, hardware_changed_at: null }));
    }

    return jsonResponse({
      total_licenses: totalLicenses.count,
      active_licenses: activeLicenses.count,
      revoked_licenses: revokedLicenses.count,
      pending_licenses: pendingLicenses.count,
      telemetry_today: recentTelemetry.count,
      licenses: recentLicenses.results || []
    });
  } catch (error) {
    return errorResponse('Failed to fetch stats');
  }
}

export async function getPendingLicenses(request, env) {
  try { await env.DB.prepare("SELECT status FROM licenses LIMIT 1").first(); } catch {
    try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN status TEXT DEFAULT 'active'").run(); } catch {}
    try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN hardware_info TEXT").run(); } catch {}
    try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN requested_at TEXT").run(); } catch {}
  }
  try { await env.DB.prepare("SELECT client_ip FROM licenses LIMIT 1").first(); } catch { try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN client_ip TEXT").run(); } catch {} }
  try { await env.DB.prepare("SELECT client_country FROM licenses LIMIT 1").first(); } catch { try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN client_country TEXT").run(); } catch {} }
  try { await env.DB.prepare("SELECT hardware_changed_at FROM licenses LIMIT 1").first(); } catch { try { await env.DB.prepare("ALTER TABLE licenses ADD COLUMN hardware_changed_at TEXT").run(); } catch {} }
  try {
    const pending = await env.DB.prepare(
      'SELECT license_key, hwid_hash, tier, hardware_info, requested_at, client_ip, client_country, hardware_changed_at FROM licenses WHERE status = ? AND is_revoked = 0 ORDER BY id DESC'
    ).bind('pending').all();

    return jsonResponse({
      pending: pending.results || []
    });
  } catch (error) {
    return errorResponse('Failed to fetch pending licenses');
  }
}

export async function getLoginEvents(request, env) {
  try {
    await env.DB.prepare("SELECT id FROM login_events LIMIT 1").first();
  } catch {
    try {
      await env.DB.prepare("CREATE TABLE IF NOT EXISTS login_events (id INTEGER PRIMARY KEY AUTOINCREMENT, license_key TEXT NOT NULL, hwid TEXT, ip_address TEXT, country TEXT, hostname TEXT, event_type TEXT DEFAULT 'login', created_at TEXT DEFAULT (datetime('now')))").run();
      await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_login_events_created ON login_events(created_at)").run();
    } catch {}
  }
  const events = await env.DB.prepare(
    "SELECT * FROM login_events ORDER BY created_at DESC LIMIT 30"
  ).all();
  return jsonResponse({ events: events.results || [] });
}
