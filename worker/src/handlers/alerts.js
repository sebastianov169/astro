// Security alerting - clone detection and suspicious event recording
// Alerts are written to security_alerts table; cron purges old ones, admin panel reads them.

export async function raiseAlert(env, { type, severity = 'medium', license_key = null, hwid = null,
                                         ip = null, country = null, details = null }) {
  try {
    await env.DB.prepare(
      'INSERT INTO security_alerts (alert_type, severity, license_key, hwid, ip_address, country, details) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(type, severity, license_key, hwid, ip, country, details ? String(details).substring(0, 2000) : null).run();
    console.log(`[ALERT] ${severity.toUpperCase()} ${type} key=${license_key || '-'} ip=${ip || '-'}`);
  } catch (e) {
    console.error('raiseAlert failed:', e && e.message);
  }
}

export async function getAlerts(env, { limit = 100, unseenOnly = false } = {}) {
  const q = unseenOnly
    ? 'SELECT * FROM security_alerts WHERE seen = 0 ORDER BY id DESC LIMIT ?'
    : 'SELECT * FROM security_alerts ORDER BY id DESC LIMIT ?';
  const rs = await env.DB.prepare(q).bind(limit).all();
  return rs.results || [];
}

export async function markAlertsSeen(env, ids = null) {
  if (ids && Array.isArray(ids) && ids.length > 0) {
    const placeholders = ids.map(() => '?').join(',');
    await env.DB.prepare(`UPDATE security_alerts SET seen = 1 WHERE id IN (${placeholders})`)
      .bind(...ids.map(Number)).run();
  } else {
    await env.DB.prepare('UPDATE security_alerts SET seen = 1').run();
  }
  return { success: true };
}

// Clone-pattern analysis over recent telemetry + hardware changes.
// Signals:
//   A) same license seen from >= N distinct IPs in window
//   B) same license with hardware_info change recorded recently
//   C) same hwid used by >= 2 distinct licenses (key sharing)
export async function scanClonePatterns(env, windowHours = 24, minIps = 3) {
  const findings = [];
  // A) distinct IPs per license in window
  try {
    const rsA = await env.DB.prepare(
      `SELECT license_key, COUNT(DISTINCT ip_address) AS n_ips
       FROM telemetry WHERE timestamp >= datetime('now', ?)
       GROUP BY license_key HAVING n_ips >= ?`
    ).bind(`-${windowHours} hours`, minIps).all();
    for (const row of (rsA.results || [])) {
      findings.push({ type: 'MULTI_IP_LICENSE', severity: 'high',
        detail: `license=${row.license_key} ips=${row.n_ips} in ${windowHours}h` });
    }
  } catch {}
  // B) recent hardware change rows already flagged in licenses
  try {
    const rsB = await env.DB.prepare(
      `SELECT license_key, client_ip, country FROM licenses
       WHERE hardware_changed_at IS NOT NULL AND hardware_changed_at >= datetime('now', ?)`
    ).bind(`-${windowHours} hours`).all();
    for (const row of (rsB.results || [])) {
      findings.push({ type: 'HARDWARE_CHANGE_RECENT', severity: 'high',
        detail: `license=${row.license_key} ip=${row.client_ip} country=${row.country}` });
    }
  } catch {}
  // C) one hwid bound to multiple active licenses
  try {
    const rsC = await env.DB.prepare(
      `SELECT hwid_hash, COUNT(*) AS n FROM licenses
       WHERE hwid_hash IS NOT NULL AND is_revoked = 0 AND status = 'active'
       GROUP BY hwid_hash HAVING n >= 2`
    ).all();
    for (const row of (rsC.results || [])) {
      findings.push({ type: 'SHARED_HWID', severity: 'medium',
        detail: `hwid=${String(row.hwid_hash).substring(0,16)}... licenses=${row.n}` });
    }
  } catch {}
  return findings;
}
