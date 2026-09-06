
CREATE TABLE IF NOT EXISTS security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    severity TEXT DEFAULT 'medium',
    license_key TEXT,
    hwid TEXT,
    ip_address TEXT,
    country TEXT,
    details TEXT,
    seen INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON security_alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_seen ON security_alerts(seen);
