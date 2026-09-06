ALTER TABLE licenses ADD COLUMN owner_name TEXT DEFAULT '';

CREATE TABLE IF NOT EXISTS login_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT NOT NULL,
    hwid TEXT,
    ip_address TEXT,
    country TEXT,
    hostname TEXT,
    event_type TEXT DEFAULT 'login',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_login_events_license ON login_events(license_key);
CREATE INDEX IF NOT EXISTS idx_login_events_created ON login_events(created_at);
