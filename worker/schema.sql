CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT UNIQUE NOT NULL,
    hwid_hash TEXT,
    tier INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active',
    hardware_info TEXT,
    requested_at TEXT,
    activated_at TEXT,
    expires_at TEXT,
    is_revoked INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);

-- Migration for existing D1 databases missing pending-approval columns
-- Safe to run repeatedly (IF NOT EXISTS via try-catch in code; here we use ALTER with ignore)
-- Run manually once: wrangler d1 execute astro-licenses --remote --command "ALTER TABLE licenses ADD COLUMN status TEXT DEFAULT 'active'"
-- wrangler d1 execute astro-licenses --remote --command "ALTER TABLE licenses ADD COLUMN hardware_info TEXT"
-- wrangler d1 execute astro-licenses --remote --command "ALTER TABLE licenses ADD COLUMN requested_at TEXT"

CREATE TABLE IF NOT EXISTS telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT,
    hwid TEXT,
    ip_address TEXT,
    components TEXT,
    timestamp TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS kill_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT,
    reason TEXT,
    executed_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS updates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version TEXT,
    platform TEXT,
    sha256 TEXT,
    signature TEXT,
    file_url TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS session_tokens (
    token TEXT PRIMARY KEY,
    license_key TEXT NOT NULL,
    hwid TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    used INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_session_license ON session_tokens(license_key);
CREATE INDEX IF NOT EXISTS idx_session_expires ON session_tokens(expires_at);

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

-- Indexes
CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key);
CREATE INDEX IF NOT EXISTS idx_licenses_hwid ON licenses(hwid_hash);
CREATE INDEX IF NOT EXISTS idx_telemetry_key ON telemetry(license_key);
CREATE INDEX IF NOT EXISTS idx_updates_platform ON updates(platform);
