-- Migration 001: add pending approval columns to existing D1 licenses
-- Run: npx wrangler d1 execute astro-licenses --remote --command "ALTER TABLE licenses ADD COLUMN status TEXT DEFAULT 'active'"
-- If column already exists, this will error "duplicate column name" – safe to ignore.
ALTER TABLE licenses ADD COLUMN status TEXT DEFAULT 'active';
