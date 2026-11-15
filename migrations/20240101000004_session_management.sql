-- Migration: Add session lifecycle columns and index for active session lookups.

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS last_active_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS absolute_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS session_type TEXT NOT NULL DEFAULT 'web',
    ADD COLUMN IF NOT EXISTS csrf_token TEXT;

-- Backfill existing rows if any: default last_active_at to created_at, absolute_expires_at to expires_at
UPDATE sessions
SET last_active_at = created_at
WHERE last_active_at IS NULL;

UPDATE sessions
SET absolute_expires_at = expires_at
WHERE absolute_expires_at IS NULL;

-- Index for querying active sessions for a user ordered by last activity
CREATE INDEX IF NOT EXISTS idx_sessions_user_id_active
    ON sessions (user_id, last_active_at);

-- Ensure user_id index exists (idempotent)
CREATE INDEX IF NOT EXISTS idx_sessions_user_id
    ON sessions (user_id);
