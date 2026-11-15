-- Migration: Add session lifecycle columns and index for active session lookups.
-- Phase 4: Session Management additions to the sessions table.

BEGIN;

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS last_active_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS absolute_expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '30 days',
    ADD COLUMN IF NOT EXISTS session_type TEXT NOT NULL DEFAULT 'cookie'
        CHECK (session_type IN ('cookie', 'bearer')),
    ADD COLUMN IF NOT EXISTS csrf_token TEXT;

-- Drop legacy NOT NULL constraints for backwards compatibility with phase 4 session lifecycle
ALTER TABLE sessions
    ALTER COLUMN expires_at DROP NOT NULL,
    ALTER COLUMN idle_expires_at DROP NOT NULL;

-- Backfill existing rows if any: default last_active_at to created_at
UPDATE sessions
SET last_active_at = created_at
WHERE last_active_at = now();

UPDATE sessions
SET absolute_expires_at = created_at + INTERVAL '30 days'
WHERE absolute_expires_at >= now();

-- Index for fast TTL sweeps
CREATE INDEX IF NOT EXISTS idx_sessions_absolute_expires_at
    ON sessions (absolute_expires_at);

CREATE INDEX IF NOT EXISTS idx_sessions_last_active_at
    ON sessions (last_active_at);

-- Index for querying active sessions for a user ordered by last activity
CREATE INDEX IF NOT EXISTS idx_sessions_user_id_active
    ON sessions (user_id, last_active_at);

-- Ensure user_id index exists (idempotent)
CREATE INDEX IF NOT EXISTS idx_sessions_user_id
    ON sessions (user_id);

COMMIT;
