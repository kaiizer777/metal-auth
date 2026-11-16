-- Migration: Add session lifecycle columns and index for active session lookups.
-- Phase 4: Session Management additions to the sessions table.
--
-- NOTE: no explicit BEGIN/COMMIT here. `sqlx::migrate!` already wraps each
-- migration file in a transaction; an explicit BEGIN only warns as a no-op
-- while COMMIT would close the runner's transaction early.

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS last_active_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS absolute_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS session_type TEXT NOT NULL DEFAULT 'cookie'
        CHECK (session_type IN ('cookie', 'bearer')),
    ADD COLUMN IF NOT EXISTS csrf_token TEXT;

-- Drop legacy NOT NULL constraints for backwards compatibility with phase 4 session lifecycle
ALTER TABLE sessions
    ALTER COLUMN expires_at DROP NOT NULL,
    ALTER COLUMN idle_expires_at DROP NOT NULL;

-- Backfill legacy rows: only touch unpopulated rows (IS NULL).
-- Replay-safe: re-executing this migration will never touch or rewrite live sessions.
UPDATE sessions
SET last_active_at = created_at
WHERE last_active_at IS NULL;

-- Backfill absolute_expires_at capped at 1 day (aligning with default_absolute_lifetime_secs 86400)
-- or legacy expires_at if sooner.
UPDATE sessions
SET absolute_expires_at = LEAST(created_at + INTERVAL '1 day', COALESCE(expires_at, created_at + INTERVAL '1 day'))
WHERE absolute_expires_at IS NULL;

-- Enforce NOT NULL and defaults for future inserts
ALTER TABLE sessions
    ALTER COLUMN last_active_at SET DEFAULT now(),
    ALTER COLUMN last_active_at SET NOT NULL,
    ALTER COLUMN absolute_expires_at SET DEFAULT now() + INTERVAL '1 day',
    ALTER COLUMN absolute_expires_at SET NOT NULL;

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
