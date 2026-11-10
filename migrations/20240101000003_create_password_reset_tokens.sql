-- Phase 3: replace password_reset_tokens table with correct schema per spec.
-- DELETE-on-consume model: no `used` column; row deleted atomically on first use.
-- token_hash is BYTEA PRIMARY KEY (SHA-256 of raw 32-byte token), not TEXT or UUID.
-- All tokens for a user are deleted on successful password change (TOCTOU prevention).

DROP TABLE IF EXISTS password_reset_tokens;

CREATE TABLE password_reset_tokens (
    token_hash  BYTEA        NOT NULL PRIMARY KEY,  -- SHA-256 of raw token bytes; 32 bytes
    user_id     UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ  NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_prt_user_id ON password_reset_tokens (user_id);
