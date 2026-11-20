-- Migration: TOTP two-factor authentication state.
-- Phase 7: encrypted TOTP secrets, replay log, and intermediate challenge tokens.

CREATE TABLE totp_secrets (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- AES-256-GCM blob: nonce (12 bytes) || ciphertext || tag (16 bytes)
    encrypted_secret  BYTEA NOT NULL,
    -- JSON array of Argon2id PHC strings; raw codes are never stored
    backup_codes      JSONB NOT NULL DEFAULT '[]',
    enabled           BOOLEAN NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_totp_secrets_user_id UNIQUE (user_id)
);

CREATE INDEX idx_totp_secrets_user_id ON totp_secrets (user_id);

CREATE TABLE totp_used_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- SHA-256 of (code_string || "::" || step_window_number)
    code_hash  BYTEA NOT NULL,
    used_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_totp_used_codes UNIQUE (user_id, code_hash)
);

-- Replay lookup and TTL pruning both seek on this composite.
CREATE INDEX idx_totp_used_codes_user_used ON totp_used_codes (user_id, used_at);

CREATE TABLE two_factor_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- SHA-256 of the raw 32-byte challenge token
    token_hash  BYTEA NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_two_factor_tokens_hash UNIQUE (token_hash)
);

CREATE INDEX idx_two_factor_tokens_user_id ON two_factor_tokens (user_id);
CREATE INDEX idx_two_factor_tokens_expires ON two_factor_tokens (expires_at);

-- Down migration (sqlx applies forward only; kept as the rollback reference):
-- DROP INDEX IF EXISTS idx_two_factor_tokens_expires;
-- DROP INDEX IF EXISTS idx_two_factor_tokens_user_id;
-- DROP TABLE IF EXISTS two_factor_tokens;
-- DROP INDEX IF EXISTS idx_totp_used_codes_user_used;
-- DROP TABLE IF EXISTS totp_used_codes;
-- DROP INDEX IF EXISTS idx_totp_secrets_user_id;
-- DROP TABLE IF EXISTS totp_secrets;
