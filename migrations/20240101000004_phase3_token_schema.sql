-- Phase 3: Transition verification_tokens and password_reset_tokens to DELETE-on-consume model.
-- Replaces id UUID and used BOOLEAN with token_hash BYTEA PRIMARY KEY (32-byte SHA-256 digest).

DROP TABLE IF EXISTS verification_tokens;

CREATE TABLE verification_tokens (
    token_hash  BYTEA        NOT NULL PRIMARY KEY,
    user_id     UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ  NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vt_user_id ON verification_tokens (user_id);

DROP TABLE IF EXISTS password_reset_tokens;

CREATE TABLE password_reset_tokens (
    token_hash  BYTEA        NOT NULL PRIMARY KEY,
    user_id     UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ  NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_prt_user_id ON password_reset_tokens (user_id);
