CREATE TABLE IF NOT EXISTS totp_secrets (
    id                BINARY(16) NOT NULL PRIMARY KEY,
    user_id           BINARY(16) NOT NULL,
    encrypted_secret  VARBINARY(255) NOT NULL,
    backup_codes      JSON NOT NULL,
    enabled           BOOLEAN NOT NULL DEFAULT FALSE,
    created_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_totp_secrets_user_id UNIQUE (user_id),
    CONSTRAINT fk_totp_secrets_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE INDEX idx_totp_secrets_user_id ON totp_secrets (user_id);

CREATE TABLE IF NOT EXISTS totp_used_codes (
    id         BINARY(16) NOT NULL PRIMARY KEY,
    user_id    BINARY(16) NOT NULL,
    code_hash  VARBINARY(32) NOT NULL,
    used_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_totp_used_codes UNIQUE (user_id, code_hash),
    CONSTRAINT fk_totp_used_codes_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE INDEX idx_totp_used_codes_user_used ON totp_used_codes (user_id, used_at);

CREATE TABLE IF NOT EXISTS two_factor_tokens (
    id               BINARY(16) NOT NULL PRIMARY KEY,
    user_id          BINARY(16) NOT NULL,
    token_hash       VARBINARY(32) NOT NULL,
    credential_hash  TEXT NOT NULL,
    expires_at       DATETIME(6) NOT NULL,
    CONSTRAINT uq_two_factor_tokens_hash UNIQUE (token_hash),
    CONSTRAINT fk_two_factor_tokens_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE INDEX idx_two_factor_tokens_user_id ON two_factor_tokens (user_id);
CREATE INDEX idx_two_factor_tokens_expires ON two_factor_tokens (expires_at);
