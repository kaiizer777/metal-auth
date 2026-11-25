CREATE TABLE IF NOT EXISTS verification_tokens (
    token_hash  VARBINARY(32) NOT NULL PRIMARY KEY,
    user_id     BINARY(16) NOT NULL,
    expires_at  DATETIME(6) NOT NULL,
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_verification_tokens_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE INDEX idx_verification_tokens_user_id ON verification_tokens (user_id);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash  VARBINARY(32) NOT NULL PRIMARY KEY,
    user_id     BINARY(16) NOT NULL,
    expires_at  DATETIME(6) NOT NULL,
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_password_reset_tokens_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens (user_id);
