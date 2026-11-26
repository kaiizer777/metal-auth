CREATE TABLE IF NOT EXISTS sessions (
    id                  BINARY(16) NOT NULL PRIMARY KEY,
    user_id             BINARY(16) NOT NULL,
    token_hash          VARCHAR(64) NOT NULL,
    created_at          DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_active_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    absolute_expires_at DATETIME(6) NOT NULL,
    session_type        VARCHAR(16) NOT NULL DEFAULT 'cookie',
    csrf_token          VARCHAR(64) NULL,
    CONSTRAINT chk_sessions_type CHECK (session_type IN ('cookie', 'bearer')),
    CONSTRAINT uq_sessions_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_sessions_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE INDEX idx_sessions_user_id ON sessions (user_id);
CREATE INDEX idx_sessions_last_active_at ON sessions (last_active_at);
CREATE INDEX idx_sessions_absolute_expires_at ON sessions (absolute_expires_at);
CREATE INDEX idx_sessions_user_id_active ON sessions (user_id, last_active_at);
