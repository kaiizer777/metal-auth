CREATE TABLE IF NOT EXISTS email_outbox (
    id              BINARY(16) NOT NULL PRIMARY KEY,
    recipient       VARCHAR(255) NOT NULL,
    email_type      VARCHAR(64) NOT NULL,
    payload         JSON NOT NULL,
    status          VARCHAR(32) NOT NULL DEFAULT 'pending',
    retry_count     INT NOT NULL DEFAULT 0,
    next_retry_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    sent_at         DATETIME(6) NULL,
    error_log       TEXT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE INDEX idx_email_outbox_poll ON email_outbox (status, next_retry_at);
CREATE INDEX idx_email_outbox_cleanup ON email_outbox (status, sent_at);
