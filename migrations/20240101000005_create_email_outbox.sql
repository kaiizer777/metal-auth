-- Migration: Create email_outbox table for transactional email outbox pattern.

CREATE TABLE IF NOT EXISTS email_outbox (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    recipient       TEXT NOT NULL,
    email_type      TEXT NOT NULL,
    payload         JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    retry_count     INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at         TIMESTAMPTZ,
    error_log       TEXT
);

CREATE INDEX IF NOT EXISTS idx_email_outbox_status_next_retry_at
    ON email_outbox (status, next_retry_at);
