use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::{Executor, PgPool, Postgres};
use uuid::Uuid;

use crate::db::models::{
    EmailOutbox, OUTBOX_STATUS_FAILED, OUTBOX_STATUS_PENDING, OUTBOX_STATUS_PROCESSING,
    OUTBOX_STATUS_SENT,
};

/// Inserts a new outbox entry within an arbitrary executor (typically an active transaction).
pub async fn insert_outbox<'e, E>(
    executor: E,
    recipient: &str,
    email_type: &str,
    payload: serde_json::Value,
) -> Result<EmailOutbox, sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<Postgres, EmailOutbox>(
        r#"
        INSERT INTO email_outbox (recipient, email_type, payload, status, retry_count, next_retry_at)
        VALUES ($1, $2, $3, $4, 0, NOW())
        RETURNING id, recipient, email_type, payload, status, retry_count, next_retry_at, created_at, sent_at, error_log
        "#,
    )
    .bind(recipient)
    .bind(email_type)
    .bind(payload)
    .bind(OUTBOX_STATUS_PENDING)
    .fetch_one(executor)
    .await
}

/// Atomically claims pending or expired processing outbox entries due for delivery using `FOR UPDATE SKIP LOCKED`.
///
/// Sets `status = 'processing'` and advances `next_retry_at` to the lease expiration timestamp.
/// Expired `processing` entries from crashed workers are reclaimed automatically.
pub async fn claim_pending_outbox(
    pool: &PgPool,
    limit: i64,
    lease_duration: Duration,
) -> Result<Vec<EmailOutbox>, sqlx::Error> {
    let lease_expires_at = Utc::now()
        + ChronoDuration::from_std(lease_duration).unwrap_or(ChronoDuration::seconds(300));

    sqlx::query_as::<Postgres, EmailOutbox>(
        r#"
        UPDATE email_outbox
        SET status = $1, next_retry_at = $4
        WHERE id IN (
            SELECT id
            FROM email_outbox
            WHERE (status = $2 AND next_retry_at <= NOW())
               OR (status = $1 AND next_retry_at <= NOW())
            ORDER BY next_retry_at ASC
            LIMIT $3
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id, recipient, email_type, payload, status, retry_count, next_retry_at, created_at, sent_at, error_log
        "#,
    )
    .bind(OUTBOX_STATUS_PROCESSING)
    .bind(OUTBOX_STATUS_PENDING)
    .bind(limit)
    .bind(lease_expires_at)
    .fetch_all(pool)
    .await
}

/// Resets stale processing records whose lease has expired back to pending status.
pub async fn recover_stale_processing(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE email_outbox
        SET status = $1
        WHERE status = $2 AND next_retry_at <= NOW()
        "#,
    )
    .bind(OUTBOX_STATUS_PENDING)
    .bind(OUTBOX_STATUS_PROCESSING)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Marks an outbox message as successfully sent.
pub async fn mark_outbox_sent<'e, E>(executor: E, id: Uuid) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        r#"
        UPDATE email_outbox
        SET status = $1, sent_at = NOW(), error_log = NULL
        WHERE id = $2
        "#,
    )
    .bind(OUTBOX_STATUS_SENT)
    .bind(id)
    .execute(executor)
    .await?;

    Ok(())
}

/// Schedules an outbox message for retry with an updated backoff timestamp and error message.
pub async fn record_outbox_retry<'e, E>(
    executor: E,
    id: Uuid,
    next_retry_at: DateTime<Utc>,
    error_log: &str,
) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        r#"
        UPDATE email_outbox
        SET status = $1, retry_count = retry_count + 1, next_retry_at = $2, error_log = $3
        WHERE id = $4
        "#,
    )
    .bind(OUTBOX_STATUS_PENDING)
    .bind(next_retry_at)
    .bind(error_log)
    .bind(id)
    .execute(executor)
    .await?;

    Ok(())
}

/// Marks an outbox message as permanently failed after exhausting retry attempts.
pub async fn mark_outbox_failed<'e, E>(
    executor: E,
    id: Uuid,
    error_log: &str,
) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        r#"
        UPDATE email_outbox
        SET status = $1, retry_count = retry_count + 1, error_log = $2
        WHERE id = $3
        "#,
    )
    .bind(OUTBOX_STATUS_FAILED)
    .bind(error_log)
    .bind(id)
    .execute(executor)
    .await?;

    Ok(())
}

/// Fetches an outbox record by ID for testing and state verification.
pub async fn get_outbox_by_id<'e, E>(
    executor: E,
    id: Uuid,
) -> Result<Option<EmailOutbox>, sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<Postgres, EmailOutbox>(
        r#"
        SELECT id, recipient, email_type, payload, status, retry_count, next_retry_at, created_at, sent_at, error_log
        FROM email_outbox
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(executor)
    .await
}
