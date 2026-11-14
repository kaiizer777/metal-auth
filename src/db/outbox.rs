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

/// Purges successfully sent outbox messages older than the retention duration.
///
/// Only rows with `status = 'sent'` and `sent_at < NOW() - retention_window` are removed.
/// Pending, processing, and failed records are never deleted.
pub async fn cleanup_sent_outbox<'e, E>(
    executor: E,
    retention_window: Duration,
) -> Result<u64, sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    let cutoff =
        Utc::now() - ChronoDuration::from_std(retention_window).unwrap_or(ChronoDuration::days(7));
    let result = sqlx::query(
        r#"
        DELETE FROM email_outbox
        WHERE status = $1 AND sent_at < $2
        "#,
    )
    .bind(OUTBOX_STATUS_SENT)
    .bind(cutoff)
    .execute(executor)
    .await?;

    Ok(result.rows_affected())
}

/// Marks an outbox message as successfully sent.
///
/// Verifies `status = 'processing'` to ensure the worker holds an active claim lease.
/// Returns `Ok(true)` if updated, `Ok(false)` if claim was lost.
pub async fn mark_outbox_sent<'e, E>(executor: E, id: Uuid) -> Result<bool, sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query(
        r#"
        UPDATE email_outbox
        SET status = $1, sent_at = NOW(), error_log = NULL
        WHERE id = $2 AND status = $3
        "#,
    )
    .bind(OUTBOX_STATUS_SENT)
    .bind(id)
    .bind(OUTBOX_STATUS_PROCESSING)
    .execute(executor)
    .await?;

    Ok(result.rows_affected() == 1)
}

/// Schedules an outbox message for retry with an updated backoff timestamp and error message.
///
/// Verifies `status = 'processing'` to ensure the worker holds an active claim lease.
/// Returns `Ok(true)` if updated, `Ok(false)` if claim was lost.
pub async fn record_outbox_retry<'e, E>(
    executor: E,
    id: Uuid,
    next_retry_at: DateTime<Utc>,
    error_log: &str,
) -> Result<bool, sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query(
        r#"
        UPDATE email_outbox
        SET status = $1, retry_count = retry_count + 1, next_retry_at = $2, error_log = $3
        WHERE id = $4 AND status = $5
        "#,
    )
    .bind(OUTBOX_STATUS_PENDING)
    .bind(next_retry_at)
    .bind(error_log)
    .bind(id)
    .bind(OUTBOX_STATUS_PROCESSING)
    .execute(executor)
    .await?;

    Ok(result.rows_affected() == 1)
}

/// Marks an outbox message as permanently failed after exhausting retry attempts.
///
/// Verifies `status = 'processing'` to ensure the worker holds an active claim lease.
/// Returns `Ok(true)` if updated, `Ok(false)` if claim was lost.
pub async fn mark_outbox_failed<'e, E>(
    executor: E,
    id: Uuid,
    error_log: &str,
) -> Result<bool, sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query(
        r#"
        UPDATE email_outbox
        SET status = $1, retry_count = retry_count + 1, error_log = $2
        WHERE id = $3 AND status = $4
        "#,
    )
    .bind(OUTBOX_STATUS_FAILED)
    .bind(error_log)
    .bind(id)
    .bind(OUTBOX_STATUS_PROCESSING)
    .execute(executor)
    .await?;

    Ok(result.rows_affected() == 1)
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn test_pool() -> Option<PgPool> {
        dotenvy::dotenv().ok();
        let url = match std::env::var("DATABASE_URL") {
            Ok(u) => u,
            Err(_) => {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "DATABASE_URL must be set in CI"
                );
                return None;
            }
        };
        crate::db::init_pool(&crate::Config {
            database_url: url,
            ..Default::default()
        })
        .await
        .ok()
    }

    #[tokio::test]
    async fn cleanup_sent_outbox_deletes_only_sent_rows_older_than_cutoff() {
        let Some(pool) = test_pool().await else {
            return;
        };

        let old_sent_id = Uuid::new_v4();
        let fresh_sent_id = Uuid::new_v4();
        let pending_id = Uuid::new_v4();

        // 1. Insert old sent row (sent 10 days ago)
        sqlx::query(
            r#"
            INSERT INTO email_outbox (id, recipient, email_type, payload, status, retry_count, next_retry_at, sent_at)
            VALUES ($1, $2, 'verification', '{}'::jsonb, $3, 0, NOW(), NOW() - INTERVAL '10 days')
            "#,
        )
        .bind(old_sent_id)
        .bind(format!("old_sent_{}@example.com", old_sent_id))
        .bind(OUTBOX_STATUS_SENT)
        .execute(&pool)
        .await
        .expect("insert old sent row");

        // 2. Insert fresh sent row (sent now)
        sqlx::query(
            r#"
            INSERT INTO email_outbox (id, recipient, email_type, payload, status, retry_count, next_retry_at, sent_at)
            VALUES ($1, $2, 'verification', '{}'::jsonb, $3, 0, NOW(), NOW())
            "#,
        )
        .bind(fresh_sent_id)
        .bind(format!("fresh_sent_{}@example.com", fresh_sent_id))
        .bind(OUTBOX_STATUS_SENT)
        .execute(&pool)
        .await
        .expect("insert fresh sent row");

        // 3. Insert pending row
        sqlx::query(
            r#"
            INSERT INTO email_outbox (id, recipient, email_type, payload, status, retry_count, next_retry_at)
            VALUES ($1, $2, 'verification', '{}'::jsonb, $3, 0, NOW())
            "#,
        )
        .bind(pending_id)
        .bind(format!("pending_{}@example.com", pending_id))
        .bind(OUTBOX_STATUS_PENDING)
        .execute(&pool)
        .await
        .expect("insert pending row");

        // Run retention cleanup with 7-day window
        let deleted = cleanup_sent_outbox(&pool, Duration::from_secs(7 * 24 * 3600))
            .await
            .expect("cleanup sent outbox");
        assert!(deleted >= 1);

        // Verify old sent row is deleted
        let old_sent = get_outbox_by_id(&pool, old_sent_id)
            .await
            .expect("fetch old sent row");
        assert!(old_sent.is_none());

        // Verify fresh sent row is preserved
        let fresh_sent = get_outbox_by_id(&pool, fresh_sent_id)
            .await
            .expect("fetch fresh sent row");
        assert!(fresh_sent.is_some());

        // Verify pending row is preserved
        let pending = get_outbox_by_id(&pool, pending_id)
            .await
            .expect("fetch pending row");
        assert!(pending.is_some());

        // Cleanup created test rows
        let _ = sqlx::query("DELETE FROM email_outbox WHERE id IN ($1, $2)")
            .bind(fresh_sent_id)
            .bind(pending_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn mark_outbox_sent_enforces_processing_status_claim() {
        let Some(pool) = test_pool().await else {
            return;
        };

        let recipient = format!("cas_{}@example.com", Uuid::new_v4());
        let row = insert_outbox(&pool, &recipient, "verification", json!({}))
            .await
            .expect("insert outbox");

        // Status is pending: mark_outbox_sent must return false
        let updated = mark_outbox_sent(&pool, row.id)
            .await
            .expect("mark outbox sent on pending");
        assert!(!updated);

        let row_after_failed_sent = get_outbox_by_id(&pool, row.id)
            .await
            .expect("get outbox")
            .expect("row exists");
        assert_eq!(row_after_failed_sent.status, OUTBOX_STATUS_PENDING);

        // Transition to processing via claim
        let claimed = claim_pending_outbox(&pool, 50, Duration::from_secs(60))
            .await
            .expect("claim outbox");
        assert!(claimed.iter().any(|r| r.id == row.id));

        // Now status is processing: mark_outbox_sent must return true
        let updated_processing = mark_outbox_sent(&pool, row.id)
            .await
            .expect("mark outbox sent on processing");
        assert!(updated_processing);

        let row_after_sent = get_outbox_by_id(&pool, row.id)
            .await
            .expect("get outbox")
            .expect("row exists");
        assert_eq!(row_after_sent.status, OUTBOX_STATUS_SENT);
        assert!(row_after_sent.sent_at.is_some());

        // Second call when already sent: must return false (CAS lease ownership)
        let second_update = mark_outbox_sent(&pool, row.id)
            .await
            .expect("mark outbox sent on already sent");
        assert!(!second_update);

        // Cleanup
        let _ = sqlx::query("DELETE FROM email_outbox WHERE id = $1")
            .bind(row.id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn record_outbox_retry_and_failed_enforce_processing_status() {
        let Some(pool) = test_pool().await else {
            return;
        };

        let recipient = format!("cas_retry_{}@example.com", Uuid::new_v4());
        let row = insert_outbox(&pool, &recipient, "verification", json!({}))
            .await
            .expect("insert outbox");

        // Pending status: retry returns false
        let next_retry = Utc::now() + ChronoDuration::seconds(30);
        let retry_res = record_outbox_retry(&pool, row.id, next_retry, "err")
            .await
            .expect("record retry");
        assert!(!retry_res);

        // Pending status: failed returns false
        let failed_res = mark_outbox_failed(&pool, row.id, "err")
            .await
            .expect("mark failed");
        assert!(!failed_res);

        // Claim to processing
        let claimed = claim_pending_outbox(&pool, 50, Duration::from_secs(60))
            .await
            .expect("claim outbox");
        assert!(claimed.iter().any(|r| r.id == row.id));

        // Processing status: record_outbox_retry returns true
        let retry_ok = record_outbox_retry(&pool, row.id, next_retry, "transient error")
            .await
            .expect("record retry processing");
        assert!(retry_ok);

        let row_retried = get_outbox_by_id(&pool, row.id)
            .await
            .expect("get outbox")
            .expect("row exists");
        assert_eq!(row_retried.status, OUTBOX_STATUS_PENDING);
        assert_eq!(row_retried.retry_count, 1);

        // Claim again to test mark_outbox_failed
        // Note: next_retry is in future, so manually set next_retry_at to past to claim
        sqlx::query(
            "UPDATE email_outbox SET next_retry_at = NOW() - INTERVAL '1 second' WHERE id = $1",
        )
        .bind(row.id)
        .execute(&pool)
        .await
        .expect("reset next_retry_at");

        let claimed_again = claim_pending_outbox(&pool, 50, Duration::from_secs(60))
            .await
            .expect("claim outbox again");
        assert!(claimed_again.iter().any(|r| r.id == row.id));

        // Now processing: mark_outbox_failed returns true
        let failed_ok = mark_outbox_failed(&pool, row.id, "fatal error")
            .await
            .expect("mark failed processing");
        assert!(failed_ok);

        let row_failed = get_outbox_by_id(&pool, row.id)
            .await
            .expect("get outbox")
            .expect("row exists");
        assert_eq!(row_failed.status, OUTBOX_STATUS_FAILED);
        assert_eq!(row_failed.retry_count, 2);

        // Cleanup
        let _ = sqlx::query("DELETE FROM email_outbox WHERE id = $1")
            .bind(row.id)
            .execute(&pool)
            .await;
    }
}
