use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::{Executor, MySql, MySqlPool, QueryBuilder};
use uuid::Uuid;

use crate::{
    db::models::{
        EmailOutbox, OUTBOX_STATUS_FAILED, OUTBOX_STATUS_PENDING, OUTBOX_STATUS_PROCESSING,
        OUTBOX_STATUS_SENT,
    },
    error::AppError,
};

pub async fn insert_outbox<'e, E>(
    executor: E,
    recipient: &str,
    email_type: &str,
    payload: serde_json::Value,
) -> Result<EmailOutbox, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO email_outbox (id, recipient, email_type, payload, status, retry_count, next_retry_at, created_at)
        VALUES (?, ?, ?, ?, ?, 0, ?, ?)
        "#,
    )
    .bind(id)
    .bind(recipient)
    .bind(email_type)
    .bind(&payload)
    .bind(OUTBOX_STATUS_PENDING)
    .bind(now)
    .bind(now)
    .execute(executor)
    .await
    .map_err(AppError::from)?;

    Ok(EmailOutbox {
        id,
        recipient: recipient.to_string(),
        email_type: email_type.to_string(),
        payload,
        status: OUTBOX_STATUS_PENDING.to_string(),
        retry_count: 0,
        next_retry_at: now,
        created_at: now,
        sent_at: None,
        error_log: None,
    })
}

pub async fn claim_pending_outbox(
    pool: &MySqlPool,
    batch_size: u32,
    lock_duration: Duration,
) -> Result<Vec<EmailOutbox>, AppError> {
    let mut tx = pool.begin().await.map_err(AppError::from)?;
    let now = Utc::now();
    let lease_expires_at = now
        + ChronoDuration::from_std(lock_duration).unwrap_or(ChronoDuration::seconds(300));

    let mut rows = sqlx::query_as::<MySql, EmailOutbox>(
        r#"
        SELECT id, recipient, email_type, payload, status, retry_count, next_retry_at, created_at, sent_at, error_log
        FROM email_outbox
        WHERE (status = ? AND next_retry_at <= ?)
           OR (status = ? AND next_retry_at <= ?)
        ORDER BY next_retry_at ASC
        LIMIT ?
        FOR UPDATE SKIP LOCKED
        "#,
    )
    .bind(OUTBOX_STATUS_PENDING)
    .bind(now)
    .bind(OUTBOX_STATUS_PROCESSING)
    .bind(now)
    .bind(batch_size as i64)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::from)?;

    if rows.is_empty() {
        tx.commit().await.map_err(AppError::from)?;
        return Ok(Vec::new());
    }

    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let mut builder = QueryBuilder::<MySql>::new("UPDATE email_outbox SET status = ");
    builder.push_bind(OUTBOX_STATUS_PROCESSING);
    builder.push(", next_retry_at = ");
    builder.push_bind(lease_expires_at);
    builder.push(" WHERE id IN (");
    let mut separated = builder.separated(", ");
    for id in &ids {
        separated.push_bind(id);
    }
    separated.push_unseparated(")");

    builder.build().execute(&mut *tx).await.map_err(AppError::from)?;
    tx.commit().await.map_err(AppError::from)?;

    for row in &mut rows {
        row.status = OUTBOX_STATUS_PROCESSING.to_string();
        row.next_retry_at = lease_expires_at;
    }

    Ok(rows)
}

pub async fn mark_outbox_sent<'e, E>(executor: E, id: Uuid) -> Result<(), AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let result = sqlx::query(
        r#"
        UPDATE email_outbox
        SET status = ?, sent_at = UTC_TIMESTAMP(6), error_log = NULL
        WHERE id = ? AND status = ?
        "#,
    )
    .bind(OUTBOX_STATUS_SENT)
    .bind(id)
    .bind(OUTBOX_STATUS_PROCESSING)
    .execute(executor)
    .await
    .map_err(AppError::from)?;

    if result.rows_affected() != 1 {
        tracing::warn!(outbox_id = %id, "mark_outbox_sent: lease expired or row missing");
    }

    Ok(())
}

pub async fn record_outbox_retry<'e, E>(
    executor: E,
    id: Uuid,
    _retry_count: i32,
    next_retry_at: DateTime<Utc>,
    error_log: &str,
) -> Result<(), AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let result = sqlx::query(
        r#"
        UPDATE email_outbox
        SET status = ?, retry_count = retry_count + 1, next_retry_at = ?, error_log = ?
        WHERE id = ? AND status = ?
        "#,
    )
    .bind(OUTBOX_STATUS_PENDING)
    .bind(next_retry_at)
    .bind(error_log)
    .bind(id)
    .bind(OUTBOX_STATUS_PROCESSING)
    .execute(executor)
    .await
    .map_err(AppError::from)?;

    if result.rows_affected() != 1 {
        tracing::warn!(outbox_id = %id, "record_outbox_retry: lease expired or row missing");
    }

    Ok(())
}

pub async fn mark_outbox_failed<'e, E>(
    executor: E,
    id: Uuid,
    error_log: &str,
) -> Result<(), AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let result = sqlx::query(
        r#"
        UPDATE email_outbox
        SET status = ?, retry_count = retry_count + 1, error_log = ?
        WHERE id = ? AND status = ?
        "#,
    )
    .bind(OUTBOX_STATUS_FAILED)
    .bind(error_log)
    .bind(id)
    .bind(OUTBOX_STATUS_PROCESSING)
    .execute(executor)
    .await
    .map_err(AppError::from)?;

    if result.rows_affected() != 1 {
        tracing::warn!(outbox_id = %id, "mark_outbox_failed: lease expired or row missing");
    }

    Ok(())
}

pub async fn cleanup_sent_outbox<'e, E>(
    executor: E,
    retention_duration: Duration,
) -> Result<u64, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let cutoff =
        Utc::now() - ChronoDuration::from_std(retention_duration).unwrap_or(ChronoDuration::days(7));
    let result = sqlx::query(
        r#"
        DELETE FROM email_outbox
        WHERE status = ? AND sent_at IS NOT NULL AND sent_at < ?
        "#,
    )
    .bind(OUTBOX_STATUS_SENT)
    .bind(cutoff)
    .execute(executor)
    .await
    .map_err(AppError::from)?;

    Ok(result.rows_affected())
}

pub async fn recover_stale_processing(pool: &MySqlPool) -> Result<u64, AppError> {
    let result = sqlx::query(
        r#"
        UPDATE email_outbox
        SET status = ?
        WHERE status = ? AND next_retry_at <= UTC_TIMESTAMP(6)
        "#,
    )
    .bind(OUTBOX_STATUS_PENDING)
    .bind(OUTBOX_STATUS_PROCESSING)
    .execute(pool)
    .await
    .map_err(AppError::from)?;

    Ok(result.rows_affected())
}

#[cfg(any(test, feature = "test-utils"))]
pub async fn discard_claimable_outbox(pool: &MySqlPool) -> Result<u64, AppError> {
    let result = sqlx::query("DELETE FROM email_outbox WHERE status = ? OR status = ?")
        .bind(OUTBOX_STATUS_PENDING)
        .bind(OUTBOX_STATUS_PROCESSING)
        .execute(pool)
        .await
        .map_err(AppError::from)?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_outbox_claim_placeholders() {
        let q = "SELECT id, recipient, email_type, payload, status, retry_count, next_retry_at, created_at, sent_at, error_log FROM email_outbox WHERE (status = ? AND next_retry_at <= ?) OR (status = ? AND next_retry_at <= ?) ORDER BY next_retry_at ASC LIMIT ? FOR UPDATE SKIP LOCKED";
        assert_eq!(q.matches('?').count(), 5);
    }
}
