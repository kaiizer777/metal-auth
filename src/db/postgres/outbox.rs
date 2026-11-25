use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::{Executor, PgPool, Postgres};
use uuid::Uuid;

use crate::{db::models::EmailOutbox, error::AppError};

pub async fn insert_outbox<'e, E>(
    executor: E,
    recipient: &str,
    email_type: &str,
    payload: serde_json::Value,
) -> Result<EmailOutbox, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    crate::db::outbox::insert_outbox(executor, recipient, email_type, payload)
        .await
        .map_err(AppError::from)
}

pub async fn claim_pending_outbox(
    pool: &PgPool,
    batch_size: u32,
    lock_duration: Duration,
) -> Result<Vec<EmailOutbox>, AppError> {
    crate::db::outbox::claim_pending_outbox(pool, batch_size as i64, lock_duration)
        .await
        .map_err(AppError::from)
}

pub async fn mark_outbox_sent<'e, E>(executor: E, id: Uuid) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let updated = crate::db::outbox::mark_outbox_sent(executor, id)
        .await
        .map_err(AppError::from)?;
    if !updated {
        tracing::warn!(outbox_id = %id, "mark_outbox_sent: lease expired or row missing");
    }
    Ok(())
}

pub async fn record_outbox_retry<'e, E>(
    executor: E,
    id: Uuid,
    retry_count: i32,
    next_retry_at: DateTime<Utc>,
    error_log: &str,
) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let _ = retry_count;
    let updated = crate::db::outbox::record_outbox_retry(executor, id, next_retry_at, error_log)
        .await
        .map_err(AppError::from)?;
    if !updated {
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
    E: Executor<'e, Database = Postgres>,
{
    let updated = crate::db::outbox::mark_outbox_failed(executor, id, error_log)
        .await
        .map_err(AppError::from)?;
    if !updated {
        tracing::warn!(outbox_id = %id, "mark_outbox_failed: lease expired or row missing");
    }
    Ok(())
}

pub async fn cleanup_sent_outbox<'e, E>(
    executor: E,
    retention_duration: Duration,
) -> Result<u64, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    crate::db::outbox::cleanup_sent_outbox(executor, retention_duration)
        .await
        .map_err(AppError::from)
}

pub async fn recover_stale_processing(pool: &PgPool) -> Result<u64, AppError> {
    crate::db::outbox::recover_stale_processing(pool)
        .await
        .map_err(AppError::from)
}
