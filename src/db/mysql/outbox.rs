use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::{Executor, MySql, MySqlPool};
use uuid::Uuid;

use crate::{db::models::EmailOutbox, error::AppError};

pub async fn insert_outbox<'e, E>(
    _executor: E,
    _recipient: &str,
    _email_type: &str,
    _payload: serde_json::Value,
) -> Result<EmailOutbox, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn claim_pending_outbox(
    _pool: &MySqlPool,
    _batch_size: u32,
    _lock_duration: Duration,
) -> Result<Vec<EmailOutbox>, AppError>
{
    Err(AppError::Internal)
}

pub async fn mark_outbox_sent<'e, E>(_executor: E, _id: Uuid) -> Result<(), AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn record_outbox_retry<'e, E>(
    _executor: E,
    _id: Uuid,
    _retry_count: i32,
    _next_retry_at: DateTime<Utc>,
    _error_log: &str,
) -> Result<(), AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn mark_outbox_failed<'e, E>(
    _executor: E,
    _id: Uuid,
    _error_log: &str,
) -> Result<(), AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn cleanup_sent_outbox<'e, E>(
    _executor: E,
    _retention_duration: Duration,
) -> Result<u64, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn recover_stale_processing(_pool: &MySqlPool) -> Result<u64, AppError> {
    Err(AppError::Internal)
}
