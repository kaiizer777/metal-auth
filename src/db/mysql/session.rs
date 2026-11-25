use chrono::{DateTime, Utc};
use sqlx::{Executor, MySql};
use uuid::Uuid;

use crate::{db::models::Session, error::AppError};

pub async fn create_session<'e, E>(
    _executor: E,
    _user_id: Uuid,
    _token_hash: &str,
    _session_type: &str,
    _csrf_token: Option<&str>,
    _absolute_expires_at: DateTime<Utc>,
) -> Result<Session, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn get_session_by_token_hash<'e, E>(
    _executor: E,
    _token_hash: &str,
) -> Result<Option<Session>, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn touch_session<'e, E>(
    _executor: E,
    _session_id: Uuid,
    _last_active_at: DateTime<Utc>,
) -> Result<(), AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn rotate_session<'e, E>(
    _executor: E,
    _session_id: Uuid,
    _new_token_hash: &str,
    _new_csrf_token: Option<&str>,
    _last_active_at: DateTime<Utc>,
) -> Result<(), AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn delete_session<'e, E>(_executor: E, _session_id: Uuid) -> Result<(), AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn delete_by_token_hash<'e, E>(_executor: E, _token_hash: &str) -> Result<bool, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn delete_user_sessions<'e, E>(_executor: E, _user_id: Uuid) -> Result<u64, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn list_user_sessions<'e, E>(
    _executor: E,
    _user_id: Uuid,
) -> Result<Vec<Session>, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn delete_expired_sessions<'e, E>(_executor: E) -> Result<u64, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}
