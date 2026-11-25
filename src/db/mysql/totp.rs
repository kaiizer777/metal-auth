use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::{Executor, MySql};
use uuid::Uuid;

use crate::{
    db::models::{TotpSecret, TwoFactorToken},
    error::AppError,
};

pub async fn get_secret<'e, E>(_executor: E, _user_id: Uuid) -> Result<Option<TotpSecret>, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn upsert_secret<'e, E>(
    _executor: E,
    _user_id: Uuid,
    _encrypted_secret: &[u8],
    _backup_codes: serde_json::Value,
) -> Result<TotpSecret, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn enable_totp<'e, E>(_executor: E, _user_id: Uuid) -> Result<bool, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn disable_totp<'e, E>(_executor: E, _user_id: Uuid) -> Result<bool, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn record_used_code<'e, E>(
    _executor: E,
    _user_id: Uuid,
    _code_hash: &[u8],
) -> Result<bool, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn is_code_used<'e, E>(
    _executor: E,
    _user_id: Uuid,
    _code_hash: &[u8],
) -> Result<bool, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn create_two_factor_token<'e, E>(
    _executor: E,
    _user_id: Uuid,
    _token_hash: &[u8],
    _credential_hash: &str,
    _expires_at: DateTime<Utc>,
) -> Result<TwoFactorToken, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn consume_two_factor_token<'e, E>(
    _executor: E,
    _token_hash: &[u8],
) -> Result<Option<TwoFactorToken>, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn delete_two_factor_tokens_for_user<'e, E>(
    _executor: E,
    _user_id: Uuid,
) -> Result<u64, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn prune_expired_two_factor_tokens<'e, E>(_executor: E) -> Result<u64, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn prune_used_codes<'e, E>(_executor: E, _max_age: Duration) -> Result<u64, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}
