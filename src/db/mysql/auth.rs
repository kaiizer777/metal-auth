use chrono::{DateTime, Utc};
use sqlx::{Executor, MySql};
use uuid::Uuid;

use crate::{
    db::models::{PasswordResetToken, User, VerificationToken},
    error::AppError,
};

pub async fn create_user<'e, E>(
    _executor: E,
    _email: &str,
    _password_hash: &str,
) -> Result<User, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn get_user_by_id<'e, E>(_executor: E, _id: Uuid) -> Result<Option<User>, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn get_user_by_email<'e, E>(_executor: E, _email: &str) -> Result<Option<User>, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn set_email_verified<'e, E>(
    _executor: E,
    _user_id: Uuid,
    _verified: bool,
) -> Result<(), AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn update_password_hash<'e, E>(
    _executor: E,
    _user_id: Uuid,
    _new_hash: &str,
) -> Result<(), AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn delete_user<'e, E>(_executor: E, _user_id: Uuid) -> Result<bool, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn create_verification_token<'e, E>(
    _executor: E,
    _user_id: Uuid,
    _token_hash: &[u8],
    _expires_at: DateTime<Utc>,
) -> Result<VerificationToken, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn consume_verification_token<'e, E>(
    _executor: E,
    _token_hash: &[u8],
) -> Result<Option<VerificationToken>, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn create_password_reset_token<'e, E>(
    _executor: E,
    _user_id: Uuid,
    _token_hash: &[u8],
    _expires_at: DateTime<Utc>,
) -> Result<PasswordResetToken, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn consume_password_reset_token<'e, E>(
    _executor: E,
    _token_hash: &[u8],
) -> Result<Option<PasswordResetToken>, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn delete_user_password_reset_tokens<'e, E>(
    _executor: E,
    _user_id: Uuid,
) -> Result<u64, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn delete_verification_tokens_for_user<'e, E>(
    _executor: E,
    _user_id: Uuid,
) -> Result<u64, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}
