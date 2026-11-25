use sqlx::{Executor, MySql};
use uuid::Uuid;

use crate::{db::models::OAuthAccount, error::AppError};

pub async fn get_account<'e, E>(
    _executor: E,
    _provider_id: &str,
    _provider_user_id: &str,
) -> Result<Option<OAuthAccount>, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn list_accounts_for_user<'e, E>(
    _executor: E,
    _user_id: Uuid,
) -> Result<Vec<OAuthAccount>, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn link_account<'e, E>(
    _executor: E,
    _user_id: Uuid,
    _provider_id: &str,
    _provider_user_id: &str,
    _email: &str,
) -> Result<OAuthAccount, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}

pub async fn unlink_account<'e, E>(
    _executor: E,
    _user_id: Uuid,
    _provider_id: &str,
) -> Result<bool, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    Err(AppError::Internal)
}
