use sqlx::{Executor, Postgres};
use uuid::Uuid;

use crate::{db::models::OAuthAccount, error::AppError};

pub async fn get_account<'e, E>(
    executor: E,
    provider_id: &str,
    provider_user_id: &str,
) -> Result<Option<OAuthAccount>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<Postgres, OAuthAccount>(
        r#"
        SELECT id, user_id, provider_id, provider_user_id, email, created_at, updated_at
        FROM oauth_accounts
        WHERE provider_id = $1 AND provider_user_id = $2
        "#,
    )
    .bind(provider_id)
    .bind(provider_user_id)
    .fetch_optional(executor)
    .await
    .map_err(AppError::from)
}

pub async fn list_accounts_for_user<'e, E>(
    executor: E,
    user_id: Uuid,
) -> Result<Vec<OAuthAccount>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<Postgres, OAuthAccount>(
        r#"
        SELECT id, user_id, provider_id, provider_user_id, email, created_at, updated_at
        FROM oauth_accounts
        WHERE user_id = $1
        ORDER BY created_at ASC
        "#,
    )
    .bind(user_id)
    .fetch_all(executor)
    .await
    .map_err(AppError::from)
}

pub async fn link_account<'e, E>(
    executor: E,
    user_id: Uuid,
    provider_id: &str,
    provider_user_id: &str,
    email: &str,
) -> Result<OAuthAccount, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let normalized_email = email.trim().to_lowercase();
    sqlx::query_as::<Postgres, OAuthAccount>(
        r#"
        INSERT INTO oauth_accounts (user_id, provider_id, provider_user_id, email)
        VALUES ($1, $2, $3, $4)
        RETURNING id, user_id, provider_id, provider_user_id, email, created_at, updated_at
        "#,
    )
    .bind(user_id)
    .bind(provider_id)
    .bind(provider_user_id)
    .bind(normalized_email)
    .fetch_one(executor)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db_err) if db_err.code().as_deref() == Some("23505") => {
            AppError::OAuthAccountLinkConflict
        }
        other => AppError::from(other),
    })
}

pub async fn unlink_account<'e, E>(
    executor: E,
    user_id: Uuid,
    provider_id: &str,
) -> Result<bool, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query("DELETE FROM oauth_accounts WHERE user_id = $1 AND provider_id = $2")
        .bind(user_id)
        .bind(provider_id)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected() > 0)
}
