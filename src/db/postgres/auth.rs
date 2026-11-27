use chrono::{DateTime, Utc};
use sqlx::{Executor, Postgres};
use uuid::Uuid;

use crate::{
    db::models::{PasswordResetToken, User, VerificationToken},
    error::AppError,
};

pub async fn create_user<'e, E>(
    executor: E,
    email: &str,
    password_hash: &str,
) -> Result<User, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let normalized = email.trim().to_lowercase();
    let row = sqlx::query_as::<Postgres, User>(
        r#"
        INSERT INTO users (email, password_hash)
        VALUES ($1, $2)
        RETURNING id, email, password_hash, email_verified, created_at, updated_at
        "#,
    )
    .bind(normalized)
    .bind(password_hash)
    .fetch_one(executor)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db_err) if db_err.code().as_deref() == Some("23505") => {
            AppError::EmailAlreadyExists
        }
        other => AppError::from(other),
    })?;

    Ok(row)
}

pub async fn get_user_by_id<'e, E>(executor: E, id: Uuid) -> Result<Option<User>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<Postgres, User>(
        r#"
        SELECT id, email, password_hash, email_verified, created_at, updated_at
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(executor)
    .await
    .map_err(AppError::from)
}

pub async fn get_user_by_email<'e, E>(executor: E, email: &str) -> Result<Option<User>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let normalized = email.trim().to_lowercase();
    sqlx::query_as::<Postgres, User>(
        r#"
        SELECT id, email, password_hash, email_verified, created_at, updated_at
        FROM users
        WHERE LOWER(email) = LOWER($1)
        "#,
    )
    .bind(normalized)
    .fetch_optional(executor)
    .await
    .map_err(AppError::from)
}

pub async fn set_email_verified<'e, E>(
    executor: E,
    user_id: Uuid,
    verified: bool,
) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        r#"
        UPDATE users
        SET email_verified = $1, updated_at = NOW()
        WHERE id = $2
        "#,
    )
    .bind(verified)
    .bind(user_id)
    .execute(executor)
    .await
    .map_err(AppError::from)?;

    Ok(())
}

pub async fn update_password_hash<'e, E>(
    executor: E,
    user_id: Uuid,
    new_hash: &str,
) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        r#"
        UPDATE users
        SET password_hash = $1, updated_at = NOW()
        WHERE id = $2
        "#,
    )
    .bind(new_hash)
    .bind(user_id)
    .execute(executor)
    .await
    .map_err(AppError::from)?;

    Ok(())
}

pub async fn create_verification_token<'e, E>(
    executor: E,
    user_id: Uuid,
    token_hash: &[u8],
    expires_at: DateTime<Utc>,
) -> Result<VerificationToken, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<Postgres, VerificationToken>(
        r#"
        INSERT INTO verification_tokens (token_hash, user_id, expires_at)
        VALUES ($1, $2, $3)
        RETURNING token_hash, user_id, expires_at, created_at
        "#,
    )
    .bind(token_hash)
    .bind(user_id)
    .bind(expires_at)
    .fetch_one(executor)
    .await
    .map_err(AppError::from)
}

pub async fn consume_verification_token<'e, E>(
    executor: E,
    token_hash: &[u8],
) -> Result<Option<VerificationToken>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<Postgres, VerificationToken>(
        r#"
        DELETE FROM verification_tokens
        WHERE token_hash = $1
        RETURNING token_hash, user_id, expires_at, created_at
        "#,
    )
    .bind(token_hash)
    .fetch_optional(executor)
    .await
    .map_err(AppError::from)
}

pub async fn create_password_reset_token<'e, E>(
    executor: E,
    user_id: Uuid,
    token_hash: &[u8],
    expires_at: DateTime<Utc>,
) -> Result<PasswordResetToken, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<Postgres, PasswordResetToken>(
        r#"
        INSERT INTO password_reset_tokens (token_hash, user_id, expires_at)
        VALUES ($1, $2, $3)
        RETURNING token_hash, user_id, expires_at, created_at
        "#,
    )
    .bind(token_hash)
    .bind(user_id)
    .bind(expires_at)
    .fetch_one(executor)
    .await
    .map_err(AppError::from)
}

pub async fn consume_password_reset_token<'e, E>(
    executor: E,
    token_hash: &[u8],
) -> Result<Option<PasswordResetToken>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<Postgres, PasswordResetToken>(
        r#"
        DELETE FROM password_reset_tokens
        WHERE token_hash = $1
        RETURNING token_hash, user_id, expires_at, created_at
        "#,
    )
    .bind(token_hash)
    .fetch_optional(executor)
    .await
    .map_err(AppError::from)
}

pub async fn delete_user_password_reset_tokens<'e, E>(
    executor: E,
    user_id: Uuid,
) -> Result<u64, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected())
}

pub async fn delete_user<'e, E>(executor: E, user_id: Uuid) -> Result<bool, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected() > 0)
}

pub async fn delete_verification_tokens_for_user<'e, E>(
    executor: E,
    user_id: Uuid,
) -> Result<u64, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query("DELETE FROM verification_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected())
}
