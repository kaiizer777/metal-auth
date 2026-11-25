use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::{Executor, Postgres};
use uuid::Uuid;

use crate::{
    db::models::{TotpSecret, TwoFactorToken},
    error::AppError,
};

pub async fn get_secret<'e, E>(executor: E, user_id: Uuid) -> Result<Option<TotpSecret>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<Postgres, TotpSecret>(
        r#"
        SELECT id, user_id, encrypted_secret, backup_codes, enabled, created_at, updated_at
        FROM totp_secrets
        WHERE user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(executor)
    .await
    .map_err(AppError::from)
}

pub async fn upsert_secret<'e, E>(
    executor: E,
    user_id: Uuid,
    encrypted_secret: &[u8],
    backup_codes: serde_json::Value,
) -> Result<TotpSecret, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<Postgres, TotpSecret>(
        r#"
        INSERT INTO totp_secrets (user_id, encrypted_secret, backup_codes, enabled)
        VALUES ($1, $2, $3, FALSE)
        ON CONFLICT (user_id) DO UPDATE
        SET encrypted_secret = EXCLUDED.encrypted_secret,
            backup_codes = EXCLUDED.backup_codes,
            updated_at = NOW()
        WHERE totp_secrets.enabled = FALSE
        RETURNING id, user_id, encrypted_secret, backup_codes, enabled, created_at, updated_at
        "#,
    )
    .bind(user_id)
    .bind(encrypted_secret)
    .bind(backup_codes)
    .fetch_one(executor)
    .await
    .map_err(AppError::from)
}

pub async fn enable_totp<'e, E>(executor: E, user_id: Uuid) -> Result<bool, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query(
        r#"
        UPDATE totp_secrets
        SET enabled = TRUE, updated_at = NOW()
        WHERE user_id = $1 AND enabled = FALSE
        "#,
    )
    .bind(user_id)
    .execute(executor)
    .await
    .map_err(AppError::from)?;

    Ok(result.rows_affected() > 0)
}

pub async fn disable_totp<'e, E>(executor: E, user_id: Uuid) -> Result<bool, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query(
        r#"
        UPDATE totp_secrets
        SET enabled = FALSE, updated_at = NOW()
        WHERE user_id = $1 AND enabled = TRUE
        "#,
    )
    .bind(user_id)
    .execute(executor)
    .await
    .map_err(AppError::from)?;

    Ok(result.rows_affected() > 0)
}

pub async fn record_used_code<'e, E>(
    executor: E,
    user_id: Uuid,
    code_hash: &[u8],
) -> Result<bool, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query(
        r#"
        INSERT INTO totp_used_codes (user_id, code_hash)
        VALUES ($1, $2)
        "#,
    )
    .bind(user_id)
    .bind(code_hash)
    .execute(executor)
    .await;

    match result {
        Ok(r) => Ok(r.rows_affected() > 0),
        Err(sqlx::Error::Database(ref db_err)) if db_err.code().as_deref() == Some("23505") => {
            Err(AppError::TotpCodeReplayed)
        }
        Err(e) => Err(AppError::from(e)),
    }
}

pub async fn is_code_used<'e, E>(
    executor: E,
    user_id: Uuid,
    code_hash: &[u8],
) -> Result<bool, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM totp_used_codes
            WHERE user_id = $1 AND code_hash = $2
        )
        "#,
    )
    .bind(user_id)
    .bind(code_hash)
    .fetch_one(executor)
    .await
    .map_err(AppError::from)?;

    Ok(exists)
}

pub async fn create_two_factor_token<'e, E>(
    executor: E,
    user_id: Uuid,
    token_hash: &[u8],
    credential_hash: &str,
    expires_at: DateTime<Utc>,
) -> Result<TwoFactorToken, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<Postgres, TwoFactorToken>(
        r#"
        INSERT INTO two_factor_tokens (user_id, token_hash, credential_hash, expires_at)
        VALUES ($1, $2, $3, $4)
        RETURNING id, user_id, token_hash, credential_hash, expires_at, created_at
        "#,
    )
    .bind(user_id)
    .bind(token_hash)
    .bind(credential_hash)
    .bind(expires_at)
    .fetch_one(executor)
    .await
    .map_err(AppError::from)
}

pub async fn consume_two_factor_token<'e, E>(
    executor: E,
    token_hash: &[u8],
) -> Result<Option<TwoFactorToken>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<Postgres, TwoFactorToken>(
        r#"
        DELETE FROM two_factor_tokens
        WHERE token_hash = $1
        RETURNING id, user_id, token_hash, credential_hash, expires_at, created_at
        "#,
    )
    .bind(token_hash)
    .fetch_optional(executor)
    .await
    .map_err(AppError::from)
}

pub async fn delete_two_factor_tokens_for_user<'e, E>(
    executor: E,
    user_id: Uuid,
) -> Result<u64, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query("DELETE FROM two_factor_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected())
}

pub async fn prune_expired_two_factor_tokens<'e, E>(executor: E) -> Result<u64, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query("DELETE FROM two_factor_tokens WHERE expires_at <= NOW()")
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected())
}

pub async fn prune_used_codes<'e, E>(executor: E, max_age: Duration) -> Result<u64, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let cutoff =
        Utc::now() - ChronoDuration::from_std(max_age).unwrap_or(ChronoDuration::minutes(10));
    let result = sqlx::query("DELETE FROM totp_used_codes WHERE used_at <= $1")
        .bind(cutoff)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected())
}
