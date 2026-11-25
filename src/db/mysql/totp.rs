use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::{Executor, MySql, MySqlConnection};
use uuid::Uuid;

use crate::{
    db::models::{TotpSecret, TwoFactorToken},
    error::AppError,
};

pub async fn get_secret<'e, E>(executor: E, user_id: Uuid) -> Result<Option<TotpSecret>, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    sqlx::query_as::<MySql, TotpSecret>(
        r#"
        SELECT id, user_id, encrypted_secret, backup_codes, enabled, created_at, updated_at
        FROM totp_secrets
        WHERE user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_optional(executor)
    .await
    .map_err(AppError::from)
}

pub async fn upsert_secret(
    conn: &mut MySqlConnection,
    user_id: Uuid,
    encrypted_secret: &[u8],
    backup_codes: serde_json::Value,
) -> Result<TotpSecret, AppError> {
    // 1. Lock parent user row to serialize concurrent enrollments and eliminate
    // InnoDB gap lock deadlocks on the totp_secrets unique index.
    let user_exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE id = ? FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(AppError::from)?;

    if user_exists.is_none() {
        return Err(AppError::NotFound);
    }

    // 2. Check existing totp_secrets row
    let existing = sqlx::query_as::<MySql, TotpSecret>(
        r#"
        SELECT id, user_id, encrypted_secret, backup_codes, enabled, created_at, updated_at
        FROM totp_secrets
        WHERE user_id = ?
        FOR UPDATE
        "#,
    )
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::from)?;

    let now = Utc::now();
    match existing {
        Some(secret) => {
            if secret.enabled {
                return Err(AppError::TotpAlreadyEnabled);
            }
            sqlx::query(
                r#"
                UPDATE totp_secrets
                SET encrypted_secret = ?, backup_codes = ?, updated_at = ?
                WHERE user_id = ?
                "#,
            )
            .bind(encrypted_secret)
            .bind(&backup_codes)
            .bind(now)
            .bind(user_id)
            .execute(&mut *conn)
            .await
            .map_err(AppError::from)?;

            Ok(TotpSecret {
                id: secret.id,
                user_id,
                encrypted_secret: encrypted_secret.to_vec(),
                backup_codes,
                enabled: false,
                created_at: secret.created_at,
                updated_at: now,
            })
        }
        None => {
            let id = Uuid::new_v4();
            sqlx::query(
                r#"
                INSERT INTO totp_secrets (id, user_id, encrypted_secret, backup_codes, enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, FALSE, ?, ?)
                "#,
            )
            .bind(id)
            .bind(user_id)
            .bind(encrypted_secret)
            .bind(&backup_codes)
            .bind(now)
            .bind(now)
            .execute(&mut *conn)
            .await
            .map_err(AppError::from)?;

            Ok(TotpSecret {
                id,
                user_id,
                encrypted_secret: encrypted_secret.to_vec(),
                backup_codes,
                enabled: false,
                created_at: now,
                updated_at: now,
            })
        }
    }
}

pub async fn enable_totp<'e, E>(executor: E, user_id: Uuid) -> Result<bool, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let result = sqlx::query(
        r#"
        UPDATE totp_secrets
        SET enabled = TRUE, updated_at = UTC_TIMESTAMP(6)
        WHERE user_id = ? AND enabled = FALSE
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
    E: Executor<'e, Database = MySql>,
{
    let result = sqlx::query(
        r#"
        UPDATE totp_secrets
        SET enabled = FALSE, updated_at = UTC_TIMESTAMP(6)
        WHERE user_id = ? AND enabled = TRUE
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
    E: Executor<'e, Database = MySql>,
{
    let id = Uuid::new_v4();
    let now = Utc::now();
    let result = sqlx::query(
        r#"
        INSERT INTO totp_used_codes (id, user_id, code_hash, used_at)
        VALUES (?, ?, ?, ?)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(code_hash)
    .bind(now)
    .execute(executor)
    .await;

    match result {
        Ok(r) => Ok(r.rows_affected() > 0),
        Err(sqlx::Error::Database(ref db_err)) if db_err.code().as_deref() == Some("1062") => {
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
    E: Executor<'e, Database = MySql>,
{
    let exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM totp_used_codes
            WHERE user_id = ? AND code_hash = ?
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
    E: Executor<'e, Database = MySql>,
{
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO two_factor_tokens (id, user_id, token_hash, credential_hash, expires_at)
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(token_hash)
    .bind(credential_hash)
    .bind(expires_at)
    .execute(executor)
    .await
    .map_err(AppError::from)?;

    Ok(TwoFactorToken {
        id,
        user_id,
        token_hash: token_hash.to_vec(),
        expires_at,
    })
}

pub async fn consume_two_factor_token(
    conn: &mut MySqlConnection,
    token_hash: &[u8],
) -> Result<Option<TwoFactorToken>, AppError> {
    let row = sqlx::query_as::<MySql, TwoFactorToken>(
        r#"
        SELECT id, user_id, token_hash, expires_at
        FROM two_factor_tokens
        WHERE token_hash = ?
        FOR UPDATE
        "#,
    )
    .bind(token_hash)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::from)?;

    if row.is_some() {
        sqlx::query("DELETE FROM two_factor_tokens WHERE token_hash = ?")
            .bind(token_hash)
            .execute(&mut *conn)
            .await
            .map_err(AppError::from)?;
    }

    Ok(row)
}

pub async fn delete_two_factor_tokens_for_user<'e, E>(
    executor: E,
    user_id: Uuid,
) -> Result<u64, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let result = sqlx::query("DELETE FROM two_factor_tokens WHERE user_id = ?")
        .bind(user_id)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected())
}

pub async fn prune_expired_two_factor_tokens<'e, E>(executor: E) -> Result<u64, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let result = sqlx::query("DELETE FROM two_factor_tokens WHERE expires_at <= UTC_TIMESTAMP(6)")
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected())
}

pub async fn prune_used_codes<'e, E>(executor: E, max_age: Duration) -> Result<u64, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let cutoff =
        Utc::now() - ChronoDuration::from_std(max_age).unwrap_or(ChronoDuration::minutes(10));
    let result = sqlx::query("DELETE FROM totp_used_codes WHERE used_at <= ?")
        .bind(cutoff)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_totp_query_placeholders() {
        let q1 = "INSERT INTO totp_secrets (id, user_id, encrypted_secret, backup_codes, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, FALSE, ?, ?)";
        assert_eq!(q1.matches('?').count(), 6);

        let q2 =
            "INSERT INTO totp_used_codes (id, user_id, code_hash, used_at) VALUES (?, ?, ?, ?)";
        assert_eq!(q2.matches('?').count(), 4);

        let q3 = "INSERT INTO two_factor_tokens (id, user_id, token_hash, credential_hash, expires_at) VALUES (?, ?, ?, ?, ?)";
        assert_eq!(q3.matches('?').count(), 5);
    }
}
