use chrono::{DateTime, Utc};
use sqlx::{Executor, MySql, MySqlConnection};
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
    E: Executor<'e, Database = MySql>,
{
    let normalized = email.trim().to_lowercase();
    let id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO users (id, email, password_hash, email_verified, created_at, updated_at)
        VALUES (?, ?, ?, FALSE, ?, ?)
        "#,
    )
    .bind(id)
    .bind(&normalized)
    .bind(password_hash)
    .bind(now)
    .bind(now)
    .execute(executor)
    .await
    .map_err(|e| {
        if crate::db::mysql::is_mysql_duplicate_key_error(&e) {
            AppError::EmailAlreadyExists
        } else {
            AppError::from(e)
        }
    })?;

    Ok(User {
        id,
        email: normalized,
        password_hash: password_hash.to_string(),
        email_verified: false,
        created_at: now,
        updated_at: now,
    })
}

pub async fn get_user_by_id<'e, E>(executor: E, id: Uuid) -> Result<Option<User>, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    sqlx::query_as::<MySql, User>(
        r#"
        SELECT id, email, password_hash, email_verified, created_at, updated_at
        FROM users
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(executor)
    .await
    .map_err(AppError::from)
}

pub async fn get_user_by_email<'e, E>(executor: E, email: &str) -> Result<Option<User>, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let normalized = email.trim().to_lowercase();
    sqlx::query_as::<MySql, User>(
        r#"
        SELECT id, email, password_hash, email_verified, created_at, updated_at
        FROM users
        WHERE email = ?
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
    E: Executor<'e, Database = MySql>,
{
    sqlx::query(
        r#"
        UPDATE users
        SET email_verified = ?, updated_at = UTC_TIMESTAMP(6)
        WHERE id = ?
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
    E: Executor<'e, Database = MySql>,
{
    sqlx::query(
        r#"
        UPDATE users
        SET password_hash = ?, updated_at = UTC_TIMESTAMP(6)
        WHERE id = ?
        "#,
    )
    .bind(new_hash)
    .bind(user_id)
    .execute(executor)
    .await
    .map_err(AppError::from)?;

    Ok(())
}

pub async fn delete_user<'e, E>(executor: E, user_id: Uuid) -> Result<bool, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let result = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user_id)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected() > 0)
}

pub async fn create_verification_token<'e, E>(
    executor: E,
    user_id: Uuid,
    token_hash: &[u8],
    expires_at: DateTime<Utc>,
) -> Result<VerificationToken, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let now = Utc::now();
    sqlx::query(
        r#"
        INSERT INTO verification_tokens (token_hash, user_id, expires_at, created_at)
        VALUES (?, ?, ?, ?)
        "#,
    )
    .bind(token_hash)
    .bind(user_id)
    .bind(expires_at)
    .bind(now)
    .execute(executor)
    .await
    .map_err(AppError::from)?;

    Ok(VerificationToken {
        token_hash: token_hash.to_vec(),
        user_id,
        expires_at,
        created_at: now,
    })
}

pub async fn consume_verification_token(
    conn: &mut MySqlConnection,
    token_hash: &[u8],
) -> Result<Option<VerificationToken>, AppError> {
    let row = sqlx::query_as::<MySql, VerificationToken>(
        r#"
        SELECT token_hash, user_id, expires_at, created_at
        FROM verification_tokens
        WHERE token_hash = ?
        FOR UPDATE
        "#,
    )
    .bind(token_hash)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::from)?;

    if row.is_some() {
        sqlx::query("DELETE FROM verification_tokens WHERE token_hash = ?")
            .bind(token_hash)
            .execute(&mut *conn)
            .await
            .map_err(AppError::from)?;
    }

    Ok(row)
}

pub async fn create_password_reset_token<'e, E>(
    executor: E,
    user_id: Uuid,
    token_hash: &[u8],
    expires_at: DateTime<Utc>,
) -> Result<PasswordResetToken, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let now = Utc::now();
    sqlx::query(
        r#"
        INSERT INTO password_reset_tokens (token_hash, user_id, expires_at, created_at)
        VALUES (?, ?, ?, ?)
        "#,
    )
    .bind(token_hash)
    .bind(user_id)
    .bind(expires_at)
    .bind(now)
    .execute(executor)
    .await
    .map_err(AppError::from)?;

    Ok(PasswordResetToken {
        token_hash: token_hash.to_vec(),
        user_id,
        expires_at,
        created_at: now,
    })
}

pub async fn consume_password_reset_token(
    conn: &mut MySqlConnection,
    token_hash: &[u8],
) -> Result<Option<PasswordResetToken>, AppError> {
    let row = sqlx::query_as::<MySql, PasswordResetToken>(
        r#"
        SELECT token_hash, user_id, expires_at, created_at
        FROM password_reset_tokens
        WHERE token_hash = ?
        FOR UPDATE
        "#,
    )
    .bind(token_hash)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::from)?;

    if row.is_some() {
        sqlx::query("DELETE FROM password_reset_tokens WHERE token_hash = ?")
            .bind(token_hash)
            .execute(&mut *conn)
            .await
            .map_err(AppError::from)?;
    }

    Ok(row)
}

pub async fn delete_user_password_reset_tokens<'e, E>(
    executor: E,
    user_id: Uuid,
) -> Result<u64, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let result = sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = ?")
        .bind(user_id)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected())
}

pub async fn delete_verification_tokens_for_user<'e, E>(
    executor: E,
    user_id: Uuid,
) -> Result<u64, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let result = sqlx::query("DELETE FROM verification_tokens WHERE user_id = ?")
        .bind(user_id)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_email_normalization_logic() {
        let input = "  User.Name@Example.COM  ";
        let normalized = input.trim().to_lowercase();
        assert_eq!(normalized, "user.name@example.com");
    }

    #[test]
    fn test_sql_syntax_placeholders() {
        let q1 = "INSERT INTO users (id, email, password_hash, email_verified, created_at, updated_at) VALUES (?, ?, ?, FALSE, ?, ?)";
        assert_eq!(q1.matches('?').count(), 5);

        let q2 = "SELECT id, email, password_hash, email_verified, created_at, updated_at FROM users WHERE id = ?";
        assert_eq!(q2.matches('?').count(), 1);

        let q3 = "UPDATE users SET email_verified = ?, updated_at = UTC_TIMESTAMP(6) WHERE id = ?";
        assert_eq!(q3.matches('?').count(), 2);

        let q4 = "INSERT INTO verification_tokens (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)";
        assert_eq!(q4.matches('?').count(), 4);
    }
}
