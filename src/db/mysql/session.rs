use chrono::{DateTime, Utc};
use sqlx::{Executor, MySql};
use uuid::Uuid;

use crate::{db::models::Session, error::AppError};

pub async fn create_session<'e, E>(
    executor: E,
    user_id: Uuid,
    token_hash: &str,
    session_type: &str,
    csrf_token: Option<&str>,
    absolute_expires_at: DateTime<Utc>,
) -> Result<Session, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, token_hash, session_type, csrf_token, created_at, last_active_at, absolute_expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(token_hash)
    .bind(session_type)
    .bind(csrf_token)
    .bind(now)
    .bind(now)
    .bind(absolute_expires_at)
    .execute(executor)
    .await
    .map_err(AppError::from)?;

    Ok(Session {
        id,
        user_id,
        token_hash: token_hash.to_string(),
        created_at: now,
        last_active_at: now,
        absolute_expires_at,
        session_type: session_type.to_string(),
        csrf_token: csrf_token.map(ToString::to_string),
    })
}

pub async fn get_session_by_token_hash<'e, E>(
    executor: E,
    token_hash: &str,
) -> Result<Option<Session>, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    sqlx::query_as::<MySql, Session>(
        r#"
        SELECT id, user_id, token_hash, created_at, last_active_at, absolute_expires_at, session_type, csrf_token
        FROM sessions
        WHERE token_hash = ?
        "#,
    )
    .bind(token_hash)
    .fetch_optional(executor)
    .await
    .map_err(AppError::from)
}

pub async fn touch_session<'e, E>(
    executor: E,
    session_id: Uuid,
    last_active_at: DateTime<Utc>,
) -> Result<(), AppError>
where
    E: Executor<'e, Database = MySql>,
{
    sqlx::query("UPDATE sessions SET last_active_at = ? WHERE id = ?")
        .bind(last_active_at)
        .bind(session_id)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(())
}

pub async fn rotate_session<'e, E>(
    executor: E,
    session_id: Uuid,
    new_token_hash: &str,
    new_csrf_token: Option<&str>,
    last_active_at: DateTime<Utc>,
) -> Result<(), AppError>
where
    E: Executor<'e, Database = MySql>,
{
    sqlx::query(
        r#"
        UPDATE sessions
        SET token_hash = ?, csrf_token = ?, last_active_at = ?
        WHERE id = ?
        "#,
    )
    .bind(new_token_hash)
    .bind(new_csrf_token)
    .bind(last_active_at)
    .bind(session_id)
    .execute(executor)
    .await
    .map_err(AppError::from)?;

    Ok(())
}

pub async fn delete_session<'e, E>(executor: E, session_id: Uuid) -> Result<(), AppError>
where
    E: Executor<'e, Database = MySql>,
{
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(session_id)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(())
}

pub async fn delete_by_token_hash<'e, E>(executor: E, token_hash: &str) -> Result<bool, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let result = sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
        .bind(token_hash)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected() > 0)
}

pub async fn delete_user_sessions<'e, E>(executor: E, user_id: Uuid) -> Result<u64, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let result = sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected())
}

pub async fn list_user_sessions<'e, E>(executor: E, user_id: Uuid) -> Result<Vec<Session>, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    sqlx::query_as::<MySql, Session>(
        r#"
        SELECT id, user_id, token_hash, created_at, last_active_at, absolute_expires_at, session_type, csrf_token
        FROM sessions
        WHERE user_id = ?
        ORDER BY last_active_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(executor)
    .await
    .map_err(AppError::from)
}

pub async fn delete_expired_sessions<'e, E>(executor: E) -> Result<u64, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let result = sqlx::query("DELETE FROM sessions WHERE absolute_expires_at <= UTC_TIMESTAMP(6)")
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_session_query_placeholders() {
        let q1 = "INSERT INTO sessions (id, user_id, token_hash, session_type, csrf_token, created_at, last_active_at, absolute_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        assert_eq!(q1.matches('?').count(), 8);

        let q2 =
            "UPDATE sessions SET token_hash = ?, csrf_token = ?, last_active_at = ? WHERE id = ?";
        assert_eq!(q2.matches('?').count(), 4);
    }
}
