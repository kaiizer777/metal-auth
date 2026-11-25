use chrono::{DateTime, Utc};
use sqlx::{Executor, Postgres};
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
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<Postgres, Session>(
        r#"
        INSERT INTO sessions (user_id, token_hash, session_type, csrf_token, absolute_expires_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, user_id, token_hash, created_at, last_active_at, absolute_expires_at, session_type, csrf_token
        "#,
    )
    .bind(user_id)
    .bind(token_hash)
    .bind(session_type)
    .bind(csrf_token)
    .bind(absolute_expires_at)
    .fetch_one(executor)
    .await
    .map_err(AppError::from)
}

pub async fn get_session_by_token_hash<'e, E>(
    executor: E,
    token_hash: &str,
) -> Result<Option<Session>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<Postgres, Session>(
        r#"
        SELECT id, user_id, token_hash, created_at, last_active_at, absolute_expires_at, session_type, csrf_token
        FROM sessions
        WHERE token_hash = $1
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
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query("UPDATE sessions SET last_active_at = $1 WHERE id = $2")
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
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        r#"
        UPDATE sessions
        SET token_hash = $1, csrf_token = $2, last_active_at = $3
        WHERE id = $4
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
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(session_id)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(())
}

pub async fn delete_user_sessions<'e, E>(executor: E, user_id: Uuid) -> Result<u64, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected())
}

pub async fn list_user_sessions<'e, E>(
    executor: E,
    user_id: Uuid,
) -> Result<Vec<Session>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_as::<Postgres, Session>(
        r#"
        SELECT id, user_id, token_hash, created_at, last_active_at, absolute_expires_at, session_type, csrf_token
        FROM sessions
        WHERE user_id = $1
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
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query("DELETE FROM sessions WHERE absolute_expires_at <= NOW()")
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected())
}
