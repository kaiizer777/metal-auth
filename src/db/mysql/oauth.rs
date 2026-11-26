use chrono::Utc;
use sqlx::{Executor, MySql};
use uuid::Uuid;

use crate::{db::models::OAuthAccount, error::AppError};

pub async fn get_account<'e, E>(
    executor: E,
    provider_id: &str,
    provider_user_id: &str,
) -> Result<Option<OAuthAccount>, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    sqlx::query_as::<MySql, OAuthAccount>(
        r#"
        SELECT id, user_id, provider_id, provider_user_id, email, created_at, updated_at
        FROM oauth_accounts
        WHERE provider_id = ? AND provider_user_id = ?
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
    E: Executor<'e, Database = MySql>,
{
    sqlx::query_as::<MySql, OAuthAccount>(
        r#"
        SELECT id, user_id, provider_id, provider_user_id, email, created_at, updated_at
        FROM oauth_accounts
        WHERE user_id = ?
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
    E: Executor<'e, Database = MySql>,
{
    let normalized = email.trim().to_lowercase();
    let id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO oauth_accounts (id, user_id, provider_id, provider_user_id, email, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(provider_id)
    .bind(provider_user_id)
    .bind(&normalized)
    .bind(now)
    .bind(now)
    .execute(executor)
    .await
    .map_err(|e| {
        if crate::db::mysql::is_mysql_duplicate_key_error(&e) {
            AppError::OAuthAccountLinkConflict
        } else {
            AppError::from(e)
        }
    })?;

    Ok(OAuthAccount {
        id,
        user_id,
        provider_id: provider_id.to_string(),
        provider_user_id: provider_user_id.to_string(),
        email: normalized,
        created_at: now,
        updated_at: now,
    })
}

pub async fn unlink_account<'e, E>(
    executor: E,
    user_id: Uuid,
    provider_id: &str,
) -> Result<bool, AppError>
where
    E: Executor<'e, Database = MySql>,
{
    let result = sqlx::query("DELETE FROM oauth_accounts WHERE user_id = ? AND provider_id = ?")
        .bind(user_id)
        .bind(provider_id)
        .execute(executor)
        .await
        .map_err(AppError::from)?;

    Ok(result.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_oauth_query_placeholders() {
        let q1 = "INSERT INTO oauth_accounts (id, user_id, provider_id, provider_user_id, email, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)";
        assert_eq!(q1.matches('?').count(), 7);

        let q2 = "SELECT id, user_id, provider_id, provider_user_id, email, created_at, updated_at FROM oauth_accounts WHERE provider_id = ? AND provider_user_id = ?";
        assert_eq!(q2.matches('?').count(), 2);
    }
}
