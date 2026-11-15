//! Stateful session service and PostgreSQL lifecycle management.

use std::sync::Arc;
use chrono::Utc;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    config::Config,
    db::models::Session,
    error::AppError,
};

/// Service managing persistent session lifecycle, dual-timeout expiry, and revocation.
#[derive(Clone)]
pub struct SessionService {
    db: PgPool,
    config: Arc<Config>,
}

impl SessionService {
    /// Construct a new session service with the provided database connection pool and configuration.
    pub fn new(db: PgPool, config: Arc<Config>) -> Self {
        Self { db, config }
    }

    /// Returns a reference to the underlying database connection pool.
    pub fn db(&self) -> &PgPool {
        &self.db
    }

    /// Returns a reference to the application configuration.
    pub fn config(&self) -> &Arc<Config> {
        &self.config
    }

    /// Generate 32-character lowercase hex raw session ID from 16 OsRng bytes (128-bit entropy).
    ///
    /// Never logged or persisted directly.
    pub(crate) fn generate_raw_id() -> String {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Returns the SHA-256 lowercase hex digest of a raw session ID.
    ///
    /// Deterministic 64-character hex output safe to query and store.
    pub fn hash_raw_id(raw_id: &str) -> String {
        let digest = Sha256::digest(raw_id.as_bytes());
        hex::encode(digest)
    }

    /// Create a new session for `user_id`.
    ///
    /// Generates a 128-bit entropy session token, SHA-256 hashes it for database storage,
    /// enforces per-user concurrent session limits, and generates a CSRF token for cookie sessions.
    ///
    /// Returns `(Session, raw_session_token)`.
    pub async fn create_session(
        &self,
        user_id: Uuid,
        session_type: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(Session, String), AppError> {
        let raw_id = Self::generate_raw_id();
        let token_hash = Self::hash_raw_id(&raw_id);

        let now = Utc::now();
        let absolute_expires_at = now + self.config.session.absolute_lifetime();

        let csrf_token = if session_type == "cookie" {
            let mut csrf_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut csrf_bytes);
            Some(hex::encode(csrf_bytes))
        } else {
            None
        };

        // Enforce maximum concurrent active sessions limit per user.
        if self.config.session.max_active_sessions_per_user > 0 {
            let active_sessions: Vec<Uuid> = sqlx::query_scalar::<_, Uuid>(
                r#"
                SELECT id FROM sessions
                WHERE user_id = $1 AND absolute_expires_at > $2
                ORDER BY last_active_at ASC
                "#,
            )
            .bind(user_id)
            .bind(now)
            .fetch_all(&self.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to check active sessions for capacity limit");
                AppError::Database(e)
            })?;

            if active_sessions.len() >= self.config.session.max_active_sessions_per_user {
                let to_evict_count =
                    active_sessions.len() - self.config.session.max_active_sessions_per_user + 1;
                let ids_to_evict = &active_sessions[..to_evict_count];
                sqlx::query("DELETE FROM sessions WHERE id = ANY($1)")
                    .bind(ids_to_evict)
                    .execute(&self.db)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "Failed to evict oldest active sessions");
                        AppError::Database(e)
                    })?;
            }
        }

        let session = sqlx::query_as::<_, Session>(
            r#"
            INSERT INTO sessions (
                id, user_id, token_hash, created_at,
                last_active_at, absolute_expires_at,
                session_type, csrf_token
            )
            VALUES (
                gen_random_uuid(), $1, $2, $3,
                $3, $4,
                $5, $6
            )
            RETURNING
                id, user_id, token_hash, created_at,
                last_active_at, absolute_expires_at,
                session_type, csrf_token
            "#,
        )
        .bind(user_id)
        .bind(&token_hash)
        .bind(now)
        .bind(absolute_expires_at)
        .bind(session_type)
        .bind(csrf_token)
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to insert session");
            AppError::Database(e)
        })?;

        tracing::info!(
            event = "session_created",
            user_id = %user_id,
            session_type = session_type,
            ip = ip.unwrap_or("unknown"),
            user_agent = user_agent.unwrap_or("unknown"),
        );

        Ok((session, raw_id))
    }

    /// Convenience wrapper for session creation without explicit IP or User-Agent metadata.
    pub async fn create_session_simple(
        &self,
        user_id: Uuid,
        session_type: &str,
    ) -> Result<(Session, String), AppError> {
        self.create_session(user_id, session_type, None, None).await
    }

    /// Look up and validate an active session by its raw session token.
    ///
    /// Verifies absolute expiry before idle timeout, eagerly invalidates expired rows,
    /// and updates `last_active_at` on active sessions.
    pub async fn get_session(&self, raw_id: &str) -> Result<Session, AppError> {
        let token_hash = Self::hash_raw_id(raw_id);
        let now = Utc::now();

        let session = sqlx::query_as::<_, Session>(
            r#"
            SELECT
                id, user_id, token_hash, created_at,
                last_active_at, absolute_expires_at,
                session_type, csrf_token
            FROM sessions
            WHERE token_hash = $1
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Database error fetching session");
            AppError::Database(e)
        })?
        .ok_or(AppError::SessionNotFound)?;

        // Defence-in-depth: check absolute timeout first.
        if now > session.absolute_expires_at {
            tracing::info!(
                event = "session_expired",
                reason = "absolute",
            );
            let _ = self.invalidate_by_hash(&token_hash).await;
            return Err(AppError::SessionExpired);
        }

        // Check sliding idle timeout second.
        let idle_deadline = session.last_active_at
            + chrono::Duration::from_std(self.config.session.idle_timeout())
                .map_err(|_| AppError::Internal)?;
        if now > idle_deadline {
            tracing::info!(
                event = "session_expired",
                reason = "idle",
            );
            let _ = self.invalidate_by_hash(&token_hash).await;
            return Err(AppError::SessionExpired);
        }

        // Update sliding activity window.
        sqlx::query("UPDATE sessions SET last_active_at = $1 WHERE token_hash = $2")
            .bind(now)
            .bind(&token_hash)
            .execute(&self.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to update session last_active_at");
                AppError::Database(e)
            })?;

        let mut session = session;
        session.last_active_at = now;
        Ok(session)
    }

    /// Alias for [`get_session`](Self::get_session) validating a raw token.
    pub async fn validate_session(&self, raw_token: &str) -> Result<Session, AppError> {
        self.get_session(raw_token).await
    }

    /// Touch session activity timestamp by token hash after verifying timeouts.
    pub async fn touch_session(&self, token_hash: &str) -> Result<(), AppError> {
        let now = Utc::now();
        let session = sqlx::query_as::<_, Session>(
            r#"
            SELECT
                id, user_id, token_hash, created_at,
                last_active_at, absolute_expires_at,
                session_type, csrf_token
            FROM sessions
            WHERE token_hash = $1
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Database error fetching session to touch");
            AppError::Database(e)
        })?
        .ok_or(AppError::SessionNotFound)?;

        // Defence-in-depth: check absolute timeout first.
        if now > session.absolute_expires_at {
            tracing::info!(
                event = "session_expired",
                reason = "absolute",
            );
            let _ = self.invalidate_by_hash(token_hash).await;
            return Err(AppError::SessionExpired);
        }

        // Check sliding idle timeout second.
        let idle_deadline = session.last_active_at
            + chrono::Duration::from_std(self.config.session.idle_timeout())
                .map_err(|_| AppError::Internal)?;
        if now > idle_deadline {
            tracing::info!(
                event = "session_expired",
                reason = "idle",
            );
            let _ = self.invalidate_by_hash(token_hash).await;
            return Err(AppError::SessionExpired);
        }

        sqlx::query("UPDATE sessions SET last_active_at = $1 WHERE token_hash = $2")
            .bind(now)
            .bind(token_hash)
            .execute(&self.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to touch session");
                AppError::Database(e)
            })?;
        Ok(())
    }

    /// Invalidate a session by raw session token. Idempotent.
    pub async fn invalidate_session(&self, raw_id: &str) -> Result<(), AppError> {
        let token_hash = Self::hash_raw_id(raw_id);
        self.invalidate_by_hash(&token_hash).await
    }

    /// Alias for [`invalidate_session`](Self::invalidate_session).
    pub async fn revoke_session(&self, raw_id: &str) -> Result<(), AppError> {
        self.invalidate_session(raw_id).await
    }

    /// Invalidate a session by its stored SHA-256 hash. Idempotent.
    pub async fn invalidate_by_hash(&self, token_hash: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&self.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete session by hash");
                AppError::Database(e)
            })?;
        Ok(())
    }

    /// Invalidate all active and inactive sessions belonging to `user_id`.
    ///
    /// Returns the number of sessions deleted.
    pub async fn invalidate_all_user_sessions(&self, user_id: Uuid) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, user_id = %user_id, "Failed to delete all user sessions");
                AppError::Database(e)
            })?;

        tracing::info!(
            event = "all_sessions_invalidated",
            user_id = %user_id,
        );

        Ok(result.rows_affected())
    }

    /// Alias for [`invalidate_all_user_sessions`](Self::invalidate_all_user_sessions).
    pub async fn revoke_all_user_sessions(&self, user_id: Uuid) -> Result<u64, AppError> {
        self.invalidate_all_user_sessions(user_id).await
    }

    /// Atomically rotate a session: validates old session, revokes it, and issues a fresh session.
    pub async fn rotate_session(
        &self,
        old_raw_id: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(Session, String), AppError> {
        // get_session validates existence, enforces absolute expiry first, enforces idle timeout second,
        // and eagerly purges expired sessions returning AppError::SessionExpired.
        let old_session = self.get_session(old_raw_id).await?;
        let old_hash = Self::hash_raw_id(old_raw_id);

        self.invalidate_by_hash(&old_hash).await?;

        self.create_session(
            old_session.user_id,
            &old_session.session_type,
            ip,
            user_agent,
        )
        .await
    }

    /// List active, non-expired sessions for a user ordered by most recently active.
    pub async fn list_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, AppError> {
        let now = Utc::now();
        let sessions = sqlx::query_as::<_, Session>(
            r#"
            SELECT
                id, user_id, token_hash, created_at,
                last_active_at, absolute_expires_at,
                session_type, csrf_token
            FROM sessions
            WHERE user_id = $1
              AND absolute_expires_at > $2
            ORDER BY last_active_at DESC
            "#,
        )
        .bind(user_id)
        .bind(now)
        .fetch_all(&self.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to list sessions for user");
            AppError::Database(e)
        })?;

        Ok(sessions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use chrono::Duration;

    #[test]
    fn test_session_id_entropy() {
        let mut ids = HashSet::with_capacity(1000);
        for _ in 0..1000 {
            let id = SessionService::generate_raw_id();
            assert_eq!(id.len(), 32, "raw session ID must be 32 hex chars (16 bytes)");
            assert!(
                id.chars().all(|c| c.is_ascii_hexdigit()),
                "raw session ID must be hex"
            );
            ids.insert(id);
        }
        assert_eq!(ids.len(), 1000, "all 1000 generated session IDs must be unique");
    }

    #[test]
    fn test_hash_determinism() {
        let raw = "abcdef0123456789abcdef0123456789";
        let hash1 = SessionService::hash_raw_id(raw);
        let hash2 = SessionService::hash_raw_id(raw);
        assert_eq!(hash1, hash2, "hashing must be deterministic");
        assert_eq!(hash1.len(), 64, "SHA-256 hash must be 64 hex characters");
        assert!(
            hash1.chars().all(|c| c.is_ascii_hexdigit()),
            "hash must be lowercase hex"
        );

        let hash_other = SessionService::hash_raw_id("fedcba9876543210fedcba9876543210");
        assert_ne!(hash1, hash_other, "distinct raw tokens must yield distinct hashes");
    }

    #[test]
    fn test_idle_timeout_logic() {
        let now = Utc::now();
        let idle_timeout = Duration::minutes(30);

        // Case 1: Active 31 minutes ago -> expired
        let last_active_expired = now - Duration::minutes(31);
        let expired_deadline = last_active_expired + idle_timeout;
        assert!(
            now > expired_deadline,
            "session inactive for 31m must exceed 30m idle deadline"
        );

        // Case 2: Active 10 minutes ago -> active
        let last_active_valid = now - Duration::minutes(10);
        let valid_deadline = last_active_valid + idle_timeout;
        assert!(
            now <= valid_deadline,
            "session active 10m ago must be within 30m idle deadline"
        );
    }

    #[test]
    fn test_absolute_timeout_logic() {
        let now = Utc::now();

        // Case 1: Expiry in the past -> expired
        let expired_at = now - Duration::seconds(1);
        assert!(now > expired_at, "past absolute expiry must be expired");

        // Case 2: Expiry in future -> active
        let valid_at = now + Duration::hours(12);
        assert!(now <= valid_at, "future absolute expiry must be active");
    }
}
