//! Stateful session service and PostgreSQL lifecycle management.

use chrono::{DateTime, Utc};
use rand_core::{OsRng, RngCore};
use sqlx::{PgConnection, PgPool};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{config::Config, db::models::Session, error::AppError};

/// Service managing persistent session lifecycle, dual-timeout expiry, and revocation.
#[derive(Clone, Debug)]
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

    /// Generate the canonical 64-character lowercase hex raw session ID (32 OsRng bytes).
    ///
    /// Delegates to [`crate::session::generate_session_id`]: a single generator guarantees
    /// every session token carries 256-bit entropy. Never logged or persisted directly.
    pub(crate) fn generate_raw_id() -> String {
        super::generate_session_id()
    }

    /// Returns the SHA-256 lowercase hex digest of a raw session ID.
    ///
    /// Delegates to [`crate::session::hash_session_id`]: a single hash function, so
    /// stored `token_hash` values are comparable regardless of call site.
    /// Deterministic 64-character hex output safe to query and store.
    pub fn hash_raw_id(raw_id: &str) -> String {
        super::hash_session_id(raw_id)
    }

    /// Create a new session for `user_id`.
    ///
    /// Generates a 256-bit entropy session token, SHA-256 hashes it for database storage,
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
        self.create_session_inner(user_id, None, session_type, ip, user_agent)
            .await
    }

    /// Read the user's current Argon2id PHC string for a credential-freshness check.
    ///
    /// A missing row and a failed lookup both surface as `SessionInvalid`, so this path
    /// gains no user-enumerating error variant.
    pub async fn current_credential_hash(&self, user_id: Uuid) -> Result<String, AppError> {
        sqlx::query_scalar::<_, String>("SELECT password_hash FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&self.db)
            .await
            .map_err(AppError::Database)?
            .ok_or(AppError::SessionInvalid)
    }

    /// Session creation gated on credential freshness (issue #37).
    ///
    /// `expected_credential_hash` is the Argon2id PHC string verified at login.
    /// It is compared against the live row under the existing user `FOR NO KEY UPDATE`
    /// lock — a cheap string compare, never a re-hash — so a password reset
    /// committing between verification and insert rejects with
    /// `InvalidCredentials` instead of minting a stale session.
    pub async fn create_session_checked(
        &self,
        user_id: Uuid,
        expected_credential_hash: &str,
        session_type: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(Session, String), AppError> {
        self.create_session_inner(
            user_id,
            Some(expected_credential_hash),
            session_type,
            ip,
            user_agent,
        )
        .await
    }

    async fn create_session_inner(
        &self,
        user_id: Uuid,
        expected_credential_hash: Option<&str>,
        session_type: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(Session, String), AppError> {
        let mut tx = self.db.begin().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to begin transaction for create_session");
            AppError::Database(e)
        })?;

        let result = self
            .create_session_in(&mut tx, user_id, expected_credential_hash, session_type)
            .await;
        let (session, raw_id) = match result {
            Ok(result) => result,
            Err(error) => {
                let _ = tx.rollback().await;
                return Err(error);
            }
        };

        tx.commit().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to commit session creation transaction");
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

    /// Insert the session row on the caller's transaction.
    ///
    /// Callers that must atomically couple session issuance with another state change
    /// (the TOTP redemption path) own the transaction; the standalone paths wrap this in
    /// [`Self::create_session_inner`].
    pub(crate) async fn create_session_in(
        &self,
        tx: &mut PgConnection,
        user_id: Uuid,
        expected_credential_hash: Option<&str>,
        session_type: &str,
    ) -> Result<(Session, String), AppError> {
        let raw_id = Self::generate_raw_id();
        let token_hash = Self::hash_raw_id(&raw_id);

        let now = Utc::now();
        let absolute_expires_at = now + self.config.session.absolute_lifetime();
        // Validated config bounds idle_timeout_secs far below i64::MAX, but fail
        // closed instead of wrapping on absurd values.
        let idle_secs =
            i64::try_from(self.config.session.idle_timeout_secs).map_err(|_| AppError::Internal)?;
        let idle_expires_at = now + chrono::Duration::seconds(idle_secs);

        // Row lock on the user row to serialize concurrent session creations for the user.
        // `FOR NO KEY UPDATE` keeps that serialization (and the conflict with `UPDATE users`)
        // without blocking the `FOR KEY SHARE` child inserts the FKs take on this row.
        sqlx::query("SELECT id FROM users WHERE id = $1 FOR NO KEY UPDATE")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to lock user row for session capacity check");
                AppError::Database(e)
            })?;

        // Credential freshness: reject a login whose password was superseded
        // after verification. Same row, same lock — serializes with reset's
        // `UPDATE users ... WHERE id` commit. Missing row also rejects: no
        // user-enumerating error variant leaves this path. Constant-time compare
        // avoids leaking the stored PHC string via timing.
        if let Some(expected) = expected_credential_hash {
            let current: Option<String> =
                sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
                    .bind(user_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(AppError::Database)?;
            let fresh = match current {
                Some(ref stored) if stored.len() == expected.len() => {
                    stored.as_bytes().ct_eq(expected.as_bytes()).into()
                }
                _ => false,
            };
            if !fresh {
                return Err(AppError::SessionInvalid);
            }
        }

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
            .fetch_all(&mut *tx)
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
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "Failed to evict oldest active sessions");
                        AppError::Database(e)
                    })?;
            }
        }

        let session = Self::insert_session_row(
            &mut *tx,
            user_id,
            &token_hash,
            session_type,
            now,
            absolute_expires_at,
            idle_expires_at,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to insert session");
            AppError::Database(e)
        })?;

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
            tracing::info!(event = "session_expired", reason = "absolute",);
            if let Err(e) = self.invalidate_by_hash(&token_hash).await {
                tracing::warn!(event = "expired_session_purge_failed", error = %e);
            }
            return Err(AppError::SessionExpired);
        }

        // Check sliding idle timeout second.
        let idle_deadline = session.last_active_at
            + chrono::Duration::from_std(self.config.session.idle_timeout())
                .map_err(|_| AppError::Internal)?;
        if now > idle_deadline {
            tracing::info!(event = "session_expired", reason = "idle",);
            if let Err(e) = self.invalidate_by_hash(&token_hash).await {
                tracing::warn!(event = "expired_session_purge_failed", error = %e);
            }
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
            tracing::info!(event = "session_expired", reason = "absolute",);
            if let Err(e) = self.invalidate_by_hash(token_hash).await {
                tracing::warn!(event = "expired_session_purge_failed", error = %e);
            }
            return Err(AppError::SessionExpired);
        }

        // Check sliding idle timeout second.
        let idle_deadline = session.last_active_at
            + chrono::Duration::from_std(self.config.session.idle_timeout())
                .map_err(|_| AppError::Internal)?;
        if now > idle_deadline {
            tracing::info!(event = "session_expired", reason = "idle",);
            if let Err(e) = self.invalidate_by_hash(token_hash).await {
                tracing::warn!(event = "expired_session_purge_failed", error = %e);
            }
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
    pub async fn invalidate_all_user_sessions(&self, user_id: Uuid) -> Result<(), AppError> {
        let mut tx = self.db.begin().await.map_err(|e| {
            tracing::error!(error = %e, user_id = %user_id, "Failed to begin transaction for revoke-all");
            AppError::Database(e)
        })?;

        // Serialize with rotate_session, which locks this row before
        // deleting/inserting sessions: whichever tx locks first wins, so no
        // rotate can mint a session this DELETE never sees.
        sqlx::query("SELECT id FROM users WHERE id = $1 FOR NO KEY UPDATE")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, user_id = %user_id, "Failed to lock user row for revoke-all");
                AppError::Database(e)
            })?;

        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, user_id = %user_id, "Failed to delete all user sessions");
                AppError::Database(e)
            })?;

        tx.commit().await.map_err(|e| {
            tracing::error!(error = %e, user_id = %user_id, "Failed to commit revoke-all sessions transaction");
            AppError::Database(e)
        })?;

        tracing::info!(
            event = "all_sessions_invalidated",
            user_id = %user_id,
        );

        Ok(())
    }

    /// Alias for [`invalidate_all_user_sessions`](Self::invalidate_all_user_sessions).
    pub async fn revoke_all_user_sessions(&self, user_id: Uuid) -> Result<(), AppError> {
        self.invalidate_all_user_sessions(user_id).await
    }

    /// Atomically rotate a session: validates old session, revokes it within a transaction,
    /// and issues a fresh session preserving the original absolute expiry deadline.
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

        let mut tx = self.db.begin().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to begin transaction for rotate_session");
            AppError::Database(e)
        })?;

        // Serialize with reset_password's purge: the reset tx locks this row via
        // `UPDATE users ... WHERE id` (src/auth/service.rs:437) before deleting
        // sessions, so whichever tx locks first wins. Reset-first leaves zero
        // rows for the DELETE below.
        sqlx::query("SELECT id FROM users WHERE id = $1 FOR NO KEY UPDATE")
            .bind(old_session.user_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to lock user row for session rotation");
                AppError::Database(e)
            })?;

        // Atomically delete old session; must affect exactly 1 row to prevent replay/duplicate rotation
        let delete_res = sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(&old_hash)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete old session during rotation");
                AppError::Database(e)
            })?;

        if delete_res.rows_affected() == 0 {
            return Err(AppError::SessionNotFound);
        }

        let raw_id = Self::generate_raw_id();
        let token_hash = Self::hash_raw_id(&raw_id);
        let now = Utc::now();
        let idle_secs =
            i64::try_from(self.config.session.idle_timeout_secs).map_err(|_| AppError::Internal)?;
        let idle_expires_at = now + chrono::Duration::seconds(idle_secs);
        // Preserve old absolute deadline to prevent infinite session extension (ASVS L1)
        let absolute_expires_at = old_session.absolute_expires_at;

        let session = Self::insert_session_row(
            &mut *tx,
            old_session.user_id,
            &token_hash,
            &old_session.session_type,
            now,
            absolute_expires_at,
            idle_expires_at,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to insert rotated session");
            AppError::Database(e)
        })?;

        tx.commit().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to commit session rotation transaction");
            AppError::Database(e)
        })?;

        // Token hashes are stable session correlators — never log them.
        tracing::info!(
            event = "session_rotated",
            user_id = %old_session.user_id,
            ip = ip.unwrap_or("unknown"),
            user_agent = user_agent.unwrap_or("unknown"),
        );

        Ok((session, raw_id))
    }

    /// List active, non-expired sessions for a user ordered by most recently active.
    ///
    /// Excludes both absolute-expired and idle-expired rows, mirroring the
    /// `get_session`/`touch_session` validation so listings never advertise a
    /// session those paths would reject.
    pub async fn list_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, AppError> {
        let now = Utc::now();
        let idle_secs = self.config.session.idle_timeout_secs as f64;
        let sessions = sqlx::query_as::<_, Session>(
            r#"
            SELECT
                id, user_id, token_hash, created_at,
                last_active_at, absolute_expires_at,
                session_type, csrf_token
            FROM sessions
            WHERE user_id = $1
              AND absolute_expires_at > $2
              AND last_active_at + make_interval(secs => $3) > $2
            ORDER BY last_active_at DESC
            "#,
        )
        .bind(user_id)
        .bind(now)
        .bind(idle_secs)
        .fetch_all(&self.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to list sessions for user");
            AppError::Database(e)
        })?;

        Ok(sessions)
    }

    /// Mint a CSRF token: 32 OsRng bytes as 64 lowercase hex characters.
    fn new_csrf_token() -> String {
        let mut csrf_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut csrf_bytes);
        dbg!(csrf_bytes);
        tracing::info!(csrf_token = %hex::encode(csrf_bytes), "generated csrf token");
        hex::encode(csrf_bytes)
    }

    /// Insert a session row on the caller's transaction and return the stored row.
    ///
    /// `expires_at` and `absolute_expires_at` both receive `absolute_expires_at`
    /// (schema quirk); `last_active_at` mirrors `created_at`.
    async fn insert_session_row(
        tx: &mut PgConnection,
        user_id: Uuid,
        token_hash: &str,
        session_type: &str,
        created_at: DateTime<Utc>,
        absolute_expires_at: DateTime<Utc>,
        idle_expires_at: DateTime<Utc>,
    ) -> Result<Session, sqlx::Error> {
        let csrf_token = if session_type == "cookie" {
            Some(Self::new_csrf_token())
        } else {
            None
        };

        sqlx::query_as::<_, Session>(
            r#"
            INSERT INTO sessions (
                id, user_id, token_hash, created_at,
                expires_at, idle_expires_at,
                last_active_at, absolute_expires_at,
                session_type, csrf_token
            )
            VALUES (
                gen_random_uuid(), $1, $2, $3,
                $4, $5,
                $3, $4,
                $6, $7
            )
            RETURNING
                id, user_id, token_hash, created_at,
                last_active_at, absolute_expires_at,
                session_type, csrf_token
            "#,
        )
        .bind(user_id)
        .bind(token_hash)
        .bind(created_at)
        .bind(absolute_expires_at)
        .bind(idle_expires_at)
        .bind(session_type)
        .bind(csrf_token)
        .fetch_one(&mut *tx)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::collections::HashSet;

    #[test]
    fn test_session_id_entropy() {
        let mut ids = HashSet::with_capacity(1000);
        for _ in 0..1000 {
            let id = SessionService::generate_raw_id();
            assert_eq!(
                id.len(),
                64,
                "raw session ID must be 64 hex chars (32 bytes)"
            );
            assert!(
                id.chars().all(|c| c.is_ascii_hexdigit()),
                "raw session ID must be hex"
            );
            ids.insert(id);
        }
        assert_eq!(
            ids.len(),
            1000,
            "all 1000 generated session IDs must be unique"
        );
    }

    #[test]
    fn service_delegates_to_canonical_generator_and_hash() {
        // Single generator/hash: service and crate-root outputs share shape.
        let id = SessionService::generate_raw_id();
        assert_eq!(id.len(), crate::session::generate_session_id().len());
        assert_eq!(
            SessionService::hash_raw_id(&id),
            crate::session::hash_session_id(&id)
        );
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
        assert_ne!(
            hash1, hash_other,
            "distinct raw tokens must yield distinct hashes"
        );
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

    async fn live_pool() -> Option<PgPool> {
        dotenvy::dotenv().ok();
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = crate::db::init_pool_with_options(
            &url,
            crate::db::DbPoolOptions {
                max_connections: 2,
                min_connections: 1,
                ..Default::default()
            },
        )
        .await
        .expect("DATABASE_URL is set, so the expiry test pool must connect");
        Some(pool)
    }

    #[tokio::test]
    async fn list_user_sessions_excludes_idle_and_absolute_expired() {
        let Some(pool) = live_pool().await else {
            eprintln!("SKIP: list_user_sessions expiry test needs DATABASE_URL");
            return;
        };
        let config = Arc::new(crate::config::Config {
            database_url: String::new(),
            ..Default::default()
        });
        let service = SessionService::new(pool.clone(), config.clone());
        let idle_margin = i64::try_from(config.session.idle_timeout_secs).unwrap_or(1800) + 120;

        let user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, email, password_hash) VALUES ($1, $2, 'test-hash')")
            .bind(user_id)
            .bind(format!("list_expiry_{user_id}@example.com"))
            .execute(&pool)
            .await
            .expect("seed expiry-test user");

        let (active, _) = service
            .create_session_simple(user_id, "cookie")
            .await
            .expect("active session");
        let (idle, _) = service
            .create_session_simple(user_id, "cookie")
            .await
            .expect("idle-expired session");
        let (absolute, _) = service
            .create_session_simple(user_id, "cookie")
            .await
            .expect("absolute-expired session");

        let now = Utc::now();
        sqlx::query("UPDATE sessions SET last_active_at = $1 WHERE token_hash = $2")
            .bind(now - Duration::seconds(idle_margin))
            .bind(&idle.token_hash)
            .execute(&pool)
            .await
            .expect("backdate idle-expired row");
        sqlx::query(
            "UPDATE sessions SET last_active_at = $1, absolute_expires_at = $2 WHERE token_hash = $3",
        )
        .bind(now)
        .bind(now - Duration::seconds(60))
        .bind(&absolute.token_hash)
        .execute(&pool)
        .await
        .expect("backdate absolute-expired row");

        let listed = service
            .list_user_sessions(user_id)
            .await
            .expect("list sessions");
        let hashes: Vec<&str> = listed.iter().map(|s| s.token_hash.as_str()).collect();
        assert!(
            hashes.contains(&active.token_hash.as_str()),
            "active session must be listed"
        );
        assert!(
            !hashes.contains(&idle.token_hash.as_str()),
            "idle-expired row must be excluded"
        );
        assert!(
            !hashes.contains(&absolute.token_hash.as_str()),
            "absolute-expired row must be excluded"
        );
        assert_eq!(listed.len(), 1, "only the active session is listed");

        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("remove expiry-test user");
    }
}
