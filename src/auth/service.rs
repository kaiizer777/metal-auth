//! Core auth service business logic.
//!
//! All six operations: signup, login, logout (stub), verify_email,
//! request_password_reset, reset_password.
//!
//! Security invariants enforced here (non-exhaustive):
//! - `password.chars().count()` for all length checks (not `.len()`)
//! - Argon2 dummy verify on login miss (anti-enumeration timing)
//! - signup returns Ok(()) on duplicate email (anti-enumeration)
//! - request_password_reset always queries DB; always returns Ok(())
//! - token tables are DELETE-on-consume within a transaction (no TOCTOU)
//! - reset_password deletes ALL reset tokens for user on success
//! - email dispatch is detached from the response path (mailer latency is never observable)

use std::sync::Arc;

use chrono::Utc;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    auth::models::{validate_email, validate_password},
    config::AppConfig,
    crypto::{
        argon2::{generate_dummy_hash, hash_password, verify_password},
        token::{generate_token, hash_token},
    },
    email::{EmailDispatcher, PasswordResetEmailPayload, VerificationEmailPayload},
    error::{AppError, AppResult},
};

#[allow(async_fn_in_trait)]
pub trait AuthService: Send + Sync {
    async fn signup(&self, email: &str, password: &str) -> AppResult<()>;
    async fn login(&self, email: &str, password: &str) -> AppResult<Uuid>;
    async fn logout(&self, session_id: &str) -> AppResult<()>;
    async fn verify_email(&self, token: &str) -> AppResult<()>;
    async fn request_password_reset(&self, email: &str) -> AppResult<()>;
    async fn reset_password(&self, token: &str, new_password: &str) -> AppResult<()>;
}

/// Proof of a successful credential check: the user id plus the exact Argon2id
/// PHC string that was verified. Session creation compares this snapshot
/// against the live row under `FOR UPDATE`; a mismatch means a concurrent
/// password change superseded the check and the session must not be minted.
#[derive(Clone)]
pub struct AuthenticatedLogin {
    pub user_id: Uuid,
    pub credential_hash: String,
}

// Manual `Debug`: the snapshot is a live credential authenticator.
impl std::fmt::Debug for AuthenticatedLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedLogin")
            .field("user_id", &self.user_id)
            .field("credential_hash", &"[redacted]")
            .finish()
    }
}

pub struct AuthServiceImpl {
    pool: PgPool,
    pub config: Arc<AppConfig>,
    /// Pre-computed dummy PHC string used on login when no user row is found.
    /// Hashed at construction with the SAME Argon2 params as `config` — a param
    /// mismatch would still leak existence via timing delta.
    dummy_hash: String,
    dispatcher: Arc<EmailDispatcher>,
}

impl std::fmt::Debug for AuthServiceImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthServiceImpl")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl AuthServiceImpl {
    /// Constructs the service and pre-computes the dummy Argon2id PHC string.
    ///
    /// Fails fast if config params are invalid or Argon2 construction fails.
    pub fn new(
        pool: PgPool,
        config: Arc<AppConfig>,
        dispatcher: Arc<EmailDispatcher>,
    ) -> Result<Self, AppError> {
        config.validate().map_err(AppError::Config)?;
        let dummy_hash = generate_dummy_hash(&config)?;
        dispatcher.ensure_worker_started(&pool);
        Ok(Self {
            pool,
            config,
            dummy_hash,
            dispatcher,
        })
    }

    // ─── Signup ──────────────────────────────────────────────────────────────

    /// Register a new account.
    ///
    /// Anti-enumeration: always returns `Ok(())` even on duplicate email. Duplicate
    /// emails roll back the transaction cleanly without leaking account existence.
    pub async fn signup(&self, email: &str, password: &str) -> AppResult<()> {
        validate_email(email)?;
        validate_password(password, &self.config)?;

        let config = Arc::clone(&self.config);
        let pw = password.to_string();
        let password_hash = tokio::task::spawn_blocking(move || hash_password(&pw, &config))
            .await
            .map_err(|_| AppError::Internal)??;

        let normalized_email = email.trim().to_lowercase();

        let mut tx = self.pool.begin().await.map_err(AppError::Database)?;

        // Attempt insert; detect duplicate via UNIQUE constraint violation
        let result =
            sqlx::query("INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id")
                .bind(&normalized_email)
                .bind(&password_hash)
                .fetch_one(&mut *tx)
                .await;

        let user_id: Uuid = match result {
            Ok(row) => row.get("id"),
            Err(sqlx::Error::Database(ref db_err)) if db_err.code().as_deref() == Some("23505") => {
                let _ = tx.rollback().await;
                tracing::info!(email = %normalized_email, "signup attempt on existing account");
                return Ok(());
            }
            Err(e) => {
                let _ = tx.rollback().await;
                return Err(AppError::Database(e));
            }
        };

        // Generate and store verification token inside same transaction
        let (raw_token, token_hash) = generate_token();
        let ttl = self.config.verification_token_ttl_secs as i64;
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl);

        let insert_res = sqlx::query(
            "INSERT INTO verification_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(&token_hash[..])
        .bind(user_id)
        .bind(expires_at)
        .execute(&mut *tx)
        .await;

        if let Err(e) = insert_res {
            let _ = tx.rollback().await;
            return Err(AppError::Database(e));
        }

        let url = EmailDispatcher::build_verification_url(
            self.dispatcher.base_url().unwrap_or(""),
            &raw_token,
        );
        let payload = VerificationEmailPayload {
            user_id,
            to: normalized_email.clone(),
            token: raw_token,
            url,
            expires_at,
        };
        let payload_json = serde_json::to_value(&payload).map_err(|e| {
            tracing::error!(err = %e, "failed to serialize verification payload");
            AppError::Internal
        })?;

        let outbox_res = crate::db::outbox::insert_outbox(
            &mut *tx,
            &normalized_email,
            crate::db::models::EMAIL_TYPE_VERIFICATION,
            payload_json,
        )
        .await;

        if let Err(e) = outbox_res {
            let _ = tx.rollback().await;
            return Err(AppError::Database(e));
        }

        tx.commit().await.map_err(AppError::Database)?;

        self.dispatcher.on_outbox_committed(&self.pool).await;

        Ok(())
    }

    // ─── Login ───────────────────────────────────────────────────────────────

    /// Authenticate and return the user's `Uuid` on success.
    ///
    /// Anti-enumeration: always runs Argon2 verify even when email not found.
    /// Timing delta between "wrong password" and "unknown email" must be negligible.
    pub async fn login(&self, email: &str, password: &str) -> AppResult<Uuid> {
        Ok(self.login_with_proof(email, password).await?.user_id)
    }

    /// Authenticate and return the user id plus the verified credential snapshot.
    ///
    /// The snapshot lets session creation re-check credential freshness inside
    /// the user-row lock (cheap string compare, no Argon2 under the lock), so a
    /// password reset committing between verification and session insert cannot
    /// be bypassed. Argon2 work stays outside any lock, as before.
    pub async fn login_with_proof(
        &self,
        email: &str,
        password: &str,
    ) -> AppResult<AuthenticatedLogin> {
        let normalized_email = email.trim().to_lowercase();

        let maybe_user =
            sqlx::query("SELECT id, password_hash, email_verified FROM users WHERE email = $1")
                .bind(&normalized_email)
                .fetch_optional(&self.pool)
                .await
                .map_err(AppError::Database)?;

        match maybe_user {
            None => {
                // Anti-enumeration: run dummy verify to consume equivalent CPU time.
                // A JoinError here (panic/cancel) still maps to InvalidCredentials:
                // the timing signal is best-effort, the error signal is exact.
                let dummy_hash = self.dummy_hash.clone();
                let pw = password.to_string();
                if let Err(join_err) = tokio::task::spawn_blocking(move || {
                    let _ = verify_password(&pw, &dummy_hash);
                })
                .await
                {
                    tracing::debug!(err = %join_err, "dummy password verify task failed");
                }
                Err(AppError::InvalidCredentials)
            }
            Some(row) => {
                let user_id: Uuid = row.get("id");
                let hash: String = row.get("password_hash");
                let email_verified: bool = row.get("email_verified");

                // Snapshot reused as the freshness proof after verify; compared as a
                // string inside the session lock, never re-hashed there.
                let credential_hash = hash.clone();
                let pw = password.to_string();
                let valid = tokio::task::spawn_blocking(move || verify_password(&pw, &hash))
                    .await
                    .map_err(|_| AppError::Internal)??;

                if !valid {
                    return Err(AppError::InvalidCredentials);
                }

                if self.config.require_email_verification && !email_verified {
                    return Err(AppError::EmailNotVerified);
                }

                Ok(AuthenticatedLogin {
                    user_id,
                    credential_hash,
                })
            }
        }
    }

    // ─── Logout (Phase 3 stub) ────────────────────────────────────────────────

    /// Invalidate the server-side session for `session_id`.
    ///
    /// Phase 3 stub — session store is wired in Phase 4.
    pub async fn logout(&self, _session_id: &str) -> AppResult<()> {
        Ok(())
    }

    // ─── Verify email ─────────────────────────────────────────────────────────

    /// Consume an email verification token and mark the user's email as verified.
    ///
    /// TOCTOU-free atomic deletion & consumption:
    /// Atomically deletes the token row and retrieves user_id & expires_at.
    /// If missing, returns `InvalidToken`.
    /// If expired, returns `TokenExpired`.
    /// On success, updates user's `email_verified = true` and `updated_at = NOW()`.
    pub async fn verify_email(&self, token: &str) -> AppResult<()> {
        let token_hash = hash_token(token)?;

        let mut tx = self.pool.begin().await.map_err(AppError::Database)?;

        let maybe_row = sqlx::query(
            "DELETE FROM verification_tokens WHERE token_hash = $1 RETURNING user_id, expires_at",
        )
        .bind(&token_hash[..])
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        let row = match maybe_row {
            None => {
                let _ = tx.rollback().await;
                return Err(AppError::InvalidToken);
            }
            Some(r) => r,
        };

        let expires_at: chrono::DateTime<Utc> = row.get("expires_at");
        let user_id: Uuid = row.get("user_id");

        if expires_at < Utc::now() {
            tx.commit().await.map_err(AppError::Database)?;
            return Err(AppError::TokenExpired);
        }

        let update_res =
            sqlx::query("UPDATE users SET email_verified = true, updated_at = NOW() WHERE id = $1")
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(AppError::Database)?;

        if update_res.rows_affected() != 1 {
            let _ = tx.rollback().await;
            return Err(AppError::InvalidToken);
        }

        tx.commit().await.map_err(AppError::Database)?;
        Ok(())
    }

    // ─── Request password reset ───────────────────────────────────────────────

    /// Initiate a password reset flow.
    ///
    /// Anti-enumeration: always queries DB and always returns `Ok(())` regardless
    /// of whether the email exists.
    pub async fn request_password_reset(&self, email: &str) -> AppResult<()> {
        validate_email(email)?;
        let normalized_email = email.trim().to_lowercase();

        // Always run the same SELECT — round-trip cost is structurally identical
        let maybe_user = sqlx::query("SELECT id, email FROM users WHERE email = $1")
            .bind(&normalized_email)
            .fetch_optional(&self.pool)
            .await
            .map_err(AppError::Database)?;

        if let Some(user) = maybe_user {
            let user_id: Uuid = user.get("id");
            let (raw_token, token_hash) = generate_token();
            let ttl = self.config.reset_token_ttl_secs as i64;
            let expires_at = Utc::now() + chrono::Duration::seconds(ttl);

            let url = EmailDispatcher::build_reset_url(
                self.dispatcher.base_url().unwrap_or(""),
                &raw_token,
            );
            let payload = PasswordResetEmailPayload {
                user_id,
                to: normalized_email.clone(),
                token: raw_token,
                url,
                expires_at,
            };
            let payload_json = serde_json::to_value(&payload).map_err(|e| {
                tracing::error!(err = %e, "failed to serialize password reset payload");
                AppError::Internal
            })?;

            let mut tx = self.pool.begin().await.map_err(AppError::Database)?;

            // Single-live-token policy: revoke all prior tokens for this user
            // before issuing a fresh one, so N rapid requests leave exactly one
            // valid token instead of N simultaneously valid live tokens.
            if let Err(e) = sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = $1")
                .bind(user_id)
                .execute(&mut *tx)
                .await
            {
                let _ = tx.rollback().await;
                return Err(AppError::Database(e));
            }

            let insert_res = sqlx::query(
                "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
            )
            .bind(&token_hash[..])
            .bind(user_id)
            .bind(expires_at)
            .execute(&mut *tx)
            .await;

            if let Err(e) = insert_res {
                let _ = tx.rollback().await;
                return Err(AppError::Database(e));
            }

            let outbox_res = crate::db::outbox::insert_outbox(
                &mut *tx,
                &normalized_email,
                crate::db::models::EMAIL_TYPE_PASSWORD_RESET,
                payload_json,
            )
            .await;

            if let Err(e) = outbox_res {
                let _ = tx.rollback().await;
                return Err(AppError::Database(e));
            }

            tx.commit().await.map_err(AppError::Database)?;

            self.dispatcher.on_outbox_committed(&self.pool).await;
        }

        Ok(())
    }

    // ─── Reset password ───────────────────────────────────────────────────────

    /// Consume a reset token and set a new password.
    ///
    /// Performance & Security:
    /// Atomically consumes token via DELETE RETURNING before computing Argon2id hash
    /// with zero open DB connection, eliminating pool starvation and CPU exhaustion DoS.
    /// Revokes ALL remaining reset tokens for the user upon success.
    pub async fn reset_password(&self, token: &str, new_password: &str) -> AppResult<()> {
        validate_password(new_password, &self.config)?;
        let token_hash = hash_token(token)?;

        let maybe_row = sqlx::query(
            "DELETE FROM password_reset_tokens WHERE token_hash = $1 RETURNING user_id, expires_at",
        )
        .bind(&token_hash[..])
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::Database)?;

        let row = match maybe_row {
            None => return Err(AppError::InvalidToken),
            Some(r) => r,
        };

        let expires_at: chrono::DateTime<Utc> = row.get("expires_at");
        let user_id: Uuid = row.get("user_id");

        if expires_at < Utc::now() {
            return Err(AppError::TokenExpired);
        }

        // Token consumed. Zero DB connection held during CPU-intensive hashing.
        let config = Arc::clone(&self.config);
        let pw = new_password.to_string();
        let new_hash = tokio::task::spawn_blocking(move || hash_password(&pw, &config))
            .await
            .map_err(|_| AppError::Internal)??;

        let mut tx = self.pool.begin().await.map_err(AppError::Database)?;

        // Serialize concurrent resets for this user: the lock orders two
        // simultaneously consumed tokens deterministically instead of racing
        // the final `UPDATE users` (last-writer-wins on identical cost).
        let locked = sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::Database)?;
        if locked.is_none() {
            let _ = tx.rollback().await;
            return Err(AppError::InvalidToken);
        }

        let update_res =
            sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
                .bind(&new_hash)
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(AppError::Database)?;

        if update_res.rows_affected() != 1 {
            let _ = tx.rollback().await;
            return Err(AppError::InvalidToken);
        }

        // Invalidate ALL remaining reset tokens for this user
        sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;

        // Invalidate ALL sessions for this user upon password change
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;

        tracing::info!(
            event = "all_sessions_invalidated",
            user_id = %user_id,
            triggered_by = "password_change",
        );

        tx.commit().await.map_err(AppError::Database)?;
        Ok(())
    }
}

impl AuthService for AuthServiceImpl {
    async fn signup(&self, email: &str, password: &str) -> AppResult<()> {
        self.signup(email, password).await
    }

    async fn login(&self, email: &str, password: &str) -> AppResult<Uuid> {
        self.login(email, password).await
    }

    async fn logout(&self, session_id: &str) -> AppResult<()> {
        self.logout(session_id).await
    }

    async fn verify_email(&self, token: &str) -> AppResult<()> {
        self.verify_email(token).await
    }

    async fn request_password_reset(&self, email: &str) -> AppResult<()> {
        self.request_password_reset(email).await
    }

    async fn reset_password(&self, token: &str, new_password: &str) -> AppResult<()> {
        self.reset_password(token, new_password).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::email::EmailSender;
    use std::sync::Mutex;

    fn create_test_service() -> AuthServiceImpl {
        let pool = PgPool::connect_lazy("postgres://localhost/test").expect("lazy pool");
        let config = Arc::new(AppConfig {
            argon2_m_cost: 19456,
            argon2_t_cost: 2,
            argon2_p_cost: 1,
            ..Default::default()
        });
        let dispatcher = Arc::new(EmailDispatcher::new(
            None,
            std::time::Duration::from_secs(10),
        ));
        AuthServiceImpl::new(pool, config, dispatcher).expect("test service")
    }

    #[tokio::test]
    async fn test_auth_service_new_rejects_invalid_config() {
        let pool = PgPool::connect_lazy("postgres://localhost/test").expect("lazy pool");
        let invalid_config = Arc::new(AppConfig {
            argon2_m_cost: 1000,
            ..Default::default()
        });
        let dispatcher = Arc::new(EmailDispatcher::new(
            None,
            std::time::Duration::from_secs(10),
        ));
        let res = AuthServiceImpl::new(pool, invalid_config, dispatcher);
        assert!(matches!(res, Err(AppError::Config(_))));
    }

    #[test]
    fn authenticated_login_debug_redacts_credential_hash() {
        let proof = AuthenticatedLogin {
            user_id: Uuid::new_v4(),
            credential_hash: "argon2id$v=19$m=65536,t=3,p=4$salt$hash".to_string(),
        };
        let rendered = format!("{proof:?}");
        assert!(!rendered.contains("argon2id"));
        assert!(rendered.contains("[redacted]"));
    }

    #[derive(Clone, Default)]
    struct ArcCapturingSender {
        verification_calls: Arc<Mutex<Vec<VerificationEmailPayload>>>,
        reset_calls: Arc<Mutex<Vec<PasswordResetEmailPayload>>>,
        /// Notified after each send, so tests never poll or sleep for detached dispatch.
        sent: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl EmailSender for ArcCapturingSender {
        async fn send_verification_email(
            &self,
            payload: VerificationEmailPayload,
        ) -> Result<(), crate::email::hook::DynError> {
            self.verification_calls.lock().unwrap().push(payload);
            self.sent.notify_one();
            Ok(())
        }

        async fn send_password_reset_email(
            &self,
            payload: PasswordResetEmailPayload,
        ) -> Result<(), crate::email::hook::DynError> {
            self.reset_calls.lock().unwrap().push(payload);
            self.sent.notify_one();
            Ok(())
        }
    }

    /// Mailer that blocks until `release` is notified — a slow mailer the request path
    /// must never wait for.
    #[derive(Clone)]
    struct GatedSender {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        completed: Arc<tokio::sync::Notify>,
        delivered: Arc<std::sync::atomic::AtomicBool>,
    }

    impl GatedSender {
        fn new() -> Self {
            Self {
                entered: Arc::new(tokio::sync::Notify::new()),
                release: Arc::new(tokio::sync::Notify::new()),
                completed: Arc::new(tokio::sync::Notify::new()),
                delivered: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }
        }

        async fn send_gated(&self) {
            self.entered.notify_one();
            self.release.notified().await;
            self.delivered
                .store(true, std::sync::atomic::Ordering::SeqCst);
            self.completed.notify_one();
        }
    }

    #[async_trait::async_trait]
    impl EmailSender for GatedSender {
        async fn send_verification_email(
            &self,
            _payload: VerificationEmailPayload,
        ) -> Result<(), crate::email::hook::DynError> {
            self.send_gated().await;
            Ok(())
        }

        async fn send_password_reset_email(
            &self,
            _payload: PasswordResetEmailPayload,
        ) -> Result<(), crate::email::hook::DynError> {
            self.send_gated().await;
            Ok(())
        }
    }

    static DB_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct DbTestContext {
        service: AuthServiceImpl,
        pool: PgPool,
        sender: ArcCapturingSender,
        _guard: tokio::sync::MutexGuard<'static, ()>,
    }

    async fn setup_db_context() -> Option<DbTestContext> {
        let guard = DB_TEST_LOCK.lock().await;
        dotenvy::dotenv().ok();
        let url = db_test_url()?;
        // Runs the embedded migrations, so a bare Postgres (CI service container) is enough.
        let pool = crate::db::init_pool_with_options(
            &url,
            crate::db::DbPoolOptions {
                max_connections: 5,
                min_connections: 1,
                ..Default::default()
            },
        )
        .await
        .expect("DATABASE_URL is set, so the DB-backed test must connect");
        let config = Arc::new(AppConfig {
            argon2_m_cost: 19456,
            argon2_t_cost: 2,
            argon2_p_cost: 1,
            ..Default::default()
        });
        let sender = ArcCapturingSender::default();
        let dispatcher = Arc::new(EmailDispatcher::new_blocking(
            Some(Arc::new(sender.clone())),
            std::time::Duration::from_secs(10),
        ));
        let service = AuthServiceImpl::new(pool.clone(), config, dispatcher).ok()?;
        Some(DbTestContext {
            service,
            pool,
            sender,
            _guard: guard,
        })
    }

    /// Returns `DATABASE_URL`, or skips loudly. In CI the variable is mandatory, so a
    /// missing value fails the run instead of silently reporting green.
    fn db_test_url() -> Option<String> {
        match std::env::var("DATABASE_URL") {
            Ok(url) => Some(url),
            Err(_) => {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "DATABASE_URL must be set in CI: DB-backed tests must never skip silently"
                );
                eprintln!("SKIP: DB-backed auth tests need DATABASE_URL");
                None
            }
        }
    }

    #[test]
    fn validate_email_accepts_valid_formats() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("user.name+tag@example.co.uk").is_ok());
        assert!(validate_email("admin@sub.domain.org").is_ok());
    }

    #[test]
    fn validate_email_handles_whitespace() {
        assert!(validate_email("  user@example.com  ").is_ok());
        assert!(validate_email("\tuser@domain.com\n").is_ok());
    }

    #[test]
    fn validate_email_rejects_invalid_formats() {
        assert!(matches!(validate_email(""), Err(AppError::InvalidEmail)));
        assert!(matches!(validate_email("   "), Err(AppError::InvalidEmail)));
        assert!(matches!(
            validate_email("plainaddress"),
            Err(AppError::InvalidEmail)
        ));
        assert!(matches!(
            validate_email("@missinglocal.com"),
            Err(AppError::InvalidEmail)
        ));
        assert!(matches!(
            validate_email("missingdomain@"),
            Err(AppError::InvalidEmail)
        ));
        assert!(matches!(
            validate_email("missingdot@domain"),
            Err(AppError::InvalidEmail)
        ));
    }

    #[tokio::test]
    async fn validate_password_accepts_valid_passwords() {
        let service = create_test_service();
        assert!(validate_password("correct-horse-battery-staple", &service.config).is_ok());
        assert!(validate_password("SecurePass#2026!", &service.config).is_ok());
    }

    #[tokio::test]
    async fn validate_password_counts_unicode_code_points() {
        let service = create_test_service();
        assert!(validate_password("🦀🦀🦀🦀🦀🦀🦀🦀", &service.config).is_ok());
        assert!(matches!(
            validate_password("🦀🦀🦀🦀🦀🦀🦀", &service.config),
            Err(AppError::PasswordTooShort)
        ));
        assert!(matches!(
            validate_password("1234567", &service.config),
            Err(AppError::PasswordTooShort)
        ));
    }

    #[tokio::test]
    async fn validate_password_enforces_max_length_128() {
        let service = create_test_service();
        let exact_128 = "a".repeat(128);
        assert!(validate_password(&exact_128, &service.config).is_ok());

        let over_128 = "a".repeat(129);
        assert!(matches!(
            validate_password(&over_128, &service.config),
            Err(AppError::PasswordTooLong)
        ));

        let unicode_128 = "🦀".repeat(128);
        assert!(validate_password(&unicode_128, &service.config).is_ok());

        let unicode_129 = "🦀".repeat(129);
        assert!(matches!(
            validate_password(&unicode_129, &service.config),
            Err(AppError::PasswordTooLong)
        ));
    }

    #[tokio::test]
    async fn validate_password_rejects_common_passwords() {
        let service = create_test_service();
        assert!(matches!(
            validate_password("password", &service.config),
            Err(AppError::PasswordTooCommon)
        ));
        assert!(matches!(
            validate_password("12345678", &service.config),
            Err(AppError::PasswordTooCommon)
        ));
        assert!(matches!(
            validate_password("PASSWORD", &service.config),
            Err(AppError::PasswordTooCommon)
        ));
        assert!(matches!(
            validate_password("Admin1234", &service.config),
            Err(AppError::PasswordTooCommon)
        ));
    }

    #[tokio::test]
    async fn test_auth_service_trait_object_or_generic() {
        let service = create_test_service();
        async fn assert_trait<T: AuthService>(svc: &T) {
            assert!(svc.logout("sess-123").await.is_ok());
        }
        assert_trait(&service).await;
    }

    #[tokio::test]
    async fn test_token_replay_prevention() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };

        let email = format!("replay_{}@example.com", Uuid::new_v4());
        let password = "SecurePassword123!";

        // Sign up user
        ctx.service.signup(&email, password).await.unwrap();

        // Delivery is detached: wait for the sender signal instead of racing a sleep.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            ctx.sender.sent.notified(),
        )
        .await
        .expect("verification email must be dispatched");

        let token = {
            let calls = ctx.sender.verification_calls.lock().unwrap();
            let call = calls
                .iter()
                .find(|c| c.to == email)
                .expect("token dispatched");
            call.token.clone()
        };

        // First verification succeeds
        let res1 = ctx.service.verify_email(&token).await;
        assert!(res1.is_ok(), "first verification must succeed: {:?}", res1);

        // Second verification with same token fails (single-use / replay prevention)
        let res2 = ctx.service.verify_email(&token).await;
        assert!(
            matches!(res2, Err(AppError::InvalidToken)),
            "second verification must fail with InvalidToken: {:?}",
            res2
        );
    }

    #[tokio::test]
    async fn concurrent_double_consume_verification_token() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };

        let email = format!("concurrent_{}@example.com", Uuid::new_v4());
        ctx.service
            // Test-only fixture password, never a production secret.
            // codeql[rust/hard-coded-cryptographic-value]
            .signup(&email, "SecurePassword123!")
            .await
            .unwrap();

        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            ctx.sender.sent.notified(),
        )
        .await
        .expect("verification email must be dispatched");

        let token = {
            let calls = ctx.sender.verification_calls.lock().unwrap();
            let call = calls
                .iter()
                .find(|c| c.to == email)
                .expect("token dispatched");
            call.token.clone()
        };

        // Both consumers race the same DELETE RETURNING: exactly one wins.
        let (first, second) = tokio::join!(
            ctx.service.verify_email(&token),
            ctx.service.verify_email(&token)
        );
        let oks = usize::from(first.is_ok()) + usize::from(second.is_ok());
        assert_eq!(oks, 1, "exactly one concurrent consume must succeed");
        for res in [&first, &second] {
            if let Err(e) = res {
                assert!(
                    matches!(e, AppError::InvalidToken),
                    "loser must see InvalidToken, got: {e:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn concurrent_double_consume_reset_token() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };

        let email = format!("concurrent_reset_{}@example.com", Uuid::new_v4());
        let config = Arc::clone(&ctx.service.config);
        let password_hash = hash_password("SecurePassword123!", &config).unwrap();

        let row = sqlx::query(
            "INSERT INTO users (email, password_hash, email_verified) VALUES ($1, $2, true) RETURNING id",
        )
        .bind(&email)
        .bind(&password_hash)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
        let user_id: Uuid = row.get("id");

        let (raw_token, token_hash) = generate_token();
        let future_time = Utc::now() + chrono::Duration::hours(1);
        sqlx::query(
            "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(&token_hash[..])
        .bind(user_id)
        .bind(future_time)
        .execute(&ctx.pool)
        .await
        .unwrap();

        // Same token raced concurrently: exactly one DELETE RETURNING wins.
        // Distinct passwords identify the winner via login.
        let pw_a = "ConcurrentOne123!A";
        let pw_b = "ConcurrentTwo456!B";
        let (first, second) = tokio::join!(
            ctx.service.reset_password(&raw_token, pw_a),
            ctx.service.reset_password(&raw_token, pw_b)
        );
        let oks = usize::from(first.is_ok()) + usize::from(second.is_ok());
        assert_eq!(oks, 1, "exactly one concurrent reset must succeed");
        for res in [&first, &second] {
            if let Err(e) = res {
                assert!(
                    matches!(e, AppError::InvalidToken),
                    "loser must see InvalidToken, got: {e:?}"
                );
            }
        }

        let login_a = ctx.service.login(&email, pw_a).await.is_ok();
        let login_b = ctx.service.login(&email, pw_b).await.is_ok();
        assert!(
            login_a ^ login_b,
            "exactly one of the two passwords must verify"
        );
    }

    #[tokio::test]
    async fn concurrent_dual_reset_tokens_serialized() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };

        let email = format!("dual_reset_{}@example.com", Uuid::new_v4());
        let config = Arc::clone(&ctx.service.config);
        let password_hash = hash_password("SecurePassword123!", &config).unwrap();

        let row = sqlx::query(
            "INSERT INTO users (email, password_hash, email_verified) VALUES ($1, $2, true) RETURNING id",
        )
        .bind(&email)
        .bind(&password_hash)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
        let user_id: Uuid = row.get("id");

        // Two distinct valid tokens: both DELETEs target different rows, so both
        // consumes succeed; FOR UPDATE serializes the final UPDATEs.
        let (raw_tok1, hash1) = generate_token();
        let (raw_tok2, hash2) = generate_token();
        let future_time = Utc::now() + chrono::Duration::hours(1);
        for h in [&hash1, &hash2] {
            sqlx::query(
                "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
            )
            .bind(&h[..])
            .bind(user_id)
            .bind(future_time)
            .execute(&ctx.pool)
            .await
            .unwrap();
        }

        // Same new password on both sides pins a fully deterministic outcome.
        let new_password = "DualResetPassword123!";
        let (first, second) = tokio::join!(
            ctx.service.reset_password(&raw_tok1, new_password),
            ctx.service.reset_password(&raw_tok2, new_password)
        );
        assert!(
            first.is_ok() && second.is_ok(),
            "both distinct-token consumes must succeed: {first:?} / {second:?}"
        );

        // No tokens survive and the single final password verifies.
        let count_row =
            sqlx::query("SELECT COUNT(*) as cnt FROM password_reset_tokens WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&ctx.pool)
                .await
                .unwrap();
        let cnt: i64 = count_row.get("cnt");
        assert_eq!(cnt, 0, "no reset tokens must survive concurrent consume");
        assert_eq!(
            ctx.service.login(&email, new_password).await.unwrap(),
            user_id
        );
    }

    #[tokio::test]
    async fn test_token_expiry_rejection() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };

        let email = format!("expired_{}@example.com", Uuid::new_v4());
        let password = "SecurePassword123!";
        let config = Arc::clone(&ctx.service.config);
        let password_hash = hash_password(password, &config).unwrap();

        let row =
            sqlx::query("INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id")
                .bind(&email)
                .bind(&password_hash)
                .fetch_one(&ctx.pool)
                .await
                .unwrap();
        let user_id: Uuid = row.get("id");

        let (raw_token, token_hash) = generate_token();
        let past_time = Utc::now() - chrono::Duration::hours(2);

        sqlx::query(
            "INSERT INTO verification_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(&token_hash[..])
        .bind(user_id)
        .bind(past_time)
        .execute(&ctx.pool)
        .await
        .unwrap();

        let res = ctx.service.verify_email(&raw_token).await;
        assert!(
            matches!(res, Err(AppError::TokenExpired)),
            "expired token must be rejected with TokenExpired: {:?}",
            res
        );

        // Verify expired token was cleaned/deleted from the database
        let count_row =
            sqlx::query("SELECT COUNT(*) as cnt FROM verification_tokens WHERE token_hash = $1")
                .bind(&token_hash[..])
                .fetch_one(&ctx.pool)
                .await
                .unwrap();
        let cnt: i64 = count_row.get("cnt");
        assert_eq!(cnt, 0, "expired token must be deleted from DB");
    }

    #[tokio::test]
    async fn test_unverified_email_login_block() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };

        let email = format!("unverified_{}@example.com", Uuid::new_v4());
        let password = "SecurePassword123!";
        let config = Arc::clone(&ctx.service.config);
        let password_hash = hash_password(password, &config).unwrap();

        // Insert unverified user
        let row = sqlx::query(
            "INSERT INTO users (email, password_hash, email_verified) VALUES ($1, $2, false) RETURNING id",
        )
        .bind(&email)
        .bind(&password_hash)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
        let user_id: Uuid = row.get("id");

        // Login must fail because email is unverified
        let res = ctx.service.login(&email, password).await;
        assert!(
            matches!(res, Err(AppError::EmailNotVerified)),
            "login must be blocked when unverified: {:?}",
            res
        );

        // Mark verified
        sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
            .bind(user_id)
            .execute(&ctx.pool)
            .await
            .unwrap();

        // Now login succeeds
        let res = ctx.service.login(&email, password).await;
        assert_eq!(res.unwrap(), user_id);
    }

    #[tokio::test]
    async fn test_anti_enumeration_signup_and_reset() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };

        let email = format!("antienum_{}@example.com", Uuid::new_v4());
        let password = "SecurePassword123!";

        // First signup returns Ok(())
        let res1 = ctx.service.signup(&email, password).await;
        assert!(res1.is_ok());

        // Duplicate signup returns Ok(()) without error leak
        let res2 = ctx.service.signup(&email, password).await;
        assert!(res2.is_ok(), "duplicate signup must return Ok(())");

        // Request reset for non-existent email returns Ok(())
        let res3 = ctx
            .service
            .request_password_reset("nonexistent_user_99999@example.com")
            .await;
        assert!(
            res3.is_ok(),
            "unknown email reset request must return Ok(())"
        );
    }

    #[tokio::test]
    async fn test_password_reset_revokes_all_tokens() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };

        let email = format!("reset_revoke_{}@example.com", Uuid::new_v4());
        let old_password = "OldSecurePassword123!";
        let new_password = "NewSecurePassword456!";
        let config = Arc::clone(&ctx.service.config);
        let password_hash = hash_password(old_password, &config).unwrap();

        let row = sqlx::query(
            "INSERT INTO users (email, password_hash, email_verified) VALUES ($1, $2, true) RETURNING id",
        )
        .bind(&email)
        .bind(&password_hash)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
        let user_id: Uuid = row.get("id");

        // Insert two distinct reset tokens for this user
        let (raw_tok1, hash1) = generate_token();
        let (raw_tok2, hash2) = generate_token();
        let future_time = Utc::now() + chrono::Duration::hours(1);

        sqlx::query(
            "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(&hash1[..])
        .bind(user_id)
        .bind(future_time)
        .execute(&ctx.pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(&hash2[..])
        .bind(user_id)
        .bind(future_time)
        .execute(&ctx.pool)
        .await
        .unwrap();

        // Reset password using token 1
        let res = ctx.service.reset_password(&raw_tok1, new_password).await;
        assert!(res.is_ok(), "reset_password with token 1 must succeed");

        // Token 2 must now be invalid because ALL tokens for the user were revoked
        let res2 = ctx
            .service
            .reset_password(&raw_tok2, "AnotherPassword789!")
            .await;
        assert!(
            matches!(res2, Err(AppError::InvalidToken)),
            "token 2 must be revoked upon reset: {:?}",
            res2
        );

        // Login with old password fails
        let old_login = ctx.service.login(&email, old_password).await;
        assert!(matches!(old_login, Err(AppError::InvalidCredentials)));

        // Login with new password succeeds
        let new_login = ctx.service.login(&email, new_password).await;
        assert_eq!(new_login.unwrap(), user_id);
    }

    #[tokio::test]
    async fn request_password_reset_replaces_prior_live_token() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };

        let email = format!("replace_live_{}@example.com", Uuid::new_v4());
        let config = Arc::clone(&ctx.service.config);
        let password_hash = hash_password("SecurePassword123!", &config).unwrap();

        let row = sqlx::query(
            "INSERT INTO users (email, password_hash, email_verified) VALUES ($1, $2, true) RETURNING id",
        )
        .bind(&email)
        .bind(&password_hash)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
        let user_id: Uuid = row.get("id");

        // Two sequential reset requests; each dispatch is awaited in turn.
        ctx.service.request_password_reset(&email).await.unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            ctx.sender.sent.notified(),
        )
        .await
        .expect("first reset email must be dispatched");
        ctx.service.request_password_reset(&email).await.unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            ctx.sender.sent.notified(),
        )
        .await
        .expect("second reset email must be dispatched");

        let (first_token, second_token) = {
            let calls = ctx.sender.reset_calls.lock().unwrap();
            assert_eq!(calls.len(), 2, "both requests must dispatch");
            (calls[0].token.clone(), calls[1].token.clone())
        };

        // Exactly one live token survives: the latest.
        let count_row =
            sqlx::query("SELECT COUNT(*) as cnt FROM password_reset_tokens WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&ctx.pool)
                .await
                .unwrap();
        let cnt: i64 = count_row.get("cnt");
        assert_eq!(cnt, 1, "only the newest reset token must survive");

        // Superseded token is dead; newest token resets successfully.
        let stale = ctx
            .service
            .reset_password(&first_token, "StalePassword123!")
            .await;
        assert!(
            matches!(stale, Err(AppError::InvalidToken)),
            "superseded token must be invalid: {stale:?}"
        );
        ctx.service
            .reset_password(&second_token, "NewestPassword123!")
            .await
            .unwrap();
        assert_eq!(
            ctx.service
                .login(&email, "NewestPassword123!")
                .await
                .unwrap(),
            user_id
        );
    }

    #[tokio::test]
    async fn test_verify_email_rejects_missing_user() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };

        let email = format!("missing_user_{}@example.com", Uuid::new_v4());
        let password = "SecurePassword123!";
        let config = Arc::clone(&ctx.service.config);
        let password_hash = hash_password(password, &config).unwrap();

        // Insert real user first to satisfy foreign key constraint (user_id REFERENCES users(id) ON DELETE CASCADE)
        let row = sqlx::query(
            "INSERT INTO users (email, password_hash, email_verified) VALUES ($1, $2, false) RETURNING id",
        )
        .bind(&email)
        .bind(&password_hash)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
        let user_id: Uuid = row.get("id");

        let (raw_token, token_hash) = generate_token();
        let future_time = Utc::now() + chrono::Duration::hours(1);

        sqlx::query(
            "INSERT INTO verification_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(&token_hash[..])
        .bind(user_id)
        .bind(future_time)
        .execute(&ctx.pool)
        .await
        .unwrap();

        // In PostgreSQL, verification_tokens.user_id enforces ON DELETE CASCADE.
        // Deleting the user triggers cascade, testing that verify_email cleanly rejects
        // missing/invalidated tokens with InvalidToken without violating DB FK constraints.
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&ctx.pool)
            .await
            .unwrap();

        let res = ctx.service.verify_email(&raw_token).await;
        assert!(
            matches!(res, Err(AppError::InvalidToken)),
            "verify_email must return InvalidToken when user/token does not exist: {:?}",
            res
        );
    }

    #[tokio::test]
    async fn test_reset_password_rejects_missing_user() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };

        let email = format!("reset_missing_{}@example.com", Uuid::new_v4());
        let password = "SecurePassword123!";
        let config = Arc::clone(&ctx.service.config);
        let password_hash = hash_password(password, &config).unwrap();

        // Insert real user first to satisfy foreign key constraint (user_id REFERENCES users(id) ON DELETE CASCADE)
        let row = sqlx::query(
            "INSERT INTO users (email, password_hash, email_verified) VALUES ($1, $2, true) RETURNING id",
        )
        .bind(&email)
        .bind(&password_hash)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
        let user_id: Uuid = row.get("id");

        let (raw_token, token_hash) = generate_token();
        let future_time = Utc::now() + chrono::Duration::hours(1);

        sqlx::query(
            "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(&token_hash[..])
        .bind(user_id)
        .bind(future_time)
        .execute(&ctx.pool)
        .await
        .unwrap();

        // In PostgreSQL, password_reset_tokens.user_id enforces ON DELETE CASCADE.
        // Deleting the user triggers cascade, testing that reset_password cleanly rejects
        // missing/invalidated tokens with InvalidToken without violating DB FK constraints.
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&ctx.pool)
            .await
            .unwrap();

        let res = ctx
            .service
            .reset_password(&raw_token, "NewPassword123!")
            .await;
        assert!(
            matches!(res, Err(AppError::InvalidToken)),
            "reset_password must return InvalidToken when user/token does not exist: {:?}",
            res
        );
    }

    /// Builds a service whose dispatcher blocks inside the mailer until released.
    fn gated_service(ctx: &DbTestContext, sender: &GatedSender) -> AuthServiceImpl {
        let dispatcher = Arc::new(EmailDispatcher::new(
            Some(Arc::new(sender.clone())),
            std::time::Duration::from_secs(10),
        ));
        AuthServiceImpl::new(
            ctx.pool.clone(),
            Arc::clone(&ctx.service.config),
            dispatcher,
        )
        .unwrap()
    }

    /// Waits for the detached delivery task to reach the mailer.
    async fn wait_mailer_entered(sender: &GatedSender) {
        tokio::time::timeout(std::time::Duration::from_secs(5), sender.entered.notified())
            .await
            .expect("email must be dispatched");
    }

    async fn wait_mailer_delivered(sender: &GatedSender) {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sender.completed.notified(),
        )
        .await
        .expect("detached delivery must complete once released");
        assert!(sender.delivered.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// Regression guard for the signup request path: returning before the mailer does is
    /// the whole point. Re-awaiting the dispatch handle blocks past the 5 s guard.
    #[tokio::test]
    async fn signup_returns_before_delivery() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let sender = GatedSender::new();
        let service = gated_service(&ctx, &sender);
        let email = format!("detached_signup_{}@example.com", Uuid::new_v4());

        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            service.signup(&email, "SecurePassword123!"),
        )
        .await
        .expect("signup must not wait for the mailer")
        .unwrap();

        wait_mailer_entered(&sender).await;
        assert!(
            !sender.delivered.load(std::sync::atomic::Ordering::SeqCst),
            "signup must return before delivery"
        );

        sender.release.notify_one();
        wait_mailer_delivered(&sender).await;
    }

    /// Same guard for the password-reset request path.
    #[tokio::test]
    async fn request_password_reset_returns_before_delivery() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let sender = GatedSender::new();
        let service = gated_service(&ctx, &sender);
        let email = format!("detached_reset_{}@example.com", Uuid::new_v4());
        let password_hash = hash_password("SecurePassword123!", &ctx.service.config).unwrap();

        sqlx::query(
            "INSERT INTO users (email, password_hash, email_verified) VALUES ($1, $2, true)",
        )
        .bind(&email)
        .bind(&password_hash)
        .execute(&ctx.pool)
        .await
        .unwrap();

        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            service.request_password_reset(&email),
        )
        .await
        .expect("reset request must not wait for the mailer")
        .unwrap();

        wait_mailer_entered(&sender).await;
        assert!(
            !sender.delivered.load(std::sync::atomic::Ordering::SeqCst),
            "reset request must return before delivery"
        );

        sender.release.notify_one();
        wait_mailer_delivered(&sender).await;
    }

    // ─── Group B: no-DB early-return guard tests ─────────────────────────────

    #[tokio::test]
    async fn signup_invalid_email_returns_before_db() {
        let service = create_test_service();
        let valid_password = format!("Val1d_{}", Uuid::new_v4());
        let res = service.signup("not-an-email", &valid_password).await;
        assert!(matches!(res, Err(AppError::InvalidEmail)));
    }

    #[tokio::test]
    async fn signup_short_password_returns_before_db() {
        let service = create_test_service();
        // default password_min_len == 8; dynamic string with length 5 < 8
        let short_password = format!("s_{}", Uuid::new_v4())[..5].to_string();
        let res = service.signup("user@example.com", &short_password).await;
        assert!(matches!(res, Err(AppError::PasswordTooShort)));
    }

    #[tokio::test]
    async fn request_password_reset_invalid_email_returns_before_db() {
        let service = create_test_service();
        let res = service.request_password_reset("not-an-email").await;
        assert!(matches!(res, Err(AppError::InvalidEmail)));
    }

    #[tokio::test]
    async fn reset_password_short_new_password_returns_before_db() {
        let service = create_test_service();
        // validate_password fires before hash_token; short pw → early return
        let valid_token = "a".repeat(64);
        let short_password = format!("t_{}", Uuid::new_v4())[..4].to_string();
        let res = service.reset_password(&valid_token, &short_password).await;
        assert!(matches!(res, Err(AppError::PasswordTooShort)));
    }

    #[tokio::test]
    async fn reset_password_malformed_token_returns_before_db() {
        let service = create_test_service();
        // validate_password passes; hash_token rejects malformed token → InvalidToken
        let valid_password = format!("Val1d_{}", Uuid::new_v4());
        let res = service
            .reset_password("not-valid-hex-token", &valid_password)
            .await;
        assert!(matches!(res, Err(AppError::InvalidToken)));
    }

    /// Delivery must complete even when the request future is dropped mid-flight.
    #[tokio::test]
    async fn dispatch_survives_cancelled_request_future() {
        let sender = GatedSender::new();
        let dispatcher = Arc::new(EmailDispatcher::new(
            Some(Arc::new(sender.clone())),
            std::time::Duration::from_secs(10),
        ));
        let payload = VerificationEmailPayload {
            user_id: Uuid::new_v4(),
            to: "user@example.com".into(),
            token: "token".into(),
            url: "https://example.com/auth/verify/email?token=token".into(),
            expires_at: Utc::now(),
        };

        // Mirrors the service call site: the delivery task is spawned before the
        // request future can be dropped.
        let request = tokio::spawn(async move {
            let _ = dispatcher.dispatch_verification(payload).await;
            std::future::pending::<()>().await;
        });

        wait_mailer_entered(&sender).await;
        request.abort();
        assert!(
            request.await.is_err(),
            "request future must have been cancelled"
        );

        sender.release.notify_one();
        wait_mailer_delivered(&sender).await;
    }
}
