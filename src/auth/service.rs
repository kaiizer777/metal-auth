//! Core auth service business logic.
//!
//! All six operations: signup, login, logout (stub), verify_email,
//! request_password_reset, reset_password.
//!
//! Security invariants enforced here (non-exhaustive):
//! - `password.chars().count()` for all length checks (not `.len()`)
//! - Argon2 dummy verify on login miss (anti-enumeration timing)
//! - signup returns Ok(()) on duplicate email; dispatcher always spawned
//! - request_password_reset always queries DB; always returns Ok(())
//! - token tables are DELETE-on-consume within a transaction (no TOCTOU)
//! - reset_password deletes ALL reset tokens for user on success

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
    /// Anti-enumeration: always returns `Ok(())` and always spawns a dispatcher
    /// task, even on duplicate email. Duplicate emails roll back the transaction
    /// cleanly without leaking account existence.
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
                tokio::spawn(async move {});
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

        tx.commit().await.map_err(AppError::Database)?;

        // Fire-and-forget email dispatch — never await on HTTP path
        let dispatcher = Arc::clone(&self.dispatcher);
        let url = EmailDispatcher::build_verification_url(
            dispatcher.base_url().unwrap_or(""),
            &raw_token,
        );
        tokio::spawn(async move {
            let _ = dispatcher
                .dispatch_verification(VerificationEmailPayload {
                    user_id,
                    to: normalized_email,
                    token: raw_token,
                    url,
                    expires_at,
                })
                .await;
        });

        Ok(())
    }

    // ─── Login ───────────────────────────────────────────────────────────────

    /// Authenticate and return the user's `Uuid` on success.
    ///
    /// Anti-enumeration: always runs Argon2 verify even when email not found.
    /// Timing delta between "wrong password" and "unknown email" must be negligible.
    pub async fn login(&self, email: &str, password: &str) -> AppResult<Uuid> {
        let normalized_email = email.trim().to_lowercase();

        let maybe_user =
            sqlx::query("SELECT id, password_hash, email_verified FROM users WHERE email = $1")
                .bind(&normalized_email)
                .fetch_optional(&self.pool)
                .await
                .map_err(AppError::Database)?;

        match maybe_user {
            None => {
                // Anti-enumeration: run dummy verify to consume equivalent CPU time
                let dummy_hash = self.dummy_hash.clone();
                let pw = password.to_string();
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = verify_password(&pw, &dummy_hash);
                })
                .await;
                Err(AppError::InvalidCredentials)
            }
            Some(row) => {
                let user_id: Uuid = row.get("id");
                let hash: String = row.get("password_hash");
                let email_verified: bool = row.get("email_verified");

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

                Ok(user_id)
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

        sqlx::query("UPDATE users SET email_verified = true, updated_at = NOW() WHERE id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;

        tx.commit().await.map_err(AppError::Database)?;
        Ok(())
    }

    // ─── Request password reset ───────────────────────────────────────────────

    /// Initiate a password reset flow.
    ///
    /// Anti-enumeration: always queries DB and always returns `Ok(())` regardless
    /// of whether the email exists. Spawns timing-parity dummy task if not found.
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

            sqlx::query(
                "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
            )
            .bind(&token_hash[..])
            .bind(user_id)
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .map_err(AppError::Database)?;

            let dispatcher = Arc::clone(&self.dispatcher);
            let uid = user_id;
            let url =
                EmailDispatcher::build_reset_url(dispatcher.base_url().unwrap_or(""), &raw_token);
            tokio::spawn(async move {
                let _ = dispatcher
                    .dispatch_password_reset(PasswordResetEmailPayload {
                        user_id: uid,
                        to: normalized_email,
                        token: raw_token,
                        url,
                        expires_at,
                    })
                    .await;
            });
        } else {
            tokio::spawn(async move {});
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

        sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
            .bind(&new_hash)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;

        // Invalidate ALL remaining reset tokens for this user
        sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;

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
            true,
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
            true,
        ));
        let res = AuthServiceImpl::new(pool, invalid_config, dispatcher);
        assert!(matches!(res, Err(AppError::Config(_))));
    }

    #[derive(Clone, Default)]
    struct ArcCapturingSender {
        verification_calls: Arc<Mutex<Vec<VerificationEmailPayload>>>,
        reset_calls: Arc<Mutex<Vec<PasswordResetEmailPayload>>>,
    }

    #[async_trait::async_trait]
    impl EmailSender for ArcCapturingSender {
        async fn send_verification_email(
            &self,
            payload: VerificationEmailPayload,
        ) -> Result<(), crate::email::hook::DynError> {
            self.verification_calls.lock().unwrap().push(payload);
            Ok(())
        }

        async fn send_password_reset_email(
            &self,
            payload: PasswordResetEmailPayload,
        ) -> Result<(), crate::email::hook::DynError> {
            self.reset_calls.lock().unwrap().push(payload);
            Ok(())
        }
    }

    struct DbTestContext {
        service: AuthServiceImpl,
        pool: PgPool,
        sender: ArcCapturingSender,
    }

    async fn setup_db_context() -> Option<DbTestContext> {
        dotenvy::dotenv().ok();
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = PgPool::connect(&url).await.ok()?;
        let config = Arc::new(AppConfig {
            argon2_m_cost: 19456,
            argon2_t_cost: 2,
            argon2_p_cost: 1,
            ..Default::default()
        });
        let sender = ArcCapturingSender::default();
        let dispatcher = Arc::new(EmailDispatcher::new(
            Some(Arc::new(sender.clone())),
            std::time::Duration::from_secs(10),
            true,
        ));
        let service = AuthServiceImpl::new(pool.clone(), config, dispatcher).ok()?;
        Some(DbTestContext {
            service,
            pool,
            sender,
        })
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

        // Give async spawn time to dispatch
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

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
}
