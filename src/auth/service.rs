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
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    config::AppConfig,
    crypto::{
        argon2::{generate_dummy_hash, hash_password, verify_password},
        blocklist::is_common_password,
        token::{generate_token, hash_token},
    },
    email::{EmailDispatcher, PasswordResetEmailPayload, VerificationEmailPayload},
    error::{AppError, AppResult},
};

pub struct AuthServiceImpl {
    pool: PgPool,
    config: Arc<AppConfig>,
    /// Pre-computed dummy PHC string used on login when no user row is found.
    /// Hashed at construction with the SAME Argon2 params as `config` — a param
    /// mismatch would still leak existence via timing delta.
    dummy_hash: String,
    dispatcher: Arc<EmailDispatcher>,
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
        let dummy_hash = generate_dummy_hash(&config)?;
        Ok(Self {
            pool,
            config,
            dummy_hash,
            dispatcher,
        })
    }

    // ─── Password validation helpers ─────────────────────────────────────────

    fn validate_password(&self, password: &str) -> AppResult<()> {
        let count = password.chars().count(); // Unicode code points, not bytes
        if count < self.config.password_min_len {
            return Err(AppError::PasswordTooShort);
        }
        if count > self.config.password_max_len {
            return Err(AppError::PasswordTooLong);
        }
        if is_common_password(password) {
            return Err(AppError::PasswordTooCommon);
        }
        Ok(())
    }

    fn validate_email(email: &str) -> AppResult<()> {
        let trimmed = email.trim();
        if trimmed.is_empty() {
            return Err(AppError::InvalidEmail);
        }
        // Basic format: must contain '@' with non-empty local and domain parts
        let at = trimmed.rfind('@').ok_or(AppError::InvalidEmail)?;
        if at == 0 || at + 1 >= trimmed.len() {
            return Err(AppError::InvalidEmail);
        }
        let domain = &trimmed[at + 1..];
        if domain.is_empty() || !domain.contains('.') {
            return Err(AppError::InvalidEmail);
        }
        Ok(())
    }

    // ─── Signup ──────────────────────────────────────────────────────────────

    /// Register a new account.
    ///
    /// Anti-enumeration: always returns `Ok(())` and always spawns a dispatcher
    /// task, even on duplicate email. Handler always sends 200. Duplicate emails
    /// are logged internally only.
    pub async fn signup(&self, email: &str, password: &str) -> AppResult<()> {
        Self::validate_email(email)?;
        self.validate_password(password)?;

        let password_hash = hash_password(password, &self.config)?;
        let email_lc = email.to_lowercase();

        // Attempt insert; detect duplicate via UNIQUE constraint violation
        let result = sqlx::query!(
            "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id",
            email_lc,
            password_hash,
        )
        .fetch_one(&self.pool)
        .await;

        let (user_id, is_duplicate) = match result {
            Ok(row) => (row.id, false),
            Err(sqlx::Error::Database(ref db_err)) if db_err.code().as_deref() == Some("23505") => {
                // Unique constraint violation — duplicate email
                // Anti-enum: log internally, never expose to caller
                tracing::info!(email = %email_lc, "signup attempt on existing account");
                // We still need a user_id-shaped value for the dispatcher spawn —
                // create a placeholder so the spawn cost is structurally identical
                (Uuid::nil(), true)
            }
            Err(e) => return Err(AppError::Database(e)),
        };

        if !is_duplicate {
            // Generate and store verification token
            let (raw_token, token_hash) = generate_token();
            let ttl = self.config.verification_token_ttl_secs as i64;
            let expires_at = Utc::now() + chrono::Duration::seconds(ttl);

            sqlx::query!(
                "INSERT INTO verification_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
                &token_hash,
                user_id,
                expires_at,
            )
            .execute(&self.pool)
            .await
            .map_err(AppError::Database)?;

            // Fire-and-forget email dispatch — never await on HTTP path
            let dispatcher = Arc::clone(&self.dispatcher);
            let email_clone = email_lc.clone();
            tokio::spawn(async move {
                dispatcher.dispatch_verification(VerificationEmailPayload {
                    to_email: email_clone,
                    token: raw_token,
                    user_id,
                });
            });
        } else {
            // Timing parity: spawn a no-op task with equivalent cost
            let dispatcher = Arc::clone(&self.dispatcher);
            tokio::spawn(async move {
                dispatcher.dispatch_verification(VerificationEmailPayload {
                    to_email: String::new(),
                    token: String::new(),
                    user_id: Uuid::nil(),
                });
            });
        }

        Ok(())
    }

    // ─── Login ───────────────────────────────────────────────────────────────

    /// Authenticate and return the user's `Uuid` on success.
    ///
    /// Anti-enumeration: always runs Argon2 verify even when email not found.
    /// Timing delta between "wrong password" and "unknown email" must be negligible.
    pub async fn login(&self, email: &str, password: &str) -> AppResult<Uuid> {
        let email_lc = email.to_lowercase();

        let maybe_user = sqlx::query!(
            "SELECT id, password_hash, email_verified FROM users WHERE email = $1",
            email_lc,
        )
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
            Some(user) => {
                let hash = user.password_hash.clone();
                let pw = password.to_string();
                let valid = tokio::task::spawn_blocking(move || verify_password(&pw, &hash))
                    .await
                    .map_err(|_| AppError::Internal)??;

                if !valid {
                    return Err(AppError::InvalidCredentials);
                }

                if self.config.require_email_verification && !user.email_verified {
                    return Err(AppError::EmailNotVerified);
                }

                Ok(user.id)
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
    /// Token lifecycle (all within a single transaction, prevents replay):
    /// 1. Hex-decode the 64-char token → SHA-256 → lookup by `token_hash`
    /// 2. If no row: `InvalidToken`
    /// 3. If `expires_at < NOW()`: DELETE row + `TokenExpired`
    /// 4. If valid: DELETE row + UPDATE `users.email_verified = true`
    pub async fn verify_email(&self, token: &str) -> AppResult<()> {
        let token_hash = hash_token(token)?;

        let mut tx = self.pool.begin().await.map_err(AppError::Database)?;

        let maybe_row = sqlx::query!(
            "SELECT user_id, expires_at FROM verification_tokens WHERE token_hash = $1",
            &token_hash,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        let row = match maybe_row {
            None => {
                tx.rollback().await.map_err(AppError::Database)?;
                return Err(AppError::InvalidToken);
            }
            Some(r) => r,
        };

        // DELETE first (single-use: prevent replay even if we return early)
        sqlx::query!(
            "DELETE FROM verification_tokens WHERE token_hash = $1",
            &token_hash,
        )
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        if row.expires_at < Utc::now() {
            tx.commit().await.map_err(AppError::Database)?;
            return Err(AppError::TokenExpired);
        }

        sqlx::query!(
            "UPDATE users SET email_verified = true WHERE id = $1",
            row.user_id,
        )
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
    /// of whether the email exists. The SELECT round-trip cost is structurally
    /// identical on the found and not-found paths.
    pub async fn request_password_reset(&self, email: &str) -> AppResult<()> {
        Self::validate_email(email)?;
        let email_lc = email.to_lowercase();

        // Always run the same SELECT — round-trip cost is structurally identical
        let maybe_user = sqlx::query!("SELECT id, email FROM users WHERE email = $1", email_lc,)
            .fetch_optional(&self.pool)
            .await
            .map_err(AppError::Database)?;

        if let Some(user) = maybe_user {
            let (raw_token, token_hash) = generate_token();
            let ttl = self.config.reset_token_ttl_secs as i64;
            let expires_at = Utc::now() + chrono::Duration::seconds(ttl);

            sqlx::query!(
                "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
                &token_hash,
                user.id,
                expires_at,
            )
            .execute(&self.pool)
            .await
            .map_err(AppError::Database)?;

            let dispatcher = Arc::clone(&self.dispatcher);
            let email_clone = user.email.clone();
            let uid = user.id;
            tokio::spawn(async move {
                dispatcher.dispatch_password_reset(PasswordResetEmailPayload {
                    to_email: email_clone,
                    token: raw_token,
                    user_id: uid,
                });
            });
        }
        // On not-found path: no DB write, no email, but function still returns Ok(()).
        // The SELECT above already equalized the round-trip cost.

        Ok(())
    }

    // ─── Reset password ───────────────────────────────────────────────────────

    /// Consume a reset token and set a new password.
    ///
    /// Validation order per spec:
    /// 1. Body parse (caller's responsibility — handled in handler layer)
    /// 2. Password length >= min Unicode code points
    /// 3. Password length <= max
    /// 4. Common password blocklist
    /// 5. Token lookup (hex-decode → SHA-256 → SELECT+DELETE in txn)
    ///
    /// On success: UPDATE password, DELETE ALL reset tokens for this user.
    pub async fn reset_password(&self, token: &str, new_password: &str) -> AppResult<()> {
        self.validate_password(new_password)?;

        let token_hash = hash_token(token)?;

        let mut tx = self.pool.begin().await.map_err(AppError::Database)?;

        let maybe_row = sqlx::query!(
            "SELECT user_id, expires_at FROM password_reset_tokens WHERE token_hash = $1",
            &token_hash,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        let row = match maybe_row {
            None => {
                tx.rollback().await.map_err(AppError::Database)?;
                return Err(AppError::InvalidToken);
            }
            Some(r) => r,
        };

        // DELETE the specific token first (single-use)
        sqlx::query!(
            "DELETE FROM password_reset_tokens WHERE token_hash = $1",
            &token_hash,
        )
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        if row.expires_at < Utc::now() {
            tx.commit().await.map_err(AppError::Database)?;
            return Err(AppError::TokenExpired);
        }

        let new_hash = hash_password(new_password, &self.config)?;
        let user_id = row.user_id;

        sqlx::query!(
            "UPDATE users SET password_hash = $1 WHERE id = $2",
            new_hash,
            user_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        // Invalidate ALL remaining reset tokens for this user (spec §1.5)
        sqlx::query!(
            "DELETE FROM password_reset_tokens WHERE user_id = $1",
            user_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        tx.commit().await.map_err(AppError::Database)?;
        Ok(())
    }
}
