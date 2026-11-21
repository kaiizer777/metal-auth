//! TOTP lifecycle service.
//!
//! Owns secret enrollment, code verification, the replay barrier, backup-code
//! consumption, and challenge-token storage. Rate limiting is a handler concern: the
//! two `totp:*` dimensions are checked on ingress by the HTTP layer, never here.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    config::{AppConfig, Config},
    crypto::{generate_token, hash_token, verify_password},
    error::AppError,
    totp::{
        backup,
        crypto::{
            DecryptedSecret, build_otpauth_uri, compute_code_replay_hash, decode_totp_secret,
            decrypt_secret, encrypt_secret, generate_totp_secret, verify_totp_code,
        },
    },
};

/// All TOTP lifecycle operations for metal-auth.
///
/// `Debug` is safe to derive because the AES key never lands in this struct; it is
/// resolved per operation from [`Config`], whose `Debug` redacts it.
#[derive(Clone, Debug)]
pub struct TotpService {
    pool: PgPool,
    config: Arc<Config>,
    auth_config: Arc<AppConfig>,
}

impl TotpService {
    /// Build the service. Never fails on a missing TOTP key: a deployment without 2FA
    /// still boots, and key-dependent operations fail fast when they ask for the key.
    #[must_use]
    pub fn new(pool: PgPool, config: Arc<Config>, auth_config: Arc<AppConfig>) -> Self {
        Self {
            pool,
            config,
            auth_config,
        }
    }

    /// Step 1 of enrollment: rotate the secret, store it encrypted, and issue backup codes.
    ///
    /// Never activates 2FA; [`Self::confirm_enrollment`] does that. Requires a verified
    /// email and refuses to overwrite an already enabled secret.
    pub async fn enroll_totp(&self, user_id: Uuid) -> Result<EnrollTotpResponse, AppError> {
        let user = sqlx::query("SELECT email, email_verified FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(AppError::Database)?
            .ok_or(AppError::Unauthenticated)?;
        let email: String = user.try_get("email").map_err(AppError::Database)?;
        let email_verified: bool = user.try_get("email_verified").map_err(AppError::Database)?;
        if !email_verified {
            return Err(AppError::TotpEmailNotVerified);
        }

        if self.is_totp_enabled(user_id).await? {
            return Err(AppError::TotpAlreadyEnabled);
        }

        let secret_base32 = generate_totp_secret();
        let key = self.encryption_key()?;
        let mut raw_secret = decode_totp_secret(&secret_base32)?;
        let encrypted_secret = encrypt_secret(&key, &raw_secret);
        crate::crypto::zeroize_bytes(&mut raw_secret);
        let encrypted_secret = encrypted_secret?;

        // 10 Argon2id hashes cost roughly a second of CPU; keep it off the executor.
        let auth_config = Arc::clone(&self.auth_config);
        let (backup_codes, backup_hashes) =
            tokio::task::spawn_blocking(move || backup::generate_backup_codes(&auth_config))
                .await
                .map_err(|err| {
                    tracing::error!(error = %err, "backup code generation task failed");
                    AppError::Internal
                })??;
        let backup_hashes = serde_json::Value::Array(
            backup_hashes
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        );

        sqlx::query(
            "INSERT INTO totp_secrets (user_id, encrypted_secret, backup_codes, enabled) \
             VALUES ($1, $2, $3, FALSE) \
             ON CONFLICT (user_id) DO UPDATE SET \
                encrypted_secret = EXCLUDED.encrypted_secret, \
                backup_codes = EXCLUDED.backup_codes, \
                enabled = FALSE, \
                updated_at = CURRENT_TIMESTAMP",
        )
        .bind(user_id)
        .bind(&encrypted_secret[..])
        .bind(&backup_hashes)
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        let otpauth_uri = build_otpauth_uri(&secret_base32, &email, &self.config.totp.issuer);
        Ok(EnrollTotpResponse {
            secret_base32,
            otpauth_uri,
            backup_codes,
        })
    }

    /// Step 2 of enrollment: verify the first code against the pending secret and enable.
    pub async fn confirm_enrollment(
        &self,
        user_id: Uuid,
        code: &str,
        _ip: &str,
    ) -> Result<(), AppError> {
        let record =
            sqlx::query("SELECT encrypted_secret, enabled FROM totp_secrets WHERE user_id = $1")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(AppError::Database)?
                .ok_or(AppError::TotpNotEnrolled)?;
        if record
            .try_get::<bool, _>("enabled")
            .map_err(AppError::Database)?
        {
            return Err(AppError::TotpAlreadyEnabled);
        }

        let encrypted_secret: Vec<u8> = record
            .try_get("encrypted_secret")
            .map_err(AppError::Database)?;
        let secret = self.decrypt_totp_secret(&encrypted_secret)?;
        verify_totp_code(secret.as_ref(), code)?;

        sqlx::query(
            "UPDATE totp_secrets SET enabled = TRUE, updated_at = CURRENT_TIMESTAMP \
             WHERE user_id = $1",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;
        Ok(())
    }

    /// Verify a live TOTP code and burn it in the same step window.
    ///
    /// The replay insert is a single autocommitted statement: the `uq_totp_used_codes`
    /// constraint arbitrates concurrent submissions, so there is no read-then-write gap.
    pub async fn verify_totp(&self, user_id: Uuid, code: &str, _ip: &str) -> Result<(), AppError> {
        let record =
            sqlx::query("SELECT encrypted_secret, enabled FROM totp_secrets WHERE user_id = $1")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(AppError::Database)?
                .ok_or(AppError::TotpNotEnrolled)?;
        if !record
            .try_get::<bool, _>("enabled")
            .map_err(AppError::Database)?
        {
            return Err(AppError::TotpNotEnrolled);
        }

        let encrypted_secret: Vec<u8> = record
            .try_get("encrypted_secret")
            .map_err(AppError::Database)?;
        let secret = self.decrypt_totp_secret(&encrypted_secret)?;
        let step = verify_totp_code(secret.as_ref(), code)?;
        let replay_hash = compute_code_replay_hash(code);

        sqlx::query("INSERT INTO totp_used_codes (user_id, code_hash) VALUES ($1, $2)")
            .bind(user_id)
            .bind(&replay_hash[..])
            .execute(&self.pool)
            .await
            .map_err(classify_used_code_error)?;

        tracing::debug!(
            event = "totp_code_verified",
            user_id = %user_id,
            step,
            outcome = "accepted",
        );
        Ok(())
    }

    /// Verify a single-use backup code and remove exactly that hash.
    ///
    /// The removal is one atomic statement keyed on the matched hash, so two concurrent
    /// submissions cannot both consume a code or delete a neighbouring one.
    pub async fn verify_backup_code(
        &self,
        user_id: Uuid,
        code: &str,
        _ip: &str,
    ) -> Result<(), AppError> {
        let record =
            sqlx::query("SELECT backup_codes, enabled FROM totp_secrets WHERE user_id = $1")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(AppError::Database)?
                .ok_or(AppError::TotpNotEnrolled)?;
        if !record
            .try_get::<bool, _>("enabled")
            .map_err(AppError::Database)?
        {
            return Err(AppError::TotpNotEnrolled);
        }

        let stored_codes: serde_json::Value =
            record.try_get("backup_codes").map_err(AppError::Database)?;
        let hashes: Vec<String> = serde_json::from_value(stored_codes).map_err(|err| {
            tracing::error!(error = %err, user_id = %user_id, "backup code store is corrupt");
            AppError::Internal
        })?;

        // Both inputs must cross into the blocking closure; every Argon2id verify is CPU-bound.
        let candidate = code.to_string();
        let hashes_for_verification = hashes.clone();
        let index = tokio::task::spawn_blocking(move || {
            backup::verify_backup_code(&candidate, &hashes_for_verification)
        })
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "backup code verification task failed");
            AppError::Internal
        })??;

        let matched_hash = hashes.get(index).ok_or(AppError::Internal)?;
        let removed = sqlx::query(
            "UPDATE totp_secrets SET backup_codes = backup_codes - $2, \
             updated_at = CURRENT_TIMESTAMP \
             WHERE user_id = $1 AND backup_codes ? $2",
        )
        .bind(user_id)
        .bind(matched_hash.as_str())
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;
        if removed.rows_affected() == 0 {
            // Another request consumed this exact hash after our read.
            return Err(AppError::TotpBackupCodeInvalid);
        }

        tracing::debug!(
            event = "totp_backup_code_verified",
            user_id = %user_id,
            outcome = "accepted",
        );
        Ok(())
    }

    /// Disable 2FA after a fresh password or live TOTP proof.
    ///
    /// Deletes the secret (and its backup codes) plus the user's replay log. Any live
    /// challenge token therefore has no secret left to satisfy.
    pub async fn disable_totp(
        &self,
        user_id: Uuid,
        fresh_auth: FreshAuthProof,
        ip: &str,
    ) -> Result<(), AppError> {
        match fresh_auth {
            FreshAuthProof::Password(password) => {
                let password_hash: String = sqlx::query_scalar::<_, String>(
                    "SELECT password_hash FROM users WHERE id = $1",
                )
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(AppError::Database)?
                .ok_or(AppError::InvalidCredentials)?;

                // Argon2id is CPU-bound; never run it on the executor thread.
                let verified =
                    tokio::task::spawn_blocking(move || verify_password(&password, &password_hash))
                        .await
                        .map_err(|err| {
                            tracing::error!(error = %err, "password verification task failed");
                            AppError::Internal
                        })??;
                if !verified {
                    return Err(AppError::InvalidCredentials);
                }
            }
            FreshAuthProof::TotpCode(code) => self.verify_totp(user_id, &code, ip).await?,
        }

        let mut transaction = self.pool.begin().await.map_err(AppError::Database)?;
        let secret_delete = sqlx::query("DELETE FROM totp_secrets WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await;
        if let Err(error) = secret_delete {
            let _ = transaction.rollback().await;
            return Err(AppError::Database(error));
        }
        let replay_delete = sqlx::query("DELETE FROM totp_used_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await;
        if let Err(error) = replay_delete {
            let _ = transaction.rollback().await;
            return Err(AppError::Database(error));
        }
        transaction.commit().await.map_err(AppError::Database)?;

        tracing::debug!(
            event = "totp_secret_deleted",
            user_id = %user_id,
            outcome = "disabled",
        );
        Ok(())
    }

    /// Mint a half-authenticated challenge token; only its SHA-256 hash is stored.
    pub async fn generate_two_factor_token(&self, user_id: Uuid) -> Result<String, AppError> {
        let (raw_token, token_hash) = generate_token();
        let ttl_seconds = i64::try_from(self.config.totp.challenge_token_ttl_secs)
            .map_err(|_| AppError::Internal)?;
        let expires_at = Utc::now() + Duration::seconds(ttl_seconds);

        sqlx::query(
            "INSERT INTO two_factor_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(user_id)
        .bind(&token_hash[..])
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(raw_token)
    }

    /// Resolve a challenge token to its user without consuming it, so a mistyped code
    /// can be retried until the token expires or the handler's limits trip.
    pub async fn validate_two_factor_token(&self, token: &str) -> Result<Uuid, AppError> {
        let token_hash = hash_token(token).map_err(|_| AppError::TwoFactorTokenInvalid)?;
        let record =
            sqlx::query("SELECT user_id, expires_at FROM two_factor_tokens WHERE token_hash = $1")
                .bind(&token_hash[..])
                .fetch_optional(&self.pool)
                .await
                .map_err(AppError::Database)?
                .ok_or(AppError::TwoFactorTokenInvalid)?;

        let expires_at: DateTime<Utc> = record.try_get("expires_at").map_err(AppError::Database)?;
        if expires_at < Utc::now() {
            return Err(AppError::TwoFactorTokenExpired);
        }
        record.try_get("user_id").map_err(AppError::Database)
    }

    /// Atomically delete a challenge token after successful verification.
    ///
    /// Reports whether a row was actually deleted, so a double consume cannot mint a
    /// second session from the same token.
    pub async fn consume_two_factor_token(&self, token: &str) -> Result<(), AppError> {
        let token_hash = hash_token(token).map_err(|_| AppError::TwoFactorTokenInvalid)?;
        let deleted = sqlx::query("DELETE FROM two_factor_tokens WHERE token_hash = $1")
            .bind(&token_hash[..])
            .execute(&self.pool)
            .await
            .map_err(AppError::Database)?;
        if deleted.rows_affected() == 0 {
            return Err(AppError::TwoFactorTokenInvalid);
        }
        Ok(())
    }

    /// Return true when `totp_secrets.enabled` is set for `user_id`.
    pub async fn is_totp_enabled(&self, user_id: Uuid) -> Result<bool, AppError> {
        sqlx::query_scalar::<_, bool>("SELECT enabled FROM totp_secrets WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map(Option::unwrap_or_default)
            .map_err(AppError::Database)
    }

    fn encryption_key(&self) -> Result<[u8; crate::totp::crypto::AES_KEY_BYTES], AppError> {
        self.config
            .totp
            .encryption_key_bytes()
            .map_err(AppError::Config)
    }

    /// Decrypt a stored secret, treating decryption failure as an invalid code.
    ///
    /// A failed decrypt can only mean corruption or a rotated key; surfacing it as
    /// `TotpCodeInvalid` keeps the client response indistinguishable from a wrong code.
    fn decrypt_totp_secret(&self, encrypted_secret: &[u8]) -> Result<DecryptedSecret, AppError> {
        let key = self.encryption_key()?;
        decrypt_secret(&key, encrypted_secret).map_err(|err| {
            tracing::error!(error = %err, "stored totp secret could not be decrypted");
            AppError::TotpCodeInvalid
        })
    }
}

/// Map the replay insert failure: only `uq_totp_used_codes` means a replay.
///
/// Any other `23505` (or any other error) stays a database error instead of being
/// blanket-labelled as a reused code.
fn classify_used_code_error(error: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(database_error) = &error
        && database_error.code().as_deref() == Some("23505")
        && database_error.constraint() == Some("uq_totp_used_codes")
    {
        return AppError::TotpCodeReplayed;
    }
    AppError::Database(error)
}

/// Input to [`TotpService::disable_totp`]: one fresh-auth proof, never a boolean toggle.
#[derive(Clone)]
pub enum FreshAuthProof {
    Password(String),
    TotpCode(String),
}

// Manual `Debug`: both variants carry a live credential.
impl std::fmt::Debug for FreshAuthProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => f.write_str("FreshAuthProof::Password([redacted])"),
            Self::TotpCode(_) => f.write_str("FreshAuthProof::TotpCode([redacted])"),
        }
    }
}

/// Response from [`TotpService::enroll_totp`].
#[derive(Clone, serde::Serialize)]
pub struct EnrollTotpResponse {
    /// Base32-encoded TOTP secret for manual entry.
    pub secret_base32: String,
    /// `otpauth://` URI for client-side QR rendering.
    pub otpauth_uri: String,
    /// Raw backup codes, returned exactly once and never stored.
    pub backup_codes: Vec<String>,
}

// Manual `Debug`: secret, URI, and recovery codes must not reach logs.
impl std::fmt::Debug for EnrollTotpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollTotpResponse")
            .field("secret_base32", &"[redacted]")
            .field("otpauth_uri", &"[redacted]")
            .field(
                "backup_codes",
                &format_args!("[{} redacted]", self.backup_codes.len()),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::TotpConfig,
        crypto::hash_password,
        db::DbPoolOptions,
        totp::crypto::{current_totp_counter, generate_totp},
    };

    static TOTP_DB_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Test-only AES key. Never a production key.
    const TEST_KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    struct DbTestContext {
        service: TotpService,
        pool: PgPool,
        auth_config: Arc<AppConfig>,
        _guard: tokio::sync::MutexGuard<'static, ()>,
    }

    async fn setup_db_context() -> Option<DbTestContext> {
        let guard = TOTP_DB_TEST_LOCK.lock().await;
        dotenvy::dotenv().ok();
        let url = db_test_url()?;
        let pool = crate::db::init_pool_with_options(
            &url,
            DbPoolOptions {
                max_connections: 5,
                min_connections: 1,
                ..Default::default()
            },
        )
        .await
        .expect("DATABASE_URL is set, so the DB-backed test must connect");
        let auth_config = Arc::new(AppConfig {
            argon2_m_cost: 8,
            argon2_t_cost: 1,
            argon2_p_cost: 1,
            ..Default::default()
        });
        let config = Arc::new(Config {
            database_url: url,
            totp: TotpConfig {
                encryption_key: Some(TEST_KEY_HEX.into()),
                ..TotpConfig::default()
            },
            ..Config::default()
        });
        let service = TotpService::new(pool.clone(), config, Arc::clone(&auth_config));
        Some(DbTestContext {
            service,
            pool,
            auth_config,
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
                eprintln!("SKIP: DB-backed totp service tests need DATABASE_URL");
                None
            }
        }
    }

    // Unique generated password per call: no hard-coded credential material in tests.
    fn fixture_password() -> String {
        format!("Fixture-{}-Aa1!", Uuid::new_v4().simple())
    }

    async fn create_user(ctx: &DbTestContext, verified: bool, password: &str) -> Uuid {
        let email = format!("totp-{}@example.com", Uuid::new_v4().simple());
        let password_hash = hash_password(password, &ctx.auth_config).expect("hash");
        sqlx::query_scalar(
            "INSERT INTO users (email, password_hash, email_verified) \
             VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(email)
        .bind(password_hash)
        .bind(verified)
        .fetch_one(&ctx.pool)
        .await
        .expect("insert user")
    }

    fn current_code(secret_base32: &str) -> String {
        let raw = decode_totp_secret(secret_base32).expect("decode");
        format!(
            "{:06}",
            generate_totp(&raw, current_totp_counter()).expect("generate")
        )
    }

    async fn enroll_and_confirm(ctx: &DbTestContext, user_id: Uuid) -> EnrollTotpResponse {
        let response = ctx.service.enroll_totp(user_id).await.expect("enroll");
        let code = current_code(&response.secret_base32);
        ctx.service
            .confirm_enrollment(user_id, &code, "127.0.0.1")
            .await
            .expect("confirm");
        response
    }

    async fn count_rows(pool: &PgPool, table: &str, user_id: Uuid) -> i64 {
        let sql = match table {
            "totp_secrets" => "SELECT COUNT(*) FROM totp_secrets WHERE user_id = $1",
            "totp_used_codes" => "SELECT COUNT(*) FROM totp_used_codes WHERE user_id = $1",
            "two_factor_tokens" => "SELECT COUNT(*) FROM two_factor_tokens WHERE user_id = $1",
            other => panic!("unexpected table {other}"),
        };
        sqlx::query_scalar(sql)
            .bind(user_id)
            .fetch_one(pool)
            .await
            .expect("count")
    }

    #[tokio::test]
    async fn enroll_requires_verified_email() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, false, &fixture_password()).await;

        assert!(matches!(
            ctx.service.enroll_totp(user_id).await,
            Err(AppError::TotpEmailNotVerified)
        ));
        assert_eq!(count_rows(&ctx.pool, "totp_secrets", user_id).await, 0);
    }

    #[tokio::test]
    async fn enroll_issues_secret_uri_and_ten_backup_codes() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;

        let response = ctx.service.enroll_totp(user_id).await.expect("enroll");
        assert_eq!(response.secret_base32.len(), 32);
        assert!(response.otpauth_uri.starts_with("otpauth://totp/"));
        assert_eq!(response.backup_codes.len(), 10);
        let unique: std::collections::HashSet<_> = response.backup_codes.iter().collect();
        assert_eq!(unique.len(), 10);

        let enabled: bool =
            sqlx::query_scalar("SELECT enabled FROM totp_secrets WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&ctx.pool)
                .await
                .expect("pending secret");
        assert!(!enabled);
    }

    #[tokio::test]
    async fn enroll_rejects_enabled_user_but_rerolls_pending_secret() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;

        let first = ctx
            .service
            .enroll_totp(user_id)
            .await
            .expect("first enroll");
        let second = ctx.service.enroll_totp(user_id).await.expect("reroll");
        assert_ne!(first.secret_base32, second.secret_base32);

        enroll_and_confirm(&ctx, user_id).await;
        assert!(matches!(
            ctx.service.enroll_totp(user_id).await,
            Err(AppError::TotpAlreadyEnabled)
        ));
    }

    #[tokio::test]
    async fn confirm_requires_pending_secret_and_valid_code() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;

        assert!(matches!(
            ctx.service
                .confirm_enrollment(user_id, "000000", "127.0.0.1")
                .await,
            Err(AppError::TotpNotEnrolled)
        ));

        let response = ctx.service.enroll_totp(user_id).await.expect("enroll");
        assert!(matches!(
            ctx.service
                .confirm_enrollment(user_id, "000000", "127.0.0.1")
                .await,
            Err(AppError::TotpCodeInvalid)
        ));

        let code = current_code(&response.secret_base32);
        ctx.service
            .confirm_enrollment(user_id, &code, "127.0.0.1")
            .await
            .expect("confirm");
        assert!(ctx.service.is_totp_enabled(user_id).await.expect("state"));
        assert!(matches!(
            ctx.service
                .confirm_enrollment(user_id, &code, "127.0.0.1")
                .await,
            Err(AppError::TotpAlreadyEnabled)
        ));
    }

    #[tokio::test]
    async fn verify_requires_an_enabled_secret() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        assert!(matches!(
            ctx.service.verify_totp(user_id, "000000", "ip").await,
            Err(AppError::TotpNotEnrolled)
        ));

        let response = ctx.service.enroll_totp(user_id).await.expect("enroll");
        let code = current_code(&response.secret_base32);
        assert!(matches!(
            ctx.service.verify_totp(user_id, &code, "ip").await,
            Err(AppError::TotpNotEnrolled)
        ));
    }

    #[tokio::test]
    async fn verify_totp_accepts_once_then_reports_replay() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let code = current_code(&response.secret_base32);

        ctx.service
            .verify_totp(user_id, &code, "ip")
            .await
            .expect("first use");
        assert!(matches!(
            ctx.service.verify_totp(user_id, &code, "ip").await,
            Err(AppError::TotpCodeReplayed)
        ));
        assert_eq!(count_rows(&ctx.pool, "totp_used_codes", user_id).await, 1);
    }

    #[tokio::test]
    async fn verify_rejects_out_of_window_and_malformed_codes() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let raw = decode_totp_secret(&response.secret_base32).expect("decode");
        let distant_code = format!(
            "{:06}",
            generate_totp(&raw, current_totp_counter() + 3).expect("generate")
        );

        assert!(matches!(
            ctx.service.verify_totp(user_id, &distant_code, "ip").await,
            Err(AppError::TotpCodeInvalid)
        ));
        assert!(matches!(
            ctx.service.verify_totp(user_id, "12345", "ip").await,
            Err(AppError::TotpCodeInvalid)
        ));
        assert_eq!(count_rows(&ctx.pool, "totp_used_codes", user_id).await, 0);
    }

    #[tokio::test]
    async fn verify_rejects_corrupt_ciphertext_without_leaking_the_cause() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let code = current_code(&response.secret_base32);

        sqlx::query("UPDATE totp_secrets SET encrypted_secret = $2 WHERE user_id = $1")
            .bind(user_id)
            .bind(vec![0u8; 40])
            .execute(&ctx.pool)
            .await
            .expect("corrupt");

        assert!(matches!(
            ctx.service.verify_totp(user_id, &code, "ip").await,
            Err(AppError::TotpCodeInvalid)
        ));
    }

    #[tokio::test]
    async fn concurrent_verification_admits_exactly_one_request() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let code = current_code(&response.secret_base32);

        let mut handles = Vec::new();
        for _ in 0..5 {
            let service = ctx.service.clone();
            let attempt = code.clone();
            handles.push(tokio::spawn(async move {
                service.verify_totp(user_id, &attempt, "ip").await
            }));
        }
        let mut accepted = 0;
        let mut replayed = 0;
        for handle in handles {
            match handle.await.expect("join") {
                Ok(()) => accepted += 1,
                Err(AppError::TotpCodeReplayed) => replayed += 1,
                Err(other) => panic!("unexpected result: {other:?}"),
            }
        }
        assert_eq!(accepted, 1);
        assert_eq!(replayed, 4);
        assert_eq!(count_rows(&ctx.pool, "totp_used_codes", user_id).await, 1);
    }

    #[tokio::test]
    async fn backup_codes_are_single_use() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let code = response.backup_codes[0].clone();

        ctx.service
            .verify_backup_code(user_id, &code, "ip")
            .await
            .expect("first use");
        assert!(matches!(
            ctx.service.verify_backup_code(user_id, &code, "ip").await,
            Err(AppError::TotpBackupCodeInvalid)
        ));
        assert!(matches!(
            ctx.service
                .verify_backup_code(user_id, "AAAAAAAAAA", "ip")
                .await,
            Err(AppError::TotpBackupCodeInvalid)
        ));

        let stored: serde_json::Value =
            sqlx::query_scalar("SELECT backup_codes FROM totp_secrets WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&ctx.pool)
                .await
                .expect("backup codes");
        assert_eq!(stored.as_array().expect("array").len(), 9);
    }

    #[tokio::test]
    async fn disable_requires_a_valid_password_and_wipes_state() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let password = fixture_password();
        let user_id = create_user(&ctx, true, &password).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let code = current_code(&response.secret_base32);
        ctx.service
            .verify_totp(user_id, &code, "ip")
            .await
            .expect("seed replay row");

        assert!(matches!(
            ctx.service
                .disable_totp(
                    user_id,
                    FreshAuthProof::Password("wrong-password".into()),
                    "ip",
                )
                .await,
            Err(AppError::InvalidCredentials)
        ));
        assert!(ctx.service.is_totp_enabled(user_id).await.expect("state"));

        ctx.service
            .disable_totp(user_id, FreshAuthProof::Password(password), "ip")
            .await
            .expect("disable");
        assert!(!ctx.service.is_totp_enabled(user_id).await.expect("state"));
        assert_eq!(count_rows(&ctx.pool, "totp_secrets", user_id).await, 0);
        assert_eq!(count_rows(&ctx.pool, "totp_used_codes", user_id).await, 0);
    }

    #[tokio::test]
    async fn disable_accepts_a_live_totp_code() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let code = current_code(&response.secret_base32);

        ctx.service
            .disable_totp(user_id, FreshAuthProof::TotpCode(code), "ip")
            .await
            .expect("disable");
        assert!(!ctx.service.is_totp_enabled(user_id).await.expect("state"));
        assert_eq!(count_rows(&ctx.pool, "totp_used_codes", user_id).await, 0);
    }

    #[tokio::test]
    async fn challenge_token_survives_validation_and_is_single_use() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;

        let token = ctx
            .service
            .generate_two_factor_token(user_id)
            .await
            .expect("generate");
        assert_eq!(
            ctx.service
                .validate_two_factor_token(&token)
                .await
                .expect("validate"),
            user_id
        );
        assert_eq!(
            ctx.service
                .validate_two_factor_token(&token)
                .await
                .expect("retry"),
            user_id
        );

        ctx.service
            .consume_two_factor_token(&token)
            .await
            .expect("consume");
        assert!(matches!(
            ctx.service.consume_two_factor_token(&token).await,
            Err(AppError::TwoFactorTokenInvalid)
        ));
        assert!(matches!(
            ctx.service.validate_two_factor_token(&token).await,
            Err(AppError::TwoFactorTokenInvalid)
        ));
        assert!(matches!(
            ctx.service.validate_two_factor_token("not-a-token").await,
            Err(AppError::TwoFactorTokenInvalid)
        ));
    }

    #[tokio::test]
    async fn expired_challenge_token_is_rejected_and_left_for_cleanup() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let token = ctx
            .service
            .generate_two_factor_token(user_id)
            .await
            .expect("generate");

        sqlx::query(
            "UPDATE two_factor_tokens SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second' \
             WHERE user_id = $1",
        )
        .bind(user_id)
        .execute(&ctx.pool)
        .await
        .expect("expire");

        assert!(matches!(
            ctx.service.validate_two_factor_token(&token).await,
            Err(AppError::TwoFactorTokenExpired)
        ));
        assert_eq!(count_rows(&ctx.pool, "two_factor_tokens", user_id).await, 1);
    }

    #[tokio::test]
    async fn is_totp_enabled_defaults_to_false() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        assert!(!ctx.service.is_totp_enabled(user_id).await.expect("state"));
    }
}
