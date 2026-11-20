//! TOTP lifecycle service.
//!
//! Owns secret enrollment, code verification, the replay barrier, backup-code
//! consumption, and challenge-token storage. Rate limiting is a handler concern: the
//! two `totp:*` dimensions are checked on ingress by the HTTP layer, never here.

use std::sync::Arc;

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    config::{AppConfig, Config},
    crypto::verify_password,
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
        let replay_hash = compute_code_replay_hash(code, step);

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
