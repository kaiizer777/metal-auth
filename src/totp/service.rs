//! TOTP lifecycle service.
//!
//! Owns secret enrollment, code verification, the replay barrier, backup-code
//! consumption, and challenge-token storage. Rate limiting is a handler concern: the
//! two `totp:*` dimensions are checked on ingress by the HTTP layer, never here.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use sqlx::{PgConnection, PgPool, Row};
use uuid::Uuid;

use crate::{
    config::{AppConfig, Config},
    crypto::{generate_token, hash_token, verify_password},
    error::AppError,
    totp::{
        backup,
        crypto::{
            DecryptedSecret, build_otpauth_uri, code_window_end, compute_code_replay_hash,
            decode_totp_secret, decrypt_secret, encrypt_secret, generate_totp_secret,
            totp_counter_at, verify_totp_code_at,
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
    /// Build the service. `config` must already have passed [`Config::validate`].
    ///
    /// Never fails on a missing TOTP key: a deployment without 2FA
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
        let encrypted = encrypt_secret(&key, &raw_secret);
        crate::crypto::zeroize_bytes(&mut raw_secret);
        let encrypted_secret = encrypted?;

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

        self.store_pending_secret(user_id, &encrypted_secret, &backup_hashes)
            .await?;

        let otpauth_uri = build_otpauth_uri(&secret_base32, &email, &self.config.totp.issuer);
        Ok(EnrollTotpResponse {
            secret_base32,
            otpauth_uri,
            backup_codes,
        })
    }

    /// Store or rotate a pending secret.
    ///
    /// The conflict update is fenced on `enabled = FALSE`: a confirmation that commits
    /// while the backup codes are hashing must win, otherwise enrollment downgrades a
    /// live factor. A zero-row result is that race, reported as `TotpAlreadyEnabled`.
    async fn store_pending_secret(
        &self,
        user_id: Uuid,
        encrypted_secret: &[u8],
        backup_hashes: &serde_json::Value,
    ) -> Result<(), AppError> {
        let stored = sqlx::query(
            "INSERT INTO totp_secrets (user_id, encrypted_secret, backup_codes, enabled) \
             VALUES ($1, $2, $3, FALSE) \
             ON CONFLICT (user_id) DO UPDATE SET \
                encrypted_secret = EXCLUDED.encrypted_secret, \
                backup_codes = EXCLUDED.backup_codes, \
                enabled = FALSE, \
                updated_at = CURRENT_TIMESTAMP \
             WHERE totp_secrets.enabled = FALSE",
        )
        .bind(user_id)
        .bind(encrypted_secret)
        .bind(backup_hashes)
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;
        if stored.rows_affected() == 0 {
            return Err(AppError::TotpAlreadyEnabled);
        }
        Ok(())
    }

    /// Step 2 of enrollment: verify the first code against the pending secret and enable.
    ///
    /// The counter derives from one database timestamp read on this transaction, the same
    /// anchor [`Self::verify_totp`] uses. Taking it from the application clock instead
    /// would let inter-host skew admit a code here and reject the same code at every later
    /// login.
    ///
    /// `ip` is part of the Part 3 handler contract; rate limiting is handler-owned.
    pub async fn confirm_enrollment(
        &self,
        user_id: Uuid,
        code: &str,
        _ip: &str,
    ) -> Result<(), AppError> {
        let mut transaction = self.pool.begin().await.map_err(AppError::Database)?;
        let reference = transaction_now(&mut transaction).await?;
        self.confirm_enrollment_at(&mut transaction, user_id, code, reference)
            .await?;
        transaction.commit().await.map_err(AppError::Database)
    }

    /// Confirmation body against one explicit clock reference.
    ///
    /// Every production call reaches this body through [`Self::confirm_enrollment`] with
    /// `transaction_now`, and no other code-check entry point exists on this path, so an
    /// application-clock window cannot be reintroduced beside it. The seam lets a test pin
    /// the body against a reference the application clock does not agree with; it does not
    /// observe which source the wrapper chose, which is covered by that single entry point.
    async fn confirm_enrollment_at(
        &self,
        connection: &mut PgConnection,
        user_id: Uuid,
        code: &str,
        reference: DateTime<Utc>,
    ) -> Result<(), AppError> {
        let record =
            sqlx::query("SELECT encrypted_secret, enabled FROM totp_secrets WHERE user_id = $1")
                .bind(user_id)
                .fetch_optional(&mut *connection)
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
        verify_totp_code_at(secret.as_ref(), code, totp_counter_at(reference))?;

        self.activate_pending_secret(connection, user_id, &encrypted_secret)
            .await
    }

    /// Enable the exact pending secret that was just verified.
    ///
    /// Keyed on the secret fingerprint, not the user: a concurrent enrollment replaces the
    /// secret in place (`ON CONFLICT DO UPDATE` keeps the row), so a user-scoped update
    /// would enable a secret whose code was never presented. `enabled = FALSE` makes the
    /// first confirmation the only winner.
    async fn activate_pending_secret(
        &self,
        connection: &mut PgConnection,
        user_id: Uuid,
        encrypted_secret: &[u8],
    ) -> Result<(), AppError> {
        let activated = sqlx::query(
            "UPDATE totp_secrets SET enabled = TRUE, updated_at = CURRENT_TIMESTAMP \
             WHERE user_id = $1 AND encrypted_secret = $2 AND enabled = FALSE",
        )
        .bind(user_id)
        .bind(encrypted_secret)
        .execute(&mut *connection)
        .await
        .map_err(AppError::Database)?;
        if activated.rows_affected() == 0 {
            // Either the verified enrollment was replaced or it was confirmed first. Read
            // on the same connection: a pool read here could block on this transaction's
            // own row lock.
            let enabled: bool =
                sqlx::query_scalar("SELECT enabled FROM totp_secrets WHERE user_id = $1")
                    .bind(user_id)
                    .fetch_optional(&mut *connection)
                    .await
                    .map_err(AppError::Database)?
                    .unwrap_or_default();
            return Err(if enabled {
                AppError::TotpAlreadyEnabled
            } else {
                AppError::TotpNotEnrolled
            });
        }
        Ok(())
    }

    /// Verify a live TOTP code and burn it in the same step window.
    ///
    /// Two arbiters, one statement pair: the guarded insert refuses any write that lands
    /// after the matched step's acceptance band, so a pruned tombstone cannot be
    /// re-created, and `uq_totp_used_codes` rejects reuse while a tombstone survives.
    /// Neither reads before writing, so there is no read-then-write gap.
    ///
    /// `ip` is part of the Part 3 handler contract; rate limiting is handler-owned.
    pub async fn verify_totp(&self, user_id: Uuid, code: &str, _ip: &str) -> Result<(), AppError> {
        let mut transaction = self.pool.begin().await.map_err(AppError::Database)?;
        self.verify_and_record_totp(&mut transaction, user_id, code)
            .await?;
        transaction.commit().await.map_err(AppError::Database)
    }

    /// Verify `code` and record the use on the caller's transaction.
    ///
    /// The counter and the prune cutoff both derive from one database timestamp read on
    /// this transaction. Two independent references — a wall-clock pre-read for the
    /// counter, the transaction time for the cutoff — let a stalled request prune the row
    /// that blocks its own replay, because the cutoff outruns the counter.
    pub(crate) async fn verify_and_record_totp(
        &self,
        connection: &mut PgConnection,
        user_id: Uuid,
        code: &str,
    ) -> Result<(), AppError> {
        let reference = transaction_now(connection).await?;
        self.verify_totp_within(connection, user_id, code, reference)
            .await
    }

    /// Verify `code` and record the use against one explicit clock reference.
    ///
    /// The counter and the prune cutoff are both derived here, from the same value: two
    /// references let a stalled request prune the row that blocks its own replay.
    async fn verify_totp_within(
        &self,
        connection: &mut PgConnection,
        user_id: Uuid,
        code: &str,
        reference: DateTime<Utc>,
    ) -> Result<(), AppError> {
        self.record_totp_use(
            connection,
            user_id,
            code,
            totp_counter_at(reference),
            reference,
        )
        .await
        .map(|_step| ())
    }

    /// Verify at an explicit step counter, pruning against `reference`.
    ///
    /// Tests use the explicit counter to prove a code cannot be replayed at `T-1`/`T+1`.
    #[cfg(test)]
    async fn verify_totp_at(
        &self,
        user_id: Uuid,
        code: &str,
        counter: u64,
    ) -> Result<(), AppError> {
        let mut transaction = self.pool.begin().await.map_err(AppError::Database)?;
        let reference = transaction_now(&mut transaction).await?;
        self.record_totp_use(&mut transaction, user_id, code, counter, reference)
            .await?;
        transaction.commit().await.map_err(AppError::Database)
    }

    /// Verify and record with a supplied database reference.
    ///
    /// Production always reads the reference inside its own transaction; this seam lets a
    /// test simulate a stalled request without waiting out the acceptance window.
    #[cfg(test)]
    async fn verify_totp_at_reference(
        &self,
        user_id: Uuid,
        code: &str,
        reference: DateTime<Utc>,
    ) -> Result<(), AppError> {
        let mut transaction = self.pool.begin().await.map_err(AppError::Database)?;
        self.verify_totp_within(&mut transaction, user_id, code, reference)
            .await?;
        transaction.commit().await.map_err(AppError::Database)
    }

    /// Load and decrypt the caller's enabled secret, or report why no code can be checked.
    async fn enabled_secret(
        &self,
        connection: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<DecryptedSecret, AppError> {
        let record =
            sqlx::query("SELECT encrypted_secret, enabled FROM totp_secrets WHERE user_id = $1")
                .bind(user_id)
                .fetch_optional(&mut *connection)
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
        self.decrypt_totp_secret(&encrypted_secret)
    }

    async fn record_totp_use(
        &self,
        connection: &mut PgConnection,
        user_id: Uuid,
        code: &str,
        counter: u64,
        reference: DateTime<Utc>,
    ) -> Result<u64, AppError> {
        let secret = self.enabled_secret(connection, user_id).await?;
        let step = verify_totp_code_at(secret.as_ref(), code, counter)?;
        let replay_hash = compute_code_replay_hash(code);

        // Prune and insert share one unit so no stale row can split them. A 23505 rolls
        // the prune back with the insert; the failed insert is still the replay arbiter.
        let pruned = sqlx::query(
            "DELETE FROM totp_used_codes WHERE user_id = $1 \
             AND used_at < $2 - make_interval(secs => $3)",
        )
        .bind(user_id)
        .bind(reference)
        .bind(self.config.totp.used_code_prune_age_secs as f64)
        .execute(&mut *connection)
        .await;
        if let Err(error) = pruned {
            return Err(AppError::Database(error));
        }

        // The insert is the replay arbiter only while the tombstone survives. Re-check the
        // matched step's window at write time `clock_timestamp()`, because `reference` was
        // frozen before any stall: a verifier stalled past its own window must not
        // re-create a tombstone a concurrent transaction legitimately pruned.
        //
        // `used_at` is bound rather than defaulted: the column default is
        // `CURRENT_TIMESTAMP`, frozen at `BEGIN`, so a stalled transaction would stamp the
        // row earlier than the reference its own cutoff uses and a later transaction would
        // prune it sooner.
        let window_end = code_window_end(step).ok_or(AppError::TotpCodeInvalid)?;
        let inserted = sqlx::query(
            "INSERT INTO totp_used_codes (user_id, code_hash, used_at) \
             SELECT $1, $2, $3 WHERE clock_timestamp() < $4",
        )
        .bind(user_id)
        .bind(&replay_hash[..])
        .bind(reference)
        .bind(window_end)
        .execute(&mut *connection)
        .await;
        let inserted = match inserted {
            Ok(result) => result,
            Err(error) => return Err(classify_used_code_error(error)),
        };
        // Zero rows: the write landed after the code's last accepted step, so it expired.
        if inserted.rows_affected() == 0 {
            return Err(AppError::TotpCodeInvalid);
        }

        tracing::debug!(
            event = "totp_code_verified",
            user_id = %user_id,
            step,
            outcome = "accepted",
        );
        Ok(step)
    }

    /// Verify a single-use backup code and remove exactly that hash.
    ///
    /// Matching runs off the executor and outside any transaction; the removal is one
    /// atomic statement keyed on the matched hash, so two concurrent submissions cannot
    /// both consume a code or delete a neighbouring one.
    ///
    /// `ip` is part of the Part 3 handler contract; rate limiting is handler-owned.
    pub async fn verify_backup_code(
        &self,
        user_id: Uuid,
        code: &str,
        _ip: &str,
    ) -> Result<(), AppError> {
        let matched_hash = self.match_backup_code(user_id, code).await?;
        let mut transaction = self.pool.begin().await.map_err(AppError::Database)?;
        self.consume_backup_code(&mut transaction, user_id, &matched_hash)
            .await?;
        transaction.commit().await.map_err(AppError::Database)
    }

    /// Match `code` against the stored hashes without spending it.
    ///
    /// The Argon2id work is CPU-bound and owns no connection: it runs on the blocking pool
    /// before the caller opens its transaction.
    pub(crate) async fn match_backup_code(
        &self,
        user_id: Uuid,
        code: &str,
    ) -> Result<String, AppError> {
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

        // Owned inputs cross the blocking boundary; `swap_remove` takes the matched PHC
        // string at the index already found by the traversal, with no clone or re-walk.
        let candidate = code.to_string();
        tokio::task::spawn_blocking(move || {
            let mut hashes = hashes;
            let index = backup::verify_backup_code(&candidate, &hashes)?;
            if index >= hashes.len() {
                return Err(AppError::Internal);
            }
            Ok(hashes.swap_remove(index))
        })
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "backup code verification task failed");
            AppError::Internal
        })?
    }

    /// Remove exactly the matched hash on the caller's transaction.
    ///
    /// Zero rows means another request consumed this hash after our read, which must fail
    /// the whole unit of work rather than mint a session from a spent code.
    pub(crate) async fn consume_backup_code(
        &self,
        connection: &mut PgConnection,
        user_id: Uuid,
        matched_hash: &str,
    ) -> Result<(), AppError> {
        let removed = sqlx::query(
            "UPDATE totp_secrets SET backup_codes = backup_codes - $2, \
             updated_at = CURRENT_TIMESTAMP \
             WHERE user_id = $1 AND backup_codes ? $2",
        )
        .bind(user_id)
        .bind(matched_hash)
        .execute(&mut *connection)
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
    /// Rejections keep the status of the check that rejected the proof: a wrong password
    /// is `InvalidCredentials` (401), while a wrong TOTP code is passed through from the
    /// code check as `TotpCodeInvalid` (400), matching every other code check. A missing
    /// or ambiguous body proof is rejected as `ValidationError` (400) before this call.
    /// Deletes the secret (and its backup codes) plus the user's replay log. Any live
    /// challenge token therefore has no secret left to satisfy.
    ///
    /// The code branch is one transaction that takes `FOR UPDATE` on the user's factor row
    /// before reading the proof. That lock is what serializes two disables presenting the
    /// same code: the second waits here and, once the first commits its delete, finds no
    /// row and fails `TotpNotEnrolled` rather than reporting a second success. It covers
    /// only that row and only for the life of this transaction — an enrollment committing a
    /// new factor afterwards is not observed (an absent row takes no lock), and the password
    /// branch takes no lock at all, because two password proofs present no code and
    /// converge on the same end state.
    ///
    /// The replay row is then written against the same in-transaction clock the verification
    /// path uses, and while it exists `uq_totp_used_codes` rejects a code already spent at
    /// login. Rolling back a failed disable rolls the row back with it, leaving the
    /// still-valid code retryable instead of reporting it as replayed. The delete that
    /// follows still wipes the whole replay log — that is what disabling means — but the
    /// wipe runs after the proof is accepted, so it is no longer the arbiter of whether the
    /// proof was spent.
    pub async fn disable_totp(
        &self,
        user_id: Uuid,
        fresh_auth: FreshAuthProof,
        _ip: &str,
    ) -> Result<(), AppError> {
        match fresh_auth {
            FreshAuthProof::Password(password) => {
                self.verify_password_proof(user_id, password).await?;
                self.delete_factor_state(user_id).await
            }
            FreshAuthProof::TotpCode(code) => {
                let mut transaction = self.pool.begin().await.map_err(AppError::Database)?;
                self.lock_factor_for_disable(&mut transaction, user_id)
                    .await?;
                self.verify_and_record_totp(&mut transaction, user_id, &code)
                    .await?;
                self.delete_factor_state_in(&mut transaction, user_id)
                    .await?;
                transaction.commit().await.map_err(AppError::Database)
            }
        }
    }

    /// Lock the caller's factor row until this transaction ends, or report it unusable.
    ///
    /// Taken before the disable proof is read so a second disable presenting the same code
    /// blocks here instead of racing the replay insert. The absent row takes no lock: an
    /// enrollment committed after this point is not excluded, the same boundary as
    /// [`Self::is_totp_enabled_locked`].
    async fn lock_factor_for_disable(
        &self,
        connection: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<(), AppError> {
        let enabled: Option<bool> =
            sqlx::query_scalar("SELECT enabled FROM totp_secrets WHERE user_id = $1 FOR UPDATE")
                .bind(user_id)
                .fetch_optional(&mut *connection)
                .await
                .map_err(AppError::Database)?;
        if enabled != Some(true) {
            return Err(AppError::TotpNotEnrolled);
        }
        Ok(())
    }

    /// Check a password proof on the pool: Argon2id is CPU-bound and must run off the
    /// executor, and no transaction may be held while it does.
    async fn verify_password_proof(&self, user_id: Uuid, password: String) -> Result<(), AppError> {
        let password_hash: String =
            sqlx::query_scalar::<_, String>("SELECT password_hash FROM users WHERE id = $1")
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
        Ok(())
    }

    /// Delete the factor and the replay log in their own transaction.
    async fn delete_factor_state(&self, user_id: Uuid) -> Result<(), AppError> {
        let mut transaction = self.pool.begin().await.map_err(AppError::Database)?;
        self.delete_factor_state_in(&mut transaction, user_id)
            .await?;
        transaction.commit().await.map_err(AppError::Database)
    }

    /// Delete the factor and the replay log on the caller's transaction.
    async fn delete_factor_state_in(
        &self,
        connection: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query("DELETE FROM totp_secrets WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *connection)
            .await
            .map_err(AppError::Database)?;
        sqlx::query("DELETE FROM totp_used_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *connection)
            .await
            .map_err(AppError::Database)?;

        tracing::debug!(
            event = "totp_secret_deleted",
            user_id = %user_id,
            outcome = "disabled",
        );
        Ok(())
    }

    /// Mint a half-authenticated challenge token; only its SHA-256 hash is stored.
    ///
    /// Minting never needs the encryption key: a keyless deployment must still be able to
    /// present the backup-code leg, which matches Argon2id hashes and never decrypts the
    /// secret. The TOTP-code leg fails closed on its own when the key is missing.
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
        let mut transaction = self.pool.begin().await.map_err(AppError::Database)?;
        self.consume_two_factor_token_in(&mut transaction, token)
            .await?;
        transaction.commit().await.map_err(AppError::Database)
    }

    /// Delete the challenge token on the caller's transaction.
    pub(crate) async fn consume_two_factor_token_in(
        &self,
        connection: &mut PgConnection,
        token: &str,
    ) -> Result<(), AppError> {
        let token_hash = hash_token(token).map_err(|_| AppError::TwoFactorTokenInvalid)?;
        let deleted = sqlx::query("DELETE FROM two_factor_tokens WHERE token_hash = $1")
            .bind(&token_hash[..])
            .execute(&mut *connection)
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

    /// Read `totp_secrets.enabled` on the caller's transaction, holding a share lock on the
    /// row until that transaction ends.
    ///
    /// A login that couples this read with its session insert excludes a concurrent
    /// `confirm_enrollment` for a row that exists at read time: the activation update blocks
    /// on the lock and commits after the session, never between the decision and the
    /// insert. Coverage stops at that row — a factor created after this read is not
    /// observed, because `enroll_totp` inserts a new row and an absent row takes no lock.
    /// Closing that case would mean `SELECT … FOR UPDATE` on the user row before this read;
    /// `create_session_in` takes that same lock later in the same transaction, so the
    /// acquisition would not add serialization, only move it earlier. It is not taken
    /// because the boundary is not a bypass: a factor created after this decision did not
    /// exist when the credentials were validated, and a session minted before activation is
    /// not revoked — the same position as enabling 2FA after a finished login.
    pub(crate) async fn is_totp_enabled_locked(
        &self,
        connection: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<bool, AppError> {
        sqlx::query_scalar::<_, bool>(
            "SELECT enabled FROM totp_secrets WHERE user_id = $1 FOR SHARE",
        )
        .bind(user_id)
        .fetch_optional(&mut *connection)
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
    /// `TotpCodeInvalid` keeps the client response indistinguishable from a wrong code. A
    /// missing key is not a statement about the code, so it stays a server fault.
    fn decrypt_totp_secret(&self, encrypted_secret: &[u8]) -> Result<DecryptedSecret, AppError> {
        let key = self.encryption_key().map_err(|error| {
            tracing::error!(error = %error, "totp verification is unavailable without a key");
            AppError::TwoFactorUnavailable
        })?;
        decrypt_secret(&key, encrypted_secret).map_err(|err| {
            tracing::error!(error = %err, "stored totp secret could not be decrypted");
            AppError::TotpCodeInvalid
        })
    }
}

/// Single clock reference for one verification transaction.
///
/// `clock_timestamp()` is read when this statement executes, so a transaction that stalls
/// after `BEGIN` verifies against the instant the code is checked. `transaction_timestamp()`
/// is frozen at `BEGIN`: a transaction stalled past the prune age would then accept a code
/// whose replay row a later transaction has already pruned, and write `used_at` in the past.
/// One reference still feeds the counter, the prune cutoff, and the replay row's `used_at`.
async fn transaction_now(connection: &mut PgConnection) -> Result<DateTime<Utc>, AppError> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *connection)
        .await
        .map_err(AppError::Database)
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
        auth::{models::LoginRequest, service::AuthServiceImpl},
        config::TotpConfig,
        crypto::hash_password,
        db::DbPoolOptions,
        email::EmailDispatcher,
        handler::auth::{AuthHandlerState, login},
        session::SessionService,
        totp::crypto::{TOTP_STEP_SECS, current_totp_counter, generate_totp},
    };
    use axum::{
        Json,
        body::to_bytes,
        extract::State,
        http::{HeaderMap, StatusCode, header},
    };

    /// Test-only AES key. Never a production key.
    const TEST_KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    struct DbTestContext {
        service: TotpService,
        pool: PgPool,
        config: Arc<Config>,
        auth_config: Arc<AppConfig>,
        _guard: tokio::sync::MutexGuard<'static, ()>,
    }

    async fn setup_db_context() -> Option<DbTestContext> {
        let guard = crate::db::DB_TEST_LOCK.lock().await;
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
        // Same global claim as the integration binaries: a prior run's claimable rows would
        // otherwise reach the next test's capturing sender.
        crate::db::outbox::discard_claimable_outbox(&pool)
            .await
            .expect("clear claimable outbox residue");
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
                used_code_prune_age_secs: crate::totp::crypto::MIN_USED_CODE_PRUNE_AGE_SECS,
                ..TotpConfig::default()
            },
            ..Config::default()
        });
        let service = TotpService::new(pool.clone(), Arc::clone(&config), Arc::clone(&auth_config));
        Some(DbTestContext {
            service,
            pool,
            config,
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

    async fn create_user_with_email(
        ctx: &DbTestContext,
        verified: bool,
        password: &str,
    ) -> (Uuid, String) {
        let email = format!("totp-{}@example.com", Uuid::new_v4().simple());
        let password_hash = hash_password(password, &ctx.auth_config).expect("hash");
        let user_id = sqlx::query_scalar(
            "INSERT INTO users (email, password_hash, email_verified) \
             VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(&email)
        .bind(password_hash)
        .bind(verified)
        .fetch_one(&ctx.pool)
        .await
        .expect("insert user");
        (user_id, email)
    }

    async fn create_user(ctx: &DbTestContext, verified: bool, password: &str) -> Uuid {
        create_user_with_email(ctx, verified, password).await.0
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
            "sessions" => "SELECT COUNT(*) FROM sessions WHERE user_id = $1",
            other => panic!("unexpected table {other}"),
        };
        sqlx::query_scalar(sql)
            .bind(user_id)
            .fetch_one(pool)
            .await
            .expect("count")
    }

    async fn count_used_code(pool: &PgPool, user_id: Uuid, code: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM totp_used_codes WHERE user_id = $1 AND code_hash = $2",
        )
        .bind(user_id)
        .bind(compute_code_replay_hash(code))
        .fetch_one(pool)
        .await
        .expect("count")
    }

    async fn database_now(ctx: &DbTestContext) -> DateTime<Utc> {
        sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&ctx.pool)
            .await
            .expect("database clock")
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
    async fn enrollment_upsert_cannot_downgrade_a_confirmed_factor() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        enroll_and_confirm(&ctx, user_id).await;
        let before: (Vec<u8>, bool) =
            sqlx::query_as("SELECT encrypted_secret, enabled FROM totp_secrets WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&ctx.pool)
                .await
                .expect("confirmed secret");

        // The enroll request passed the pre-hash gate, then the confirmation landed.
        let replacement = serde_json::Value::Array(Vec::new());
        assert!(matches!(
            ctx.service
                .store_pending_secret(user_id, &[7u8; 40], &replacement)
                .await,
            Err(AppError::TotpAlreadyEnabled)
        ));

        let after: (Vec<u8>, bool) =
            sqlx::query_as("SELECT encrypted_secret, enabled FROM totp_secrets WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&ctx.pool)
                .await
                .expect("confirmed secret");
        assert_eq!(before, after, "a losing enrollment must not touch the row");
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
    async fn confirm_cannot_activate_a_replaced_pending_enrollment() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        ctx.service
            .enroll_totp(user_id)
            .await
            .expect("first enroll");
        let verified_secret: Vec<u8> =
            sqlx::query_scalar("SELECT encrypted_secret FROM totp_secrets WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&ctx.pool)
                .await
                .expect("first secret");

        // A second enrollment replaces the secret before the first confirmation lands.
        let second = ctx
            .service
            .enroll_totp(user_id)
            .await
            .expect("second enroll");

        let mut transaction = ctx.pool.begin().await.expect("transaction");
        assert!(matches!(
            ctx.service
                .activate_pending_secret(&mut transaction, user_id, &verified_secret)
                .await,
            Err(AppError::TotpNotEnrolled)
        ));
        transaction.rollback().await.expect("rollback");
        assert!(!ctx.service.is_totp_enabled(user_id).await.expect("state"));

        let second_code = current_code(&second.secret_base32);
        ctx.service
            .confirm_enrollment(user_id, &second_code, "127.0.0.1")
            .await
            .expect("the live pending enrollment still confirms");
    }

    #[tokio::test]
    async fn confirmation_and_verification_verify_against_the_same_database_clock() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let enrollment = ctx.service.enroll_totp(user_id).await.expect("enroll");
        let raw = decode_totp_secret(&enrollment.secret_base32).expect("decode");

        // Stands in for a database host whose clock is three steps ahead of the application
        // host: a code derived from the application clock is outside the ±1 step window.
        let reference: DateTime<Utc> = sqlx::query_scalar("SELECT transaction_timestamp()")
            .fetch_one(&ctx.pool)
            .await
            .expect("database clock");
        let reference = reference + Duration::seconds(90);
        let code = format!(
            "{:06}",
            generate_totp(&raw, totp_counter_at(reference)).expect("generate")
        );

        let mut transaction = ctx.pool.begin().await.expect("transaction");
        ctx.service
            .confirm_enrollment_at(&mut transaction, user_id, &code, reference)
            .await
            .expect("confirmation must verify against the database clock");
        transaction.commit().await.expect("commit");

        ctx.service
            .verify_totp_at_reference(user_id, &code, reference)
            .await
            .expect("a code accepted at confirmation must be accepted at verification");

        // The public entry point is the only production caller of the pinned body; drive it
        // so the wrapper stays on the path the test exercises.
        let production_user = create_user(&ctx, true, &fixture_password()).await;
        let production = ctx
            .service
            .enroll_totp(production_user)
            .await
            .expect("enroll");
        let production_code = current_code(&production.secret_base32);
        ctx.service
            .confirm_enrollment(production_user, &production_code, "127.0.0.1")
            .await
            .expect("the public entry point confirms on the same anchor");
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
    async fn code_is_single_use_across_the_whole_window() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let raw = decode_totp_secret(&response.secret_base32).expect("decode");
        let step = current_totp_counter();
        let code = format!("{:06}", generate_totp(&raw, step).expect("generate"));

        ctx.service
            .verify_totp_at(user_id, &code, step)
            .await
            .expect("accepted at T");
        for counter in [step + 1, step.saturating_sub(1)] {
            assert!(
                matches!(
                    ctx.service.verify_totp_at(user_id, &code, counter).await,
                    Err(AppError::TotpCodeReplayed)
                ),
                "same code was accepted at counter {counter}"
            );
        }
        assert_eq!(count_rows(&ctx.pool, "totp_used_codes", user_id).await, 1);
    }

    #[tokio::test]
    async fn code_accepted_at_t_minus_one_still_replays_at_t_plus_one() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let raw = decode_totp_secret(&response.secret_base32).expect("decode");
        let step = current_totp_counter();
        let code = format!("{:06}", generate_totp(&raw, step).expect("generate"));

        ctx.service
            .verify_totp_at(user_id, &code, step.saturating_sub(1))
            .await
            .expect("accepted at T-1");

        // A row written at the start of T-1 is 60s old when T+1 begins. At the minimum
        // legal horizon it must still be present when the same code is replayed.
        sqlx::query(
            "UPDATE totp_used_codes SET used_at = CURRENT_TIMESTAMP - INTERVAL '61 seconds' \
             WHERE user_id = $1",
        )
        .bind(user_id)
        .execute(&ctx.pool)
        .await
        .expect("backdate row");

        assert!(matches!(
            ctx.service.verify_totp_at(user_id, &code, step + 1).await,
            Err(AppError::TotpCodeReplayed)
        ));
        assert_eq!(count_rows(&ctx.pool, "totp_used_codes", user_id).await, 1);
    }

    #[tokio::test]
    async fn stalled_request_counter_comes_from_the_reference() {
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

        // A stalled request: its counter and its prune cutoff are one instant, 121s past
        // the code's step, which is beyond the default 120s prune age. The code is
        // therefore outside the ±1 step window by the same reference that sets the cutoff.
        // A wall-clock counter with this cutoff would prune the blocking row and accept
        // the code instead.
        let replay = ctx
            .service
            .verify_totp_at_reference(user_id, &code, Utc::now() + Duration::seconds(121))
            .await;

        assert!(
            matches!(replay, Err(AppError::TotpCodeInvalid)),
            "a stalled request must reject the code as out of window, not as a replay: {replay:?}"
        );
    }

    #[tokio::test]
    async fn stalled_replay_is_rejected_after_its_tombstone_is_pruned() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let raw = decode_totp_secret(&response.secret_base32).expect("decode");

        // Eight steps back: the code's last accepted step closed well before a write can
        // land now, and the fresher verify below still reads a step far from the boundary.
        let step = current_totp_counter() - 8;
        let code = format!("{:06}", generate_totp(&raw, step).expect("generate"));
        let used_at =
            DateTime::from_timestamp(i64::try_from(step * TOTP_STEP_SECS).expect("fits"), 0)
                .expect("timestamp");

        // The original redemption, committed while the code was live.
        sqlx::query(
            "INSERT INTO totp_used_codes (user_id, code_hash, used_at) VALUES ($1, $2, $3)",
        )
        .bind(user_id)
        .bind(compute_code_replay_hash(&code))
        .bind(used_at)
        .execute(&ctx.pool)
        .await
        .expect("seed redemption");
        assert_eq!(
            count_used_code(&ctx.pool, user_id, &code).await,
            1,
            "the seeded tombstone must land, or the prune half proves nothing"
        );

        // A verify 241s later outlives the minimum 120s prune age and removes the row.
        let fresher = format!("{:06}", generate_totp(&raw, step + 8).expect("generate"));
        ctx.service
            .verify_totp_at_reference(user_id, &fresher, used_at + Duration::seconds(241))
            .await
            .expect("a later verify prunes the stale row");
        assert_eq!(
            count_used_code(&ctx.pool, user_id, &code).await,
            0,
            "the later verify must prune the tombstone"
        );

        // The stalled verifier resumes holding its pre-stall reference, still in the code's
        // window. The pruned tombstone left no conflict, so only the write-time window
        // check can refuse to re-create it.
        let replay = ctx
            .service
            .verify_totp_at_reference(user_id, &code, used_at)
            .await;
        assert!(
            matches!(replay, Err(AppError::TotpCodeInvalid)),
            "a stalled replay must expire, not be accepted or labelled a replay: {replay:?}"
        );
        assert_eq!(count_used_code(&ctx.pool, user_id, &code).await, 0);
    }

    #[tokio::test]
    async fn write_at_the_window_bound_tracks_the_acceptance_band() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let raw = decode_totp_secret(&response.secret_base32).expect("decode");
        let counter = totp_counter_at(database_now(&ctx).await);

        // The matched step is the current one, so the write is a full step inside the bound.
        let live_end = code_window_end(counter).expect("bound");
        let live = format!("{:06}", generate_totp(&raw, counter).expect("generate"));
        ctx.service
            .verify_totp_at_reference(user_id, &live, live_end - Duration::seconds(1))
            .await
            .expect("the last accepted second must still verify");
        assert_eq!(count_used_code(&ctx.pool, user_id, &live).await, 1);

        // Two steps older: the reference is still inside the band, the write is past it.
        let stale_step = counter - 2;
        let stale_end = code_window_end(stale_step).expect("bound");
        let stale = format!("{:06}", generate_totp(&raw, stale_step).expect("generate"));
        let write_late = ctx
            .service
            .verify_totp_at_reference(user_id, &stale, stale_end - Duration::seconds(1))
            .await;
        assert!(
            matches!(write_late, Err(AppError::TotpCodeInvalid)),
            "a write past the bound must expire: {write_late:?}"
        );

        // At the bound the code's own reference is one counter outside the band.
        let at_bound = ctx
            .service
            .verify_totp_at_reference(user_id, &stale, stale_end)
            .await;
        assert!(
            matches!(at_bound, Err(AppError::TotpCodeInvalid)),
            "the bound is exclusive: {at_bound:?}"
        );
        assert_eq!(count_used_code(&ctx.pool, user_id, &stale).await, 0);
    }

    #[tokio::test]
    async fn expired_and_already_used_reports_expired() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let raw = decode_totp_secret(&response.secret_base32).expect("decode");
        let now = database_now(&ctx).await;
        let counter = totp_counter_at(now);

        // Five steps back, with a tombstone too young for the prune to take.
        let step = counter - 5;
        let code = format!("{:06}", generate_totp(&raw, step).expect("generate"));
        sqlx::query(
            "INSERT INTO totp_used_codes (user_id, code_hash, used_at) VALUES ($1, $2, $3)",
        )
        .bind(user_id)
        .bind(compute_code_replay_hash(&code))
        .bind(now - Duration::seconds(60))
        .execute(&ctx.pool)
        .await
        .expect("seed used code");
        assert_eq!(count_used_code(&ctx.pool, user_id, &code).await, 1);

        // Reference inside the band, write past it: expiry outranks the unique index.
        let window_end = code_window_end(step).expect("bound");
        let verdict = ctx
            .service
            .verify_totp_at_reference(user_id, &code, window_end - Duration::seconds(1))
            .await;
        assert!(
            matches!(verdict, Err(AppError::TotpCodeInvalid)),
            "an expired code must report expiry, not replay: {verdict:?}"
        );
        assert_eq!(count_used_code(&ctx.pool, user_id, &code).await, 1);
    }

    #[tokio::test]
    async fn transaction_reference_is_execution_time_not_begin() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };

        let mut transaction = ctx.pool.begin().await.expect("transaction");
        let begin: DateTime<Utc> = sqlx::query_scalar("SELECT transaction_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .expect("begin reference");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let reference = transaction_now(&mut transaction).await.expect("reference");
        let frozen: DateTime<Utc> = sqlx::query_scalar("SELECT transaction_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .expect("frozen reference");

        assert!(
            reference - begin >= Duration::seconds(1),
            "the reference must be read when the statement runs, not at BEGIN: reference is \
             {reference}, begin is {begin}"
        );
        assert!(
            frozen - begin < Duration::seconds(1),
            "the probe must stay transaction-frozen, otherwise it proves nothing"
        );
        transaction.rollback().await.expect("rollback");
    }

    #[tokio::test]
    async fn used_code_row_is_stamped_with_the_reference() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let code = current_code(&response.secret_base32);

        let mut transaction = ctx.pool.begin().await.expect("transaction");
        let begin: DateTime<Utc> = sqlx::query_scalar("SELECT transaction_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .expect("begin reference");
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

        let reference = transaction_now(&mut transaction).await.expect("reference");
        ctx.service
            .record_totp_use(
                &mut transaction,
                user_id,
                &code,
                totp_counter_at(reference),
                reference,
            )
            .await
            .expect("record");

        let used_at: DateTime<Utc> =
            sqlx::query_scalar("SELECT used_at FROM totp_used_codes WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&mut *transaction)
                .await
                .expect("stored used_at");

        assert_eq!(
            used_at, reference,
            "the replay row must carry the reference, not the transaction default"
        );
        assert!(
            used_at - begin >= Duration::milliseconds(500),
            "a row stamped with the frozen default would be {begin} or earlier"
        );
        transaction.rollback().await.expect("rollback");
    }

    #[tokio::test]
    async fn stale_used_codes_are_pruned_before_the_insert() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let raw = decode_totp_secret(&response.secret_base32).expect("decode");
        let step = current_totp_counter();
        let code = format!("{:06}", generate_totp(&raw, step).expect("generate"));
        let replay_hash = compute_code_replay_hash(&code);

        sqlx::query(
            "INSERT INTO totp_used_codes (user_id, code_hash, used_at) \
             VALUES ($1, $2, CURRENT_TIMESTAMP - INTERVAL '1 hour')",
        )
        .bind(user_id)
        .bind(&replay_hash[..])
        .execute(&ctx.pool)
        .await
        .expect("seed stale row");

        ctx.service
            .verify_totp_at(user_id, &code, step)
            .await
            .expect("stale row must be pruned");
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 5)]
    async fn concurrent_verification_admits_exactly_one_request() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let code = current_code(&response.secret_base32);

        let barrier = Arc::new(tokio::sync::Barrier::new(5));
        let mut handles = Vec::new();
        for _ in 0..5 {
            let service = ctx.service.clone();
            let attempt = code.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
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
    async fn verify_backup_code_requires_an_enabled_secret() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        assert!(matches!(
            ctx.service
                .verify_backup_code(user_id, "AAAAAAAAAA", "ip")
                .await,
            Err(AppError::TotpNotEnrolled)
        ));

        let response = ctx.service.enroll_totp(user_id).await.expect("enroll");
        assert!(matches!(
            ctx.service
                .verify_backup_code(user_id, &response.backup_codes[0], "ip")
                .await,
            Err(AppError::TotpNotEnrolled)
        ));
    }

    #[tokio::test]
    async fn disable_rejects_an_invalid_totp_proof() {
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
            ctx.service
                .disable_totp(user_id, FreshAuthProof::TotpCode(distant_code), "ip")
                .await,
            Err(AppError::TotpCodeInvalid)
        ));
        assert!(ctx.service.is_totp_enabled(user_id).await.expect("state"));
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
                    // Cannot match the stored hash: the real password never carries this prefix.
                    FreshAuthProof::Password(format!("wrong-{password}")),
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
    async fn disable_rejects_a_code_already_spent_at_login() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let code = current_code(&response.secret_base32);

        // The login leg records the code, so a sniffed code can buy exactly one session.
        ctx.service
            .verify_totp(user_id, &code, "ip")
            .await
            .expect("login spends the code");

        assert!(matches!(
            ctx.service
                .disable_totp(user_id, FreshAuthProof::TotpCode(code), "ip")
                .await,
            Err(AppError::TotpCodeReplayed)
        ));
        assert!(
            ctx.service.is_totp_enabled(user_id).await.expect("state"),
            "a rejected disable must leave the second factor enabled"
        );
        assert_eq!(
            count_rows(&ctx.pool, "totp_used_codes", user_id).await,
            1,
            "the login's replay row must survive the rejected disable"
        );
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_disables_with_the_same_code_admit_exactly_one() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let code = current_code(&response.secret_base32);

        // Hold the factor row so a loser cannot simply arrive after the wipe and be
        // rejected for the wrong reason: both disables must present a proof first.
        let mut blocker = ctx.pool.begin().await.expect("blocking transaction");
        sqlx::query("SELECT id FROM totp_secrets WHERE user_id = $1 FOR UPDATE")
            .bind(user_id)
            .execute(&mut *blocker)
            .await
            .expect("hold the factor row");

        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let service = ctx.service.clone();
            let attempt = code.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                service
                    .disable_totp(user_id, FreshAuthProof::TotpCode(attempt), "ip")
                    .await
            }));
        }
        barrier.wait().await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            handles.iter().all(|handle| !handle.is_finished()),
            "both disables must be waiting on the factor row, not past it"
        );
        blocker.commit().await.expect("release the factor row");

        let mut accepted = 0;
        let mut rejected = 0;
        for handle in handles {
            match handle.await.expect("join") {
                Ok(()) => accepted += 1,
                Err(AppError::TotpNotEnrolled) => rejected += 1,
                Err(other) => panic!("unexpected result: {other:?}"),
            }
        }
        assert_eq!(accepted, 1, "exactly one disable may succeed");
        assert_eq!(rejected, 1, "the second disable must find no factor");
        assert_eq!(count_rows(&ctx.pool, "totp_secrets", user_id).await, 0);
        assert_eq!(count_rows(&ctx.pool, "totp_used_codes", user_id).await, 0);
    }

    #[tokio::test]
    async fn a_second_disable_with_the_same_code_finds_no_factor() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let response = enroll_and_confirm(&ctx, user_id).await;
        let code = current_code(&response.secret_base32);

        ctx.service
            .disable_totp(user_id, FreshAuthProof::TotpCode(code.clone()), "ip")
            .await
            .expect("first disable");

        // Disable is destructive, so the repeated proof meets no factor. The rejection is
        // `TotpNotEnrolled`, before any code check: nothing is left to replay it against.
        assert!(matches!(
            ctx.service
                .disable_totp(user_id, FreshAuthProof::TotpCode(code), "ip")
                .await,
            Err(AppError::TotpNotEnrolled)
        ));
        assert_eq!(count_rows(&ctx.pool, "totp_secrets", user_id).await, 0);
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

    fn handler_state(ctx: &DbTestContext) -> AuthHandlerState {
        handler_state_with_config(ctx, &ctx.config)
    }

    /// Login state whose TOTP and session services both run against `config`.
    fn handler_state_with_config(ctx: &DbTestContext, config: &Arc<Config>) -> AuthHandlerState {
        // AuthServiceImpl validates the production Argon2 floor; the TOTP hash fixtures
        // use cheaper parameters because verification reads the PHC header.
        let auth_config = Arc::new(AppConfig {
            argon2_m_cost: 19456,
            argon2_t_cost: 2,
            argon2_p_cost: 1,
            ..Default::default()
        });
        let auth_service = Arc::new(
            AuthServiceImpl::new(
                ctx.pool.clone(),
                auth_config,
                Arc::new(EmailDispatcher::new(
                    None,
                    std::time::Duration::from_secs(10),
                )),
            )
            .expect("auth service"),
        );
        AuthHandlerState {
            service: auth_service,
            session_service: Some(Arc::new(SessionService::new(
                ctx.pool.clone(),
                Arc::clone(config),
            ))),
            rate_limiter: None,
            config: Some(Arc::clone(config)),
            totp_service: Arc::new(TotpService::new(
                ctx.pool.clone(),
                Arc::clone(config),
                Arc::clone(&ctx.auth_config),
            )),
        }
    }

    #[tokio::test]
    async fn keyless_deployment_still_mints_a_challenge() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let password = fixture_password();
        let (user_id, email) = create_user_with_email(&ctx, true, &password).await;
        enroll_and_confirm(&ctx, user_id).await;

        let keyless = Arc::new(Config {
            totp: TotpConfig {
                encryption_key: None,
                ..TotpConfig::default()
            },
            ..Config::default()
        });

        let response = login(
            State(handler_state_with_config(&ctx, &keyless)),
            HeaderMap::new(),
            Ok(Json(LoginRequest { email, password })),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(header::SET_COOKIE).is_none(),
            "a 2fa challenge must not carry a session cookie"
        );
        let body = to_bytes(response.into_body(), 4096).await.expect("body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(body["two_factor_required"], true);
        assert!(body["challenge_token"].as_str().is_some());
        assert_eq!(
            count_rows(&ctx.pool, "two_factor_tokens", user_id).await,
            1,
            "the backup-code leg needs a challenge even without a key"
        );
        assert_eq!(count_rows(&ctx.pool, "sessions", user_id).await, 0);
    }

    #[tokio::test]
    async fn login_gate_issues_a_challenge_without_a_session() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let password = fixture_password();
        let (user_id, email) = create_user_with_email(&ctx, true, &password).await;
        enroll_and_confirm(&ctx, user_id).await;

        let response = login(
            State(handler_state(&ctx)),
            HeaderMap::new(),
            Ok(Json(LoginRequest { email, password })),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(header::SET_COOKIE).is_none(),
            "2fa challenge must not issue a session cookie"
        );
        let body = to_bytes(response.into_body(), 4096).await.expect("body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(body["two_factor_required"], true);
        assert!(body.get("user_id").is_none());
        assert!(body.get("expires_at").is_none());
        let token = body["challenge_token"].as_str().expect("challenge token");
        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(count_rows(&ctx.pool, "sessions", user_id).await, 0);
    }

    #[tokio::test]
    async fn auth_router_without_totp_routes_refuses_a_two_factor_login() {
        use crate::handler::auth::routes_with_state;
        use axum::{
            body::Body,
            http::{Request, header as http_header},
        };
        use tower::ServiceExt;

        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let password = fixture_password();
        let (user_id, email) = create_user_with_email(&ctx, true, &password).await;
        enroll_and_confirm(&ctx, user_id).await;

        // Exactly what `routes()` builds: no session service, and no `/totp/*` route.
        let mut handler = handler_state(&ctx);
        handler.session_service = None;
        let app = routes_with_state(handler);

        let request = Request::builder()
            .method("POST")
            .uri("/login")
            .header(http_header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&LoginRequest { email, password }).expect("body"),
            ))
            .expect("request");
        let response = app.oneshot(request).await.expect("response");

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            count_rows(&ctx.pool, "two_factor_tokens", user_id).await,
            0,
            "a router that cannot redeem a challenge must not mint one"
        );
        assert_eq!(count_rows(&ctx.pool, "sessions", user_id).await, 0);
    }

    #[tokio::test]
    async fn activation_cannot_land_between_the_gate_read_and_the_session_commit() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let password = fixture_password();
        let (user_id, email) = create_user_with_email(&ctx, true, &password).await;
        // Pending enrollment: the row exists and `enabled` is still FALSE.
        ctx.service.enroll_totp(user_id).await.expect("enroll");

        let mut blocker = ctx.pool.begin().await.expect("blocking transaction");
        sqlx::query("SELECT id FROM totp_secrets WHERE user_id = $1 FOR UPDATE")
            .bind(user_id)
            .execute(&mut *blocker)
            .await
            .expect("hold the factor row");

        let attempt = tokio::spawn(login(
            State(handler_state(&ctx)),
            HeaderMap::new(),
            Ok(Json(LoginRequest { email, password })),
        ));

        // The gate read must wait on the factor row: a decision taken before the
        // activation commits is not allowed to reach the session insert.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(
            !attempt.is_finished(),
            "login must hold the factor row until the session is committed"
        );
        assert_eq!(
            count_rows(&ctx.pool, "sessions", user_id).await,
            0,
            "no session may be visible while the gate decision is still open"
        );

        // `confirm_enrollment`'s activation commits, then the login resumes and must see it.
        sqlx::query("UPDATE totp_secrets SET enabled = TRUE WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *blocker)
            .await
            .expect("activate");
        blocker.commit().await.expect("release");

        let response = attempt.await.expect("join");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(header::SET_COOKIE).is_none(),
            "an account activated mid-login must not receive a session"
        );
        let body = to_bytes(response.into_body(), 4096).await.expect("body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(body["two_factor_required"], true);
        assert_eq!(count_rows(&ctx.pool, "sessions", user_id).await, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gate_lock_covers_only_the_factor_row_present_at_read_time() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };

        // Present row: the activation cannot land before the gate transaction ends.
        let user_id = create_user(&ctx, true, &fixture_password()).await;
        let enrollment = ctx.service.enroll_totp(user_id).await.expect("enroll");
        let code = current_code(&enrollment.secret_base32);

        let mut gate = ctx.pool.begin().await.expect("gate transaction");
        assert!(
            !ctx.service
                .is_totp_enabled_locked(&mut gate, user_id)
                .await
                .expect("gate read")
        );
        let confirmer = {
            let service = ctx.service.clone();
            tokio::spawn(async move { service.confirm_enrollment(user_id, &code, "ip").await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(
            !confirmer.is_finished(),
            "a row present at read time must not be activated before the gate commits"
        );
        gate.commit().await.expect("release the gate");
        confirmer
            .await
            .expect("join")
            .expect("the activation proceeds once the gate releases the row");

        // Absent row: the gate takes no lock, so an enrollment created afterwards is not
        // excluded. That is the documented boundary of this helper, pinned here so a
        // future change to the coverage has to update the claim.
        let new_user = create_user(&ctx, true, &fixture_password()).await;
        let mut gate = ctx.pool.begin().await.expect("gate transaction");
        assert!(
            !ctx.service
                .is_totp_enabled_locked(&mut gate, new_user)
                .await
                .expect("gate read")
        );
        let enrollment = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            ctx.service.enroll_totp(new_user),
        )
        .await
        .expect("an absent row must not block a concurrent enrollment")
        .expect("enroll");
        let code = current_code(&enrollment.secret_base32);
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            ctx.service.confirm_enrollment(new_user, &code, "ip"),
        )
        .await
        .expect("an absent row must not block a concurrent confirmation")
        .expect("confirm");
        gate.commit().await.expect("release the gate");
        assert!(ctx.service.is_totp_enabled(new_user).await.expect("state"));
    }

    #[tokio::test]
    async fn activation_after_an_absent_row_gate_leaves_the_session_live() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };

        // The gate saw no factor row, so its session is password-only. A later activation must
        // not rewrite that decision: enabling 2FA does not revoke live sessions.
        let password = fixture_password();
        let (late_user, email) = create_user_with_email(&ctx, true, &password).await;
        let response = login(
            State(handler_state(&ctx)),
            HeaderMap::new(),
            Ok(Json(LoginRequest { email, password })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(count_rows(&ctx.pool, "sessions", late_user).await, 1);

        let enrollment = ctx.service.enroll_totp(late_user).await.expect("enroll");
        let code = current_code(&enrollment.secret_base32);
        ctx.service
            .confirm_enrollment(late_user, &code, "ip")
            .await
            .expect("confirm");

        assert!(
            ctx.service.is_totp_enabled(late_user).await.expect("state"),
            "the activation itself must succeed behind a committed gate"
        );
        assert_eq!(
            count_rows(&ctx.pool, "sessions", late_user).await,
            1,
            "activation must not revoke the session minted before it"
        );
    }

    #[tokio::test]
    async fn login_without_totp_keeps_the_session_body() {
        let Some(ctx) = setup_db_context().await else {
            return;
        };
        let password = fixture_password();
        let (user_id, email) = create_user_with_email(&ctx, true, &password).await;

        let response = login(
            State(handler_state(&ctx)),
            HeaderMap::new(),
            Ok(Json(LoginRequest { email, password })),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096).await.expect("body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(body["user_id"], user_id.to_string());
        assert!(body.get("two_factor_required").is_none());
        assert_eq!(count_rows(&ctx.pool, "sessions", user_id).await, 1);
    }
}
