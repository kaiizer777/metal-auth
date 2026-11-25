use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    config::DatabaseBackend,
    db::{
        models::{
            EmailOutbox, OAuthAccount, PasswordResetToken, Session, TotpSecret, TwoFactorToken,
            User, VerificationToken,
        },
        store::{
            DatabaseStore, OAuthStore, OutboxStore, SessionStore, StoreTx, TokenStore, TotpStore,
            UserStore,
        },
    },
    error::AppError,
};

pub mod auth;
pub mod oauth;
pub mod outbox;
pub mod session;
pub mod totp;

/// PostgreSQL-backed implementation of [`DatabaseStore`].
#[derive(Clone, Debug)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    /// Creates a new `PostgresStore` wrapping the provided [`PgPool`].
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Returns a reference to the wrapped [`PgPool`].
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl UserStore for PostgresStore {
    async fn create_user(&self, email: &str, password_hash: &str) -> Result<User, AppError> {
        auth::create_user(&self.pool, email, password_hash).await
    }

    async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>, AppError> {
        auth::get_user_by_id(&self.pool, id).await
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        auth::get_user_by_email(&self.pool, email).await
    }

    async fn set_email_verified(&self, user_id: Uuid, verified: bool) -> Result<(), AppError> {
        auth::set_email_verified(&self.pool, user_id, verified).await
    }

    async fn update_password_hash(&self, user_id: Uuid, new_hash: &str) -> Result<(), AppError> {
        auth::update_password_hash(&self.pool, user_id, new_hash).await
    }

    async fn delete_user(&self, user_id: Uuid) -> Result<bool, AppError> {
        auth::delete_user(&self.pool, user_id).await
    }
}

#[async_trait]
impl SessionStore for PostgresStore {
    async fn create_session(
        &self,
        user_id: Uuid,
        token_hash: &str,
        session_type: &str,
        csrf_token: Option<&str>,
        absolute_expires_at: DateTime<Utc>,
    ) -> Result<Session, AppError> {
        session::create_session(
            &self.pool,
            user_id,
            token_hash,
            session_type,
            csrf_token,
            absolute_expires_at,
        )
        .await
    }

    async fn get_session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<Session>, AppError> {
        session::get_session_by_token_hash(&self.pool, token_hash).await
    }

    async fn touch_session(
        &self,
        session_id: Uuid,
        last_active_at: DateTime<Utc>,
    ) -> Result<(), AppError> {
        session::touch_session(&self.pool, session_id, last_active_at).await
    }

    async fn rotate_session(
        &self,
        session_id: Uuid,
        new_token_hash: &str,
        new_csrf_token: Option<&str>,
        last_active_at: DateTime<Utc>,
    ) -> Result<(), AppError> {
        session::rotate_session(
            &self.pool,
            session_id,
            new_token_hash,
            new_csrf_token,
            last_active_at,
        )
        .await
    }

    async fn delete_session(&self, session_id: Uuid) -> Result<(), AppError> {
        session::delete_session(&self.pool, session_id).await
    }

    async fn delete_by_token_hash(&self, token_hash: &str) -> Result<bool, AppError> {
        session::delete_by_token_hash(&self.pool, token_hash).await
    }

    async fn delete_user_sessions(&self, user_id: Uuid) -> Result<u64, AppError> {
        session::delete_user_sessions(&self.pool, user_id).await
    }

    async fn list_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, AppError> {
        session::list_user_sessions(&self.pool, user_id).await
    }

    async fn delete_expired_sessions(&self) -> Result<u64, AppError> {
        session::delete_expired_sessions(&self.pool).await
    }
}

#[async_trait]
impl TokenStore for PostgresStore {
    async fn create_verification_token(
        &self,
        user_id: Uuid,
        token_hash: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<VerificationToken, AppError> {
        auth::create_verification_token(&self.pool, user_id, token_hash, expires_at).await
    }

    async fn consume_verification_token(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<VerificationToken>, AppError> {
        auth::consume_verification_token(&self.pool, token_hash).await
    }

    async fn create_password_reset_token(
        &self,
        user_id: Uuid,
        token_hash: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<PasswordResetToken, AppError> {
        auth::create_password_reset_token(&self.pool, user_id, token_hash, expires_at).await
    }

    async fn consume_password_reset_token(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<PasswordResetToken>, AppError> {
        auth::consume_password_reset_token(&self.pool, token_hash).await
    }

    async fn delete_user_password_reset_tokens(&self, user_id: Uuid) -> Result<u64, AppError> {
        auth::delete_user_password_reset_tokens(&self.pool, user_id).await
    }

    async fn delete_verification_tokens_for_user(&self, user_id: Uuid) -> Result<u64, AppError> {
        auth::delete_verification_tokens_for_user(&self.pool, user_id).await
    }
}

#[async_trait]
impl OutboxStore for PostgresStore {
    async fn insert_outbox(
        &self,
        recipient: &str,
        email_type: &str,
        payload: serde_json::Value,
    ) -> Result<EmailOutbox, AppError> {
        outbox::insert_outbox(&self.pool, recipient, email_type, payload).await
    }

    async fn claim_pending_outbox(
        &self,
        batch_size: u32,
        lock_duration: Duration,
    ) -> Result<Vec<EmailOutbox>, AppError> {
        outbox::claim_pending_outbox(&self.pool, batch_size, lock_duration).await
    }

    async fn mark_outbox_sent(&self, id: Uuid) -> Result<(), AppError> {
        outbox::mark_outbox_sent(&self.pool, id).await
    }

    async fn record_outbox_retry(
        &self,
        id: Uuid,
        retry_count: i32,
        next_retry_at: DateTime<Utc>,
        error_log: &str,
    ) -> Result<(), AppError> {
        outbox::record_outbox_retry(&self.pool, id, retry_count, next_retry_at, error_log).await
    }

    async fn mark_outbox_failed(&self, id: Uuid, error_log: &str) -> Result<(), AppError> {
        outbox::mark_outbox_failed(&self.pool, id, error_log).await
    }

    async fn cleanup_sent_outbox(&self, retention_duration: Duration) -> Result<u64, AppError> {
        outbox::cleanup_sent_outbox(&self.pool, retention_duration).await
    }

    async fn recover_stale_processing(&self, _stale_duration: Duration) -> Result<u64, AppError> {
        outbox::recover_stale_processing(&self.pool).await
    }
}

#[async_trait]
impl OAuthStore for PostgresStore {
    async fn get_account(
        &self,
        provider_id: &str,
        provider_user_id: &str,
    ) -> Result<Option<OAuthAccount>, AppError> {
        oauth::get_account(&self.pool, provider_id, provider_user_id).await
    }

    async fn list_accounts_for_user(&self, user_id: Uuid) -> Result<Vec<OAuthAccount>, AppError> {
        oauth::list_accounts_for_user(&self.pool, user_id).await
    }

    async fn link_account(
        &self,
        user_id: Uuid,
        provider_id: &str,
        provider_user_id: &str,
        email: &str,
    ) -> Result<OAuthAccount, AppError> {
        oauth::link_account(&self.pool, user_id, provider_id, provider_user_id, email).await
    }

    async fn unlink_account(&self, user_id: Uuid, provider_id: &str) -> Result<bool, AppError> {
        oauth::unlink_account(&self.pool, user_id, provider_id).await
    }
}

#[async_trait]
impl TotpStore for PostgresStore {
    async fn get_secret(&self, user_id: Uuid) -> Result<Option<TotpSecret>, AppError> {
        totp::get_secret(&self.pool, user_id).await
    }

    async fn upsert_secret(
        &self,
        user_id: Uuid,
        encrypted_secret: &[u8],
        backup_codes: serde_json::Value,
    ) -> Result<TotpSecret, AppError> {
        totp::upsert_secret(&self.pool, user_id, encrypted_secret, backup_codes).await
    }

    async fn enable_totp(&self, user_id: Uuid) -> Result<bool, AppError> {
        totp::enable_totp(&self.pool, user_id).await
    }

    async fn disable_totp(&self, user_id: Uuid) -> Result<bool, AppError> {
        totp::disable_totp(&self.pool, user_id).await
    }

    async fn record_used_code(&self, user_id: Uuid, code_hash: &[u8]) -> Result<bool, AppError> {
        totp::record_used_code(&self.pool, user_id, code_hash).await
    }

    async fn is_code_used(&self, user_id: Uuid, code_hash: &[u8]) -> Result<bool, AppError> {
        totp::is_code_used(&self.pool, user_id, code_hash).await
    }

    async fn create_two_factor_token(
        &self,
        user_id: Uuid,
        token_hash: &[u8],
        credential_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<TwoFactorToken, AppError> {
        totp::create_two_factor_token(&self.pool, user_id, token_hash, credential_hash, expires_at)
            .await
    }

    async fn consume_two_factor_token(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<TwoFactorToken>, AppError> {
        totp::consume_two_factor_token(&self.pool, token_hash).await
    }

    async fn delete_two_factor_tokens_for_user(&self, user_id: Uuid) -> Result<u64, AppError> {
        totp::delete_two_factor_tokens_for_user(&self.pool, user_id).await
    }

    async fn prune_expired_two_factor_tokens(&self) -> Result<u64, AppError> {
        totp::prune_expired_two_factor_tokens(&self.pool).await
    }

    async fn prune_used_codes(&self, max_age: Duration) -> Result<u64, AppError> {
        totp::prune_used_codes(&self.pool, max_age).await
    }
}

#[async_trait]
impl DatabaseStore for PostgresStore {
    fn backend(&self) -> DatabaseBackend {
        DatabaseBackend::Postgres
    }

    fn users(&self) -> &dyn UserStore {
        self
    }

    fn sessions(&self) -> &dyn SessionStore {
        self
    }

    fn tokens(&self) -> &dyn TokenStore {
        self
    }

    fn outbox(&self) -> &dyn OutboxStore {
        self
    }

    fn oauth(&self) -> &dyn OAuthStore {
        self
    }

    fn totp(&self) -> &dyn TotpStore {
        self
    }

    async fn begin(&self) -> Result<Box<dyn StoreTx>, AppError> {
        let tx = self.pool.begin().await.map_err(AppError::from)?;
        Ok(Box::new(PostgresTx::new(tx)))
    }

    async fn ping(&self) -> Result<(), AppError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(AppError::from)?;
        Ok(())
    }
}

/// Transaction boundary wrapper for PostgreSQL.
pub struct PostgresTx {
    tx: Arc<Mutex<Option<Transaction<'static, Postgres>>>>,
}

impl PostgresTx {
    pub fn new(tx: Transaction<'static, Postgres>) -> Self {
        Self {
            tx: Arc::new(Mutex::new(Some(tx))),
        }
    }
}

#[async_trait]
impl UserStore for PostgresTx {
    async fn create_user(&self, email: &str, password_hash: &str) -> Result<User, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        auth::create_user(&mut **tx, email, password_hash).await
    }

    async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        auth::get_user_by_id(&mut **tx, id).await
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        auth::get_user_by_email(&mut **tx, email).await
    }

    async fn set_email_verified(&self, user_id: Uuid, verified: bool) -> Result<(), AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        auth::set_email_verified(&mut **tx, user_id, verified).await
    }

    async fn update_password_hash(&self, user_id: Uuid, new_hash: &str) -> Result<(), AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        auth::update_password_hash(&mut **tx, user_id, new_hash).await
    }

    async fn delete_user(&self, user_id: Uuid) -> Result<bool, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        auth::delete_user(&mut **tx, user_id).await
    }
}

#[async_trait]
impl SessionStore for PostgresTx {
    async fn create_session(
        &self,
        user_id: Uuid,
        token_hash: &str,
        session_type: &str,
        csrf_token: Option<&str>,
        absolute_expires_at: DateTime<Utc>,
    ) -> Result<Session, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        session::create_session(
            &mut **tx,
            user_id,
            token_hash,
            session_type,
            csrf_token,
            absolute_expires_at,
        )
        .await
    }

    async fn get_session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<Session>, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        session::get_session_by_token_hash(&mut **tx, token_hash).await
    }

    async fn touch_session(
        &self,
        session_id: Uuid,
        last_active_at: DateTime<Utc>,
    ) -> Result<(), AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        session::touch_session(&mut **tx, session_id, last_active_at).await
    }

    async fn rotate_session(
        &self,
        session_id: Uuid,
        new_token_hash: &str,
        new_csrf_token: Option<&str>,
        last_active_at: DateTime<Utc>,
    ) -> Result<(), AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        session::rotate_session(
            &mut **tx,
            session_id,
            new_token_hash,
            new_csrf_token,
            last_active_at,
        )
        .await
    }

    async fn delete_session(&self, session_id: Uuid) -> Result<(), AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        session::delete_session(&mut **tx, session_id).await
    }

    async fn delete_by_token_hash(&self, token_hash: &str) -> Result<bool, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        session::delete_by_token_hash(&mut **tx, token_hash).await
    }

    async fn delete_user_sessions(&self, user_id: Uuid) -> Result<u64, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        session::delete_user_sessions(&mut **tx, user_id).await
    }

    async fn list_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        session::list_user_sessions(&mut **tx, user_id).await
    }

    async fn delete_expired_sessions(&self) -> Result<u64, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        session::delete_expired_sessions(&mut **tx).await
    }
}

#[async_trait]
impl TokenStore for PostgresTx {
    async fn create_verification_token(
        &self,
        user_id: Uuid,
        token_hash: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<VerificationToken, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        auth::create_verification_token(&mut **tx, user_id, token_hash, expires_at).await
    }

    async fn consume_verification_token(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<VerificationToken>, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        auth::consume_verification_token(&mut **tx, token_hash).await
    }

    async fn create_password_reset_token(
        &self,
        user_id: Uuid,
        token_hash: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<PasswordResetToken, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        auth::create_password_reset_token(&mut **tx, user_id, token_hash, expires_at).await
    }

    async fn consume_password_reset_token(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<PasswordResetToken>, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        auth::consume_password_reset_token(&mut **tx, token_hash).await
    }

    async fn delete_user_password_reset_tokens(&self, user_id: Uuid) -> Result<u64, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        auth::delete_user_password_reset_tokens(&mut **tx, user_id).await
    }

    async fn delete_verification_tokens_for_user(&self, user_id: Uuid) -> Result<u64, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        auth::delete_verification_tokens_for_user(&mut **tx, user_id).await
    }
}

#[async_trait]
impl OutboxStore for PostgresTx {
    async fn insert_outbox(
        &self,
        recipient: &str,
        email_type: &str,
        payload: serde_json::Value,
    ) -> Result<EmailOutbox, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        outbox::insert_outbox(&mut **tx, recipient, email_type, payload).await
    }

    async fn claim_pending_outbox(
        &self,
        _batch_size: u32,
        _lock_duration: Duration,
    ) -> Result<Vec<EmailOutbox>, AppError> {
        // Outbox batch claiming is managed at the pool level, not inside an arbitrary caller transaction
        Err(AppError::Database(crate::db::DbError::new(
            "outbox batch claiming is not supported inside a child transaction",
        )))
    }

    async fn mark_outbox_sent(&self, id: Uuid) -> Result<(), AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        outbox::mark_outbox_sent(&mut **tx, id).await
    }

    async fn record_outbox_retry(
        &self,
        id: Uuid,
        retry_count: i32,
        next_retry_at: DateTime<Utc>,
        error_log: &str,
    ) -> Result<(), AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        outbox::record_outbox_retry(&mut **tx, id, retry_count, next_retry_at, error_log).await
    }

    async fn mark_outbox_failed(&self, id: Uuid, error_log: &str) -> Result<(), AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        outbox::mark_outbox_failed(&mut **tx, id, error_log).await
    }

    async fn cleanup_sent_outbox(&self, retention_duration: Duration) -> Result<u64, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        outbox::cleanup_sent_outbox(&mut **tx, retention_duration).await
    }

    async fn recover_stale_processing(&self, _stale_duration: Duration) -> Result<u64, AppError> {
        // Recovery runs across the pool
        Err(AppError::Database(crate::db::DbError::new(
            "stale outbox recovery is not supported inside a child transaction",
        )))
    }
}

#[async_trait]
impl OAuthStore for PostgresTx {
    async fn get_account(
        &self,
        provider_id: &str,
        provider_user_id: &str,
    ) -> Result<Option<OAuthAccount>, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        oauth::get_account(&mut **tx, provider_id, provider_user_id).await
    }

    async fn list_accounts_for_user(&self, user_id: Uuid) -> Result<Vec<OAuthAccount>, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        oauth::list_accounts_for_user(&mut **tx, user_id).await
    }

    async fn link_account(
        &self,
        user_id: Uuid,
        provider_id: &str,
        provider_user_id: &str,
        email: &str,
    ) -> Result<OAuthAccount, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        oauth::link_account(&mut **tx, user_id, provider_id, provider_user_id, email).await
    }

    async fn unlink_account(&self, user_id: Uuid, provider_id: &str) -> Result<bool, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        oauth::unlink_account(&mut **tx, user_id, provider_id).await
    }
}

#[async_trait]
impl TotpStore for PostgresTx {
    async fn get_secret(&self, user_id: Uuid) -> Result<Option<TotpSecret>, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        totp::get_secret(&mut **tx, user_id).await
    }

    async fn upsert_secret(
        &self,
        user_id: Uuid,
        encrypted_secret: &[u8],
        backup_codes: serde_json::Value,
    ) -> Result<TotpSecret, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        totp::upsert_secret(&mut **tx, user_id, encrypted_secret, backup_codes).await
    }

    async fn enable_totp(&self, user_id: Uuid) -> Result<bool, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        totp::enable_totp(&mut **tx, user_id).await
    }

    async fn disable_totp(&self, user_id: Uuid) -> Result<bool, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        totp::disable_totp(&mut **tx, user_id).await
    }

    async fn record_used_code(&self, user_id: Uuid, code_hash: &[u8]) -> Result<bool, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        totp::record_used_code(&mut **tx, user_id, code_hash).await
    }

    async fn is_code_used(&self, user_id: Uuid, code_hash: &[u8]) -> Result<bool, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        totp::is_code_used(&mut **tx, user_id, code_hash).await
    }

    async fn create_two_factor_token(
        &self,
        user_id: Uuid,
        token_hash: &[u8],
        credential_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<TwoFactorToken, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        totp::create_two_factor_token(&mut **tx, user_id, token_hash, credential_hash, expires_at)
            .await
    }

    async fn consume_two_factor_token(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<TwoFactorToken>, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        totp::consume_two_factor_token(&mut **tx, token_hash).await
    }

    async fn delete_two_factor_tokens_for_user(&self, user_id: Uuid) -> Result<u64, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        totp::delete_two_factor_tokens_for_user(&mut **tx, user_id).await
    }

    async fn prune_expired_two_factor_tokens(&self) -> Result<u64, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        totp::prune_expired_two_factor_tokens(&mut **tx).await
    }

    async fn prune_used_codes(&self, max_age: Duration) -> Result<u64, AppError> {
        let mut guard = self.tx.lock().await;
        let tx = guard.as_mut().ok_or(AppError::Internal)?;
        totp::prune_used_codes(&mut **tx, max_age).await
    }
}

#[async_trait]
impl StoreTx for PostgresTx {
    fn users(&mut self) -> &mut dyn UserStore {
        self
    }

    fn sessions(&mut self) -> &mut dyn SessionStore {
        self
    }

    fn tokens(&mut self) -> &mut dyn TokenStore {
        self
    }

    fn outbox(&mut self) -> &mut dyn OutboxStore {
        self
    }

    fn oauth(&mut self) -> &mut dyn OAuthStore {
        self
    }

    fn totp(&mut self) -> &mut dyn TotpStore {
        self
    }

    async fn commit(self: Box<Self>) -> Result<(), AppError> {
        let mut guard = self.tx.lock().await;
        if let Some(tx) = guard.take() {
            tx.commit().await.map_err(AppError::from)?;
        }
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> Result<(), AppError> {
        let mut guard = self.tx.lock().await;
        if let Some(tx) = guard.take() {
            tx.rollback().await.map_err(AppError::from)?;
        }
        Ok(())
    }
}
