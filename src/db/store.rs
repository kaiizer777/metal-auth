use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    db::models::{
        EmailOutbox, OAuthAccount, PasswordResetToken, Session, TotpSecret, TwoFactorToken, User,
        VerificationToken,
    },
    error::AppError,
};

/// Storage operations on user accounts and authentication credentials.
#[async_trait]
pub trait UserStore: Send + Sync {
    async fn create_user(&self, email: &str, password_hash: &str) -> Result<User, AppError>;
    async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>, AppError>;
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AppError>;
    async fn set_email_verified(&self, user_id: Uuid, verified: bool) -> Result<(), AppError>;
    async fn update_password_hash(&self, user_id: Uuid, new_hash: &str) -> Result<(), AppError>;
    async fn delete_user(&self, user_id: Uuid) -> Result<bool, AppError>;
}

/// Storage operations on user sessions and tokens.
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create_session(
        &self,
        user_id: Uuid,
        token_hash: &str,
        session_type: &str,
        csrf_token: Option<&str>,
        absolute_expires_at: DateTime<Utc>,
    ) -> Result<Session, AppError>;
    async fn get_session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<Session>, AppError>;
    async fn touch_session(
        &self,
        session_id: Uuid,
        last_active_at: DateTime<Utc>,
    ) -> Result<(), AppError>;
    async fn rotate_session(
        &self,
        session_id: Uuid,
        new_token_hash: &str,
        new_csrf_token: Option<&str>,
        last_active_at: DateTime<Utc>,
    ) -> Result<(), AppError>;
    async fn delete_session(&self, session_id: Uuid) -> Result<(), AppError>;
    async fn delete_by_token_hash(&self, token_hash: &str) -> Result<bool, AppError>;
    async fn delete_user_sessions(&self, user_id: Uuid) -> Result<u64, AppError>;
    async fn list_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, AppError>;
    async fn delete_expired_sessions(&self) -> Result<u64, AppError>;
}

/// Storage operations for single-use email verification and password reset tokens.
#[async_trait]
pub trait TokenStore: Send + Sync {
    async fn create_verification_token(
        &self,
        user_id: Uuid,
        token_hash: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<VerificationToken, AppError>;
    async fn consume_verification_token(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<VerificationToken>, AppError>;
    async fn create_password_reset_token(
        &self,
        user_id: Uuid,
        token_hash: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<PasswordResetToken, AppError>;
    async fn consume_password_reset_token(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<PasswordResetToken>, AppError>;
    async fn delete_user_password_reset_tokens(&self, user_id: Uuid) -> Result<u64, AppError>;
    async fn delete_verification_tokens_for_user(&self, user_id: Uuid) -> Result<u64, AppError>;
}

/// Storage operations for transactional email outbox records.
#[async_trait]
pub trait OutboxStore: Send + Sync {
    async fn insert_outbox(
        &self,
        recipient: &str,
        email_type: &str,
        payload: serde_json::Value,
    ) -> Result<EmailOutbox, AppError>;
    async fn claim_pending_outbox(
        &self,
        batch_size: u32,
        lock_duration: Duration,
    ) -> Result<Vec<EmailOutbox>, AppError>;
    async fn mark_outbox_sent(&self, id: Uuid) -> Result<(), AppError>;
    async fn record_outbox_retry(
        &self,
        id: Uuid,
        retry_count: i32,
        next_retry_at: DateTime<Utc>,
        error_log: &str,
    ) -> Result<(), AppError>;
    async fn mark_outbox_failed(&self, id: Uuid, error_log: &str) -> Result<(), AppError>;
    async fn cleanup_sent_outbox(&self, retention_duration: Duration) -> Result<u64, AppError>;
    async fn recover_stale_processing(&self, stale_duration: Duration) -> Result<u64, AppError>;
}

/// Storage operations for federated OAuth accounts linked to users.
#[async_trait]
pub trait OAuthStore: Send + Sync {
    async fn get_account(
        &self,
        provider_id: &str,
        provider_user_id: &str,
    ) -> Result<Option<OAuthAccount>, AppError>;
    async fn list_accounts_for_user(&self, user_id: Uuid) -> Result<Vec<OAuthAccount>, AppError>;
    async fn link_account(
        &self,
        user_id: Uuid,
        provider_id: &str,
        provider_user_id: &str,
        email: &str,
    ) -> Result<OAuthAccount, AppError>;
    async fn unlink_account(&self, user_id: Uuid, provider_id: &str) -> Result<bool, AppError>;
}

/// Storage operations for TOTP two-factor authentication enrollments, codes, and challenges.
#[async_trait]
pub trait TotpStore: Send + Sync {
    async fn get_secret(&self, user_id: Uuid) -> Result<Option<TotpSecret>, AppError>;
    async fn upsert_secret(
        &self,
        user_id: Uuid,
        encrypted_secret: &[u8],
        backup_codes: serde_json::Value,
    ) -> Result<TotpSecret, AppError>;
    async fn enable_totp(&self, user_id: Uuid) -> Result<bool, AppError>;
    async fn disable_totp(&self, user_id: Uuid) -> Result<bool, AppError>;
    async fn record_used_code(&self, user_id: Uuid, code_hash: &[u8]) -> Result<bool, AppError>;
    async fn is_code_used(&self, user_id: Uuid, code_hash: &[u8]) -> Result<bool, AppError>;
    async fn create_two_factor_token(
        &self,
        user_id: Uuid,
        token_hash: &[u8],
        credential_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<TwoFactorToken, AppError>;
    async fn consume_two_factor_token(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<TwoFactorToken>, AppError>;
    async fn delete_two_factor_tokens_for_user(&self, user_id: Uuid) -> Result<u64, AppError>;
    async fn prune_expired_two_factor_tokens(&self) -> Result<u64, AppError>;
    async fn prune_used_codes(&self, max_age: Duration) -> Result<u64, AppError>;
}

/// Transaction boundary granting sub-store access within an isolated atomic transaction.
#[async_trait]
pub trait StoreTx: Send + Sync {
    fn users(&mut self) -> &mut dyn UserStore;
    fn sessions(&mut self) -> &mut dyn SessionStore;
    fn tokens(&mut self) -> &mut dyn TokenStore;
    fn outbox(&mut self) -> &mut dyn OutboxStore;
    fn oauth(&mut self) -> &mut dyn OAuthStore;
    fn totp(&mut self) -> &mut dyn TotpStore;
    async fn commit(self: Box<Self>) -> Result<(), AppError>;
    async fn rollback(self: Box<Self>) -> Result<(), AppError>;
}

/// Root database storage handle providing access to domain sub-stores and transaction demarcation.
#[async_trait]
pub trait DatabaseStore: Send + Sync + std::fmt::Debug {
    fn backend(&self) -> crate::config::DatabaseBackend;
    fn users(&self) -> &dyn UserStore;
    fn sessions(&self) -> &dyn SessionStore;
    fn tokens(&self) -> &dyn TokenStore;
    fn outbox(&self) -> &dyn OutboxStore;
    fn oauth(&self) -> &dyn OAuthStore;
    fn totp(&self) -> &dyn TotpStore;
    async fn begin(&self) -> Result<Box<dyn StoreTx>, AppError>;
    async fn ping(&self) -> Result<(), AppError>;
}
