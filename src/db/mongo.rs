//! Native MongoDB 6.0+ adapter implementing all stores.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use bson::doc;
use chrono::{DateTime, Utc};
use mongodb::{Client, Database};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    config::{Config, DatabaseBackend},
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

#[allow(clippy::needless_option_as_deref)]
pub mod auth;
pub mod indexes;
pub mod models;
#[allow(clippy::needless_option_as_deref)]
pub mod oauth;
#[allow(clippy::needless_option_as_deref)]
pub mod outbox;
#[allow(clippy::needless_option_as_deref)]
pub mod session;
#[allow(clippy::needless_option_as_deref)]
pub mod totp;

pub use indexes::ensure_indexes;
pub use models::*;

/// Returns true if the MongoDB error represents a duplicate key error (code 11000).
pub fn is_duplicate_key_error(err: &mongodb::error::Error) -> bool {
    use mongodb::error::{ErrorKind, WriteFailure};
    match *err.kind {
        ErrorKind::Write(WriteFailure::WriteError(ref write_err)) => write_err.code == 11000,
        ErrorKind::InsertMany(ref insert_err) => {
            if let Some(ref write_errors) = insert_err.write_errors {
                write_errors.iter().any(|e| e.code == 11000)
            } else {
                false
            }
        }
        ErrorKind::Command(ref cmd_err) => cmd_err.code == 11000,
        ErrorKind::Custom(ref any) => {
            if let Some(s) = any.downcast_ref::<&'static str>() {
                s.contains("E11000") || s.contains("duplicate key error")
            } else if let Some(s) = any.downcast_ref::<String>() {
                s.contains("E11000") || s.contains("duplicate key error")
            } else {
                false
            }
        }
        _ => {
            let msg = err.to_string();
            msg.contains("E11000") || msg.contains("duplicate key error")
        }
    }
}

/// MongoDB database store adapter.
#[derive(Clone, Debug)]
pub struct MongoStore {
    client: Client,
    db: Database,
    is_replica_set: bool,
    allow_non_transactional_standalone: bool,
}

impl MongoStore {
    /// Creates a new `MongoStore` wrapping the provided [`Client`] and target database.
    pub fn new(
        client: Client,
        database_name: &str,
        is_replica_set: bool,
        allow_non_transactional_standalone: bool,
    ) -> Self {
        let db = client.database(database_name);
        Self {
            client,
            db,
            is_replica_set,
            allow_non_transactional_standalone,
        }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub fn is_replica_set(&self) -> bool {
        self.is_replica_set
    }

    pub fn allow_non_transactional_standalone(&self) -> bool {
        self.allow_non_transactional_standalone
    }
}

/// Initializes a MongoDB store using configuration parameters from [`Config`].
pub async fn init_mongo_store(cfg: &Config) -> Result<MongoStore, AppError> {
    let mongo_cfg = cfg.mongo.as_ref().cloned().unwrap_or_default();
    let mut client_options = mongodb::options::ClientOptions::parse(&cfg.database_url)
        .await
        .map_err(AppError::from)?;

    client_options.connect_timeout = Some(Duration::from_secs(5));
    client_options.server_selection_timeout = Some(Duration::from_secs(5));
    if cfg.max_connections > 0 {
        client_options.max_pool_size = Some(cfg.max_connections);
    }
    if cfg.min_connections > 0 {
        client_options.min_pool_size = Some(cfg.min_connections);
    }

    let client = Client::with_options(client_options).map_err(AppError::from)?;
    let db = client.database(&mongo_cfg.database_name);

    // Verify connectivity with ping
    db.run_command(doc! { "ping": 1 })
        .await
        .map_err(AppError::from)?;

    // Probe topology via hello command
    let hello_doc = db
        .run_command(doc! { "hello": 1 })
        .await
        .map_err(AppError::from)?;
    let is_replica_set = hello_doc.contains_key("setName")
        || hello_doc
            .get_str("msg")
            .map(|m| m == "isdbgrid")
            .unwrap_or(false);

    // Ensure idempotent indexes
    ensure_indexes(&db).await?;

    Ok(MongoStore::new(
        client,
        &mongo_cfg.database_name,
        is_replica_set,
        mongo_cfg.allow_non_transactional_standalone,
    ))
}

// ─── Sub-store delegation for MongoStore (session = None) ───────────────────

#[async_trait]
impl UserStore for MongoStore {
    async fn create_user(&self, email: &str, password_hash: &str) -> Result<User, AppError> {
        auth::create_user(&self.db, None, email, password_hash).await
    }

    async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>, AppError> {
        auth::get_user_by_id(&self.db, None, id).await
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        auth::get_user_by_email(&self.db, None, email).await
    }

    async fn set_email_verified(&self, user_id: Uuid, verified: bool) -> Result<(), AppError> {
        auth::set_email_verified(&self.db, None, user_id, verified).await
    }

    async fn update_password_hash(&self, user_id: Uuid, new_hash: &str) -> Result<(), AppError> {
        auth::update_password_hash(&self.db, None, user_id, new_hash).await
    }

    async fn delete_user(&self, user_id: Uuid) -> Result<bool, AppError> {
        auth::delete_user(&self.db, None, user_id).await
    }
}

#[async_trait]
impl SessionStore for MongoStore {
    async fn create_session(
        &self,
        user_id: Uuid,
        token_hash: &str,
        session_type: &str,
        csrf_token: Option<&str>,
        absolute_expires_at: DateTime<Utc>,
    ) -> Result<Session, AppError> {
        session::create_session(
            &self.db,
            None,
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
        session::get_session_by_token_hash(&self.db, None, token_hash).await
    }

    async fn touch_session(
        &self,
        session_id: Uuid,
        last_active_at: DateTime<Utc>,
    ) -> Result<(), AppError> {
        session::touch_session(&self.db, None, session_id, last_active_at).await
    }

    async fn rotate_session(
        &self,
        session_id: Uuid,
        new_token_hash: &str,
        new_csrf_token: Option<&str>,
        last_active_at: DateTime<Utc>,
    ) -> Result<(), AppError> {
        session::rotate_session(
            &self.db,
            None,
            session_id,
            new_token_hash,
            new_csrf_token,
            last_active_at,
        )
        .await
    }

    async fn delete_session(&self, session_id: Uuid) -> Result<(), AppError> {
        session::delete_session(&self.db, None, session_id).await
    }

    async fn delete_by_token_hash(&self, token_hash: &str) -> Result<bool, AppError> {
        session::delete_by_token_hash(&self.db, None, token_hash).await
    }

    async fn delete_user_sessions(&self, user_id: Uuid) -> Result<u64, AppError> {
        session::delete_user_sessions(&self.db, None, user_id).await
    }

    async fn list_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, AppError> {
        session::list_user_sessions(&self.db, None, user_id).await
    }

    async fn delete_expired_sessions(&self) -> Result<u64, AppError> {
        session::delete_expired_sessions(&self.db, None).await
    }
}

#[async_trait]
impl TokenStore for MongoStore {
    async fn create_verification_token(
        &self,
        user_id: Uuid,
        token_hash: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<VerificationToken, AppError> {
        auth::create_verification_token(&self.db, None, user_id, token_hash, expires_at).await
    }

    async fn consume_verification_token(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<VerificationToken>, AppError> {
        auth::consume_verification_token(&self.db, None, token_hash).await
    }

    async fn create_password_reset_token(
        &self,
        user_id: Uuid,
        token_hash: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<PasswordResetToken, AppError> {
        auth::create_password_reset_token(&self.db, None, user_id, token_hash, expires_at).await
    }

    async fn consume_password_reset_token(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<PasswordResetToken>, AppError> {
        auth::consume_password_reset_token(&self.db, None, token_hash).await
    }

    async fn delete_user_password_reset_tokens(&self, user_id: Uuid) -> Result<u64, AppError> {
        auth::delete_user_password_reset_tokens(&self.db, None, user_id).await
    }

    async fn delete_verification_tokens_for_user(&self, user_id: Uuid) -> Result<u64, AppError> {
        auth::delete_verification_tokens_for_user(&self.db, None, user_id).await
    }
}

#[async_trait]
impl OutboxStore for MongoStore {
    async fn insert_outbox(
        &self,
        recipient: &str,
        email_type: &str,
        payload: serde_json::Value,
    ) -> Result<EmailOutbox, AppError> {
        outbox::insert_outbox(&self.db, None, recipient, email_type, payload).await
    }

    async fn claim_pending_outbox(
        &self,
        batch_size: u32,
        lock_duration: Duration,
    ) -> Result<Vec<EmailOutbox>, AppError> {
        outbox::claim_pending_outbox(&self.db, None, batch_size, lock_duration).await
    }

    async fn mark_outbox_sent(&self, id: Uuid) -> Result<(), AppError> {
        outbox::mark_outbox_sent(&self.db, None, id).await
    }

    async fn record_outbox_retry(
        &self,
        id: Uuid,
        retry_count: i32,
        next_retry_at: DateTime<Utc>,
        error_log: &str,
    ) -> Result<(), AppError> {
        outbox::record_outbox_retry(&self.db, None, id, retry_count, next_retry_at, error_log).await
    }

    async fn mark_outbox_failed(&self, id: Uuid, error_log: &str) -> Result<(), AppError> {
        outbox::mark_outbox_failed(&self.db, None, id, error_log).await
    }

    async fn cleanup_sent_outbox(&self, retention_duration: Duration) -> Result<u64, AppError> {
        outbox::cleanup_sent_outbox(&self.db, None, retention_duration).await
    }

    async fn recover_stale_processing(&self, stale_duration: Duration) -> Result<u64, AppError> {
        outbox::recover_stale_processing(&self.db, None, stale_duration).await
    }
}

#[async_trait]
impl OAuthStore for MongoStore {
    async fn get_account(
        &self,
        provider_id: &str,
        provider_user_id: &str,
    ) -> Result<Option<OAuthAccount>, AppError> {
        oauth::get_account(&self.db, None, provider_id, provider_user_id).await
    }

    async fn list_accounts_for_user(&self, user_id: Uuid) -> Result<Vec<OAuthAccount>, AppError> {
        oauth::list_accounts_for_user(&self.db, None, user_id).await
    }

    async fn link_account(
        &self,
        user_id: Uuid,
        provider_id: &str,
        provider_user_id: &str,
        email: &str,
    ) -> Result<OAuthAccount, AppError> {
        oauth::link_account(
            &self.db,
            None,
            user_id,
            provider_id,
            provider_user_id,
            email,
        )
        .await
    }

    async fn unlink_account(&self, user_id: Uuid, provider_id: &str) -> Result<bool, AppError> {
        oauth::unlink_account(&self.db, None, user_id, provider_id).await
    }
}

#[async_trait]
impl TotpStore for MongoStore {
    async fn get_secret(&self, user_id: Uuid) -> Result<Option<TotpSecret>, AppError> {
        totp::get_secret(&self.db, None, user_id).await
    }

    async fn upsert_secret(
        &self,
        user_id: Uuid,
        encrypted_secret: &[u8],
        backup_codes: serde_json::Value,
    ) -> Result<TotpSecret, AppError> {
        totp::upsert_secret(&self.db, None, user_id, encrypted_secret, backup_codes).await
    }

    async fn enable_totp(&self, user_id: Uuid) -> Result<bool, AppError> {
        totp::enable_totp(&self.db, None, user_id).await
    }

    async fn disable_totp(&self, user_id: Uuid) -> Result<bool, AppError> {
        totp::disable_totp(&self.db, None, user_id).await
    }

    async fn record_used_code(&self, user_id: Uuid, code_hash: &[u8]) -> Result<bool, AppError> {
        totp::record_used_code(&self.db, None, user_id, code_hash).await
    }

    async fn is_code_used(&self, user_id: Uuid, code_hash: &[u8]) -> Result<bool, AppError> {
        totp::is_code_used(&self.db, None, user_id, code_hash).await
    }

    async fn create_two_factor_token(
        &self,
        user_id: Uuid,
        token_hash: &[u8],
        credential_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<TwoFactorToken, AppError> {
        totp::create_two_factor_token(
            &self.db,
            None,
            user_id,
            token_hash,
            credential_hash,
            expires_at,
        )
        .await
    }

    async fn consume_two_factor_token(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<TwoFactorToken>, AppError> {
        totp::consume_two_factor_token(&self.db, None, token_hash).await
    }

    async fn delete_two_factor_tokens_for_user(&self, user_id: Uuid) -> Result<u64, AppError> {
        totp::delete_two_factor_tokens_for_user(&self.db, None, user_id).await
    }

    async fn prune_expired_two_factor_tokens(&self) -> Result<u64, AppError> {
        totp::prune_expired_two_factor_tokens(&self.db, None).await
    }

    async fn prune_used_codes(&self, max_age: Duration) -> Result<u64, AppError> {
        totp::prune_used_codes(&self.db, None, max_age).await
    }
}

#[async_trait]
impl DatabaseStore for MongoStore {
    fn backend(&self) -> DatabaseBackend {
        DatabaseBackend::Mongodb
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
        if !self.is_replica_set {
            if !self.allow_non_transactional_standalone {
                return Err(AppError::TransactionNotSupported);
            }
            return Ok(Box::new(MongoTx::standalone(self.db.clone())));
        }

        let mut session = self.client.start_session().await.map_err(AppError::from)?;
        session.start_transaction().await.map_err(AppError::from)?;
        Ok(Box::new(MongoTx::session(self.db.clone(), session)))
    }

    async fn ping(&self) -> Result<(), AppError> {
        self.db
            .run_command(doc! { "ping": 1 })
            .await
            .map_err(AppError::from)?;
        Ok(())
    }
}

// ─── MongoTx Transaction Wrapper ────────────────────────────────────────────

/// Transaction boundary wrapper for MongoDB.
pub struct MongoTx {
    db: Database,
    session: Option<Arc<Mutex<mongodb::ClientSession>>>,
    active: Arc<AtomicBool>,
}

impl MongoTx {
    /// Creates a replica-set backed transactional session.
    pub fn session(db: Database, session: mongodb::ClientSession) -> Self {
        Self {
            db,
            session: Some(Arc::new(Mutex::new(session))),
            active: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Creates an opt-in non-transactional standalone pseudo-transaction.
    pub fn standalone(db: Database) -> Self {
        Self {
            db,
            session: None,
            active: Arc::new(AtomicBool::new(true)),
        }
    }
}

#[async_trait]
impl UserStore for MongoTx {
    async fn create_user(&self, email: &str, password_hash: &str) -> Result<User, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                auth::create_user(&self.db, Some(&mut *guard), email, password_hash).await
            }
            None => auth::create_user(&self.db, None, email, password_hash).await,
        }
    }

    async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                auth::get_user_by_id(&self.db, Some(&mut *guard), id).await
            }
            None => auth::get_user_by_id(&self.db, None, id).await,
        }
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                auth::get_user_by_email(&self.db, Some(&mut *guard), email).await
            }
            None => auth::get_user_by_email(&self.db, None, email).await,
        }
    }

    async fn set_email_verified(&self, user_id: Uuid, verified: bool) -> Result<(), AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                auth::set_email_verified(&self.db, Some(&mut *guard), user_id, verified).await
            }
            None => auth::set_email_verified(&self.db, None, user_id, verified).await,
        }
    }

    async fn update_password_hash(&self, user_id: Uuid, new_hash: &str) -> Result<(), AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                auth::update_password_hash(&self.db, Some(&mut *guard), user_id, new_hash).await
            }
            None => auth::update_password_hash(&self.db, None, user_id, new_hash).await,
        }
    }

    async fn delete_user(&self, user_id: Uuid) -> Result<bool, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                auth::delete_user(&self.db, Some(&mut *guard), user_id).await
            }
            None => auth::delete_user(&self.db, None, user_id).await,
        }
    }
}

#[async_trait]
impl SessionStore for MongoTx {
    async fn create_session(
        &self,
        user_id: Uuid,
        token_hash: &str,
        session_type: &str,
        csrf_token: Option<&str>,
        absolute_expires_at: DateTime<Utc>,
    ) -> Result<Session, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                session::create_session(
                    &self.db,
                    Some(&mut *guard),
                    user_id,
                    token_hash,
                    session_type,
                    csrf_token,
                    absolute_expires_at,
                )
                .await
            }
            None => {
                session::create_session(
                    &self.db,
                    None,
                    user_id,
                    token_hash,
                    session_type,
                    csrf_token,
                    absolute_expires_at,
                )
                .await
            }
        }
    }

    async fn get_session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<Session>, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                session::get_session_by_token_hash(&self.db, Some(&mut *guard), token_hash).await
            }
            None => session::get_session_by_token_hash(&self.db, None, token_hash).await,
        }
    }

    async fn touch_session(
        &self,
        session_id: Uuid,
        last_active_at: DateTime<Utc>,
    ) -> Result<(), AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                session::touch_session(&self.db, Some(&mut *guard), session_id, last_active_at)
                    .await
            }
            None => session::touch_session(&self.db, None, session_id, last_active_at).await,
        }
    }

    async fn rotate_session(
        &self,
        session_id: Uuid,
        new_token_hash: &str,
        new_csrf_token: Option<&str>,
        last_active_at: DateTime<Utc>,
    ) -> Result<(), AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                session::rotate_session(
                    &self.db,
                    Some(&mut *guard),
                    session_id,
                    new_token_hash,
                    new_csrf_token,
                    last_active_at,
                )
                .await
            }
            None => {
                session::rotate_session(
                    &self.db,
                    None,
                    session_id,
                    new_token_hash,
                    new_csrf_token,
                    last_active_at,
                )
                .await
            }
        }
    }

    async fn delete_session(&self, session_id: Uuid) -> Result<(), AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                session::delete_session(&self.db, Some(&mut *guard), session_id).await
            }
            None => session::delete_session(&self.db, None, session_id).await,
        }
    }

    async fn delete_by_token_hash(&self, token_hash: &str) -> Result<bool, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                session::delete_by_token_hash(&self.db, Some(&mut *guard), token_hash).await
            }
            None => session::delete_by_token_hash(&self.db, None, token_hash).await,
        }
    }

    async fn delete_user_sessions(&self, user_id: Uuid) -> Result<u64, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                session::delete_user_sessions(&self.db, Some(&mut *guard), user_id).await
            }
            None => session::delete_user_sessions(&self.db, None, user_id).await,
        }
    }

    async fn list_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                session::list_user_sessions(&self.db, Some(&mut *guard), user_id).await
            }
            None => session::list_user_sessions(&self.db, None, user_id).await,
        }
    }

    async fn delete_expired_sessions(&self) -> Result<u64, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                session::delete_expired_sessions(&self.db, Some(&mut *guard)).await
            }
            None => session::delete_expired_sessions(&self.db, None).await,
        }
    }
}

#[async_trait]
impl TokenStore for MongoTx {
    async fn create_verification_token(
        &self,
        user_id: Uuid,
        token_hash: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<VerificationToken, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                auth::create_verification_token(
                    &self.db,
                    Some(&mut *guard),
                    user_id,
                    token_hash,
                    expires_at,
                )
                .await
            }
            None => {
                auth::create_verification_token(&self.db, None, user_id, token_hash, expires_at)
                    .await
            }
        }
    }

    async fn consume_verification_token(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<VerificationToken>, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                auth::consume_verification_token(&self.db, Some(&mut *guard), token_hash).await
            }
            None => auth::consume_verification_token(&self.db, None, token_hash).await,
        }
    }

    async fn create_password_reset_token(
        &self,
        user_id: Uuid,
        token_hash: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<PasswordResetToken, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                auth::create_password_reset_token(
                    &self.db,
                    Some(&mut *guard),
                    user_id,
                    token_hash,
                    expires_at,
                )
                .await
            }
            None => {
                auth::create_password_reset_token(&self.db, None, user_id, token_hash, expires_at)
                    .await
            }
        }
    }

    async fn consume_password_reset_token(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<PasswordResetToken>, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                auth::consume_password_reset_token(&self.db, Some(&mut *guard), token_hash).await
            }
            None => auth::consume_password_reset_token(&self.db, None, token_hash).await,
        }
    }

    async fn delete_user_password_reset_tokens(&self, user_id: Uuid) -> Result<u64, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                auth::delete_user_password_reset_tokens(&self.db, Some(&mut *guard), user_id).await
            }
            None => auth::delete_user_password_reset_tokens(&self.db, None, user_id).await,
        }
    }

    async fn delete_verification_tokens_for_user(&self, user_id: Uuid) -> Result<u64, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                auth::delete_verification_tokens_for_user(&self.db, Some(&mut *guard), user_id)
                    .await
            }
            None => auth::delete_verification_tokens_for_user(&self.db, None, user_id).await,
        }
    }
}

#[async_trait]
impl OutboxStore for MongoTx {
    async fn insert_outbox(
        &self,
        recipient: &str,
        email_type: &str,
        payload: serde_json::Value,
    ) -> Result<EmailOutbox, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                outbox::insert_outbox(&self.db, Some(&mut *guard), recipient, email_type, payload)
                    .await
            }
            None => outbox::insert_outbox(&self.db, None, recipient, email_type, payload).await,
        }
    }

    async fn claim_pending_outbox(
        &self,
        batch_size: u32,
        lock_duration: Duration,
    ) -> Result<Vec<EmailOutbox>, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                outbox::claim_pending_outbox(&self.db, Some(&mut *guard), batch_size, lock_duration)
                    .await
            }
            None => outbox::claim_pending_outbox(&self.db, None, batch_size, lock_duration).await,
        }
    }

    async fn mark_outbox_sent(&self, id: Uuid) -> Result<(), AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                outbox::mark_outbox_sent(&self.db, Some(&mut *guard), id).await
            }
            None => outbox::mark_outbox_sent(&self.db, None, id).await,
        }
    }

    async fn record_outbox_retry(
        &self,
        id: Uuid,
        retry_count: i32,
        next_retry_at: DateTime<Utc>,
        error_log: &str,
    ) -> Result<(), AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                outbox::record_outbox_retry(
                    &self.db,
                    Some(&mut *guard),
                    id,
                    retry_count,
                    next_retry_at,
                    error_log,
                )
                .await
            }
            None => {
                outbox::record_outbox_retry(
                    &self.db,
                    None,
                    id,
                    retry_count,
                    next_retry_at,
                    error_log,
                )
                .await
            }
        }
    }

    async fn mark_outbox_failed(&self, id: Uuid, error_log: &str) -> Result<(), AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                outbox::mark_outbox_failed(&self.db, Some(&mut *guard), id, error_log).await
            }
            None => outbox::mark_outbox_failed(&self.db, None, id, error_log).await,
        }
    }

    async fn cleanup_sent_outbox(&self, retention_duration: Duration) -> Result<u64, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                outbox::cleanup_sent_outbox(&self.db, Some(&mut *guard), retention_duration).await
            }
            None => outbox::cleanup_sent_outbox(&self.db, None, retention_duration).await,
        }
    }

    async fn recover_stale_processing(&self, stale_duration: Duration) -> Result<u64, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                outbox::recover_stale_processing(&self.db, Some(&mut *guard), stale_duration).await
            }
            None => outbox::recover_stale_processing(&self.db, None, stale_duration).await,
        }
    }
}

#[async_trait]
impl OAuthStore for MongoTx {
    async fn get_account(
        &self,
        provider_id: &str,
        provider_user_id: &str,
    ) -> Result<Option<OAuthAccount>, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                oauth::get_account(&self.db, Some(&mut *guard), provider_id, provider_user_id).await
            }
            None => oauth::get_account(&self.db, None, provider_id, provider_user_id).await,
        }
    }

    async fn list_accounts_for_user(&self, user_id: Uuid) -> Result<Vec<OAuthAccount>, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                oauth::list_accounts_for_user(&self.db, Some(&mut *guard), user_id).await
            }
            None => oauth::list_accounts_for_user(&self.db, None, user_id).await,
        }
    }

    async fn link_account(
        &self,
        user_id: Uuid,
        provider_id: &str,
        provider_user_id: &str,
        email: &str,
    ) -> Result<OAuthAccount, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                oauth::link_account(
                    &self.db,
                    Some(&mut *guard),
                    user_id,
                    provider_id,
                    provider_user_id,
                    email,
                )
                .await
            }
            None => {
                oauth::link_account(
                    &self.db,
                    None,
                    user_id,
                    provider_id,
                    provider_user_id,
                    email,
                )
                .await
            }
        }
    }

    async fn unlink_account(&self, user_id: Uuid, provider_id: &str) -> Result<bool, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                oauth::unlink_account(&self.db, Some(&mut *guard), user_id, provider_id).await
            }
            None => oauth::unlink_account(&self.db, None, user_id, provider_id).await,
        }
    }
}

#[async_trait]
impl TotpStore for MongoTx {
    async fn get_secret(&self, user_id: Uuid) -> Result<Option<TotpSecret>, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                totp::get_secret(&self.db, Some(&mut *guard), user_id).await
            }
            None => totp::get_secret(&self.db, None, user_id).await,
        }
    }

    async fn upsert_secret(
        &self,
        user_id: Uuid,
        encrypted_secret: &[u8],
        backup_codes: serde_json::Value,
    ) -> Result<TotpSecret, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                totp::upsert_secret(
                    &self.db,
                    Some(&mut *guard),
                    user_id,
                    encrypted_secret,
                    backup_codes,
                )
                .await
            }
            None => {
                totp::upsert_secret(&self.db, None, user_id, encrypted_secret, backup_codes).await
            }
        }
    }

    async fn enable_totp(&self, user_id: Uuid) -> Result<bool, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                totp::enable_totp(&self.db, Some(&mut *guard), user_id).await
            }
            None => totp::enable_totp(&self.db, None, user_id).await,
        }
    }

    async fn disable_totp(&self, user_id: Uuid) -> Result<bool, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                totp::disable_totp(&self.db, Some(&mut *guard), user_id).await
            }
            None => totp::disable_totp(&self.db, None, user_id).await,
        }
    }

    async fn record_used_code(&self, user_id: Uuid, code_hash: &[u8]) -> Result<bool, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                totp::record_used_code(&self.db, Some(&mut *guard), user_id, code_hash).await
            }
            None => totp::record_used_code(&self.db, None, user_id, code_hash).await,
        }
    }

    async fn is_code_used(&self, user_id: Uuid, code_hash: &[u8]) -> Result<bool, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                totp::is_code_used(&self.db, Some(&mut *guard), user_id, code_hash).await
            }
            None => totp::is_code_used(&self.db, None, user_id, code_hash).await,
        }
    }

    async fn create_two_factor_token(
        &self,
        user_id: Uuid,
        token_hash: &[u8],
        credential_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<TwoFactorToken, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                totp::create_two_factor_token(
                    &self.db,
                    Some(&mut *guard),
                    user_id,
                    token_hash,
                    credential_hash,
                    expires_at,
                )
                .await
            }
            None => {
                totp::create_two_factor_token(
                    &self.db,
                    None,
                    user_id,
                    token_hash,
                    credential_hash,
                    expires_at,
                )
                .await
            }
        }
    }

    async fn consume_two_factor_token(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<TwoFactorToken>, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                totp::consume_two_factor_token(&self.db, Some(&mut *guard), token_hash).await
            }
            None => totp::consume_two_factor_token(&self.db, None, token_hash).await,
        }
    }

    async fn delete_two_factor_tokens_for_user(&self, user_id: Uuid) -> Result<u64, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                totp::delete_two_factor_tokens_for_user(&self.db, Some(&mut *guard), user_id).await
            }
            None => totp::delete_two_factor_tokens_for_user(&self.db, None, user_id).await,
        }
    }

    async fn prune_expired_two_factor_tokens(&self) -> Result<u64, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                totp::prune_expired_two_factor_tokens(&self.db, Some(&mut *guard)).await
            }
            None => totp::prune_expired_two_factor_tokens(&self.db, None).await,
        }
    }

    async fn prune_used_codes(&self, max_age: Duration) -> Result<u64, AppError> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        match &self.session {
            Some(s) => {
                let mut guard = s.lock().await;
                totp::prune_used_codes(&self.db, Some(&mut *guard), max_age).await
            }
            None => totp::prune_used_codes(&self.db, None, max_age).await,
        }
    }
}

#[async_trait]
impl StoreTx for MongoTx {
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
        if !self.active.swap(false, Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        if let Some(s) = &self.session {
            let mut session = s.lock().await;
            session.commit_transaction().await.map_err(AppError::from)?;
        }
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> Result<(), AppError> {
        if !self.active.swap(false, Ordering::SeqCst) {
            return Err(AppError::Internal);
        }
        if let Some(s) = &self.session {
            let mut session = s.lock().await;
            session.abort_transaction().await.map_err(AppError::from)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_standalone_fails_closed_by_default() {
        let client = Client::with_uri_str("mongodb://127.0.0.1:27017")
            .await
            .unwrap();
        let store = MongoStore::new(client, "test_db", false, false);
        assert!(!store.is_replica_set());
        assert!(!store.allow_non_transactional_standalone());

        let begin_res = store.begin().await;
        assert!(matches!(begin_res, Err(AppError::TransactionNotSupported)));
    }

    #[tokio::test]
    async fn test_standalone_opt_in_allows_pseudo_transaction() {
        let client = Client::with_uri_str("mongodb://127.0.0.1:27017")
            .await
            .unwrap();
        let store = MongoStore::new(client, "test_db", false, true);
        assert!(!store.is_replica_set());
        assert!(store.allow_non_transactional_standalone());

        let begin_res = store.begin().await;
        assert!(begin_res.is_ok());
        let tx = begin_res.unwrap();
        assert!(tx.commit().await.is_ok());
    }
}
