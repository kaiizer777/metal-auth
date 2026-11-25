use std::fmt;
use std::sync::Arc;
#[allow(unused_imports)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tracing::{Instrument, error, info_span, warn};

use crate::email::OutboxWorkerConfig;
use crate::email::hook::{DynError, SharedEmailSender, sanitize_sender_error};
use crate::email::payload::{PasswordResetEmailPayload, VerificationEmailPayload};

fn percent_encode_token(input: &str) -> String {
    let needs_encoding = input.bytes().any(|b| {
        !matches!(
            b,
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~'
        )
    });
    if !needs_encoding {
        return input.to_string();
    }

    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(input.len().saturating_mul(3));
    for byte in input.bytes() {
        if matches!(
            byte,
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~'
        ) {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX_UPPER[(byte >> 4) as usize] as char);
            encoded.push(HEX_UPPER[(byte & 0x0F) as usize] as char);
        }
    }
    encoded
}

/// Constructs a verification URL from a base URL and an unencoded token.
pub fn build_verification_url(base_url: &str, token: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let encoded_token = percent_encode_token(token);
    format!("{}/auth/verify/email?token={}", base, encoded_token)
}

/// Constructs a password reset URL from a base URL and an unencoded token.
pub fn build_reset_url(base_url: &str, token: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let encoded_token = percent_encode_token(token);
    format!("{}/auth/password/reset?token={}", base, encoded_token)
}

/// Email dispatcher responsible for URL formatting and email delivery dispatch.
#[derive(Clone)]
pub struct EmailDispatcher {
    sender: Option<SharedEmailSender>,
    timeout: Duration,
    base_url: Option<String>,
    #[allow(dead_code)]
    notify: Arc<tokio::sync::Notify>,
    #[allow(dead_code)]
    worker_started: Arc<AtomicBool>,
    outbox_config: OutboxWorkerConfig,
    /// Inline (caller-blocking) delivery — test-only, absent from default builds.
    #[cfg(any(test, feature = "test-utils"))]
    block_on_delivery: bool,
    /// First inline-batch failure — test-only, so a claim error is diagnosable instead of
    /// surfacing as the caller's delivery wait timing out.
    ///
    /// Write-once, read-any: `OnceLock` needs no `Option`, no mutex and no poison handling.
    /// `Arc` only because the dispatcher is `Clone`, like `notify` and `worker_started`.
    #[cfg(any(test, feature = "test-utils"))]
    inline_error: Arc<std::sync::OnceLock<String>>,
}
impl EmailDispatcher {
    /// Creates a dispatcher that always delivers on a detached Tokio task.
    pub fn new(sender: Option<SharedEmailSender>, timeout: Duration) -> Self {
        Self {
            sender,
            timeout,
            base_url: None,
            notify: Arc::new(tokio::sync::Notify::new()),
            worker_started: Arc::new(AtomicBool::new(false)),
            outbox_config: OutboxWorkerConfig::default(),
            #[cfg(any(test, feature = "test-utils"))]
            block_on_delivery: false,
            #[cfg(any(test, feature = "test-utils"))]
            inline_error: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Creates a dispatcher that delivers inline, blocking the caller until the sender
    /// finishes or the timeout elapses.
    ///
    /// Test-only: production request paths must never wait for mailer latency, so this
    /// constructor does not exist in a default build.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_blocking(sender: Option<SharedEmailSender>, timeout: Duration) -> Self {
        Self {
            block_on_delivery: true,
            ..Self::new(sender, timeout)
        }
    }

    /// Configures outbox worker settings from application configuration.
    pub fn with_outbox_config(mut self, config: &crate::config::Config) -> Self {
        self.outbox_config = OutboxWorkerConfig::from(config);
        self
    }

    /// Spawns the background outbox worker loop once if not already running.
    #[cfg(feature = "postgres")]
    pub fn ensure_worker_started(&self, pool: &sqlx::PgPool) {
        #[cfg(any(test, feature = "test-utils"))]
        if self.block_on_delivery {
            return;
        }

        if tokio::runtime::Handle::try_current().is_err() {
            warn!("no active tokio runtime; skipping background outbox worker spawn");
            return;
        }

        if !self.worker_started.swap(true, Ordering::SeqCst) {
            let pool = pool.clone();
            let sender = self.sender.clone();
            let timeout = self.timeout;
            let config = self.outbox_config.clone();
            let notify = Arc::clone(&self.notify);

            tokio::spawn(async move {
                crate::email::outbox::run_outbox_worker(pool, sender, timeout, config, notify)
                    .await;
            });
        }
    }

    /// Called immediately after committing an outbox row to wake up the processor.
    ///
    /// Under blocking test mode (`new_blocking`), delivers pending messages inline so
    /// assertions can verify delivery synchronously without polling.
    #[cfg(feature = "postgres")]
    pub async fn on_outbox_committed(&self, _pool: &sqlx::PgPool) {
        #[cfg(any(test, feature = "test-utils"))]
        if self.block_on_delivery {
            let result = crate::email::outbox::process_outbox_batch(
                _pool,
                &self.sender,
                self.timeout,
                &self.outbox_config,
            )
            .await;
            // Blocking mode deliberately spawns no worker, so nothing retries this batch:
            // discarding the error left the caller waiting out its delivery timeout with no
            // hint that the claim itself failed.
            if let Err(e) = result {
                let err = crate::email::hook::sanitize_error_str(&e.to_string());
                tracing::error!(err = %err, "inline outbox batch failed; no worker will retry it");
                self.record_inline_error(err);
            }
            return;
        }

        self.notify.notify_one();
    }

    /// Synchronously drains and processes all due outbox messages.
    ///
    /// Test helper in practice; unlike the detached dispatch paths this is a
    /// typed boundary — DB failures surface as [`crate::AppError`] (wire
    /// envelope) instead of raw [`sqlx::Error`].
    #[cfg(feature = "postgres")]
    pub async fn flush_outbox(&self, pool: &sqlx::PgPool) -> Result<usize, crate::AppError> {
        Ok(crate::email::outbox::process_outbox_batch(
            pool,
            &self.sender,
            self.timeout,
            &self.outbox_config,
        )
        .await?)
    }

    /// Returns a reference to the configured email sender, if any.
    pub fn sender(&self) -> Option<&SharedEmailSender> {
        self.sender.as_ref()
    }

    /// Returns the first inline batch failure, if any.
    ///
    /// Test-only: production dispatch is log-only by contract, so the error is reported here
    /// instead of changing the return type of [`EmailDispatcher::on_outbox_committed`].
    #[cfg(any(test, feature = "test-utils"))]
    pub fn inline_delivery_error(&self) -> Option<String> {
        self.inline_error.get().cloned()
    }

    #[cfg(any(test, feature = "test-utils"))]
    fn record_inline_error(&self, err: String) {
        // Keep the first failure: a later retry of the same batch is usually the same cause.
        let _ = self.inline_error.set(err);
    }

    /// Configures a base URL on the dispatcher.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    /// Returns the configured base URL, if any.
    pub fn base_url(&self) -> Option<&str> {
        self.base_url.as_deref()
    }

    /// Constructs a verification URL using the provided base URL and token.
    pub fn build_verification_url(base_url: &str, token: &str) -> String {
        build_verification_url(base_url, token)
    }

    /// Constructs a password reset URL using the provided base URL and token.
    pub fn build_reset_url(base_url: &str, token: &str) -> String {
        build_reset_url(base_url, token)
    }

    /// Dispatches a verification email payload.
    ///
    /// Delivery runs on a detached Tokio task bounded by the configured timeout, so the
    /// caller never observes mailer latency. Send failures are logged (sanitized),
    /// never returned — the log-only contract is intentional. HTTP callers observe
    /// delivery health via the outbox table and the `AppError::EmailDispatch*`
    /// envelope codes, not via this return value.
    ///
    /// Returns the task handle; dropping it detaches the task.
    ///
    /// Test builds may use `EmailDispatcher::new_blocking` to await delivery inline
    /// instead; that mode returns `None`.
    pub async fn dispatch_verification(
        &self,
        payload: VerificationEmailPayload,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let Some(sender) = self.sender.clone() else {
            warn!(op = "verification", "no email sender configured");
            return None;
        };
        let timeout = self.timeout;

        #[cfg(any(test, feature = "test-utils"))]
        if self.block_on_delivery {
            log_send_result(
                "verification",
                tokio::time::timeout(timeout, sender.send_verification_email(payload)).await,
            );
            return None;
        }

        let span = info_span!("dispatch_verification", user_id = %payload.user_id);
        let handle = tokio::spawn(
            async move {
                log_send_result(
                    "verification",
                    tokio::time::timeout(timeout, sender.send_verification_email(payload)).await,
                );
            }
            .instrument(span),
        );
        Some(handle)
    }

    /// Dispatches a password reset email payload.
    ///
    /// Detached and bounded exactly like [`EmailDispatcher::dispatch_verification`].
    pub async fn dispatch_password_reset(
        &self,
        payload: PasswordResetEmailPayload,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let Some(sender) = self.sender.clone() else {
            warn!(op = "password_reset", "no email sender configured");
            return None;
        };
        let timeout = self.timeout;

        #[cfg(any(test, feature = "test-utils"))]
        if self.block_on_delivery {
            log_send_result(
                "password_reset",
                tokio::time::timeout(timeout, sender.send_password_reset_email(payload)).await,
            );
            return None;
        }

        let span = info_span!("dispatch_password_reset", user_id = %payload.user_id);
        let handle = tokio::spawn(
            async move {
                log_send_result(
                    "password_reset",
                    tokio::time::timeout(timeout, sender.send_password_reset_email(payload)).await,
                );
            }
            .instrument(span),
        );
        Some(handle)
    }
}

fn log_send_result(
    op: &'static str,
    result: Result<Result<(), DynError>, tokio::time::error::Elapsed>,
) {
    match result {
        Err(_elapsed) => error!(op, "email dispatch timed out"),
        // Sender errors are untrusted: redact before logging so a chatty
        // sender cannot leak tokens into tracing output.
        Ok(Err(e)) => error!(op, err = %sanitize_sender_error(&e), "email dispatch failed"),
        Ok(Ok(())) => {}
    }
}

impl fmt::Debug for EmailDispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("EmailDispatcher");
        debug
            .field("timeout", &self.timeout)
            .field("sender", &self.sender.is_some())
            .field("base_url", &self.base_url)
            .field("outbox_config", &self.outbox_config);
        #[cfg(any(test, feature = "test-utils"))]
        debug.field("block_on_delivery", &self.block_on_delivery);
        #[cfg(any(test, feature = "test-utils"))]
        debug.field("inline_error", &self.inline_delivery_error());
        debug.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::email::hook::EmailSender;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct RecordingSender {
        verification: Mutex<Vec<VerificationEmailPayload>>,
    }

    #[async_trait::async_trait]
    impl EmailSender for RecordingSender {
        async fn send_verification_email(
            &self,
            payload: VerificationEmailPayload,
        ) -> Result<(), DynError> {
            self.verification.lock().unwrap().push(payload);
            Ok(())
        }

        async fn send_password_reset_email(
            &self,
            _payload: PasswordResetEmailPayload,
        ) -> Result<(), DynError> {
            Ok(())
        }
    }

    struct HangingSender;

    #[async_trait::async_trait]
    impl EmailSender for HangingSender {
        async fn send_verification_email(
            &self,
            _payload: VerificationEmailPayload,
        ) -> Result<(), DynError> {
            std::future::pending().await
        }

        async fn send_password_reset_email(
            &self,
            _payload: PasswordResetEmailPayload,
        ) -> Result<(), DynError> {
            std::future::pending().await
        }
    }

    fn verification_payload() -> VerificationEmailPayload {
        VerificationEmailPayload {
            user_id: uuid::Uuid::new_v4(),
            to: "user@example.com".into(),
            token: "token".into(),
            url: "https://example.com/auth/verify/email?token=token".into(),
            expires_at: chrono::Utc::now(),
        }
    }

    fn reset_payload() -> PasswordResetEmailPayload {
        PasswordResetEmailPayload {
            user_id: uuid::Uuid::new_v4(),
            to: "user@example.com".into(),
            token: "token".into(),
            url: "https://example.com/auth/password/reset?token=token".into(),
            expires_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn blocking_dispatch_delivers_before_returning() {
        let sender = Arc::new(RecordingSender::default());
        let dispatcher =
            EmailDispatcher::new_blocking(Some(sender.clone()), Duration::from_secs(1));

        let handle = dispatcher
            .dispatch_verification(verification_payload())
            .await;

        assert!(handle.is_none(), "blocking dispatch returns no task handle");
        assert_eq!(sender.verification.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn blocking_dispatch_times_out_without_panicking() {
        let dispatcher =
            EmailDispatcher::new_blocking(Some(Arc::new(HangingSender)), Duration::from_millis(10));

        assert!(
            dispatcher
                .dispatch_verification(verification_payload())
                .await
                .is_none()
        );
        assert!(
            dispatcher
                .dispatch_password_reset(reset_payload())
                .await
                .is_none()
        );
    }

    #[test]
    fn test_build_verification_url() {
        assert_eq!(
            build_verification_url("https://example.com", "token-123"),
            "https://example.com/auth/verify/email?token=token-123"
        );
        assert_eq!(
            build_verification_url("https://example.com/", "token-123"),
            "https://example.com/auth/verify/email?token=token-123"
        );
        assert_eq!(
            build_verification_url("https://example.com/", "token with spaces+symbols"),
            "https://example.com/auth/verify/email?token=token%20with%20spaces%2Bsymbols"
        );
    }

    #[test]
    fn test_build_reset_url() {
        assert_eq!(
            build_reset_url("https://example.com", "token-456"),
            "https://example.com/auth/password/reset?token=token-456"
        );
        assert_eq!(
            build_reset_url("https://example.com/", "token-456"),
            "https://example.com/auth/password/reset?token=token-456"
        );
        assert_eq!(
            build_reset_url("https://example.com/", "token with spaces+symbols"),
            "https://example.com/auth/password/reset?token=token%20with%20spaces%2Bsymbols"
        );
    }

    #[test]
    fn test_percent_encode_high_escape() {
        let input = " !@#$%^&*()";
        let encoded = percent_encode_token(input);
        assert_eq!(encoded, "%20%21%40%23%24%25%5E%26%2A%28%29");
    }

    #[test]
    fn test_percent_encode_no_escape() {
        let input = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
        let encoded = percent_encode_token(input);
        assert_eq!(encoded, input);
    }

    #[tokio::test]
    async fn dispatch_password_reset_returns_some_handle_when_sender_present() {
        let sender = Arc::new(RecordingSender::default());
        let dispatcher = EmailDispatcher::new(Some(sender), Duration::from_secs(1));
        let handle = dispatcher.dispatch_password_reset(reset_payload()).await;
        assert!(
            handle.is_some(),
            "Some sender → dispatch returns a JoinHandle"
        );
        handle.unwrap().await.unwrap();
    }

    #[test]
    fn base_url_returns_configured_value() {
        let dispatcher = EmailDispatcher::new(None, Duration::from_secs(1))
            .with_base_url("https://auth.example.com");
        assert_eq!(dispatcher.base_url(), Some("https://auth.example.com"));
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn ensure_worker_started_outside_tokio_does_not_panic() {
        let dispatcher = EmailDispatcher::new(None, Duration::from_secs(1));
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/dummy").unwrap();
        let handle = std::thread::spawn(move || {
            dispatcher.ensure_worker_started(&pool);
            assert!(!dispatcher.worker_started.load(Ordering::SeqCst));
        });
        handle.join().unwrap();
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn blocking_dispatcher_skips_worker_spawn() {
        let dispatcher = EmailDispatcher::new_blocking(None, Duration::from_secs(1));
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/dummy").unwrap();
        dispatcher.ensure_worker_started(&pool);
        assert!(!dispatcher.worker_started.load(Ordering::SeqCst));
    }

    /// No worker to retry a blocking batch, so a lost claim must be reported instead of
    /// leaving the caller to time out on a delivery that can never happen.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn blocking_batch_claim_failure_is_reported_instead_of_discarded() {
        let sender = Arc::new(RecordingSender::default());
        let dispatcher = EmailDispatcher::new_blocking(
            Some(sender.clone() as SharedEmailSender),
            Duration::from_secs(1),
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(500))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/postgres")
            .expect("lazy pool");

        assert_eq!(dispatcher.inline_delivery_error(), None);
        dispatcher.on_outbox_committed(&pool).await;

        let err = dispatcher
            .inline_delivery_error()
            .expect("a failed claim must be reported, not discarded");
        assert!(!err.is_empty(), "the recorded failure must name its cause");
        assert!(
            sender.verification.lock().unwrap().is_empty(),
            "a failed claim delivers nothing"
        );
    }

    #[test]
    fn with_outbox_config_attaches_config_properly() {
        let cfg = crate::config::Config {
            outbox_poll_interval: Duration::from_millis(750),
            outbox_batch_size: 42,
            outbox_max_retries: 7,
            outbox_initial_backoff: Duration::from_secs(4),
            outbox_max_backoff: Duration::from_secs(120),
            outbox_sent_retention: Duration::from_secs(86400 * 3),
            ..Default::default()
        };
        let dispatcher =
            EmailDispatcher::new(None, Duration::from_secs(1)).with_outbox_config(&cfg);
        assert_eq!(
            dispatcher.outbox_config.poll_interval,
            Duration::from_millis(750)
        );
        assert_eq!(dispatcher.outbox_config.batch_size, 42);
        assert_eq!(dispatcher.outbox_config.max_retries, 7);
        assert_eq!(
            dispatcher.outbox_config.initial_backoff,
            Duration::from_secs(4)
        );
        assert_eq!(
            dispatcher.outbox_config.max_backoff,
            Duration::from_secs(120)
        );
        assert_eq!(
            dispatcher.outbox_config.sent_retention,
            Duration::from_secs(86400 * 3)
        );
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn on_outbox_committed_non_blocking_notifies_worker() {
        let dispatcher = EmailDispatcher::new(None, Duration::from_secs(1));
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/dummy").unwrap();

        let notify = Arc::clone(&dispatcher.notify);
        let notified_future = notify.notified();

        dispatcher.on_outbox_committed(&pool).await;

        tokio::time::timeout(Duration::from_millis(100), notified_future)
            .await
            .expect("notify_one must wake the notify subscriber");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn ensure_worker_started_in_tokio_runtime_spawns_worker_once() {
        let dispatcher = EmailDispatcher::new(None, Duration::from_secs(1));
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/dummy").unwrap();

        assert!(!dispatcher.worker_started.load(Ordering::SeqCst));
        dispatcher.ensure_worker_started(&pool);
        assert!(dispatcher.worker_started.load(Ordering::SeqCst));

        // Subsequent call is a no-op and preserves true
        dispatcher.ensure_worker_started(&pool);
        assert!(dispatcher.worker_started.load(Ordering::SeqCst));
    }
}
