//! Email hook dispatch — token generation, URL construction, and async hook invocation.

use std::time::Duration;

pub mod dispatcher;
pub mod hook;
#[cfg(any(feature = "postgres", feature = "mysql", feature = "mongodb"))]
pub mod outbox;
pub mod payload;

pub use dispatcher::{EmailDispatcher, build_reset_url, build_verification_url};
pub use hook::{
    DynError, EmailSender, SharedEmailSender, sanitize_error_str, sanitize_sender_error,
};
#[cfg(any(feature = "postgres", feature = "mysql", feature = "mongodb"))]
pub use outbox::{process_outbox_batch, run_outbox_worker, run_outbox_worker_until};
pub use payload::{PasswordResetEmailPayload, VerificationEmailPayload};

/// Configuration parameters for the outbox worker polling loop and retry policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxWorkerConfig {
    pub poll_interval: Duration,
    pub batch_size: u32,
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub lease_duration: Duration,
    pub sent_retention: Duration,
}

impl Default for OutboxWorkerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(crate::config::DEFAULT_OUTBOX_POLL_INTERVAL_MS),
            batch_size: crate::config::DEFAULT_OUTBOX_BATCH_SIZE,
            max_retries: crate::config::DEFAULT_OUTBOX_MAX_RETRIES,
            initial_backoff: Duration::from_secs(
                crate::config::DEFAULT_OUTBOX_INITIAL_BACKOFF_SECS,
            ),
            max_backoff: Duration::from_secs(crate::config::DEFAULT_OUTBOX_MAX_BACKOFF_SECS),
            lease_duration: Duration::from_secs(300),
            sent_retention: Duration::from_secs(crate::config::DEFAULT_OUTBOX_SENT_RETENTION_SECS),
        }
    }
}

impl From<&crate::config::Config> for OutboxWorkerConfig {
    fn from(cfg: &crate::config::Config) -> Self {
        Self {
            poll_interval: cfg.outbox_poll_interval,
            batch_size: cfg.outbox_batch_size,
            max_retries: cfg.outbox_max_retries,
            initial_backoff: cfg.outbox_initial_backoff,
            max_backoff: cfg.outbox_max_backoff,
            lease_duration: Duration::from_secs(300),
            sent_retention: cfg.outbox_sent_retention,
        }
    }
}

impl OutboxWorkerConfig {
    pub fn with_lease_duration(mut self, lease_duration: Duration) -> Self {
        self.lease_duration = lease_duration;
        self
    }

    pub fn with_sent_retention(mut self, sent_retention: Duration) -> Self {
        self.sent_retention = sent_retention;
        self
    }
}

/// No-op email sender — drops all payloads without sending.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopEmailSender;

#[async_trait::async_trait]
impl EmailSender for NoopEmailSender {
    async fn send_verification_email(
        &self,
        _payload: VerificationEmailPayload,
    ) -> Result<(), DynError> {
        Ok(())
    }

    async fn send_password_reset_email(
        &self,
        _payload: PasswordResetEmailPayload,
    ) -> Result<(), DynError> {
        Ok(())
    }
}

/// Test utilities for capturing dispatched email payloads.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    fn lock_guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        match mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[derive(Default)]
    pub struct CapturingEmailSender {
        pub verification_calls: Mutex<Vec<VerificationEmailPayload>>,
        pub reset_calls: Mutex<Vec<PasswordResetEmailPayload>>,
    }

    impl CapturingEmailSender {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn verification_calls(&self) -> Vec<VerificationEmailPayload> {
            lock_guard(&self.verification_calls).clone()
        }

        pub fn reset_calls(&self) -> Vec<PasswordResetEmailPayload> {
            lock_guard(&self.reset_calls).clone()
        }

        pub fn last_verification_token(&self) -> Option<String> {
            lock_guard(&self.verification_calls)
                .last()
                .map(|p| p.token.clone())
        }

        pub fn verification_token_for(&self, recipient: &str) -> Option<String> {
            lock_guard(&self.verification_calls)
                .iter()
                .rfind(|p| p.to == recipient)
                .map(|p| p.token.clone())
        }

        pub fn last_reset_token(&self) -> Option<String> {
            lock_guard(&self.reset_calls)
                .last()
                .map(|p| p.token.clone())
        }

        pub fn reset_token_for(&self, recipient: &str) -> Option<String> {
            lock_guard(&self.reset_calls)
                .iter()
                .rfind(|p| p.to == recipient)
                .map(|p| p.token.clone())
        }

        pub fn clear(&self) {
            lock_guard(&self.verification_calls).clear();
            lock_guard(&self.reset_calls).clear();
        }
    }

    #[async_trait::async_trait]
    impl EmailSender for CapturingEmailSender {
        async fn send_verification_email(
            &self,
            payload: VerificationEmailPayload,
        ) -> Result<(), DynError> {
            lock_guard(&self.verification_calls).push(payload);
            Ok(())
        }

        async fn send_password_reset_email(
            &self,
            payload: PasswordResetEmailPayload,
        ) -> Result<(), DynError> {
            lock_guard(&self.reset_calls).push(payload);
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn test_capturing_email_sender_scoped_tokens() {
            let sender = CapturingEmailSender::new();
            let p1 = VerificationEmailPayload {
                to: "user1@example.com".into(),
                token: "token-user1".into(),
                url: "https://example.com/v1".into(),
                expires_at: chrono::Utc::now(),
                user_id: uuid::Uuid::new_v4(),
            };
            let p2 = VerificationEmailPayload {
                to: "user2@example.com".into(),
                token: "token-user2".into(),
                url: "https://example.com/v2".into(),
                expires_at: chrono::Utc::now(),
                user_id: uuid::Uuid::new_v4(),
            };
            sender.send_verification_email(p1).await.unwrap();
            sender.send_verification_email(p2).await.unwrap();

            assert_eq!(
                sender.verification_token_for("user1@example.com"),
                Some("token-user1".into())
            );
            assert_eq!(
                sender.verification_token_for("user2@example.com"),
                Some("token-user2".into())
            );
            assert_eq!(sender.verification_token_for("unknown@example.com"), None);

            let r1 = PasswordResetEmailPayload {
                to: "reset1@example.com".into(),
                token: "reset-tok-1".into(),
                url: "https://example.com/r1".into(),
                expires_at: chrono::Utc::now(),
                user_id: uuid::Uuid::new_v4(),
            };
            sender.send_password_reset_email(r1).await.unwrap();
            assert_eq!(
                sender.reset_token_for("reset1@example.com"),
                Some("reset-tok-1".into())
            );
            assert_eq!(sender.reset_token_for("unknown@example.com"), None);
        }
    }
}
