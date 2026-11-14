//! Email hook dispatch — token generation, URL construction, and async hook invocation.

pub mod dispatcher;
pub mod hook;
pub mod outbox;
pub mod payload;

pub use dispatcher::{EmailDispatcher, build_reset_url, build_verification_url};
pub use hook::{DynError, EmailSender, SharedEmailSender};
pub use outbox::{OutboxWorkerConfig, process_outbox_batch, run_outbox_worker};
pub use payload::{PasswordResetEmailPayload, VerificationEmailPayload};

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
