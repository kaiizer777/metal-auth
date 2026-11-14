//! Email hook dispatch — token generation, URL construction, and async hook invocation.

pub mod dispatcher;
pub mod hook;
pub mod payload;

pub use dispatcher::{EmailDispatcher, build_reset_url, build_verification_url};
pub use hook::{DynError, EmailSender, SharedEmailSender};
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

        pub fn last_reset_token(&self) -> Option<String> {
            lock_guard(&self.reset_calls)
                .last()
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
}
