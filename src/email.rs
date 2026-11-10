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
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct CapturingEmailSender {
        pub verification_calls: Mutex<Vec<VerificationEmailPayload>>,
        pub reset_calls: Mutex<Vec<PasswordResetEmailPayload>>,
    }

    #[async_trait::async_trait]
    impl EmailSender for CapturingEmailSender {
        async fn send_verification_email(
            &self,
            payload: VerificationEmailPayload,
        ) -> Result<(), DynError> {
            self.verification_calls.lock().unwrap().push(payload);
            Ok(())
        }

        async fn send_password_reset_email(
            &self,
            payload: PasswordResetEmailPayload,
        ) -> Result<(), DynError> {
            self.reset_calls.lock().unwrap().push(payload);
            Ok(())
        }
    }
}
