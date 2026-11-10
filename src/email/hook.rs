use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;

use crate::email::payload::{PasswordResetEmailPayload, VerificationEmailPayload};

/// A thread-safe, heap-allocated dynamic error for email sender failures.
pub type DynError = Box<dyn Error + Send + Sync>;

/// Asynchronous email sender contract for delivering verification and password reset emails.
#[async_trait]
pub trait EmailSender: Send + Sync {
    /// Dispatches an email containing the email verification link and token.
    async fn send_verification_email(
        &self,
        payload: VerificationEmailPayload,
    ) -> Result<(), DynError>;

    /// Dispatches an email containing the password reset link and token.
    async fn send_password_reset_email(
        &self,
        payload: PasswordResetEmailPayload,
    ) -> Result<(), DynError>;
}

/// A shared reference-counted handle to a thread-safe [`EmailSender`].
pub type SharedEmailSender = Arc<dyn EmailSender>;
