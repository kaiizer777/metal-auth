use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;

use crate::email::payload::{PasswordResetEmailPayload, VerificationEmailPayload};

pub type DynError = Box<dyn Error + Send + Sync>;

#[async_trait]
#[trait_variant::make(EmailSender: Send)]
pub trait LocalEmailSender: Send + Sync {
    async fn send_verification_email(
        &self,
        payload: VerificationEmailPayload,
    ) -> Result<(), DynError>;
    async fn send_password_reset_email(
        &self,
        payload: PasswordResetEmailPayload,
    ) -> Result<(), DynError>;
}

pub type SharedEmailSender = Arc<dyn EmailSender>;
