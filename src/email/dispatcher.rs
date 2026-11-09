use std::fmt;
use std::time::Duration;

use tracing::{error, warn};

use crate::email::hook::SharedEmailSender;
use crate::email::payload::{PasswordResetEmailPayload, VerificationEmailPayload};

#[allow(dead_code)]
fn build_verification_url(base_url: &str, token: &str) -> String {
    format!("{}/auth/verify/email?token={}", base_url, token)
}

#[allow(dead_code)]
fn build_reset_url(base_url: &str, token: &str) -> String {
    format!("{}/auth/password/reset?token={}", base_url, token)
}

#[derive(Clone)]
pub struct EmailDispatcher {
    sender: Option<SharedEmailSender>,
    timeout: Duration,
    async_dispatch: bool,
}

impl EmailDispatcher {
    pub fn new(sender: Option<SharedEmailSender>, timeout: Duration, async_dispatch: bool) -> Self {
        Self {
            sender,
            timeout,
            async_dispatch,
        }
    }

    pub async fn dispatch_verification(&self, payload: VerificationEmailPayload) {
        let Some(sender) = self.sender.clone() else {
            warn!("no email sender configured; dropping verification email");
            return;
        };
        let timeout = self.timeout;

        if self.async_dispatch {
            tokio::spawn(async move {
                match tokio::time::timeout(timeout, sender.send_verification_email(payload)).await {
                    Err(_elapsed) => {
                        error!(op = "verification", "email dispatch timed out");
                    }
                    Ok(Err(e)) => {
                        error!(op = "verification", err = %e, "email dispatch failed");
                    }
                    Ok(Ok(())) => {}
                }
            });
        } else {
            if let Err(e) = sender.send_verification_email(payload).await {
                error!(op = "verification", err = %e, "email dispatch failed");
            }
        }
    }

    pub async fn dispatch_password_reset(&self, payload: PasswordResetEmailPayload) {
        let Some(sender) = self.sender.clone() else {
            warn!("no email sender configured; dropping password reset email");
            return;
        };
        let timeout = self.timeout;

        if self.async_dispatch {
            tokio::spawn(async move {
                match tokio::time::timeout(timeout, sender.send_password_reset_email(payload)).await
                {
                    Err(_elapsed) => {
                        error!(op = "password_reset", "email dispatch timed out");
                    }
                    Ok(Err(e)) => {
                        error!(op = "password_reset", err = %e, "email dispatch failed");
                    }
                    Ok(Ok(())) => {}
                }
            });
        } else {
            if let Err(e) = sender.send_password_reset_email(payload).await {
                error!(op = "password_reset", err = %e, "email dispatch failed");
            }
        }
    }
}

impl fmt::Debug for EmailDispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmailDispatcher")
            .field("timeout", &self.timeout)
            .field("async_dispatch", &self.async_dispatch)
            .field("sender", &self.sender.is_some())
            .finish()
    }
}
