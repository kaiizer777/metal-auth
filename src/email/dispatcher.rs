use std::fmt;
use std::time::Duration;

use tracing::{Instrument, error, info_span, warn};

use crate::email::hook::SharedEmailSender;
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
    async_dispatch: bool,
    base_url: Option<String>,
}

impl EmailDispatcher {
    /// Creates a new `EmailDispatcher` with an optional sender, timeout, and dispatch mode.
    pub fn new(sender: Option<SharedEmailSender>, timeout: Duration, async_dispatch: bool) -> Self {
        Self {
            sender,
            timeout,
            async_dispatch,
            base_url: None,
        }
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
    /// In async mode (`async_dispatch == true`), spawns a Tokio task with the configured timeout
    /// and returns `Some(JoinHandle<()>)`.
    ///
    /// In sync mode (`async_dispatch == false`), awaits the sender inline with timeout and returns `None`.
    pub async fn dispatch_verification(
        &self,
        payload: VerificationEmailPayload,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let Some(sender) = self.sender.clone() else {
            warn!(op = "verification", "no email sender configured");
            return None;
        };
        let timeout = self.timeout;

        if self.async_dispatch {
            let span = info_span!("dispatch_verification", user_id = %payload.user_id);
            let handle = tokio::spawn(
                async move {
                    match tokio::time::timeout(timeout, sender.send_verification_email(payload))
                        .await
                    {
                        Err(_elapsed) => {
                            error!(op = "verification", "email dispatch timed out");
                        }
                        Ok(Err(e)) => {
                            error!(op = "verification", err = %e, "email dispatch failed");
                        }
                        Ok(Ok(())) => {}
                    }
                }
                .instrument(span),
            );
            Some(handle)
        } else {
            match tokio::time::timeout(timeout, sender.send_verification_email(payload)).await {
                Err(_elapsed) => {
                    error!(op = "verification", "email dispatch timed out");
                }
                Ok(Err(e)) => {
                    error!(op = "verification", err = %e, "email dispatch failed");
                }
                Ok(Ok(())) => {}
            }
            None
        }
    }

    /// Dispatches a password reset email payload.
    ///
    /// In async mode (`async_dispatch == true`), spawns a Tokio task with the configured timeout
    /// and returns `Some(JoinHandle<()>)`.
    ///
    /// In sync mode (`async_dispatch == false`), awaits the sender inline with timeout and returns `None`.
    pub async fn dispatch_password_reset(
        &self,
        payload: PasswordResetEmailPayload,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let Some(sender) = self.sender.clone() else {
            warn!(op = "password_reset", "no email sender configured");
            return None;
        };
        let timeout = self.timeout;

        if self.async_dispatch {
            let span = info_span!("dispatch_password_reset", user_id = %payload.user_id);
            let handle = tokio::spawn(
                async move {
                    match tokio::time::timeout(timeout, sender.send_password_reset_email(payload))
                        .await
                    {
                        Err(_elapsed) => {
                            error!(op = "password_reset", "email dispatch timed out");
                        }
                        Ok(Err(e)) => {
                            error!(op = "password_reset", err = %e, "email dispatch failed");
                        }
                        Ok(Ok(())) => {}
                    }
                }
                .instrument(span),
            );
            Some(handle)
        } else {
            match tokio::time::timeout(timeout, sender.send_password_reset_email(payload)).await {
                Err(_elapsed) => {
                    error!(op = "password_reset", "email dispatch timed out");
                }
                Ok(Err(e)) => {
                    error!(op = "password_reset", err = %e, "email dispatch failed");
                }
                Ok(Ok(())) => {}
            }
            None
        }
    }
}

impl fmt::Debug for EmailDispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmailDispatcher")
            .field("timeout", &self.timeout)
            .field("async_dispatch", &self.async_dispatch)
            .field("sender", &self.sender.is_some())
            .field("base_url", &self.base_url)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
