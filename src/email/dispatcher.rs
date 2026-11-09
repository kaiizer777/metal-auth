use std::fmt;
use std::time::Duration;

use tracing::{error, warn};

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
    let mut encoded = String::with_capacity(input.len() + 16);
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

pub fn build_verification_url(base_url: &str, token: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let encoded_token = percent_encode_token(token);
    format!("{}/auth/verify/email?token={}", base, encoded_token)
}

pub fn build_reset_url(base_url: &str, token: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let encoded_token = percent_encode_token(token);
    format!("{}/auth/password/reset?token={}", base, encoded_token)
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

    pub fn build_verification_url(base_url: &str, token: &str) -> String {
        build_verification_url(base_url, token)
    }

    pub fn build_reset_url(base_url: &str, token: &str) -> String {
        build_reset_url(base_url, token)
    }

    pub async fn dispatch_verification(
        &self,
        payload: VerificationEmailPayload,
    ) -> tokio::task::JoinHandle<()> {
        let Some(sender) = self.sender.clone() else {
            warn!("no email sender configured; dropping verification email");
            return tokio::spawn(async {});
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
            })
        } else {
            if let Err(e) = sender.send_verification_email(payload).await {
                error!(op = "verification", err = %e, "email dispatch failed");
            }
            tokio::spawn(async {})
        }
    }

    pub async fn dispatch_password_reset(
        &self,
        payload: PasswordResetEmailPayload,
    ) -> tokio::task::JoinHandle<()> {
        let Some(sender) = self.sender.clone() else {
            warn!("no email sender configured; dropping password reset email");
            return tokio::spawn(async {});
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
            })
        } else {
            if let Err(e) = sender.send_password_reset_email(payload).await {
                error!(op = "password_reset", err = %e, "email dispatch failed");
            }
            tokio::spawn(async {})
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
}
