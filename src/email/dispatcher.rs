use std::fmt;
use std::time::Duration;

use tracing::{Instrument, error, info_span, warn};

use crate::email::hook::{DynError, SharedEmailSender};
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
    /// Inline (caller-blocking) delivery — test-only, absent from default builds.
    #[cfg(any(test, feature = "test-utils"))]
    block_on_delivery: bool,
}

impl EmailDispatcher {
    /// Creates a dispatcher that always delivers on a detached Tokio task.
    pub fn new(sender: Option<SharedEmailSender>, timeout: Duration) -> Self {
        Self {
            sender,
            timeout,
            base_url: None,
            #[cfg(any(test, feature = "test-utils"))]
            block_on_delivery: false,
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
    /// caller never observes mailer latency. Send failures are logged, never returned.
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
        Ok(Err(e)) => error!(op, err = %e, "email dispatch failed"),
        Ok(Ok(())) => {}
    }
}

impl fmt::Debug for EmailDispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("EmailDispatcher");
        debug
            .field("timeout", &self.timeout)
            .field("sender", &self.sender.is_some())
            .field("base_url", &self.base_url);
        #[cfg(any(test, feature = "test-utils"))]
        debug.field("block_on_delivery", &self.block_on_delivery);
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
}
