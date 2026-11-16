use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;

use crate::email::payload::{PasswordResetEmailPayload, VerificationEmailPayload};

/// A thread-safe, heap-allocated dynamic error for email sender failures.
pub type DynError = Box<dyn Error + Send + Sync>;

/// Error-text contract: implementations must never embed payloads (tokens, URLs,
/// recipients) in returned errors. Outbox and dispatcher layers redact `token=`
/// assignments defensively, but redaction is a backstop, not a license to echo secrets.
///
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

/// Redacts `token=` assignments from a sender error before it is logged or
/// persisted to the outbox `error_log`.
///
/// Matches the key ASCII-case-insensitively (`token=`, `Token=`, `auth_token=`)
/// and replaces the value up to the next `&`, whitespace, quote, `;`, or end
/// of input with `[REDACTED]`. Keys merely containing the substring (e.g.
/// `token_type=`) are left alone. Returns the input unchanged when no marker
/// is present, so non-secret errors pass through unmodified.
pub fn sanitize_sender_error(err: &DynError) -> String {
    sanitize_error_text(&err.to_string())
}

fn sanitize_error_text(raw: &str) -> String {
    // ASCII-only lowering preserves byte indices, so marker offsets found in
    // `lowered` are valid slice boundaries in `raw` (markers are pure ASCII).
    let lowered = raw.to_ascii_lowercase();
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut kept_from = 0;
    for (marker_at, _) in lowered.match_indices("token=") {
        if marker_at < kept_from {
            continue;
        }
        let value_at = marker_at + "token=".len();
        out.push_str(&raw[kept_from..value_at]);
        out.push_str("[REDACTED]");
        let mut end = value_at;
        while end < bytes.len()
            && !matches!(
                bytes[end],
                b'&' | b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'\'' | b';'
            )
        {
            end += 1;
        }
        kept_from = end;
    }
    out.push_str(&raw[kept_from..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boxed(msg: &str) -> DynError {
        Box::new(std::io::Error::other(msg.to_string()))
    }

    #[test]
    fn redacts_echoed_token() {
        let err = boxed("smtp rejected token=supersecret123 for user@example.com");
        assert_eq!(
            sanitize_sender_error(&err),
            "smtp rejected token=[REDACTED] for user@example.com"
        );
    }

    #[test]
    fn redacts_case_variants_and_prefixed_keys() {
        let err = boxed("fail Token=aaa&auth_token=bbb ok");
        assert_eq!(
            sanitize_sender_error(&err),
            "fail Token=[REDACTED]&auth_token=[REDACTED] ok"
        );
    }

    #[test]
    fn leaves_token_type_and_plain_errors_alone() {
        let err = boxed("unsupported grant token_type=bearer");
        assert_eq!(
            sanitize_sender_error(&err),
            "unsupported grant token_type=bearer"
        );
        let err = boxed("connection refused");
        assert_eq!(sanitize_sender_error(&err), "connection refused");
    }

    #[test]
    fn redacts_url_with_fragment() {
        let err = boxed("get https://example.com/reset?token=abc#frag failed");
        assert_eq!(
            sanitize_sender_error(&err),
            "get https://example.com/reset?token=[REDACTED]#frag failed"
        );
    }
}
