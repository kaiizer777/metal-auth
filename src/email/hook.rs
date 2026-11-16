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

/// Redacts token values from a sender error before it is logged or persisted
/// to the outbox `error_log`.
///
/// Covers `token=` assignments (ASCII-case-insensitive: `token=`, `Token=`,
/// `auth_token=`; value runs to the next `&`, `#`, whitespace, quote, `;`,
/// or end of input) and JSON string pairs (`"token": "<value>"`, quote style
/// and whitespace around `:` tolerated). Keys merely containing the substring
/// (e.g. `token_type=`, `"token_type":`) are left alone. Returns the input
/// unchanged when no marker is present, so non-secret errors pass through
/// unmodified.
pub fn sanitize_sender_error(err: &DynError) -> String {
    sanitize_error_str(&err.to_string())
}

/// [`sanitize_sender_error`] over an already-rendered message: use for
/// outbox-internal `error_log` strings assembled from untrusted parts.
pub fn sanitize_error_str(raw: &str) -> String {
    redact_json_token(redact_token_assignments(raw))
}

// `token=`-assignment pass. ASCII-only lowering preserves byte indices, so
// marker offsets found in `lowered` are valid slice boundaries in `raw`.
fn redact_token_assignments(raw: &str) -> String {
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
                b'&' | b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'\'' | b';' | b'#'
            )
        {
            end += 1;
        }
        kept_from = end;
    }
    out.push_str(&raw[kept_from..]);
    out
}

// `"token": "<value>"` JSON pass. The closing quote in the `"token"` match
// excludes `"token_type"`-style keys; `token=`-adjacent quotes were already
// consumed by the assignment pass above.
fn redact_json_token(stage: String) -> String {
    let lowered = stage.to_ascii_lowercase();
    let bytes = stage.as_bytes();
    let mut out = String::with_capacity(stage.len());
    let mut kept_from = 0;
    let mut search_from = 0;
    while let Some(rel) = lowered[search_from..].find("\"token\"") {
        let key_at = search_from + rel;
        if key_at < kept_from {
            search_from = key_at + 1;
            continue;
        }
        let mut cursor = key_at + "\"token\"".len();
        while cursor < bytes.len() && matches!(bytes[cursor], b' ' | b'\t' | b'\r' | b'\n') {
            cursor += 1;
        }
        if cursor >= bytes.len() || bytes[cursor] != b':' {
            search_from = key_at + 1;
            continue;
        }
        cursor += 1;
        while cursor < bytes.len() && matches!(bytes[cursor], b' ' | b'\t' | b'\r' | b'\n') {
            cursor += 1;
        }
        if cursor >= bytes.len() || !matches!(bytes[cursor], b'"' | b'\'') {
            search_from = key_at + 1;
            continue;
        }
        let quote = bytes[cursor];
        let value_at = cursor + 1;
        let mut end = value_at;
        while end < bytes.len() && bytes[end] != quote {
            end += 1;
        }
        out.push_str(&stage[kept_from..value_at]);
        out.push_str("[REDACTED]");
        if end < bytes.len() {
            out.push(quote as char);
            kept_from = end + 1;
            search_from = kept_from;
        } else {
            // Unterminated string: fail closed, drop the trailing secret bytes.
            kept_from = stage.len();
            search_from = stage.len();
        }
    }
    out.push_str(&stage[kept_from..]);
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
    fn redacts_json_token_shape() {
        let err = boxed(r#"smtp rejected {"token":"supersecret123"} for user"#);
        assert_eq!(
            sanitize_sender_error(&err),
            r#"smtp rejected {"token":"[REDACTED]"} for user"#
        );
        let err = boxed(r#"fail {"Token" : 'abc', "token_type": "bearer"} end"#);
        assert_eq!(
            sanitize_sender_error(&err),
            r#"fail {"Token" : '[REDACTED]', "token_type": "bearer"} end"#
        );
        // Non-string JSON values are not secrets to redact.
        let err = boxed(r#"fail {"token": 42} end"#);
        assert_eq!(sanitize_sender_error(&err), r#"fail {"token": 42} end"#);
    }

    #[test]
    fn redacts_url_with_fragment() {
        let err = boxed("get https://example.com/reset?token=abc#frag failed");
        assert_eq!(
            sanitize_sender_error(&err),
            "get https://example.com/reset?token=[REDACTED]#frag failed"
        );
        let err = boxed("fail token=abc#token=xyz end");
        assert_eq!(
            sanitize_sender_error(&err),
            "fail token=[REDACTED]#token=[REDACTED] end"
        );
    }
}
