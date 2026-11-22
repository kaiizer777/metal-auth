use std::borrow::Cow;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationEmailPayload {
    pub user_id: Uuid,
    pub to: String,
    pub token: String,
    pub url: String,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for VerificationEmailPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerificationEmailPayload")
            .field("user_id", &self.user_id)
            .field("to", &self.to)
            .field("token", &"[REDACTED]")
            .field("url", &redact_url_token(&self.url))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordResetEmailPayload {
    pub user_id: Uuid,
    pub to: String,
    pub token: String,
    pub url: String,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for PasswordResetEmailPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordResetEmailPayload")
            .field("user_id", &self.user_id)
            .field("to", &self.to)
            .field("token", &"[REDACTED]")
            .field("url", &redact_url_token(&self.url))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

const REDACTED: &str = "[REDACTED]";

// A query/fragment key carries a token when it is exactly `token` (any ASCII
// case) or ends in `_token` (`auth_token=`); `token_type=` and friends stay.
fn is_token_key(key: &str) -> bool {
    key.eq_ignore_ascii_case("token")
        || key.len() >= "_token".len()
            && key.as_bytes()[key.len() - "_token".len()..].eq_ignore_ascii_case(b"_token")
}

fn redact_params(params: &str) -> String {
    let mut redacted = String::with_capacity(params.len() + 16);
    for (i, part) in params.split('&').enumerate() {
        if i > 0 {
            redacted.push('&');
        }
        match part.split_once('=') {
            Some((k, _)) if is_token_key(k) => {
                redacted.push_str(k);
                redacted.push_str("=[REDACTED]");
            }
            None if is_token_key(part) => {
                redacted.push_str(part);
                redacted.push_str("=[REDACTED]");
            }
            _ => redacted.push_str(part),
        }
    }
    redacted
}

fn redact_url_token(url: &str) -> Cow<'_, str> {
    // Split the fragment first: everything after the first `#` is fragment,
    // so a `?` there must never be parsed as a query string (and a token in
    // the head must never be copied verbatim into the redacted output).
    let (head, fragment) = match url.split_once('#') {
        Some((h, f)) => (h, Some(f)),
        None => (url, None),
    };
    let (base, query) = match head.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        // No query string and no fragment: nothing to redact.
        None if fragment.is_none() => return Cow::Borrowed(url),
        None => (head, None),
    };

    let mut result = String::with_capacity(url.len() + 16);
    result.push_str(base);
    if let Some(q) = query {
        result.push('?');
        result.push_str(&redact_params(q));
    }
    if let Some(f) = fragment {
        result.push('#');
        // Builders never emit fragments; a bare fragment is unclassifiable, so
        // redact it fail-closed while param-style fragments get key redaction.
        // A `?` inside the fragment also separates params for this purpose so
        // `frag?token=...` cannot smuggle a token past key matching.
        if f.contains('=') {
            result.push_str(&redact_params(&f.replace('?', "&")));
        } else if !f.is_empty() {
            result.push_str(REDACTED);
        }
    }
    Cow::Owned(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_payload_debug_redacts_token_and_url() {
        let payload = VerificationEmailPayload {
            user_id: Uuid::nil(),
            to: "user@example.com".into(),
            token: "supersecrettoken123".into(),
            url: "https://example.com/verify?token=supersecrettoken123".into(),
            expires_at: Utc::now(),
        };
        let debug_str = format!("{payload:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("supersecrettoken123"));
        assert!(debug_str.contains("https://example.com/verify?token=[REDACTED]"));
    }

    #[test]
    fn password_reset_payload_debug_redacts_token_and_url() {
        let payload = PasswordResetEmailPayload {
            user_id: Uuid::nil(),
            to: "user@example.com".into(),
            token: "supersecrettoken456".into(),
            url: "https://example.com/reset?token=supersecrettoken456#frag".into(),
            expires_at: Utc::now(),
        };
        let debug_str = format!("{payload:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("supersecrettoken456"));
        assert!(debug_str.contains("https://example.com/reset?token=[REDACTED]#[REDACTED]"));
    }

    #[test]
    fn redact_url_token_edge_cases() {
        assert_eq!(
            redact_url_token("https://example.com/auth/verify?token=abc"),
            "https://example.com/auth/verify?token=[REDACTED]"
        );
        assert_eq!(
            redact_url_token("https://example.com/auth/verify?a=1&token=abc&b=2"),
            "https://example.com/auth/verify?a=1&token=[REDACTED]&b=2"
        );
        assert_eq!(
            redact_url_token("https://example.com/auth/verify?token_type=bearer&token=abc"),
            "https://example.com/auth/verify?token_type=bearer&token=[REDACTED]"
        );
        assert_eq!(
            redact_url_token("https://example.com/auth/verify?Token=abc&auth_token=def"),
            "https://example.com/auth/verify?Token=[REDACTED]&auth_token=[REDACTED]"
        );
        assert_eq!(
            redact_url_token("https://example.com/reset?token=abc#token=xyz"),
            "https://example.com/reset?token=[REDACTED]#token=[REDACTED]"
        );
        assert_eq!(
            redact_url_token("https://example.com/reset?token=abc#frag"),
            "https://example.com/reset?token=[REDACTED]#[REDACTED]"
        );
        assert_eq!(
            redact_url_token("https://example.com/reset?token=abc#"),
            "https://example.com/reset?token=[REDACTED]#"
        );
        assert_eq!(
            redact_url_token("https://example.com/reset#token=abc"),
            "https://example.com/reset#token=[REDACTED]"
        );
        assert_eq!(
            redact_url_token("https://example.com/reset#frag"),
            "https://example.com/reset#[REDACTED]"
        );
        assert_eq!(
            redact_url_token("https://example.com/reset#"),
            "https://example.com/reset#"
        );
        assert_eq!(
            redact_url_token("https://example.com/auth/verify"),
            "https://example.com/auth/verify"
        );
        assert_eq!(redact_url_token(""), "");
        assert!(matches!(
            redact_url_token("https://example.com/auth/verify"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn redact_url_token_fragment_token_with_query() {
        // Query and fragment tokens are both redacted.
        assert_eq!(
            redact_url_token("https://example.com/reset?next=/home&token=qsecret#token=fsecret"),
            "https://example.com/reset?next=/home&token=[REDACTED]#token=[REDACTED]"
        );
        // `#` before `?`: the `?` belongs to the fragment, never the query.
        let redacted =
            redact_url_token("https://example.com/reset#token=fsecret?token=qsecret").to_string();
        assert!(!redacted.contains("fsecret"));
        assert!(!redacted.contains("qsecret"));
        // `?`-smuggled token behind a non-param fragment prefix.
        let redacted = redact_url_token("https://example.com/reset#frag?token=sneaky").to_string();
        assert!(!redacted.contains("sneaky"));
    }

    #[test]
    fn verification_payload_eq_identical_fields() {
        let p = VerificationEmailPayload {
            user_id: Uuid::nil(),
            to: "user@example.com".into(),
            token: "tok".into(),
            url: "https://example.com/verify?token=tok".into(),
            expires_at: DateTime::from_timestamp(0, 0).unwrap(),
        };
        assert_eq!(p.clone(), p);
    }

    #[test]
    fn password_reset_payload_eq_identical_fields() {
        let p = PasswordResetEmailPayload {
            user_id: Uuid::nil(),
            to: "user@example.com".into(),
            token: "tok".into(),
            url: "https://example.com/reset?token=tok".into(),
            expires_at: DateTime::from_timestamp(0, 0).unwrap(),
        };
        assert_eq!(p.clone(), p);
    }
}
