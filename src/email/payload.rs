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

fn redact_url_token(url: &str) -> String {
    let Some((base, rest)) = url.split_once('?') else {
        return url.to_string();
    };

    let (query, fragment) = match rest.split_once('#') {
        Some((q, f)) => (q, Some(f)),
        None => (rest, None),
    };

    let mut redacted_query = String::with_capacity(query.len() + 16);
    for (i, part) in query.split('&').enumerate() {
        if i > 0 {
            redacted_query.push('&');
        }
        if let Some((k, _v)) = part.split_once('=') {
            if k == "token" {
                redacted_query.push_str("token=[REDACTED]");
            } else {
                redacted_query.push_str(part);
            }
        } else if part == "token" {
            redacted_query.push_str("token=[REDACTED]");
        } else {
            redacted_query.push_str(part);
        }
    }

    let mut result = String::with_capacity(
        base.len() + 1 + redacted_query.len() + fragment.map_or(0, |f| f.len() + 1),
    );
    result.push_str(base);
    result.push('?');
    result.push_str(&redacted_query);
    if let Some(f) = fragment {
        result.push('#');
        result.push_str(f);
    }
    result
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
        assert!(debug_str.contains("https://example.com/reset?token=[REDACTED]#frag"));
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
            redact_url_token("https://example.com/auth/verify"),
            "https://example.com/auth/verify"
        );
        assert_eq!(redact_url_token(""), "");
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
