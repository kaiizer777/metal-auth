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
            .field("url", &self.url)
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
            .field("url", &self.url)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_payload_debug_redacts_token() {
        let payload = VerificationEmailPayload {
            user_id: Uuid::nil(),
            to: "user@example.com".into(),
            token: "supersecrettoken123".into(),
            url: "https://example.com/verify".into(),
            expires_at: Utc::now(),
        };
        let debug_str = format!("{payload:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("supersecrettoken123"));
    }

    #[test]
    fn password_reset_payload_debug_redacts_token() {
        let payload = PasswordResetEmailPayload {
            user_id: Uuid::nil(),
            to: "user@example.com".into(),
            token: "supersecrettoken456".into(),
            url: "https://example.com/reset".into(),
            expires_at: Utc::now(),
        };
        let debug_str = format!("{payload:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("supersecrettoken456"));
    }
}
