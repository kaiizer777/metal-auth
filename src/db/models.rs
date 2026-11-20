use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

pub use crate::auth::models::UserResponse;

/// Internal user database entity.
///
/// Intentionally does NOT derive `Serialize` to prevent `password_hash`
/// from ever leaking across API responses. Outbound serialization must
/// use [`UserResponse`](crate::auth::models::UserResponse).
#[derive(Clone, FromRow, PartialEq, Eq)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Manual `Debug`: the Argon2 PHC string must never reach logs or traces.
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("email", &self.email)
            .field("password_hash", &"[redacted]")
            .field("email_verified", &self.email_verified)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Prefix of password-hash sentinels marking an account with no usable password.
pub(crate) const UNUSABLE_PASSWORD_PREFIX: &str = "$unusable$";

/// Password hash stored for users provisioned through OAuth.
pub(crate) const OAUTH_UNUSABLE_PASSWORD_HASH: &str = "$unusable$oauth$";

/// Whether `hash` marks an account that cannot authenticate with a password.
pub(crate) fn is_unusable_password_hash(hash: &str) -> bool {
    hash.is_empty() || hash.starts_with(UNUSABLE_PASSWORD_PREFIX)
}

/// Session entity stored with a cryptographic hash of the session token.
///
/// Intentionally does NOT derive `Serialize` to prevent `token_hash`
/// from leaking across API responses.
#[derive(Clone, FromRow, PartialEq, Eq)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    /// SHA-256 hex digest of the raw session token. Safe to store; raw token is never persisted.
    pub token_hash: String,
    pub created_at: DateTime<Utc>,
    /// Updated on every validated request. Used for idle timeout enforcement.
    pub last_active_at: DateTime<Utc>,
    /// Computed at creation: created_at + config.session.absolute_lifetime.
    pub absolute_expires_at: DateTime<Utc>,
    /// "cookie" or "bearer".
    pub session_type: String,
    /// 64-char hex CSRF token. None for bearer sessions.
    pub csrf_token: Option<String>,
}

// Manual `Debug`: `token_hash` authenticates bearer sessions; csrf tokens
// are per-session secrets. Neither belongs in logs or traces.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("token_hash", &"[redacted]")
            .field("created_at", &self.created_at)
            .field("last_active_at", &self.last_active_at)
            .field("absolute_expires_at", &self.absolute_expires_at)
            .field("session_type", &self.session_type)
            .field(
                "csrf_token",
                &self.csrf_token.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

/// Single-use email verification token entity.
///
/// Intentionally does NOT derive `Serialize` to prevent `token_hash`
/// from leaking across API responses.
#[derive(Clone, FromRow, PartialEq, Eq)]
pub struct VerificationToken {
    pub token_hash: Vec<u8>,
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

// Manual `Debug`: the hash preimage is a live single-use token.
impl std::fmt::Debug for VerificationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerificationToken")
            .field("token_hash", &"[redacted]")
            .field("user_id", &self.user_id)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Single-use password reset token entity.
///
/// Intentionally does NOT derive `Serialize` to prevent `token_hash`
/// from leaking across API responses.
#[derive(Clone, FromRow, PartialEq, Eq)]
pub struct PasswordResetToken {
    pub token_hash: Vec<u8>,
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

// Manual `Debug`: the hash preimage is a live single-use token.
impl std::fmt::Debug for PasswordResetToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordResetToken")
            .field("token_hash", &"[redacted]")
            .field("user_id", &self.user_id)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

pub const OUTBOX_STATUS_PENDING: &str = "pending";
pub const OUTBOX_STATUS_PROCESSING: &str = "processing";
pub const OUTBOX_STATUS_SENT: &str = "sent";
pub const OUTBOX_STATUS_FAILED: &str = "failed";

pub const EMAIL_TYPE_VERIFICATION: &str = "verification";
pub const EMAIL_TYPE_PASSWORD_RESET: &str = "password_reset";

/// Transactional email outbox entity.
///
/// Guarantees at-least-once email delivery across application crashes
/// and transient network failures by capturing dispatches inside the database transaction.
#[derive(Clone, FromRow, PartialEq, Eq)]
pub struct EmailOutbox {
    pub id: Uuid,
    pub recipient: String,
    pub email_type: String,
    pub payload: serde_json::Value,
    pub status: String,
    pub retry_count: i32,
    pub next_retry_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub sent_at: Option<DateTime<Utc>>,
    pub error_log: Option<String>,
}

// Manual `Debug`: `payload` carries raw single-use tokens; never log the row verbatim.
impl std::fmt::Debug for EmailOutbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailOutbox")
            .field("id", &self.id)
            .field("recipient", &self.recipient)
            .field("email_type", &self.email_type)
            .field("payload", &"[redacted]")
            .field("status", &self.status)
            .field("retry_count", &self.retry_count)
            .field("next_retry_at", &self.next_retry_at)
            .field("created_at", &self.created_at)
            .field("sent_at", &self.sent_at)
            .field("error_log", &self.error_log)
            .finish()
    }
}

/// Domain model for an external federated identity linked to a user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct OAuthAccount {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider_id: String,
    pub provider_user_id: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A user's TOTP enrollment record.
///
/// `encrypted_secret` is AES-256-GCM ciphertext (`nonce || ciphertext || tag`);
/// `backup_codes` holds Argon2id PHC strings only. Intentionally does NOT derive
/// `Serialize` so neither the ciphertext nor the hashes can reach an API response.
#[derive(Clone, FromRow, PartialEq, Eq)]
pub struct TotpSecret {
    pub id: Uuid,
    pub user_id: Uuid,
    pub encrypted_secret: Vec<u8>,
    pub backup_codes: serde_json::Value,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Manual `Debug`: the ciphertext decrypts to the TOTP seed, the JSON array holds
// backup-code hashes. Neither belongs in logs or traces.
impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpSecret")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("encrypted_secret", &"[redacted]")
            .field("backup_codes", &"[redacted]")
            .field("enabled", &self.enabled)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Replay-tracking row for a consumed TOTP code.
///
/// `code_hash` is SHA-256 of `code_string || "::" || step`; the raw code is never stored.
#[derive(Clone, FromRow, PartialEq, Eq)]
pub struct TotpUsedCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: Vec<u8>,
    pub used_at: DateTime<Utc>,
}

// Manual `Debug`: the hash identifies a live one-time code.
impl std::fmt::Debug for TotpUsedCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpUsedCode")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("code_hash", &"[redacted]")
            .field("used_at", &self.used_at)
            .finish()
    }
}

/// Intermediate two-factor challenge token issued between password and second factor.
///
/// `token_hash` is SHA-256 of the raw token. Intentionally does NOT derive `Serialize`
/// so the hash cannot reach an API response.
#[derive(Clone, FromRow, PartialEq, Eq)]
pub struct TwoFactorToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}

// Manual `Debug`: the hash preimage is a live half-authentication credential.
impl std::fmt::Debug for TwoFactorToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoFactorToken")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("token_hash", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_to_user_response_conversion() {
        let now = Utc::now();
        let user_id = Uuid::new_v4();
        let user = User {
            id: user_id,
            email: "alice@example.com".to_string(),
            password_hash: "argon2id$hashedpassword".to_string(),
            email_verified: true,
            created_at: now,
            updated_at: now,
        };

        let response = UserResponse::from(&user);
        assert_eq!(response.id, user_id);
        assert_eq!(response.email, "alice@example.com");
        assert!(response.email_verified);
        assert_eq!(response.created_at, now);

        let json = serde_json::to_string(&response).expect("serialize response");
        assert!(!json.contains("password_hash"));
        assert!(!json.contains("argon2id"));
    }

    #[test]
    fn test_email_outbox_model_and_constants() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let outbox = EmailOutbox {
            id,
            recipient: "user@example.com".to_string(),
            email_type: EMAIL_TYPE_VERIFICATION.to_string(),
            payload: serde_json::json!({"test": "data"}),
            status: OUTBOX_STATUS_PENDING.to_string(),
            retry_count: 0,
            next_retry_at: now,
            created_at: now,
            sent_at: None,
            error_log: None,
        };

        assert_eq!(outbox.id, id);
        assert_eq!(outbox.status, OUTBOX_STATUS_PENDING);
        assert_eq!(outbox.email_type, EMAIL_TYPE_VERIFICATION);
        assert_eq!(outbox.retry_count, 0);
        assert_eq!(outbox.sent_at, None);
        assert_eq!(outbox.error_log, None);
    }

    #[test]
    fn db_entities_debug_redacts_secrets() {
        let now = Utc::now();
        let user = User {
            id: Uuid::new_v4(),
            email: "alice@example.com".to_string(),
            password_hash: "argon2id$v=19$m=65536,t=3,p=4$salt$hash".to_string(),
            email_verified: true,
            created_at: now,
            updated_at: now,
        };
        let rendered = format!("{user:?}");
        assert!(!rendered.contains("argon2id"));
        assert!(rendered.contains("alice@example.com"));

        let session = Session {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash: "deadbeef".to_string(),
            created_at: now,
            last_active_at: now,
            absolute_expires_at: now,
            session_type: "cookie".to_string(),
            csrf_token: Some("csrf-secret".to_string()),
        };
        let rendered = format!("{session:?}");
        assert!(!rendered.contains("deadbeef"));
        assert!(!rendered.contains("csrf-secret"));

        let token = VerificationToken {
            token_hash: vec![0xAA, 0xBB],
            user_id: user.id,
            expires_at: now,
            created_at: now,
        };
        let rendered_token = format!("{token:?}");
        assert!(!rendered_token.contains("[170, 187]"));
        assert!(rendered_token.contains("token_hash: \"[redacted]\""));

        let reset = PasswordResetToken {
            token_hash: vec![0xCC, 0xDD],
            user_id: user.id,
            expires_at: now,
            created_at: now,
        };
        let rendered_reset = format!("{reset:?}");
        assert!(!rendered_reset.contains("[204, 221]"));
        assert!(rendered_reset.contains("token_hash: \"[redacted]\""));

        let outbox = EmailOutbox {
            id: Uuid::new_v4(),
            recipient: "user@example.com".to_string(),
            email_type: EMAIL_TYPE_VERIFICATION.to_string(),
            payload: serde_json::json!({"token": "raw-single-use-token"}),
            status: OUTBOX_STATUS_PENDING.to_string(),
            retry_count: 0,
            next_retry_at: now,
            created_at: now,
            sent_at: None,
            error_log: None,
        };
        assert!(!format!("{outbox:?}").contains("raw-single-use-token"));

        let totp_secret = TotpSecret {
            id: Uuid::new_v4(),
            user_id: user.id,
            encrypted_secret: vec![0x11, 0x22, 0x33],
            backup_codes: serde_json::json!(["$argon2id$v=19$m=19456,t=2,p=1$salt$hash"]),
            enabled: true,
            created_at: now,
            updated_at: now,
        };
        let rendered_totp = format!("{totp_secret:?}");
        assert!(!rendered_totp.contains("[17, 34, 51]"));
        assert!(!rendered_totp.contains("$argon2id$"));
        assert!(rendered_totp.contains("enabled: true"));

        let used_code = TotpUsedCode {
            id: Uuid::new_v4(),
            user_id: user.id,
            code_hash: vec![0x44, 0x55],
            used_at: now,
        };
        let rendered_used = format!("{used_code:?}");
        assert!(!rendered_used.contains("[68, 85]"));
        assert!(rendered_used.contains("code_hash: \"[redacted]\""));

        let two_factor = TwoFactorToken {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash: vec![0x66, 0x77],
            expires_at: now,
        };
        let rendered_two_factor = format!("{two_factor:?}");
        assert!(!rendered_two_factor.contains("[102, 119]"));
        assert!(rendered_two_factor.contains("token_hash: \"[redacted]\""));
    }

    #[test]
    fn test_oauth_account_model_serialization_and_fields() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let account = OAuthAccount {
            id,
            user_id,
            provider_id: "google".to_string(),
            provider_user_id: "google-123".to_string(),
            email: "user@example.com".to_string(),
            created_at: now,
            updated_at: now,
        };

        assert_eq!(account.provider_id, "google");
        assert_eq!(account.provider_user_id, "google-123");
        assert_eq!(account.email, "user@example.com");

        let json = serde_json::to_string(&account).expect("serialize oauth account");
        let deserialized: OAuthAccount =
            serde_json::from_str(&json).expect("deserialize oauth account");
        assert_eq!(deserialized, account);
    }
}
