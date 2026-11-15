use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

pub use crate::auth::models::UserResponse;

/// Internal user database entity.
///
/// Intentionally does NOT derive `Serialize` to prevent `password_hash`
/// from ever leaking across API responses. Outbound serialization must
/// use [`UserResponse`](crate::auth::models::UserResponse).
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Session entity stored with a cryptographic hash of the session token.
///
/// Intentionally does NOT derive `Serialize` to prevent `token_hash`
/// from leaking across API responses.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
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

/// Single-use email verification token entity.
///
/// Intentionally does NOT derive `Serialize` to prevent `token_hash`
/// from leaking across API responses.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct VerificationToken {
    pub token_hash: Vec<u8>,
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Single-use password reset token entity.
///
/// Intentionally does NOT derive `Serialize` to prevent `token_hash`
/// from leaking across API responses.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct PasswordResetToken {
    pub token_hash: Vec<u8>,
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
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
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
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
}
