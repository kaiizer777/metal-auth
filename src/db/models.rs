use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

/// Internal user database entity.
///
/// Intentionally does NOT derive `Serialize` to prevent `password_hash`
/// from ever leaking across API responses. Outbound serialization must
/// use [`UserResponse`].
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Outbound user representation safe for client responses.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            email_verified: user.email_verified,
            created_at: user.created_at,
        }
    }
}

impl From<&User> for UserResponse {
    fn from(user: &User) -> Self {
        Self {
            id: user.id,
            email: user.email.clone(),
            email_verified: user.email_verified,
            created_at: user.created_at,
        }
    }
}

/// Session entity stored with a cryptographic hash of the session token.
///
/// Intentionally does NOT derive `Serialize` to prevent `token_hash`
/// from leaking across API responses.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
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
