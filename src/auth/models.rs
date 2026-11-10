use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    config::AppConfig,
    crypto::blocklist::is_common_password,
    error::{AppError, AppResult},
};

pub use crate::db::models::{
    PasswordResetToken, PasswordResetToken as PasswordResetTokenRow, User, User as UserRow,
    VerificationToken, VerificationToken as VerificationTokenRow,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageResponse {
    pub message: String,
}

impl MessageResponse {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginResponse {
    pub user_id: Uuid,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
}

impl SignupRequest {
    pub fn validate(&self, config: &AppConfig) -> AppResult<()> {
        validate_email(&self.email)?;
        validate_password(&self.password, config)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

impl LoginRequest {
    pub fn validate(&self) -> AppResult<()> {
        let email = self.email.trim();
        if email.is_empty() || self.password.is_empty() {
            return Err(AppError::InvalidCredentials);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct VerifyEmailRequest {
    pub token: String,
}

impl VerifyEmailRequest {
    pub fn validate(&self) -> AppResult<()> {
        if self.token.len() != 64 || !self.token.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AppError::InvalidToken);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PasswordResetRequest {
    pub email: String,
}

impl PasswordResetRequest {
    pub fn validate(&self) -> AppResult<()> {
        validate_email(&self.email)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PasswordResetConfirmRequest {
    pub token: String,
    pub new_password: String,
}

impl PasswordResetConfirmRequest {
    pub fn validate(&self, config: &AppConfig) -> AppResult<()> {
        if self.token.len() != 64 || !self.token.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AppError::InvalidToken);
        }
        validate_password(&self.new_password, config)?;
        Ok(())
    }
}

pub fn validate_email(email: &str) -> AppResult<()> {
    let trimmed = email.trim();
    if trimmed.is_empty() || trimmed.len() > 255 {
        return Err(AppError::InvalidEmail);
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(AppError::InvalidEmail);
    }
    let mut parts = trimmed.split('@');
    let local = parts.next().ok_or(AppError::InvalidEmail)?;
    let domain = parts.next().ok_or(AppError::InvalidEmail)?;
    if parts.next().is_some() {
        return Err(AppError::InvalidEmail);
    }
    if local.is_empty() || domain.is_empty() {
        return Err(AppError::InvalidEmail);
    }
    if domain.starts_with('.')
        || domain.ends_with('.')
        || !domain.contains('.')
        || domain.contains("..")
    {
        return Err(AppError::InvalidEmail);
    }
    Ok(())
}

pub fn validate_password(password: &str, config: &AppConfig) -> AppResult<()> {
    let count = password.chars().count();
    if count < config.password_min_len {
        return Err(AppError::PasswordTooShort);
    }
    if count > config.password_max_len {
        return Err(AppError::PasswordTooLong);
    }
    if is_common_password(password) {
        return Err(AppError::PasswordTooCommon);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AppConfig {
        AppConfig {
            password_min_len: 8,
            password_max_len: 128,
            ..Default::default()
        }
    }

    #[test]
    fn test_user_response_serialization_excludes_password_hash() {
        let now = Utc::now();
        let user = User {
            id: Uuid::new_v4(),
            email: "alice@example.com".to_string(),
            password_hash: "$argon2id$v=19$m=65536,t=3,p=4$dummy_hash".to_string(),
            email_verified: true,
            created_at: now,
            updated_at: now,
        };

        let response = UserResponse::from(&user);
        let serialized = serde_json::to_string(&response).expect("serialization succeeds");
        assert!(!serialized.contains("password_hash"));
        assert!(!serialized.contains("password"));
        assert!(!serialized.contains("dummy_hash"));
    }

    #[test]
    fn test_signup_request_validation() {
        let config = test_config();

        // Valid
        let req = SignupRequest {
            email: "user@example.com".to_string(),
            password: "SecurePassword123!".to_string(),
        };
        assert!(req.validate(&config).is_ok());

        // Short password (< 8 chars)
        let req = SignupRequest {
            email: "user@example.com".to_string(),
            password: "short".to_string(),
        };
        assert!(matches!(
            req.validate(&config),
            Err(AppError::PasswordTooShort)
        ));

        // Long password (> 128 chars)
        let req = SignupRequest {
            email: "user@example.com".to_string(),
            password: "a".repeat(129),
        };
        assert!(matches!(
            req.validate(&config),
            Err(AppError::PasswordTooLong)
        ));

        // Common password
        let req = SignupRequest {
            email: "user@example.com".to_string(),
            password: "12345678".to_string(),
        };
        assert!(matches!(
            req.validate(&config),
            Err(AppError::PasswordTooCommon)
        ));

        // Invalid emails
        let invalid_emails = [
            "",
            "   ",
            "invalid",
            "@example.com",
            "user@",
            "user@example",
            "user@domain..com",
            "user@.domain.com",
            "user@domain.com.",
            "user@extra@domain.com",
            "user space@domain.com",
            "user\x00@domain.com",
        ];
        for email in invalid_emails {
            let req = SignupRequest {
                email: email.to_string(),
                password: "SecurePassword123!".to_string(),
            };
            assert!(
                matches!(req.validate(&config), Err(AppError::InvalidEmail)),
                "expected InvalidEmail for: {email}"
            );
        }

        let too_long_email = format!("{}@example.com", "a".repeat(245)); // 245 + 12 = 257 > 255
        let req = SignupRequest {
            email: too_long_email,
            password: "SecurePassword123!".to_string(),
        };
        assert!(matches!(req.validate(&config), Err(AppError::InvalidEmail)));
    }

    #[test]
    fn test_login_request_validation() {
        // Valid
        let req = LoginRequest {
            email: "user@example.com".to_string(),
            password: "any-password".to_string(),
        };
        assert!(req.validate().is_ok());

        // Empty email
        let req = LoginRequest {
            email: "".to_string(),
            password: "any-password".to_string(),
        };
        assert!(matches!(req.validate(), Err(AppError::InvalidCredentials)));

        // Whitespace email
        let req = LoginRequest {
            email: "   ".to_string(),
            password: "any-password".to_string(),
        };
        assert!(matches!(req.validate(), Err(AppError::InvalidCredentials)));

        // Empty password
        let req = LoginRequest {
            email: "user@example.com".to_string(),
            password: "".to_string(),
        };
        assert!(matches!(req.validate(), Err(AppError::InvalidCredentials)));
    }

    #[test]
    fn test_verify_email_request_validation() {
        // Valid 64-char hex
        let req = VerifyEmailRequest {
            token: "a".repeat(64),
        };
        assert!(req.validate().is_ok());

        // Short hex
        let req = VerifyEmailRequest {
            token: "a".repeat(63),
        };
        assert!(matches!(req.validate(), Err(AppError::InvalidToken)));

        // Long hex
        let req = VerifyEmailRequest {
            token: "a".repeat(65),
        };
        assert!(matches!(req.validate(), Err(AppError::InvalidToken)));

        // Non-hex chars
        let req = VerifyEmailRequest {
            token: format!("{}z", "a".repeat(63)),
        };
        assert!(matches!(req.validate(), Err(AppError::InvalidToken)));

        // Empty
        let req = VerifyEmailRequest {
            token: "".to_string(),
        };
        assert!(matches!(req.validate(), Err(AppError::InvalidToken)));

        // Whitespace-padded valid-length hex is rejected
        let req = VerifyEmailRequest {
            token: format!(" {} ", "a".repeat(62)),
        };
        assert!(matches!(req.validate(), Err(AppError::InvalidToken)));
    }

    #[test]
    fn test_password_reset_request_validation() {
        // Valid
        let req = PasswordResetRequest {
            email: "user@example.com".to_string(),
        };
        assert!(req.validate().is_ok());

        // Valid with whitespace (validate_email trims)
        let req = PasswordResetRequest {
            email: "  user@example.com  ".to_string(),
        };
        assert!(req.validate().is_ok());

        // Invalid emails
        let invalid_emails = [
            "",
            "   ",
            "invalid",
            "@example.com",
            "user@",
            "user@example",
        ];
        for email in invalid_emails {
            let req = PasswordResetRequest {
                email: email.to_string(),
            };
            assert!(
                matches!(req.validate(), Err(AppError::InvalidEmail)),
                "expected InvalidEmail for: {email}"
            );
        }
    }

    #[test]
    fn test_password_reset_confirm_request_validation() {
        let config = test_config();

        // Valid
        let req = PasswordResetConfirmRequest {
            token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            new_password: "FreshStrongPassword2026!".to_string(),
        };
        assert!(req.validate(&config).is_ok());

        // Whitespace-padded token is rejected
        let req = PasswordResetConfirmRequest {
            token: " 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef ".to_string(),
            new_password: "FreshStrongPassword2026!".to_string(),
        };
        assert!(matches!(req.validate(&config), Err(AppError::InvalidToken)));

        // Invalid token
        let req = PasswordResetConfirmRequest {
            token: "invalid-token".to_string(),
            new_password: "FreshStrongPassword2026!".to_string(),
        };
        assert!(matches!(req.validate(&config), Err(AppError::InvalidToken)));

        // Invalid password (too short)
        let req = PasswordResetConfirmRequest {
            token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            new_password: "short".to_string(),
        };
        assert!(matches!(
            req.validate(&config),
            Err(AppError::PasswordTooShort)
        ));
    }

    #[test]
    fn test_unicode_password_code_point_counting() {
        let mut config = test_config();
        config.password_min_len = 8;
        config.password_max_len = 10;

        // 8 code points of 4-byte emojis (32 bytes in UTF-8, but 8 characters)
        let exact_8_codepoints = "🦀🔥✨🚀⭐💡🎉🌟";
        assert_eq!(exact_8_codepoints.chars().count(), 8);
        assert!(exact_8_codepoints.len() > 8); // UTF-8 byte length > 8
        assert!(validate_password(exact_8_codepoints, &config).is_ok());

        let short_7_codepoints = "🦀🔥✨🚀⭐💡🎉";
        assert_eq!(short_7_codepoints.chars().count(), 7);
        assert!(matches!(
            validate_password(short_7_codepoints, &config),
            Err(AppError::PasswordTooShort)
        ));

        let long_11_codepoints = "🦀🔥✨🚀⭐💡🎉🌟🌈⚡🎯";
        assert_eq!(long_11_codepoints.chars().count(), 11);
        assert!(matches!(
            validate_password(long_11_codepoints, &config),
            Err(AppError::PasswordTooLong)
        ));
    }
}
