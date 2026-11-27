use std::num::ParseIntError;

use axum::{
    Json,
    http::{
        StatusCode,
        header::{InvalidHeaderName, InvalidHeaderValue},
        method::InvalidMethod,
    },
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::email::hook::DynError;

/// Wire-level error code returned to API clients.
///
/// Non-exhaustive: every phase adds codes, and a caller matching on this type must not break
/// when one lands. Match with a wildcard.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    // Phase 1 — infra
    InvalidConfig,
    DatabaseError,
    DatabaseUnavailable,
    MigrationFailed,
    InternalError,
    NotFound,
    MethodNotAllowed,
    // Phase 3 — auth
    InvalidCredentials,
    Unauthenticated,
    EmailNotVerified,
    PasswordTooShort,
    PasswordTooLong,
    PasswordTooCommon,
    InvalidEmail,
    ValidationError,
    InvalidToken,
    TokenExpired,
    // Phase 4 — session, CSRF, rate limit
    SessionNotFound,
    SessionExpired,
    SessionInvalid,
    CsrfTokenMissing,
    CsrfTokenInvalid,
    RateLimitExceeded,
    // Phase 6 — OAuth / Social Login
    #[serde(rename = "OAUTH_STATE_INVALID")]
    OAuthStateInvalid,
    #[serde(rename = "OAUTH_CODE_INVALID")]
    OAuthCodeInvalid,
    #[serde(rename = "OAUTH_EMAIL_UNVERIFIED")]
    OAuthEmailUnverified,
    #[serde(rename = "OAUTH_PROVIDER_ERROR")]
    OAuthProviderError,
    #[serde(rename = "OAUTH_ACCOUNT_LINK_CONFLICT")]
    OAuthAccountLinkConflict,
    #[serde(rename = "OAUTH_PROVIDER_NOT_FOUND")]
    OAuthProviderNotFound,
    // Phase 7 — TOTP two-factor authentication
    #[serde(rename = "TOTP_NOT_ENROLLED")]
    TotpNotEnrolled,
    #[serde(rename = "TOTP_ALREADY_ENABLED")]
    TotpAlreadyEnabled,
    #[serde(rename = "TOTP_CODE_INVALID")]
    TotpCodeInvalid,
    #[serde(rename = "TOTP_CODE_EXPIRED")]
    TotpCodeExpired,
    #[serde(rename = "TOTP_CODE_REPLAYED")]
    TotpCodeReplayed,
    #[serde(rename = "TOTP_BACKUP_CODE_INVALID")]
    TotpBackupCodeInvalid,
    /// Not an error: the login sentinel returned when a second factor is required.
    #[serde(rename = "TWO_FACTOR_REQUIRED")]
    TwoFactorRequired,
    #[serde(rename = "TWO_FACTOR_TOKEN_INVALID")]
    TwoFactorTokenInvalid,
    #[serde(rename = "TWO_FACTOR_TOKEN_EXPIRED")]
    TwoFactorTokenExpired,
    /// Server-side refusal: the deployment cannot verify a second factor right now.
    #[serde(rename = "TWO_FACTOR_UNAVAILABLE")]
    TwoFactorUnavailable,
    #[serde(rename = "TOTP_RATE_LIMIT_EXCEEDED")]
    TotpRateLimitExceeded,
    // Multi-database abstraction sentinels
    #[serde(rename = "UNSUPPORTED_DATABASE_BACKEND")]
    UnsupportedDatabaseBackend,
    #[serde(rename = "TRANSACTION_NOT_SUPPORTED")]
    TransactionNotSupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing environment variable: {0}")]
    MissingEnvVar(&'static str),

    #[error("environment variable is not valid unicode: {0}")]
    NonUnicodeEnvVar(&'static str),

    #[error("invalid port")]
    InvalidPort(#[from] ParseIntError),

    #[error("invalid environment variable: {0}")]
    InvalidEnvVar(&'static str),

    #[error("invalid CORS origin: {value}")]
    InvalidOrigin {
        value: String,
        #[source]
        source: InvalidHeaderValue,
    },

    #[error("invalid CORS method: {value}")]
    InvalidMethod {
        value: String,
        #[source]
        source: InvalidMethod,
    },

    #[error("invalid CORS header: {value}")]
    InvalidHeader {
        value: String,
        #[source]
        source: InvalidHeaderName,
    },

    #[error("invalid value for {field}: {reason}")]
    InvalidValue {
        field: &'static str,
        reason: &'static str,
    },
}

/// Opaque backend-agnostic database error wrapping driver-specific errors.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct DbError {
    pub message: String,
    #[source]
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl DbError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    #[must_use]
    pub fn with_source(
        message: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(source.into()),
        }
    }
}

#[cfg(any(feature = "postgres", feature = "mysql", feature = "mongodb"))]
impl From<sqlx::Error> for DbError {
    fn from(err: sqlx::Error) -> Self {
        Self {
            message: err.to_string(),
            source: Some(Box::new(err)),
        }
    }
}

#[cfg(feature = "mongodb")]
impl From<mongodb::error::Error> for DbError {
    fn from(err: mongodb::error::Error) -> Self {
        Self {
            message: err.to_string(),
            source: Some(Box::new(err)),
        }
    }
}

#[cfg(feature = "mongodb")]
impl From<bson::ser::Error> for DbError {
    fn from(err: bson::ser::Error) -> Self {
        Self {
            message: err.to_string(),
            source: Some(Box::new(err)),
        }
    }
}

#[cfg(feature = "mongodb")]
impl From<bson::de::Error> for DbError {
    fn from(err: bson::de::Error) -> Self {
        Self {
            message: err.to_string(),
            source: Some(Box::new(err)),
        }
    }
}

/// Non-exhaustive: each phase adds variants, and embedders match on this type in their own
/// error mapping. Match with a wildcard.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("configuration error")]
    Config(#[from] ConfigError),

    #[error("database error")]
    Database(#[from] DbError),

    #[error("database unavailable")]
    DatabaseUnavailable(#[source] DbError),

    #[error("migration error")]
    Migration(#[source] DbError),

    #[error("unsupported database backend: {0}")]
    UnsupportedDatabaseBackend(String),

    #[error("transactions require a mongodb replica set")]
    TransactionNotSupported,

    #[error("not found")]
    NotFound,

    #[error("method not allowed")]
    MethodNotAllowed,

    #[error("internal error")]
    Internal,

    // Phase 2 — email dispatch
    /// Email sender hook was not configured when email dispatch was attempted.
    #[error("email sender not configured")]
    EmailHookNotConfigured,

    /// Email dispatch failed during external delivery via the email hook.
    #[error("email dispatch failed")]
    EmailDispatchFailed(#[source] DynError),

    /// Email dispatch exceeded configured timeout duration.
    #[error("email dispatch timed out")]
    EmailDispatchTimeout,

    // Phase 3 — auth errors
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("unauthenticated")]
    Unauthenticated,

    #[error("email not verified")]
    EmailNotVerified,

    #[error("password too short")]
    PasswordTooShort,

    #[error("password too long")]
    PasswordTooLong,

    #[error("password too common")]
    PasswordTooCommon,

    #[error("invalid email")]
    InvalidEmail,

    #[error("validation error: {0}")]
    ValidationError(String),

    #[error("invalid token")]
    InvalidToken,

    #[error("token expired")]
    TokenExpired,

    /// Internal-only sentinel indicating a signup attempt for an already registered email.
    ///
    /// Preserves anti-enumeration guarantees without revealing account existence to clients.
    #[error("email already exists")]
    EmailAlreadyExists,

    // Phase 4 — session, CSRF, rate limit
    #[error("session not found")]
    SessionNotFound,

    #[error("session expired")]
    SessionExpired,

    #[error("session invalid")]
    SessionInvalid,

    #[error("CSRF token missing")]
    CsrfTokenMissing,

    #[error("CSRF token invalid")]
    CsrfTokenInvalid,

    #[error("rate limit exceeded")]
    RateLimitExceeded,

    // Phase 6 — OAuth / Social Login
    #[error("invalid oauth state")]
    OAuthStateInvalid,

    #[error("oauth code is invalid")]
    OAuthCodeInvalid,

    #[error("oauth provider email is not verified")]
    OAuthEmailUnverified,

    #[error("oauth provider error")]
    OAuthProviderError,

    #[error("cannot link oauth identity to unverified local account")]
    OAuthAccountLinkConflict,

    #[error("oauth provider not found")]
    OAuthProviderNotFound,

    // Phase 7 — TOTP two-factor authentication
    #[error("totp not enrolled for this user")]
    TotpNotEnrolled,

    #[error("totp already enabled for this user")]
    TotpAlreadyEnabled,

    #[error("totp code is invalid")]
    TotpCodeInvalid,

    #[error("totp code window has expired")]
    TotpCodeExpired,

    #[error("totp code has already been used")]
    TotpCodeReplayed,

    #[error("backup code is invalid")]
    TotpBackupCodeInvalid,

    /// Wire-code mapping for [`ErrorCode::TwoFactorRequired`] only — never returned from a handler.
    ///
    /// [`Self::status_code`] maps it to `200 OK`, and the error envelope cannot carry the
    /// `challenge_token`. The 2FA login contract is a success body
    /// (`{"two_factor_required": true, "challenge_token": …}`), not an `Err`.
    #[error("two factor authentication required")]
    TwoFactorRequired,

    #[error("two factor token is invalid")]
    TwoFactorTokenInvalid,

    #[error("two factor token has expired")]
    TwoFactorTokenExpired,

    /// The deployment cannot verify this factor (no TOTP key, missing challenge storage).
    /// A server fault, never a statement about the presented code.
    #[error("two factor authentication is temporarily unavailable")]
    TwoFactorUnavailable,

    #[error("totp rate limit exceeded")]
    TotpRateLimitExceeded,

    /// Enrollment on an unverified email. Distinct from [`Self::EmailNotVerified`],
    /// which stays `403` for the login contract; this one answers `400`.
    #[error("totp enrollment requires a verified email")]
    TotpEmailNotVerified,
}

impl AppError {
    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Config(_) => ErrorCode::InvalidConfig,
            Self::Database(_) => ErrorCode::DatabaseError,
            Self::DatabaseUnavailable(_) => ErrorCode::DatabaseUnavailable,
            Self::Migration(_) => ErrorCode::MigrationFailed,
            Self::NotFound => ErrorCode::NotFound,
            Self::MethodNotAllowed => ErrorCode::MethodNotAllowed,
            Self::Internal
            | Self::EmailHookNotConfigured
            | Self::EmailDispatchFailed(_)
            | Self::EmailDispatchTimeout
            | Self::EmailAlreadyExists => ErrorCode::InternalError,
            // Phase 3
            Self::InvalidCredentials => ErrorCode::InvalidCredentials,
            Self::Unauthenticated => ErrorCode::Unauthenticated,
            Self::EmailNotVerified => ErrorCode::EmailNotVerified,
            Self::PasswordTooShort => ErrorCode::PasswordTooShort,
            Self::PasswordTooLong => ErrorCode::PasswordTooLong,
            Self::PasswordTooCommon => ErrorCode::PasswordTooCommon,
            Self::InvalidEmail => ErrorCode::InvalidEmail,
            Self::ValidationError(_) => ErrorCode::ValidationError,
            Self::InvalidToken => ErrorCode::InvalidToken,
            Self::TokenExpired => ErrorCode::TokenExpired,
            // Phase 4
            Self::SessionNotFound => ErrorCode::SessionNotFound,
            Self::SessionExpired => ErrorCode::SessionExpired,
            Self::SessionInvalid => ErrorCode::SessionInvalid,
            Self::CsrfTokenMissing => ErrorCode::CsrfTokenMissing,
            Self::CsrfTokenInvalid => ErrorCode::CsrfTokenInvalid,
            Self::RateLimitExceeded => ErrorCode::RateLimitExceeded,
            // Phase 6
            Self::OAuthStateInvalid => ErrorCode::OAuthStateInvalid,
            Self::OAuthCodeInvalid => ErrorCode::OAuthCodeInvalid,
            Self::OAuthEmailUnverified => ErrorCode::OAuthEmailUnverified,
            Self::OAuthProviderError => ErrorCode::OAuthProviderError,
            Self::OAuthAccountLinkConflict => ErrorCode::OAuthAccountLinkConflict,
            Self::OAuthProviderNotFound => ErrorCode::OAuthProviderNotFound,
            // Phase 7
            Self::TotpNotEnrolled => ErrorCode::TotpNotEnrolled,
            Self::TotpAlreadyEnabled => ErrorCode::TotpAlreadyEnabled,
            Self::TotpCodeInvalid => ErrorCode::TotpCodeInvalid,
            Self::TotpCodeExpired => ErrorCode::TotpCodeExpired,
            Self::TotpCodeReplayed => ErrorCode::TotpCodeReplayed,
            Self::TotpBackupCodeInvalid => ErrorCode::TotpBackupCodeInvalid,
            Self::TwoFactorRequired => ErrorCode::TwoFactorRequired,
            Self::TwoFactorTokenInvalid => ErrorCode::TwoFactorTokenInvalid,
            Self::TwoFactorTokenExpired => ErrorCode::TwoFactorTokenExpired,
            Self::TwoFactorUnavailable => ErrorCode::TwoFactorUnavailable,
            Self::TotpRateLimitExceeded => ErrorCode::TotpRateLimitExceeded,
            Self::UnsupportedDatabaseBackend(_) => ErrorCode::UnsupportedDatabaseBackend,
            Self::TransactionNotSupported => ErrorCode::TransactionNotSupported,
            // Shares the login wire code, keeps its own 400 mapping.
            Self::TotpEmailNotVerified => ErrorCode::EmailNotVerified,
        }
    }

    #[must_use]
    pub fn code(&self) -> ErrorCode {
        self.error_code()
    }

    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::DatabaseUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::Config(_)
            | Self::Database(_)
            | Self::Migration(_)
            | Self::Internal
            | Self::EmailHookNotConfigured
            | Self::EmailDispatchFailed(_)
            | Self::EmailDispatchTimeout
            | Self::EmailAlreadyExists
            | Self::UnsupportedDatabaseBackend(_) => StatusCode::INTERNAL_SERVER_ERROR,
            // 401
            Self::InvalidCredentials
            | Self::Unauthenticated
            | Self::SessionNotFound
            | Self::SessionExpired
            | Self::SessionInvalid => StatusCode::UNAUTHORIZED,
            // 403
            Self::EmailNotVerified
            | Self::CsrfTokenMissing
            | Self::CsrfTokenInvalid
            | Self::OAuthStateInvalid => StatusCode::FORBIDDEN,
            // 404
            Self::OAuthProviderNotFound => StatusCode::NOT_FOUND,
            // 409
            Self::OAuthAccountLinkConflict => StatusCode::CONFLICT,
            // 502
            Self::OAuthProviderError => StatusCode::BAD_GATEWAY,
            // 429
            Self::RateLimitExceeded | Self::TotpRateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            // 200 — sentinel, not a failure
            Self::TwoFactorRequired => StatusCode::OK,
            // 401 — challenge token
            Self::TwoFactorTokenInvalid | Self::TwoFactorTokenExpired => StatusCode::UNAUTHORIZED,
            // 503 — the deployment cannot verify a factor at all
            Self::TwoFactorUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            // 409 — already enrolled
            Self::TotpAlreadyEnabled => StatusCode::CONFLICT,
            // 501
            Self::TransactionNotSupported => StatusCode::NOT_IMPLEMENTED,
            // 400
            Self::PasswordTooShort
            | Self::PasswordTooLong
            | Self::PasswordTooCommon
            | Self::InvalidEmail
            | Self::ValidationError(_)
            | Self::InvalidToken
            | Self::TokenExpired
            | Self::OAuthCodeInvalid
            | Self::OAuthEmailUnverified
            | Self::TotpNotEnrolled
            | Self::TotpCodeInvalid
            | Self::TotpCodeExpired
            | Self::TotpCodeReplayed
            | Self::TotpBackupCodeInvalid
            | Self::TotpEmailNotVerified => StatusCode::BAD_REQUEST,
        }
    }

    #[must_use]
    pub fn response_message(&self) -> String {
        match self {
            Self::Config(_) => "Invalid configuration".to_owned(),
            Self::Database(_) => "Database error".to_owned(),
            Self::DatabaseUnavailable(_) => "Database unavailable".to_owned(),
            Self::Migration(_) => "Migration failed".to_owned(),
            Self::NotFound => "Not found".to_owned(),
            Self::MethodNotAllowed => "Method not allowed".to_owned(),
            Self::Internal
            | Self::EmailHookNotConfigured
            | Self::EmailDispatchFailed(_)
            | Self::EmailDispatchTimeout
            | Self::EmailAlreadyExists => "Internal error".to_owned(),
            // Phase 3
            Self::InvalidCredentials => "Invalid email or password".to_owned(),
            Self::Unauthenticated => "Authentication required".to_owned(),
            Self::EmailNotVerified => "Email address has not been verified".to_owned(),
            Self::PasswordTooShort => {
                "Password does not meet the minimum length requirement".to_owned()
            }
            Self::PasswordTooLong => "Password exceeds the maximum length requirement".to_owned(),
            Self::PasswordTooCommon => {
                "Password is too common, please choose a stronger password".to_owned()
            }
            Self::InvalidEmail => "Invalid email address".to_owned(),
            Self::ValidationError(msg) => {
                if msg.is_empty() {
                    "Invalid request body".to_owned()
                } else {
                    msg.to_owned()
                }
            }
            Self::InvalidToken => "Invalid or already used token".to_owned(),
            Self::TokenExpired => "Token has expired".to_owned(),
            // Phase 4
            Self::SessionNotFound | Self::SessionExpired | Self::SessionInvalid => {
                "Session is invalid or has expired".to_owned()
            }
            Self::CsrfTokenMissing => "CSRF token is missing".to_owned(),
            Self::CsrfTokenInvalid => "CSRF token is invalid".to_owned(),
            Self::RateLimitExceeded => "Too many requests, please try again later".to_owned(),
            // Phase 6
            Self::OAuthStateInvalid => "invalid oauth state".to_owned(),
            Self::OAuthCodeInvalid => "oauth code is invalid".to_owned(),
            Self::OAuthEmailUnverified => "oauth provider email is not verified".to_owned(),
            Self::OAuthProviderNotFound => "oauth provider not found".to_owned(),
            Self::OAuthAccountLinkConflict => {
                "cannot link oauth identity to unverified local account".to_owned()
            }
            Self::OAuthProviderError => "oauth provider error".to_owned(),
            // Phase 7
            Self::TotpNotEnrolled => "totp not enrolled for this user".to_owned(),
            Self::TotpAlreadyEnabled => "totp already enabled for this user".to_owned(),
            Self::TotpCodeInvalid => "totp code is invalid".to_owned(),
            Self::TotpCodeExpired => "totp code window has expired".to_owned(),
            Self::TotpCodeReplayed => "totp code has already been used".to_owned(),
            Self::TotpBackupCodeInvalid => "backup code is invalid".to_owned(),
            Self::TwoFactorRequired => "two factor authentication required".to_owned(),
            Self::TwoFactorTokenInvalid => "two factor token is invalid".to_owned(),
            Self::TwoFactorTokenExpired => "two factor token has expired".to_owned(),
            Self::TwoFactorUnavailable => {
                "two factor authentication is temporarily unavailable".to_owned()
            }
            Self::TotpRateLimitExceeded => "totp rate limit exceeded".to_owned(),
            Self::UnsupportedDatabaseBackend(msg) => {
                if msg.is_empty() {
                    "Unsupported database backend".to_owned()
                } else {
                    format!("Unsupported database backend: {msg}")
                }
            }
            Self::TransactionNotSupported => {
                "transactions require a mongodb replica set".to_owned()
            }
            // Same wire code and message as the login gate.
            Self::TotpEmailNotVerified => "Email address has not been verified".to_owned(),
        }
    }

    /// Reconstruct a typed error from a wire [`ErrorCode`] for status mapping.
    ///
    /// Only meaningful for stateless codes (session, CSRF, rate limit, auth);
    /// every production caller uses those arms. The infra arms synthesize
    /// placeholder sources that were never observed — never treat their
    /// `source()` chains as real diagnostics.
    #[must_use]
    pub fn from_code(code: ErrorCode) -> Self {
        match code {
            ErrorCode::InvalidConfig => Self::Config(ConfigError::InvalidValue {
                field: "unknown",
                reason: "invalid configuration",
            }),
            ErrorCode::DatabaseError => Self::Database(DbError::new("Database error")),
            ErrorCode::DatabaseUnavailable => {
                Self::DatabaseUnavailable(DbError::new("Database unavailable"))
            }
            ErrorCode::MigrationFailed => Self::Migration(DbError::new("Migration failed")),
            ErrorCode::UnsupportedDatabaseBackend => {
                Self::UnsupportedDatabaseBackend("unsupported database backend".into())
            }
            ErrorCode::TransactionNotSupported => Self::TransactionNotSupported,
            ErrorCode::NotFound => Self::NotFound,
            ErrorCode::MethodNotAllowed => Self::MethodNotAllowed,
            ErrorCode::InternalError => Self::Internal,
            ErrorCode::InvalidCredentials => Self::InvalidCredentials,
            ErrorCode::Unauthenticated => Self::Unauthenticated,
            ErrorCode::EmailNotVerified => Self::EmailNotVerified,
            ErrorCode::PasswordTooShort => Self::PasswordTooShort,
            ErrorCode::PasswordTooLong => Self::PasswordTooLong,
            ErrorCode::PasswordTooCommon => Self::PasswordTooCommon,
            ErrorCode::InvalidEmail => Self::InvalidEmail,
            ErrorCode::ValidationError => Self::ValidationError("validation error".into()),
            ErrorCode::InvalidToken => Self::InvalidToken,
            ErrorCode::TokenExpired => Self::TokenExpired,
            ErrorCode::SessionNotFound => Self::SessionNotFound,
            ErrorCode::SessionExpired => Self::SessionExpired,
            ErrorCode::SessionInvalid => Self::SessionInvalid,
            ErrorCode::CsrfTokenMissing => Self::CsrfTokenMissing,
            ErrorCode::CsrfTokenInvalid => Self::CsrfTokenInvalid,
            ErrorCode::RateLimitExceeded => Self::RateLimitExceeded,
            // Phase 6
            ErrorCode::OAuthStateInvalid => Self::OAuthStateInvalid,
            ErrorCode::OAuthCodeInvalid => Self::OAuthCodeInvalid,
            ErrorCode::OAuthEmailUnverified => Self::OAuthEmailUnverified,
            ErrorCode::OAuthProviderError => Self::OAuthProviderError,
            ErrorCode::OAuthAccountLinkConflict => Self::OAuthAccountLinkConflict,
            ErrorCode::OAuthProviderNotFound => Self::OAuthProviderNotFound,
            // Phase 7
            ErrorCode::TotpNotEnrolled => Self::TotpNotEnrolled,
            ErrorCode::TotpAlreadyEnabled => Self::TotpAlreadyEnabled,
            ErrorCode::TotpCodeInvalid => Self::TotpCodeInvalid,
            ErrorCode::TotpCodeExpired => Self::TotpCodeExpired,
            ErrorCode::TotpCodeReplayed => Self::TotpCodeReplayed,
            ErrorCode::TotpBackupCodeInvalid => Self::TotpBackupCodeInvalid,
            // Mapping-only: no handler ever produces this, see `Self::TwoFactorRequired`.
            ErrorCode::TwoFactorRequired => Self::TwoFactorRequired,
            ErrorCode::TwoFactorTokenInvalid => Self::TwoFactorTokenInvalid,
            ErrorCode::TwoFactorTokenExpired => Self::TwoFactorTokenExpired,
            ErrorCode::TwoFactorUnavailable => Self::TwoFactorUnavailable,
            ErrorCode::TotpRateLimitExceeded => Self::TotpRateLimitExceeded,
        }
    }

    #[must_use]
    pub fn internal() -> Self {
        Self::Internal
    }
}

/// Upper bound on user-controlled characters emitted into a single log field.
const MAX_LOG_FIELD_CHARS: usize = 256;

/// Truncate user-controlled input for log fields, always at a char boundary.
pub(crate) fn truncate_for_log(input: &str) -> &str {
    match input.char_indices().nth(MAX_LOG_FIELD_CHARS) {
        Some((idx, _)) => &input[..idx],
        None => input,
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match &self {
            Self::Config(err) => tracing::error!(error = %err, "configuration error"),
            Self::Database(err) => tracing::error!(error = %err, "internal database error"),
            Self::DatabaseUnavailable(err) => tracing::error!(error = %err, "database unavailable"),
            Self::Migration(err) => tracing::error!(error = %err, "migration failed"),
            Self::NotFound => tracing::debug!("resource not found"),
            Self::MethodNotAllowed => tracing::debug!("method not allowed"),
            Self::Internal => tracing::error!("internal error"),
            Self::EmailHookNotConfigured => tracing::error!("email hook not configured"),
            Self::EmailDispatchFailed(err) => {
                tracing::error!(error = %err, "email dispatch failed")
            }
            Self::EmailDispatchTimeout => tracing::error!("email dispatch timed out"),
            // Phase 3 — log at appropriate levels; never log credentials
            Self::InvalidCredentials => tracing::debug!("invalid credentials attempt"),
            Self::Unauthenticated => tracing::debug!("unauthenticated request"),
            Self::EmailNotVerified => tracing::debug!("login blocked: email not verified"),
            Self::PasswordTooShort => tracing::debug!("password too short"),
            Self::PasswordTooLong => tracing::debug!("password too long"),
            Self::PasswordTooCommon => tracing::debug!("password too common"),
            Self::InvalidEmail => tracing::debug!("invalid email format"),
            Self::ValidationError(msg) => {
                tracing::debug!(msg = %truncate_for_log(msg), "validation error")
            }
            Self::InvalidToken => tracing::debug!("invalid or consumed token"),
            Self::TokenExpired => tracing::debug!("expired token presented"),
            // EmailAlreadyExists is internal-only — never reaches this handler in normal flow
            Self::EmailAlreadyExists => tracing::info!("signup attempt on existing account"),
            // Phase 4 — session, CSRF, rate limit
            Self::SessionNotFound | Self::SessionExpired | Self::SessionInvalid => {
                tracing::debug!("session validation failure")
            }
            Self::CsrfTokenMissing | Self::CsrfTokenInvalid => {
                tracing::debug!("csrf validation failure")
            }
            Self::RateLimitExceeded => tracing::warn!("rate limit exceeded"),
            // Phase 6
            Self::OAuthStateInvalid => tracing::warn!("oauth state validation failed"),
            Self::OAuthCodeInvalid => tracing::warn!("oauth code invalid"),
            Self::OAuthEmailUnverified => tracing::warn!("oauth email unverified"),
            Self::OAuthProviderError => tracing::error!("oauth provider error"),
            Self::OAuthAccountLinkConflict => tracing::warn!("oauth account link conflict"),
            Self::OAuthProviderNotFound => tracing::debug!("oauth provider not found"),
            // Phase 7
            Self::TotpNotEnrolled => tracing::debug!("totp not enrolled"),
            Self::TotpAlreadyEnabled => tracing::debug!("totp already enabled"),
            Self::TotpCodeInvalid => tracing::debug!("totp code invalid"),
            Self::TotpCodeExpired => tracing::debug!("totp code window expired"),
            Self::TotpCodeReplayed => tracing::warn!("totp code replay rejected"),
            Self::TotpBackupCodeInvalid => tracing::debug!("backup code invalid"),
            Self::TwoFactorRequired => tracing::debug!("two factor authentication required"),
            Self::TwoFactorTokenInvalid | Self::TwoFactorTokenExpired => {
                tracing::debug!("two factor token validation failure")
            }
            Self::TwoFactorUnavailable => tracing::error!("two factor verification unavailable"),
            Self::TotpRateLimitExceeded => tracing::warn!("totp rate limit exceeded"),
            Self::TotpEmailNotVerified => {
                tracing::debug!("totp enrollment blocked: email not verified")
            }
            Self::UnsupportedDatabaseBackend(backend) => {
                tracing::error!(backend = %backend, "unsupported database backend")
            }
            Self::TransactionNotSupported => {
                tracing::error!("transactions not supported on this database deployment")
            }
        }

        let status = self.status_code();
        let payload = ErrorResponse::from(&self);
        let mut resp = (status, Json(payload)).into_response();

        // RFC 6750 §3.1: Bearer 401s must carry a WWW-Authenticate challenge.
        if matches!(
            self,
            Self::SessionNotFound | Self::SessionExpired | Self::SessionInvalid
        ) {
            resp.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static(
                    r#"Bearer realm="metal-auth", error="invalid_token""#,
                ),
            );
        }

        resp
    }
}

impl From<&AppError> for ErrorResponse {
    fn from(err: &AppError) -> Self {
        Self {
            code: err.error_code(),
            message: err.response_message(),
        }
    }
}

#[cfg(any(feature = "postgres", feature = "mysql", feature = "mongodb"))]
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(DbError::from(err))
    }
}

#[cfg(any(feature = "postgres", feature = "mysql", feature = "mongodb"))]
impl From<sqlx::migrate::MigrateError> for AppError {
    fn from(err: sqlx::migrate::MigrateError) -> Self {
        Self::Migration(DbError {
            message: err.to_string(),
            source: Some(Box::new(err)),
        })
    }
}

#[cfg(feature = "mongodb")]
impl From<mongodb::error::Error> for AppError {
    fn from(err: mongodb::error::Error) -> Self {
        Self::Database(DbError::from(err))
    }
}

/// Convenience alias used throughout the service and handler layers.
pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_serialization_and_deserialization() {
        let cases = [
            (ErrorCode::InvalidConfig, "\"INVALID_CONFIG\""),
            (ErrorCode::DatabaseError, "\"DATABASE_ERROR\""),
            (ErrorCode::DatabaseUnavailable, "\"DATABASE_UNAVAILABLE\""),
            (ErrorCode::MigrationFailed, "\"MIGRATION_FAILED\""),
            (ErrorCode::InternalError, "\"INTERNAL_ERROR\""),
            (ErrorCode::NotFound, "\"NOT_FOUND\""),
            (ErrorCode::MethodNotAllowed, "\"METHOD_NOT_ALLOWED\""),
            // Phase 3
            (ErrorCode::InvalidCredentials, "\"INVALID_CREDENTIALS\""),
            (ErrorCode::Unauthenticated, "\"UNAUTHENTICATED\""),
            (ErrorCode::EmailNotVerified, "\"EMAIL_NOT_VERIFIED\""),
            (ErrorCode::PasswordTooShort, "\"PASSWORD_TOO_SHORT\""),
            (ErrorCode::PasswordTooLong, "\"PASSWORD_TOO_LONG\""),
            (ErrorCode::PasswordTooCommon, "\"PASSWORD_TOO_COMMON\""),
            (ErrorCode::InvalidEmail, "\"INVALID_EMAIL\""),
            (ErrorCode::ValidationError, "\"VALIDATION_ERROR\""),
            (ErrorCode::InvalidToken, "\"INVALID_TOKEN\""),
            (ErrorCode::TokenExpired, "\"TOKEN_EXPIRED\""),
            // Phase 4
            (ErrorCode::SessionNotFound, "\"SESSION_NOT_FOUND\""),
            (ErrorCode::SessionExpired, "\"SESSION_EXPIRED\""),
            (ErrorCode::SessionInvalid, "\"SESSION_INVALID\""),
            (ErrorCode::CsrfTokenMissing, "\"CSRF_TOKEN_MISSING\""),
            (ErrorCode::CsrfTokenInvalid, "\"CSRF_TOKEN_INVALID\""),
            (ErrorCode::RateLimitExceeded, "\"RATE_LIMIT_EXCEEDED\""),
            // Phase 6
            (ErrorCode::OAuthStateInvalid, "\"OAUTH_STATE_INVALID\""),
            (ErrorCode::OAuthCodeInvalid, "\"OAUTH_CODE_INVALID\""),
            (
                ErrorCode::OAuthEmailUnverified,
                "\"OAUTH_EMAIL_UNVERIFIED\"",
            ),
            (ErrorCode::OAuthProviderError, "\"OAUTH_PROVIDER_ERROR\""),
            (
                ErrorCode::OAuthAccountLinkConflict,
                "\"OAUTH_ACCOUNT_LINK_CONFLICT\"",
            ),
            (
                ErrorCode::OAuthProviderNotFound,
                "\"OAUTH_PROVIDER_NOT_FOUND\"",
            ),
            // Phase 7
            (ErrorCode::TotpNotEnrolled, "\"TOTP_NOT_ENROLLED\""),
            (ErrorCode::TotpAlreadyEnabled, "\"TOTP_ALREADY_ENABLED\""),
            (ErrorCode::TotpCodeInvalid, "\"TOTP_CODE_INVALID\""),
            (ErrorCode::TotpCodeExpired, "\"TOTP_CODE_EXPIRED\""),
            (ErrorCode::TotpCodeReplayed, "\"TOTP_CODE_REPLAYED\""),
            (
                ErrorCode::TotpBackupCodeInvalid,
                "\"TOTP_BACKUP_CODE_INVALID\"",
            ),
            (ErrorCode::TwoFactorRequired, "\"TWO_FACTOR_REQUIRED\""),
            (
                ErrorCode::TwoFactorTokenInvalid,
                "\"TWO_FACTOR_TOKEN_INVALID\"",
            ),
            (
                ErrorCode::TwoFactorTokenExpired,
                "\"TWO_FACTOR_TOKEN_EXPIRED\"",
            ),
            (
                ErrorCode::TwoFactorUnavailable,
                "\"TWO_FACTOR_UNAVAILABLE\"",
            ),
            (
                ErrorCode::TotpRateLimitExceeded,
                "\"TOTP_RATE_LIMIT_EXCEEDED\"",
            ),
            (
                ErrorCode::UnsupportedDatabaseBackend,
                "\"UNSUPPORTED_DATABASE_BACKEND\"",
            ),
            (
                ErrorCode::TransactionNotSupported,
                "\"TRANSACTION_NOT_SUPPORTED\"",
            ),
        ];

        for (code, expected_json) in cases {
            let serialized = serde_json::to_string(&code).expect("serialize error code");
            assert_eq!(serialized, expected_json);
            let deserialized: ErrorCode =
                serde_json::from_str(&serialized).expect("deserialize error code");
            assert_eq!(deserialized, code);
        }
    }

    #[test]
    fn test_error_response_json_shape() {
        let resp = ErrorResponse {
            code: ErrorCode::NotFound,
            message: "Not found".to_string(),
        };

        let json_str = serde_json::to_string(&resp).expect("serialize ErrorResponse");
        assert_eq!(json_str, r#"{"code":"NOT_FOUND","message":"Not found"}"#);

        let parsed: ErrorResponse =
            serde_json::from_str(&json_str).expect("deserialize ErrorResponse");
        assert_eq!(parsed, resp);
    }

    #[tokio::test]
    async fn test_app_error_status_codes_and_payloads() {
        let test_cases: Vec<(AppError, StatusCode, ErrorCode, &'static str)> = vec![
            (
                AppError::NotFound,
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
                "Not found",
            ),
            (
                AppError::MethodNotAllowed,
                StatusCode::METHOD_NOT_ALLOWED,
                ErrorCode::MethodNotAllowed,
                "Method not allowed",
            ),
            (
                AppError::DatabaseUnavailable(DbError::new("Database unavailable")),
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::DatabaseUnavailable,
                "Database unavailable",
            ),
            (
                AppError::Internal,
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InternalError,
                "Internal error",
            ),
            (
                AppError::Database(DbError::new("Database error")),
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::DatabaseError,
                "Database error",
            ),
            (
                AppError::UnsupportedDatabaseBackend("cockroachdb".to_string()),
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::UnsupportedDatabaseBackend,
                "Unsupported database backend: cockroachdb",
            ),
            (
                AppError::TransactionNotSupported,
                StatusCode::NOT_IMPLEMENTED,
                ErrorCode::TransactionNotSupported,
                "transactions require a mongodb replica set",
            ),
            (
                AppError::Config(ConfigError::MissingEnvVar("DATABASE_URL")),
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InvalidConfig,
                "Invalid configuration",
            ),
            (
                AppError::Config(ConfigError::InvalidValue {
                    field: "argon2_m_cost",
                    reason: "must be at least 19456 KiB",
                }),
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InvalidConfig,
                "Invalid configuration",
            ),
            (
                AppError::PasswordTooShort,
                StatusCode::BAD_REQUEST,
                ErrorCode::PasswordTooShort,
                "Password does not meet the minimum length requirement",
            ),
            (
                AppError::PasswordTooLong,
                StatusCode::BAD_REQUEST,
                ErrorCode::PasswordTooLong,
                "Password exceeds the maximum length requirement",
            ),
            (
                AppError::EmailHookNotConfigured,
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InternalError,
                "Internal error",
            ),
            (
                AppError::EmailDispatchFailed(Box::new(std::io::Error::other("mock failure"))),
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InternalError,
                "Internal error",
            ),
            (
                AppError::EmailDispatchTimeout,
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InternalError,
                "Internal error",
            ),
            (
                AppError::EmailAlreadyExists,
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InternalError,
                "Internal error",
            ),
            // Phase 3 — missing variant coverage
            (
                AppError::InvalidCredentials,
                StatusCode::UNAUTHORIZED,
                ErrorCode::InvalidCredentials,
                "Invalid email or password",
            ),
            (
                AppError::Unauthenticated,
                StatusCode::UNAUTHORIZED,
                ErrorCode::Unauthenticated,
                "Authentication required",
            ),
            (
                AppError::EmailNotVerified,
                StatusCode::FORBIDDEN,
                ErrorCode::EmailNotVerified,
                "Email address has not been verified",
            ),
            (
                AppError::PasswordTooCommon,
                StatusCode::BAD_REQUEST,
                ErrorCode::PasswordTooCommon,
                "Password is too common, please choose a stronger password",
            ),
            (
                AppError::InvalidEmail,
                StatusCode::BAD_REQUEST,
                ErrorCode::InvalidEmail,
                "Invalid email address",
            ),
            (
                AppError::ValidationError("field required".into()),
                StatusCode::BAD_REQUEST,
                ErrorCode::ValidationError,
                "field required",
            ),
            (
                AppError::ValidationError("".into()),
                StatusCode::BAD_REQUEST,
                ErrorCode::ValidationError,
                "Invalid request body",
            ),
            (
                AppError::InvalidToken,
                StatusCode::BAD_REQUEST,
                ErrorCode::InvalidToken,
                "Invalid or already used token",
            ),
            (
                AppError::TokenExpired,
                StatusCode::BAD_REQUEST,
                ErrorCode::TokenExpired,
                "Token has expired",
            ),
            (
                AppError::Migration(DbError::new("Migration failed")),
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::MigrationFailed,
                "Migration failed",
            ),
            (
                AppError::Config(ConfigError::NonUnicodeEnvVar("TEST_VAR")),
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InvalidConfig,
                "Invalid configuration",
            ),
            // Phase 4 — session, CSRF, rate limit
            (
                AppError::SessionNotFound,
                StatusCode::UNAUTHORIZED,
                ErrorCode::SessionNotFound,
                "Session is invalid or has expired",
            ),
            (
                AppError::SessionExpired,
                StatusCode::UNAUTHORIZED,
                ErrorCode::SessionExpired,
                "Session is invalid or has expired",
            ),
            (
                AppError::SessionInvalid,
                StatusCode::UNAUTHORIZED,
                ErrorCode::SessionInvalid,
                "Session is invalid or has expired",
            ),
            (
                AppError::CsrfTokenMissing,
                StatusCode::FORBIDDEN,
                ErrorCode::CsrfTokenMissing,
                "CSRF token is missing",
            ),
            (
                AppError::CsrfTokenInvalid,
                StatusCode::FORBIDDEN,
                ErrorCode::CsrfTokenInvalid,
                "CSRF token is invalid",
            ),
            (
                AppError::RateLimitExceeded,
                StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::RateLimitExceeded,
                "Too many requests, please try again later",
            ),
            // Phase 6 — OAuth
            (
                AppError::OAuthStateInvalid,
                StatusCode::FORBIDDEN,
                ErrorCode::OAuthStateInvalid,
                "invalid oauth state",
            ),
            (
                AppError::OAuthCodeInvalid,
                StatusCode::BAD_REQUEST,
                ErrorCode::OAuthCodeInvalid,
                "oauth code is invalid",
            ),
            (
                AppError::OAuthEmailUnverified,
                StatusCode::BAD_REQUEST,
                ErrorCode::OAuthEmailUnverified,
                "oauth provider email is not verified",
            ),
            (
                AppError::OAuthProviderNotFound,
                StatusCode::NOT_FOUND,
                ErrorCode::OAuthProviderNotFound,
                "oauth provider not found",
            ),
            (
                AppError::OAuthAccountLinkConflict,
                StatusCode::CONFLICT,
                ErrorCode::OAuthAccountLinkConflict,
                "cannot link oauth identity to unverified local account",
            ),
            (
                AppError::OAuthProviderError,
                StatusCode::BAD_GATEWAY,
                ErrorCode::OAuthProviderError,
                "oauth provider error",
            ),
            // Phase 7 — TOTP
            (
                AppError::TotpNotEnrolled,
                StatusCode::BAD_REQUEST,
                ErrorCode::TotpNotEnrolled,
                "totp not enrolled for this user",
            ),
            (
                AppError::TotpAlreadyEnabled,
                StatusCode::CONFLICT,
                ErrorCode::TotpAlreadyEnabled,
                "totp already enabled for this user",
            ),
            (
                AppError::TotpCodeInvalid,
                StatusCode::BAD_REQUEST,
                ErrorCode::TotpCodeInvalid,
                "totp code is invalid",
            ),
            (
                AppError::TotpCodeExpired,
                StatusCode::BAD_REQUEST,
                ErrorCode::TotpCodeExpired,
                "totp code window has expired",
            ),
            (
                AppError::TotpCodeReplayed,
                StatusCode::BAD_REQUEST,
                ErrorCode::TotpCodeReplayed,
                "totp code has already been used",
            ),
            (
                AppError::TotpBackupCodeInvalid,
                StatusCode::BAD_REQUEST,
                ErrorCode::TotpBackupCodeInvalid,
                "backup code is invalid",
            ),
            (
                AppError::TwoFactorTokenInvalid,
                StatusCode::UNAUTHORIZED,
                ErrorCode::TwoFactorTokenInvalid,
                "two factor token is invalid",
            ),
            (
                AppError::TwoFactorTokenExpired,
                StatusCode::UNAUTHORIZED,
                ErrorCode::TwoFactorTokenExpired,
                "two factor token has expired",
            ),
            (
                AppError::TwoFactorUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::TwoFactorUnavailable,
                "two factor authentication is temporarily unavailable",
            ),
            (
                AppError::TotpRateLimitExceeded,
                StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::TotpRateLimitExceeded,
                "totp rate limit exceeded",
            ),
            (
                AppError::TotpEmailNotVerified,
                StatusCode::BAD_REQUEST,
                ErrorCode::EmailNotVerified,
                "Email address has not been verified",
            ),
        ];

        for (err, expected_status, expected_code, expected_msg) in test_cases {
            assert_eq!(err.status_code(), expected_status);
            assert_eq!(err.error_code(), expected_code);
            assert_eq!(err.response_message(), expected_msg);

            let resp = err.into_response();
            assert_eq!(resp.status(), expected_status);

            let body_bytes = axum::body::to_bytes(resp.into_body(), 1024)
                .await
                .expect("collect body");
            let parsed: ErrorResponse =
                serde_json::from_slice(&body_bytes).expect("parse error response body");
            assert_eq!(parsed.code, expected_code);
            assert_eq!(parsed.message, expected_msg);
        }
    }

    #[test]
    fn test_phase4_error_codes_http_mapping() {
        assert_eq!(
            AppError::SessionNotFound.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AppError::SessionExpired.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AppError::SessionInvalid.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AppError::CsrfTokenMissing.status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            AppError::CsrfTokenInvalid.status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            AppError::RateLimitExceeded.status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn test_app_error_from_code() {
        assert!(matches!(
            AppError::from_code(ErrorCode::SessionNotFound),
            AppError::SessionNotFound
        ));
        assert!(matches!(
            AppError::from_code(ErrorCode::SessionExpired),
            AppError::SessionExpired
        ));
        assert!(matches!(
            AppError::from_code(ErrorCode::SessionInvalid),
            AppError::SessionInvalid
        ));
        assert!(matches!(
            AppError::from_code(ErrorCode::CsrfTokenMissing),
            AppError::CsrfTokenMissing
        ));
        assert!(matches!(
            AppError::from_code(ErrorCode::CsrfTokenInvalid),
            AppError::CsrfTokenInvalid
        ));
        assert!(matches!(
            AppError::from_code(ErrorCode::RateLimitExceeded),
            AppError::RateLimitExceeded
        ));
        assert!(matches!(
            AppError::from_code(ErrorCode::InvalidCredentials),
            AppError::InvalidCredentials
        ));
    }

    #[test]
    fn test_session_anti_enumeration_messages() {
        let msg_not_found = AppError::SessionNotFound.response_message();
        let msg_expired = AppError::SessionExpired.response_message();
        let msg_invalid = AppError::SessionInvalid.response_message();

        assert_eq!(msg_not_found, msg_expired);
        assert_eq!(msg_expired, msg_invalid);
        assert_eq!(msg_not_found, "Session is invalid or has expired");
    }

    #[test]
    fn test_error_response_serialization() {
        let err = ErrorResponse {
            code: ErrorCode::SessionNotFound,
            message: "Session is invalid or has expired".into(),
        };
        let json = serde_json::to_string(&err).expect("serialize ErrorResponse");
        assert!(json.contains("\"code\":\"SESSION_NOT_FOUND\""));
        assert!(json.contains("\"message\":\"Session is invalid or has expired\""));
    }

    #[test]
    fn error_code_session_not_found_serializes_correctly() {
        assert_eq!(
            serde_json::to_string(&ErrorCode::SessionNotFound).expect("serialize ErrorCode"),
            "\"SESSION_NOT_FOUND\""
        );
    }

    #[test]
    fn error_code_csrf_token_missing_maps_to_403() {
        use axum::response::IntoResponse;
        let response = AppError::from_code(ErrorCode::CsrfTokenMissing).into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn error_code_rate_limit_exceeded_maps_to_429() {
        use axum::response::IntoResponse;
        let response = AppError::from_code(ErrorCode::RateLimitExceeded).into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn session_401_responses_include_www_authenticate_header() {
        use axum::response::IntoResponse;
        let session_errors = [
            AppError::SessionNotFound,
            AppError::SessionExpired,
            AppError::SessionInvalid,
        ];

        for err in session_errors {
            let resp = err.into_response();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            let auth_header = resp
                .headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .expect("WWW-Authenticate header must be present on session 401");
            assert_eq!(
                auth_header.to_str().unwrap(),
                r#"Bearer realm="metal-auth", error="invalid_token""#
            );
        }

        let other_401 = AppError::InvalidCredentials.into_response();
        assert_eq!(other_401.status(), StatusCode::UNAUTHORIZED);
        assert!(
            other_401
                .headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .is_none()
        );
    }

    #[test]
    fn from_code_round_trips_every_wire_code() {
        let codes = [
            ErrorCode::InvalidConfig,
            ErrorCode::DatabaseError,
            ErrorCode::DatabaseUnavailable,
            ErrorCode::MigrationFailed,
            ErrorCode::InternalError,
            ErrorCode::NotFound,
            ErrorCode::MethodNotAllowed,
            ErrorCode::InvalidCredentials,
            ErrorCode::Unauthenticated,
            ErrorCode::EmailNotVerified,
            ErrorCode::PasswordTooShort,
            ErrorCode::PasswordTooLong,
            ErrorCode::PasswordTooCommon,
            ErrorCode::InvalidEmail,
            ErrorCode::ValidationError,
            ErrorCode::InvalidToken,
            ErrorCode::TokenExpired,
            ErrorCode::SessionNotFound,
            ErrorCode::SessionExpired,
            ErrorCode::SessionInvalid,
            ErrorCode::CsrfTokenMissing,
            ErrorCode::CsrfTokenInvalid,
            ErrorCode::RateLimitExceeded,
            // Phase 6
            ErrorCode::OAuthStateInvalid,
            ErrorCode::OAuthCodeInvalid,
            ErrorCode::OAuthEmailUnverified,
            ErrorCode::OAuthProviderError,
            ErrorCode::OAuthAccountLinkConflict,
            ErrorCode::OAuthProviderNotFound,
            // Phase 7
            ErrorCode::TotpNotEnrolled,
            ErrorCode::TotpAlreadyEnabled,
            ErrorCode::TotpCodeInvalid,
            ErrorCode::TotpCodeExpired,
            ErrorCode::TotpCodeReplayed,
            ErrorCode::TotpBackupCodeInvalid,
            ErrorCode::TwoFactorRequired,
            ErrorCode::TwoFactorTokenInvalid,
            ErrorCode::TwoFactorTokenExpired,
            ErrorCode::TwoFactorUnavailable,
            ErrorCode::TotpRateLimitExceeded,
        ];
        for code in codes {
            assert_eq!(AppError::from_code(code).error_code(), code);
        }
    }

    #[test]
    fn test_oauth_error_codes_wire_serialization_and_envelope() {
        let cases = [
            (
                ErrorCode::OAuthStateInvalid,
                "OAUTH_STATE_INVALID",
                StatusCode::FORBIDDEN,
            ),
            (
                ErrorCode::OAuthCodeInvalid,
                "OAUTH_CODE_INVALID",
                StatusCode::BAD_REQUEST,
            ),
            (
                ErrorCode::OAuthEmailUnverified,
                "OAUTH_EMAIL_UNVERIFIED",
                StatusCode::BAD_REQUEST,
            ),
            (
                ErrorCode::OAuthProviderError,
                "OAUTH_PROVIDER_ERROR",
                StatusCode::BAD_GATEWAY,
            ),
            (
                ErrorCode::OAuthAccountLinkConflict,
                "OAUTH_ACCOUNT_LINK_CONFLICT",
                StatusCode::CONFLICT,
            ),
            (
                ErrorCode::OAuthProviderNotFound,
                "OAUTH_PROVIDER_NOT_FOUND",
                StatusCode::NOT_FOUND,
            ),
        ];

        for (code, expected_wire, expected_status) in cases {
            let json = serde_json::to_string(&code).expect("serialize error code");
            assert_eq!(json, format!("\"{expected_wire}\""));

            let app_err = AppError::from_code(code);
            assert_eq!(app_err.code(), code);
            assert_eq!(app_err.status_code(), expected_status);

            let resp = ErrorResponse::from(&app_err);
            let resp_json = serde_json::to_string(&resp).expect("serialize ErrorResponse");
            assert!(resp_json.contains(&format!("\"code\":\"{expected_wire}\"")));
            assert!(resp_json.contains("\"message\":"));
        }
    }

    #[test]
    fn email_already_exists_stays_anti_enumerating() {
        let err = AppError::EmailAlreadyExists;
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.error_code(), ErrorCode::InternalError);
        assert_eq!(err.response_message(), "Internal error");
    }

    #[test]
    fn phase7_unverified_email_gate_is_400_without_moving_login_gate() {
        assert_eq!(
            AppError::TotpEmailNotVerified.status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AppError::TotpEmailNotVerified.error_code(),
            ErrorCode::EmailNotVerified
        );
        assert_eq!(
            AppError::EmailNotVerified.status_code(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn two_factor_required_is_a_success_sentinel() {
        assert_eq!(AppError::TwoFactorRequired.status_code(), StatusCode::OK);
        assert_eq!(
            AppError::TwoFactorRequired.error_code(),
            ErrorCode::TwoFactorRequired
        );
    }

    #[test]
    fn truncate_for_log_keeps_short_input() {
        assert_eq!(truncate_for_log("field required"), "field required");
        assert_eq!(truncate_for_log(""), "");
    }

    #[test]
    fn truncate_for_log_caps_at_char_boundary() {
        let long = "é".repeat(300);
        let truncated = truncate_for_log(&long);
        assert_eq!(truncated.chars().count(), MAX_LOG_FIELD_CHARS);
        let ascii = "x".repeat(1000);
        assert_eq!(truncate_for_log(&ascii).len(), MAX_LOG_FIELD_CHARS);
    }

    #[test]
    fn test_db_error_creation_and_conversion() {
        let err = DbError::new("connection dropped");
        assert_eq!(err.message, "connection dropped");
        assert!(err.source.is_none());

        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        let with_src = DbError::with_source("failed query", io_err);
        assert_eq!(with_src.message, "failed query");
        assert!(with_src.source.is_some());

        let app_err = AppError::from(err);
        assert_eq!(app_err.error_code(), ErrorCode::DatabaseError);
        assert_eq!(app_err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);

        #[cfg(any(feature = "postgres", feature = "mysql"))]
        {
            let sqlx_err = sqlx::Error::RowNotFound;
            let from_sqlx: AppError = sqlx_err.into();
            assert_eq!(from_sqlx.error_code(), ErrorCode::DatabaseError);
        }
    }

    #[test]
    fn test_unsupported_database_backend_and_transaction_sentinels() {
        let unsupported = AppError::UnsupportedDatabaseBackend("cockroachdb".into());
        assert_eq!(unsupported.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            unsupported.error_code(),
            ErrorCode::UnsupportedDatabaseBackend
        );
        assert_eq!(
            unsupported.response_message(),
            "Unsupported database backend: cockroachdb"
        );

        let unsupported_empty = AppError::UnsupportedDatabaseBackend("".into());
        assert_eq!(
            unsupported_empty.response_message(),
            "Unsupported database backend"
        );

        let tx_not_supported = AppError::TransactionNotSupported;
        assert_eq!(tx_not_supported.status_code(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(
            tx_not_supported.error_code(),
            ErrorCode::TransactionNotSupported
        );
        assert_eq!(
            tx_not_supported.response_message(),
            "transactions require a mongodb replica set"
        );
    }

    #[test]
    fn test_duplicate_key_error_code_mappings() {
        // Assert domain sentinel error mappings for unique constraint violations
        let email_err = AppError::EmailAlreadyExists;
        assert_eq!(email_err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(email_err.error_code(), ErrorCode::InternalError);

        let oauth_err = AppError::OAuthAccountLinkConflict;
        assert_eq!(oauth_err.status_code(), StatusCode::CONFLICT);
        assert_eq!(oauth_err.error_code(), ErrorCode::OAuthAccountLinkConflict);

        let totp_err = AppError::TotpCodeReplayed;
        assert_eq!(totp_err.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(totp_err.error_code(), ErrorCode::TotpCodeReplayed);
    }

    #[test]
    #[cfg(feature = "mongodb")]
    fn test_mongo_is_duplicate_key_error_classifier() {
        // Generic error message containing E11000
        let dup_err1 =
            mongodb::error::Error::custom("E11000 duplicate key error in index: email_1");
        assert!(crate::db::mongo::is_duplicate_key_error(&dup_err1));

        let dup_err2 =
            mongodb::error::Error::custom("duplicate key error collection: users index: idx_email");
        assert!(crate::db::mongo::is_duplicate_key_error(&dup_err2));

        // Non-duplicate error message
        let non_dup = mongodb::error::Error::custom("connection timed out to replica set");
        assert!(!crate::db::mongo::is_duplicate_key_error(&non_dup));
    }
}
