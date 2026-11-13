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

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("configuration error")]
    Config(#[from] ConfigError),

    #[error("database error")]
    Database(#[from] sqlx::Error),

    #[error("database unavailable")]
    DatabaseUnavailable(#[source] sqlx::Error),

    #[error("migration error")]
    Migration(#[from] sqlx::migrate::MigrateError),

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
        }
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
            | Self::EmailAlreadyExists => StatusCode::INTERNAL_SERVER_ERROR,
            // 401
            Self::InvalidCredentials | Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            // 403
            Self::EmailNotVerified => StatusCode::FORBIDDEN,
            // 400
            Self::PasswordTooShort
            | Self::PasswordTooLong
            | Self::PasswordTooCommon
            | Self::InvalidEmail
            | Self::ValidationError(_)
            | Self::InvalidToken
            | Self::TokenExpired => StatusCode::BAD_REQUEST,
        }
    }

    #[must_use]
    pub fn response_message(&self) -> &'static str {
        match self {
            Self::Config(_) => "Invalid configuration",
            Self::Database(_) => "Database error",
            Self::DatabaseUnavailable(_) => "Database unavailable",
            Self::Migration(_) => "Migration failed",
            Self::NotFound => "Not found",
            Self::MethodNotAllowed => "Method not allowed",
            Self::Internal
            | Self::EmailHookNotConfigured
            | Self::EmailDispatchFailed(_)
            | Self::EmailDispatchTimeout
            | Self::EmailAlreadyExists => "Internal error",
            // Phase 3
            Self::InvalidCredentials => "Invalid email or password",
            Self::Unauthenticated => "Authentication required",
            Self::EmailNotVerified => "Email address has not been verified",
            Self::PasswordTooShort => "Password does not meet the minimum length requirement",
            Self::PasswordTooLong => "Password exceeds the maximum length requirement",
            Self::PasswordTooCommon => "Password is too common, please choose a stronger password",
            Self::InvalidEmail => "Invalid email address",
            Self::ValidationError(_) => "Invalid request body",
            Self::InvalidToken => "Invalid or already used token",
            Self::TokenExpired => "Token has expired",
        }
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
            Self::ValidationError(msg) => tracing::debug!(msg = %msg, "validation error"),
            Self::InvalidToken => tracing::debug!("invalid or consumed token"),
            Self::TokenExpired => tracing::debug!("expired token presented"),
            // EmailAlreadyExists is internal-only — never reaches this handler in normal flow
            Self::EmailAlreadyExists => tracing::info!("signup attempt on existing account"),
        }

        let status = self.status_code();
        let payload = ErrorResponse::from(&self);

        (status, Json(payload)).into_response()
    }
}

impl From<&AppError> for ErrorResponse {
    fn from(err: &AppError) -> Self {
        Self {
            code: err.error_code(),
            message: err.response_message().to_string(),
        }
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
                AppError::DatabaseUnavailable(sqlx::Error::PoolTimedOut),
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
                AppError::Database(sqlx::Error::RowNotFound),
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::DatabaseError,
                "Database error",
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
}
