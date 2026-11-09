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

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidConfig,
    DatabaseError,
    DatabaseUnavailable,
    MigrationFailed,
    InternalError,
    NotFound,
    MethodNotAllowed,
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
            Self::Internal => ErrorCode::InternalError,
        }
    }

    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::DatabaseUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::Config(_) | Self::Database(_) | Self::Migration(_) | Self::Internal => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
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
            Self::Internal => "Internal error",
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
        }

        let status = self.status_code();
        let payload = ErrorResponse {
            code: self.error_code(),
            message: self.response_message().to_string(),
        };

        (status, Json(payload)).into_response()
    }
}

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
