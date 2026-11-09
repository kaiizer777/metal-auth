use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("database error")]
    Database(#[from] sqlx::Error),

    #[error("not found")]
    NotFound,

    #[error("internal error")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not found"),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
        };

        tracing::error!("{:?}", self);
        (status, Json(json!({ "error": message }))).into_response()
    }
}

#[test]
fn test_app_error_status_codes() {
    let not_found_resp = AppError::NotFound.into_response();
    assert_eq!(not_found_resp.status(), StatusCode::NOT_FOUND);

    let internal_resp = AppError::Internal("disk full".into()).into_response();
    assert_eq!(internal_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
