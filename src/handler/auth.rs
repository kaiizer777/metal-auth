//! Axum route handlers for all 6 auth endpoints.
//!
//! All error responses use envelope `{"code":"...","message":"..."}`.
//! All success responses use `{"message":"..."}` or domain fields.
//! Never raw strings, never internal details.

use std::sync::Arc;

use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[allow(unused_imports)]
use crate::{
    auth::models::{
        LoginRequest, LoginResponse, MessageResponse, PasswordResetConfirmRequest,
        PasswordResetRequest, SignupRequest, UserResponse, VerifyEmailRequest,
    },
    auth::service::AuthServiceImpl,
    error::{AppError, ErrorCode, ErrorResponse},
};

// ─── Shared app state for handlers ───────────────────────────────────────────

#[derive(Clone)]
pub struct AuthHandlerState {
    pub service: Arc<AuthServiceImpl>,
}

// ─── Error mapping helpers ────────────────────────────────────────────────────

/// Map a JSON extraction failure to a `VALIDATION_ERROR` 400.
fn json_rejection_response(rejection: JsonRejection) -> Response {
    tracing::debug!(error = %rejection, "JSON parse/validation error");
    let payload = ErrorResponse {
        code: ErrorCode::ValidationError,
        message: "Invalid request body".to_string(),
    };
    (StatusCode::BAD_REQUEST, Json(payload)).into_response()
}

/// Map `AppError` to HTTP response following spec wire codes.
fn service_error_response(err: AppError) -> Response {
    err.into_response()
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// POST /auth/signup
///
/// Anti-enumeration: always returns 200 regardless of duplicate email.
/// Handler MUST still spawn dispatcher on duplicate path — service handles this.
pub async fn signup(
    State(state): State<AuthHandlerState>,
    body: Result<Json<SignupRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match body {
        Ok(b) => b,
        Err(e) => return json_rejection_response(e),
    };

    match state.service.signup(&req.email, &req.password).await {
        Ok(()) | Err(AppError::EmailAlreadyExists) => {
            // Anti-enum: both paths return identical 200
            (
                StatusCode::OK,
                Json(MessageResponse::new(
                    "if this email is new, a verification link has been sent",
                )),
            )
                .into_response()
        }
        Err(e) => service_error_response(e),
    }
}

/// POST /auth/login
///
/// Returns 200 with `user_id` on success.
/// Returns 401 for wrong password OR unknown email (identical response — anti-enum).
/// Returns 403 when `require_email_verification = true` and email unverified.
pub async fn login(
    State(state): State<AuthHandlerState>,
    body: Result<Json<LoginRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match body {
        Ok(b) => b,
        Err(e) => return json_rejection_response(e),
    };

    match state.service.login(&req.email, &req.password).await {
        Ok(user_id) => (StatusCode::OK, Json(LoginResponse { user_id })).into_response(),
        Err(e) => service_error_response(e),
    }
}

/// POST /auth/logout
///
/// Phase 3 stub — returns 204 No Content.
/// Authorization: Bearer <token> header is accepted but not validated in Phase 3.
pub async fn logout(State(state): State<AuthHandlerState>) -> Response {
    let _ = state.service.logout("").await;
    StatusCode::NO_CONTENT.into_response()
}

/// POST /auth/verify
///
/// Consumes a 64-char hex email verification token.
pub async fn verify_email(
    State(state): State<AuthHandlerState>,
    body: Result<Json<VerifyEmailRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match body {
        Ok(b) => b,
        Err(e) => return json_rejection_response(e),
    };

    match state.service.verify_email(&req.token).await {
        Ok(()) => (StatusCode::OK, Json(MessageResponse::new("email verified"))).into_response(),
        Err(e) => service_error_response(e),
    }
}

/// POST /auth/password/reset-request
///
/// Anti-enumeration: always returns 200 regardless of account existence.
pub async fn request_password_reset(
    State(state): State<AuthHandlerState>,
    body: Result<Json<PasswordResetRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match body {
        Ok(b) => b,
        Err(e) => return json_rejection_response(e),
    };

    match state.service.request_password_reset(&req.email).await {
        Ok(()) => (
            StatusCode::OK,
            Json(MessageResponse::new(
                "if an account with that email exists, a password reset link has been sent",
            )),
        )
            .into_response(),
        Err(AppError::InvalidEmail) => service_error_response(AppError::InvalidEmail),
        Err(e) => service_error_response(e),
    }
}

/// POST /auth/password/reset
///
/// Consumes a reset token and sets a new password.
pub async fn reset_password(
    State(state): State<AuthHandlerState>,
    body: Result<Json<PasswordResetConfirmRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match body {
        Ok(b) => b,
        Err(e) => return json_rejection_response(e),
    };

    match state
        .service
        .reset_password(&req.token, &req.new_password)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(MessageResponse::new("password reset successful")),
        )
            .into_response(),
        Err(e) => service_error_response(e),
    }
}
