//! Axum route handlers for all 6 auth endpoints.
//!
//! All error responses use envelope `{"code":"...","message":"..."}`.
//! All success responses use `{"message":"..."}` or domain fields.
//! Never raw strings, never internal details.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{State, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::{
    auth::models::{
        LoginRequest, LoginResponse, MessageResponse, PasswordResetConfirmRequest,
        PasswordResetRequest, SignupRequest, VerifyEmailRequest,
    },
    auth::service::AuthServiceImpl,
    error::{AppError, ErrorCode, ErrorResponse},
};

// ─── Shared app state for handlers ───────────────────────────────────────────

#[derive(Clone)]
pub struct AuthHandlerState {
    pub service: Arc<AuthServiceImpl>,
}

pub fn routes(service: Arc<AuthServiceImpl>) -> Router {
    let state = AuthHandlerState { service };
    Router::new()
        .route("/signup", axum::routing::post(signup))
        .route("/login", axum::routing::post(login))
        .route("/logout", axum::routing::post(logout))
        .route("/verify", axum::routing::post(verify_email))
        .route("/password/reset-request", axum::routing::post(request_password_reset))
        .route("/password/reset", axum::routing::post(reset_password))
        .with_state(state)
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

    if let Err(e) = req.validate(&state.service.config) {
        return service_error_response(e);
    }

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

    if let Err(e) = req.validate() {
        return service_error_response(e);
    }

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

    if let Err(e) = req.validate() {
        return service_error_response(e);
    }

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

    if let Err(e) = req.validate() {
        return service_error_response(e);
    }

    match state.service.request_password_reset(&req.email).await {
        Ok(()) => (
            StatusCode::OK,
            Json(MessageResponse::new(
                "if an account with that email exists, a password reset link has been sent",
            )),
        )
            .into_response(),
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

    if let Err(e) = req.validate(&state.service.config) {
        return service_error_response(e);
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::AppConfig,
        email::{EmailDispatcher, test_utils::CapturingEmailSender},
    };
    use axum::body::to_bytes;
    use sqlx::PgPool;

    fn create_test_state() -> AuthHandlerState {
        let pool = PgPool::connect_lazy("postgres://localhost/test").expect("lazy pool");
        let config = Arc::new(AppConfig {
            argon2_m_cost: 19456,
            argon2_t_cost: 2,
            argon2_p_cost: 1,
            password_min_len: 8,
            password_max_len: 128,
            ..Default::default()
        });
        let dispatcher = Arc::new(EmailDispatcher::new(CapturingEmailSender::default()));
        let service =
            Arc::new(AuthServiceImpl::new(pool, config, dispatcher).expect("test service"));
        AuthHandlerState { service }
    }

    #[tokio::test]
    async fn login_handler_rejects_empty_credentials_without_db() {
        let state = create_test_state();
        let payload = LoginRequest {
            email: "".to_string(),
            password: "".to_string(),
        };

        let resp = login(State(state), Ok(Json(payload))).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, ErrorCode::InvalidCredentials);
    }

    #[tokio::test]
    async fn signup_handler_rejects_invalid_password_without_db() {
        let state = create_test_state();
        let payload = SignupRequest {
            email: "valid@example.com".to_string(),
            password: "short".to_string(),
        };

        let resp = signup(State(state), Ok(Json(payload))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, ErrorCode::PasswordTooShort);
    }

    #[tokio::test]
    async fn verify_email_handler_rejects_invalid_token_without_db() {
        let state = create_test_state();
        let payload = VerifyEmailRequest {
            token: "not-a-valid-hex-token".to_string(),
        };

        let resp = verify_email(State(state), Ok(Json(payload))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, ErrorCode::InvalidToken);
    }

    #[tokio::test]
    async fn request_password_reset_handler_rejects_invalid_email_without_db() {
        let state = create_test_state();
        let payload = PasswordResetRequest {
            email: "invalid-email".to_string(),
        };

        let resp = request_password_reset(State(state), Ok(Json(payload))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, ErrorCode::InvalidEmail);
    }

    #[tokio::test]
    async fn reset_password_handler_rejects_invalid_token_without_db() {
        let state = create_test_state();
        let payload = PasswordResetConfirmRequest {
            token: "short-token".to_string(),
            new_password: "ValidPassword123!".to_string(),
        };

        let resp = reset_password(State(state), Ok(Json(payload))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, ErrorCode::InvalidToken);
    }

    #[tokio::test]
    async fn logout_handler_returns_no_content() {
        let state = create_test_state();
        let resp = logout(State(state)).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
}
