//! TOTP two-factor HTTP handlers.
//!
//! `enroll`, `confirm`, and `DELETE /auth/totp` are authenticated cookie
//! mutations and sit behind `require_auth` + CSRF. `verify` and `backup`
//! authenticate with a body-borne challenge token instead of the session
//! cookie, so they are mounted outside the CSRF layer on purpose.

use serde::Deserialize;

use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{
    auth::models::MessageResponse,
    error::AppError,
    handler::auth::{extract_client_ip, json_rejection_response, service_error_response},
    middleware::auth::AuthUser,
    state::AppState,
};

/// `POST /auth/totp/confirm` body.
#[derive(Deserialize)]
pub struct ConfirmTotpRequest {
    pub code: String,
}

// Manual `Debug`: the one-time code must never reach a log or error trace.
impl std::fmt::Debug for ConfirmTotpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfirmTotpRequest")
            .field("code", &"[redacted]")
            .finish()
    }
}

/// `POST /auth/totp/verify` and `POST /auth/totp/backup` body.
#[derive(Deserialize)]
pub struct TwoFactorChallengeRequest {
    pub challenge_token: String,
    pub code: String,
}

// Manual `Debug`: challenge token and code are live credentials.
impl std::fmt::Debug for TwoFactorChallengeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoFactorChallengeRequest")
            .field("challenge_token", &"[redacted]")
            .field("code", &"[redacted]")
            .finish()
    }
}

/// `DELETE /auth/totp` body: exactly one fresh-auth proof.
#[derive(Deserialize)]
pub struct DisableTotpRequest {
    pub password: Option<String>,
    pub totp_code: Option<String>,
}

// Manual `Debug`: both fields carry a live credential.
impl std::fmt::Debug for DisableTotpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DisableTotpRequest")
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .field("totp_code", &self.totp_code.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// `POST /auth/totp/enroll`
///
/// Rotates the pending secret and returns the QR URI plus the backup codes once.
/// Refuses unverified emails and an already enabled secret.
pub async fn totp_enroll(State(state): State<AppState>, auth_user: AuthUser) -> Response {
    match state.totp_service.enroll_totp(auth_user.user_id).await {
        Ok(enrollment) => (StatusCode::OK, Json(enrollment)).into_response(),
        Err(error) => service_error_response(error),
    }
}

/// `POST /auth/totp/confirm`
///
/// Verifies the first code against the pending secret and enables 2FA.
pub async fn totp_confirm(
    State(state): State<AppState>,
    auth_user: AuthUser,
    headers: HeaderMap,
    body: Result<Json<ConfirmTotpRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match body {
        Ok(body) => body,
        Err(rejection) => return json_rejection_response(rejection),
    };

    let client_ip = extract_client_ip(&headers);

    if state
        .rate_limiter
        .check_totp_ip_limit(&client_ip, &state.config.totp)
        .is_err()
    {
        return totp_rate_limit_exceeded();
    }
    if state
        .rate_limiter
        .check_totp_user_limit(auth_user.user_id, &state.config.totp)
        .is_err()
    {
        return totp_rate_limit_exceeded();
    }

    match state
        .totp_service
        .confirm_enrollment(auth_user.user_id, &request.code, &client_ip)
        .await
    {
        Ok(()) => (StatusCode::OK, Json(MessageResponse::new("totp confirmed"))).into_response(),
        Err(error) => service_error_response(error),
    }
}

/// 429 for either TOTP dimension.
///
/// No `Retry-After`: the limiter rejects with `Exceeded` (sliding window), which has
/// no exact retry instant to advertise; a one-window `Lockout` header would misstate
/// when the budget actually reopens.
fn totp_rate_limit_exceeded() -> Response {
    service_error_response(AppError::TotpRateLimitExceeded)
}
