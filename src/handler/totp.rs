//! TOTP two-factor HTTP handlers.
//!
//! `enroll`, `confirm`, and `DELETE /auth/totp` are authenticated cookie
//! mutations and sit behind `require_auth` + CSRF. `verify` and `backup`
//! authenticate with a body-borne challenge token instead of the session
//! cookie, so they are mounted outside the CSRF layer on purpose.

use serde::Deserialize;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::{handler::auth::service_error_response, middleware::auth::AuthUser, state::AppState};

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
