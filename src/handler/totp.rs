//! TOTP two-factor HTTP handlers.
//!
//! `enroll`, `confirm`, and `DELETE /auth/totp` are authenticated cookie
//! mutations and sit behind `require_auth` + CSRF. `verify` and `backup`
//! authenticate with a body-borne challenge token instead of the session
//! cookie, so they are mounted outside the CSRF layer on purpose.

use serde::Deserialize;

use axum::{
    Json, Router,
    extract::{State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::{
    auth::models::{LoginResponse, MessageResponse},
    error::AppError,
    handler::auth::{
        attach_login_cookies, extract_client_ip, json_rejection_response, method_not_allowed,
        service_error_response,
    },
    middleware::{
        auth::{AuthUser, require_auth},
        csrf_middleware,
    },
    state::AppState,
    totp::service::FreshAuthProof,
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

impl DisableTotpRequest {
    /// Reject an absent, blank, or ambiguous proof before any rate-limit budget is spent.
    fn into_proof(self) -> Result<FreshAuthProof, AppError> {
        match (self.password, self.totp_code) {
            (Some(password), None) if !password.is_empty() => {
                Ok(FreshAuthProof::Password(password))
            }
            (None, Some(code)) if !code.is_empty() => Ok(FreshAuthProof::TotpCode(code)),
            _ => Err(AppError::ValidationError(
                "provide exactly one of password or totp_code".into(),
            )),
        }
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

/// `POST /auth/totp/backup`
///
/// Same lifecycle as [`totp_verify`] with a single-use backup code as the factor.
pub async fn totp_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<TwoFactorChallengeRequest>, JsonRejection>,
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

    let user_id = match state
        .totp_service
        .validate_two_factor_token(&request.challenge_token)
        .await
    {
        Ok(user_id) => user_id,
        Err(error) => return service_error_response(error),
    };

    if state
        .rate_limiter
        .check_totp_user_limit(user_id, &state.config.totp)
        .is_err()
    {
        return totp_rate_limit_exceeded();
    }

    if let Err(error) = state
        .totp_service
        .verify_backup_code(user_id, &request.code, &client_ip)
        .await
    {
        return service_error_response(error);
    }

    if let Err(error) = state
        .totp_service
        .consume_two_factor_token(&request.challenge_token)
        .await
    {
        return service_error_response(error);
    }

    issue_two_factor_session(&state, user_id, &headers, &client_ip).await
}

/// `DELETE /auth/totp`
///
/// Requires a fresh-auth proof: the current password or a live TOTP code. A missing or
/// malformed proof is a 400 before any budget is spent; a wrong proof is a 401 from the
/// service. An absent session is rejected by `require_auth` before this runs.
pub async fn totp_disable(
    State(state): State<AppState>,
    auth_user: AuthUser,
    headers: HeaderMap,
    body: Result<Json<DisableTotpRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match body {
        Ok(body) => body,
        Err(rejection) => return json_rejection_response(rejection),
    };

    let proof = match request.into_proof() {
        Ok(proof) => proof,
        Err(error) => return service_error_response(error),
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
        .disable_totp(auth_user.user_id, proof, &client_ip)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(MessageResponse::new("two-factor authentication disabled")),
        )
            .into_response(),
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

/// `POST /auth/totp/verify`
///
/// Order is load-bearing: IP budget, then non-destructive token validation, then the
/// user budget, then the code check, then token consumption on success only.
pub async fn totp_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<TwoFactorChallengeRequest>, JsonRejection>,
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

    // Non-destructive: holding the challenge while the code is retyped is the point.
    let user_id = match state
        .totp_service
        .validate_two_factor_token(&request.challenge_token)
        .await
    {
        Ok(user_id) => user_id,
        Err(error) => return service_error_response(error),
    };

    if state
        .rate_limiter
        .check_totp_user_limit(user_id, &state.config.totp)
        .is_err()
    {
        return totp_rate_limit_exceeded();
    }

    if let Err(error) = state
        .totp_service
        .verify_totp(user_id, &request.code, &client_ip)
        .await
    {
        return service_error_response(error);
    }

    if let Err(error) = state
        .totp_service
        .consume_two_factor_token(&request.challenge_token)
        .await
    {
        return service_error_response(error);
    }

    issue_two_factor_session(&state, user_id, &headers, &client_ip).await
}

/// Issue the post-challenge session using the same wire shape as a password login.
async fn issue_two_factor_session(
    state: &AppState,
    user_id: Uuid,
    headers: &HeaderMap,
    client_ip: &str,
) -> Response {
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    let is_bearer = headers
        .get("x-auth-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("bearer"));
    let session_type = if is_bearer { "bearer" } else { "cookie" };

    // Re-read the live credential hash: `create_session_checked` compares it under the
    // user row lock, so a password reset committing after the challenge was issued
    // rejects here instead of minting a session from superseded credentials.
    let credential_hash = match current_credential_hash(state, user_id).await {
        Ok(hash) => hash,
        Err(error) => return service_error_response(error),
    };

    let (session, raw_id) = match state
        .session_service
        .create_session_checked(
            user_id,
            &credential_hash,
            session_type,
            Some(client_ip),
            user_agent,
        )
        .await
    {
        Ok(session) => session,
        Err(error) => return service_error_response(error),
    };

    if is_bearer {
        (
            StatusCode::OK,
            Json(LoginResponse::with_token(user_id, raw_id)),
        )
            .into_response()
    } else {
        let response = (StatusCode::OK, Json(LoginResponse::new(user_id))).into_response();
        match attach_login_cookies(
            response,
            &state.config,
            raw_id.as_str(),
            session.csrf_token.as_deref(),
        ) {
            Ok(response) => response,
            Err(error) => service_error_response(error),
        }
    }
}

/// Read the user's current Argon2id PHC string for the freshness check.
///
/// A missing row and a failed lookup both surface as `SessionInvalid`, so this path
/// gains no user-enumerating error variant.
async fn current_credential_hash(state: &AppState, user_id: Uuid) -> Result<String, AppError> {
    sqlx::query_scalar::<_, String>("SELECT password_hash FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Database)?
        .ok_or(AppError::SessionInvalid)
}

/// Router for the TOTP endpoints, merged under `/auth` by [`crate::handler::create_router`].
///
/// CSRF split is deliberate. `enroll`, `confirm`, and `DELETE /totp` mutate state on an
/// ambient session cookie and sit behind `require_auth` + CSRF (guard outermost, so an
/// anonymous request gets 401 before CSRF can answer 403). `verify` and `backup`
/// authenticate with a body-borne `challenge_token` and carry no ambient authority;
/// inside the CSRF layer a browser holding any unrelated `sid` cookie would be rejected
/// before the challenge is read, while cookie-less clients would still pass.
pub fn routes(state: AppState) -> Router {
    let protected = Router::new()
        .route(
            "/totp/enroll",
            axum::routing::post(totp_enroll).fallback(method_not_allowed),
        )
        .route(
            "/totp/confirm",
            axum::routing::post(totp_confirm).fallback(method_not_allowed),
        )
        // No JSON 405 fallback here: the shared helper advertises POST only.
        .route("/totp", axum::routing::delete(totp_disable))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            csrf_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ))
        .with_state(state.clone());

    // CSRF-exempt by design: see the type-level note above.
    let public = Router::new()
        .route(
            "/totp/verify",
            axum::routing::post(totp_verify).fallback(method_not_allowed),
        )
        .route(
            "/totp/backup",
            axum::routing::post(totp_backup).fallback(method_not_allowed),
        )
        .with_state(state);

    protected.merge(public)
}
