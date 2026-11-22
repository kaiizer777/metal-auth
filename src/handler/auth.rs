//! Axum route handlers for all 6 auth endpoints.
//!
//! All error responses use envelope `{"code":"...","message":"..."}`.
//! All success responses use `{"message":"..."}` or domain fields.
//! Never raw strings, never internal details.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{State, rejection::JsonRejection},
    handler::Handler,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::{
    auth::models::{
        LoginRequest, LoginResponse, MessageResponse, PasswordResetConfirmRequest,
        PasswordResetRequest, SignupRequest, VerifyEmailRequest,
    },
    auth::service::AuthServiceImpl,
    config::Config,
    db::models::Session,
    error::{AppError, ErrorCode, ErrorResponse},
    handler::{require_totp_key, untrusted_client_ip},
    ratelimit::{RateLimitRejection, RateLimiter},
    session::{
        SessionService,
        bearer::read_bearer_token,
        cookie::{
            clear_csrf_cookie, clear_session_cookie, read_session_cookie, set_csrf_cookie,
            set_session_cookie,
        },
    },
    state::AppState,
    totp::service::TotpService,
};

// ─── Shared app state for handlers ───────────────────────────────────────────

#[derive(Clone)]
pub struct AuthHandlerState {
    pub service: Arc<AuthServiceImpl>,
    pub session_service: Option<Arc<SessionService>>,
    pub rate_limiter: Option<Arc<RateLimiter>>,
    pub config: Option<Arc<Config>>,
    /// Non-optional: a missing service must never degrade the login gate to a bypass.
    pub totp_service: Arc<TotpService>,
}

pub(crate) async fn method_not_allowed() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, "POST")],
        Json(ErrorResponse::from(&AppError::MethodNotAllowed)),
    )
}

/// Build the auth router for callers that hold only the auth service.
///
/// Fails at startup when `config` has no usable TOTP key. This router has no session
/// service and mounts no `/totp/verify` or `/totp/backup` route, so it cannot redeem a
/// challenge: a TOTP-enabled login is refused here instead of answered with a token that
/// nothing on this router can consume. Serve 2FA through [`routes_with_app_state`] (or
/// [`crate::handler::create_router`]), which mount the TOTP routes alongside.
pub fn routes(service: Arc<AuthServiceImpl>, config: Arc<Config>) -> Result<Router, AppError> {
    config.validate().map_err(AppError::Config)?;
    config
        .totp
        .encryption_key_bytes()
        .map_err(AppError::Config)?;
    let totp_service = Arc::new(TotpService::new(
        service.pool().clone(),
        Arc::clone(&config),
        Arc::clone(&service.config),
    ));
    routes_with_state(AuthHandlerState {
        service,
        session_service: None,
        rate_limiter: None,
        config: Some(config),
        totp_service,
    })
}

/// Build the auth router on top of an existing [`AppState`].
///
/// Fails at startup when the TOTP encryption key is absent or unusable: this router mounts
/// `/auth/login`, so a keyless config would mint challenges it cannot verify.
pub fn routes_with_app_state(state: AppState) -> Result<Router, AppError> {
    require_totp_key(Some(&state.config))?;

    let handler_state = AuthHandlerState {
        service: Arc::clone(&state.auth_service),
        session_service: Some(Arc::clone(&state.session_service)),
        rate_limiter: Some(Arc::clone(&state.rate_limiter)),
        config: Some(Arc::new(state.config.clone())),
        totp_service: Arc::clone(&state.totp_service),
    };

    let csrf_layer =
        axum::middleware::from_fn_with_state(state.clone(), crate::middleware::csrf_middleware);
    let csrf_routes = Router::new()
        .route(
            "/logout",
            axum::routing::post(logout.layer(csrf_layer)).fallback(method_not_allowed),
        )
        .with_state(handler_state.clone());

    let public_routes = Router::new()
        .route(
            "/signup",
            axum::routing::post(signup).fallback(method_not_allowed),
        )
        .route(
            "/login",
            axum::routing::post(login).fallback(method_not_allowed),
        )
        .route(
            "/verify",
            axum::routing::post(verify_email).fallback(method_not_allowed),
        )
        .route(
            "/password/reset-request",
            axum::routing::post(request_password_reset).fallback(method_not_allowed),
        )
        .route(
            "/password/reset",
            axum::routing::post(reset_password).fallback(method_not_allowed),
        )
        .with_state(handler_state);

    Ok(public_routes.merge(csrf_routes))
}

/// Build the auth router from a prebuilt [`AuthHandlerState`].
///
/// Fails at startup when the state carries no config or its TOTP encryption key is absent or
/// unusable: this router mounts `/login`, so a keyless config would mint challenges it cannot
/// verify.
pub fn routes_with_state(state: AuthHandlerState) -> Result<Router, AppError> {
    require_totp_key(state.config.as_deref())?;

    Ok(Router::new()
        .route(
            "/signup",
            axum::routing::post(signup).fallback(method_not_allowed),
        )
        .route(
            "/login",
            axum::routing::post(login).fallback(method_not_allowed),
        )
        .route(
            "/logout",
            axum::routing::post(logout).fallback(method_not_allowed),
        )
        .route(
            "/verify",
            axum::routing::post(verify_email).fallback(method_not_allowed),
        )
        .route(
            "/password/reset-request",
            axum::routing::post(request_password_reset).fallback(method_not_allowed),
        )
        .route(
            "/password/reset",
            axum::routing::post(reset_password).fallback(method_not_allowed),
        )
        .with_state(state))
}

// ─── Error mapping helpers ────────────────────────────────────────────────────

/// Map a JSON extraction failure to a `VALIDATION_ERROR` 400.
pub(crate) fn json_rejection_response(rejection: JsonRejection) -> Response {
    tracing::debug!(error = %rejection, "JSON parse/validation error");
    let payload = ErrorResponse {
        code: ErrorCode::ValidationError,
        message: "Invalid request body".to_string(),
    };
    (StatusCode::BAD_REQUEST, Json(payload)).into_response()
}

/// Map `AppError` to HTTP response following spec wire codes.
pub(crate) fn service_error_response(err: AppError) -> Response {
    err.into_response()
}

/// Attach session + CSRF cookies to a cookie-login response.
///
/// Fails closed: a cookie that cannot encode (server-side bug — tokens are hex)
/// becomes a 500 via `AppError::Internal`, never an empty `Set-Cookie`.
pub(crate) fn attach_login_cookies(
    mut response: Response,
    cfg: &Config,
    raw_id: &str,
    csrf_token: Option<&str>,
) -> Result<Response, AppError> {
    response
        .headers_mut()
        .insert(header::SET_COOKIE, set_session_cookie(cfg, raw_id)?);
    if let Some(csrf) = csrf_token {
        response
            .headers_mut()
            .append(header::SET_COOKIE, set_csrf_cookie(cfg, csrf)?);
    }
    Ok(response)
}

/// Extract client IP from proxy headers, falling back to 127.0.0.1.
///
/// Spoofable unless a trusted proxy strips these headers; audit/rate-limit use only.
pub(crate) fn extract_client_ip(headers: &HeaderMap) -> String {
    untrusted_client_ip(headers)
        .unwrap_or("127.0.0.1")
        .to_string()
}

/// Construct an HTTP 429 response, carrying `Retry-After` only for a lockout.
///
/// The auth routes pass a cooldown to every limiter call, so their window rejections are
/// always lockouts; capacity saturation admits no attempt and has no window to advertise.
/// A bare window rejection is not emitted here on purpose — the TOTP routes advertise
/// theirs through `handler::totp::totp_rate_limit_exceeded`, which keeps their header a
/// statement about the rejection that produced it.
fn rate_limit_response(rejection: RateLimitRejection) -> Response {
    let mut resp = service_error_response(AppError::RateLimitExceeded);
    if let RateLimitRejection::Lockout(secs) = rejection
        && let Ok(val) = header::HeaderValue::from_str(&secs.to_string())
    {
        resp.headers_mut().insert(header::RETRY_AFTER, val);
    }
    resp
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// POST /auth/signup
///
/// Anti-enumeration: always returns 200 regardless of duplicate email.
pub async fn signup(
    State(state): State<AuthHandlerState>,
    headers: HeaderMap,
    body: Result<Json<SignupRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match body {
        Ok(b) => b,
        Err(e) => return json_rejection_response(e),
    };

    if let Err(e) = req.validate(&state.service.config) {
        return service_error_response(e);
    }

    let client_ip = extract_client_ip(&headers);
    let normalized_email = req.email.trim().to_lowercase();

    if let Some(limiter) = &state.rate_limiter {
        match limiter.check_dual(&client_ip, &normalized_email) {
            Ok(()) => {}
            Err(rejection) => {
                tracing::warn!(
                    event = "rate_limit_exceeded",
                    ip = %client_ip,
                    key_prefix = "signup",
                );
                return rate_limit_response(rejection);
            }
        }
    }

    match state.service.signup(&req.email, &req.password).await {
        Ok(()) => (
            StatusCode::OK,
            Json(MessageResponse::new(
                "if this email is new, a verification link has been sent",
            )),
        )
            .into_response(),
        Err(e) => service_error_response(e),
    }
}

/// POST /auth/login
///
/// Returns 200 with `user_id` (and token if bearer) on success.
/// Sets HttpOnly session cookie and SameSite=Strict CSRF cookie for cookie sessions.
/// Returns 401 for wrong password OR unknown email (identical response — anti-enum).
/// Returns 403 when `require_email_verification = true` and email unverified.
/// Returns 429 when login rate limit is exceeded.
/// Returns 500 when the account has 2FA enabled but this router carries no session
/// service, and therefore no route that could redeem the challenge.
pub async fn login(
    State(state): State<AuthHandlerState>,
    headers: HeaderMap,
    body: Result<Json<LoginRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match body {
        Ok(b) => b,
        Err(e) => return json_rejection_response(e),
    };

    if let Err(e) = req.validate() {
        return service_error_response(e);
    }

    let client_ip = extract_client_ip(&headers);

    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let normalized_email = req.email.trim().to_lowercase();

    // Pre-credential rate limit check prevents account existence timing oracles
    if let Some(limiter) = &state.rate_limiter {
        match limiter.check_dual(&client_ip, &normalized_email) {
            Ok(()) => {}
            Err(rejection) => {
                tracing::warn!(
                    event = "rate_limit_exceeded",
                    ip = %client_ip,
                    key_prefix = "login",
                );
                return rate_limit_response(rejection);
            }
        }
    }

    let proof = match state
        .service
        .login_with_proof(&normalized_email, &req.password)
        .await
    {
        Ok(proof) => proof,
        Err(e) => {
            tracing::warn!(
                event = "login_failure",
                reason = "invalid_credentials",
                ip = %client_ip,
                user_agent = %user_agent.as_deref().unwrap_or("unknown"),
            );
            return service_error_response(e);
        }
    };
    let user_id = proof.user_id;

    // Reset rate limit attempts upon successful authentication for account only
    if let Some(limiter) = &state.rate_limiter {
        limiter.reset_account(&normalized_email);
    }

    // Second factor gate: password verified, no session until the code is accepted.
    // Fail closed: an unavailable service or lookup error aborts login, never bypasses it.
    let Some(session_service) = &state.session_service else {
        // Without a session service this router also has no way to redeem a challenge,
        // so it must not hand one out at all.
        return match state.totp_service.is_totp_enabled(user_id).await {
            Ok(false) => (StatusCode::OK, Json(LoginResponse::new(user_id))).into_response(),
            Ok(true) => {
                tracing::error!(
                    event = "two_factor_unavailable",
                    reason = "router_without_session_service",
                    user_id = %user_id,
                    "login refused: this router cannot redeem a totp challenge"
                );
                service_error_response(AppError::Internal)
            }
            Err(e) => service_error_response(e),
        };
    };

    let is_bearer = headers
        .get("x-auth-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.eq_ignore_ascii_case("bearer"));

    let session_type = if is_bearer { "bearer" } else { "cookie" };

    let outcome = match issue_session_after_gate(
        &state,
        session_service,
        user_id,
        &proof.credential_hash,
        session_type,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(e) => return service_error_response(e),
    };

    let (session, raw_id) = match outcome {
        PasswordLoginOutcome::SecondFactorRequired => {
            let challenge_token = match state.totp_service.generate_two_factor_token(user_id).await
            {
                Ok(token) => token,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        user_id = %user_id,
                        "login refused: second-factor challenge could not be minted"
                    );
                    return service_error_response(AppError::TwoFactorUnavailable);
                }
            };
            tracing::info!(
                target: "security_event",
                event = "two_factor_challenge_issued",
                user_id = %user_id,
                ip = %client_ip,
                user_agent = %user_agent.as_deref().unwrap_or("unknown"),
            );
            return (
                StatusCode::OK,
                Json(LoginResponse::two_factor_required(challenge_token)),
            )
                .into_response();
        }
        PasswordLoginOutcome::Session(session, raw_id) => (session, raw_id),
    };

    tracing::info!(
        event = "session_created",
        user_id = %user_id,
        session_type = session_type,
        ip = %client_ip,
        user_agent = %user_agent.as_deref().unwrap_or("unknown"),
    );
    // `session_id_hash` is a SHA-256 of a 256-bit token, never the token: a correlator,
    // not a credential. Every authentication event carries it; lifecycle events do not.
    tracing::info!(
        event = "login_success",
        user_id = %user_id,
        session_type = session_type,
        ip = %client_ip,
        user_agent = %user_agent.as_deref().unwrap_or("unknown"),
        session_id_hash = %session.token_hash,
    );

    if is_bearer {
        (
            StatusCode::OK,
            Json(LoginResponse::with_token(user_id, raw_id)),
        )
            .into_response()
    } else {
        let response = (StatusCode::OK, Json(LoginResponse::new(user_id))).into_response();
        if let Some(cfg) = &state.config {
            return match attach_login_cookies(
                response,
                cfg.as_ref(),
                raw_id.as_str(),
                session.csrf_token.as_deref(),
            ) {
                Ok(resp) => resp,
                Err(e) => service_error_response(e),
            };
        }
        response
    }
}

/// What the password login gate decided.
enum PasswordLoginOutcome {
    /// 2FA is enabled: no session was written, and the caller must mint a challenge.
    SecondFactorRequired,
    Session(Session, String),
}

/// Decide the second-factor gate and commit the session in one transaction.
///
/// `is_totp_enabled_locked` holds a share lock on the factor row for this transaction, so
/// `confirm_enrollment` — the only path that sets `enabled` — cannot commit between this read
/// and the session insert when the row exists at read time. Lock first and the activation
/// waits for the commit; activation first and this read waits, then re-reads the new value.
///
/// A missing row takes no lock, and the guarantee stops there: `enroll_totp` can create the
/// row and `confirm_enrollment` enable it between this read and the session insert, leaving a
/// password-only session. The enrollment window opens before the password check too, so a
/// login already past that gate can outrun a confirmation that started earlier. Neither is a
/// bypass: enabling 2FA does not revoke live sessions, so a session minted before activation
/// survives, exactly like any session older than the factor.
///
/// Still not enforced: the challenge token carries no credential state, so one minted
/// before a password reset stays redeemable (#58).
///
/// Lock order is factor row, then user row — the same order [`crate::handler::totp`]
/// redemption takes, so the two cannot deadlock.
async fn issue_session_after_gate(
    state: &AuthHandlerState,
    session_service: &SessionService,
    user_id: Uuid,
    credential_hash: &str,
    session_type: &str,
) -> Result<PasswordLoginOutcome, AppError> {
    let mut transaction = session_service.db().begin().await.map_err(|error| {
        tracing::error!(error = %error, "failed to begin the login gate transaction");
        AppError::Database(error)
    })?;

    let enabled = match state
        .totp_service
        .is_totp_enabled_locked(&mut transaction, user_id)
        .await
    {
        Ok(enabled) => enabled,
        Err(error) => {
            let _ = transaction.rollback().await;
            return Err(error);
        }
    };
    if enabled {
        let _ = transaction.rollback().await;
        return Ok(PasswordLoginOutcome::SecondFactorRequired);
    }

    match session_service
        .create_session_in(
            &mut transaction,
            user_id,
            Some(credential_hash),
            session_type,
        )
        .await
    {
        Ok((session, raw_id)) => {
            transaction.commit().await.map_err(|error| {
                tracing::error!(error = %error, "failed to commit the login gate transaction");
                AppError::Database(error)
            })?;
            Ok(PasswordLoginOutcome::Session(session, raw_id))
        }
        Err(error) => {
            let _ = transaction.rollback().await;
            Err(error)
        }
    }
}

/// POST /auth/logout
///
/// Revokes session on server side and clears the session cookie.
pub async fn logout(State(state): State<AuthHandlerState>, headers: HeaderMap) -> Response {
    let client_ip = extract_client_ip(&headers);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        target: "security_event",
        event = "logout",
        ip = %client_ip,
        user_agent = %user_agent,
    );

    let cookie_name = state
        .config
        .as_ref()
        .map_or("sid", |c| c.session.cookie_name.as_str());

    let raw_id_opt =
        read_session_cookie(&headers, cookie_name).or_else(|| read_bearer_token(&headers));

    let Some(ref raw_id) = raw_id_opt else {
        // Unauthenticated logout: return 204 without revoking credentials or clearing cookies.
        // Emitting Set-Cookie on unauthenticated requests enables cross-site cookie deletion attacks.
        return StatusCode::NO_CONTENT.into_response();
    };

    if let Some(ref session_svc) = state.session_service {
        match session_svc.invalidate_session(raw_id).await {
            Ok(()) => {}
            Err(e) => return service_error_response(e),
        }
    }
    if let Err(e) = state.service.logout(raw_id).await {
        return service_error_response(e);
    }

    let mut response = StatusCode::NO_CONTENT.into_response();
    if let Some(ref cfg) = state.config {
        let clear_cookie = match clear_session_cookie(cfg.as_ref()) {
            Ok(hv) => hv,
            Err(e) => return service_error_response(e),
        };
        response
            .headers_mut()
            .append(header::SET_COOKIE, clear_cookie);

        let clear_csrf = match clear_csrf_cookie(cfg.as_ref()) {
            Ok(hv) => hv,
            Err(e) => return service_error_response(e),
        };
        response
            .headers_mut()
            .append(header::SET_COOKIE, clear_csrf);
    }
    response
}

/// POST /auth/verify
///
/// Consumes a 64-char hex email verification token.
pub async fn verify_email(
    State(state): State<AuthHandlerState>,
    headers: HeaderMap,
    body: Result<Json<VerifyEmailRequest>, JsonRejection>,
) -> Response {
    let client_ip = extract_client_ip(&headers);
    if let Some(limiter) = &state.rate_limiter {
        match limiter.check_ip(&client_ip) {
            Ok(()) => {}
            Err(rejection) => {
                tracing::warn!(
                    event = "rate_limit_exceeded",
                    ip = %client_ip,
                    key_prefix = "verify",
                );
                return rate_limit_response(rejection);
            }
        }
    }

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
    headers: HeaderMap,
    body: Result<Json<PasswordResetRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match body {
        Ok(b) => b,
        Err(e) => return json_rejection_response(e),
    };

    if let Err(e) = req.validate() {
        return service_error_response(e);
    }

    let client_ip = extract_client_ip(&headers);
    let normalized_email = req.email.trim().to_lowercase();

    if let Some(limiter) = &state.rate_limiter {
        match limiter.check_password_reset(&client_ip, &normalized_email) {
            Ok(()) => {}
            Err(rejection) => {
                tracing::warn!(
                    event = "rate_limit_exceeded",
                    ip = %client_ip,
                    key_prefix = "password_reset_request",
                );
                return rate_limit_response(rejection);
            }
        }
    }

    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        target: "security_event",
        event = "password_reset_requested",
        ip = %client_ip,
        user_agent = %user_agent,
    );

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
    headers: HeaderMap,
    body: Result<Json<PasswordResetConfirmRequest>, JsonRejection>,
) -> Response {
    let client_ip = extract_client_ip(&headers);
    if let Some(limiter) = &state.rate_limiter {
        match limiter.check_ip(&client_ip) {
            Ok(()) => {}
            Err(rejection) => {
                tracing::warn!(
                    event = "rate_limit_exceeded",
                    ip = %client_ip,
                    key_prefix = "password_reset",
                );
                return rate_limit_response(rejection);
            }
        }
    }

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
    use crate::{config::AppConfig, email::EmailDispatcher};
    use axum::body::to_bytes;
    use sqlx::PgPool;

    fn test_config_with_totp_key() -> Arc<Config> {
        Arc::new(Config {
            totp: crate::config::TotpConfig {
                encryption_key: Some("00".repeat(32)),
                ..crate::config::TotpConfig::default()
            },
            ..Config::default()
        })
    }

    fn create_test_state() -> AuthHandlerState {
        // The gate is mandatory, so never let its pool point at an unrelated database.
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set: the 2FA gate builds a real pool");
        let pool = PgPool::connect_lazy(&database_url).expect("lazy pool");
        let config = Arc::new(AppConfig {
            argon2_m_cost: 19456,
            argon2_t_cost: 2,
            argon2_p_cost: 1,
            password_min_len: 8,
            password_max_len: 128,
            ..Default::default()
        });
        // Blocking mode is worker-free. A detached dispatcher would spawn the production
        // worker on the real schema, and that worker rewrites `email_outbox` every poll
        // tick without holding `crate::db::DB_TEST_LOCK`. These tests assert HTTP shapes
        // and never deliver, so inline mode costs nothing and removes the writer.
        let dispatcher = Arc::new(EmailDispatcher::new_blocking(
            None,
            std::time::Duration::from_secs(10),
        ));
        let service = Arc::new(
            AuthServiceImpl::new(pool.clone(), Arc::clone(&config), dispatcher)
                .expect("test service"),
        );
        let totp_service = Arc::new(TotpService::new(pool, Arc::new(Config::default()), config));
        AuthHandlerState {
            service,
            session_service: None,
            rate_limiter: None,
            config: None,
            totp_service,
        }
    }

    #[tokio::test]
    async fn routes_reject_a_config_without_a_totp_key() {
        let state = create_test_state();
        let result = routes(state.service, Arc::new(Config::default()));

        assert!(
            matches!(result, Err(AppError::Config(_))),
            "a keyless config must fail at startup, not at the first challenge"
        );
    }

    #[tokio::test]
    async fn login_handler_rejects_empty_credentials_without_db() {
        let state = create_test_state();
        let payload = LoginRequest {
            email: String::new(),
            password: String::new(),
        };

        let resp = login(State(state), HeaderMap::new(), Ok(Json(payload))).await;
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
            password: format!("s_{}", uuid::Uuid::new_v4().simple())[..5].to_string(),
        };

        let resp = signup(State(state), HeaderMap::new(), Ok(Json(payload))).await;
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

        let resp = verify_email(State(state), HeaderMap::new(), Ok(Json(payload))).await;
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

        let resp = request_password_reset(State(state), HeaderMap::new(), Ok(Json(payload))).await;
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
            new_password: format!("ValidPass_{}!", uuid::Uuid::new_v4().simple()),
        };

        let resp = reset_password(State(state), HeaderMap::new(), Ok(Json(payload))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, ErrorCode::InvalidToken);
    }

    #[tokio::test]
    async fn logout_handler_returns_no_content() {
        let state = create_test_state();
        let resp = logout(State(state), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn logout_handler_propagates_session_invalidation_error() {
        let mut state = create_test_state();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/postgres")
            .expect("lazy pool");
        let session_svc = Arc::new(SessionService::new(pool, Arc::new(Config::default())));
        state.session_service = Some(session_svc);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer test-token"),
        );

        let resp = logout(State(state), headers).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn malformed_json_body_returns_400_validation_error() {
        use tower::ServiceExt;
        let app = routes(create_test_state().service, test_config_with_totp_key()).expect("routes");
        let req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/signup")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from("{not valid json"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, ErrorCode::ValidationError);
        assert_eq!(err.message, "Invalid request body");
    }

    #[tokio::test]
    async fn route_method_not_allowed_returns_405_json_envelope() {
        use tower::ServiceExt;
        let app = routes(create_test_state().service, test_config_with_totp_key()).expect("routes");
        let req = axum::http::Request::builder()
            .method(axum::http::Method::GET)
            .uri("/signup")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            resp.headers()
                .get(header::ALLOW)
                .and_then(|v| v.to_str().ok()),
            Some("POST")
        );

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, ErrorCode::MethodNotAllowed);
        assert_eq!(err.message, "Method not allowed");
    }

    #[tokio::test]
    async fn login_handler_rate_limits_and_normalizes_email() {
        let mut state = create_test_state();
        let limiter = Arc::new(RateLimiter::with_config(crate::config::RateLimitConfig {
            enabled: true,
            max_attempts: 2,
            window_secs: 60,
            login_cooldown_secs: 300,
        }));
        state.rate_limiter = Some(limiter);

        // First attempt with " User@Example.COM "
        let payload1 = LoginRequest {
            email: " User@Example.COM ".to_string(),
            password: "wrong-password".to_string(),
        };
        let _ = login(State(state.clone()), HeaderMap::new(), Ok(Json(payload1))).await;

        // Second attempt with "user@example.com"
        let payload2 = LoginRequest {
            email: "user@example.com".to_string(),
            password: "wrong-password".to_string(),
        };
        let _ = login(State(state.clone()), HeaderMap::new(), Ok(Json(payload2))).await;

        // Third attempt exceeds max_attempts (2) and activates cooldown
        let payload3 = LoginRequest {
            email: "USER@EXAMPLE.COM".to_string(),
            password: "wrong-password".to_string(),
        };
        let resp = login(State(state), HeaderMap::new(), Ok(Json(payload3))).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key(header::RETRY_AFTER));

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, ErrorCode::RateLimitExceeded);
    }

    #[test]
    fn rate_limit_response_omits_retry_after_without_a_lockout() {
        let window = rate_limit_response(RateLimitRejection::Exceeded(42));
        assert!(
            !window.headers().contains_key(header::RETRY_AFTER),
            "an auth-route window rejection must keep the pre-existing header behaviour"
        );

        let lockout = rate_limit_response(RateLimitRejection::Lockout(42));
        assert_eq!(
            lockout
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("42")
        );
    }

    #[tokio::test]
    async fn signup_handler_rate_limits_dual_key() {
        let mut state = create_test_state();
        let limiter = Arc::new(RateLimiter::with_config(crate::config::RateLimitConfig {
            enabled: true,
            max_attempts: 1,
            window_secs: 60,
            login_cooldown_secs: 300,
        }));
        state.rate_limiter = Some(limiter);

        let payload = SignupRequest {
            email: "victim@example.com".to_string(),
            password: format!("ValidPass_{}!", uuid::Uuid::new_v4().simple()),
        };

        let mut headers1 = HeaderMap::new();
        headers1.insert("x-forwarded-for", "198.51.100.1".parse().unwrap());
        let _ = signup(State(state.clone()), headers1, Ok(Json(payload.clone()))).await;

        // Distinct IP with the same email must be rate limited by account key
        let mut headers2 = HeaderMap::new();
        headers2.insert("x-forwarded-for", "198.51.100.2".parse().unwrap());
        let resp = signup(State(state.clone()), headers2, Ok(Json(payload))).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key(header::RETRY_AFTER));

        // Same original IP with a different email must be rate limited by IP key
        let mut headers3 = HeaderMap::new();
        headers3.insert("x-forwarded-for", "198.51.100.1".parse().unwrap());
        let payload_other = SignupRequest {
            email: "other@example.com".to_string(),
            password: format!("ValidPass_{}!", uuid::Uuid::new_v4().simple()),
        };
        let resp_ip = signup(State(state), headers3, Ok(Json(payload_other))).await;
        assert_eq!(resp_ip.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp_ip.headers().contains_key(header::RETRY_AFTER));
    }

    #[tokio::test]
    async fn verify_email_handler_rate_limits_ip() {
        let mut state = create_test_state();
        let limiter = Arc::new(RateLimiter::with_config(crate::config::RateLimitConfig {
            enabled: true,
            max_attempts: 1,
            window_secs: 60,
            login_cooldown_secs: 300,
        }));
        state.rate_limiter = Some(limiter);

        let dynamic_token = format!(
            "{:032x}{:032x}",
            uuid::Uuid::new_v4().as_u128(),
            uuid::Uuid::new_v4().as_u128()
        );
        let payload = VerifyEmailRequest {
            token: dynamic_token,
        };

        let _ = verify_email(
            State(state.clone()),
            HeaderMap::new(),
            Ok(Json(payload.clone())),
        )
        .await;

        let resp = verify_email(State(state), HeaderMap::new(), Ok(Json(payload))).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key(header::RETRY_AFTER));
    }

    #[tokio::test]
    async fn request_password_reset_handler_rate_limits_dual_key() {
        let mut state = create_test_state();
        let limiter = Arc::new(RateLimiter::with_config(crate::config::RateLimitConfig {
            enabled: true,
            max_attempts: 1,
            window_secs: 60,
            login_cooldown_secs: 300,
        }));
        state.rate_limiter = Some(limiter);

        let payload = PasswordResetRequest {
            email: "target@example.com".to_string(),
        };

        let mut headers1 = HeaderMap::new();
        headers1.insert("x-forwarded-for", "198.51.100.10".parse().unwrap());
        let _ =
            request_password_reset(State(state.clone()), headers1, Ok(Json(payload.clone()))).await;

        // Distinct IP with same email must hit reset_account rate limit
        let mut headers2 = HeaderMap::new();
        headers2.insert("x-forwarded-for", "198.51.100.11".parse().unwrap());
        let resp = request_password_reset(State(state), headers2, Ok(Json(payload))).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key(header::RETRY_AFTER));
    }

    #[tokio::test]
    async fn reset_password_handler_rate_limits_ip() {
        let mut state = create_test_state();
        let limiter = Arc::new(RateLimiter::with_config(crate::config::RateLimitConfig {
            enabled: true,
            max_attempts: 1,
            window_secs: 60,
            login_cooldown_secs: 300,
        }));
        state.rate_limiter = Some(limiter);

        let dynamic_token = format!(
            "{:032x}{:032x}",
            uuid::Uuid::new_v4().as_u128(),
            uuid::Uuid::new_v4().as_u128()
        );
        let payload = PasswordResetConfirmRequest {
            token: dynamic_token,
            new_password: format!("ValidPass_{}!", uuid::Uuid::new_v4().simple()),
        };

        let _ = reset_password(
            State(state.clone()),
            HeaderMap::new(),
            Ok(Json(payload.clone())),
        )
        .await;

        let resp = reset_password(State(state), HeaderMap::new(), Ok(Json(payload))).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key(header::RETRY_AFTER));
    }

    #[tokio::test]
    async fn logout_clears_session_and_csrf_cookies() {
        let mut state = create_test_state();
        let config = Config::default();
        state.config = Some(Arc::new(config));

        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "sid=mock_session_id".parse().unwrap());
        let resp = logout(State(state), headers).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let cookies: Vec<_> = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|h| h.to_str().unwrap().to_string())
            .collect();

        assert_eq!(cookies.len(), 2);
        assert!(
            cookies
                .iter()
                .any(|c| c.contains("sid=") && c.contains("Max-Age=0"))
        );
        assert!(
            cookies
                .iter()
                .any(|c| c.contains("csrf_token=") && c.contains("Max-Age=0"))
        );
    }

    #[tokio::test]
    async fn logout_unauthenticated_does_not_clear_cookies() {
        let mut state = create_test_state();
        let config = Config::default();
        state.config = Some(Arc::new(config));

        let resp = logout(State(state), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(!resp.headers().contains_key(header::SET_COOKIE));
    }

    #[tokio::test]
    async fn logout_unsupported_methods_return_405() {
        use tower::ServiceExt;
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let config = Config {
            totp: crate::config::TotpConfig {
                encryption_key: Some("00".repeat(crate::config::TOTP_ENCRYPTION_KEY_BYTES)),
                ..crate::config::TotpConfig::default()
            },
            ..Config::default()
        };
        let app_state = AppState::with_configs_and_dispatcher(
            pool,
            config,
            Arc::new(AppConfig::default()),
            // Worker-free, like `create_test_state`: the default dispatcher would spawn the
            // production outbox worker against whatever the lazy pool resolves to.
            Some(Arc::new(EmailDispatcher::new_blocking(
                None,
                std::time::Duration::from_secs(10),
            ))),
        )
        .expect("valid test AppState");
        let app = routes_with_app_state(app_state).expect("keyed config builds the auth router");

        for method in [
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::GET,
        ] {
            let req = axum::http::Request::builder()
                .method(method)
                .uri("/logout")
                .header(header::COOKIE, "sid=mock_session_id")
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(resp.headers().get(header::ALLOW).unwrap(), "POST");
        }

        let post_req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/logout")
            .header(header::COOKIE, "sid=mock_session_id")
            .body(axum::body::Body::empty())
            .unwrap();
        let post_resp = app.oneshot(post_req).await.unwrap();
        assert_eq!(post_resp.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(post_resp.into_body(), 1024).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, ErrorCode::CsrfTokenMissing);
    }

    #[tokio::test]
    async fn signup_validation_runs_before_rate_limiter() {
        let mut state = create_test_state();
        let limiter = Arc::new(RateLimiter::new());
        state.rate_limiter = Some(Arc::clone(&limiter));

        let payload = SignupRequest {
            email: "valid@example.com".to_string(),
            password: format!("s_{}", uuid::Uuid::new_v4().simple())[..5].to_string(),
        };

        let resp = signup(State(state), HeaderMap::new(), Ok(Json(payload))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(limiter.entry_count(), 0);
    }

    #[tokio::test]
    async fn request_password_reset_validation_runs_before_rate_limiter() {
        let mut state = create_test_state();
        let limiter = Arc::new(RateLimiter::new());
        state.rate_limiter = Some(Arc::clone(&limiter));

        let payload = PasswordResetRequest {
            email: "invalid-email".to_string(),
        };

        let resp = request_password_reset(State(state), HeaderMap::new(), Ok(Json(payload))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(limiter.entry_count(), 0);
    }

    /// Returns a real pool on the shared test schema, or skips loudly outside CI.
    async fn db_test_pool() -> Option<PgPool> {
        let url = match std::env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "DATABASE_URL must be set in CI: DB-backed tests must never skip silently"
                );
                eprintln!("SKIP: DB-backed handler tests need DATABASE_URL");
                return None;
            }
        };
        Some(
            crate::db::init_pool_with_options(
                &url,
                crate::db::DbPoolOptions {
                    max_connections: 2,
                    min_connections: 1,
                    ..Default::default()
                },
            )
            .await
            .expect("DATABASE_URL is set, so the DB-backed test must connect"),
        )
    }

    /// A state built for handler tests must not run the production outbox worker: that worker
    /// rewrites `email_outbox` on startup and on every poll tick, off-lock, so it can reset or
    /// delete a row the owning test is asserting on.
    #[tokio::test]
    async fn test_state_runs_no_outbox_worker() {
        let _guard = crate::db::DB_TEST_LOCK.lock().await;
        let Some(pool) = db_test_pool().await else {
            return;
        };

        let stale_id = uuid::Uuid::new_v4();
        let expired_id = uuid::Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO email_outbox (id, recipient, email_type, payload, status, retry_count, next_retry_at)
            VALUES ($1, $2, 'verification', '{}'::jsonb, $3, 0, NOW() - INTERVAL '10 seconds')
            "#,
        )
        .bind(stale_id)
        .bind(format!("handler_stale_{stale_id}@example.com"))
        .bind(crate::db::models::OUTBOX_STATUS_PROCESSING)
        .execute(&pool)
        .await
        .expect("insert expired processing row");
        sqlx::query(
            r#"
            INSERT INTO email_outbox (id, recipient, email_type, payload, status, retry_count, next_retry_at, sent_at)
            VALUES ($1, $2, 'verification', '{}'::jsonb, $3, 0, NOW(), NOW() - INTERVAL '10 days')
            "#,
        )
        .bind(expired_id)
        .bind(format!("handler_expired_{expired_id}@example.com"))
        .bind(crate::db::models::OUTBOX_STATUS_SENT)
        .execute(&pool)
        .await
        .expect("insert retainable sent row");

        let _state = create_test_state();

        // The worker recovers stale leases and purges expired `sent` rows immediately on
        // spawn, so two poll intervals leave no room for a lucky-timing pass.
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        let stale = crate::db::outbox::get_outbox_by_id(&pool, stale_id)
            .await
            .expect("fetch expired processing row")
            .expect("row exists");
        assert_eq!(
            stale.status,
            crate::db::models::OUTBOX_STATUS_PROCESSING,
            "building a handler test state must not run recover_stale_processing"
        );
        assert!(
            crate::db::outbox::get_outbox_by_id(&pool, expired_id)
                .await
                .expect("fetch sent row")
                .is_some(),
            "building a handler test state must not run cleanup_sent_outbox"
        );

        let _ = sqlx::query("DELETE FROM email_outbox WHERE id IN ($1, $2)")
            .bind(stale_id)
            .bind(expired_id)
            .execute(&pool)
            .await;
    }
}
