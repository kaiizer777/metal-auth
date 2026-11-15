//! Axum route handlers for all 6 auth endpoints.
//!
//! All error responses use envelope `{"code":"...","message":"..."}`.
//! All success responses use `{"message":"..."}` or domain fields.
//! Never raw strings, never internal details.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::{
    auth::models::{
        LoginRequest, LoginResponse, MessageResponse, PasswordResetConfirmRequest,
        PasswordResetRequest, SignupRequest, VerifyEmailRequest,
    },
    auth::service::AuthServiceImpl,
    config::Config,
    error::{AppError, ErrorCode, ErrorResponse},
    ratelimit::{RateLimiter, rate_limit_key},
    session::{
        SessionService,
        bearer::read_bearer_token,
        cookie::{clear_session_cookie, read_session_cookie, set_csrf_cookie, set_session_cookie},
    },
    state::AppState,
};

// ─── Shared app state for handlers ───────────────────────────────────────────

#[derive(Clone)]
pub struct AuthHandlerState {
    pub service: Arc<AuthServiceImpl>,
    pub session_service: Option<Arc<SessionService>>,
    pub rate_limiter: Option<Arc<RateLimiter>>,
    pub config: Option<Arc<Config>>,
}

async fn method_not_allowed() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, "POST")],
        Json(ErrorResponse::from(&AppError::MethodNotAllowed)),
    )
}

pub fn routes(service: Arc<AuthServiceImpl>) -> Router {
    routes_with_state(AuthHandlerState {
        service,
        session_service: None,
        rate_limiter: None,
        config: None,
    })
}

pub fn routes_with_app_state(state: AppState) -> Router {
    routes_with_state(AuthHandlerState {
        service: Arc::clone(&state.auth_service),
        session_service: Some(Arc::clone(&state.session_service)),
        rate_limiter: Some(Arc::clone(&state.rate_limiter)),
        config: Some(Arc::new(state.config.clone())),
    })
}

pub fn routes_with_state(state: AuthHandlerState) -> Router {
    Router::new()
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

    let client_ip = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim())
        .unwrap_or("127.0.0.1")
        .to_string();

    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let normalized_email = req.email.trim().to_lowercase();

    // Pre-credential rate limit check prevents account existence timing oracles
    if let Some(limiter) = &state.rate_limiter {
        let key = rate_limit_key(&client_ip, &normalized_email);
        if let Err(e) = limiter.check_rate_limit(&key) {
            tracing::warn!(
                event = "rate_limit_exceeded",
                ip = %client_ip,
                key_prefix = "login",
            );
            let mut resp = service_error_response(e);
            let cooldown = state
                .config
                .as_ref()
                .map(|c| c.rate_limit.login_cooldown_secs)
                .unwrap_or(900);
            if let Ok(val) = header::HeaderValue::from_str(&cooldown.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, val);
            }
            return resp;
        }
    }

    let user_id = match state.service.login(&normalized_email, &req.password).await {
        Ok(uid) => uid,
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

    // Reset rate limit attempts upon successful authentication
    if let Some(limiter) = &state.rate_limiter {
        let key = rate_limit_key(&client_ip, &normalized_email);
        limiter.reset(&key);
    }

    let is_bearer = headers
        .get("x-auth-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("bearer"))
        .unwrap_or(false);

    let session_type = if is_bearer { "bearer" } else { "cookie" };

    if let Some(session_svc) = &state.session_service {
        let (session, raw_id) = match session_svc
            .create_session(
                user_id,
                session_type,
                Some(&client_ip),
                user_agent.as_deref(),
            )
            .await
        {
            Ok(s) => s,
            Err(e) => return service_error_response(e),
        };

        tracing::info!(
            event = "login_success",
            user_id = %user_id,
            session_type = session_type,
            ip = %client_ip,
            user_agent = %user_agent.as_deref().unwrap_or("unknown"),
        );

        if is_bearer {
            (
                StatusCode::OK,
                Json(LoginResponse::with_token(user_id, raw_id)),
            )
                .into_response()
        } else {
            let mut response = (StatusCode::OK, Json(LoginResponse::new(user_id))).into_response();
            if let Some(cfg) = &state.config {
                response.headers_mut().insert(
                    header::SET_COOKIE,
                    set_session_cookie(raw_id.as_str(), cfg.as_ref()),
                );
                if let Some(ref csrf) = session.csrf_token {
                    response.headers_mut().append(
                        header::SET_COOKIE,
                        set_csrf_cookie(csrf.as_str(), cfg.as_ref()),
                    );
                }
            }
            response
        }
    } else {
        (StatusCode::OK, Json(LoginResponse::new(user_id))).into_response()
    }
}

/// POST /auth/logout
///
/// Revokes session on server side and clears the session cookie.
pub async fn logout(State(state): State<AuthHandlerState>, headers: HeaderMap) -> Response {
    let cookie_name = state
        .config
        .as_ref()
        .map(|c| c.session.cookie_name.as_str())
        .unwrap_or("sid");

    let raw_id_opt =
        read_session_cookie(&headers, cookie_name).or_else(|| read_bearer_token(&headers));

    if let Some(ref raw_id) = raw_id_opt {
        if let Some(ref session_svc) = state.session_service {
            let _ = session_svc.invalidate_session(raw_id).await;
        }
        let _ = state.service.logout(raw_id).await;
    } else {
        let _ = state.service.logout("").await;
    }

    let mut response = StatusCode::NO_CONTENT.into_response();
    if let Some(ref cfg) = state.config {
        response
            .headers_mut()
            .insert(header::SET_COOKIE, clear_session_cookie(cfg.as_ref()));
    }
    response
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
    use crate::{config::AppConfig, email::EmailDispatcher};
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
        let dispatcher = Arc::new(EmailDispatcher::new(
            None,
            std::time::Duration::from_secs(10),
        ));
        let service =
            Arc::new(AuthServiceImpl::new(pool, config, dispatcher).expect("test service"));
        AuthHandlerState {
            service,
            session_service: None,
            rate_limiter: None,
            config: None,
        }
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
        let resp = logout(State(state), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn malformed_json_body_returns_400_validation_error() {
        use tower::ServiceExt;
        let app = routes(create_test_state().service);
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
        let app = routes(create_test_state().service);
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
}
