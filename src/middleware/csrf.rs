//! CSRF protection via Double Submit Cookie pattern.

use axum::{
    body::Body,
    extract::State,
    http::{Method, Request, Response},
    middleware::Next,
};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;

use crate::{
    error::{AppError, ErrorCode},
    session::{
        bearer::has_bearer_token,
        cookie::{read_session_cookie, set_csrf_cookie},
    },
    state::AppState,
};

/// Axum middleware enforcing Double Submit Cookie CSRF protection.
pub async fn csrf_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, AppError> {
    // 1. Bearer-only requests carry no ambient authority and are CSRF-safe.
    // A request that ALSO presents a session cookie is cookie-authenticated
    // (require_auth prefers the cookie) and must still pass the CSRF check.
    let has_session_cookie =
        read_session_cookie(req.headers(), &state.config.session.cookie_name).is_some();
    let has_csrf_cookie = read_session_cookie(req.headers(), "csrf_token").is_some();
    let has_csrf_header = req.headers().contains_key("x-csrf-token");

    if has_bearer_token(req.headers()) && !has_session_cookie {
        return Ok(next.run(req).await);
    }

    // Requests presenting neither ambient cookies nor CSRF headers carry no ambient authority.
    if !has_session_cookie && !has_csrf_cookie && !has_csrf_header {
        return Ok(next.run(req).await);
    }

    // 2. Safe methods bypass verification and ensure a CSRF cookie is present.
    if matches!(
        req.method(),
        &Method::GET | &Method::HEAD | &Method::OPTIONS | &Method::TRACE
    ) {
        return Ok(maybe_attach_csrf_cookie(req, next, &state).await);
    }

    // 3. Mutating methods (POST, PUT, PATCH, DELETE) require matching cookie and header.
    let csrf_cookie_val = read_session_cookie(req.headers(), "csrf_token");
    let csrf_header_val = req
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok());

    match (csrf_cookie_val, csrf_header_val) {
        (Some(cookie_val), Some(header_val)) => {
            let cookie_trim = cookie_val.trim();
            let header_trim = header_val.trim();

            if cookie_trim.is_empty() || header_trim.is_empty() {
                return Err(AppError::from_code(ErrorCode::CsrfTokenMissing));
            }

            // Enforce expected token length (32 or 64 hex characters) and length parity
            if cookie_trim.len() != header_trim.len()
                || (cookie_trim.len() != 32 && cookie_trim.len() != 64)
            {
                tracing::warn!(
                    event = "csrf_mismatch",
                    reason = "invalid_or_mismatched_token_length"
                );
                return Err(AppError::from_code(ErrorCode::CsrfTokenInvalid));
            }

            let cookie_bytes = cookie_trim.as_bytes();
            let header_bytes = header_trim.as_bytes();

            let ct_eq: bool = cookie_bytes.ct_eq(header_bytes).into();

            if !ct_eq {
                tracing::warn!(event = "csrf_mismatch");
                return Err(AppError::from_code(ErrorCode::CsrfTokenInvalid));
            }

            Ok(next.run(req).await)
        }
        _ => Err(AppError::from_code(ErrorCode::CsrfTokenMissing)),
    }
}

/// Attach a fresh CSRF cookie on safe methods if one is not already present.
pub async fn maybe_attach_csrf_cookie(
    req: Request<Body>,
    next: Next,
    state: &AppState,
) -> Response<Body> {
    let has_csrf_cookie = read_session_cookie(req.headers(), "csrf_token").is_some();
    let mut response = next.run(req).await;

    if !has_csrf_cookie {
        let mut csrf_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut csrf_bytes);
        let csrf_token = hex::encode(csrf_bytes);
        // Hex always encodes; on failure skip issuance (fail closed — later
        // mutating requests get 403 CsrfTokenMissing) rather than sending empty.
        match set_csrf_cookie(&state.config, csrf_token.as_str()) {
            Ok(cookie_hv) => {
                response.headers_mut().append("set-cookie", cookie_hv);
            }
            Err(e) => tracing::error!(event = "csrf_cookie_build_failed", error = %e),
        }
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::to_bytes,
        middleware::from_fn_with_state,
        routing::{get, post},
    };
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use crate::{config::Config, error::ErrorResponse};

    fn test_app_state() -> AppState {
        let cfg = Config {
            database_url: "postgres://postgres:postgres@127.0.0.1:1/postgres".to_string(),
            ..Default::default()
        };
        let pool = PgPoolOptions::new()
            .connect_lazy(&cfg.database_url)
            .expect("lazy pool");
        AppState::new(pool, cfg).expect("AppState::new")
    }

    fn test_router(state: AppState) -> Router {
        Router::new()
            .route("/test", get(|| async { "get_ok" }))
            .route("/test", post(|| async { "post_ok" }))
            .layer(from_fn_with_state(state.clone(), csrf_middleware))
            .with_state(state)
    }

    #[tokio::test]
    async fn safe_method_get_passes_and_issues_csrf_cookie() {
        let state = test_app_state();
        let app = test_router(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let set_cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(set_cookie.contains("csrf_token="));
        assert!(set_cookie.contains("SameSite=Strict"));
        assert!(!set_cookie.contains("HttpOnly"));
    }

    #[tokio::test]
    async fn safe_method_get_with_existing_csrf_cookie_does_not_reissue() {
        let state = test_app_state();
        let app = test_router(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header("cookie", "csrf_token=existing_token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert!(resp.headers().get("set-cookie").is_none());
    }

    #[tokio::test]
    async fn bearer_token_bypasses_csrf_on_post() {
        let state = test_app_state();
        let app = test_router(state);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/test")
            .header("authorization", "Bearer some_jwt_or_token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn bearer_with_session_cookie_does_not_bypass_csrf() {
        let state = test_app_state();
        let cookie_name = state.config.session.cookie_name.clone();
        let app = test_router(state);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/test")
            .header("authorization", "Bearer some_dummy_token")
            .header("cookie", format!("{cookie_name}=session_value_123"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, ErrorCode::CsrfTokenMissing);
    }

    #[tokio::test]
    async fn matching_cookie_and_header_passes_on_post() {
        let state = test_app_state();
        let app = test_router(state);

        let token = "c4d7e9301123456789abcdef01234567";
        let req = Request::builder()
            .method(Method::POST)
            .uri("/test")
            .header("cookie", format!("csrf_token={token}"))
            .header("x-csrf-token", token)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_header_returns_403_csrf_token_missing() {
        let state = test_app_state();
        let app = test_router(state);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/test")
            .header("cookie", "csrf_token=abc")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, ErrorCode::CsrfTokenMissing);
    }

    #[tokio::test]
    async fn missing_cookie_returns_403_csrf_token_missing() {
        let state = test_app_state();
        let app = test_router(state);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/test")
            .header("x-csrf-token", "abc")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, ErrorCode::CsrfTokenMissing);
    }

    #[tokio::test]
    async fn token_mismatch_returns_403_csrf_token_invalid() {
        let state = test_app_state();
        let app = test_router(state);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/test")
            .header("cookie", "csrf_token=token_aaa")
            .header("x-csrf-token", "token_bbb")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, ErrorCode::CsrfTokenInvalid);
    }

    #[tokio::test]
    async fn different_length_tokens_return_403_without_panic() {
        let state = test_app_state();
        let app = test_router(state);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/test")
            .header("cookie", "csrf_token=short")
            .header("x-csrf-token", "very_long_token_string")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, ErrorCode::CsrfTokenInvalid);
    }

    #[tokio::test]
    async fn empty_tokens_in_cookie_and_header_rejected_as_missing() {
        let state = test_app_state();
        let app = test_router(state);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/test")
            .header("cookie", "csrf_token=")
            .header("x-csrf-token", "")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, ErrorCode::CsrfTokenMissing);
    }

    #[tokio::test]
    async fn whitespace_tokens_rejected_as_missing() {
        let state = test_app_state();
        let app = test_router(state);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/test")
            .header("cookie", "csrf_token=   ")
            .header("x-csrf-token", "   ")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, ErrorCode::CsrfTokenMissing);
    }

    #[tokio::test]
    async fn sixty_four_char_matching_tokens_pass() {
        let state = test_app_state();
        let app = test_router(state);

        let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let req = Request::builder()
            .method(Method::POST)
            .uri("/test")
            .header("cookie", format!("csrf_token={token}"))
            .header("x-csrf-token", token)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }
}
