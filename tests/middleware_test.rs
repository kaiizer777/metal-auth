//! Integration and contract tests for CSRF, rate limiter, and authentication middleware.

use std::time::Duration;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::FromRequestParts,
    http::{Method, Request, StatusCode, header},
    middleware::from_fn_with_state,
    routing::{get, post},
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tower::ServiceExt;
use uuid::Uuid;

use metal_auth::{
    AppState, AuthUser, Config, ErrorCode, ErrorResponse, RateLimitConfig, RateLimiter,
    SessionConfig, csrf_middleware, rate_limit_key, require_auth,
};

fn dummy_app_state() -> AppState {
    let cfg = Config {
        database_url: "postgres://postgres:postgres@127.0.0.1:1/postgres".to_string(),
        totp: metal_auth::TotpConfig {
            encryption_key: Some("00".repeat(32)),
            ..metal_auth::TotpConfig::default()
        },
        ..Default::default()
    };
    let pool = PgPoolOptions::new()
        .connect_lazy(&cfg.database_url)
        .expect("lazy pool");
    AppState::new(pool, cfg).expect("AppState::new")
}

async fn setup_live_db() -> Option<(PgPool, AppState)> {
    dotenvy::dotenv().ok();
    let url = match std::env::var("DATABASE_URL") {
        Ok(val) => val,
        Err(std::env::VarError::NotPresent) => {
            assert!(
                std::env::var_os("CI").is_none(),
                "DATABASE_URL must be set in CI: live require_auth tests must not skip silently"
            );
            return None;
        }
        Err(e) => panic!("invalid DATABASE_URL environment variable: {e}"),
    };
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_millis(500))
        .connect(&url)
        .await
        .ok()?;

    let cfg = Config {
        database_url: url,
        session: SessionConfig {
            cookie_name: "sid".to_string(),
            idle_timeout_secs: 1800,
            absolute_lifetime_secs: 86400,
            cookie_path: "/".to_string(),
            cookie_same_site: "Lax".to_string(),
            cookie_secure: false,
            cookie_domain: None,
            ..Default::default()
        },
        rate_limit: RateLimitConfig::default(),
        totp: metal_auth::TotpConfig {
            encryption_key: Some("00".repeat(32)),
            ..metal_auth::TotpConfig::default()
        },
        ..Default::default()
    };

    let state = AppState::new(pool.clone(), cfg).ok()?;
    Some((pool, state))
}

// =========================================================================
// CSRF Middleware Integration Tests
// =========================================================================

/// NOTE: `test_csrf_app` applies `csrf_middleware` in isolation WITHOUT `require_auth` to test
/// the Double-Submit CSRF layer independently. In production, mutating routes MUST also
/// layer `require_auth` so that present-but-invalid Bearer tokens are rejected with 401.
fn test_csrf_app(state: AppState) -> Router {
    Router::new()
        .route("/api/data", get(|| async { "safe_get" }))
        .route("/api/mutate", post(|| async { "mutated" }))
        .layer(from_fn_with_state(state.clone(), csrf_middleware))
        .with_state(state)
}

#[tokio::test]
async fn test_csrf_safe_methods_bypass_and_set_cookie() {
    let state = dummy_app_state();
    let app = test_csrf_app(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/data")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let set_cookie = resp.headers().get(header::SET_COOKIE).expect("set-cookie");
    let cookie_str = set_cookie.to_str().unwrap();
    assert!(cookie_str.contains("csrf_token="));
    assert!(cookie_str.contains("SameSite=Strict"));
    assert!(!cookie_str.contains("HttpOnly"));
}

/// Verifies that `csrf_middleware` exempts requests carrying an Authorization Bearer header
/// (as browsers cannot send custom headers cross-origin without a preflight).
/// Downstream authentication (`require_auth`) is responsible for verifying token validity.
#[tokio::test]
async fn test_csrf_bearer_token_bypasses_check_on_post() {
    let state = dummy_app_state();
    let app = test_csrf_app(state);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/mutate")
        .header(header::AUTHORIZATION, "Bearer some_valid_jwt_or_token")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_csrf_missing_header_returns_403() {
    let state = dummy_app_state();
    let app = test_csrf_app(state);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/mutate")
        .header(header::COOKIE, "csrf_token=1234567890abcdef")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(resp.into_body(), 1024).await.unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.code, ErrorCode::CsrfTokenMissing);
}

#[tokio::test]
async fn test_csrf_missing_cookie_returns_403() {
    let state = dummy_app_state();
    let app = test_csrf_app(state);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/mutate")
        .header("x-csrf-token", "1234567890abcdef")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(resp.into_body(), 1024).await.unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.code, ErrorCode::CsrfTokenMissing);
}

#[tokio::test]
async fn test_csrf_token_mismatch_returns_403() {
    let state = dummy_app_state();
    let app = test_csrf_app(state);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/mutate")
        .header(header::COOKIE, "csrf_token=aaaaaaaaaaaaaaaa")
        .header("x-csrf-token", "bbbbbbbbbbbbbbbb")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(resp.into_body(), 1024).await.unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.code, ErrorCode::CsrfTokenInvalid);
}

#[tokio::test]
async fn test_csrf_length_mismatch_returns_403_without_panic() {
    let state = dummy_app_state();
    let app = test_csrf_app(state);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/mutate")
        .header(header::COOKIE, "csrf_token=short")
        .header("x-csrf-token", "much_longer_token_value_here")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(resp.into_body(), 1024).await.unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.code, ErrorCode::CsrfTokenInvalid);
}

#[tokio::test]
async fn test_csrf_valid_match_passes_post() {
    let state = dummy_app_state();
    let app = test_csrf_app(state);

    let token = "deadbeefcafebabe0123456789abcdef";
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/mutate")
        .header(header::COOKIE, format!("csrf_token={token}"))
        .header("x-csrf-token", token)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// =========================================================================
// Rate Limiter Unit and Integration Tests
// =========================================================================

#[test]
fn test_ratelimit_sliding_window_allow_and_block() {
    let limiter = RateLimiter::new();
    let key = "127.0.0.1|login";
    let window = Duration::from_millis(50);

    for _ in 0..3 {
        assert!(limiter.allow(key, 3, window));
    }
    assert!(!limiter.allow(key, 3, window));

    // Wait for window to expire
    std::thread::sleep(Duration::from_millis(60));
    assert!(limiter.allow(key, 3, window));
}

#[test]
fn test_ratelimit_reset_restores_capacity() {
    let limiter = RateLimiter::new();
    let key = "127.0.0.1|reset";
    let window = Duration::from_secs(60);

    for _ in 0..2 {
        assert!(limiter.allow(key, 2, window));
    }
    assert!(!limiter.allow(key, 2, window));

    limiter.reset(key);
    assert!(limiter.allow(key, 2, window));
}

#[test]
fn test_ratelimit_key_helper_format() {
    assert_eq!(
        rate_limit_key("POST /auth/login", "user@example.com"),
        "POST /auth/login|user@example.com"
    );
    assert_eq!(rate_limit_key("10.0.0.1", ""), "10.0.0.1|");
}

#[test]
fn test_ratelimit_check_rate_limit_cooldown_rejection() {
    let config = RateLimitConfig {
        enabled: true,
        max_attempts: 2,
        window_secs: 60,
        login_cooldown_secs: 60,
    };
    let limiter = RateLimiter::with_config(config);
    assert!(limiter.check_rate_limit("user|cooldown").is_ok());
    assert!(limiter.check_rate_limit("user|cooldown").is_ok());

    let err = limiter.check_rate_limit("user|cooldown").unwrap_err();
    assert_eq!(err.status_code(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(err.error_code(), ErrorCode::RateLimitExceeded);
}

// =========================================================================
// Authentication Middleware (require_auth) Tests
// =========================================================================

fn test_auth_app(state: AppState) -> Router {
    Router::new()
        .route(
            "/api/me",
            get(|user: AuthUser| async move {
                format!(
                    "user_id: {}, session_hash: {}, session_type: {}",
                    user.user_id, user.session_hash, user.session_type
                )
            }),
        )
        .layer(from_fn_with_state(state.clone(), require_auth))
        .with_state(state)
}

#[tokio::test]
async fn test_require_auth_missing_credentials_fails_401() {
    let state = dummy_app_state();
    let app = test_auth_app(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/me")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body = to_bytes(resp.into_body(), 1024).await.unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.code, ErrorCode::SessionNotFound);
}

#[tokio::test]
async fn test_auth_user_extractor_unit_validation() {
    let user_id = Uuid::new_v4();
    let user = AuthUser {
        user_id,
        session_hash: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
            .to_string(),
        session_type: "bearer".to_string(),
    };

    let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
    req.extensions_mut().insert(user.clone());

    let (mut parts, _) = req.into_parts();
    let extracted = AuthUser::from_request_parts(&mut parts, &()).await.unwrap();
    assert_eq!(extracted.user_id, user_id);
    assert_eq!(extracted.session_hash, user.session_hash);
    assert_eq!(extracted.session_type, "bearer");
}

#[tokio::test]
async fn test_require_auth_live_session_cookie_and_bearer_lifecycle() {
    let Some((pool, state)) = setup_live_db().await else {
        if std::env::var_os("CI").is_some() {
            panic!(
                "DATABASE_URL must be set in CI: live require_auth tests must not skip silently"
            );
        }
        println!("Skipping live DB require_auth tests: DATABASE_URL not available");
        return;
    };

    let user_id = Uuid::new_v4();
    let email = format!("mw_user_{}@example.com", user_id);
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(&email)
    .bind("test_placeholder_hash")
    .execute(&state.pool)
    .await
    .expect("insert test user");

    // 1. Test Cookie Session Lifecycle
    let (cookie_session, raw_cookie_token) = state
        .session_service
        .create_session(user_id, "cookie", None, None)
        .await
        .expect("create cookie session");

    let app = test_auth_app(state.clone());
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/me")
        .header(header::COOKIE, format!("sid={raw_cookie_token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(body_str.contains(&format!("user_id: {user_id}")));
    assert!(body_str.contains(&format!("session_hash: {}", cookie_session.token_hash)));
    assert!(body_str.contains("session_type: cookie"));

    // 2. Test Bearer Session Lifecycle
    let (bearer_session, raw_bearer_token) = state
        .session_service
        .create_session(user_id, "bearer", None, None)
        .await
        .expect("create bearer session");

    let app = test_auth_app(state.clone());
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/me")
        .header(header::AUTHORIZATION, format!("Bearer {raw_bearer_token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(body_str.contains(&format!("user_id: {user_id}")));
    assert!(body_str.contains(&format!("session_hash: {}", bearer_session.token_hash)));
    assert!(body_str.contains("session_type: bearer"));

    // 3. Test Invalidated Session returns 401
    state
        .session_service
        .invalidate_session(&raw_cookie_token)
        .await
        .expect("invalidate session");

    let app = test_auth_app(state.clone());
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/me")
        .header(header::COOKIE, format!("sid={raw_cookie_token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 4. Clean up test user and cascading sessions
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn test_csrf_bearer_bypass_fails_downstream_auth_with_invalid_token() {
    let Some((_pool, state)) = setup_live_db().await else {
        if std::env::var_os("CI").is_some() {
            panic!(
                "DATABASE_URL must be set in CI: live require_auth tests must not skip silently"
            );
        }
        println!("Skipping live DB require_auth tests: DATABASE_URL not available");
        return;
    };

    let app = Router::new()
        .route("/api/mutate", post(|| async { "mutated" }))
        .layer(from_fn_with_state(state.clone(), require_auth))
        .layer(from_fn_with_state(state.clone(), csrf_middleware))
        .with_state(state);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/mutate")
        .header(header::AUTHORIZATION, "Bearer invalid_or_garbage_token")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // Passes CSRF check, but fails downstream require_auth with 401 Unauthorized
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(resp.into_body(), 1024).await.unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.code, ErrorCode::SessionNotFound);
}

#[tokio::test]
async fn test_create_router_mounts_security_headers_and_cache_control() {
    let state = dummy_app_state();
    let app = metal_auth::handler::create_router(state).expect("create_router");

    let req = Request::builder()
        .method(Method::POST)
        .uri("/auth/signup")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    let h = resp.headers();
    assert_eq!(
        h.get(header::STRICT_TRANSPORT_SECURITY).unwrap(),
        "max-age=63072000; includeSubDomains; preload"
    );
    assert_eq!(h.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
    assert_eq!(h.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert_eq!(
        h.get(header::CONTENT_SECURITY_POLICY).unwrap(),
        "default-src 'self'"
    );
    assert_eq!(
        h.get(header::REFERRER_POLICY).unwrap(),
        "strict-origin-when-cross-origin"
    );
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(h.get(header::PRAGMA).unwrap(), "no-cache");
}

#[tokio::test]
async fn test_logout_with_session_cookie_requires_csrf() {
    let state = dummy_app_state();
    let app = metal_auth::handler::create_router(state.clone()).expect("create_router");

    // Cookie session without CSRF header must be rejected with 403 CsrfTokenMissing
    let req = Request::builder()
        .method(Method::POST)
        .uri("/auth/logout")
        .header(
            header::COOKIE,
            format!("{}=dummy-session-id", state.config.session.cookie_name),
        )
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(resp.into_body(), 1024).await.unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.code, ErrorCode::CsrfTokenMissing);
}

#[tokio::test]
async fn test_cors_preflight_allows_csrf_token_header() {
    let state = dummy_app_state();
    let app = metal_auth::handler::create_router(state).expect("create_router");

    let req = Request::builder()
        .method(Method::OPTIONS)
        .uri("/auth/logout")
        .header(header::ORIGIN, "https://app.example.com")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .header(
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "x-csrf-token, content-type",
        )
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert!(resp.status().is_success() || resp.status() == StatusCode::NO_CONTENT);

    let h = resp.headers();
    assert_eq!(
        h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
        "https://app.example.com"
    );
    assert_eq!(
        h.get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS).unwrap(),
        "true"
    );

    let allow_headers_raw = h
        .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
        .expect("access-control-allow-headers present")
        .to_str()
        .unwrap();

    let allowed: Vec<String> = allow_headers_raw
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();

    assert!(
        allowed.iter().any(|h| h == "x-csrf-token"),
        "allowed headers must include x-csrf-token"
    );
    assert!(
        allowed.iter().any(|h| h == "content-type"),
        "allowed headers must include content-type"
    );

    assert_eq!(
        h.get(header::STRICT_TRANSPORT_SECURITY).unwrap(),
        "max-age=63072000; includeSubDomains; preload"
    );
    assert_eq!(h.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
    assert_eq!(h.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert_eq!(
        h.get(header::CONTENT_SECURITY_POLICY).unwrap(),
        "default-src 'self'"
    );
    assert_eq!(
        h.get(header::REFERRER_POLICY).unwrap(),
        "strict-origin-when-cross-origin"
    );

    assert!(h.get(header::CACHE_CONTROL).is_none());
    assert!(h.get(header::PRAGMA).is_none());
}

#[tokio::test]
async fn test_exact_path_segment_matching_in_security_headers() {
    let state = dummy_app_state();
    let app = metal_auth::handler::create_router(state).expect("create_router");

    let req_non_auth = Request::builder()
        .method(Method::GET)
        .uri("/authors")
        .body(Body::empty())
        .unwrap();

    let resp_non_auth = app.clone().oneshot(req_non_auth).await.unwrap();
    let h_non_auth = resp_non_auth.headers();
    assert_eq!(
        h_non_auth.get(header::STRICT_TRANSPORT_SECURITY).unwrap(),
        "max-age=63072000; includeSubDomains; preload"
    );
    assert!(
        h_non_auth.get(header::CACHE_CONTROL).is_none(),
        "/authors must not receive Cache-Control: no-store"
    );
    assert!(
        h_non_auth.get(header::PRAGMA).is_none(),
        "/authors must not receive Pragma: no-cache"
    );

    let req_auth = Request::builder()
        .method(Method::POST)
        .uri("/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();

    let resp_auth = app.oneshot(req_auth).await.unwrap();
    let h_auth = resp_auth.headers();
    assert_eq!(
        h_auth.get(header::CACHE_CONTROL).unwrap(),
        "no-store",
        "/auth/login must receive Cache-Control: no-store"
    );
    assert_eq!(
        h_auth.get(header::PRAGMA).unwrap(),
        "no-cache",
        "/auth/login must receive Pragma: no-cache"
    );
}
