use std::str::FromStr;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use chrono::Utc;
use metal_auth::{
    AppError, AppState, Auth, Config, ConfigError, ErrorCode, ErrorResponse, PasswordResetToken,
    Session, User, UserResponse, VerificationToken,
};
use sqlx::PgPool;
use tower::Service;
use uuid::Uuid;

#[tokio::test]
async fn test_auth_facade_and_router_boot() {
    let cfg = Config {
        database_url: "postgres://user:pass@localhost:5432/metal_auth_test".into(),
        port: 8080,
        allowed_origins: vec!["https://app.example.com".into()],
        allowed_methods: vec!["GET".into(), "POST".into(), "OPTIONS".into()],
        allowed_headers: vec!["Authorization".into(), "Content-Type".into()],
        max_connections: 10,
        min_connections: 2,
    };

    let pool = PgPool::connect_lazy(&cfg.database_url).expect("lazy pool creation");
    let state = AppState::new(pool, cfg);
    let mut auth = Auth::from_state(state).unwrap();

    // 1. Unknown route returns 404 with standardized error response envelope
    let req = Request::builder()
        .uri("/unknown-route")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();

    let resp = auth.router.call(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let err_envelope: ErrorResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(err_envelope.code, ErrorCode::NotFound);
    assert_eq!(err_envelope.message, "Not found");

    // 2. Preflight OPTIONS request handled by CORS layer
    let preflight_req = Request::builder()
        .uri("/auth/session")
        .method(Method::OPTIONS)
        .header(header::ORIGIN, "https://app.example.com")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
        .body(Body::empty())
        .unwrap();

    let preflight_resp = auth.router.call(preflight_req).await.unwrap();
    assert_eq!(preflight_resp.status(), StatusCode::OK);
    assert_eq!(
        preflight_resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://app.example.com"
    );
    assert_eq!(
        preflight_resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .unwrap(),
        "true"
    );

    // 3. Denied origin returns no CORS allow header
    let denied_req = Request::builder()
        .uri("/auth/session")
        .method(Method::OPTIONS)
        .header(header::ORIGIN, "https://unauthorized-origin.com")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .body(Body::empty())
        .unwrap();

    let denied_resp = auth.router.call(denied_req).await.unwrap();
    assert!(
        denied_resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );
}

#[tokio::test]
async fn test_auth_new_fails_gracefully_on_invalid_db() {
    let cfg = Config {
        database_url: "postgres://invalid_user:invalid_pass@127.0.0.1:54329/nonexistent".into(),
        port: 3000,
        allowed_origins: vec![],
        allowed_methods: vec!["GET".into()],
        allowed_headers: vec!["Content-Type".into()],
        max_connections: 2,
        min_connections: 1,
    };

    let result = Auth::new(cfg).await;
    assert!(matches!(result, Err(AppError::DatabaseUnavailable(_))));
}

#[test]
fn test_facade_re_exported_models_contract() {
    let now = Utc::now();
    let uid = Uuid::new_v4();

    let user = User {
        id: uid,
        email: "bob@example.com".into(),
        password_hash: "$argon2id$v=19$m=65536,t=3,p=4$dummy".into(),
        email_verified: false,
        created_at: now,
        updated_at: now,
    };

    let resp_dto: UserResponse = (&user).into();
    assert_eq!(resp_dto.id, uid);
    assert_eq!(resp_dto.email, "bob@example.com");
    assert!(!resp_dto.email_verified);

    let session = Session {
        id: Uuid::new_v4(),
        user_id: uid,
        token_hash: "sha256_hash_here".into(),
        expires_at: now,
        idle_expires_at: now,
        created_at: now,
    };
    assert_eq!(session.user_id, uid);

    let v_token = VerificationToken {
        token_hash: vec![0u8; 32],
        user_id: uid,
        expires_at: now,
        created_at: now,
    };
    assert_eq!(v_token.user_id, uid);
    assert_eq!(v_token.token_hash.len(), 32);

    let r_token = PasswordResetToken {
        token_hash: vec![1u8; 32],
        user_id: uid,
        expires_at: now,
        created_at: now,
    };
    assert_eq!(r_token.user_id, uid);
    assert_eq!(r_token.token_hash.len(), 32);
}

#[test]
fn test_facade_re_exported_error_contract() {
    use std::error::Error;

    let not_found = AppError::NotFound;
    let internal = AppError::Internal;

    assert_eq!(not_found.to_string(), "not found");
    assert_eq!(internal.to_string(), "internal error");

    assert_eq!(ErrorCode::NotFound, ErrorCode::NotFound);
    let resp = ErrorResponse {
        code: ErrorCode::NotFound,
        message: "Not found".to_string(),
    };
    assert_eq!(resp.code, ErrorCode::NotFound);

    let cfg_err = ConfigError::MissingEnvVar("DATABASE_URL");
    assert_eq!(
        cfg_err.to_string(),
        "missing environment variable: DATABASE_URL"
    );

    let unicode_err = ConfigError::NonUnicodeEnvVar("DATABASE_URL");
    assert_eq!(
        unicode_err.to_string(),
        "environment variable is not valid unicode: DATABASE_URL"
    );

    let parse_err: Result<u16, _> = "invalid-port".parse();
    let port_err = ConfigError::InvalidPort(parse_err.unwrap_err());
    assert_eq!(port_err.to_string(), "invalid port");
    assert!(port_err.source().is_some());

    let origin_err = ConfigError::InvalidOrigin {
        value: "bad\norigin".to_string(),
        source: axum::http::HeaderValue::from_str("bad\norigin").unwrap_err(),
    };
    assert_eq!(origin_err.to_string(), "invalid CORS origin: bad\norigin");
    assert!(origin_err.source().is_some());

    let method_err = ConfigError::InvalidMethod {
        value: "BAD METHOD".to_string(),
        source: axum::http::Method::from_str("BAD METHOD").unwrap_err(),
    };
    assert_eq!(method_err.to_string(), "invalid CORS method: BAD METHOD");
    assert!(method_err.source().is_some());

    let header_err = ConfigError::InvalidHeader {
        value: "Bad Header".to_string(),
        source: axum::http::header::HeaderName::from_str("Bad Header").unwrap_err(),
    };
    assert_eq!(header_err.to_string(), "invalid CORS header: Bad Header");
    assert!(header_err.source().is_some());

    let app_cfg_err = AppError::Config(ConfigError::MissingEnvVar("DATABASE_URL"));
    assert_eq!(app_cfg_err.to_string(), "configuration error");
    assert!(app_cfg_err.source().is_some());

    let app_db_err = AppError::Database(sqlx::Error::RowNotFound);
    assert_eq!(app_db_err.to_string(), "database error");
    assert!(app_db_err.source().is_some());

    let app_db_unavail = AppError::DatabaseUnavailable(sqlx::Error::PoolTimedOut);
    assert_eq!(app_db_unavail.to_string(), "database unavailable");
    assert!(app_db_unavail.source().is_some());
}

#[tokio::test]
async fn test_auth_boot_fails_fast_on_invalid_cors() {
    let cfg = Config {
        database_url: "postgres://user:pass@localhost:5432/metal_auth_test".into(),
        port: 8080,
        allowed_origins: vec!["invalid\norigin".into()],
        allowed_methods: vec!["GET".into()],
        allowed_headers: vec!["Content-Type".into()],
        max_connections: 10,
        min_connections: 2,
    };

    let pool = PgPool::connect_lazy(&cfg.database_url).expect("lazy pool creation");
    let state = AppState::new(pool, cfg);
    let result = Auth::from_state(state);
    assert!(matches!(
        result,
        Err(AppError::Config(ConfigError::InvalidOrigin { ref value, .. })) if value == "invalid\norigin"
    ));
}

#[tokio::test]
async fn test_auth_new_fails_fast_on_invalid_cors_before_db() {
    let cfg = Config {
        database_url: "not-a-valid-database-url".into(),
        port: 3000,
        allowed_origins: vec!["invalid\norigin".into()],
        allowed_methods: vec!["GET".into()],
        allowed_headers: vec!["Content-Type".into()],
        max_connections: 2,
        min_connections: 1,
    };

    let result = Auth::new(cfg).await;
    assert!(matches!(
        result,
        Err(AppError::Config(ConfigError::InvalidOrigin { ref value, .. })) if value == "invalid\norigin"
    ));
}

#[tokio::test]
async fn test_auth_new_fails_with_database_error_on_malformed_url() {
    let cfg = Config {
        database_url: "not-a-valid-database-url".into(),
        port: 3000,
        allowed_origins: vec![],
        allowed_methods: vec!["GET".into()],
        allowed_headers: vec!["Content-Type".into()],
        max_connections: 2,
        min_connections: 1,
    };

    let result = Auth::new(cfg).await;
    assert!(matches!(result, Err(AppError::Database(_))));
}
