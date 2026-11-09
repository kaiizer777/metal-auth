use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use chrono::Utc;
use metal_auth::{
    AppError, AppState, Auth, Config, PasswordResetToken, Session, User, UserResponse,
    VerificationToken,
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
    let mut auth = Auth::from_state(state);

    // 1. Unknown route returns 404
    let req = Request::builder()
        .uri("/unknown-route")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();

    let resp = auth.router.call(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

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
    assert!(denied_resp
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());
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
    assert!(result.is_err());
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
        id: Uuid::new_v4(),
        user_id: uid,
        token_hash: "v_token_hash".into(),
        expires_at: now,
        used: false,
        created_at: now,
    };
    assert!(!v_token.used);

    let r_token = PasswordResetToken {
        id: Uuid::new_v4(),
        user_id: uid,
        token_hash: "r_token_hash".into(),
        expires_at: now,
        used: false,
        created_at: now,
    };
    assert!(!r_token.used);
}

#[test]
fn test_facade_re_exported_error_contract() {
    let not_found = AppError::NotFound;
    let internal = AppError::Internal("test reason".into());

    assert_eq!(not_found.to_string(), "not found");
    assert_eq!(internal.to_string(), "internal error");
}
