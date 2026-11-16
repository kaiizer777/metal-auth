//! Regression tests for issue #37: in-flight login must not mint an active
//! session after a concurrent password reset.
//!
//! Deterministic interleaving: complete the credential check, commit a reset,
//! then attempt session creation. Pre-fix this leaves a live session behind.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use chrono::{Duration, Utc};
use metal_auth::{
    AppError, AppState, Config, crypto::token::generate_token, handler::create_router,
};
use serde_json::json;
use sqlx::Row;
use tower::ServiceExt;
use uuid::Uuid;

async fn setup_live_db() -> Option<(axum::Router, sqlx::PgPool, AppState)> {
    dotenvy::dotenv().ok();
    let url = match std::env::var("DATABASE_URL") {
        Ok(val) => val,
        Err(_) => {
            assert!(
                std::env::var_os("CI").is_none(),
                "DATABASE_URL must be set in CI: DB-backed tests must never skip silently"
            );
            eprintln!("SKIP: live-DB race tests need DATABASE_URL");
            return None;
        }
    };
    let pool = metal_auth::db::init_pool_with_options(
        &url,
        metal_auth::db::DbPoolOptions {
            max_connections: 5,
            min_connections: 1,
            ..Default::default()
        },
    )
    .await
    .expect("DATABASE_URL is set, so the DB-backed test must connect");
    let cfg = Config {
        database_url: url.clone(),
        port: 8080,
        allowed_origins: vec!["https://app.example.com".into()],
        allowed_methods: vec!["GET".into(), "POST".into()],
        allowed_headers: vec!["Authorization".into(), "Content-Type".into()],
        max_connections: 5,
        min_connections: 1,
        base_url: "https://example.com".into(),
        email_dispatch_timeout: std::time::Duration::from_secs(10),
        async_email_dispatch: true,
        outbox_poll_interval: std::time::Duration::from_millis(50),
        outbox_batch_size: 50,
        outbox_max_retries: 5,
        outbox_initial_backoff: std::time::Duration::from_secs(1),
        outbox_max_backoff: std::time::Duration::from_secs(300),
        outbox_sent_retention: std::time::Duration::from_secs(7 * 24 * 3600),
        session: metal_auth::SessionConfig::default(),
        rate_limit: metal_auth::RateLimitConfig::default(),
    };
    let state = AppState::new(pool.clone(), cfg).expect("failed to create app state");
    let router = create_router(state.clone()).expect("failed to create router");
    Some((router, pool, state))
}

fn json_request(method: Method, uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

async fn active_session_count(pool: &sqlx::PgPool, user_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn in_flight_login_leaves_no_session_after_concurrent_reset() {
    let Some((router, pool, state)) = setup_live_db().await else {
        return;
    };

    let email = format!("race_{}@example.com", Uuid::new_v4());
    let old_pw = format!("OldSecret_{}_P@ssw0rd!", Uuid::new_v4());
    let new_pw = format!("NewSecret_{}_P@ssw0rd!", Uuid::new_v4());

    let signup = json_request(
        Method::POST,
        "/auth/signup",
        json!({"email": email, "password": old_pw}),
    );
    assert_eq!(
        router.clone().oneshot(signup).await.unwrap().status(),
        StatusCode::OK
    );

    let user_id: Uuid = sqlx::query("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("id");
    sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    let (raw_token, token_hash) = generate_token();
    sqlx::query(
        "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(token_hash.as_slice())
    .bind(user_id)
    .bind(Utc::now() + Duration::hours(1))
    .execute(&pool)
    .await
    .unwrap();

    // In-flight login: credential check passes against the pre-reset hash.
    let proof = state
        .auth_service
        .login_with_proof(&email, &old_pw)
        .await
        .expect("old password verifies before reset");

    // Concurrent reset commits: new hash stored, all sessions purged.
    state
        .auth_service
        .reset_password(&raw_token, &new_pw)
        .await
        .expect("reset commits");

    // Stale credential must no longer verify anywhere.
    assert!(matches!(
        state.auth_service.login(&email, &old_pw).await,
        Err(AppError::InvalidCredentials)
    ));

    // The in-flight login resumes: gated session creation rejects the
    // superseded proof as an invalidated session, distinct from a bad password.
    assert!(matches!(
        state
            .session_service
            .create_session_checked(proof.user_id, &proof.credential_hash, "cookie", None, None)
            .await,
        Err(AppError::SessionInvalid)
    ));

    // Invariant: no live session authorized by the superseded credential.
    assert_eq!(
        active_session_count(&pool, user_id).await,
        0,
        "concurrent reset must invalidate the in-flight login: stale session created"
    );

    // Fresh login under the new password still mints exactly one session.
    let fresh = state
        .auth_service
        .login_with_proof(&email, &new_pw)
        .await
        .expect("new password verifies after reset");
    state
        .session_service
        .create_session_checked(fresh.user_id, &fresh.credential_hash, "cookie", None, None)
        .await
        .expect("fresh credential mints a session");
    assert_eq!(active_session_count(&pool, user_id).await, 1);
}
