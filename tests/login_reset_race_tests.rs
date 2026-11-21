//! Regression tests for issue #37: in-flight login must not mint an active
//! session after a concurrent password reset.
//!
//! Deterministic interleaving: complete the credential check, commit a reset,
//! then attempt session creation. Pre-fix this leaves a live session behind.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
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
        oauth: metal_auth::OAuthConfig::default(),
        totp: metal_auth::TotpConfig::default(),
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

async fn reset_token_count(pool: &sqlx::PgPool, user_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

struct HttpOutcome {
    status: StatusCode,
    set_cookies: Vec<String>,
    code: Option<String>,
}

async fn dispatch(router: &axum::Router, req: Request<Body>) -> HttpOutcome {
    let resp = router.clone().oneshot(req).await.expect("router dispatch");
    let status = resp.status();
    let set_cookies = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_owned))
        .collect();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    let code = json.get("code").and_then(|c| c.as_str()).map(str::to_owned);
    HttpOutcome {
        status,
        set_cookies,
        code,
    }
}

fn session_cookie(outcome: &HttpOutcome, name: &str) -> Option<String> {
    outcome.set_cookies.iter().find_map(|h| {
        let (k, v) = h.split(';').next()?.trim().split_once('=')?;
        (k == name).then(|| v.to_owned())
    })
}

fn authed_get(uri: &str, cookie_name: &str, raw: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::COOKIE, format!("{cookie_name}={raw}"))
        .body(Body::empty())
        .unwrap()
}

struct RaceFixture {
    email: String,
    old_pw: String,
    new_pw: String,
    user_id: Uuid,
    raw_token: String,
}

async fn signup_verify_and_issue_token(router: &axum::Router, pool: &sqlx::PgPool) -> RaceFixture {
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
        .fetch_one(pool)
        .await
        .unwrap()
        .get("id");
    sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .unwrap();

    let (raw_token, token_hash) = generate_token();
    sqlx::query(
        "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(token_hash.as_slice())
    .bind(user_id)
    .bind(Utc::now() + Duration::hours(1))
    .execute(pool)
    .await
    .unwrap();

    RaceFixture {
        email,
        old_pw,
        new_pw,
        user_id,
        raw_token,
    }
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

#[tokio::test]
async fn stale_credential_http_login_rejected_and_cookie_purged() {
    let Some((router, pool, state)) = setup_live_db().await else {
        return;
    };
    let fix = signup_verify_and_issue_token(&router, &pool).await;
    let cookie_name = state.config.session.cookie_name.clone();

    // Baseline: old credential logs in over HTTP; the cookie opens the session endpoint.
    let login = dispatch(
        &router,
        json_request(
            Method::POST,
            "/auth/login",
            json!({"email": fix.email, "password": fix.old_pw}),
        ),
    )
    .await;
    assert_eq!(login.status, StatusCode::OK);
    let raw = session_cookie(&login, &cookie_name).expect("login mints a session cookie");
    assert_eq!(
        dispatch(&router, authed_get("/auth/session/me", &cookie_name, &raw))
            .await
            .status,
        StatusCode::OK
    );

    // Reset commits: new hash stored, all sessions and tokens purged.
    state
        .auth_service
        .reset_password(&fix.raw_token, &fix.new_pw)
        .await
        .expect("reset commits");

    // Stale credential over HTTP: 401 with no replacement cookie and no new session row.
    // Verify precedes the session gate in the handler, so a superseded password
    // surfaces as INVALID_CREDENTIALS; SESSION_INVALID is unreachable by sequencing.
    let stale = dispatch(
        &router,
        json_request(
            Method::POST,
            "/auth/login",
            json!({"email": fix.email, "password": fix.old_pw}),
        ),
    )
    .await;
    assert_eq!(stale.status, StatusCode::UNAUTHORIZED);
    assert!(
        stale.set_cookies.is_empty(),
        "rejected login must not mint a session"
    );
    assert_eq!(stale.code.as_deref(), Some("INVALID_CREDENTIALS"));

    // Pre-reset cookie is dead: the purged row surfaces as SESSION_NOT_FOUND.
    let dead = dispatch(&router, authed_get("/auth/session/me", &cookie_name, &raw)).await;
    assert_eq!(dead.status, StatusCode::UNAUTHORIZED);
    assert_eq!(dead.code.as_deref(), Some("SESSION_NOT_FOUND"));

    // Purge observed at the row level.
    assert_eq!(active_session_count(&pool, fix.user_id).await, 0);
    assert_eq!(reset_token_count(&pool, fix.user_id).await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_login_vs_reset_leaves_no_live_session() {
    let Some((router, pool, state)) = setup_live_db().await else {
        return;
    };
    let fix = signup_verify_and_issue_token(&router, &pool).await;

    // Four tasks (3 logins + 1 reset) stay under the 5-connection pool budget.
    let barrier = Arc::new(tokio::sync::Barrier::new(4));
    let mut logins = Vec::new();
    for _ in 0..3 {
        let router = router.clone();
        let barrier = Arc::clone(&barrier);
        let (email, password) = (fix.email.clone(), fix.old_pw.clone());
        logins.push(tokio::spawn(async move {
            barrier.wait().await;
            dispatch(
                &router,
                json_request(
                    Method::POST,
                    "/auth/login",
                    json!({"email": email, "password": password}),
                ),
            )
            .await
        }));
    }
    let reset_state = state.clone();
    let reset_barrier = Arc::clone(&barrier);
    let (token, new_pw) = (fix.raw_token.clone(), fix.new_pw.clone());
    let reset = tokio::spawn(async move {
        reset_barrier.wait().await;
        reset_state
            .auth_service
            .reset_password(&token, &new_pw)
            .await
    });

    reset
        .await
        .expect("reset task joins")
        .expect("reset commits");

    let cookie_name = state.config.session.cookie_name.clone();
    let mut issued = Vec::new();
    for handle in logins {
        let out = handle.await.expect("login task joins");
        assert!(
            out.status == StatusCode::OK || out.status == StatusCode::UNAUTHORIZED,
            "unexpected login status {}",
            out.status
        );
        if out.status == StatusCode::OK {
            issued.push(session_cookie(&out, &cookie_name).expect("200 carries a session cookie"));
        } else {
            assert!(
                out.set_cookies.is_empty(),
                "rejected login must not mint a session"
            );
            // Verify-after-reset fails the password; verify-before-reset
            // is rejected by the session gate. No other code is acceptable.
            assert!(
                out.code.as_deref() == Some("INVALID_CREDENTIALS")
                    || out.code.as_deref() == Some("SESSION_INVALID"),
                "unexpected error code {:?}",
                out.code
            );
        }
    }

    // Every pre-reset mint was purged: no issued cookie opens a session.
    for raw in &issued {
        assert_eq!(
            dispatch(&router, authed_get("/auth/session/me", &cookie_name, raw))
                .await
                .status,
            StatusCode::UNAUTHORIZED,
            "superseded session survived the reset purge"
        );
    }
    assert_eq!(active_session_count(&pool, fix.user_id).await, 0);
    assert_eq!(reset_token_count(&pool, fix.user_id).await, 0);
}
