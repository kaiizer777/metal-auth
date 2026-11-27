#![cfg(feature = "mysql")]

mod common;

use std::time::Duration;

use chrono::Utc;
use common::setup_mysql_test_app;
use metal_auth::{
    AppError, DatabaseBackend, DatabaseStore, MySqlStore,
    db::{DbPoolOptions, init_mysql_pool_with_options},
};
use sqlx::MySqlPool;
use uuid::Uuid;

async fn get_test_mysql_pool() -> Option<MySqlPool> {
    dotenvy::dotenv().ok();
    let url = std::env::var("MYSQL_DATABASE_URL")
        .or_else(|_| std::env::var("MYSQL_URL"))
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()?;
    if !url.starts_with("mysql://") {
        return None;
    }
    let opts = DbPoolOptions {
        max_connections: 10,
        min_connections: 1,
        acquire_timeout: Duration::from_secs(3),
        max_retries: 1,
        ..Default::default()
    };
    init_mysql_pool_with_options(&url, opts).await.ok()
}

#[tokio::test]
async fn test_mysql_complete_auth_journey() {
    let Some(pool) = get_test_mysql_pool().await else {
        eprintln!("skipping test_mysql_complete_auth_journey: MYSQL_DATABASE_URL not set");
        return;
    };
    let store = MySqlStore::new(pool);
    assert_eq!(store.backend(), DatabaseBackend::Mysql);

    let email = format!("mysql_journey_{}@example.com", Uuid::new_v4());
    let initial_hash = "$argon2id$v=19$m=19456,t=2,p=1$fake_hash_init";
    let updated_hash = "$argon2id$v=19$m=19456,t=2,p=1$fake_hash_new";

    // ── 1. Signup ─────────────────────────────────────────────────────────────
    let user = store
        .users()
        .create_user(&email, initial_hash)
        .await
        .expect("signup: create user");
    assert_eq!(user.email, email);
    assert!(!user.email_verified);

    // Queue verification email into outbox
    let outbox = store
        .outbox()
        .insert_outbox(
            &email,
            "verification",
            serde_json::json!({"action": "verify", "user_id": user.id}),
        )
        .await
        .expect("signup: queue outbox verification email");
    assert_eq!(outbox.recipient, email);
    assert_eq!(outbox.status, "pending");

    // Mint verification token
    let v_token_hash = [11u8; 32];
    let v_expiry = Utc::now() + chrono::Duration::hours(24);
    store
        .tokens()
        .create_verification_token(user.id, &v_token_hash, v_expiry)
        .await
        .expect("signup: mint verification token");

    // ── 2. Email Verification ────────────────────────────────────────────────
    let claimed_batch = store
        .outbox()
        .claim_pending_outbox(10, Duration::from_secs(60))
        .await
        .expect("verify: claim outbox");
    assert!(claimed_batch.iter().any(|item| item.id == outbox.id));

    store
        .outbox()
        .mark_outbox_sent(outbox.id)
        .await
        .expect("verify: mark outbox sent");

    let consumed_vtoken = store
        .tokens()
        .consume_verification_token(&v_token_hash)
        .await
        .expect("verify: consume verification token")
        .expect("verification token must exist");
    assert_eq!(consumed_vtoken.user_id, user.id);

    // Single-use guarantee: replaying verification token returns None
    let replay_vtoken = store
        .tokens()
        .consume_verification_token(&v_token_hash)
        .await
        .expect("verify: re-consume verification token");
    assert!(replay_vtoken.is_none());

    store
        .users()
        .set_email_verified(user.id, true)
        .await
        .expect("verify: mark user email_verified");

    let verified_user = store
        .users()
        .get_user_by_id(user.id)
        .await
        .expect("verify: fetch user")
        .expect("user exists");
    assert!(verified_user.email_verified);

    // ── 3. Login & Session Lifecycle ─────────────────────────────────────────
    let sess_token_hash_1 = format!("sess_1_{}", Uuid::new_v4());
    let session = store
        .sessions()
        .create_session(
            user.id,
            &sess_token_hash_1,
            "cookie",
            Some("csrf_initial"),
            Utc::now() + chrono::Duration::hours(2),
        )
        .await
        .expect("login: create session");
    assert_eq!(session.user_id, user.id);

    // Inspect session
    let inspected = store
        .sessions()
        .get_session_by_token_hash(&sess_token_hash_1)
        .await
        .expect("session: inspect session")
        .expect("session present");
    assert_eq!(inspected.id, session.id);

    // Touch session
    store
        .sessions()
        .touch_session(session.id, Utc::now())
        .await
        .expect("session: touch session");

    // Rotate session token
    let sess_token_hash_2 = format!("sess_2_{}", Uuid::new_v4());
    store
        .sessions()
        .rotate_session(
            session.id,
            &sess_token_hash_2,
            Some("csrf_rotated"),
            Utc::now(),
        )
        .await
        .expect("session: rotate token");

    assert!(
        store
            .sessions()
            .get_session_by_token_hash(&sess_token_hash_1)
            .await
            .unwrap()
            .is_none()
    );
    let rotated = store
        .sessions()
        .get_session_by_token_hash(&sess_token_hash_2)
        .await
        .unwrap()
        .expect("rotated session exists");
    assert_eq!(rotated.csrf_token.as_deref(), Some("csrf_rotated"));

    // ── 4. TOTP Enrollment & Confirmation ────────────────────────────────────
    let encrypted_secret = vec![10, 20, 30, 40, 50];
    let backup_codes = serde_json::json!(["bc_code_1", "bc_code_2"]);

    let totp_doc = store
        .totp()
        .upsert_secret(user.id, &encrypted_secret, backup_codes)
        .await
        .expect("totp: enroll secret");
    assert!(!totp_doc.enabled);

    store
        .totp()
        .enable_totp(user.id)
        .await
        .expect("totp: confirm and enable");

    let enabled_secret = store
        .totp()
        .get_secret(user.id)
        .await
        .expect("totp: get secret")
        .expect("secret exists");
    assert!(enabled_secret.enabled);

    // ── 5. 2FA Challenge & TOTP Code Verification ───────────────────────────
    let challenge_hash = [22u8; 32];
    store
        .totp()
        .create_two_factor_token(
            user.id,
            &challenge_hash,
            "credential_binding_hash",
            Utc::now() + chrono::Duration::minutes(5),
        )
        .await
        .expect("2fa: create challenge token");

    // Verify TOTP code and record used
    let used_code_hash = [33u8; 32];
    let recorded = store
        .totp()
        .record_used_code(user.id, &used_code_hash)
        .await
        .expect("2fa: record used code");
    assert!(recorded);

    // Single-use code protection: duplicate submission fails with TotpCodeReplayed
    let replay_err = store
        .totp()
        .record_used_code(user.id, &used_code_hash)
        .await
        .unwrap_err();
    assert!(matches!(replay_err, AppError::TotpCodeReplayed));

    // Consume challenge token
    let challenge_redeemed = store
        .totp()
        .consume_two_factor_token(&challenge_hash)
        .await
        .expect("2fa: consume challenge token")
        .expect("challenge token must be present");
    assert_eq!(challenge_redeemed.user_id, user.id);

    // Replay challenge token fails
    assert!(
        store
            .totp()
            .consume_two_factor_token(&challenge_hash)
            .await
            .unwrap()
            .is_none()
    );

    // ── 6. Password Reset Flow (Revokes Sessions & In-Flight Tokens) ─────────
    let reset_token_hash = [44u8; 32];
    store
        .tokens()
        .create_password_reset_token(
            user.id,
            &reset_token_hash,
            Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .expect("reset: mint password reset token");

    let consumed_reset = store
        .tokens()
        .consume_password_reset_token(&reset_token_hash)
        .await
        .expect("reset: consume reset token")
        .expect("reset token present");
    assert_eq!(consumed_reset.user_id, user.id);

    // Update password hash
    store
        .users()
        .update_password_hash(user.id, updated_hash)
        .await
        .expect("reset: update password hash");

    // Revoke all active sessions upon password reset
    let revoked_sessions = store
        .sessions()
        .delete_user_sessions(user.id)
        .await
        .expect("reset: delete user sessions");
    assert!(revoked_sessions >= 1);

    // Delete remaining password reset tokens
    store
        .tokens()
        .delete_user_password_reset_tokens(user.id)
        .await
        .expect("reset: delete pending reset tokens");

    // Verify session revoked
    let active_sessions = store
        .sessions()
        .list_user_sessions(user.id)
        .await
        .expect("reset: list sessions");
    assert_eq!(active_sessions.len(), 0);

    // ── 7. Teardown / User Cascade Deletion ──────────────────────────────────
    let deleted = store
        .users()
        .delete_user(user.id)
        .await
        .expect("teardown: delete user");
    assert!(deleted);
    assert!(
        store
            .users()
            .get_user_by_id(user.id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_mysql_http_and_service_journey() {
    let Some(app) = setup_mysql_test_app().await else {
        eprintln!("skipping test_mysql_http_and_service_journey: MYSQL_DATABASE_URL not set");
        return;
    };

    // 1. Backend routing verification
    assert_eq!(app.state.store().backend(), DatabaseBackend::Mysql);

    // 2. HTTP layer functionality
    // 2a. Unauthenticated logout returns 204 No Content
    let resp = app.post_empty("/auth/logout").await;
    assert_eq!(resp.status(), axum::http::StatusCode::NO_CONTENT);

    // 2b. Malformed signup returns 400 Bad Request with InvalidEmail
    let resp = app
        .post_json(
            "/auth/signup",
            serde_json::json!({
                "email": "not-an-email",
                "password": "short"
            }),
        )
        .await;
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(resp.error_code(), Some(metal_auth::ErrorCode::InvalidEmail));

    // 2c. CORS preflight OPTIONS /auth/login
    let req = axum::http::Request::builder()
        .method(axum::http::Method::OPTIONS)
        .uri("/auth/login")
        .header(axum::http::header::ORIGIN, "https://app.example.com")
        .header(axum::http::header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .body(axum::body::Body::empty())
        .expect("build cors options request");
    let resp = app.dispatch(req).await;
    assert!(resp.status().is_success());
    assert_eq!(
        resp.header("access-control-allow-origin"),
        Some("https://app.example.com")
    );

    // 2d. Fallback 404 Not Found
    let req = axum::http::Request::builder()
        .method(axum::http::Method::GET)
        .uri("/nonexistent_route_404")
        .body(axum::body::Body::empty())
        .expect("build 404 request");
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);

    // 3. Outbox service integration
    let store = app.state.store();
    let email = format!("mysql_outbox_{}@example.com", Uuid::new_v4());
    let outbox_entry = store
        .outbox()
        .insert_outbox(
            &email,
            "verification",
            serde_json::json!({"action": "verify", "email": email}),
        )
        .await
        .expect("insert outbox entry in mysql store");
    assert_eq!(outbox_entry.recipient, email);

    // Flush through dispatcher
    if let Some(dispatcher) = app.state.email_dispatcher.as_ref() {
        let flushed = dispatcher
            .flush_outbox()
            .await
            .expect("flush outbox via dispatcher");
        assert!(flushed >= 1);
        let calls = app.email_sender.verification_calls();
        assert!(calls.iter().any(|c| c.to == email));
    }
}
