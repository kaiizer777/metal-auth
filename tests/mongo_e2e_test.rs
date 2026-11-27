#![cfg(feature = "mongodb")]

mod common;

use std::time::Duration;

use chrono::Utc;
use common::setup_mongo_test_app;
use metal_auth::{
    AppError, DatabaseBackend, DatabaseStore, MongoStore, db::mongo::indexes::ensure_indexes,
};
use mongodb::{Client, bson::doc};
use uuid::Uuid;

async fn get_test_mongo_store() -> Option<common::MongoTestFixture> {
    dotenvy::dotenv().ok();
    let url = std::env::var("MONGODB_URI")
        .or_else(|_| std::env::var("MONGODB_URL"))
        .or_else(|_| std::env::var("MONGO_URL"))
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()?;
    if !url.starts_with("mongodb://") && !url.starts_with("mongodb+srv://") {
        return None;
    }
    let db_name = common::mongo_test_database_name();
    let allow_standalone = std::env::var("MONGO_ALLOW_NON_TRANSACTIONAL_STANDALONE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let mut client_options = mongodb::options::ClientOptions::parse(&url).await.ok()?;
    client_options.connect_timeout = Some(Duration::from_secs(3));
    client_options.server_selection_timeout = Some(Duration::from_secs(3));
    let client = Client::with_options(client_options).ok()?;
    let db = client.database(&db_name);
    db.run_command(doc! { "ping": 1 }).await.ok()?;

    let hello_doc = db.run_command(doc! { "hello": 1 }).await.ok()?;
    let is_replica_set = hello_doc.contains_key("setName")
        || hello_doc
            .get_str("msg")
            .map(|m| m == "isdbgrid")
            .unwrap_or(false);

    ensure_indexes(&db)
        .await
        .expect("Failed to create mongo indexes for mongo e2e test store");

    let store = MongoStore::new(client.clone(), &db_name, is_replica_set, allow_standalone);
    let guard = common::MongoTestGuard::new(client, db_name);
    Some(common::MongoTestFixture::new(store, guard))
}

#[tokio::test]
async fn test_mongo_complete_auth_journey() {
    let Some(fixture) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_complete_auth_journey: MONGODB_URI not set");
        return;
    };
    let store = &fixture.store;
    assert_eq!(store.backend(), DatabaseBackend::Mongodb);

    let email = format!("mongo_journey_{}@example.com", Uuid::new_v4());
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

    // Drop isolated test database
    fixture.teardown().await;
}

#[tokio::test]
async fn test_mongo_http_and_service_journey() {
    let Some(app) = setup_mongo_test_app().await else {
        eprintln!("skipping test_mongo_http_and_service_journey: MONGODB_URI not set");
        return;
    };

    // 1. Backend routing verification
    assert_eq!(app.state.store().backend(), DatabaseBackend::Mongodb);

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
    let email = format!("mongo_outbox_{}@example.com", Uuid::new_v4());
    let payload = serde_json::json!({
        "user_id": Uuid::new_v4(),
        "to": email,
        "token": "tok123",
        "url": "https://example.com/verify?token=tok123",
        "expires_at": Utc::now() + chrono::Duration::hours(24),
    });
    let outbox_entry = store
        .outbox()
        .insert_outbox(&email, "verification", payload)
        .await
        .expect("insert outbox entry in mongo store");
    assert_eq!(outbox_entry.recipient, email);

    // Flush through dispatcher
    if let Some(dispatcher) = app.state.email_dispatcher.as_ref() {
        let flushed = dispatcher
            .flush_outbox()
            .await
            .expect("flush outbox via dispatcher");
        assert!(flushed >= 1);
        let mut delivered = false;
        for _ in 0..20 {
            let calls = app.email_sender.verification_calls();
            if calls.iter().any(|c| c.to == email) {
                delivered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            delivered,
            "verification email delivery recorded for {email}"
        );
    }

    // Explicit teardown of the test database created by setup_mongo_test_app
    app.teardown_mongo().await;
}

#[test]
fn test_mongo_database_name_bounded_and_sanitized() {
    // 1. Long name bounded to at most 30 characters before suffix
    let long_base = "a".repeat(100);
    let bounded = common::sanitize_and_bound_mongo_db_name(&long_base);
    assert_eq!(bounded.len(), 30);
    assert_eq!(bounded, "a".repeat(30));

    // 2. Full generated database name is strictly <= 63 bytes
    let db_name = common::mongo_test_database_name();
    assert!(
        db_name.len() <= 63,
        "database name exceeds 63 bytes: {} (len {})",
        db_name,
        db_name.len()
    );

    // 3. Characters forbidden by MongoDB are stripped
    let dirty_base = "test/db.with$invalid:chars*?\\\" ";
    let clean = common::sanitize_and_bound_mongo_db_name(dirty_base);
    assert!(!clean.contains('/'));
    assert!(!clean.contains('\\'));
    assert!(!clean.contains('.'));
    assert!(!clean.contains('"'));
    assert!(!clean.contains('*'));
    assert!(!clean.contains(':'));
    assert!(!clean.contains('?'));
    assert!(!clean.contains('$'));
    assert!(!clean.contains(' '));

    // 4. Empty base defaults to fallback
    let empty = common::sanitize_and_bound_mongo_db_name("");
    assert_eq!(empty, "metal_auth_test");

    // 5. Multi-byte UTF-8 strings do not panic, truncate at valid char boundaries <= 30 bytes,
    // and keep total database name length strictly <= 63 bytes with the 33-byte UUID suffix.
    let multibyte_emoji = "🦀".repeat(20);
    let bounded_emoji = common::sanitize_and_bound_mongo_db_name(&multibyte_emoji);
    assert!(bounded_emoji.len() <= 30);
    assert_eq!(bounded_emoji, "🦀".repeat(7)); // 7 * 4 = 28 bytes <= 30
    assert_eq!(bounded_emoji.len(), 28);

    let cjk_base = "データベース名_日本語_テスト";
    let bounded_cjk = common::sanitize_and_bound_mongo_db_name(cjk_base);
    assert!(bounded_cjk.len() <= 30);
    assert_eq!(bounded_cjk, "データベース名_日本"); // Truncates cleanly before 語 at byte 28
    assert_eq!(bounded_cjk.len(), 28);

    let mixed_base = "🦀_auth_db_日本語_test_database_name_exceeding_length";
    let bounded_mixed = common::sanitize_and_bound_mongo_db_name(mixed_base);
    assert!(bounded_mixed.len() <= 30);

    let full_name = format!("{}_{}", bounded_mixed, Uuid::new_v4().simple());
    assert!(
        full_name.len() <= 63,
        "database name exceeds 63 bytes: {} (len {})",
        full_name,
        full_name.len()
    );
}
