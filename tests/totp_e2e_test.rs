//! End-to-end TOTP journeys against real PostgreSQL.
//!
//! Each journey drives the public HTTP surface only and asserts identity through the
//! `sessions.user_id` row: `GET /auth/session` never exposes the user id.

mod common;

use axum::http::{HeaderMap, Method, StatusCode, header};
use common::*;
use metal_auth::ErrorCode;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Token hashes of every session the user currently owns.
async fn session_token_hashes(pool: &PgPool, user_id: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT token_hash FROM sessions WHERE user_id = $1 ORDER BY created_at")
        .bind(user_id)
        .fetch_all(pool)
        .await
        .expect("list the journey user's sessions")
}

/// Token hash of the journey user's only session, for tying an HTTP response to a user row.
async fn only_session_token_hash(pool: &PgPool, user_id: Uuid) -> String {
    let mut hashes = session_token_hashes(pool, user_id).await;
    assert_eq!(
        hashes.len(),
        1,
        "expected exactly one session for the journey user"
    );
    hashes.pop().expect("one session")
}

/// Stored Argon2id PHC strings behind the enroll response's backup codes.
async fn stored_backup_hashes(pool: &PgPool, user_id: Uuid) -> Vec<String> {
    let value: serde_json::Value =
        sqlx::query_scalar("SELECT backup_codes FROM totp_secrets WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .expect("totp_secrets row for the journey user");
    serde_json::from_value(value).expect("backup_codes is a JSON array of strings")
}

fn cookie_header(app: &TestApp, sid: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("{}={sid}", app.state.config.session.cookie_name)
            .parse()
            .expect("cookie header"),
    );
    headers
}

#[tokio::test]
async fn journey_1_enroll_then_verify_2fa_and_reach_a_protected_route() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    let ip = dynamic_ip();

    // Signup -> verify email -> login without a second factor.
    let (email, password) = create_verified_user(&app).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let enroll_session = login(&app, &email, &password).await;

    // Enroll and confirm with a code derived from the returned secret.
    let enrollment = enroll(&app, &enroll_session, &ip).await;
    let secret = enrollment["secret_base32"]
        .as_str()
        .expect("secret_base32")
        .to_string();
    let confirm_resp = confirm(&app, &enroll_session, &secret, &ip).await;
    assert_eq!(
        confirm_resp.status(),
        StatusCode::OK,
        "confirm failed: {}",
        confirm_resp.body_str
    );

    // Logout drops the session server-side, not just the cookie.
    let logout = app
        .dispatch(session_request(
            &app,
            Method::POST,
            "/auth/logout",
            json!({}),
            &enroll_session,
            &ip,
        ))
        .await;
    assert_eq!(
        logout.status(),
        StatusCode::NO_CONTENT,
        "logout failed: {}",
        logout.body_str
    );
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        0,
        "logout must invalidate the session row"
    );

    // The next password login yields a challenge, not a session.
    let challenge_token = challenge(&app, &email, &password).await;

    let verified = app
        .post_json(
            "/auth/totp/verify",
            json!({ "challenge_token": challenge_token, "code": totp_code(&secret) }),
        )
        .await;
    assert_eq!(
        verified.status(),
        StatusCode::OK,
        "verify failed: {}",
        verified.body_str
    );
    assert!(
        verified.json.get("two_factor_required").is_none(),
        "verify must answer with a session, not another challenge"
    );

    let sid = extract_cookie_val(&verified.headers, &app.state.config.session.cookie_name)
        .expect("verify must set the session cookie");
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        1,
        "verify must issue exactly one session for the same user"
    );

    // The protected route must resolve to that same user's session row.
    let session_resp = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            cookie_header(&app, &sid),
        ))
        .await;
    assert_eq!(
        session_resp.status(),
        StatusCode::OK,
        "session lookup failed: {}",
        session_resp.body_str
    );
    assert_eq!(
        session_resp.json["session_id"],
        json!(only_session_token_hash(&app.pool, user_id).await),
        "the authenticated session must belong to the signed-up user"
    );
}

#[tokio::test]
async fn journey_2_backup_code_login_purges_the_used_hash() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    let ip = dynamic_ip();

    let (email, password, _secret, backup_codes, _enroll_session) = enabled_user(&app, &ip).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    assert_eq!(backup_codes.len(), 10);
    let used_code = backup_codes[0].clone();
    let before = stored_backup_hashes(&app.pool, user_id).await;
    assert_eq!(before.len(), 10, "enrollment must store ten hashes");
    let used_index = metal_auth::totp::backup::verify_backup_code(&used_code, &before)
        .expect("the used code must match exactly one stored hash");

    let sessions_before = count_sessions_for_user(&app.pool, user_id).await;
    let challenge_token = challenge(&app, &email, &password).await;
    let resp = app
        .post_json(
            "/auth/totp/backup",
            json!({ "challenge_token": challenge_token, "code": used_code.clone() }),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "backup login failed: {}",
        resp.body_str
    );
    let sid = extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name)
        .expect("backup login must set the session cookie");
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        sessions_before + 1,
        "backup login must issue exactly one session"
    );

    let session_resp = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            cookie_header(&app, &sid),
        ))
        .await;
    assert_eq!(
        session_resp.status(),
        StatusCode::OK,
        "session lookup failed: {}",
        session_resp.body_str
    );
    let issued_hash = session_resp.json["session_id"]
        .as_str()
        .expect("session id")
        .to_string();
    assert!(
        session_token_hashes(&app.pool, user_id)
            .await
            .contains(&issued_hash),
        "the backup-issued session must belong to the same user"
    );

    // The index of the used code is knowable: verification is public and pure. The service
    // purges by value with a JSONB array delete, which preserves order, so the expected
    // array is `before` minus that one entry.
    let mut expected = before;
    expected.remove(used_index);

    let remaining = stored_backup_hashes(&app.pool, user_id).await;
    assert_eq!(
        remaining, expected,
        "exactly the hash matching the used code must be purged"
    );
    assert!(
        remaining.iter().all(|hash| hash.starts_with("$argon2id$")),
        "the remaining nine hashes must stay intact: {remaining:?}"
    );

    // Functional proof that the consumed hash is gone: the same code cannot log in again.
    let challenge_token = challenge(&app, &email, &password).await;
    let reuse = app
        .post_json(
            "/auth/totp/backup",
            json!({ "challenge_token": challenge_token, "code": used_code }),
        )
        .await;
    assert_eq!(
        reuse.status(),
        StatusCode::BAD_REQUEST,
        "reusing a consumed backup code must fail: {}",
        reuse.body_str
    );
    assert_eq!(reuse.error_code(), Some(ErrorCode::TotpBackupCodeInvalid));
}

#[tokio::test]
async fn journey_3_disable_2fa_then_login_without_a_challenge() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    let ip = dynamic_ip();

    let (email, password, _secret, _backup_codes, session) = enabled_user(&app, &ip).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let secrets_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM totp_secrets WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&app.pool)
            .await
            .expect("count totp_secrets");
    assert_eq!(secrets_before, 1, "enrollment must leave one secret row");

    let disable = app
        .dispatch(session_request(
            &app,
            Method::DELETE,
            "/auth/totp",
            json!({ "password": password }),
            &session,
            &ip,
        ))
        .await;
    assert_eq!(
        disable.status(),
        StatusCode::OK,
        "disable failed: {}",
        disable.body_str
    );
    assert_eq!(
        disable.json["message"],
        json!("two-factor authentication disabled")
    );

    let secrets_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM totp_secrets WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&app.pool)
            .await
            .expect("count totp_secrets");
    assert_eq!(secrets_after, 0, "disable must drop the secret row");

    // The next login is a full session: no challenge, and a new row for the same user.
    let sessions_before = count_sessions_for_user(&app.pool, user_id).await;
    let login_resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(
        login_resp.status(),
        StatusCode::OK,
        "login failed: {}",
        login_resp.body_str
    );
    assert!(
        login_resp.headers.contains_key(header::SET_COOKIE),
        "login without 2FA must issue the session cookie"
    );
    assert!(
        login_resp.json.get("two_factor_required").is_none(),
        "no challenge may remain after disabling 2FA: {}",
        login_resp.body_str
    );
    assert!(login_resp.json.get("challenge_token").is_none());
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        sessions_before + 1,
        "login must issue exactly one session for the same user"
    );

    let sid = extract_cookie_val(&login_resp.headers, &app.state.config.session.cookie_name)
        .expect("session cookie");
    let session_resp = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            cookie_header(&app, &sid),
        ))
        .await;
    assert_eq!(
        session_resp.status(),
        StatusCode::OK,
        "session lookup failed: {}",
        session_resp.body_str
    );
    let issued_hash = session_resp.json["session_id"]
        .as_str()
        .expect("session id")
        .to_string();
    assert!(
        session_token_hashes(&app.pool, user_id)
            .await
            .contains(&issued_hash),
        "the post-disable session must belong to the same user"
    );
}
