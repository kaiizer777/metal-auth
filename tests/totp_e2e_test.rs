//! End-to-end TOTP journeys against real PostgreSQL.
//!
//! Each journey drives the public HTTP surface only and asserts identity through the
//! `sessions.user_id` row: `GET /auth/session` never exposes the user id.

mod common;

use axum::http::{HeaderMap, Method, StatusCode, header};
use common::*;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Token hash of the journey user's only session, for tying an HTTP response to a user row.
async fn only_session_token_hash(pool: &PgPool, user_id: Uuid) -> String {
    sqlx::query_scalar("SELECT token_hash FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("exactly one session for the journey user")
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
