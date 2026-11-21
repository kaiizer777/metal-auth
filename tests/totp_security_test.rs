//! Security-regression scenarios for TOTP two-factor authentication.
//!
//! Every test here is a negative path from the Phase 7 Tier 4 list, driven through the
//! real router and PostgreSQL. Positive handler coverage lives in `totp_handler_test.rs`.

mod common;

use axum::http::StatusCode;
use common::*;
use metal_auth::ErrorCode;
use serde_json::json;

/// Scenario 1: a challenge token past its TTL cannot mint a session.
#[tokio::test]
async fn expired_challenge_token_is_rejected() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, secret, _backup_codes, _session) = enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let sessions_before = count_sessions_for_user(&app.pool, user_id).await;

    let token = challenge(&app, &email, &password).await;
    let expired = sqlx::query(
        "UPDATE two_factor_tokens SET expires_at = NOW() - INTERVAL '1 minute' WHERE user_id = $1",
    )
    .bind(user_id)
    .execute(&app.pool)
    .await
    .expect("expire the challenge token");
    assert_eq!(
        expired.rows_affected(),
        1,
        "the login must have stored exactly one challenge row"
    );

    let resp = app
        .post_json_with_ip(
            "/auth/totp/verify",
            json!({ "challenge_token": token, "code": totp_code(&secret) }),
            &dynamic_ip(),
        )
        .await;

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "body: {}",
        resp.body_str
    );
    assert_eq!(resp.error_code(), Some(ErrorCode::TwoFactorTokenExpired));
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        sessions_before,
        "an expired challenge must not issue a session"
    );
}

/// Scenario 2: a code accepted once is burned for every later presentation.
#[tokio::test]
async fn replayed_totp_code_is_rejected() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, secret, _backup_codes, _session) = enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let sessions_before = count_sessions_for_user(&app.pool, user_id).await;

    let first_token = challenge(&app, &email, &password).await;
    let second_token = challenge(&app, &email, &password).await;
    // One step ahead keeps the code inside the ±1 acceptance window across both requests
    // and off the 30-second boundary that would move it out of range.
    let code = code_at(
        &secret,
        metal_auth::totp::crypto::current_totp_counter() + 1,
    );

    let first = app
        .post_json_with_ip(
            "/auth/totp/verify",
            json!({ "challenge_token": first_token, "code": code }),
            &dynamic_ip(),
        )
        .await;
    assert_eq!(first.status(), StatusCode::OK, "body: {}", first.body_str);
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        sessions_before + 1,
        "the first presentation must issue one session"
    );

    let second = app
        .post_json_with_ip(
            "/auth/totp/verify",
            json!({ "challenge_token": second_token, "code": code }),
            &dynamic_ip(),
        )
        .await;

    assert_eq!(
        second.status(),
        StatusCode::BAD_REQUEST,
        "body: {}",
        second.body_str
    );
    assert_eq!(second.error_code(), Some(ErrorCode::TotpCodeReplayed));
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        sessions_before + 1,
        "a replayed code must not mint a second session"
    );
}
