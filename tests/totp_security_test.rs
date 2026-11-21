//! Security-regression scenarios for TOTP two-factor authentication.
//!
//! Every test here is a negative path from the Phase 7 Tier 4 list, driven through the
//! real router and PostgreSQL. Positive handler coverage lives in `totp_handler_test.rs`.

mod common;

use axum::http::StatusCode;
use common::*;
use metal_auth::ErrorCode;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

async fn backup_code_count(pool: &PgPool, user_id: Uuid) -> i32 {
    sqlx::query_scalar("SELECT jsonb_array_length(backup_codes) FROM totp_secrets WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("totp secret row with a backup-code array")
}

async fn pending_challenge_count(pool: &PgPool, user_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM two_factor_tokens WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("count challenge tokens")
}

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

/// Scenario 3: an unknown backup code is rejected without touching any state.
#[tokio::test]
async fn unknown_backup_code_is_rejected_without_state_change() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, _secret, backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let sessions_before = count_sessions_for_user(&app.pool, user_id).await;
    let token = challenge(&app, &email, &password).await;

    // Sixteen base32 characters: shape-valid, but not one of the issued codes.
    let fabricated = "AAAAAAAAAAAAAAAA";
    assert!(
        !backup_codes.iter().any(|code| code == fabricated),
        "the fabricated code must not collide with a real backup code"
    );

    let resp = app
        .post_json_with_ip(
            "/auth/totp/backup",
            json!({ "challenge_token": token, "code": fabricated }),
            &dynamic_ip(),
        )
        .await;

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "body: {}",
        resp.body_str
    );
    assert_eq!(resp.error_code(), Some(ErrorCode::TotpBackupCodeInvalid));
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        sessions_before,
        "a rejected backup code must not issue a session"
    );
    assert_eq!(
        backup_code_count(&app.pool, user_id).await,
        10,
        "a rejected backup code must not consume a stored hash"
    );
    assert_eq!(
        pending_challenge_count(&app.pool, user_id).await,
        1,
        "a rejected backup code must leave the challenge retryable"
    );
}

/// Scenario 4: a consumed backup code is gone and cannot be replayed.
#[tokio::test]
async fn reused_backup_code_is_rejected() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, _secret, backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let sessions_before = count_sessions_for_user(&app.pool, user_id).await;
    let code = backup_codes[1].clone();

    let token = challenge(&app, &email, &password).await;
    let first = app
        .post_json_with_ip(
            "/auth/totp/backup",
            json!({ "challenge_token": token, "code": code }),
            &dynamic_ip(),
        )
        .await;
    assert_eq!(first.status(), StatusCode::OK, "body: {}", first.body_str);
    assert_eq!(
        backup_code_count(&app.pool, user_id).await,
        9,
        "a successful use must delete exactly one stored hash"
    );

    let second_token = challenge(&app, &email, &password).await;
    let second = app
        .post_json_with_ip(
            "/auth/totp/backup",
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
    assert_eq!(second.error_code(), Some(ErrorCode::TotpBackupCodeInvalid));
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        sessions_before + 1,
        "the reuse must not mint a second session"
    );
    assert_eq!(
        backup_code_count(&app.pool, user_id).await,
        9,
        "the rejected reuse must not consume another hash"
    );
}

/// Scenario 5: a real challenge for a user whose secret row is gone cannot verify.
#[tokio::test]
async fn unenrolled_user_verify_is_rejected() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, secret, _backup_codes, _session) = enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let sessions_before = count_sessions_for_user(&app.pool, user_id).await;

    // A fabricated token dies at validation (401 TWO_FACTOR_TOKEN_INVALID) before the
    // secret is ever read, so the only executable form of this scenario is a genuine
    // challenge whose enrollment disappears underneath it.
    let token = challenge(&app, &email, &password).await;
    let deleted = sqlx::query("DELETE FROM totp_secrets WHERE user_id = $1")
        .bind(user_id)
        .execute(&app.pool)
        .await
        .expect("remove the enrollment");
    assert_eq!(deleted.rows_affected(), 1, "the enrollment must exist");
    assert_eq!(
        pending_challenge_count(&app.pool, user_id).await,
        1,
        "the challenge must still be live"
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
        StatusCode::BAD_REQUEST,
        "body: {}",
        resp.body_str
    );
    assert_eq!(resp.error_code(), Some(ErrorCode::TotpNotEnrolled));
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        sessions_before,
        "an unenrolled verify must not issue a session"
    );
}
