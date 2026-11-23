//! Regression tests for issue #58: a two-factor challenge is bound to the credential that
//! authorized it, so a password reset revokes a challenge already in flight.
//!
//! The interleaving is deterministic — no sleeps, no barriers, no concurrent tasks. The
//! challenge row is inserted explicitly with the pre-reset credential hash, which is exactly
//! what a mint that lost the race against the reset writes: the reset's purge has already
//! committed, so nothing deletes the row, and only the stored snapshot can distinguish it
//! from a legitimately minted challenge.

mod common;

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use common::{
    DB_LOCK, TestApp, challenge, count_sessions_for_user, dynamic_ip, dynamic_password,
    enabled_user, setup_test_app, totp_code, user_id_for_email,
};
use metal_auth::{ErrorCode, crypto::token::generate_token};
use serde_json::json;
use uuid::Uuid;

/// Reset the password through the service and return the user plus the superseded credential.
async fn reset_password(app: &TestApp, email: &str, new_password: &str) -> (Uuid, String) {
    let user_id = user_id_for_email(&app.pool, email).await;
    let pre_reset_hash: String =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&app.pool)
            .await
            .expect("read pre-reset credential");

    let (raw_token, token_hash) = generate_token();
    sqlx::query(
        "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(token_hash.as_slice())
    .bind(user_id)
    .bind(Utc::now() + Duration::hours(1))
    .execute(&app.pool)
    .await
    .expect("insert reset token");

    app.state
        .auth_service
        .reset_password(&raw_token, new_password)
        .await
        .expect("reset commits");

    (user_id, pre_reset_hash)
}

/// Insert the challenge row a mint racing the reset would write: valid, unexpired, and
/// carrying the credential snapshot that the reset has just superseded.
async fn insert_pre_reset_challenge(app: &TestApp, user_id: Uuid, pre_reset_hash: &str) -> String {
    let (raw_token, token_hash) = generate_token();
    sqlx::query(
        "INSERT INTO two_factor_tokens (user_id, token_hash, expires_at, credential_hash) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(token_hash.as_slice())
    .bind(Utc::now() + Duration::minutes(5))
    .bind(pre_reset_hash)
    .execute(&app.pool)
    .await
    .expect("insert challenge");

    raw_token
}

async fn challenge_row_count(app: &TestApp, user_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM two_factor_tokens WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&app.pool)
        .await
        .expect("count challenges")
}

#[tokio::test]
async fn pre_reset_challenge_is_not_redeemable_after_a_reset() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    let ip = dynamic_ip();
    let (email, _old_password, secret, _backup_codes, _enrollment_session) =
        enabled_user(&app, &ip).await;

    let (user_id, pre_reset_hash) = reset_password(&app, &email, &dynamic_password()).await;
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        0,
        "the reset purges every session, so the only session a success could add is a new one"
    );

    // Mint after the reset commits, holding the credential the reset superseded.
    let challenge_token = insert_pre_reset_challenge(&app, user_id, &pre_reset_hash).await;

    let resp = app
        .post_json_with_ip(
            "/auth/totp/verify",
            json!({ "challenge_token": challenge_token, "code": totp_code(&secret) }),
            &ip,
        )
        .await;

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a challenge authorized by a superseded credential must be rejected: {}",
        resp.body_str
    );
    assert_eq!(resp.error_code(), Some(ErrorCode::TwoFactorTokenInvalid));
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        0,
        "the rejected redemption must not mint a session"
    );
    // The rejection rolls the whole transaction back, so the challenge and the code are
    // unspent. Retrying cannot succeed either: the snapshot can never match again.
    assert_eq!(challenge_row_count(&app, user_id).await, 1);
}

#[tokio::test]
async fn stale_challenge_is_not_redeemable_with_a_backup_code() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    let ip = dynamic_ip();
    let (email, _old_password, _secret, backup_codes, _enrollment_session) =
        enabled_user(&app, &ip).await;

    let (user_id, pre_reset_hash) = reset_password(&app, &email, &dynamic_password()).await;
    let challenge_token = insert_pre_reset_challenge(&app, user_id, &pre_reset_hash).await;

    let resp = app
        .post_json_with_ip(
            "/auth/totp/backup",
            json!({ "challenge_token": challenge_token, "code": backup_codes[0] }),
            &ip,
        )
        .await;

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "the backup path funnels into the same redemption: {}",
        resp.body_str
    );
    assert_eq!(resp.error_code(), Some(ErrorCode::TwoFactorTokenInvalid));
    assert_eq!(count_sessions_for_user(&app.pool, user_id).await, 0);
}

#[tokio::test]
async fn challenge_minted_for_the_live_credential_redeems() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    let ip = dynamic_ip();
    let (email, password, secret, _backup_codes, _enrollment_session) =
        enabled_user(&app, &ip).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let baseline = count_sessions_for_user(&app.pool, user_id).await;

    let challenge_token = challenge(&app, &email, &password).await;
    let resp = app
        .post_json_with_ip(
            "/auth/totp/verify",
            json!({ "challenge_token": challenge_token, "code": totp_code(&secret) }),
            &ip,
        )
        .await;

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "binding must not reject a challenge minted against the live credential: {}",
        resp.body_str
    );
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        baseline + 1
    );
    assert_eq!(challenge_row_count(&app, user_id).await, 0);
}
