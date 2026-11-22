//! Security-regression scenarios for TOTP two-factor authentication.
//!
//! Each test drives one Phase 7 Tier 4 case through the real router and PostgreSQL.
//! Positive handler coverage lives in `totp_handler_test.rs`.

mod common;

use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, Method, StatusCode, header};
use chrono::{Duration, Utc};
use common::*;
use metal_auth::{ErrorCode, RateLimiter, crypto::token::generate_token};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Cookies, CSRF header, and client IP for a protected TOTP route, minus the body.
///
/// Without all three the request would test CSRF or auth middleware instead of the
/// fresh-proof check.
fn session_headers(app: &TestApp, session: &Session, ip: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}={}; csrf_token={}",
            app.state.config.session.cookie_name, session.sid, session.csrf
        )
        .parse()
        .expect("cookie header"),
    );
    headers.insert("x-csrf-token", session.csrf.parse().expect("csrf header"));
    headers.insert("x-forwarded-for", ip.parse().expect("ip header"));
    headers
}

async fn enrollment_count(pool: &PgPool, user_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM totp_secrets WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("count enrollments")
}

async fn backup_code_count(pool: &PgPool, user_id: Uuid) -> i32 {
    sqlx::query_scalar(
        "SELECT jsonb_array_length(backup_codes) FROM totp_secrets WHERE user_id = $1",
    )
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

async fn stored_backup_hashes(pool: &PgPool, user_id: Uuid) -> Vec<String> {
    let stored: serde_json::Value =
        sqlx::query_scalar("SELECT backup_codes FROM totp_secrets WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .expect("backup code store");
    serde_json::from_value(stored).expect("backup codes are a JSON string array")
}

/// Scenario 1: a challenge token past its TTL cannot mint a session.
#[tokio::test]
async fn expired_challenge_token_is_rejected() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
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

    let (email, password, secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let sessions_before = count_sessions_for_user(&app.pool, user_id).await;

    let first_token = challenge(&app, &email, &password).await;
    let second_token = challenge(&app, &email, &password).await;
    // One step ahead keeps the code inside the ±1 acceptance window across both requests
    // and off the 30-second boundary that would move it out of range.
    let counter = metal_auth::totp::crypto::current_totp_counter();
    let code = code_at(&secret, counter + 1);
    // Never presented: a rejection of this code can only be the consumed token.
    let fresh_code = code_at(&secret, counter);

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

    // The verify above consumed `first_token`, so re-presenting it must fail on the token.
    let consumed = app
        .post_json_with_ip(
            "/auth/totp/verify",
            json!({ "challenge_token": first_token, "code": fresh_code }),
            &dynamic_ip(),
        )
        .await;
    assert_eq!(
        consumed.status(),
        StatusCode::UNAUTHORIZED,
        "a consumed challenge token must be refused: {}",
        consumed.body_str
    );
    assert_eq!(
        consumed.error_code(),
        Some(ErrorCode::TwoFactorTokenInvalid)
    );
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        sessions_before + 1,
        "a consumed challenge token must not mint a second session"
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

    // Ten base32 characters, the issued shape (`BACKUP_CODE_LEN`), but not one of the codes.
    let fabricated = "AAAAAAAAAA";
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

/// Scenario 4b: a challenge token consumed by a backup login cannot be redeemed again.
#[tokio::test]
async fn consumed_challenge_token_is_rejected_by_backup_path() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, _secret, backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let sessions_before = count_sessions_for_user(&app.pool, user_id).await;
    let token = challenge(&app, &email, &password).await;

    let first = app
        .post_json_with_ip(
            "/auth/totp/backup",
            json!({ "challenge_token": token, "code": backup_codes[0] }),
            &dynamic_ip(),
        )
        .await;
    assert_eq!(first.status(), StatusCode::OK, "body: {}", first.body_str);
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        sessions_before + 1,
        "a backup login must issue exactly one session"
    );

    // A second, still-unused code: only the consumed token can reject this request.
    let reused = app
        .post_json_with_ip(
            "/auth/totp/backup",
            json!({ "challenge_token": token, "code": backup_codes[1] }),
            &dynamic_ip(),
        )
        .await;
    assert_eq!(
        reused.status(),
        StatusCode::UNAUTHORIZED,
        "a consumed challenge token must be refused: {}",
        reused.body_str
    );
    assert_eq!(reused.error_code(), Some(ErrorCode::TwoFactorTokenInvalid));
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        sessions_before + 1,
        "a consumed challenge token must not mint a second session"
    );
    assert_eq!(
        backup_code_count(&app.pool, user_id).await,
        9,
        "a consumed challenge token must not consume another backup code"
    );
}

/// Scenario 5: a real challenge for a user whose secret row is gone cannot verify.
#[tokio::test]
async fn unenrolled_user_verify_is_rejected() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
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

/// Scenario 6a: disabling without any fresh proof is a validation error, not a toggle.
#[tokio::test]
async fn disable_without_a_fresh_proof_is_a_validation_error() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, _password, _secret, _backup_codes, session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;

    let absent = app
        .dispatch(empty_request_with_headers(
            Method::DELETE,
            "/auth/totp",
            session_headers(&app, &session, &dynamic_ip()),
        ))
        .await;
    assert_eq!(
        absent.status(),
        StatusCode::BAD_REQUEST,
        "body: {}",
        absent.body_str
    );
    assert_eq!(absent.error_code(), Some(ErrorCode::ValidationError));

    let empty = app
        .dispatch(session_request(
            &app,
            Method::DELETE,
            "/auth/totp",
            json!({}),
            &session,
            &dynamic_ip(),
        ))
        .await;
    assert_eq!(
        empty.status(),
        StatusCode::BAD_REQUEST,
        "body: {}",
        empty.body_str
    );
    assert_eq!(empty.error_code(), Some(ErrorCode::ValidationError));

    assert_eq!(
        enrollment_count(&app.pool, user_id).await,
        1,
        "a missing proof must leave 2fa enabled"
    );
}

/// Scenario 6b: a wrong password is a credential failure and keeps 2FA on.
#[tokio::test]
async fn disable_with_a_wrong_password_is_rejected() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, _password, _secret, _backup_codes, session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;

    let resp = app
        .dispatch(session_request(
            &app,
            Method::DELETE,
            "/auth/totp",
            json!({ "password": dynamic_password() }),
            &session,
            &dynamic_ip(),
        ))
        .await;

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "body: {}",
        resp.body_str
    );
    assert_eq!(resp.error_code(), Some(ErrorCode::InvalidCredentials));
    assert_eq!(
        enrollment_count(&app.pool, user_id).await,
        1,
        "a rejected proof must leave 2fa enabled"
    );
}

/// Scenario 7: enrollment on an unverified email is refused before any write.
#[tokio::test]
async fn unverified_email_enrollment_is_rejected() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    // Login rejects unverified accounts, so the session is minted first and the email
    // is unverified underneath it — the state the enrollment guard must catch.
    let (email, password) = create_verified_user(&app).await;
    let session = login(&app, &email, &password).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    sqlx::query("UPDATE users SET email_verified = false WHERE id = $1")
        .bind(user_id)
        .execute(&app.pool)
        .await
        .expect("unverify the email");

    let resp = app
        .dispatch(session_request(
            &app,
            Method::POST,
            "/auth/totp/enroll",
            json!({}),
            &session,
            &dynamic_ip(),
        ))
        .await;

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "body: {}",
        resp.body_str
    );
    assert_eq!(resp.error_code(), Some(ErrorCode::EmailNotVerified));
    assert_eq!(
        enrollment_count(&app.pool, user_id).await,
        0,
        "a rejected enrollment must not create a secret row"
    );
}

/// Advertised `Retry-After` must be a positive number of seconds inside the window.
fn retry_after_secs(resp: &TestResponse, window_secs: u64) -> u64 {
    let value: u64 = resp
        .header("retry-after")
        .expect("a 429 must advertise Retry-After")
        .parse()
        .expect("Retry-After is whole seconds");
    assert!(
        (1..=window_secs).contains(&value),
        "Retry-After {value} must be derived from the {window_secs}s window"
    );
    value
}

/// Scenario 8a: the user budget admits exactly its configured attempts, then 429s.
#[tokio::test]
async fn user_budget_admits_exactly_three_attempts_then_returns_429() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app_with(|cfg| {
        cfg.totp.rate_limit_user_max_attempts = 3;
    })
    .await
    else {
        return;
    };

    let (email, password, secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let token = challenge(&app, &email, &password).await;
    // Three steps out survives a step rollover mid-request and stays outside the ±1 window,
    // unlike a literal that can collide with the live code.
    let out_of_window = code_at(
        &secret,
        metal_auth::totp::crypto::current_totp_counter() + 3,
    );

    // Clear the verification budget so the boundary under test is exactly the configured
    // three, not whatever the enrollment flow left behind.
    app.state
        .rate_limiter
        .reset(&RateLimiter::totp_user_key(user_id));

    for attempt in 0..3 {
        let resp = app
            .post_json_with_ip(
                "/auth/totp/verify",
                json!({ "challenge_token": token, "code": out_of_window }),
                &dynamic_ip(),
            )
            .await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "attempt {attempt} must reach the code check: {}",
            resp.body_str
        );
        assert_eq!(resp.error_code(), Some(ErrorCode::TotpCodeInvalid));
    }

    let rejected = app
        .post_json_with_ip(
            "/auth/totp/verify",
            json!({ "challenge_token": token, "code": out_of_window }),
            &dynamic_ip(),
        )
        .await;
    assert_eq!(
        rejected.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "body: {}",
        rejected.body_str
    );
    assert_eq!(
        rejected.error_code(),
        Some(ErrorCode::TotpRateLimitExceeded)
    );
    retry_after_secs(&rejected, app.state.config.totp.rate_limit_window_secs);
}

/// Scenario 9: a 2FA password login yields a challenge envelope and no session.
#[tokio::test]
async fn login_with_2fa_returns_only_a_challenge() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, _secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let sessions_before = count_sessions_for_user(&app.pool, user_id).await;

    let token = challenge(&app, &email, &password).await;
    assert_eq!(token.len(), 64, "the challenge token is 32-byte hex");

    let login = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(login.status(), StatusCode::OK, "body: {}", login.body_str);
    let body = login.json.as_object().expect("login body is an object");
    assert_eq!(
        body.len(),
        2,
        "a 2FA login carries only the two challenge fields: {}",
        login.body_str
    );
    assert_eq!(body["two_factor_required"], json!(true));
    assert!(body["challenge_token"].is_string());
    assert!(
        !body.contains_key("expires_at"),
        "a half-authenticated login must not advertise a session expiry"
    );
    assert!(
        !login.headers.contains_key(header::SET_COOKIE),
        "a 2FA login must not set any cookie"
    );
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        sessions_before,
        "a 2FA login must not create a session row"
    );
}

/// Scenario 10: exactly the consumed hash leaves the JSONB array, and the rest survive.
#[tokio::test]
async fn used_backup_code_is_purged_from_storage() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, _secret, backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let code = backup_codes[2].clone();

    let before = stored_backup_hashes(&app.pool, user_id).await;
    assert_eq!(before.len(), 10, "enrollment must store ten hashes");

    let token = challenge(&app, &email, &password).await;
    let used = app
        .post_json_with_ip(
            "/auth/totp/backup",
            json!({ "challenge_token": token, "code": code }),
            &dynamic_ip(),
        )
        .await;
    assert_eq!(used.status(), StatusCode::OK, "body: {}", used.body_str);

    // The used hash is identifiable: verification is public and pure, and the JSONB array
    // delete preserves order.
    let used_index = metal_auth::totp::backup::verify_backup_code(&code, &before)
        .expect("the used code must match exactly one stored hash");
    let mut expected = before;
    expected.remove(used_index);

    let after = stored_backup_hashes(&app.pool, user_id).await;
    assert_eq!(
        after, expected,
        "exactly the hash matching the used code must be removed"
    );
    assert!(
        after.iter().all(|hash| hash.starts_with("$argon2id$")),
        "the remaining entries must stay Argon2id PHC strings"
    );
}

/// Scenario 11: five simultaneous presentations of one live code admit exactly one.
#[test]
fn concurrent_replay_admits_exactly_one_request() {
    block_on_concurrent(async {
        let _guard = DB_LOCK.lock().await;
        let Some(app) = setup_test_app_with(|cfg| {
            // Confirmation plus five attempts must fit both budgets, otherwise a loser
            // could be a 429 and the barrier would prove nothing.
            cfg.totp.rate_limit_user_max_attempts = 10;
            cfg.totp.rate_limit_ip_max_attempts = 10;
        })
        .await
        else {
            return;
        };

        let ip = dynamic_ip();
        let (email, password, secret, _backup_codes, _session) = enabled_user(&app, &ip).await;
        let user_id = user_id_for_email(&app.pool, &email).await;
        let sessions_before = count_sessions_for_user(&app.pool, user_id).await;
        let token = challenge(&app, &email, &password).await;
        let code = totp_code(&secret);

        let barrier = Arc::new(tokio::sync::Barrier::new(5));
        let mut tasks = Vec::with_capacity(5);
        for _ in 0..5 {
            let app = app.clone();
            let barrier = Arc::clone(&barrier);
            let token = token.clone();
            let code = code.clone();
            let ip = ip.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                app.post_json_with_ip(
                    "/auth/totp/verify",
                    json!({ "challenge_token": token, "code": code }),
                    &ip,
                )
                .await
            }));
        }

        let mut accepted = 0;
        let mut replayed = 0;
        let mut token_rejected = 0;
        for task in tasks {
            let resp = task.await.expect("verification task must not panic");
            match resp.status() {
                StatusCode::OK => accepted += 1,
                StatusCode::BAD_REQUEST => {
                    assert_eq!(
                        resp.error_code(),
                        Some(ErrorCode::TotpCodeReplayed),
                        "a 400 loser must be the replay rejection: {}",
                        resp.body_str
                    );
                    replayed += 1;
                }
                StatusCode::UNAUTHORIZED => {
                    assert_eq!(
                        resp.error_code(),
                        Some(ErrorCode::TwoFactorTokenInvalid),
                        "a 401 loser must be the consumption rejection: {}",
                        resp.body_str
                    );
                    token_rejected += 1;
                }
                other => panic!("unexpected loser status {other}: {}", resp.body_str),
            }
        }

        assert_eq!(accepted, 1, "exactly one request may win the code");
        assert_eq!(
            replayed + token_rejected,
            4,
            "the other four must be replay or token-consumption rejections"
        );

        let used: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM totp_used_codes WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&app.pool)
                .await
                .expect("count used codes");
        assert_eq!(used, 1, "the replay log must hold exactly one row");
        assert_eq!(
            count_sessions_for_user(&app.pool, user_id).await,
            sessions_before + 1,
            "the race must issue exactly one new session"
        );
    });
}

/// Response to a code `offset` steps from the live window, taken from an attempt whose step
/// counter did not move under it.
///
/// A step boundary between generation and dispatch slides the code into the neighbouring
/// window and can flip the expectation, so such an attempt proves nothing and is retried. An
/// accepted rollover consumes its challenge and mints a session; that count is returned so the
/// caller's session delta stays exact.
async fn out_of_window_response(
    app: &TestApp,
    user_id: Uuid,
    email: &str,
    password: &str,
    secret: &str,
    offset: i64,
) -> (TestResponse, i64) {
    let mut slipped = 0;
    for _ in 0..5 {
        let counter = metal_auth::totp::crypto::current_totp_counter();
        let token = challenge(app, email, password).await;
        let code = code_at(secret, counter.saturating_add_signed(offset));
        let resp = app
            .post_json_with_ip(
                "/auth/totp/verify",
                json!({ "challenge_token": token, "code": code }),
                &dynamic_ip(),
            )
            .await;
        if metal_auth::totp::crypto::current_totp_counter() == counter {
            return (resp, slipped);
        }
        if resp.status() == StatusCode::OK {
            slipped += 1;
        }
        // Retries are not the behaviour under test, so they must not spend the user budget.
        app.state
            .rate_limiter
            .reset(&RateLimiter::totp_user_key(user_id));
    }
    panic!("the totp step rolled over during every out-of-window probe");
}

/// Tier 4 §1: the ±1 step window accepts the next step and rejects two steps out.
#[tokio::test]
async fn clock_drift_accepts_the_next_step_and_rejects_two_steps_out() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let sessions_before = count_sessions_for_user(&app.pool, user_id).await;

    // `T-1` can decay to `T-2` across a 30-second boundary, so the accepted case uses the
    // forward drift direction where the code only moves deeper into the window.
    let token = challenge(&app, &email, &password).await;
    let next_step = code_at(
        &secret,
        metal_auth::totp::crypto::current_totp_counter() + 1,
    );
    let accepted = app
        .post_json_with_ip(
            "/auth/totp/verify",
            json!({ "challenge_token": token, "code": next_step }),
            &dynamic_ip(),
        )
        .await;
    assert_eq!(
        accepted.status(),
        StatusCode::OK,
        "T+1 must be inside the window: {}",
        accepted.body_str
    );

    let (rejected_ahead, ahead_slips) =
        out_of_window_response(&app, user_id, &email, &password, &secret, 2).await;
    assert_eq!(
        rejected_ahead.status(),
        StatusCode::BAD_REQUEST,
        "T+2 must be outside the window: {}",
        rejected_ahead.body_str
    );
    assert_eq!(
        rejected_ahead.error_code(),
        Some(ErrorCode::TotpCodeInvalid)
    );

    let (rejected_behind, behind_slips) =
        out_of_window_response(&app, user_id, &email, &password, &secret, -2).await;
    assert_eq!(
        rejected_behind.status(),
        StatusCode::BAD_REQUEST,
        "T-2 must be outside the window: {}",
        rejected_behind.body_str
    );
    assert_eq!(
        rejected_behind.error_code(),
        Some(ErrorCode::TotpCodeInvalid)
    );

    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        sessions_before + 1 + ahead_slips + behind_slips,
        "only the in-window presentation may issue a session ({ahead_slips} and \
         {behind_slips} out-of-window probes were accepted on a step rollover)"
    );
}

// ─── Tier 4 §10 — zero-leak telemetry ───────────────────────────────────────

#[derive(Clone)]
struct TestLogWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for TestLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("log buffer lock")
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TestLogWriter {
    type Writer = TestLogWriter;
    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

/// Captures the thread-local `tracing` output for the duration of a test.
///
/// The default subscriber is thread-scoped, so this only works on a `current_thread`
/// runtime where every poll of the test future stays on this thread.
struct TestLogScope {
    buf: Arc<Mutex<Vec<u8>>>,
    _guard: tracing::subscriber::DefaultGuard,
}

impl TestLogScope {
    fn new() -> Self {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(TestLogWriter(Arc::clone(&buf)))
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        Self { buf, _guard: guard }
    }

    fn text(&self) -> String {
        String::from_utf8(self.buf.lock().expect("log buffer lock").clone())
            .expect("logs are UTF-8")
    }
}

/// True when `code` appears as a value rather than inside a longer hash or id.
///
/// A leaked six-digit code shows up delimited (`code=123456,` or `"123456"`). The same
/// digits can coincidentally sit inside a hex session hash, which is not a leak.
fn contains_standalone(text: &str, code: &str) -> bool {
    let bytes = text.as_bytes();
    text.match_indices(code).any(|(index, _)| {
        let before = index.checked_sub(1).map(|i| bytes[i]);
        let after = bytes.get(index + code.len()).copied();
        !before.is_some_and(|byte| byte.is_ascii_hexdigit())
            && !after.is_some_and(|byte| byte.is_ascii_hexdigit())
    })
}

/// Tier 4 §10: no audit event may carry a secret, a code, a token, or the AES key.
#[tokio::test(flavor = "current_thread")]
async fn totp_audit_events_leak_no_secret_material() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    let log = TestLogScope::new();

    let ip = dynamic_ip();
    let (email, password) = create_verified_user(&app).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let session = login(&app, &email, &password).await;
    let enrollment = enroll(&app, &session, &ip).await;
    let secret = enrollment["secret_base32"]
        .as_str()
        .expect("secret_base32")
        .to_string();
    let backup_code = enrollment["backup_codes"][0]
        .as_str()
        .expect("backup code")
        .to_string();

    let confirm_code = totp_code(&secret);
    let confirmed = confirm(&app, &session, &secret, &ip).await;
    assert_eq!(
        confirmed.status(),
        StatusCode::OK,
        "confirm failed: {}",
        confirmed.body_str
    );

    // The stored ciphertext is on the spec's zero-leak list; read it before the disable below
    // drops the row.
    let stored_ciphertext: String = sqlx::query_scalar(
        "SELECT encode(encrypted_secret, 'hex') FROM totp_secrets WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(&app.pool)
    .await
    .expect("stored encrypted secret");
    assert_eq!(
        stored_ciphertext.len(),
        96,
        "nonce (12) || ciphertext (20) || tag (16) is 96 hex characters"
    );

    let cookie_name = app.state.config.session.cookie_name.clone();
    let challenge_token = challenge(&app, &email, &password).await;
    let verify_code = code_at(
        &secret,
        metal_auth::totp::crypto::current_totp_counter() + 1,
    );
    let verified = app
        .post_json(
            "/auth/totp/verify",
            json!({ "challenge_token": challenge_token, "code": verify_code }),
        )
        .await;
    assert_eq!(
        verified.status(),
        StatusCode::OK,
        "verify failed: {}",
        verified.body_str
    );
    let session_id = extract_cookie_val(&verified.headers, &cookie_name).expect("session cookie");

    let backup_token = challenge(&app, &email, &password).await;
    let backed_up = app
        .post_json(
            "/auth/totp/backup",
            json!({ "challenge_token": backup_token, "code": backup_code }),
        )
        .await;
    assert_eq!(
        backed_up.status(),
        StatusCode::OK,
        "backup failed: {}",
        backed_up.body_str
    );
    let backup_session_id =
        extract_cookie_val(&backed_up.headers, &cookie_name).expect("session cookie");

    let disabled = app
        .dispatch(session_request(
            &app,
            Method::DELETE,
            "/auth/totp",
            json!({ "password": password }),
            &session,
            &dynamic_ip(),
        ))
        .await;
    assert_eq!(
        disabled.status(),
        StatusCode::OK,
        "disable failed: {}",
        disabled.body_str
    );

    let text = log.text();
    // Positive control: an empty capture would make every absence assertion vacuous.
    assert!(
        text.contains("totp_verified"),
        "the log scope must capture the verification audit event"
    );
    assert!(
        text.contains("session_id_hash"),
        "the audit event logs the hash field this test audits"
    );

    let encryption_key = "00".repeat(32);
    for (label, value) in [
        ("totp secret", secret.as_str()),
        ("encrypted secret", stored_ciphertext.as_str()),
        ("challenge token", challenge_token.as_str()),
        ("backup challenge token", backup_token.as_str()),
        ("backup code", backup_code.as_str()),
        ("raw session id", session_id.as_str()),
        ("raw backup session id", backup_session_id.as_str()),
        ("encryption key", encryption_key.as_str()),
    ] {
        assert!(!text.contains(value), "the log leaked the {label}");
    }

    for (label, value) in [
        ("confirm code", confirm_code.as_str()),
        ("verify code", verify_code.as_str()),
    ] {
        assert!(
            !contains_standalone(&text, value),
            "the log leaked the {label}"
        );
    }
}

/// Scenario 8b: the IP budget is independent of the user budget and trips at 11.
#[tokio::test]
async fn ip_budget_admits_exactly_ten_attempts_then_returns_429() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app_with(|cfg| {
        cfg.totp.rate_limit_ip_max_attempts = 10;
    })
    .await
    else {
        return;
    };

    let ip = dynamic_ip();
    // No enrollment: the token fails validation, so only the IP dimension is charged.
    app.state.rate_limiter.reset(&RateLimiter::totp_ip_key(&ip));

    for attempt in 0..10 {
        // Distinct tokens per attempt: reusing one token could not tell an IP budget from a
        // per-token budget.
        let token = format!("{attempt:02x}").repeat(32);
        let resp = app
            .post_json_with_ip(
                "/auth/totp/verify",
                json!({ "challenge_token": token, "code": "000000" }),
                &ip,
            )
            .await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "attempt {attempt} must reach token validation: {}",
            resp.body_str
        );
        assert_eq!(resp.error_code(), Some(ErrorCode::TwoFactorTokenInvalid));
    }

    let rejected = app
        .post_json_with_ip(
            "/auth/totp/verify",
            json!({ "challenge_token": "ff".repeat(32), "code": "000000" }),
            &ip,
        )
        .await;
    assert_eq!(
        rejected.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "body: {}",
        rejected.body_str
    );
    assert_eq!(
        rejected.error_code(),
        Some(ErrorCode::TotpRateLimitExceeded)
    );
    retry_after_secs(&rejected, app.state.config.totp.rate_limit_window_secs);
}

/// Scenario 12: a challenge minted before a password reset cannot be redeemed after it.
#[tokio::test]
async fn password_reset_purges_the_pending_challenge() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, _secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;

    let _challenge_token = challenge(&app, &email, &password).await;
    assert_eq!(pending_challenge_count(&app.pool, user_id).await, 1);

    let (reset_token, reset_hash) = generate_token();
    sqlx::query(
        "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(reset_hash.as_slice())
    .bind(user_id)
    .bind(Utc::now() + Duration::hours(1))
    .execute(&app.pool)
    .await
    .expect("seed reset token");

    let reset = app
        .post_json_with_ip(
            "/auth/password/reset",
            json!({ "token": reset_token, "new_password": dynamic_password() }),
            &dynamic_ip(),
        )
        .await;
    assert_eq!(
        reset.status(),
        StatusCode::OK,
        "reset failed: {}",
        reset.body_str
    );
    assert_eq!(
        pending_challenge_count(&app.pool, user_id).await,
        0,
        "a committed reset must purge every outstanding challenge token"
    );
}
