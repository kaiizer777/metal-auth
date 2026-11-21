//! Security-regression scenarios for TOTP two-factor authentication.
//!
//! Every test here is a negative path from the Phase 7 Tier 4 list, driven through the
//! real router and PostgreSQL. Positive handler coverage lives in `totp_handler_test.rs`.

mod common;

use std::sync::Arc;

use axum::http::{HeaderMap, Method, StatusCode, header};
use common::*;
use metal_auth::{ErrorCode, RateLimiter};
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
    headers.insert(
        "x-csrf-token",
        session.csrf.parse().expect("csrf header"),
    );
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

    let (email, password, _secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let token = challenge(&app, &email, &password).await;

    // Confirmation already spent one attempt on this user; clear it so the boundary
    // under test is exactly the configured three, not two.
    app.state
        .rate_limiter
        .reset(&RateLimiter::totp_user_key(user_id));

    for attempt in 0..3 {
        let resp = app
            .post_json_with_ip(
                "/auth/totp/verify",
                json!({ "challenge_token": token, "code": "000000" }),
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
            json!({ "challenge_token": token, "code": "000000" }),
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

    // Per-code Argon2id salts make the used hash unidentifiable in-test, so the purge is
    // observable as the count drop plus PHC integrity; reuse rejection is proven in
    // `reused_backup_code_is_rejected`.
    let after = stored_backup_hashes(&app.pool, user_id).await;
    assert_eq!(after.len(), 9, "exactly one hash must be removed");
    assert!(
        after.iter().all(|hash| hash.starts_with("$argon2id$")),
        "the remaining entries must stay Argon2id PHC strings"
    );
    assert!(
        after.iter().all(|hash| !hash.contains(&code)),
        "no stored hash may contain the raw backup code"
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

/// Tier 4 §1: the ±1 step window accepts the next step and rejects two steps out.
#[tokio::test]
async fn clock_drift_accepts_the_next_step_and_rejects_two_steps_out() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, secret, _backup_codes, _session) = enabled_user(&app, &dynamic_ip()).await;
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

    let ahead_token = challenge(&app, &email, &password).await;
    let too_new = code_at(
        &secret,
        metal_auth::totp::crypto::current_totp_counter() + 2,
    );
    let rejected_ahead = app
        .post_json_with_ip(
            "/auth/totp/verify",
            json!({ "challenge_token": ahead_token, "code": too_new }),
            &dynamic_ip(),
        )
        .await;
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

    let behind_token = challenge(&app, &email, &password).await;
    let too_old = code_at(
        &secret,
        metal_auth::totp::crypto::current_totp_counter().saturating_sub(2),
    );
    let rejected_behind = app
        .post_json_with_ip(
            "/auth/totp/verify",
            json!({ "challenge_token": behind_token, "code": too_old }),
            &dynamic_ip(),
        )
        .await;
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
        sessions_before + 1,
        "only the in-window presentation may issue a session"
    );
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
    app.state
        .rate_limiter
        .reset(&RateLimiter::totp_ip_key(&ip));

    for attempt in 0..10 {
        let resp = app
            .post_json_with_ip(
                "/auth/totp/verify",
                json!({ "challenge_token": "00".repeat(32), "code": "000000" }),
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
            json!({ "challenge_token": "00".repeat(32), "code": "000000" }),
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
