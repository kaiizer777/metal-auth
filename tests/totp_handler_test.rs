mod common;

use axum::http::{HeaderMap, Method, StatusCode, header};
use common::*;
use metal_auth::{AppConfig, ErrorCode};
use serde_json::json;
use sqlx::{Connection, PgConnection, PgPool};
use uuid::Uuid;

// ─── Enrollment ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn enroll_requires_auth() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let resp = app.post_json("/auth/totp/enroll", json!({})).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enroll_rejects_unverified_email() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_verified_user(&app).await;
    let session = login(&app, &email, &password).await;
    sqlx::query("UPDATE users SET email_verified = false WHERE email = $1")
        .bind(&email)
        .execute(&app.pool)
        .await
        .expect("unverify email");

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

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(resp.error_code(), Some(ErrorCode::EmailNotVerified));

    let user_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&app.pool)
        .await
        .expect("user row");
    let secrets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM totp_secrets WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&app.pool)
        .await
        .expect("totp secrets count");
    assert_eq!(
        secrets, 0,
        "an unverified enrollment must not create a secret row"
    );
}

#[tokio::test]
async fn enroll_returns_secret_uri_and_ten_backup_codes() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_verified_user(&app).await;
    let session = login(&app, &email, &password).await;

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

    assert_eq!(resp.status(), StatusCode::OK, "body: {}", resp.body_str);
    assert!(
        resp.json["secret_base32"]
            .as_str()
            .is_some_and(|secret| !secret.is_empty())
    );
    assert!(
        resp.json["otpauth_uri"]
            .as_str()
            .is_some_and(|uri| uri.starts_with("otpauth://totp/"))
    );
    let backup_codes = resp.json["backup_codes"]
        .as_array()
        .expect("backup_codes array");
    assert_eq!(backup_codes.len(), 10);
    let distinct: std::collections::HashSet<&str> = backup_codes
        .iter()
        .map(|code| code.as_str().expect("backup code string"))
        .collect();
    assert_eq!(distinct.len(), 10, "backup codes must be distinct");
    assert!(
        distinct.iter().all(|code| !code.is_empty()),
        "backup codes must not be empty"
    );
}

#[tokio::test]
async fn enroll_rejects_already_enabled() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (_email, _password, _secret, _backup_codes, session) =
        enabled_user(&app, &dynamic_ip()).await;

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

    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(resp.error_code(), Some(ErrorCode::TotpAlreadyEnabled));
}

#[tokio::test]
async fn enroll_rate_limits_the_user_dimension() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app_with(|cfg| {
        cfg.totp.rate_limit_user_max_attempts = 3;
    })
    .await
    else {
        return;
    };

    let (email, password) = create_verified_user(&app).await;
    let session = login(&app, &email, &password).await;

    for attempt in 0..3 {
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
        assert_eq!(resp.status(), StatusCode::OK, "attempt {attempt}: {resp:?}");
    }

    let rejected = app
        .dispatch(session_request(
            &app,
            Method::POST,
            "/auth/totp/enroll",
            json!({}),
            &session,
            &dynamic_ip(),
        ))
        .await;
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        rejected.error_code(),
        Some(ErrorCode::TotpRateLimitExceeded)
    );
    let retry_after: u64 = rejected
        .header("retry-after")
        .expect("a 429 must advertise Retry-After")
        .parse()
        .expect("Retry-After is whole seconds");
    assert!((1..=app.state.config.totp.rate_limit_window_secs).contains(&retry_after));
}

#[tokio::test]
async fn enroll_rate_limits_the_ip_dimension() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app_with(|cfg| {
        cfg.totp.rate_limit_ip_max_attempts = 3;
    })
    .await
    else {
        return;
    };

    let (email, password) = create_verified_user(&app).await;
    let session = login(&app, &email, &password).await;
    let ip = dynamic_ip();

    for attempt in 0..3 {
        let resp = app
            .dispatch(session_request(
                &app,
                Method::POST,
                "/auth/totp/enroll",
                json!({}),
                &session,
                &ip,
            ))
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "attempt {attempt}: {resp:?}");
    }

    let rejected = app
        .dispatch(session_request(
            &app,
            Method::POST,
            "/auth/totp/enroll",
            json!({}),
            &session,
            &ip,
        ))
        .await;
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        rejected.error_code(),
        Some(ErrorCode::TotpRateLimitExceeded)
    );
}

// ─── Confirmation ────────────────────────────────────────────────────────────

#[tokio::test]
async fn confirm_requires_auth() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let resp = app
        .post_json("/auth/totp/confirm", json!({ "code": "000000" }))
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn confirm_rejects_invalid_code() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_verified_user(&app).await;
    let session = login(&app, &email, &password).await;
    enroll(&app, &session, &dynamic_ip()).await;

    let resp = app
        .dispatch(session_request(
            &app,
            Method::POST,
            "/auth/totp/confirm",
            json!({ "code": "000000" }),
            &session,
            &dynamic_ip(),
        ))
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(resp.error_code(), Some(ErrorCode::TotpCodeInvalid));
}

#[tokio::test]
async fn confirm_enables_totp_and_rejects_repeat() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_verified_user(&app).await;
    let session = login(&app, &email, &password).await;
    let enrollment = enroll(&app, &session, &dynamic_ip()).await;
    let secret = enrollment["secret_base32"].as_str().expect("secret");

    let first = confirm(&app, &session, secret, &dynamic_ip()).await;
    assert_eq!(first.status(), StatusCode::OK, "body: {}", first.body_str);
    assert_eq!(first.json["message"], json!("totp confirmed"));

    let second = confirm(&app, &session, secret, &dynamic_ip()).await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
    assert_eq!(second.error_code(), Some(ErrorCode::TotpAlreadyEnabled));
}

#[tokio::test]
async fn confirm_rate_limits_its_own_dimension() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_verified_user(&app).await;
    let session = login(&app, &email, &password).await;
    enroll(&app, &session, &dynamic_ip()).await;
    let ip = dynamic_ip();

    let mut rejected_codes = 0u32;
    let mut tripped = false;
    for _ in 0..6 {
        let resp = app
            .dispatch(session_request(
                &app,
                Method::POST,
                "/auth/totp/confirm",
                json!({ "code": "000000" }),
                &session,
                &ip,
            ))
            .await;
        match resp.status() {
            StatusCode::BAD_REQUEST => {
                assert_eq!(resp.error_code(), Some(ErrorCode::TotpCodeInvalid));
                rejected_codes += 1;
            }
            StatusCode::TOO_MANY_REQUESTS => {
                assert_eq!(resp.error_code(), Some(ErrorCode::TotpRateLimitExceeded));
                tripped = true;
                break;
            }
            other => panic!("unexpected {other}: {}", resp.body_str),
        }
    }

    assert!(tripped, "the user budget must trip within six attempts");
    assert_eq!(
        rejected_codes, app.state.config.totp.rate_limit_user_max_attempts,
        "confirm has its own budget, so the enrollment attempt it just spent is not charged"
    );
}

#[tokio::test]
async fn confirm_does_not_spend_the_enrollment_budget() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    let max = app.state.config.totp.rate_limit_user_max_attempts;

    // An enrollment reroll loop spends the whole enrollment budget...
    let (email, password) = create_verified_user(&app).await;
    let session = login(&app, &email, &password).await;
    let ip = dynamic_ip();
    for _ in 0..max {
        enroll(&app, &session, &ip).await;
    }

    // ...and the first code check still reaches the verifier instead of a 429.
    let confirm_response = app
        .dispatch(session_request(
            &app,
            Method::POST,
            "/auth/totp/confirm",
            json!({ "code": "000000" }),
            &session,
            &ip,
        ))
        .await;
    assert_eq!(
        confirm_response.status(),
        StatusCode::BAD_REQUEST,
        "a spent enrollment budget must not reject confirmation: {}",
        confirm_response.body_str
    );
    assert_eq!(
        confirm_response.error_code(),
        Some(ErrorCode::TotpCodeInvalid)
    );

    // The mirror: a spent confirmation budget leaves enrollment its own attempts.
    let (email, password) = create_verified_user(&app).await;
    let session = login(&app, &email, &password).await;
    let ip = dynamic_ip();
    enroll(&app, &session, &ip).await;
    for _ in 0..max {
        let resp = app
            .dispatch(session_request(
                &app,
                Method::POST,
                "/auth/totp/confirm",
                json!({ "code": "000000" }),
                &session,
                &ip,
            ))
            .await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "body: {}",
            resp.body_str
        );
    }
    let tripped = app
        .dispatch(session_request(
            &app,
            Method::POST,
            "/auth/totp/confirm",
            json!({ "code": "000000" }),
            &session,
            &ip,
        ))
        .await;
    assert_eq!(
        tripped.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the confirmation budget must still trip"
    );
    enroll(&app, &session, &ip).await;
}

// ─── CSRF (R15) ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn protected_routes_reject_missing_csrf_token() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_verified_user(&app).await;
    let session = login(&app, &email, &password).await;

    for (method, uri) in [
        (Method::POST, "/auth/totp/enroll"),
        (Method::POST, "/auth/totp/confirm"),
        (Method::DELETE, "/auth/totp"),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{}={}; csrf_token={}",
                app.state.config.session.cookie_name, session.sid, session.csrf
            )
            .parse()
            .expect("valid cookie header"),
        );
        let req = json_request_with_headers(method, uri, json!({}), headers);
        let resp = app.dispatch(req).await;

        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{uri} must be CSRF protected"
        );
        assert_eq!(resp.error_code(), Some(ErrorCode::CsrfTokenMissing));
    }
}

#[tokio::test]
async fn verify_and_backup_ignore_an_ambient_session_cookie() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, secret, backup_codes, session) = enabled_user(&app, &dynamic_ip()).await;
    let cookie_name = app.state.config.session.cookie_name.clone();
    let cookie = format!(
        "{}={}; csrf_token={}",
        cookie_name, session.sid, session.csrf
    );

    // Deliberately no `x-csrf-token`: the CSRF middleware would reject a two-of-three
    // request, so a 200 proves these routes stay outside the protected router.
    let token = challenge(&app, &email, &password).await;
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, cookie.parse().expect("cookie header"));
    let req = json_request_with_headers(
        Method::POST,
        "/auth/totp/verify",
        json!({ "challenge_token": token, "code": totp_code(&secret) }),
        headers,
    );
    let verify = app.dispatch(req).await;
    assert_eq!(
        verify.status(),
        StatusCode::OK,
        "verify must stay outside CSRF: {}",
        verify.body_str
    );

    let token = challenge(&app, &email, &password).await;
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, cookie.parse().expect("cookie header"));
    let req = json_request_with_headers(
        Method::POST,
        "/auth/totp/backup",
        json!({ "challenge_token": token, "code": backup_codes[0].clone() }),
        headers,
    );
    let backup = app.dispatch(req).await;
    assert_eq!(
        backup.status(),
        StatusCode::OK,
        "backup must stay outside CSRF: {}",
        backup.body_str
    );
}

#[tokio::test]
async fn verify_with_an_ambient_cookie_reaches_the_code_check() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, _secret, _backup_codes, session) =
        enabled_user(&app, &dynamic_ip()).await;
    let token = challenge(&app, &email, &password).await;

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
    let req = json_request_with_headers(
        Method::POST,
        "/auth/totp/verify",
        json!({ "challenge_token": token, "code": "000000" }),
        headers,
    );
    let resp = app.dispatch(req).await;

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "body: {}",
        resp.body_str
    );
    assert_eq!(resp.error_code(), Some(ErrorCode::TotpCodeInvalid));
}

// ─── Verification ────────────────────────────────────────────────────────────

#[tokio::test]
async fn verify_issues_a_working_session() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let token = challenge(&app, &email, &password).await;

    let resp = app
        .post_json(
            "/auth/totp/verify",
            json!({ "challenge_token": token, "code": totp_code(&secret) }),
        )
        .await;

    assert_eq!(resp.status(), StatusCode::OK, "body: {}", resp.body_str);
    assert!(resp.json["user_id"].is_string());

    let cookie_name = app.state.config.session.cookie_name.clone();
    let sid = extract_cookie_val(&resp.headers, &cookie_name).expect("session cookie");
    let sid_header =
        extract_cookie_header_string(&resp.headers, &cookie_name).expect("session Set-Cookie");
    assert!(sid_header.contains("HttpOnly"));
    assert!(sid_header.contains("SameSite=Lax"));
    assert!(sid_header.contains("Path=/"));

    let csrf_header =
        extract_cookie_header_string(&resp.headers, "csrf_token").expect("csrf Set-Cookie");
    assert!(!csrf_header.contains("HttpOnly"));
    assert!(csrf_header.contains("SameSite=Strict"));

    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("{cookie_name}={sid}")
            .parse()
            .expect("cookie header"),
    );
    let session_resp = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            headers,
        ))
        .await;
    assert_eq!(
        session_resp.status(),
        StatusCode::OK,
        "body: {}",
        session_resp.body_str
    );
    assert_eq!(
        session_resp.json["session_id"]
            .as_str()
            .expect("session id")
            .len(),
        64
    );
}

#[tokio::test]
async fn verify_issues_a_bearer_token_without_cookies() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let token = challenge(&app, &email, &password).await;

    let mut headers = HeaderMap::new();
    headers.insert("x-auth-type", "bearer".parse().expect("bearer header"));
    let req = json_request_with_headers(
        Method::POST,
        "/auth/totp/verify",
        json!({ "challenge_token": token, "code": totp_code(&secret) }),
        headers,
    );
    let resp = app.dispatch(req).await;

    assert_eq!(resp.status(), StatusCode::OK, "body: {}", resp.body_str);
    assert!(resp.json["user_id"].is_string());
    assert!(
        !resp.headers.contains_key(header::SET_COOKIE),
        "a bearer verify must not set cookies"
    );
    let raw_token = resp.json["token"].as_str().expect("bearer token");

    let mut bearer = HeaderMap::new();
    bearer.insert(
        header::AUTHORIZATION,
        format!("Bearer {raw_token}")
            .parse()
            .expect("authorization header"),
    );
    let session = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            bearer,
        ))
        .await;
    assert_eq!(
        session.status(),
        StatusCode::OK,
        "body: {}",
        session.body_str
    );
    assert_eq!(session.json["session_type"], json!("bearer"));
}

#[tokio::test]
async fn verify_rejects_unknown_challenge_token() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let resp = app
        .post_json(
            "/auth/totp/verify",
            json!({ "challenge_token": "00".repeat(32), "code": "000000" }),
        )
        .await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.error_code(), Some(ErrorCode::TwoFactorTokenInvalid));
}

#[tokio::test]
async fn verify_rejects_invalid_code() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, _secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let token = challenge(&app, &email, &password).await;

    let resp = app
        .post_json(
            "/auth/totp/verify",
            json!({ "challenge_token": token, "code": "000000" }),
        )
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(resp.error_code(), Some(ErrorCode::TotpCodeInvalid));
}

#[tokio::test]
async fn verify_rejects_replayed_code() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let first_token = challenge(&app, &email, &password).await;
    let second_token = challenge(&app, &email, &password).await;

    // Valid across the acceptance window, and the replay hash is code-keyed.
    let code = code_at(
        &secret,
        metal_auth::totp::crypto::current_totp_counter() + 1,
    );

    let first = app
        .post_json(
            "/auth/totp/verify",
            json!({ "challenge_token": first_token, "code": code }),
        )
        .await;
    assert_eq!(first.status(), StatusCode::OK, "body: {}", first.body_str);

    let second = app
        .post_json(
            "/auth/totp/verify",
            json!({ "challenge_token": second_token, "code": code }),
        )
        .await;

    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    assert_eq!(second.error_code(), Some(ErrorCode::TotpCodeReplayed));
}

#[tokio::test]
async fn failed_session_issue_leaves_the_totp_code_unspent() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app_with(|cfg| {
        cfg.totp.rate_limit_ip_max_attempts = 10;
        cfg.totp.rate_limit_user_max_attempts = 10;
    })
    .await
    else {
        return;
    };

    let (email, password, secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let token = challenge(&app, &email, &password).await;
    let code = totp_code(&secret);

    let injection = reject_session_inserts_for(&app.pool, user_id).await;
    let failed = app
        .post_json(
            "/auth/totp/verify",
            json!({ "challenge_token": token, "code": code }),
        )
        .await;
    injection.disarm().await;

    assert_eq!(
        failed.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "body: {}",
        failed.body_str
    );
    assert_eq!(
        used_code_rows(&app.pool, user_id).await,
        0,
        "the replay row must roll back with the failed session"
    );
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        1,
        "the failed redemption must not commit a session"
    );

    let retry = app
        .post_json(
            "/auth/totp/verify",
            json!({ "challenge_token": token, "code": code }),
        )
        .await;
    assert_eq!(
        retry.status(),
        StatusCode::OK,
        "the code and challenge must stay usable: {}",
        retry.body_str
    );
}

#[tokio::test]
async fn verify_rate_limits_ip_dimension() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let ip = dynamic_ip();
    let mut last_status = StatusCode::OK;
    let mut retry_after = None;
    for _ in 0..11 {
        let resp = app
            .post_json_with_ip(
                "/auth/totp/verify",
                json!({ "challenge_token": "00".repeat(32), "code": "000000" }),
                &ip,
            )
            .await;
        last_status = resp.status();
        if last_status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(resp.error_code(), Some(ErrorCode::TotpRateLimitExceeded));
            retry_after = resp.header("retry-after").map(str::to_string);
        }
    }

    assert_eq!(
        last_status,
        StatusCode::TOO_MANY_REQUESTS,
        "the 11th attempt from one IP must trip `totp:ip`"
    );
    let retry_after: u64 = retry_after
        .expect("a 429 must advertise Retry-After")
        .parse()
        .expect("Retry-After is whole seconds");
    assert!(
        (1..=app.state.config.totp.rate_limit_window_secs).contains(&retry_after),
        "Retry-After must stay inside the configured window"
    );
}

#[tokio::test]
async fn verify_rate_limits_user_dimension() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, _secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let token = challenge(&app, &email, &password).await;

    // Enrollment spends only the `totp:enroll:*` dimensions, so the whole user budget is
    // available to verification; a fresh IP per attempt keeps the dimensions isolated.
    let mut rejected_codes = 0;
    let mut tripped = None;
    for _ in 0..6 {
        let resp = app
            .post_json_with_ip(
                "/auth/totp/verify",
                json!({ "challenge_token": token, "code": "000000" }),
                &dynamic_ip(),
            )
            .await;
        match resp.status() {
            StatusCode::BAD_REQUEST => {
                assert_eq!(resp.error_code(), Some(ErrorCode::TotpCodeInvalid));
                rejected_codes += 1;
            }
            StatusCode::TOO_MANY_REQUESTS => {
                assert_eq!(resp.error_code(), Some(ErrorCode::TotpRateLimitExceeded));
                let retry_after: u64 = resp
                    .header("retry-after")
                    .expect("a 429 must advertise Retry-After")
                    .parse()
                    .expect("Retry-After is whole seconds");
                assert!(
                    (1..=app.state.config.totp.rate_limit_window_secs).contains(&retry_after),
                    "Retry-After must stay inside the configured window"
                );
                tripped = Some(());
                break;
            }
            other => panic!("unexpected {other}: {}", resp.body_str),
        }
    }

    assert!(
        tripped.is_some(),
        "the user budget must trip within six attempts"
    );
    assert_eq!(
        rejected_codes, app.state.config.totp.rate_limit_user_max_attempts,
        "enrollment uses its own dimension, so verify must admit the whole user budget"
    );
}

#[tokio::test]
async fn verify_checks_ip_before_the_token_and_keeps_dimensions_separate() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, _secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let token = challenge(&app, &email, &password).await;
    let ip = dynamic_ip();

    for attempt in 0..11 {
        let resp = app
            .post_json_with_ip(
                "/auth/totp/verify",
                json!({ "challenge_token": "00".repeat(32), "code": "000000" }),
                &ip,
            )
            .await;
        let expected = if attempt < 10 {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::TOO_MANY_REQUESTS
        };
        assert_eq!(
            resp.status(),
            expected,
            "attempt {attempt}: {}",
            resp.body_str
        );
    }

    // IP check precedes token validation: an unparsable token from an exhausted IP is
    // still a 429, not a 401.
    let resp = app
        .post_json_with_ip(
            "/auth/totp/verify",
            json!({ "challenge_token": "00".repeat(32), "code": "000000" }),
            &ip,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    // A valid challenge from the exhausted IP is rejected without being consumed.
    let resp = app
        .post_json_with_ip(
            "/auth/totp/verify",
            json!({ "challenge_token": token, "code": "000000" }),
            &ip,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    // Same token, fresh IP: not consumed by the IP rejection, and the user budget was
    // not charged by those rejections either (a 429 here would prove cross-consumption).
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
        "body: {}",
        resp.body_str
    );
    assert_eq!(resp.error_code(), Some(ErrorCode::TotpCodeInvalid));
}

// ─── Backup codes ────────────────────────────────────────────────────────────

#[tokio::test]
async fn backup_issues_a_working_session_and_consumes_the_code() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, _secret, backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let code = backup_codes[0].clone();
    let token = challenge(&app, &email, &password).await;

    let resp = app
        .post_json(
            "/auth/totp/backup",
            json!({ "challenge_token": token, "code": code }),
        )
        .await;

    assert_eq!(resp.status(), StatusCode::OK, "body: {}", resp.body_str);
    let cookie_name = app.state.config.session.cookie_name.clone();
    let sid = extract_cookie_val(&resp.headers, &cookie_name).expect("session cookie");

    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("{cookie_name}={sid}")
            .parse()
            .expect("cookie header"),
    );
    let session_resp = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            headers,
        ))
        .await;
    assert_eq!(session_resp.status(), StatusCode::OK);

    let second_token = challenge(&app, &email, &password).await;
    let reuse = app
        .post_json(
            "/auth/totp/backup",
            json!({ "challenge_token": second_token, "code": code }),
        )
        .await;
    assert_eq!(reuse.status(), StatusCode::BAD_REQUEST);
    assert_eq!(reuse.error_code(), Some(ErrorCode::TotpBackupCodeInvalid));
}

#[tokio::test]
async fn keyless_deployment_serves_backup_codes_and_fails_the_totp_leg_closed() {
    let _guard = DB_LOCK.lock().await;
    // Enrollment needs the key, so it runs on a keyed app; redemption runs on a keyless one
    // against the same database.
    let Some(keyed) = setup_test_app().await else {
        return;
    };
    let (email, password, secret, backup_codes, _session) =
        enabled_user(&keyed, &dynamic_ip()).await;

    let Some(keyless) = setup_test_app_with(|cfg| cfg.totp.encryption_key = None).await else {
        return;
    };
    let user_id = user_id_for_email(&keyless.pool, &email).await;
    let sessions_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&keyless.pool)
            .await
            .expect("count sessions");
    let token = challenge(&keyless, &email, &password).await;

    // TOTP-code leg: the stored secret cannot be decrypted, so it fails closed without
    // revealing anything about the presented code and without a session.
    let resp = keyless
        .post_json(
            "/auth/totp/verify",
            json!({ "challenge_token": token, "code": totp_code(&secret) }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.error_code(), Some(ErrorCode::TwoFactorUnavailable));
    let sessions_after_rejection: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&keyless.pool)
            .await
            .expect("count sessions");
    assert_eq!(
        sessions_after_rejection, sessions_before,
        "the failed TOTP leg must not mint a session"
    );

    // Backup-code leg: Argon2id matching never touches the encryption key, so recovery still
    // works and the challenge token is intact.
    let resp = keyless
        .post_json(
            "/auth/totp/backup",
            json!({ "challenge_token": token, "code": backup_codes[0].clone() }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "body: {}", resp.body_str);
    let cookie_name = keyless.state.config.session.cookie_name.clone();
    assert!(
        extract_cookie_val(&resp.headers, &cookie_name).is_some(),
        "backup-code recovery must still mint a session without the key"
    );
}

#[tokio::test]
async fn backup_rejects_unknown_challenge_token() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let resp = app
        .post_json(
            "/auth/totp/backup",
            json!({ "challenge_token": "00".repeat(32), "code": "AAAAAAAAAAAAAAAA" }),
        )
        .await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.error_code(), Some(ErrorCode::TwoFactorTokenInvalid));
}

#[tokio::test]
async fn backup_rejects_unknown_code() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, _secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let token = challenge(&app, &email, &password).await;

    let resp = app
        .post_json(
            "/auth/totp/backup",
            json!({ "challenge_token": token, "code": "AAAAAAAAAAAAAAAA" }),
        )
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(resp.error_code(), Some(ErrorCode::TotpBackupCodeInvalid));
}

#[tokio::test]
async fn failed_session_issue_leaves_the_backup_code_unspent() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app_with(|cfg| {
        cfg.totp.rate_limit_ip_max_attempts = 10;
        cfg.totp.rate_limit_user_max_attempts = 10;
    })
    .await
    else {
        return;
    };

    let (email, password, _secret, backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let code = backup_codes[0].clone();
    let token = challenge(&app, &email, &password).await;

    let injection = reject_session_inserts_for(&app.pool, user_id).await;
    let failed = app
        .post_json(
            "/auth/totp/backup",
            json!({ "challenge_token": token, "code": code }),
        )
        .await;
    injection.disarm().await;

    assert_eq!(
        failed.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "body: {}",
        failed.body_str
    );
    assert_eq!(
        stored_backup_code_count(&app.pool, user_id).await,
        10,
        "a single-use code must never be spent without a session"
    );
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        1,
        "the failed redemption must not commit a session"
    );

    let retry = app
        .post_json(
            "/auth/totp/backup",
            json!({ "challenge_token": token, "code": code }),
        )
        .await;
    assert_eq!(
        retry.status(),
        StatusCode::OK,
        "the backup code and challenge must stay usable: {}",
        retry.body_str
    );
}

// ─── Disable ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn disable_requires_auth() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let req = json_request(Method::DELETE, "/auth/totp", json!({}));
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn disable_requires_exactly_one_proof() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (_email, password, _secret, _backup_codes, session) =
        enabled_user(&app, &dynamic_ip()).await;

    // More malformed bodies than the user budget: rejection must happen before the
    // limiter is consulted, so none of them may come back as 429.
    let attempts = app.state.config.totp.rate_limit_user_max_attempts + 1;
    for _ in 0..attempts {
        for body in [
            json!({}),
            json!({ "password": "" }),
            json!({ "password": password, "totp_code": "000000" }),
        ] {
            let resp = app
                .dispatch(session_request(
                    &app,
                    Method::DELETE,
                    "/auth/totp",
                    body,
                    &session,
                    &dynamic_ip(),
                ))
                .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            assert_eq!(resp.error_code(), Some(ErrorCode::ValidationError));
        }
    }
}

#[tokio::test]
async fn disable_rejects_wrong_password() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (_email, _password, _secret, _backup_codes, session) =
        enabled_user(&app, &dynamic_ip()).await;

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

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.error_code(), Some(ErrorCode::InvalidCredentials));
}

#[tokio::test]
async fn disable_rejects_wrong_totp_code() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, secret, _backup_codes, session) = enabled_user(&app, &dynamic_ip()).await;
    // Three steps ahead of the ±1 acceptance window: never a valid code.
    let wrong_code = code_at(
        &secret,
        metal_auth::totp::crypto::current_totp_counter() + 3,
    );

    let resp = app
        .dispatch(session_request(
            &app,
            Method::DELETE,
            "/auth/totp",
            json!({ "totp_code": wrong_code }),
            &session,
            &dynamic_ip(),
        ))
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(resp.error_code(), Some(ErrorCode::TotpCodeInvalid));

    let user_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&app.pool)
        .await
        .expect("user row");
    let secrets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM totp_secrets WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&app.pool)
        .await
        .expect("totp secrets count");
    assert_eq!(secrets, 1, "a rejected code must leave 2FA enabled");

    let login_resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(login_resp.status(), StatusCode::OK);
    assert_eq!(login_resp.json["two_factor_required"], json!(true));
}

#[tokio::test]
async fn login_without_a_mintable_challenge_reports_authentication_unavailable() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, _secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let sessions_before = count_sessions_for_user(&app.pool, user_id).await;

    let injection = reject_challenge_inserts_for(&app.pool, user_id).await;
    let refused = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    injection.disarm().await;

    assert_eq!(
        refused.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a login that cannot mint a challenge is a server fault: {}",
        refused.body_str
    );
    assert_eq!(refused.error_code(), Some(ErrorCode::TwoFactorUnavailable));
    assert!(
        refused.header("set-cookie").is_none(),
        "a refused challenge must not carry a session cookie"
    );
    assert_eq!(
        count_sessions_for_user(&app.pool, user_id).await,
        sessions_before,
        "the refused login must not mint a session"
    );
}

#[tokio::test]
async fn disable_with_password_drops_the_login_challenge() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, _secret, _backup_codes, session) =
        enabled_user(&app, &dynamic_ip()).await;

    let resp = app
        .dispatch(session_request(
            &app,
            Method::DELETE,
            "/auth/totp",
            json!({ "password": password }),
            &session,
            &dynamic_ip(),
        ))
        .await;

    assert_eq!(resp.status(), StatusCode::OK, "body: {}", resp.body_str);
    assert_eq!(
        resp.json["message"],
        json!("two-factor authentication disabled")
    );

    let login_resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(login_resp.status(), StatusCode::OK);
    assert!(login_resp.json.get("two_factor_required").is_none());
    assert!(login_resp.json["user_id"].is_string());
}

#[tokio::test]
async fn disable_with_totp_code() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, secret, _backup_codes, session) = enabled_user(&app, &dynamic_ip()).await;

    let resp = app
        .dispatch(session_request(
            &app,
            Method::DELETE,
            "/auth/totp",
            json!({ "totp_code": totp_code(&secret) }),
            &session,
            &dynamic_ip(),
        ))
        .await;

    assert_eq!(resp.status(), StatusCode::OK, "body: {}", resp.body_str);

    let login_resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(login_resp.status(), StatusCode::OK);
    assert!(login_resp.json.get("two_factor_required").is_none());
}

#[tokio::test]
async fn disable_rejects_a_code_spent_on_the_login_leg() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, secret, _backup_codes, session) = enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let code = totp_code(&secret);

    // A sniffed code buys one login; it must not also remove the second factor.
    let token = challenge(&app, &email, &password).await;
    let login = app
        .post_json(
            "/auth/totp/verify",
            json!({ "challenge_token": token, "code": code }),
        )
        .await;
    assert_eq!(login.status(), StatusCode::OK, "body: {}", login.body_str);

    let disable = app
        .dispatch(session_request(
            &app,
            Method::DELETE,
            "/auth/totp",
            json!({ "totp_code": code }),
            &session,
            &dynamic_ip(),
        ))
        .await;

    assert_eq!(
        disable.status(),
        StatusCode::BAD_REQUEST,
        "body: {}",
        disable.body_str
    );
    assert_eq!(disable.error_code(), Some(ErrorCode::TotpCodeReplayed));
    assert!(
        totp_enabled(&app.pool, user_id).await,
        "a code already spent at login must not disable the factor"
    );
}

#[tokio::test]
async fn failed_disable_keeps_the_totp_proof_retryable() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app_with(|cfg| {
        cfg.totp.rate_limit_ip_max_attempts = 10;
        cfg.totp.rate_limit_user_max_attempts = 10;
    })
    .await
    else {
        return;
    };

    let (email, _password, secret, _backup_codes, session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let code = totp_code(&secret);

    let injection = reject_factor_deletes_for(&app.pool, user_id).await;
    let failed = app
        .dispatch(session_request(
            &app,
            Method::DELETE,
            "/auth/totp",
            json!({ "totp_code": code }),
            &session,
            &dynamic_ip(),
        ))
        .await;
    injection.disarm().await;

    assert_eq!(
        failed.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "body: {}",
        failed.body_str
    );
    assert!(
        totp_enabled(&app.pool, user_id).await,
        "a rolled-back disable must leave the factor enabled"
    );
    assert_eq!(
        used_code_rows(&app.pool, user_id).await,
        0,
        "the proof's replay row must roll back with the failed disable"
    );

    let retry = app
        .dispatch(session_request(
            &app,
            Method::DELETE,
            "/auth/totp",
            json!({ "totp_code": code }),
            &session,
            &dynamic_ip(),
        ))
        .await;
    assert_eq!(
        retry.status(),
        StatusCode::OK,
        "a rolled-back disable must not report the still-valid code as replayed: {}",
        retry.body_str
    );
    assert!(!totp_enabled(&app.pool, user_id).await);
}

// ─── Failure injection ───────────────────────────────────────────────────────

/// A panicking assertion must not leave the injected trigger behind for the next test.
#[tokio::test]
async fn injected_trigger_is_removed_when_an_assertion_panics() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, _password, _secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;

    let armed = std::sync::Mutex::new(Some(reject_challenge_inserts_for(&app.pool, user_id).await));
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _injection = armed.lock().expect("injection slot").take().expect("armed");
        panic!("simulated assertion failure");
    }));
    assert!(unwound.is_err(), "the simulated assertion must unwind");

    let triggers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_trigger WHERE tgname = $1")
        .bind(CHALLENGE_INSERT.name)
        .fetch_one(&app.pool)
        .await
        .expect("count triggers");
    assert_eq!(
        triggers, 0,
        "an unwinding assertion must still remove the injected trigger"
    );

    // A later test installs the same name: it must not collide with a leftover.
    reject_challenge_inserts_for(&app.pool, user_id)
        .await
        .disarm()
        .await;
}

/// Where an injected failure fires, and the name its trigger and function share.
struct InjectionTarget {
    name: &'static str,
    table: &'static str,
    event: &'static str,
    /// Row variable the per-user predicate reads; `DELETE` has only `OLD`.
    row: &'static str,
}

/// Make `sessions` inserts fail for one user, so a redemption fails after its factor is
/// verified without any test-only branch in production code.
const SESSION_INSERT: InjectionTarget = InjectionTarget {
    name: "totp_test_reject_session",
    table: "sessions",
    event: "INSERT",
    row: "NEW",
};

/// Make `two_factor_tokens` inserts fail for one user, so a login cannot mint its challenge.
const CHALLENGE_INSERT: InjectionTarget = InjectionTarget {
    name: "totp_test_reject_challenge",
    table: "two_factor_tokens",
    event: "INSERT",
    row: "NEW",
};

/// Make `totp_secrets` deletes fail for one user, so a disable fails after its proof.
const SECRET_DELETE: InjectionTarget = InjectionTarget {
    name: "totp_test_reject_secret_delete",
    table: "totp_secrets",
    event: "DELETE",
    row: "OLD",
};

/// An injected failure, removed when it goes out of scope.
///
/// `Drop` cannot await, and blocking a current-thread test runtime would stall the driver
/// the pool's sockets are registered on, so an armed guard opens its own connection on a
/// scratch thread and finishes the drops there. A panicking assertion therefore cannot
/// leave the trigger behind to collide with the next test in this binary.
struct FailureInjection {
    pool: PgPool,
    name: &'static str,
    table: &'static str,
    armed: bool,
}

impl FailureInjection {
    async fn install(
        pool: &PgPool,
        target: &InjectionTarget,
        raise_message: &str,
        user_id: Uuid,
    ) -> Self {
        let InjectionTarget {
            name,
            table,
            event,
            row,
        } = *target;
        let create_function = format!(
            "CREATE OR REPLACE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql \
             AS $$ BEGIN RAISE EXCEPTION '{raise_message}'; END $$"
        );
        // The only interpolated value is a `Uuid`; a trigger predicate cannot take binds.
        let create_trigger = format!(
            "CREATE TRIGGER {name} BEFORE {event} ON {table} FOR EACH ROW \
             WHEN ({row}.user_id = '{user_id}') EXECUTE FUNCTION {name}()"
        );
        // A process killed before its guard dropped leaves the trigger behind; clear the
        // name first so a later run can install the same injection.
        let drop_trigger = format!("DROP TRIGGER IF EXISTS {name} ON {table}");
        for statement in [drop_trigger, create_function, create_trigger] {
            sqlx::query(sqlx::AssertSqlSafe(statement))
                .execute(pool)
                .await
                .expect("install failure injection");
        }
        Self {
            // Arc-backed handle; the guard outlives the call and needs its own.
            pool: pool.clone(),
            name,
            table,
            armed: true,
        }
    }

    /// Remove the injection now, on a path that is about to assert.
    async fn disarm(mut self) {
        self.armed = false;
        for statement in self.drop_statements() {
            sqlx::query(sqlx::AssertSqlSafe(statement))
                .execute(&self.pool)
                .await
                .expect("drop failure injection");
        }
    }

    fn drop_statements(&self) -> [String; 2] {
        [
            format!("DROP TRIGGER IF EXISTS {} ON {}", self.name, self.table),
            format!("DROP FUNCTION IF EXISTS {}()", self.name),
        ]
    }
}

impl Drop for FailureInjection {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let options = self.pool.connect_options();
        let statements = self.drop_statements();
        // Wait for the cleanup: the next test takes `DB_LOCK` only after this frame has
        // finished unwinding.
        let cleanup = std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    eprintln!("failure injection cleanup skipped: {error}");
                    return;
                }
            };
            let dropped = runtime.block_on(async move {
                let mut connection = PgConnection::connect_with(&options).await?;
                for statement in statements {
                    sqlx::query(sqlx::AssertSqlSafe(statement))
                        .execute(&mut connection)
                        .await?;
                }
                Ok::<(), sqlx::Error>(())
            });
            if let Err(error) = dropped {
                eprintln!("failure injection cleanup failed: {error}");
            }
        });
        if cleanup.join().is_err() {
            eprintln!("failure injection cleanup thread panicked");
        }
    }
}

async fn reject_session_inserts_for(pool: &PgPool, user_id: Uuid) -> FailureInjection {
    FailureInjection::install(
        pool,
        &SESSION_INSERT,
        "injected session insert failure",
        user_id,
    )
    .await
}

async fn reject_challenge_inserts_for(pool: &PgPool, user_id: Uuid) -> FailureInjection {
    FailureInjection::install(
        pool,
        &CHALLENGE_INSERT,
        "injected challenge insert failure",
        user_id,
    )
    .await
}

async fn reject_factor_deletes_for(pool: &PgPool, user_id: Uuid) -> FailureInjection {
    FailureInjection::install(
        pool,
        &SECRET_DELETE,
        "injected factor delete failure",
        user_id,
    )
    .await
}

async fn used_code_rows(pool: &PgPool, user_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM totp_used_codes WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("count used codes")
}

async fn stored_backup_code_count(pool: &PgPool, user_id: Uuid) -> i32 {
    sqlx::query_scalar(
        "SELECT jsonb_array_length(backup_codes) FROM totp_secrets WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .expect("count backup codes")
}

async fn totp_enabled(pool: &PgPool, user_id: Uuid) -> bool {
    sqlx::query_scalar("SELECT enabled FROM totp_secrets WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .expect("read factor state")
        .unwrap_or_default()
}

// ─── Harness invariants ──────────────────────────────────────────────────────

#[test]
fn test_auth_config_uses_the_validator_floor() {
    let config = test_auth_config();
    assert_eq!(config.argon2_m_cost, 19456);
    assert_eq!(config.argon2_t_cost, 2);
    assert_eq!(config.argon2_p_cost, 1);
    assert!(config.validate().is_ok());

    let production = AppConfig::default();
    assert_eq!(production.argon2_m_cost, 65536);
    assert_eq!(production.argon2_t_cost, 3);
    assert_eq!(production.argon2_p_cost, 4);
}
