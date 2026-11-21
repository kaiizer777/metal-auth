mod common;

use axum::http::{HeaderMap, Method, StatusCode, header};
use common::*;
use metal_auth::{AppConfig, ErrorCode};
use serde_json::json;
use sqlx::PgPool;
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
async fn confirm_rate_limits_enrollment_dimension() {
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
        rejected_codes,
        app.state.config.totp.rate_limit_user_max_attempts - 1,
        "enroll shares the enrollment budget, so confirm must admit the rest of it"
    );
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

    reject_session_inserts_for(&app.pool, user_id).await;
    let failed = app
        .post_json(
            "/auth/totp/verify",
            json!({ "challenge_token": token, "code": code }),
        )
        .await;
    allow_session_inserts(&app.pool).await;

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

    reject_session_inserts_for(&app.pool, user_id).await;
    let failed = app
        .post_json(
            "/auth/totp/backup",
            json!({ "challenge_token": token, "code": code }),
        )
        .await;
    allow_session_inserts(&app.pool).await;

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

    reject_challenge_inserts_for(&app.pool, user_id).await;
    let refused = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    allow_challenge_inserts(&app.pool).await;

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

    reject_factor_deletes_for(&app.pool, user_id).await;
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
    allow_factor_deletes(&app.pool).await;

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
        "disabling must not write a replay row for a proof whose log it deletes"
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

/// Make `sessions` inserts fail for one user, so a redemption fails after its factor is
/// verified without any test-only branch in production code.
async fn reject_session_inserts_for(pool: &PgPool, user_id: Uuid) {
    sqlx::query(
        "CREATE OR REPLACE FUNCTION totp_test_reject_session() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected session insert failure'; END $$",
    )
    .execute(pool)
    .await
    .expect("create session failure function");
    // The only interpolated value is a `Uuid`; a trigger predicate cannot take binds.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE TRIGGER totp_test_reject_session BEFORE INSERT ON sessions \
         FOR EACH ROW WHEN (NEW.user_id = '{user_id}') \
         EXECUTE FUNCTION totp_test_reject_session()"
    )))
    .execute(pool)
    .await
    .expect("create session failure trigger");
}

async fn allow_session_inserts(pool: &PgPool) {
    sqlx::query("DROP TRIGGER IF EXISTS totp_test_reject_session ON sessions")
        .execute(pool)
        .await
        .expect("drop session failure trigger");
    sqlx::query("DROP FUNCTION IF EXISTS totp_test_reject_session()")
        .execute(pool)
        .await
        .expect("drop session failure function");
}

/// Make `two_factor_tokens` inserts fail for one user, so a login cannot mint its challenge.
async fn reject_challenge_inserts_for(pool: &PgPool, user_id: Uuid) {
    sqlx::query(
        "CREATE OR REPLACE FUNCTION totp_test_reject_challenge() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected challenge insert failure'; END $$",
    )
    .execute(pool)
    .await
    .expect("create challenge failure function");
    // The only interpolated value is a `Uuid`; a trigger predicate cannot take binds.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE TRIGGER totp_test_reject_challenge BEFORE INSERT ON two_factor_tokens \
         FOR EACH ROW WHEN (NEW.user_id = '{user_id}') \
         EXECUTE FUNCTION totp_test_reject_challenge()"
    )))
    .execute(pool)
    .await
    .expect("create challenge failure trigger");
}

async fn allow_challenge_inserts(pool: &PgPool) {
    sqlx::query("DROP TRIGGER IF EXISTS totp_test_reject_challenge ON two_factor_tokens")
        .execute(pool)
        .await
        .expect("drop challenge failure trigger");
    sqlx::query("DROP FUNCTION IF EXISTS totp_test_reject_challenge()")
        .execute(pool)
        .await
        .expect("drop challenge failure function");
}

/// Make `totp_secrets` deletes fail for one user, so a disable fails after its proof.
async fn reject_factor_deletes_for(pool: &PgPool, user_id: Uuid) {
    sqlx::query(
        "CREATE OR REPLACE FUNCTION totp_test_reject_secret_delete() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected factor delete failure'; END $$",
    )
    .execute(pool)
    .await
    .expect("create delete failure function");
    // The only interpolated value is a `Uuid`; a trigger predicate cannot take binds.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE TRIGGER totp_test_reject_secret_delete BEFORE DELETE ON totp_secrets \
         FOR EACH ROW WHEN (OLD.user_id = '{user_id}') \
         EXECUTE FUNCTION totp_test_reject_secret_delete()"
    )))
    .execute(pool)
    .await
    .expect("create delete failure trigger");
}

async fn allow_factor_deletes(pool: &PgPool) {
    sqlx::query("DROP TRIGGER IF EXISTS totp_test_reject_secret_delete ON totp_secrets")
        .execute(pool)
        .await
        .expect("drop delete failure trigger");
    sqlx::query("DROP FUNCTION IF EXISTS totp_test_reject_secret_delete()")
        .execute(pool)
        .await
        .expect("drop delete failure function");
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
