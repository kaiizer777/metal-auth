mod common;

use axum::{
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use common::*;
use metal_auth::{AppConfig, ErrorCode, totp::crypto::decode_totp_secret};
use serde_json::json;

struct Session {
    sid: String,
    csrf: String,
}

fn extract_cookie_val(headers: &HeaderMap, name: &str) -> Option<String> {
    for val in headers.get_all(header::SET_COOKIE) {
        if let Ok(s) = val.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some((k, v)) = part.split_once('=')
                    && k.trim() == name
                {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

fn extract_cookie_header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    for val in headers.get_all(header::SET_COOKIE) {
        if let Ok(s) = val.to_str()
            && s.starts_with(&format!("{name}="))
        {
            return Some(s.to_string());
        }
    }
    None
}

/// Current six-digit code for an enrolled base32 secret.
fn totp_code(secret_base32: &str) -> String {
    use metal_auth::totp::crypto::current_totp_counter;
    code_at(secret_base32, current_totp_counter())
}

fn code_at(secret_base32: &str, counter: u64) -> String {
    let secret = decode_totp_secret(secret_base32).expect("valid base32 secret");
    let code = metal_auth::totp::crypto::generate_totp(&secret, counter).expect("code");
    format!("{code:06}")
}

fn session_request(
    app: &TestApp,
    method: Method,
    uri: &str,
    body: serde_json::Value,
    session: &Session,
    ip: &str,
) -> Request<Body> {
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
    headers.insert(
        "x-csrf-token",
        session.csrf.parse().expect("valid csrf header"),
    );
    headers.insert("x-forwarded-for", ip.parse().expect("valid ip header"));
    json_request_with_headers(method, uri, body, headers)
}

async fn create_verified_user(app: &TestApp) -> (String, String) {
    let email = dynamic_email();
    let password = dynamic_password();

    let signup_resp = app
        .post_json(
            "/auth/signup",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(
        signup_resp.status(),
        StatusCode::OK,
        "signup failed: {}",
        signup_resp.body_str
    );

    if let Some(token) = app.email_sender.verification_token_for(&email) {
        let verify_resp = app
            .post_json("/auth/verify", json!({ "token": token }))
            .await;
        assert_eq!(verify_resp.status(), StatusCode::OK);
    }

    sqlx::query("UPDATE users SET email_verified = true WHERE email = $1")
        .bind(&email)
        .execute(&app.pool)
        .await
        .expect("ensure email verified");

    (email, password)
}

async fn login(app: &TestApp, email: &str, password: &str) -> Session {
    let resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "login failed: {}",
        resp.body_str
    );
    Session {
        sid: extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name)
            .expect("session cookie"),
        csrf: extract_cookie_val(&resp.headers, "csrf_token").expect("csrf cookie"),
    }
}

/// Password login for a 2FA user: challenge token, no session cookie.
async fn challenge(app: &TestApp, email: &str, password: &str) -> String {
    let resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "login failed: {}",
        resp.body_str
    );
    assert_eq!(resp.json["two_factor_required"], json!(true));
    assert!(
        !resp.headers.contains_key(header::SET_COOKIE),
        "2FA login must not issue a session cookie"
    );
    resp.json["challenge_token"]
        .as_str()
        .expect("challenge token")
        .to_string()
}

async fn enroll(app: &TestApp, session: &Session, ip: &str) -> serde_json::Value {
    let resp = app
        .dispatch(session_request(
            app,
            Method::POST,
            "/auth/totp/enroll",
            json!({}),
            session,
            ip,
        ))
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "enroll failed: {}",
        resp.body_str
    );
    resp.json.clone()
}

async fn confirm(app: &TestApp, session: &Session, secret: &str, ip: &str) -> TestResponse {
    let code = totp_code(secret);
    app.dispatch(session_request(
        app,
        Method::POST,
        "/auth/totp/confirm",
        json!({ "code": code }),
        session,
        ip,
    ))
    .await
}

/// Create a user, enroll, and confirm so 2FA is enabled.
///
/// Returns the pre-enablement session too: a password login for a 2FA user yields a
/// challenge, not a cookie, so later protected calls must reuse this session.
async fn enabled_user(app: &TestApp, ip: &str) -> (String, String, String, Vec<String>, Session) {
    let (email, password) = create_verified_user(app).await;
    let session = login(app, &email, &password).await;
    let enrollment = enroll(app, &session, ip).await;
    let secret = enrollment["secret_base32"]
        .as_str()
        .expect("secret_base32")
        .to_string();
    let backup_codes: Vec<String> = enrollment["backup_codes"]
        .as_array()
        .expect("backup_codes")
        .iter()
        .map(|code| code.as_str().expect("backup code string").to_string())
        .collect();

    let resp = confirm(app, &session, &secret, ip).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "confirm failed: {}",
        resp.body_str
    );

    (email, password, secret, backup_codes, session)
}

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
    assert_eq!(
        resp.json["backup_codes"]
            .as_array()
            .expect("backup_codes array")
            .len(),
        10
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
async fn confirm_rate_limits_user_dimension() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_verified_user(&app).await;
    let session = login(&app, &email, &password).await;
    enroll(&app, &session, &dynamic_ip()).await;
    let ip = dynamic_ip();

    let mut last_status = StatusCode::OK;
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
        last_status = resp.status();
        if last_status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(resp.error_code(), Some(ErrorCode::TotpRateLimitExceeded));
        }
    }

    assert_eq!(last_status, StatusCode::TOO_MANY_REQUESTS);
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

    // Confirm already spent one of the five user attempts, so four rejected codes fit
    // before the budget trips; a fresh IP per attempt keeps the dimension isolated.
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
        rejected_codes, 4,
        "the user dimension must admit exactly the budget left after confirmation"
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
    assert!(login_resp.json.get("two_factor_required").is_none());
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
