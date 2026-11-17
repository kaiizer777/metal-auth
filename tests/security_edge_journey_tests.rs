mod common;

use axum::http::{HeaderMap, Method, StatusCode, header};
use common::*;
use serde_json::json;

const ENDPOINT_SIGNUP: &str = "/auth/signup";
const ENDPOINT_VERIFY: &str = "/auth/verify";
const ENDPOINT_FORGOT_PASSWORD: &str = "/auth/password/reset-request";
const ENDPOINT_RESET_PASSWORD: &str = "/auth/password/reset";

/// Scenario 1: Duplicate Registration Anti-Enumeration Journey
///
/// Ensures that registering an existing email returns the exact same accepted/success
/// envelope without leaking user existence, dispatches no duplicate verification email,
/// and prevents duplicate rows or unhandled integrity violations in the database.
#[tokio::test]
async fn test_journey_duplicate_registration_anti_enumeration() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let email = dynamic_email();
    let password = dynamic_password();

    // 1. Initial registration
    let initial_res = app
        .post_json(
            ENDPOINT_SIGNUP,
            json!({
                "email": email,
                "password": password
            }),
        )
        .await;

    assert_eq!(initial_res.status(), StatusCode::OK);
    assert_eq!(
        initial_res.json()["message"],
        "if this email is new, a verification link has been sent"
    );

    // Initial email dispatch check
    let verification_calls: Vec<_> = app
        .email_sender
        .verification_calls()
        .into_iter()
        .filter(|c| c.to == email)
        .collect();
    assert_eq!(
        verification_calls.len(),
        1,
        "first registration must dispatch exactly one verification email"
    );
    assert_eq!(
        verification_calls[0].to, email,
        "captured verification email recipient must match registered email"
    );
    let user_id = verification_calls[0].user_id;

    // Initial database count check
    let count_after_first = count_users_by_email(&app.pool, &email)
        .await
        .expect("count users by email query");
    assert_eq!(
        count_after_first, 1,
        "exactly 1 user row must exist after first signup"
    );

    let token_count_first = count_verification_tokens_for_user(&app.pool, user_id)
        .await
        .expect("count verification tokens query");
    assert_eq!(
        token_count_first, 1,
        "exactly 1 verification token must exist in DB after first signup"
    );

    // 2. Duplicate registration with identical email
    let duplicate_res = app
        .post_json(
            ENDPOINT_SIGNUP,
            json!({
                "email": email,
                "password": password
            }),
        )
        .await;

    // Must return identical status and payload to prevent enumeration
    assert_eq!(duplicate_res.status(), StatusCode::OK);
    assert_eq!(duplicate_res.json(), initial_res.json());
    assert_eq!(
        duplicate_res.json()["message"],
        "if this email is new, a verification link has been sent"
    );

    // Verification emails must not be sent again for duplicate registration
    assert_eq!(
        app.email_sender
            .verification_calls()
            .into_iter()
            .filter(|c| c.to == email)
            .count(),
        1,
        "duplicate registration must suppress email dispatch"
    );

    // Database must strictly maintain 1 user row
    let count_after_second = count_users_by_email(&app.pool, &email)
        .await
        .expect("count users by email query");
    assert_eq!(
        count_after_second, 1,
        "database must strictly contain 1 row for the email"
    );

    // Database verification tokens table must strictly maintain 1 token
    let token_count_second = count_verification_tokens_for_user(&app.pool, user_id)
        .await
        .expect("count verification tokens query");
    assert_eq!(
        token_count_second, 1,
        "database must strictly contain 1 verification token after duplicate registration"
    );
}

const ENDPOINT_LOGIN: &str = "/auth/login";

/// Scenario 2: CORS Headers Preserved on All Responses (Success and Error)
///
/// Ensures CORS headers (`Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`)
/// are properly attached to both successful responses and error responses (401, 400, etc.),
/// while unauthorized origins are strictly denied CORS headers.
#[tokio::test]
async fn test_journey_cors_headers_on_all_responses() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let allowed_origin = "https://app.example.com";
    let disallowed_origin = "https://unauthorized.evil.com";
    let email = dynamic_email();
    let password = dynamic_password();

    // 1. Success response (200 OK signup) with configured allowed origin
    let success_res = app
        .post_json_with_origin(
            ENDPOINT_SIGNUP,
            json!({
                "email": email,
                "password": password
            }),
            allowed_origin,
        )
        .await;

    assert_eq!(success_res.status(), StatusCode::OK);
    assert_eq!(
        success_res.header("access-control-allow-origin"),
        Some(allowed_origin),
        "CORS allow-origin header must match allowed origin on success"
    );
    assert_eq!(
        success_res.header("access-control-allow-credentials"),
        Some("true"),
        "CORS allow-credentials header must be true on success"
    );

    // 2. Error response (401 Unauthorized login) with configured allowed origin
    let unauth_res = app
        .post_json_with_origin(
            ENDPOINT_LOGIN,
            json!({
                "email": dynamic_email(),
                "password": dynamic_password()
            }),
            allowed_origin,
        )
        .await;

    assert_eq!(unauth_res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauth_res.header("access-control-allow-origin"),
        Some(allowed_origin),
        "CORS allow-origin header must be preserved on 401 Unauthorized"
    );
    assert_eq!(
        unauth_res.header("access-control-allow-credentials"),
        Some("true"),
        "CORS allow-credentials header must be preserved on 401 Unauthorized"
    );

    // 3. Error response (400 Bad Request signup validation) with configured allowed origin
    let bad_req_res = app
        .post_json_with_origin(
            ENDPOINT_SIGNUP,
            json!({
                "email": "not-a-valid-email",
                "password": "short"
            }),
            allowed_origin,
        )
        .await;

    assert_eq!(bad_req_res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        bad_req_res.header("access-control-allow-origin"),
        Some(allowed_origin),
        "CORS allow-origin header must be preserved on 400 Bad Request"
    );
    assert_eq!(
        bad_req_res.header("access-control-allow-credentials"),
        Some("true"),
        "CORS allow-credentials header must be preserved on 400 Bad Request"
    );

    // 4. Disallowed origin verification (no CORS origin granted on actual POST)
    let disallowed_res = app
        .post_json_with_origin(
            ENDPOINT_SIGNUP,
            json!({
                "email": dynamic_email(),
                "password": dynamic_password()
            }),
            disallowed_origin,
        )
        .await;

    assert!(
        disallowed_res
            .header("access-control-allow-origin")
            .is_none(),
        "Disallowed origin must not receive Access-Control-Allow-Origin header"
    );
}

/// Scenario 3: Concurrent Registration Race Condition Journey
///
/// Simulates multiple concurrent clients (e.g. 8 tasks) submitting signup requests
/// for the exact same email address simultaneously. Ensures no 500 internal errors,
/// no database constraint panics or pool corruption occur, and exactly 1 user row
/// is persisted in PostgreSQL.
#[tokio::test]
async fn test_journey_concurrent_registration_race_condition() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let target_email = dynamic_email();
    let password = dynamic_password();
    let concurrency_count = 8;

    let mut handles = Vec::with_capacity(concurrency_count);

    for _ in 0..concurrency_count {
        let app_clone = app.clone();
        let email_clone = target_email.clone();
        let password_clone = password.clone();

        handles.push(tokio::spawn(async move {
            app_clone
                .post_json(
                    ENDPOINT_SIGNUP,
                    json!({
                        "email": email_clone,
                        "password": password_clone
                    }),
                )
                .await
        }));
    }

    let mut results = Vec::with_capacity(concurrency_count);
    for handle in handles {
        let resp = handle
            .await
            .expect("tokio task panicked during concurrent signup");
        results.push(resp);
    }

    assert_eq!(results.len(), concurrency_count);

    for resp in results {
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "every concurrent registration request must succeed with 200 OK without crashing"
        );
        assert_eq!(
            resp.json()["message"],
            "if this email is new, a verification link has been sent",
            "every response must return standard anti-enumeration envelope"
        );
    }

    // Exactly 1 user row must be in the database for that email
    let user_count = count_users_by_email(&app.pool, &target_email)
        .await
        .expect("count users by email query");
    assert_eq!(
        user_count, 1,
        "concurrent registrations must result in exactly 1 user record in database"
    );

    // Exactly 1 verification email must be dispatched despite concurrency
    let verification_calls: Vec<_> = app
        .email_sender
        .verification_calls()
        .into_iter()
        .filter(|c| c.to == target_email)
        .collect();
    assert_eq!(
        verification_calls.len(),
        1,
        "exactly 1 verification email should be dispatched across concurrent signups"
    );
    assert_eq!(
        verification_calls[0].to, target_email,
        "captured verification email recipient must match target email"
    );
    let user_id = verification_calls[0].user_id;

    // Exactly 1 verification token must be persisted in database
    let token_count = count_verification_tokens_for_user(&app.pool, user_id)
        .await
        .expect("count verification tokens query");
    assert_eq!(
        token_count, 1,
        "concurrent registrations must create exactly 1 verification token in database"
    );
}

/// Scenario 4: Case-Insensitive Email Uniqueness and Cross-Variant Authentication
///
/// Ensures normalized case-insensitivity: registration under mixed-case email suppresses
/// duplicate registration under lowercase/uppercase variants, maintains identical anti-enumeration
/// response envelopes, stores normalized email in the database, and allows verified authentication
/// and password resets seamlessly across any casing variation.
#[tokio::test]
async fn test_journey_case_insensitive_email_uniqueness() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let base_uuid = uuid::Uuid::new_v4();
    let mixed_email = format!("User_{}@Example.COM", base_uuid);
    let lower_email = format!("user_{}@example.com", base_uuid);
    let upper_email = format!("USER_{}@EXAMPLE.COM", base_uuid);
    let password = dynamic_password();

    // 1. Initial registration with mixed-case email
    let signup_1 = app
        .post_json(
            ENDPOINT_SIGNUP,
            json!({
                "email": mixed_email,
                "password": password
            }),
        )
        .await;
    assert_eq!(signup_1.status(), StatusCode::OK);
    assert_eq!(
        signup_1.json()["message"],
        "if this email is new, a verification link has been sent"
    );

    // Verify 1 verification email was sent to lower_email
    let verification_calls: Vec<_> = app
        .email_sender
        .verification_calls()
        .into_iter()
        .filter(|c| c.to == lower_email)
        .collect();
    assert_eq!(verification_calls.len(), 1);
    assert_eq!(verification_calls[0].to, lower_email);
    let user_id = verification_calls[0].user_id;
    let token = verification_calls[0].token.clone();

    // Verify DB stored normalized lowercase email and exactly 1 user exists
    assert_eq!(
        count_users_by_email(&app.pool, &lower_email).await.unwrap(),
        1
    );

    // 2. Duplicate registration with all-lowercase variant
    let signup_2 = app
        .post_json(
            ENDPOINT_SIGNUP,
            json!({
                "email": lower_email,
                "password": password
            }),
        )
        .await;
    // Preserves identical envelope to prevent email enumeration
    assert_eq!(signup_2.status(), StatusCode::OK);
    assert_eq!(signup_2.json(), signup_1.json());

    // 3. Duplicate registration with all-uppercase variant
    let signup_3 = app
        .post_json(
            ENDPOINT_SIGNUP,
            json!({
                "email": upper_email,
                "password": password
            }),
        )
        .await;
    assert_eq!(signup_3.status(), StatusCode::OK);
    assert_eq!(signup_3.json(), signup_1.json());

    // Verification emails must not have been sent again
    assert_eq!(
        app.email_sender
            .verification_calls()
            .into_iter()
            .filter(|c| c.to == lower_email)
            .count(),
        1,
        "duplicate registrations under casing variants must suppress email dispatch"
    );

    // Database must still have only 1 user
    assert_eq!(
        count_users_by_email(&app.pool, &lower_email).await.unwrap(),
        1
    );

    // 4. Verify email using token from first signup
    let verify_res = app
        .post_json(ENDPOINT_VERIFY, json!({ "token": token }))
        .await;
    assert_eq!(verify_res.status(), StatusCode::OK);
    assert_eq!(verify_res.json()["message"], "email verified");

    // 5. Login works using lowercase email
    let login_lower = app
        .post_json(
            ENDPOINT_LOGIN,
            json!({
                "email": lower_email,
                "password": password
            }),
        )
        .await;
    assert_eq!(login_lower.status(), StatusCode::OK);
    assert_eq!(login_lower.json()["user_id"], user_id.to_string());

    // 6. Login works using uppercase email
    let login_upper = app
        .post_json(
            ENDPOINT_LOGIN,
            json!({
                "email": upper_email,
                "password": password
            }),
        )
        .await;
    assert_eq!(login_upper.status(), StatusCode::OK);
    assert_eq!(login_upper.json()["user_id"], user_id.to_string());

    // 7. Password reset requested using mixed-case email
    let reset_req = app
        .post_json(ENDPOINT_FORGOT_PASSWORD, json!({ "email": mixed_email }))
        .await;
    assert_eq!(reset_req.status(), StatusCode::OK);

    let reset_calls: Vec<_> = app
        .email_sender
        .reset_calls()
        .into_iter()
        .filter(|c| c.to == lower_email)
        .collect();
    assert_eq!(reset_calls.len(), 1);
    assert_eq!(reset_calls[0].to, lower_email);
    assert_eq!(reset_calls[0].user_id, user_id);
    let reset_token = reset_calls[0].token.clone();

    // 8. Consume reset token with new password
    let new_password = format!("NewPass_{}", dynamic_password());
    let reset_res = app
        .post_json(
            ENDPOINT_RESET_PASSWORD,
            json!({
                "token": reset_token,
                "new_password": new_password
            }),
        )
        .await;
    assert_eq!(reset_res.status(), StatusCode::OK);

    // 9. Login with new password works with uppercase email
    let login_new = app
        .post_json(
            ENDPOINT_LOGIN,
            json!({
                "email": upper_email,
                "password": new_password
            }),
        )
        .await;
    assert_eq!(login_new.status(), StatusCode::OK);
    assert_eq!(login_new.json()["user_id"], user_id.to_string());
}

/// Scenario 5: ASVS L1 Security Baseline & Defense-in-Depth Journey
///
/// Verifies:
/// 1. ASVS L1 security headers (HSTS, nosniff, DENY, CSP, Referrer-Policy, Cache-Control: no-store, Pragma: no-cache)
///    are injected on all authentication responses.
/// 2. Botnet account trip: multiple distinct IPs targeting one account trips account-level rate limit.
/// 3. IP spray trip: single IP targeting multiple distinct accounts trips IP-level rate limit.
/// 4. Rate-limited 429 responses contain the standard `Retry-After` header.
/// 5. Successful login resets ONLY `account:<email>` and preserves `ip:<ip>` limit.
/// 6. CSRF protection on `/auth/logout` strictly rejects missing/invalid tokens when session cookie is present.
#[tokio::test]
async fn test_journey_security_baseline_defense_in_depth() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    // 1. ASVS L1 Security Headers & Cache-Control on authentication endpoints
    let signup_resp = app
        .post_json(
            ENDPOINT_SIGNUP,
            json!({
                "email": dynamic_email(),
                "password": "ValidStrongPassword2026!"
            }),
        )
        .await;
    assert_eq!(signup_resp.status(), StatusCode::OK);
    assert_eq!(
        signup_resp.header("x-content-type-options"),
        Some("nosniff"),
        "must enforce nosniff header"
    );
    assert_eq!(
        signup_resp.header("x-frame-options"),
        Some("DENY"),
        "must enforce frame DENY"
    );
    assert_eq!(
        signup_resp.header("content-security-policy"),
        Some("default-src 'self'"),
        "must enforce default CSP"
    );
    assert_eq!(
        signup_resp.header("referrer-policy"),
        Some("strict-origin-when-cross-origin"),
        "must enforce referrer policy"
    );
    assert_eq!(
        signup_resp.header("strict-transport-security"),
        Some("max-age=63072000; includeSubDomains; preload"),
        "must enforce HSTS"
    );
    assert_eq!(
        signup_resp.header("cache-control"),
        Some("no-store"),
        "must enforce Cache-Control: no-store on auth endpoints"
    );
    assert_eq!(
        signup_resp.header("pragma"),
        Some("no-cache"),
        "must enforce Pragma: no-cache on auth endpoints"
    );

    // 2. Botnet Account Trip: Multiple distinct IPs targeting the same account
    let botnet_target = dynamic_email();
    for i in 1..=10 {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", format!("203.0.113.{i}").parse().unwrap());
        let req = json_request_with_headers(
            Method::POST,
            ENDPOINT_SIGNUP,
            json!({
                "email": botnet_target,
                "password": "ValidStrongPassword2026!"
            }),
            headers,
        );
        let resp = app.dispatch(req).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "botnet attempt {i} within limit must be allowed"
        );
    }

    // 11th request from a brand new IP (203.0.113.11) targeting the same account trips account limit
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.11".parse().unwrap());
    let req = json_request_with_headers(
        Method::POST,
        ENDPOINT_SIGNUP,
        json!({
            "email": botnet_target,
            "password": "ValidStrongPassword2026!"
        }),
        headers,
    );
    let resp = app.dispatch(req).await;
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "11th request against same account from new IP must trip account rate limit"
    );
    assert!(
        resp.header("retry-after").is_some(),
        "429 response must contain Retry-After header"
    );

    // 3. IP Spray Trip: Single IP targeting multiple distinct accounts
    let spray_ip = "198.51.100.88";
    for i in 1..=10 {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", spray_ip.parse().unwrap());
        let req = json_request_with_headers(
            Method::POST,
            ENDPOINT_SIGNUP,
            json!({
                "email": format!("spray_{i}_{}@example.com", dynamic_email()),
                "password": "ValidStrongPassword2026!"
            }),
            headers,
        );
        let resp = app.dispatch(req).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "IP spray attempt {i} within limit must be allowed"
        );
    }

    // 11th request from the same IP against another fresh account trips IP limit
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", spray_ip.parse().unwrap());
    let req = json_request_with_headers(
        Method::POST,
        ENDPOINT_SIGNUP,
        json!({
            "email": format!("spray_overflow_{}@example.com", dynamic_email()),
            "password": "ValidStrongPassword2026!"
        }),
        headers,
    );
    let resp = app.dispatch(req).await;
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "11th request from same IP must trip IP rate limit"
    );
    assert!(
        resp.header("retry-after").is_some(),
        "429 response must contain Retry-After header"
    );

    // 4. Successful login resets ONLY account:<email> and preserves ip:<ip>
    let user_email = dynamic_email();
    let user_pw = "ValidSecurePass2026!";

    let _ = app
        .post_json(
            ENDPOINT_SIGNUP,
            json!({
                "email": user_email,
                "password": user_pw
            }),
        )
        .await;

    let v_token = app
        .email_sender
        .verification_calls()
        .into_iter()
        .find(|c| c.to == user_email)
        .expect("verification email dispatched")
        .token;

    let verify_res = app
        .post_json(ENDPOINT_VERIFY, json!({ "token": v_token }))
        .await;
    assert_eq!(verify_res.status(), StatusCode::OK);

    let test_ip = "192.0.2.144";

    // Consume 8 attempts from test_ip targeting user_email with wrong password
    for _ in 1..=8 {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", test_ip.parse().unwrap());
        let req = json_request_with_headers(
            Method::POST,
            ENDPOINT_LOGIN,
            json!({
                "email": user_email,
                "password": "WrongPassword123!"
            }),
            headers,
        );
        let resp = app.dispatch(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // Login successfully from test_ip with valid password
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", test_ip.parse().unwrap());
    let req = json_request_with_headers(
        Method::POST,
        ENDPOINT_LOGIN,
        json!({
            "email": user_email,
            "password": user_pw
        }),
        headers,
    );
    let login_res = app.dispatch(req).await;
    assert_eq!(login_res.status(), StatusCode::OK);

    // Invariant check 1: Account limit was reset on successful login, so 8 fresh attempts from a different IP succeed without 429
    let other_ip = "192.0.2.200";
    for _ in 1..=8 {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", other_ip.parse().unwrap());
        let req = json_request_with_headers(
            Method::POST,
            ENDPOINT_LOGIN,
            json!({
                "email": user_email,
                "password": "WrongPassword123!"
            }),
            headers,
        );
        let resp = app.dispatch(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // Invariant check 2: IP limit on test_ip was NOT reset!
    // test_ip had 8 failed + 1 successful = 9 attempts.
    // 2 more attempts from test_ip must trip the IP rate limit (9 + 2 = 11 > 10).
    for attempt in 1..=2 {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", test_ip.parse().unwrap());
        let req = json_request_with_headers(
            Method::POST,
            ENDPOINT_LOGIN,
            json!({
                "email": dynamic_email(),
                "password": "WrongPassword123!"
            }),
            headers,
        );
        let resp = app.dispatch(req).await;
        if attempt == 2 {
            assert_eq!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "IP rate limit must be preserved across successful login"
            );
        }
    }

    // 5. CSRF Enforcement on /auth/logout
    let cookie_user = dynamic_email();
    let cookie_pw = "ValidCookiePass2026!";
    let _ = app
        .post_json(
            ENDPOINT_SIGNUP,
            json!({
                "email": cookie_user,
                "password": cookie_pw
            }),
        )
        .await;

    let v_token2 = app
        .email_sender
        .verification_calls()
        .into_iter()
        .find(|c| c.to == cookie_user)
        .expect("verification email dispatched")
        .token;

    let _ = app
        .post_json(ENDPOINT_VERIFY, json!({ "token": v_token2 }))
        .await;

    let login_resp = app
        .post_json(
            ENDPOINT_LOGIN,
            json!({
                "email": cookie_user,
                "password": cookie_pw
            }),
        )
        .await;
    assert_eq!(login_resp.status(), StatusCode::OK);

    let session_cookie_name = &app.state.config.session.cookie_name;
    let session_cookie = login_resp
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|v| {
            let s = v.to_str().ok()?;
            if s.starts_with(&format!("{session_cookie_name}=")) {
                Some(s.split(';').next()?.to_string())
            } else {
                None
            }
        })
        .expect("session cookie set on login");

    let csrf_cookie_val = login_resp
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|v| {
            let s = v.to_str().ok()?;
            if s.starts_with("csrf_token=") {
                Some(
                    s.split(';')
                        .next()?
                        .trim_start_matches("csrf_token=")
                        .to_string(),
                )
            } else {
                None
            }
        })
        .expect("csrf cookie set on login");

    // Case A: Missing CSRF header with session cookie -> 403 Forbidden
    let mut headers_no_csrf = HeaderMap::new();
    headers_no_csrf.insert(
        header::COOKIE,
        format!("{session_cookie}; csrf_token={csrf_cookie_val}")
            .parse()
            .unwrap(),
    );
    let req_a = empty_request_with_headers(Method::POST, "/auth/logout", headers_no_csrf);
    let resp_a = app.dispatch(req_a).await;
    assert_eq!(
        resp_a.status(),
        StatusCode::FORBIDDEN,
        "logout with session cookie but missing csrf header must return 403"
    );

    // Case B: Tampered/invalid length CSRF header with session cookie -> 403 Forbidden
    let mut headers_bad_csrf = HeaderMap::new();
    headers_bad_csrf.insert(
        header::COOKIE,
        format!("{session_cookie}; csrf_token={csrf_cookie_val}")
            .parse()
            .unwrap(),
    );
    headers_bad_csrf.insert("x-csrf-token", "tampered_bad_token".parse().unwrap());
    let req_b = empty_request_with_headers(Method::POST, "/auth/logout", headers_bad_csrf);
    let resp_b = app.dispatch(req_b).await;
    assert_eq!(
        resp_b.status(),
        StatusCode::FORBIDDEN,
        "logout with tampered csrf header must return 403"
    );

    // Case C: Valid CSRF header and session cookie -> 200 OK
    let mut headers_valid = HeaderMap::new();
    headers_valid.insert(
        header::COOKIE,
        format!("{session_cookie}; csrf_token={csrf_cookie_val}")
            .parse()
            .unwrap(),
    );
    headers_valid.insert("x-csrf-token", csrf_cookie_val.parse().unwrap());
    let req_c = empty_request_with_headers(Method::POST, "/auth/logout", headers_valid);
    let resp_c = app.dispatch(req_c).await;
    assert_eq!(
        resp_c.status(),
        StatusCode::OK,
        "logout with valid session cookie and matching csrf token must succeed"
    );
}
