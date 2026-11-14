mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::json;

const ENDPOINT_SIGNUP: &str = "/auth/signup";

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
    let verification_calls = app.email_sender.verification_calls();
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
        app.email_sender.verification_calls().len(),
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
    assert!(
        disallowed_res
            .header("access-control-allow-credentials")
            .is_none(),
        "Disallowed origin must not receive Access-Control-Allow-Credentials header"
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
    let verification_calls = app.email_sender.verification_calls();
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
