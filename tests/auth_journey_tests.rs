mod common;

use axum::http::StatusCode;
use common::*;
use metal_auth::ErrorCode;
use serde_json::json;

const ENDPOINT_SIGNUP: &str = "/auth/signup";
const ENDPOINT_LOGIN: &str = "/auth/login";
const ENDPOINT_VERIFY: &str = "/auth/verify";

#[tokio::test]
async fn test_journey_full_registration_and_login() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let email = dynamic_email();
    let password = dynamic_password();

    // 1. Register new user
    let signup_res = app
        .post_json(
            ENDPOINT_SIGNUP,
            json!({
                "email": email,
                "password": password
            }),
        )
        .await;
    assert_eq!(signup_res.status(), StatusCode::OK);
    assert_eq!(
        signup_res.json()["message"],
        "if this email is new, a verification link has been sent"
    );

    // 2. Capture verification email and extract token from link
    let captured = app.email_sender.verification_calls();
    assert_eq!(captured.len(), 1, "exactly one verification email dispatched");
    let email_payload = &captured[0];
    assert_eq!(email_payload.to, email);

    let token_from_url = email_payload
        .url
        .split("token=")
        .nth(1)
        .expect("verification token in email url");
    assert_eq!(token_from_url, email_payload.token);
    assert_eq!(token_from_url.len(), 64, "token must be 64-character hex");

    // Pre-verification: user must not be marked verified in database
    assert!(
        !is_email_verified(&app.pool, email_payload.user_id)
            .await
            .expect("fetch verification status")
    );

    // 3. Consume verification token
    let verify_res = app
        .post_json(
            ENDPOINT_VERIFY,
            json!({
                "token": token_from_url
            }),
        )
        .await;
    assert_eq!(verify_res.status(), StatusCode::OK);
    assert_eq!(verify_res.json()["message"], "email verified");

    // Post-verification: user must be marked verified in database
    assert!(
        is_email_verified(&app.pool, email_payload.user_id)
            .await
            .expect("fetch verification status")
    );

    // 4. Login with verified account
    let login_res = app
        .post_json(
            ENDPOINT_LOGIN,
            json!({
                "email": email,
                "password": password
            }),
        )
        .await;
    assert_eq!(login_res.status(), StatusCode::OK);
    assert_eq!(
        login_res.json()["user_id"],
        email_payload.user_id.to_string()
    );
}

#[tokio::test]
async fn test_journey_login_unverified_account_forbidden() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let email = dynamic_email();
    let password = dynamic_password();

    // 1. Register new user
    let signup_res = app
        .post_json(
            ENDPOINT_SIGNUP,
            json!({
                "email": email,
                "password": password
            }),
        )
        .await;
    assert_eq!(signup_res.status(), StatusCode::OK);

    let captured = app.email_sender.verification_calls();
    assert_eq!(captured.len(), 1, "verification email captured");
    let user_id = captured[0].user_id;

    // Database verification state check
    assert!(
        !is_email_verified(&app.pool, user_id)
            .await
            .expect("fetch verification status")
    );

    // 2. Attempt login immediately before verifying email -> 403 Forbidden
    let login_forbidden_res = app
        .post_json(
            ENDPOINT_LOGIN,
            json!({
                "email": email,
                "password": password
            }),
        )
        .await;
    assert_eq!(login_forbidden_res.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        login_forbidden_res.error_code(),
        Some(ErrorCode::EmailNotVerified)
    );
    assert_eq!(login_forbidden_res.json()["code"], "EMAIL_NOT_VERIFIED");
    assert_eq!(
        login_forbidden_res.json()["message"],
        "Email address has not been verified"
    );

    // 3. Complete verification and confirm login succeeds
    let token = &captured[0].token;
    let verify_res = app
        .post_json(
            ENDPOINT_VERIFY,
            json!({
                "token": token
            }),
        )
        .await;
    assert_eq!(verify_res.status(), StatusCode::OK);
    assert_eq!(verify_res.json()["message"], "email verified");

    let login_success_res = app
        .post_json(
            ENDPOINT_LOGIN,
            json!({
                "email": email,
                "password": password
            }),
        )
        .await;
    assert_eq!(login_success_res.status(), StatusCode::OK);
    assert_eq!(login_success_res.json()["user_id"], user_id.to_string());
}

