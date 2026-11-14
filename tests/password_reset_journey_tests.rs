mod common;

use axum::http::StatusCode;
use common::*;
use metal_auth::ErrorCode;
use serde_json::json;

const ENDPOINT_SIGNUP: &str = "/auth/signup";
const ENDPOINT_VERIFY: &str = "/auth/verify";
const ENDPOINT_LOGIN: &str = "/auth/login";
const ENDPOINT_FORGOT_PASSWORD: &str = "/auth/password/reset-request";
const ENDPOINT_RESET_PASSWORD: &str = "/auth/password/reset";

#[tokio::test]
async fn test_journey_password_reset_full_lifecycle() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let email = dynamic_email();
    let old_password = dynamic_password();
    let new_password = format!("New_{}", dynamic_password());

    // 1. Register and verify user
    let signup_res = app
        .post_json(
            ENDPOINT_SIGNUP,
            json!({
                "email": email,
                "password": old_password
            }),
        )
        .await;
    assert_eq!(signup_res.status(), StatusCode::OK);

    let verify_token = app
        .email_sender
        .last_verification_token()
        .expect("verification token dispatched");
    let verify_res = app
        .post_json(ENDPOINT_VERIFY, json!({ "token": verify_token }))
        .await;
    assert_eq!(verify_res.status(), StatusCode::OK);

    // Verify initial login succeeds with old password
    let initial_login_res = app
        .post_json(
            ENDPOINT_LOGIN,
            json!({
                "email": email,
                "password": old_password
            }),
        )
        .await;
    assert_eq!(initial_login_res.status(), StatusCode::OK);
    let user_id = initial_login_res.json()["user_id"]
        .as_str()
        .expect("user_id present")
        .to_string();

    // 2. Request password reset via POST /auth/password/reset-request
    let reset_req_res = app
        .post_json(ENDPOINT_FORGOT_PASSWORD, json!({ "email": email }))
        .await;
    assert_eq!(reset_req_res.status(), StatusCode::OK);
    assert_eq!(
        reset_req_res.json()["message"],
        "if an account with that email exists, a password reset link has been sent"
    );

    // 3. Capture reset email from app.email_sender and extract reset token
    let reset_calls = app.email_sender.reset_calls();
    assert_eq!(reset_calls.len(), 1, "exactly one reset email captured");
    let reset_payload = &reset_calls[0];
    assert_eq!(reset_payload.to, email);
    assert_eq!(reset_payload.user_id.to_string(), user_id);

    let reset_token_from_url = reset_payload
        .url
        .split("token=")
        .nth(1)
        .expect("token query param present in email reset url");
    assert_eq!(reset_token_from_url, reset_payload.token);
    assert_eq!(reset_token_from_url.len(), 64);

    // 4. Submit new password via POST /auth/password/reset
    let reset_res = app
        .post_json(
            ENDPOINT_RESET_PASSWORD,
            json!({
                "token": reset_token_from_url,
                "new_password": new_password
            }),
        )
        .await;
    assert_eq!(reset_res.status(), StatusCode::OK);
    assert_eq!(reset_res.json()["message"], "password reset successful");

    // 5. Attempt login with old password -> 401 Unauthorized (INVALID_CREDENTIALS)
    let old_login_res = app
        .post_json(
            ENDPOINT_LOGIN,
            json!({
                "email": email,
                "password": old_password
            }),
        )
        .await;
    assert_eq!(old_login_res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(old_login_res.error_code(), Some(ErrorCode::InvalidCredentials));

    // 6. Attempt login with new password -> 200 OK with user_id
    let new_login_res = app
        .post_json(
            ENDPOINT_LOGIN,
            json!({
                "email": email,
                "password": new_password
            }),
        )
        .await;
    assert_eq!(new_login_res.status(), StatusCode::OK);
    assert_eq!(new_login_res.json()["user_id"], user_id);
}
