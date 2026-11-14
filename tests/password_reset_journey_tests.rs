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

#[tokio::test]
async fn test_journey_password_reset_invalid_or_expired_token() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let email = dynamic_email();
    let initial_password = dynamic_password();
    let replacement_password_1 = format!("Rep1_{}", dynamic_password());
    let replacement_password_2 = format!("Rep2_{}", dynamic_password());

    // 1. Register and verify user
    let signup_res = app
        .post_json(
            ENDPOINT_SIGNUP,
            json!({
                "email": email,
                "password": initial_password
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

    let login_res = app
        .post_json(
            ENDPOINT_LOGIN,
            json!({
                "email": email,
                "password": initial_password
            }),
        )
        .await;
    assert_eq!(login_res.status(), StatusCode::OK);
    let user_id = login_res.json()["user_id"]
        .as_str()
        .expect("user_id present")
        .to_string();
    let user_uuid = uuid::Uuid::parse_str(&user_id).expect("valid uuid");

    // 2. Attempt reset with invalid/tampered token -> 400 Bad Request (INVALID_TOKEN)
    let invalid_token = "deadbeef".repeat(8);
    let invalid_res = app
        .post_json(
            ENDPOINT_RESET_PASSWORD,
            json!({
                "token": invalid_token,
                "new_password": replacement_password_1
            }),
        )
        .await;
    assert_eq!(invalid_res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(invalid_res.error_code(), Some(ErrorCode::InvalidToken));

    // Malformed length token -> 400 Bad Request (INVALID_TOKEN)
    let malformed_res = app
        .post_json(
            ENDPOINT_RESET_PASSWORD,
            json!({
                "token": "malformed_short_token",
                "new_password": replacement_password_1
            }),
        )
        .await;
    assert_eq!(malformed_res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(malformed_res.error_code(), Some(ErrorCode::InvalidToken));

    // 3. Request reset, expire token in DB using expire_reset_tokens_for_user, attempt reset -> 400 Bad Request (TOKEN_EXPIRED)
    let reset_req_1 = app
        .post_json(ENDPOINT_FORGOT_PASSWORD, json!({ "email": email }))
        .await;
    assert_eq!(reset_req_1.status(), StatusCode::OK);

    let token_1 = app
        .email_sender
        .last_reset_token()
        .expect("reset token dispatched");

    expire_reset_tokens_for_user(&app.pool, user_uuid)
        .await
        .expect("expire reset tokens in DB");

    let expired_res = app
        .post_json(
            ENDPOINT_RESET_PASSWORD,
            json!({
                "token": token_1,
                "new_password": replacement_password_1
            }),
        )
        .await;
    assert_eq!(expired_res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(expired_res.error_code(), Some(ErrorCode::TokenExpired));

    // 4. Successfully reset password with valid token, then attempt to replay/reuse the same token -> 400 Bad Request
    let reset_req_2 = app
        .post_json(ENDPOINT_FORGOT_PASSWORD, json!({ "email": email }))
        .await;
    assert_eq!(reset_req_2.status(), StatusCode::OK);

    let token_2 = app
        .email_sender
        .last_reset_token()
        .expect("reset token 2 dispatched");

    // First consumption succeeds
    let valid_reset_res = app
        .post_json(
            ENDPOINT_RESET_PASSWORD,
            json!({
                "token": token_2,
                "new_password": replacement_password_1
            }),
        )
        .await;
    assert_eq!(valid_reset_res.status(), StatusCode::OK);
    assert_eq!(valid_reset_res.json()["message"], "password reset successful");

    // Replay attempt with the exact same consumed token -> 400 Bad Request (INVALID_TOKEN)
    let replay_res = app
        .post_json(
            ENDPOINT_RESET_PASSWORD,
            json!({
                "token": token_2,
                "new_password": replacement_password_2
            }),
        )
        .await;
    assert_eq!(replay_res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(replay_res.error_code(), Some(ErrorCode::InvalidToken));

    // Outstanding reset tokens count must be 0
    let token_count = count_reset_tokens_for_user(&app.pool, user_uuid)
        .await
        .expect("count reset tokens");
    assert_eq!(token_count, 0, "all tokens revoked after reset");

    // Login succeeds with replacement_password_1, not initial or replacement_password_2
    let login_replacement_1 = app
        .post_json(
            ENDPOINT_LOGIN,
            json!({
                "email": email,
                "password": replacement_password_1
            }),
        )
        .await;
    assert_eq!(login_replacement_1.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_journey_password_reset_nonexistent_email_enumeration() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let nonexistent_email = dynamic_email();

    // 1. Assert user does not exist in DB prior to request
    let user_count = count_users_by_email(&app.pool, &nonexistent_email)
        .await
        .expect("count users by email");
    assert_eq!(user_count, 0, "email must not exist in DB");

    // Clear any prior captured emails to ensure clean slate
    app.email_sender.clear();

    // 2. Request forgot-password for nonexistent email
    let reset_req_res = app
        .post_json(
            ENDPOINT_FORGOT_PASSWORD,
            json!({ "email": nonexistent_email }),
        )
        .await;

    // 3. Assert response returns 200 with identical anti-enumeration message
    assert_eq!(reset_req_res.status(), StatusCode::OK);
    assert_eq!(
        reset_req_res.json()["message"],
        "if an account with that email exists, a password reset link has been sent"
    );

    // 4. Assert zero emails were dispatched via app.email_sender
    assert_eq!(
        app.email_sender.reset_calls().len(),
        0,
        "zero reset emails dispatched for nonexistent email"
    );
    assert_eq!(
        app.email_sender.verification_calls().len(),
        0,
        "zero verification emails dispatched for nonexistent email"
    );
}


