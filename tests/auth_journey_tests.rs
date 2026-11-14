mod common;

use axum::http::StatusCode;
use common::*;
use metal_auth::ErrorCode;
use serde_json::json;

const ENDPOINT_SIGNUP: &str = "/auth/signup";
const ENDPOINT_LOGIN: &str = "/auth/login";
const ENDPOINT_VERIFY: &str = "/auth/verify";
const ENDPOINT_LOGOUT: &str = "/auth/logout";

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
    assert_eq!(
        captured.len(),
        1,
        "exactly one verification email dispatched"
    );
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
    let initial_user = get_user_by_id(&app.pool, email_payload.user_id)
        .await
        .expect("fetch initial user");
    assert!(!initial_user.email_verified);
    assert_eq!(
        count_verification_tokens_for_user(&app.pool, email_payload.user_id)
            .await
            .expect("fetch token count"),
        1
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

    // Consumed token row must be deleted from verification_tokens table
    assert_eq!(
        count_verification_tokens_for_user(&app.pool, email_payload.user_id)
            .await
            .expect("fetch verification token count post-verify"),
        0,
        "consumed verification token row must be purged from database"
    );

    // updated_at must be mutated to a timestamp strictly after created_at
    let verified_user = get_user_by_id(&app.pool, email_payload.user_id)
        .await
        .expect("fetch verified user");
    assert!(
        verified_user.updated_at > initial_user.created_at,
        "updated_at must be strictly after created_at upon verification"
    );
    assert!(
        verified_user.updated_at >= initial_user.updated_at,
        "updated_at must advance upon verification"
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

    // 5. Logout round trip with Bearer header -> 204 No Content
    let logout_res = app
        .post_empty_with_bearer(ENDPOINT_LOGOUT, "test-bearer-token")
        .await;
    assert_eq!(
        logout_res.status(),
        StatusCode::NO_CONTENT,
        "logout endpoint must return 204 No Content"
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

#[tokio::test]
async fn test_journey_verify_email_idempotency_or_tampered() {
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
    assert_eq!(captured.len(), 1, "verification email dispatched");
    let valid_token = &captured[0].token;
    let user_id = captured[0].user_id;

    // 2. Tampered / malformed token submission -> 400 INVALID_TOKEN
    let malformed_res = app
        .post_json(
            ENDPOINT_VERIFY,
            json!({
                "token": "malformed_tampered_non_hex_token"
            }),
        )
        .await;
    assert_eq!(malformed_res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(malformed_res.error_code(), Some(ErrorCode::InvalidToken));

    // Non-existent 64-char hex token -> 400 INVALID_TOKEN
    let non_existent_token = "0".repeat(64);
    let unknown_res = app
        .post_json(
            ENDPOINT_VERIFY,
            json!({
                "token": non_existent_token
            }),
        )
        .await;
    assert_eq!(unknown_res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(unknown_res.error_code(), Some(ErrorCode::InvalidToken));

    // Pre-verification: user remains unverified
    assert!(
        !is_email_verified(&app.pool, user_id)
            .await
            .expect("fetch verification status")
    );

    // 3. First consumption of valid token -> 200 OK
    let verify_res = app
        .post_json(
            ENDPOINT_VERIFY,
            json!({
                "token": valid_token
            }),
        )
        .await;
    assert_eq!(verify_res.status(), StatusCode::OK);
    assert_eq!(verify_res.json()["message"], "email verified");
    assert!(
        is_email_verified(&app.pool, user_id)
            .await
            .expect("fetch verification status")
    );

    // 4. Second consumption of the same token (replay attack) -> 400 INVALID_TOKEN
    let replay_res = app
        .post_json(
            ENDPOINT_VERIFY,
            json!({
                "token": valid_token
            }),
        )
        .await;
    assert_eq!(replay_res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(replay_res.error_code(), Some(ErrorCode::InvalidToken));

    // User remains verified
    assert!(
        is_email_verified(&app.pool, user_id)
            .await
            .expect("fetch verification status")
    );
}

#[tokio::test]
async fn test_journey_login_invalid_credentials() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let non_existent_email = dynamic_email();
    let password = dynamic_password();

    // 1. Login with unknown email -> 401 Unauthorized
    let unknown_email_res = app
        .post_json(
            ENDPOINT_LOGIN,
            json!({
                "email": non_existent_email,
                "password": password
            }),
        )
        .await;
    assert_eq!(unknown_email_res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unknown_email_res.error_code(),
        Some(ErrorCode::InvalidCredentials)
    );

    // 2. Register and verify a real user
    let email = dynamic_email();
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

    let token = app
        .email_sender
        .last_verification_token()
        .expect("captured verification token");
    let verify_res = app
        .post_json(
            ENDPOINT_VERIFY,
            json!({
                "token": token
            }),
        )
        .await;
    assert_eq!(verify_res.status(), StatusCode::OK);

    // 3. Login with registered email but wrong password -> 401 Unauthorized
    let wrong_password = dynamic_password();
    let wrong_pw_res = app
        .post_json(
            ENDPOINT_LOGIN,
            json!({
                "email": email,
                "password": wrong_password
            }),
        )
        .await;
    assert_eq!(wrong_pw_res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        wrong_pw_res.error_code(),
        Some(ErrorCode::InvalidCredentials)
    );

    // 4. Anti-enumeration verification: response envelope parity
    assert_eq!(unknown_email_res.status(), wrong_pw_res.status());
    assert_eq!(
        unknown_email_res.json()["code"],
        wrong_pw_res.json()["code"]
    );
    assert_eq!(
        unknown_email_res.json()["message"],
        wrong_pw_res.json()["message"]
    );
    assert_eq!(wrong_pw_res.json()["message"], "Invalid email or password");

    // 5. Correct credentials succeed -> 200 OK
    let success_res = app
        .post_json(
            ENDPOINT_LOGIN,
            json!({
                "email": email,
                "password": password
            }),
        )
        .await;
    assert_eq!(success_res.status(), StatusCode::OK);
    assert!(success_res.json().get("user_id").is_some());
}

#[tokio::test]
async fn test_journey_verify_email_expired_token() {
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
    assert_eq!(captured.len(), 1, "verification email dispatched");
    let user_id = captured[0].user_id;
    let token = &captured[0].token;

    // Pre-check: user unverified in DB
    assert!(
        !is_email_verified(&app.pool, user_id)
            .await
            .expect("fetch verification status")
    );

    // 2. Expire verification token in database
    expire_verification_tokens_for_user(&app.pool, user_id)
        .await
        .expect("expire verification tokens in DB");

    // 3. Attempt verification with expired token -> 400 Bad Request (TOKEN_EXPIRED)
    let verify_res = app
        .post_json(
            ENDPOINT_VERIFY,
            json!({
                "token": token
            }),
        )
        .await;
    assert_eq!(verify_res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(verify_res.error_code(), Some(ErrorCode::TokenExpired));
    assert_eq!(verify_res.json()["code"], "TOKEN_EXPIRED");

    // 4. Assert user remains unverified in database
    assert!(
        !is_email_verified(&app.pool, user_id)
            .await
            .expect("fetch verification status"),
        "user must remain unverified after expired token rejection"
    );

    // Expired token row must be purged from database upon rejection
    assert_eq!(
        count_verification_tokens_for_user(&app.pool, user_id)
            .await
            .expect("fetch verification token count post-expired-verify"),
        0,
        "expired verification token row must be purged from database upon rejection"
    );

    // 5. Attempt login -> 403 Forbidden (EMAIL_NOT_VERIFIED)
    let login_res = app
        .post_json(
            ENDPOINT_LOGIN,
            json!({
                "email": email,
                "password": password
            }),
        )
        .await;
    assert_eq!(login_res.status(), StatusCode::FORBIDDEN);
    assert_eq!(login_res.error_code(), Some(ErrorCode::EmailNotVerified));
}

#[tokio::test]
async fn test_journey_logout_roundtrip() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let logout_res = app
        .post_empty_with_bearer(ENDPOINT_LOGOUT, "test-bearer-token")
        .await;
    assert_eq!(
        logout_res.status(),
        StatusCode::NO_CONTENT,
        "logout endpoint must return 204 No Content"
    );
}

#[test]
fn test_harness_initializes() {
    let email = dynamic_email();
    assert!(email.contains("@example.com"));
    let pass = dynamic_password();
    assert!(pass.starts_with("JourneyPass!_"));
}
