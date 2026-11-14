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
    assert_eq!(
        app.email_sender.verification_calls().len(),
        1,
        "first registration must dispatch exactly one verification email"
    );

    // Initial database count check
    let count_after_first = count_users_by_email(&app.pool, &email)
        .await
        .expect("count users by email query");
    assert_eq!(
        count_after_first, 1,
        "exactly 1 user row must exist after first signup"
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
}
