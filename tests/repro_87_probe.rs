//! Temporary RED probe for #87: a worker running its startup prune reaps an expired
//! challenge seeded by another test, flipping `TwoFactorTokenExpired` to
//! `TwoFactorTokenInvalid`. Removed once the harness isolation lands.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use metal_auth::email::NoopEmailSender;
use metal_auth::email::outbox::{OutboxWorkerConfig, run_outbox_worker_until};
use metal_auth::{ErrorCode, SharedEmailSender};
use serde_json::json;

#[tokio::test]
async fn probe_foreign_worker_reaps_expired_challenge() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password, secret, _backup_codes, _session) =
        enabled_user(&app, &dynamic_ip()).await;
    let user_id = user_id_for_email(&app.pool, &email).await;
    let token = challenge(&app, &email, &password).await;
    sqlx::query(
        "UPDATE two_factor_tokens SET expires_at = NOW() - INTERVAL '1 minute' WHERE user_id = $1",
    )
    .bind(user_id)
    .execute(&app.pool)
    .await
    .expect("expire the challenge token");

    // Pre-signalled shutdown: the worker still runs its startup prune, then exits.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    shutdown_tx.send(true).expect("pre-signal shutdown");
    run_outbox_worker_until(
        app.pool.clone(),
        Some(Arc::new(NoopEmailSender) as SharedEmailSender),
        Duration::from_secs(5),
        OutboxWorkerConfig::default(),
        Arc::new(tokio::sync::Notify::new()),
        shutdown_rx,
    )
    .await;

    let resp = app
        .post_json_with_ip(
            "/auth/totp/verify",
            json!({ "challenge_token": token, "code": totp_code(&secret) }),
            &dynamic_ip(),
        )
        .await;
    assert_eq!(
        resp.error_code(),
        Some(ErrorCode::TwoFactorTokenExpired),
        "probe body: {}",
        resp.body_str
    );
}
