mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use metal_auth::db::models::{
    OUTBOX_STATUS_FAILED, OUTBOX_STATUS_PENDING, OUTBOX_STATUS_SENT,
};
use metal_auth::db::outbox::{
    claim_pending_outbox, get_outbox_by_id, insert_outbox, mark_outbox_failed,
    record_outbox_retry, recover_stale_processing,
};
use metal_auth::email::outbox::process_outbox_batch;
use metal_auth::email::test_utils::CapturingEmailSender;
use metal_auth::{EmailDispatcher, SharedEmailSender};
use serde_json::json;

const ENDPOINT_SIGNUP: &str = "/auth/signup";
const ENDPOINT_VERIFY: &str = "/auth/verify";
const ENDPOINT_PASSWORD_RESET_REQUEST: &str = "/auth/password/reset-request";

#[tokio::test]
async fn test_outbox_atomic_rollback_on_duplicate_signup() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let email = dynamic_email();
    let password = dynamic_password();

    // 1. Initial valid signup
    let res1 = app
        .post_json(
            ENDPOINT_SIGNUP,
            json!({
                "email": email,
                "password": password
            }),
        )
        .await;
    assert_eq!(res1.status(), StatusCode::OK);

    let rows1 = get_outbox_rows_for_recipient(&app.pool, &email)
        .await
        .expect("query outbox rows");
    assert_eq!(rows1.len(), 1, "exactly one outbox row for initial signup");

    // 2. Duplicate signup with same email -> triggers rollback
    let res2 = app
        .post_json(
            ENDPOINT_SIGNUP,
            json!({
                "email": email,
                "password": password
            }),
        )
        .await;
    assert_eq!(res2.status(), StatusCode::OK);

    let rows2 = get_outbox_rows_for_recipient(&app.pool, &email)
        .await
        .expect("query outbox rows");
    assert_eq!(
        rows2.len(),
        1,
        "rolled back duplicate signup must never commit an outbox row"
    );
}

#[tokio::test]
async fn test_outbox_record_inserted_for_password_reset() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let email = dynamic_email();
    let password = dynamic_password();

    // 1. Create and verify user
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

    let verify_token = app
        .email_sender
        .last_verification_token()
        .expect("verification token dispatched");
    let verify_res = app
        .post_json(ENDPOINT_VERIFY, json!({ "token": verify_token }))
        .await;
    assert_eq!(verify_res.status(), StatusCode::OK);

    // 2. Request password reset
    let reset_res = app
        .post_json(
            ENDPOINT_PASSWORD_RESET_REQUEST,
            json!({ "email": email }),
        )
        .await;
    assert_eq!(reset_res.status(), StatusCode::OK);

    let rows = get_outbox_rows_for_recipient(&app.pool, &email)
        .await
        .expect("query outbox rows");
    let reset_rows: Vec<_> = rows
        .into_iter()
        .filter(|r| r.email_type == "password_reset")
        .collect();
    assert_eq!(reset_rows.len(), 1, "password reset commits an outbox record");
    assert_eq!(reset_rows[0].email_type, "password_reset");
    assert_eq!(reset_rows[0].status, OUTBOX_STATUS_SENT); // blocking dispatcher in test marks sent
}

#[tokio::test]
async fn test_outbox_concurrent_claiming_skip_locked() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    // Insert 10 pending outbox records
    let mut ids = Vec::new();
    for i in 0..10 {
        let recipient = format!("concurrent_{i}_{}@example.com", uuid::Uuid::new_v4());
        let payload = json!({
            "user_id": uuid::Uuid::new_v4(),
            "to": recipient,
            "token": "tok123",
            "url": "https://example.com/verify?token=tok123",
            "expires_at": chrono::Utc::now()
        });
        let row = insert_outbox(&app.pool, &recipient, "verification", payload)
            .await
            .expect("insert outbox");
        ids.push(row.id);
    }

    // Spawn 2 concurrent workers attempting to claim batches of 5
    let pool1 = app.pool.clone();
    let pool2 = app.pool.clone();

    let (batch1, batch2) = tokio::join!(
        tokio::spawn(async move { claim_pending_outbox(&pool1, 5, Duration::from_secs(300)).await }),
        tokio::spawn(async move { claim_pending_outbox(&pool2, 5, Duration::from_secs(300)).await }),
    );

    let claimed1 = batch1.unwrap().expect("claim 1");
    let claimed2 = batch2.unwrap().expect("claim 2");

    // Mutually disjoint sets: no record claimed twice
    let set1: std::collections::HashSet<_> = claimed1.iter().map(|m| m.id).collect();
    let set2: std::collections::HashSet<_> = claimed2.iter().map(|m| m.id).collect();

    assert!(
        set1.is_disjoint(&set2),
        "concurrent workers with FOR UPDATE SKIP LOCKED must never claim duplicate rows"
    );
    assert_eq!(claimed1.len() + claimed2.len(), 10, "all 10 rows claimed");
}

#[tokio::test]
async fn test_outbox_retry_and_exhaustion_to_failed() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let recipient = format!("retry_{}@example.com", uuid::Uuid::new_v4());
    let payload = json!({
        "user_id": uuid::Uuid::new_v4(),
        "to": recipient,
        "token": "tok123",
        "url": "https://example.com/verify?token=tok123",
        "expires_at": chrono::Utc::now()
    });
    let row = insert_outbox(&app.pool, &recipient, "verification", payload)
        .await
        .expect("insert outbox");

    // Simulate transient retry attempts
    let next_retry = chrono::Utc::now() + chrono::Duration::seconds(10);
    record_outbox_retry(&app.pool, row.id, next_retry, "network timeout")
        .await
        .expect("record retry");

    let updated = get_outbox_by_id(&app.pool, row.id)
        .await
        .expect("get outbox")
        .unwrap();
    assert_eq!(updated.status, OUTBOX_STATUS_PENDING);
    assert_eq!(updated.retry_count, 1);
    assert_eq!(updated.error_log.as_deref(), Some("network timeout"));

    // Simulate exhaustion
    mark_outbox_failed(&app.pool, row.id, "exhausted max retries")
        .await
        .expect("mark failed");

    let failed = get_outbox_by_id(&app.pool, row.id)
        .await
        .expect("get outbox")
        .unwrap();
    assert_eq!(failed.status, OUTBOX_STATUS_FAILED);
    assert_eq!(failed.retry_count, 2);
    assert_eq!(failed.error_log.as_deref(), Some("exhausted max retries"));
}

#[tokio::test]
async fn test_outbox_durability_across_process_restart() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let recipient = format!("crash_{}@example.com", uuid::Uuid::new_v4());
    let payload = json!({
        "user_id": uuid::Uuid::new_v4(),
        "to": recipient,
        "token": "tok123",
        "url": "https://example.com/verify?token=tok123",
        "expires_at": chrono::Utc::now()
    });

    // 1. Outbox entry exists in DB with status 'pending' (simulating state before sudden shutdown)
    let row = insert_outbox(&app.pool, &recipient, "verification", payload)
        .await
        .expect("insert outbox");
    assert_eq!(row.status, OUTBOX_STATUS_PENDING);

    // 2. Fresh email sender & dispatcher boot (simulating process restart)
    let sender = Arc::new(CapturingEmailSender::new());
    let dispatcher = EmailDispatcher::new(
        Some(Arc::clone(&sender) as SharedEmailSender),
        Duration::from_secs(5),
    );

    // 3. Worker polls and delivers the pending message left from previous run
    let delivered = dispatcher
        .flush_outbox(&app.pool)
        .await
        .expect("flush outbox");
    assert!(delivered >= 1, "pending outbox row from prior run delivered");

    let sent_row = get_outbox_by_id(&app.pool, row.id)
        .await
        .expect("get outbox")
        .unwrap();
    assert_eq!(sent_row.status, OUTBOX_STATUS_SENT);
    assert!(sent_row.sent_at.is_some());

    let calls = sender.verification_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].to, recipient);
}

#[tokio::test]
async fn test_outbox_stale_processing_lease_recovery() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let recipient = format!("stale_{}@example.com", uuid::Uuid::new_v4());
    let payload = json!({
        "user_id": uuid::Uuid::new_v4(),
        "to": recipient,
        "token": "tok123",
        "url": "https://example.com/verify?token=tok123",
        "expires_at": chrono::Utc::now()
    });
    let row = insert_outbox(&app.pool, &recipient, "verification", payload)
        .await
        .expect("insert outbox");

    // 1. Claim row with a 1-second lease
    let claimed = claim_pending_outbox(&app.pool, 1, Duration::from_secs(1))
        .await
        .expect("claim outbox");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].id, row.id);

    // Verify row in DB is 'processing' with next_retry_at in the future
    let row_in_db = get_outbox_by_id(&app.pool, row.id)
        .await
        .expect("get outbox")
        .unwrap();
    assert_eq!(row_in_db.status, "processing");
    assert!(row_in_db.next_retry_at > chrono::Utc::now());

    // 2. Immediate claim attempt while lease is active should NOT claim the row
    let unexpired = claim_pending_outbox(&app.pool, 1, Duration::from_secs(1))
        .await
        .expect("claim outbox unexpired");
    assert_eq!(unexpired.len(), 0, "active lease must not be reclaimed");

    // 3. Wait for lease to expire
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // 4. Claiming again should reclaim the stale processing record
    let reclaimed = claim_pending_outbox(&app.pool, 1, Duration::from_secs(60))
        .await
        .expect("claim outbox expired lease");
    assert_eq!(reclaimed.len(), 1, "expired lease must be reclaimed");
    assert_eq!(reclaimed[0].id, row.id);

    // 5. Verify recover_stale_processing resets expired processing records to pending
    sqlx::query("UPDATE email_outbox SET next_retry_at = NOW() - INTERVAL '10 seconds' WHERE id = $1")
        .bind(row.id)
        .execute(&app.pool)
        .await
        .expect("expire next_retry_at");

    let recovered_count = recover_stale_processing(&app.pool)
        .await
        .expect("recover stale processing");
    assert!(recovered_count >= 1);

    let recovered_row = get_outbox_by_id(&app.pool, row.id)
        .await
        .expect("get outbox")
        .unwrap();
    assert_eq!(recovered_row.status, OUTBOX_STATUS_PENDING);
}

#[tokio::test]
async fn test_outbox_unconfigured_sender_does_not_burn_retries() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let recipient = format!("unconfigured_{}@example.com", uuid::Uuid::new_v4());
    let payload = json!({
        "user_id": uuid::Uuid::new_v4(),
        "to": recipient,
        "token": "tok123",
        "url": "https://example.com/verify?token=tok123",
        "expires_at": chrono::Utc::now()
    });
    let row = insert_outbox(&app.pool, &recipient, "verification", payload)
        .await
        .expect("insert outbox");

    let processed = process_outbox_batch(
        &app.pool,
        &None,
        Duration::from_secs(5),
        50,
        5,
        Duration::from_secs(1),
        Duration::from_secs(300),
        Duration::from_secs(300),
    )
    .await
    .expect("process outbox batch");

    assert_eq!(processed, 0, "no messages claimed or processed when sender is None");

    let row_in_db = get_outbox_by_id(&app.pool, row.id)
        .await
        .expect("get outbox")
        .unwrap();

    assert_eq!(row_in_db.status, OUTBOX_STATUS_PENDING, "status must remain pending");
    assert_eq!(row_in_db.retry_count, 0, "retry count must not be incremented");
}
