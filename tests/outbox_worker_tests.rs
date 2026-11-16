mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use metal_auth::db::models::{OUTBOX_STATUS_FAILED, OUTBOX_STATUS_PENDING, OUTBOX_STATUS_SENT};
use metal_auth::db::outbox::{
    claim_pending_outbox, cleanup_sent_outbox, get_outbox_by_id, insert_outbox,
    recover_stale_processing,
};
use metal_auth::email::outbox::{
    OutboxWorkerConfig, process_outbox_batch, run_outbox_worker_until,
};
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

    let _ = sqlx::query("DELETE FROM email_outbox WHERE recipient = $1")
        .bind(&email)
        .execute(&app.pool)
        .await;
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
        .verification_token_for(&email)
        .expect("verification token dispatched");
    let verify_res = app
        .post_json(ENDPOINT_VERIFY, json!({ "token": verify_token }))
        .await;
    assert_eq!(verify_res.status(), StatusCode::OK);

    // 2. Request password reset
    let reset_res = app
        .post_json(ENDPOINT_PASSWORD_RESET_REQUEST, json!({ "email": email }))
        .await;
    assert_eq!(reset_res.status(), StatusCode::OK);

    let rows = get_outbox_rows_for_recipient(&app.pool, &email)
        .await
        .expect("query outbox rows");
    let reset_rows: Vec<_> = rows
        .into_iter()
        .filter(|r| r.email_type == "password_reset")
        .collect();
    assert_eq!(
        reset_rows.len(),
        1,
        "password reset commits an outbox record"
    );
    assert_eq!(reset_rows[0].email_type, "password_reset");
    assert_eq!(reset_rows[0].status, OUTBOX_STATUS_SENT); // blocking dispatcher in test marks sent

    let _ = sqlx::query("DELETE FROM email_outbox WHERE recipient = $1")
        .bind(&email)
        .execute(&app.pool)
        .await;
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
        tokio::spawn(
            async move { claim_pending_outbox(&pool1, 5, Duration::from_secs(300)).await }
        ),
        tokio::spawn(
            async move { claim_pending_outbox(&pool2, 5, Duration::from_secs(300)).await }
        ),
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

    let _ = sqlx::query("DELETE FROM email_outbox WHERE id = ANY($1)")
        .bind(&ids)
        .execute(&app.pool)
        .await;
}

#[derive(Clone, Default)]
struct FailingEmailSender;

#[async_trait::async_trait]
impl metal_auth::email::hook::EmailSender for FailingEmailSender {
    async fn send_verification_email(
        &self,
        _payload: metal_auth::email::payload::VerificationEmailPayload,
    ) -> Result<(), metal_auth::email::hook::DynError> {
        Err("simulated transport failure".into())
    }

    async fn send_password_reset_email(
        &self,
        _payload: metal_auth::email::payload::PasswordResetEmailPayload,
    ) -> Result<(), metal_auth::email::hook::DynError> {
        Err("simulated transport failure".into())
    }
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

    let failing_sender: Option<SharedEmailSender> = Some(Arc::new(FailingEmailSender));
    let config = OutboxWorkerConfig {
        batch_size: 10,
        max_retries: 3,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(10),
        ..OutboxWorkerConfig::default()
    };

    // Attempt 1: failure schedules retry with backoff, retry_count becomes 1
    let p1 = process_outbox_batch(&app.pool, &failing_sender, Duration::from_secs(1), &config)
        .await
        .expect("batch attempt 1");
    assert!(p1 >= 1);

    let updated = get_outbox_by_id(&app.pool, row.id)
        .await
        .expect("get outbox")
        .unwrap();
    assert_eq!(updated.status, OUTBOX_STATUS_PENDING);
    assert_eq!(updated.retry_count, 1);
    assert!(
        updated
            .error_log
            .as_deref()
            .unwrap_or("")
            .contains("simulated transport failure")
    );

    // Advance next_retry_at to NOW() so attempt 2 is eligible
    sqlx::query("UPDATE email_outbox SET next_retry_at = NOW() WHERE id = $1")
        .bind(row.id)
        .execute(&app.pool)
        .await
        .expect("reset next_retry_at");

    // Attempt 2: retry_count becomes 2
    let p2 = process_outbox_batch(&app.pool, &failing_sender, Duration::from_secs(1), &config)
        .await
        .expect("batch attempt 2");
    assert!(p2 >= 1);

    let updated2 = get_outbox_by_id(&app.pool, row.id)
        .await
        .expect("get outbox")
        .unwrap();
    assert_eq!(updated2.status, OUTBOX_STATUS_PENDING);
    assert_eq!(updated2.retry_count, 2);

    // Advance next_retry_at to NOW() so attempt 3 is eligible
    sqlx::query("UPDATE email_outbox SET next_retry_at = NOW() WHERE id = $1")
        .bind(row.id)
        .execute(&app.pool)
        .await
        .expect("reset next_retry_at");

    // Attempt 3: next_retry_count reaches max_retries (3), row marked failed
    let p3 = process_outbox_batch(&app.pool, &failing_sender, Duration::from_secs(1), &config)
        .await
        .expect("batch attempt 3");
    assert!(p3 >= 1);

    let failed = get_outbox_by_id(&app.pool, row.id)
        .await
        .expect("get outbox")
        .unwrap();
    assert_eq!(failed.status, OUTBOX_STATUS_FAILED);
    assert!(
        failed
            .error_log
            .as_deref()
            .unwrap_or("")
            .contains("simulated transport failure")
    );

    let _ = sqlx::query("DELETE FROM email_outbox WHERE id = $1")
        .bind(row.id)
        .execute(&app.pool)
        .await;
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
    assert!(
        delivered >= 1,
        "pending outbox row from prior run delivered"
    );

    let sent_row = get_outbox_by_id(&app.pool, row.id)
        .await
        .expect("get outbox")
        .unwrap();
    assert_eq!(sent_row.status, OUTBOX_STATUS_SENT);
    assert!(sent_row.sent_at.is_some());

    let calls = sender.verification_calls();
    let own_calls: Vec<_> = calls.iter().filter(|c| c.to == recipient).collect();
    assert_eq!(own_calls.len(), 1);
    assert_eq!(own_calls[0].to, recipient);

    let _ = sqlx::query("DELETE FROM email_outbox WHERE id = $1")
        .bind(row.id)
        .execute(&app.pool)
        .await;
}

/// Issue #50: `claim_pending_outbox` claims globally oldest-first, so rows inserted
/// by parallel test binaries can be claimed ahead of ours and `claimed[0].id == row.id`
/// flakes. Claim with a wide limit, match our own row by id, and restore any foreign
/// rows we swept up to their pre-claim state so other binaries are unaffected.
async fn claim_own_outbox_row(
    pool: &sqlx::PgPool,
    row_id: uuid::Uuid,
    lease: Duration,
) -> Option<metal_auth::EmailOutbox> {
    let foreign: Vec<(uuid::Uuid, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT id, status, next_retry_at FROM email_outbox \
         WHERE id <> $1 AND ((status = 'pending' AND next_retry_at <= NOW()) \
         OR (status = 'processing' AND next_retry_at <= NOW()))",
    )
    .bind(row_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let claimed = claim_pending_outbox(pool, 1000, lease)
        .await
        .expect("claim outbox");

    let mut own = None;
    for c in claimed {
        if c.id == row_id {
            own = Some(c);
        } else if let Some(snap) = foreign.iter().find(|(id, _, _)| *id == c.id) {
            let _ = sqlx::query(
                "UPDATE email_outbox SET status = $1, next_retry_at = $2 WHERE id = $3",
            )
            .bind(&snap.1)
            .bind(snap.2)
            .bind(c.id)
            .execute(pool)
            .await;
        } else {
            // Raced in after our snapshot: leave it claimable again.
            let _ = sqlx::query(
                "UPDATE email_outbox SET status = 'pending', next_retry_at = NOW() WHERE id = $1",
            )
            .bind(c.id)
            .execute(pool)
            .await;
        }
    }
    own
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

    // 1. Claim row with a 1-second lease (any-match on our id: foreign rows from
    // parallel binaries may be claimed alongside ours)
    let first = claim_own_outbox_row(&app.pool, row.id, Duration::from_secs(1))
        .await
        .expect("our outbox row must be claimed");
    assert_eq!(first.status, "processing");
    assert!(first.next_retry_at > chrono::Utc::now());

    // Verify row in DB is 'processing' with next_retry_at in the future
    let row_in_db = get_outbox_by_id(&app.pool, row.id)
        .await
        .expect("get outbox")
        .unwrap();
    assert_eq!(row_in_db.status, "processing");
    assert!(row_in_db.next_retry_at > chrono::Utc::now());

    // 2. Immediate claim attempt while lease is active should NOT claim the row
    // (foreign due rows may still be claimed; only ours must be absent)
    let unexpired = claim_own_outbox_row(&app.pool, row.id, Duration::from_secs(1)).await;
    assert!(unexpired.is_none(), "active lease must not be reclaimed");

    // 3. Wait for lease to expire
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // 4. Claiming again should reclaim the stale processing record
    let reclaimed = claim_own_outbox_row(&app.pool, row.id, Duration::from_secs(60))
        .await
        .expect("expired lease must be reclaimed");
    assert_eq!(reclaimed.status, "processing");
    assert!(reclaimed.next_retry_at > chrono::Utc::now());

    // 5. Verify recover_stale_processing resets expired processing records to pending
    sqlx::query(
        "UPDATE email_outbox SET next_retry_at = NOW() - INTERVAL '10 seconds' WHERE id = $1",
    )
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

    let _ = sqlx::query("DELETE FROM email_outbox WHERE id = $1")
        .bind(row.id)
        .execute(&app.pool)
        .await;
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
        &OutboxWorkerConfig::default(),
    )
    .await
    .expect("process outbox batch");

    assert_eq!(
        processed, 0,
        "no messages claimed or processed when sender is None"
    );

    let row_in_db = get_outbox_by_id(&app.pool, row.id)
        .await
        .expect("get outbox")
        .unwrap();

    assert_eq!(
        row_in_db.status, OUTBOX_STATUS_PENDING,
        "status must remain pending"
    );
    assert_eq!(
        row_in_db.retry_count, 0,
        "retry count must not be incremented"
    );

    let _ = sqlx::query("DELETE FROM email_outbox WHERE id = $1")
        .bind(row.id)
        .execute(&app.pool)
        .await;
}

#[tokio::test]
async fn test_outbox_retention_cleanup() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let old_recipient = format!("old_sent_{}@example.com", uuid::Uuid::new_v4());
    let fresh_recipient = format!("fresh_sent_{}@example.com", uuid::Uuid::new_v4());
    let pending_recipient = format!("pending_{}@example.com", uuid::Uuid::new_v4());

    let payload = json!({
        "to": "test@example.com"
    });

    // 1. Insert old sent row with sent_at = NOW() - INTERVAL '8 days'
    let old_row = insert_outbox(&app.pool, &old_recipient, "verification", payload.clone())
        .await
        .expect("insert old row");
    sqlx::query(
        "UPDATE email_outbox SET status = $1, sent_at = NOW() - INTERVAL '8 days' WHERE id = $2",
    )
    .bind(OUTBOX_STATUS_SENT)
    .bind(old_row.id)
    .execute(&app.pool)
    .await
    .expect("update old row to sent");

    // 2. Insert fresh sent row with sent_at = NOW()
    let fresh_row = insert_outbox(&app.pool, &fresh_recipient, "verification", payload.clone())
        .await
        .expect("insert fresh row");
    sqlx::query("UPDATE email_outbox SET status = $1, sent_at = NOW() WHERE id = $2")
        .bind(OUTBOX_STATUS_SENT)
        .bind(fresh_row.id)
        .execute(&app.pool)
        .await
        .expect("update fresh row to sent");

    // 3. Insert pending row
    let pending_row = insert_outbox(&app.pool, &pending_recipient, "verification", payload)
        .await
        .expect("insert pending row");

    // 4. Run cleanup_sent_outbox with 7-day retention window
    let purged = cleanup_sent_outbox(&app.pool, Duration::from_secs(7 * 24 * 3600))
        .await
        .expect("cleanup sent outbox");
    assert!(purged >= 1, "at least the old sent row must be purged");

    // 5. Assert old sent row is deleted
    let old_check = get_outbox_by_id(&app.pool, old_row.id)
        .await
        .expect("query old row");
    assert!(old_check.is_none(), "old sent row must be purged");

    // 6. Assert fresh sent row remains
    let fresh_check = get_outbox_by_id(&app.pool, fresh_row.id)
        .await
        .expect("query fresh row");
    assert!(fresh_check.is_some(), "fresh sent row must remain");

    // 7. Assert pending row remains
    let pending_check = get_outbox_by_id(&app.pool, pending_row.id)
        .await
        .expect("query pending row");
    assert!(pending_check.is_some(), "pending row must remain");

    let _ = sqlx::query("DELETE FROM email_outbox WHERE id IN ($1, $2)")
        .bind(fresh_row.id)
        .bind(pending_row.id)
        .execute(&app.pool)
        .await;
}

// Fails only our own recipient with a token-echoing error; foreign rows swept
// into the same batch must still deliver so parallel binaries are unaffected.
struct SelectiveEchoSender {
    fail_recipient: String,
}

#[async_trait::async_trait]
impl metal_auth::EmailSender for SelectiveEchoSender {
    async fn send_verification_email(
        &self,
        payload: metal_auth::VerificationEmailPayload,
    ) -> Result<(), metal_auth::DynError> {
        if payload.to == self.fail_recipient {
            return Err(Box::new(std::io::Error::other(format!(
                "smtp refused token={} for {}",
                payload.token, payload.to
            ))));
        }
        Ok(())
    }

    async fn send_password_reset_email(
        &self,
        _payload: metal_auth::PasswordResetEmailPayload,
    ) -> Result<(), metal_auth::DynError> {
        Ok(())
    }
}

#[tokio::test]
async fn test_outbox_error_log_redacts_echoed_token() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let secret = format!("zx9-outbox-secret-{}", uuid::Uuid::new_v4());
    let recipient = format!("echo_{}@example.com", uuid::Uuid::new_v4());
    let payload = json!({
        "user_id": uuid::Uuid::new_v4(),
        "to": recipient,
        "token": secret,
        "url": format!("https://example.com/verify?token={secret}"),
        "expires_at": chrono::Utc::now()
    });
    let row = insert_outbox(&app.pool, &recipient, "verification", payload)
        .await
        .expect("insert outbox");

    let sender = Arc::new(SelectiveEchoSender {
        fail_recipient: recipient.clone(),
    });
    let dispatcher = EmailDispatcher::new(
        Some(Arc::clone(&sender) as SharedEmailSender),
        Duration::from_secs(5),
    );
    let _ = dispatcher.flush_outbox(&app.pool).await;

    let stored = get_outbox_by_id(&app.pool, row.id)
        .await
        .expect("get outbox")
        .expect("own row present");
    assert_ne!(stored.status, OUTBOX_STATUS_SENT, "echo sender must fail");
    let error_log = stored.error_log.expect("failed delivery records error_log");
    assert!(
        !error_log.contains(&secret),
        "raw token leaked into error_log"
    );
    assert!(error_log.contains("token=[REDACTED]"));

    let _ = sqlx::query("DELETE FROM email_outbox WHERE id = $1")
        .bind(row.id)
        .execute(&app.pool)
        .await;
}

#[tokio::test]
async fn test_outbox_worker_until_stops_on_shutdown() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let worker = tokio::spawn(run_outbox_worker_until(
        app.pool.clone(),
        None,
        Duration::from_millis(50),
        OutboxWorkerConfig::default(),
        Arc::new(tokio::sync::Notify::new()),
        shutdown_rx,
    ));
    shutdown_tx.send(true).expect("signal shutdown");
    tokio::time::timeout(Duration::from_secs(10), worker)
        .await
        .expect("worker stops after shutdown signal")
        .expect("worker join");
}
