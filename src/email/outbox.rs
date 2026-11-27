use std::sync::Arc;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use tracing::{error, info, warn};

use crate::db::models::{EMAIL_TYPE_PASSWORD_RESET, EMAIL_TYPE_VERIFICATION, EmailOutbox};
#[cfg(any(feature = "postgres", feature = "mysql", feature = "mongodb"))]
use crate::db::store::{DatabaseStore, OutboxStore};
pub use crate::email::OutboxWorkerConfig;
use crate::email::hook::{SharedEmailSender, sanitize_error_str, sanitize_sender_error};
use crate::email::payload::{PasswordResetEmailPayload, VerificationEmailPayload};
#[cfg(any(feature = "postgres", feature = "mysql", feature = "mongodb"))]
use crate::error::AppError;

/// Computes exponential backoff: `initial_backoff * 2^retry_count`, clamped at `max_backoff`.
pub fn calculate_backoff(
    retry_count: i32,
    initial_backoff: Duration,
    max_backoff: Duration,
) -> Duration {
    let exponent = (retry_count.max(0) as u32).min(31);
    let factor = 2u32.saturating_pow(exponent);
    let backoff = initial_backoff.saturating_mul(factor);
    backoff.min(max_backoff)
}

/// Atomically claims and processes a batch of pending outbox messages.
#[cfg(any(feature = "postgres", feature = "mysql", feature = "mongodb"))]
pub async fn process_outbox_batch(
    store: &dyn OutboxStore,
    sender: &Option<SharedEmailSender>,
    timeout: Duration,
    config: &OutboxWorkerConfig,
) -> Result<usize, AppError> {
    let Some(sender) = sender.as_ref() else {
        return Ok(0);
    };

    let messages = store
        .claim_pending_outbox(config.batch_size, config.lease_duration)
        .await?;
    if messages.is_empty() {
        return Ok(0);
    }

    let count = messages.len();
    for msg in messages {
        deliver_single_message(store, sender, msg, timeout, config).await;
    }

    Ok(count)
}

async fn deliver_single_message(
    store: &dyn OutboxStore,
    sender: &SharedEmailSender,
    msg: EmailOutbox,
    timeout: Duration,
    config: &OutboxWorkerConfig,
) {
    // Destructure to move `payload` instead of cloning it; only scalars are kept.
    let EmailOutbox {
        id,
        email_type,
        payload,
        retry_count,
        ..
    } = msg;
    let result = match email_type.as_str() {
        EMAIL_TYPE_VERIFICATION => {
            match serde_json::from_value::<VerificationEmailPayload>(payload) {
                Ok(payload) => {
                    tokio::time::timeout(timeout, sender.send_verification_email(payload)).await
                }
                Err(e) => {
                    // Serde errors carry no payload bytes, but sanitize at the
                    // persistence boundary anyway so `error_log` never depends on it.
                    let err_msg = sanitize_error_str(&format!("corrupt verification payload: {e}"));
                    error!(op = "outbox_delivery", id = %id, err = %err_msg);
                    mark_failed(store, id, &err_msg).await;
                    return;
                }
            }
        }
        EMAIL_TYPE_PASSWORD_RESET => {
            match serde_json::from_value::<PasswordResetEmailPayload>(payload) {
                Ok(payload) => {
                    tokio::time::timeout(timeout, sender.send_password_reset_email(payload)).await
                }
                Err(e) => {
                    let err_msg =
                        sanitize_error_str(&format!("corrupt password reset payload: {e}"));
                    error!(op = "outbox_delivery", id = %id, err = %err_msg);
                    mark_failed(store, id, &err_msg).await;
                    return;
                }
            }
        }
        unknown => {
            let err_msg = sanitize_error_str(&format!("unknown email type: {unknown}"));
            error!(op = "outbox_delivery", id = %id, err = %err_msg);
            mark_failed(store, id, &err_msg).await;
            return;
        }
    };

    match result {
        // Lease misses stay log-only inside the store impls, so settle is fire-and-log.
        Ok(Ok(())) => match store.mark_outbox_sent(id).await {
            Ok(()) => {
                info!(op = "outbox_delivery", id = %id, email_type = %email_type, "outbox email sent")
            }
            Err(e) => {
                error!(op = "outbox_delivery", id = %id, err = %e, "database error marking sent")
            }
        },
        Ok(Err(send_err)) => {
            let err_msg = format!("send error: {}", sanitize_sender_error(&send_err));
            handle_delivery_failure(store, id, retry_count, &err_msg, config).await;
        }
        Err(_elapsed) => {
            let err_msg = "send timed out".to_string();
            handle_delivery_failure(store, id, retry_count, &err_msg, config).await;
        }
    }
}

// Shared terminal-failure path: persists a sanitized `error_log` and logs it.
async fn mark_failed(store: &dyn OutboxStore, id: uuid::Uuid, err_msg: &str) {
    if let Err(e) = store.mark_outbox_failed(id, err_msg).await {
        error!(op = "outbox_delivery", id = %id, err = %e, "database error marking outbox as failed")
    }
}

#[cfg(any(feature = "postgres", feature = "mysql", feature = "mongodb"))]
async fn handle_delivery_failure(
    store: &dyn OutboxStore,
    id: uuid::Uuid,
    retry_count: i32,
    err_msg: &str,
    config: &OutboxWorkerConfig,
) {
    let next_retry_count = retry_count + 1;
    if next_retry_count >= config.max_retries as i32 {
        error!(
            op = "outbox_delivery",
            id = %id,
            retries = next_retry_count,
            err = %err_msg,
            "outbox delivery exhausted max retries; marked failed"
        );
        if let Err(e) = store.mark_outbox_failed(id, err_msg).await {
            error!(
                op = "outbox_delivery",
                id = %id,
                err = %e,
                "database error marking outbox as failed"
            );
        }
    } else {
        let backoff = calculate_backoff(retry_count, config.initial_backoff, config.max_backoff);
        let next_retry_at =
            Utc::now() + ChronoDuration::from_std(backoff).unwrap_or(ChronoDuration::seconds(300));
        warn!(
            op = "outbox_delivery",
            id = %id,
            retries = next_retry_count,
            backoff_secs = backoff.as_secs(),
            err = %err_msg,
            "outbox delivery failed; scheduled retry with exponential backoff"
        );
        // Pass the incremented count through: the Mongo impl sets it, the SQL
        // impls increment past it to the same value.
        if let Err(e) = store
            .record_outbox_retry(id, next_retry_count, next_retry_at, err_msg)
            .await
        {
            error!(
                op = "outbox_delivery",
                id = %id,
                err = %e,
                "database error recording outbox retry"
            );
        }
    }
}

#[cfg(any(feature = "postgres", feature = "mysql", feature = "mongodb"))]
async fn drain_outbox_batches(
    store: &dyn OutboxStore,
    sender: &Option<SharedEmailSender>,
    timeout: Duration,
    config: &OutboxWorkerConfig,
    shutdown: &tokio::sync::watch::Receiver<bool>,
) {
    loop {
        // Always finish the claimed batch; only then check shutdown before
        // claiming another. Under a large backlog an unconditional drain would
        // delay exit indefinitely, but an already-signalled shutdown must not
        // abandon the in-flight batch either.
        match process_outbox_batch(store, sender, timeout, config).await {
            Ok(count) if count >= config.batch_size as usize => {
                if shutdown.has_changed().unwrap_or(true) {
                    break;
                }
            }
            Ok(_) => break,
            Err(e) => {
                error!(err = %e, "outbox batch processing error");
                break;
            }
        }
    }
}

/// Runs the background outbox polling loop until the process ends.
///
/// Prefer [`run_outbox_worker_until`] when the host supports graceful
/// shutdown; this wrapper never signals shutdown so the loop is infinite.
#[cfg(any(feature = "postgres", feature = "mysql", feature = "mongodb"))]
pub async fn run_outbox_worker(
    store: Arc<dyn DatabaseStore>,
    sender: Option<SharedEmailSender>,
    timeout: Duration,
    config: OutboxWorkerConfig,
    notify: Arc<tokio::sync::Notify>,
) {
    let (_shutdown_guard, shutdown) = tokio::sync::watch::channel(false);
    run_outbox_worker_until(store, sender, timeout, config, notify, shutdown).await;
}

/// Same as [`run_outbox_worker`], but each loop iteration also watches
/// `shutdown`: sending any value (or dropping the sender) breaks the loop
/// after the in-flight drain completes, so no claimed message is abandoned.
#[cfg(any(feature = "postgres", feature = "mysql", feature = "mongodb"))]
pub async fn run_outbox_worker_until(
    store: Arc<dyn DatabaseStore>,
    sender: Option<SharedEmailSender>,
    timeout: Duration,
    config: OutboxWorkerConfig,
    notify: Arc<tokio::sync::Notify>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    if let Err(e) = store
        .outbox()
        .recover_stale_processing(config.lease_duration)
        .await
    {
        error!(err = %e, "failed to recover stale outbox processing records on startup");
    }
    if let Err(e) = store
        .outbox()
        .cleanup_sent_outbox(config.sent_retention)
        .await
    {
        error!(err = %e, "failed to cleanup sent outbox records on startup");
    }
    // Same `expires_at <= NOW()` predicate as the retired pool-typed
    // `prune_expired_challenges`, routed through each backend's `TotpStore`.
    if let Err(e) = store.totp().prune_expired_two_factor_tokens().await {
        error!(err = %e, "failed to prune expired two-factor challenge tokens on startup");
    }

    // Drain existing pending records immediately on startup before sleeping
    drain_outbox_batches(store.outbox(), &sender, timeout, &config, &shutdown).await;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(config.poll_interval) => {}
            _ = notify.notified() => {}
            _ = shutdown.changed() => {
                break;
            }
        }

        drain_outbox_batches(store.outbox(), &sender, timeout, &config, &shutdown).await;
        if let Err(e) = store
            .outbox()
            .cleanup_sent_outbox(config.sent_retention)
            .await
        {
            error!(err = %e, "failed to cleanup sent outbox records");
        }
        if let Err(e) = store.totp().prune_expired_two_factor_tokens().await {
            error!(err = %e, "failed to prune expired two-factor challenge tokens");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    // In-memory `OutboxStore` so the claim→deliver→settle flow is covered
    // without a database; per-backend SQL semantics stay with the PG
    // integration tests below.
    struct FakeOutboxStore {
        rows: std::sync::Mutex<Vec<EmailOutbox>>,
    }

    impl FakeOutboxStore {
        fn with_rows(rows: Vec<EmailOutbox>) -> Self {
            Self {
                rows: std::sync::Mutex::new(rows),
            }
        }

        fn row(&self, id: uuid::Uuid) -> EmailOutbox {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.id == id)
                .cloned()
                .expect("test row present")
        }
    }

    fn fake_msg(email_type: &str, payload: serde_json::Value) -> EmailOutbox {
        EmailOutbox {
            id: uuid::Uuid::new_v4(),
            recipient: "fake@example.com".into(),
            email_type: email_type.into(),
            payload,
            status: crate::db::models::OUTBOX_STATUS_PENDING.into(),
            retry_count: 0,
            next_retry_at: Utc::now() - ChronoDuration::seconds(1),
            created_at: Utc::now(),
            sent_at: None,
            error_log: None,
        }
    }

    fn verification_payload_value() -> serde_json::Value {
        serde_json::json!({
            "user_id": uuid::Uuid::new_v4(),
            "to": "fake@example.com",
            "token": "tok",
            "url": "https://example.com",
            "expires_at": Utc::now(),
        })
    }

    #[async_trait::async_trait]
    impl crate::db::store::OutboxStore for FakeOutboxStore {
        async fn insert_outbox(
            &self,
            recipient: &str,
            email_type: &str,
            payload: serde_json::Value,
        ) -> Result<EmailOutbox, AppError> {
            let mut msg = fake_msg(email_type, payload);
            msg.recipient = recipient.into();
            self.rows.lock().unwrap().push(msg.clone());
            Ok(msg)
        }

        async fn claim_pending_outbox(
            &self,
            batch_size: u32,
            _lock_duration: Duration,
        ) -> Result<Vec<EmailOutbox>, AppError> {
            let now = Utc::now();
            let mut rows = self.rows.lock().unwrap();
            let mut claimed = Vec::new();
            for row in rows.iter_mut() {
                if claimed.len() >= batch_size as usize {
                    break;
                }
                if row.status == crate::db::models::OUTBOX_STATUS_PENDING
                    && row.next_retry_at <= now
                {
                    row.status = crate::db::models::OUTBOX_STATUS_PROCESSING.into();
                    claimed.push(row.clone());
                }
            }
            Ok(claimed)
        }

        async fn mark_outbox_sent(&self, id: uuid::Uuid) -> Result<(), AppError> {
            let mut rows = self.rows.lock().unwrap();
            match rows.iter_mut().find(|r| r.id == id) {
                Some(row) if row.status == crate::db::models::OUTBOX_STATUS_PROCESSING => {
                    row.status = crate::db::models::OUTBOX_STATUS_SENT.into();
                    row.sent_at = Some(Utc::now());
                    Ok(())
                }
                // Lost lease stays log-only, mirroring the backend impls.
                Some(_) | None => Ok(()),
            }
        }

        async fn record_outbox_retry(
            &self,
            id: uuid::Uuid,
            retry_count: i32,
            next_retry_at: chrono::DateTime<Utc>,
            error_log: &str,
        ) -> Result<(), AppError> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(row) = rows.iter_mut().find(|r| r.id == id) {
                row.retry_count = retry_count;
                row.next_retry_at = next_retry_at;
                row.error_log = Some(error_log.into());
                row.status = crate::db::models::OUTBOX_STATUS_PENDING.into();
            }
            Ok(())
        }

        async fn mark_outbox_failed(
            &self,
            id: uuid::Uuid,
            error_log: &str,
        ) -> Result<(), AppError> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(row) = rows.iter_mut().find(|r| r.id == id) {
                row.status = crate::db::models::OUTBOX_STATUS_FAILED.into();
                row.error_log = Some(error_log.into());
            }
            Ok(())
        }

        async fn cleanup_sent_outbox(&self, _retention: Duration) -> Result<u64, AppError> {
            let mut rows = self.rows.lock().unwrap();
            let before = rows.len();
            rows.retain(|r| r.status != crate::db::models::OUTBOX_STATUS_SENT);
            Ok((before - rows.len()) as u64)
        }

        async fn recover_stale_processing(&self, _stale: Duration) -> Result<u64, AppError> {
            let mut rows = self.rows.lock().unwrap();
            let mut recovered = 0;
            for row in rows.iter_mut() {
                if row.status == crate::db::models::OUTBOX_STATUS_PROCESSING {
                    row.status = crate::db::models::OUTBOX_STATUS_PENDING.into();
                    recovered += 1;
                }
            }
            Ok(recovered)
        }
    }

    struct FakeSender {
        calls: std::sync::Mutex<Vec<String>>,
        fail: bool,
    }

    impl FakeSender {
        fn ok() -> Self {
            Self {
                calls: std::sync::Mutex::new(Vec::new()),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                calls: std::sync::Mutex::new(Vec::new()),
                fail: true,
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::email::hook::EmailSender for FakeSender {
        async fn send_verification_email(
            &self,
            payload: VerificationEmailPayload,
        ) -> Result<(), crate::email::hook::DynError> {
            self.calls.lock().unwrap().push(payload.to.clone());
            if self.fail {
                return Err("fake sender down".into());
            }
            Ok(())
        }

        async fn send_password_reset_email(
            &self,
            payload: PasswordResetEmailPayload,
        ) -> Result<(), crate::email::hook::DynError> {
            self.calls.lock().unwrap().push(payload.to.clone());
            if self.fail {
                return Err("fake sender down".into());
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn batch_claim_delivers_and_marks_sent() {
        let store = FakeOutboxStore::with_rows(vec![
            fake_msg(
                crate::db::models::EMAIL_TYPE_VERIFICATION,
                verification_payload_value(),
            ),
            fake_msg(
                crate::db::models::EMAIL_TYPE_VERIFICATION,
                verification_payload_value(),
            ),
        ]);
        let sender: SharedEmailSender = Arc::new(FakeSender::ok());
        let count = process_outbox_batch(
            &store,
            &Some(sender.clone()),
            Duration::from_secs(1),
            &OutboxWorkerConfig::default(),
        )
        .await
        .expect("batch processes");
        assert_eq!(count, 2);
        for row in store.rows.lock().unwrap().iter() {
            assert_eq!(row.status, crate::db::models::OUTBOX_STATUS_SENT);
        }
    }

    #[tokio::test]
    async fn exhausted_retries_mark_failed() {
        let mut msg = fake_msg(
            crate::db::models::EMAIL_TYPE_VERIFICATION,
            verification_payload_value(),
        );
        msg.status = crate::db::models::OUTBOX_STATUS_PROCESSING.into();
        let id = msg.id;
        let store = FakeOutboxStore::with_rows(vec![msg]);
        let sender: SharedEmailSender = Arc::new(FakeSender::failing());
        let config = OutboxWorkerConfig {
            max_retries: 1,
            ..OutboxWorkerConfig::default()
        };
        deliver_single_message(
            &store,
            &sender,
            store.row(id),
            Duration::from_secs(1),
            &config,
        )
        .await;
        let row = store.row(id);
        assert_eq!(row.status, crate::db::models::OUTBOX_STATUS_FAILED);
        assert!(
            row.error_log
                .unwrap_or_default()
                .contains("fake sender down")
        );
    }

    #[tokio::test]
    async fn failed_send_schedules_retry_with_backoff() {
        let mut msg = fake_msg(
            crate::db::models::EMAIL_TYPE_VERIFICATION,
            verification_payload_value(),
        );
        msg.status = crate::db::models::OUTBOX_STATUS_PROCESSING.into();
        let id = msg.id;
        let store = FakeOutboxStore::with_rows(vec![msg]);
        let sender: SharedEmailSender = Arc::new(FakeSender::failing());
        deliver_single_message(
            &store,
            &sender,
            store.row(id),
            Duration::from_secs(1),
            &OutboxWorkerConfig::default(),
        )
        .await;
        let row = store.row(id);
        assert_eq!(row.status, crate::db::models::OUTBOX_STATUS_PENDING);
        assert_eq!(row.retry_count, 1);
        assert!(row.next_retry_at > Utc::now());
    }

    #[tokio::test]
    async fn corrupt_payload_marks_failed_without_sender_call() {
        let mut msg = fake_msg(
            crate::db::models::EMAIL_TYPE_VERIFICATION,
            serde_json::json!({"corrupt": true}),
        );
        msg.status = crate::db::models::OUTBOX_STATUS_PROCESSING.into();
        let id = msg.id;
        let store = FakeOutboxStore::with_rows(vec![msg]);
        let sender = Arc::new(FakeSender::ok());
        deliver_single_message(
            &store,
            &(sender.clone() as SharedEmailSender),
            store.row(id),
            Duration::from_secs(1),
            &OutboxWorkerConfig::default(),
        )
        .await;
        let row = store.row(id);
        assert_eq!(row.status, crate::db::models::OUTBOX_STATUS_FAILED);
        assert!(sender.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unknown_type_marks_failed() {
        let mut msg = fake_msg("unknown_notification", serde_json::json!({}));
        msg.status = crate::db::models::OUTBOX_STATUS_PROCESSING.into();
        let id = msg.id;
        let store = FakeOutboxStore::with_rows(vec![msg]);
        let sender: SharedEmailSender = Arc::new(FakeSender::ok());
        deliver_single_message(
            &store,
            &sender,
            store.row(id),
            Duration::from_secs(1),
            &OutboxWorkerConfig::default(),
        )
        .await;
        assert_eq!(
            store.row(id).status,
            crate::db::models::OUTBOX_STATUS_FAILED
        );
    }

    #[test]
    fn test_calculate_backoff_exponential() {
        let initial = Duration::from_secs(1);
        let max = Duration::from_secs(60);

        assert_eq!(calculate_backoff(0, initial, max), Duration::from_secs(1));
        assert_eq!(calculate_backoff(1, initial, max), Duration::from_secs(2));
        assert_eq!(calculate_backoff(2, initial, max), Duration::from_secs(4));
        assert_eq!(calculate_backoff(3, initial, max), Duration::from_secs(8));
        assert_eq!(calculate_backoff(4, initial, max), Duration::from_secs(16));
        assert_eq!(calculate_backoff(5, initial, max), Duration::from_secs(32));
        assert_eq!(calculate_backoff(6, initial, max), Duration::from_secs(60)); // capped at max
    }

    #[test]
    fn test_calculate_backoff_fractional_seconds() {
        let initial = Duration::from_millis(500);
        let max = Duration::from_secs(10);
        assert_eq!(
            calculate_backoff(0, initial, max),
            Duration::from_millis(500)
        );
        assert_eq!(
            calculate_backoff(1, initial, max),
            Duration::from_millis(1000)
        );
        assert_eq!(
            calculate_backoff(2, initial, max),
            Duration::from_millis(2000)
        );
        assert_eq!(
            calculate_backoff(3, initial, max),
            Duration::from_millis(4000)
        );
    }

    #[test]
    fn test_outbox_worker_config_retention_defaults_and_builder() {
        let config = OutboxWorkerConfig::default();
        assert_eq!(
            config.sent_retention,
            Duration::from_secs(crate::config::DEFAULT_OUTBOX_SENT_RETENTION_SECS)
        );

        let custom = config.with_sent_retention(Duration::from_secs(86400));
        assert_eq!(custom.sent_retention, Duration::from_secs(86400));
    }

    #[test]
    fn test_outbox_worker_config_lease_duration_builder() {
        let config = OutboxWorkerConfig::default();
        assert_eq!(config.lease_duration, Duration::from_secs(300));
        let custom = config.with_lease_duration(Duration::from_secs(45));
        assert_eq!(custom.lease_duration, Duration::from_secs(45));
    }

    #[cfg(feature = "postgres")]
    async fn test_pool() -> Option<PgPool> {
        dotenvy::dotenv().ok();
        let url = match std::env::var("DATABASE_URL") {
            Ok(u) => u,
            Err(_) => {
                assert!(
                    std::env::var_os("CI").is_none(),
                    "DATABASE_URL must be set in CI"
                );
                return None;
            }
        };
        Some(
            crate::db::init_pool(&crate::Config {
                database_url: url,
                ..Default::default()
            })
            .await
            .expect("failed to initialize test database pool"),
        )
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn deliver_single_message_handles_corrupt_verification_payload() {
        let _guard = crate::db::DB_TEST_LOCK.lock().await;
        let Some(pool) = test_pool().await else {
            return;
        };
        let store = crate::db::postgres::PostgresStore::new(pool.clone());

        let row_id = uuid::Uuid::new_v4();
        let recipient = format!("corrupt_v_{}@example.com", row_id);
        sqlx::query(
            r#"
            INSERT INTO email_outbox (id, recipient, email_type, payload, status, retry_count, next_retry_at)
            VALUES ($1, $2, 'verification', '{"corrupt": true}'::jsonb, $3, 0, NOW() + INTERVAL '60 seconds')
            "#,
        )
        .bind(row_id)
        .bind(&recipient)
        .bind(crate::db::models::OUTBOX_STATUS_PROCESSING)
        .execute(&pool)
        .await
        .expect("insert corrupt verification outbox row");

        let msg = crate::db::outbox::get_outbox_by_id(&pool, row_id)
            .await
            .expect("fetch row")
            .unwrap();

        let sender: SharedEmailSender = Arc::new(crate::email::NoopEmailSender);
        deliver_single_message(
            store.outbox(),
            &sender,
            msg,
            Duration::from_secs(1),
            &OutboxWorkerConfig::default(),
        )
        .await;

        let updated = crate::db::outbox::get_outbox_by_id(&pool, row_id)
            .await
            .expect("fetch row")
            .unwrap();
        assert_eq!(updated.status, crate::db::models::OUTBOX_STATUS_FAILED);
        assert!(
            updated
                .error_log
                .as_deref()
                .unwrap_or("")
                .contains("corrupt verification payload")
        );

        let _ = sqlx::query("DELETE FROM email_outbox WHERE id = $1")
            .bind(row_id)
            .execute(&pool)
            .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn deliver_single_message_handles_corrupt_password_reset_payload() {
        let _guard = crate::db::DB_TEST_LOCK.lock().await;
        let Some(pool) = test_pool().await else {
            return;
        };
        let store = crate::db::postgres::PostgresStore::new(pool.clone());

        let row_id = uuid::Uuid::new_v4();
        let recipient = format!("corrupt_pr_{}@example.com", row_id);
        sqlx::query(
            r#"
            INSERT INTO email_outbox (id, recipient, email_type, payload, status, retry_count, next_retry_at)
            VALUES ($1, $2, 'password_reset', '{"corrupt": true}'::jsonb, $3, 0, NOW() + INTERVAL '60 seconds')
            "#,
        )
        .bind(row_id)
        .bind(&recipient)
        .bind(crate::db::models::OUTBOX_STATUS_PROCESSING)
        .execute(&pool)
        .await
        .expect("insert corrupt password reset outbox row");

        let msg = crate::db::outbox::get_outbox_by_id(&pool, row_id)
            .await
            .expect("fetch row")
            .unwrap();

        let sender: SharedEmailSender = Arc::new(crate::email::NoopEmailSender);
        deliver_single_message(
            store.outbox(),
            &sender,
            msg,
            Duration::from_secs(1),
            &OutboxWorkerConfig::default(),
        )
        .await;

        let updated = crate::db::outbox::get_outbox_by_id(&pool, row_id)
            .await
            .expect("fetch row")
            .unwrap();
        assert_eq!(updated.status, crate::db::models::OUTBOX_STATUS_FAILED);
        assert!(
            updated
                .error_log
                .as_deref()
                .unwrap_or("")
                .contains("corrupt password reset payload")
        );

        let _ = sqlx::query("DELETE FROM email_outbox WHERE id = $1")
            .bind(row_id)
            .execute(&pool)
            .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn deliver_single_message_handles_unknown_email_type() {
        let _guard = crate::db::DB_TEST_LOCK.lock().await;
        let Some(pool) = test_pool().await else {
            return;
        };
        let store = crate::db::postgres::PostgresStore::new(pool.clone());

        let row_id = uuid::Uuid::new_v4();
        let recipient = format!("unknown_type_{}@example.com", row_id);
        sqlx::query(
            r#"
            INSERT INTO email_outbox (id, recipient, email_type, payload, status, retry_count, next_retry_at)
            VALUES ($1, $2, 'unknown_notification', '{}'::jsonb, $3, 0, NOW() + INTERVAL '60 seconds')
            "#,
        )
        .bind(row_id)
        .bind(&recipient)
        .bind(crate::db::models::OUTBOX_STATUS_PROCESSING)
        .execute(&pool)
        .await
        .expect("insert unknown email type outbox row");

        let msg = crate::db::outbox::get_outbox_by_id(&pool, row_id)
            .await
            .expect("fetch row")
            .unwrap();

        let sender: SharedEmailSender = Arc::new(crate::email::NoopEmailSender);
        deliver_single_message(
            store.outbox(),
            &sender,
            msg,
            Duration::from_secs(1),
            &OutboxWorkerConfig::default(),
        )
        .await;

        let updated = crate::db::outbox::get_outbox_by_id(&pool, row_id)
            .await
            .expect("fetch row")
            .unwrap();
        assert_eq!(updated.status, crate::db::models::OUTBOX_STATUS_FAILED);
        assert!(
            updated
                .error_log
                .as_deref()
                .unwrap_or("")
                .contains("unknown email type: unknown_notification")
        );

        let _ = sqlx::query("DELETE FROM email_outbox WHERE id = $1")
            .bind(row_id)
            .execute(&pool)
            .await;
    }

    struct HangingEmailSender;
    #[async_trait::async_trait]
    impl crate::email::hook::EmailSender for HangingEmailSender {
        async fn send_verification_email(
            &self,
            _payload: VerificationEmailPayload,
        ) -> Result<(), crate::email::hook::DynError> {
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok(())
        }
        async fn send_password_reset_email(
            &self,
            _payload: PasswordResetEmailPayload,
        ) -> Result<(), crate::email::hook::DynError> {
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok(())
        }
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn deliver_single_message_handles_timeout() {
        let _guard = crate::db::DB_TEST_LOCK.lock().await;
        let Some(pool) = test_pool().await else {
            return;
        };
        let store = crate::db::postgres::PostgresStore::new(pool.clone());

        let row_id = uuid::Uuid::new_v4();
        let recipient = format!("timeout_{}@example.com", row_id);
        let payload = serde_json::json!({
            "user_id": uuid::Uuid::new_v4(),
            "to": recipient,
            "token": "tok123",
            "url": "https://example.com",
            "expires_at": chrono::Utc::now()
        });
        sqlx::query(
            r#"
            INSERT INTO email_outbox (id, recipient, email_type, payload, status, retry_count, next_retry_at)
            VALUES ($1, $2, 'verification', $3, $4, 0, NOW() + INTERVAL '60 seconds')
            "#,
        )
        .bind(row_id)
        .bind(&recipient)
        .bind(payload)
        .bind(crate::db::models::OUTBOX_STATUS_PROCESSING)
        .execute(&pool)
        .await
        .expect("insert outbox row for timeout test");

        let msg = crate::db::outbox::get_outbox_by_id(&pool, row_id)
            .await
            .expect("fetch row")
            .unwrap();

        let sender: SharedEmailSender = Arc::new(HangingEmailSender);
        deliver_single_message(
            store.outbox(),
            &sender,
            msg,
            Duration::from_millis(10),
            &OutboxWorkerConfig::default(),
        )
        .await;

        let updated = crate::db::outbox::get_outbox_by_id(&pool, row_id)
            .await
            .expect("fetch row")
            .unwrap();
        assert_eq!(updated.status, crate::db::models::OUTBOX_STATUS_PENDING);
        assert_eq!(updated.retry_count, 1);
        assert!(
            updated
                .error_log
                .as_deref()
                .unwrap_or("")
                .contains("send timed out")
        );

        let _ = sqlx::query("DELETE FROM email_outbox WHERE id = $1")
            .bind(row_id)
            .execute(&pool)
            .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn deliver_single_message_lost_lease_logs_warning_and_does_not_panic() {
        let _guard = crate::db::DB_TEST_LOCK.lock().await;
        let Some(pool) = test_pool().await else {
            return;
        };
        let store = crate::db::postgres::PostgresStore::new(pool.clone());

        let row_id = uuid::Uuid::new_v4();
        let recipient = format!("lost_lease_{}@example.com", row_id);
        let payload = serde_json::json!({
            "user_id": uuid::Uuid::new_v4(),
            "to": recipient,
            "token": "tok123",
            "url": "https://example.com",
            "expires_at": chrono::Utc::now()
        });
        sqlx::query(
            r#"
            INSERT INTO email_outbox (id, recipient, email_type, payload, status, retry_count, next_retry_at)
            VALUES ($1, $2, 'verification', $3, $4, 0, NOW())
            "#,
        )
        .bind(row_id)
        .bind(&recipient)
        .bind(payload)
        .bind(crate::db::models::OUTBOX_STATUS_PENDING)
        .execute(&pool)
        .await
        .expect("insert outbox row for lost lease test");

        let msg = crate::db::outbox::get_outbox_by_id(&pool, row_id)
            .await
            .expect("fetch row")
            .unwrap();

        let sender: SharedEmailSender = Arc::new(crate::email::NoopEmailSender);
        deliver_single_message(
            store.outbox(),
            &sender,
            msg,
            Duration::from_secs(1),
            &OutboxWorkerConfig::default(),
        )
        .await;

        let row = crate::db::outbox::get_outbox_by_id(&pool, row_id)
            .await
            .expect("fetch row")
            .unwrap();
        assert_eq!(row.status, crate::db::models::OUTBOX_STATUS_PENDING);

        let _ = sqlx::query("DELETE FROM email_outbox WHERE id = $1")
            .bind(row_id)
            .execute(&pool)
            .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn drain_outbox_batches_loops_until_empty() {
        let _guard = crate::db::DB_TEST_LOCK.lock().await;
        let Some(pool) = test_pool().await else {
            return;
        };
        let store = crate::db::postgres::PostgresStore::new(pool.clone());

        let mut ids = Vec::new();
        for i in 0..3 {
            let id = uuid::Uuid::new_v4();
            let recipient = format!("multibatch_{i}_{}@example.com", id);
            let payload = serde_json::json!({
                "user_id": uuid::Uuid::new_v4(),
                "to": recipient,
                "token": "tok",
                "url": "https://example.com",
                "expires_at": chrono::Utc::now()
            });
            sqlx::query(
                r#"
                INSERT INTO email_outbox (id, recipient, email_type, payload, status, retry_count, next_retry_at)
                VALUES ($1, $2, 'verification', $3, $4, 0, NOW())
                "#,
            )
            .bind(id)
            .bind(&recipient)
            .bind(payload)
            .bind(crate::db::models::OUTBOX_STATUS_PENDING)
            .execute(&pool)
            .await
            .expect("insert outbox row");
            ids.push(id);
        }

        let sender: Option<SharedEmailSender> = Some(Arc::new(crate::email::NoopEmailSender));
        let config = OutboxWorkerConfig {
            batch_size: 1,
            ..OutboxWorkerConfig::default()
        };

        let (_shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
        drain_outbox_batches(
            store.outbox(),
            &sender,
            Duration::from_secs(1),
            &config,
            &shutdown,
        )
        .await;

        for id in &ids {
            let row = crate::db::outbox::get_outbox_by_id(&pool, *id)
                .await
                .expect("fetch row")
                .unwrap();
            assert_eq!(row.status, crate::db::models::OUTBOX_STATUS_SENT);
        }

        let _ = sqlx::query("DELETE FROM email_outbox WHERE id = ANY($1)")
            .bind(&ids)
            .execute(&pool)
            .await;
    }

    #[derive(Default)]
    #[cfg(feature = "postgres")]
    struct GatedShutdownSender {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
        sends: std::sync::Mutex<usize>,
    }

    #[async_trait::async_trait]
    impl crate::email::hook::EmailSender for GatedShutdownSender {
        async fn send_verification_email(
            &self,
            _payload: VerificationEmailPayload,
        ) -> Result<(), crate::email::hook::DynError> {
            *self.sends.lock().unwrap() += 1;
            self.entered.notify_one();
            self.release.notified().await;
            Ok(())
        }
        async fn send_password_reset_email(
            &self,
            _payload: PasswordResetEmailPayload,
        ) -> Result<(), crate::email::hook::DynError> {
            *self.sends.lock().unwrap() += 1;
            self.entered.notify_one();
            self.release.notified().await;
            Ok(())
        }
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn drain_stops_claiming_after_shutdown() {
        let _guard = crate::db::DB_TEST_LOCK.lock().await;
        let Some(pool) = test_pool().await else {
            return;
        };

        let mut ids = Vec::new();
        for i in 0..2 {
            let id = uuid::Uuid::new_v4();
            let recipient = format!("shutdown_{i}_{}@example.com", id);
            let payload = serde_json::json!({
                "user_id": uuid::Uuid::new_v4(),
                "to": recipient,
                "token": "tok",
                "url": "https://example.com",
                "expires_at": chrono::Utc::now()
            });
            sqlx::query(
                r#"
                INSERT INTO email_outbox (id, recipient, email_type, payload, status, retry_count, next_retry_at)
                VALUES ($1, $2, 'verification', $3, $4, 0, NOW())
                "#,
            )
            .bind(id)
            .bind(&recipient)
            .bind(payload)
            .bind(crate::db::models::OUTBOX_STATUS_PENDING)
            .execute(&pool)
            .await
            .expect("insert outbox row");
            ids.push(id);
        }

        let sender = Arc::new(GatedShutdownSender::default());
        let gated: Option<SharedEmailSender> = Some(sender.clone());
        let config = OutboxWorkerConfig {
            batch_size: 1,
            ..OutboxWorkerConfig::default()
        };
        let (shutdown_tx, shutdown) = tokio::sync::watch::channel(false);

        // Signal shutdown while the first delivery is in flight: the drain
        // must finish that batch but never claim the second row.
        let drain_store = crate::db::postgres::PostgresStore::new(pool.clone());
        let drain = tokio::spawn(async move {
            drain_outbox_batches(
                drain_store.outbox(),
                &gated,
                Duration::from_secs(5),
                &config,
                &shutdown,
            )
            .await;
        });
        tokio::time::timeout(Duration::from_secs(5), sender.entered.notified())
            .await
            .expect("first delivery must start");
        shutdown_tx.send(true).expect("signal shutdown");
        sender.release.notify_one();
        tokio::time::timeout(Duration::from_secs(10), drain)
            .await
            .expect("drain must exit")
            .expect("drain task panicked");

        assert_eq!(*sender.sends.lock().unwrap(), 1);
        let pending = crate::db::outbox::get_outbox_by_id(&pool, ids[1])
            .await
            .expect("fetch row")
            .unwrap();
        assert_eq!(
            pending.status,
            crate::db::models::OUTBOX_STATUS_PENDING,
            "second batch must stay unclaimed after shutdown"
        );

        let _ = sqlx::query("DELETE FROM email_outbox WHERE id = ANY($1)")
            .bind(&ids)
            .execute(&pool)
            .await;
    }
}
