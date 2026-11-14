use std::sync::Arc;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use sqlx::PgPool;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::db::models::{EMAIL_TYPE_PASSWORD_RESET, EMAIL_TYPE_VERIFICATION, EmailOutbox};
use crate::db::outbox::{
    claim_pending_outbox, mark_outbox_failed, mark_outbox_sent, record_outbox_retry,
};
use crate::email::hook::SharedEmailSender;
use crate::email::payload::{PasswordResetEmailPayload, VerificationEmailPayload};

/// Configuration parameters for the outbox worker polling loop and retry policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxWorkerConfig {
    pub poll_interval: Duration,
    pub batch_size: u32,
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub lease_duration: Duration,
}

impl Default for OutboxWorkerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(crate::config::DEFAULT_OUTBOX_POLL_INTERVAL_MS),
            batch_size: crate::config::DEFAULT_OUTBOX_BATCH_SIZE,
            max_retries: crate::config::DEFAULT_OUTBOX_MAX_RETRIES,
            initial_backoff: Duration::from_secs(
                crate::config::DEFAULT_OUTBOX_INITIAL_BACKOFF_SECS,
            ),
            max_backoff: Duration::from_secs(crate::config::DEFAULT_OUTBOX_MAX_BACKOFF_SECS),
            lease_duration: Duration::from_secs(300),
        }
    }
}

impl From<&Config> for OutboxWorkerConfig {
    fn from(cfg: &Config) -> Self {
        Self {
            poll_interval: cfg.outbox_poll_interval,
            batch_size: cfg.outbox_batch_size,
            max_retries: cfg.outbox_max_retries,
            initial_backoff: cfg.outbox_initial_backoff,
            max_backoff: cfg.outbox_max_backoff,
            lease_duration: Duration::from_secs(300),
        }
    }
}

impl OutboxWorkerConfig {
    pub fn with_lease_duration(mut self, lease_duration: Duration) -> Self {
        self.lease_duration = lease_duration;
        self
    }
}

/// Computes exponential backoff: `initial_backoff * 2^retry_count`, clamped at `max_backoff`.
pub fn calculate_backoff(
    retry_count: i32,
    initial_backoff: Duration,
    max_backoff: Duration,
) -> Duration {
    let exponent = (retry_count.max(0) as u32).min(31);
    let factor = 2u32.saturating_pow(exponent);
    let backoff_secs = initial_backoff.as_secs().saturating_mul(factor as u64);
    let backoff = Duration::from_secs(backoff_secs);
    backoff.min(max_backoff)
}

/// Atomically claims and processes a batch of pending outbox messages.
pub async fn process_outbox_batch(
    pool: &PgPool,
    sender: &Option<SharedEmailSender>,
    timeout: Duration,
    batch_size: u32,
    max_retries: u32,
    initial_backoff: Duration,
    max_backoff: Duration,
    lease_duration: Duration,
) -> Result<usize, sqlx::Error> {
    let Some(sender) = sender.as_ref() else {
        return Ok(0);
    };

    let messages = claim_pending_outbox(pool, batch_size as i64, lease_duration).await?;
    if messages.is_empty() {
        return Ok(0);
    }

    let count = messages.len();
    for msg in messages {
        deliver_single_message(
            pool,
            sender,
            msg,
            timeout,
            max_retries,
            initial_backoff,
            max_backoff,
        )
        .await;
    }

    Ok(count)
}

async fn deliver_single_message(
    pool: &PgPool,
    sender: &SharedEmailSender,
    msg: EmailOutbox,
    timeout: Duration,
    max_retries: u32,
    initial_backoff: Duration,
    max_backoff: Duration,
) {
    let result = match msg.email_type.as_str() {
        EMAIL_TYPE_VERIFICATION => {
            match serde_json::from_value::<VerificationEmailPayload>(msg.payload.clone()) {
                Ok(payload) => {
                    tokio::time::timeout(timeout, sender.send_verification_email(payload)).await
                }
                Err(e) => {
                    let err_msg = format!("corrupt verification payload: {e}");
                    error!(op = "outbox_delivery", id = %msg.id, err = %err_msg);
                    let _ = mark_outbox_failed(pool, msg.id, &err_msg).await;
                    return;
                }
            }
        }
        EMAIL_TYPE_PASSWORD_RESET => {
            match serde_json::from_value::<PasswordResetEmailPayload>(msg.payload.clone()) {
                Ok(payload) => {
                    tokio::time::timeout(timeout, sender.send_password_reset_email(payload)).await
                }
                Err(e) => {
                    let err_msg = format!("corrupt password reset payload: {e}");
                    error!(op = "outbox_delivery", id = %msg.id, err = %err_msg);
                    let _ = mark_outbox_failed(pool, msg.id, &err_msg).await;
                    return;
                }
            }
        }
        unknown => {
            let err_msg = format!("unknown email type: {unknown}");
            error!(op = "outbox_delivery", id = %msg.id, err = %err_msg);
            let _ = mark_outbox_failed(pool, msg.id, &err_msg).await;
            return;
        }
    };

    match result {
        Ok(Ok(())) => {
            if let Err(e) = mark_outbox_sent(pool, msg.id).await {
                error!(op = "outbox_delivery", id = %msg.id, err = %e, "failed to mark outbox as sent");
            } else {
                info!(op = "outbox_delivery", id = %msg.id, email_type = %msg.email_type, "outbox email sent");
            }
        }
        Ok(Err(send_err)) => {
            let err_msg = format!("send error: {send_err}");
            handle_delivery_failure(
                pool,
                msg,
                &err_msg,
                max_retries,
                initial_backoff,
                max_backoff,
            )
            .await;
        }
        Err(_elapsed) => {
            let err_msg = "send timed out".to_string();
            handle_delivery_failure(
                pool,
                msg,
                &err_msg,
                max_retries,
                initial_backoff,
                max_backoff,
            )
            .await;
        }
    }
}

async fn handle_delivery_failure(
    pool: &PgPool,
    msg: EmailOutbox,
    err_msg: &str,
    max_retries: u32,
    initial_backoff: Duration,
    max_backoff: Duration,
) {
    let next_retry_count = msg.retry_count + 1;
    if next_retry_count >= max_retries as i32 {
        error!(
            op = "outbox_delivery",
            id = %msg.id,
            retries = next_retry_count,
            err = %err_msg,
            "outbox delivery exhausted max retries; marked failed"
        );
        let _ = mark_outbox_failed(pool, msg.id, err_msg).await;
    } else {
        let backoff = calculate_backoff(msg.retry_count, initial_backoff, max_backoff);
        let next_retry_at =
            Utc::now() + ChronoDuration::from_std(backoff).unwrap_or(ChronoDuration::seconds(300));
        warn!(
            op = "outbox_delivery",
            id = %msg.id,
            retries = next_retry_count,
            backoff_secs = backoff.as_secs(),
            err = %err_msg,
            "outbox delivery failed; scheduled retry with exponential backoff"
        );
        let _ = record_outbox_retry(pool, msg.id, next_retry_at, err_msg).await;
    }
}

async fn drain_outbox_batches(
    pool: &PgPool,
    sender: &Option<SharedEmailSender>,
    timeout: Duration,
    config: &OutboxWorkerConfig,
) {
    loop {
        match process_outbox_batch(
            pool,
            sender,
            timeout,
            config.batch_size,
            config.max_retries,
            config.initial_backoff,
            config.max_backoff,
            config.lease_duration,
        )
        .await
        {
            Ok(count) if count >= config.batch_size as usize => {
                continue;
            }
            Ok(_) => break,
            Err(e) => {
                error!(err = %e, "outbox batch processing error");
                break;
            }
        }
    }
}

/// Spawns the background outbox polling loop.
pub async fn run_outbox_worker(
    pool: PgPool,
    sender: Option<SharedEmailSender>,
    timeout: Duration,
    config: OutboxWorkerConfig,
    notify: Arc<tokio::sync::Notify>,
) {
    if let Err(e) = crate::db::outbox::recover_stale_processing(&pool).await {
        error!(err = %e, "failed to recover stale outbox processing records on startup");
    }

    // Drain existing pending records immediately on startup before sleeping
    drain_outbox_batches(&pool, &sender, timeout, &config).await;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(config.poll_interval) => {}
            _ = notify.notified() => {}
        }

        drain_outbox_batches(&pool, &sender, timeout, &config).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
