//! In-process sliding-window rate limiter using DashMap.

use dashmap::DashMap;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::sleep;

use crate::{
    config::RateLimitConfig,
    error::{AppError, ErrorCode},
};

/// Default maximum entries maintained in the rate limiter before admission rejection.
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// Per-key sliding-window state.
#[derive(Debug)]
struct WindowEntry {
    attempts: Vec<Instant>,
    locked_until: Option<Instant>,
}

/// In-process sliding-window rate limiter safe for concurrent Tokio tasks.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    windows: Arc<DashMap<String, WindowEntry>>,
    config: RateLimitConfig,
    max_entries: usize,
}

impl RateLimiter {
    /// Construct a new rate limiter with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(RateLimitConfig::default())
    }

    /// Construct a new rate limiter with the provided configuration and default capacity.
    ///
    /// An enabled config must have passed [`RateLimitConfig::validate`]; a
    /// disabled config must be re-validated before it is ever re-enabled.
    #[must_use]
    pub fn with_config(config: RateLimitConfig) -> Self {
        Self::with_config_and_capacity(config, DEFAULT_MAX_ENTRIES)
    }

    /// Construct a new rate limiter with explicit configuration and maximum capacity.
    #[must_use]
    pub fn with_config_and_capacity(config: RateLimitConfig, max_entries: usize) -> Self {
        debug_assert!(
            !config.enabled || config.validate().is_ok(),
            "enabled RateLimitConfig must be validated before use"
        );
        Self {
            windows: Arc::new(DashMap::new()),
            config,
            max_entries,
        }
    }

    /// Internal core sliding-window evaluation with optional lockout cooldown.
    fn check_internal(
        &self,
        key: &str,
        max: u32,
        window: Duration,
        cooldown: Option<Duration>,
    ) -> Result<(), AppError> {
        let now = Instant::now();
        let mut entry = if let Some(existing) = self.windows.get_mut(key) {
            existing
        } else {
            if self.windows.len() >= self.max_entries {
                return Err(AppError::from_code(ErrorCode::RateLimitExceeded));
            }
            self.windows
                .entry(key.to_string())
                .or_insert_with(|| WindowEntry {
                    attempts: Vec::new(),
                    locked_until: None,
                })
        };

        if let Some(locked_until) = entry.locked_until {
            if now < locked_until {
                return Err(AppError::from_code(ErrorCode::RateLimitExceeded));
            }
            entry.locked_until = None;
            entry.attempts.clear();
        }

        entry.attempts.retain(|&t| now.duration_since(t) < window);

        if entry.attempts.len() as u32 >= max {
            if let Some(cd) = cooldown {
                entry.locked_until = Some(now + cd);
            }
            return Err(AppError::from_code(ErrorCode::RateLimitExceeded));
        }

        entry.attempts.push(now);
        Ok(())
    }

    /// Check if an action under `key` is allowed given explicit `max` attempts within `window`.
    pub fn allow(&self, key: &str, max: u32, window: Duration) -> bool {
        self.check_internal(key, max, window, None).is_ok()
    }

    /// Return the configured cooldown period in seconds for 429 Retry-After headers.
    pub fn cooldown_secs(&self) -> u64 {
        self.config.login_cooldown_secs
    }

    /// Check rate limit against configured rules and enforce cooldown on exceed.
    pub fn check_rate_limit(&self, key: &str) -> Result<(), AppError> {
        if !self.config.enabled {
            return Ok(());
        }

        self.check_internal(
            key,
            self.config.max_attempts,
            self.config.window(),
            Some(self.config.cooldown()),
        )
    }

    /// Check rate limit for an IP address.
    pub fn check_ip(&self, ip: &str) -> Result<(), AppError> {
        if !self.config.enabled {
            return Ok(());
        }
        let key = format!("ip:{ip}");
        self.check_internal(
            &key,
            self.config.max_attempts,
            self.config.window(),
            Some(self.config.cooldown()),
        )
    }

    /// Check rate limit for an account identifier (normalized email).
    pub fn check_account(&self, account: &str) -> Result<(), AppError> {
        if !self.config.enabled {
            return Ok(());
        }
        let key = format!("account:{account}");
        self.check_internal(
            &key,
            self.config.max_attempts,
            self.config.window(),
            Some(self.config.cooldown()),
        )
    }

    /// Evaluate dual-key rate limit: checks IP first, then account.
    pub fn check_dual(&self, ip: &str, account: &str) -> Result<(), AppError> {
        self.check_ip(ip)?;
        self.check_account(account)?;
        Ok(())
    }

    /// Reset rate limit counter for an account only, leaving IP counters intact.
    pub fn reset_account(&self, account: &str) {
        let key = format!("account:{account}");
        self.windows.remove(&key);
    }

    /// Reset all rate limit counters and lockouts for a specific key.
    pub fn reset(&self, key: &str) {
        self.windows.remove(key);
    }

    /// Synchronously purge stale attempts and empty entries.
    pub fn cleanup(&self, window: Duration) {
        let now = Instant::now();
        self.windows.retain(|_, entry| {
            if let Some(locked_until) = entry.locked_until {
                if now < locked_until {
                    return true;
                }
                entry.locked_until = None;
            }
            entry.attempts.retain(|&t| now.duration_since(t) < window);
            !entry.attempts.is_empty()
        });
    }

    /// Spawn a background task periodically pruning expired keys.
    ///
    /// Holds only a [`std::sync::Weak`] reference: the loop exits on its own
    /// once every strong `Arc` (e.g. the owning `AppState`) is dropped, so no
    /// `JoinHandle` bookkeeping or explicit shutdown is required.
    pub fn start_cleanup_task(self: Arc<Self>, window: Duration) {
        if tokio::runtime::Handle::try_current().is_err() {
            tracing::warn!(
                event = "rate_limiter_cleanup_skipped",
                reason = "no_tokio_runtime",
            );
            return;
        }

        let weak = Arc::downgrade(&self);
        drop(self);
        tokio::spawn(async move {
            loop {
                sleep(window).await;
                let Some(limiter) = weak.upgrade() else {
                    break;
                };
                limiter.cleanup(window);
                tracing::debug!(
                    event = "rate_limiter_cleanup",
                    remaining_keys = limiter.windows.len()
                );
            }
        });
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Construct composite rate limit key formatted as `{action}|{identifier}`.
#[must_use]
pub fn rate_limit_key(action: &str, identifier: &str) -> String {
    format!("{action}|{identifier}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_allow() {
        let limiter = RateLimiter::new();
        let key = "test_allow";
        let window = Duration::from_secs(60);

        for _ in 0..5 {
            assert!(limiter.allow(key, 5, window));
        }
        assert!(!limiter.allow(key, 5, window));
    }

    #[test]
    fn test_rate_limit_block() {
        let limiter = RateLimiter::new();
        let key = "test_block";
        let window = Duration::from_secs(60);

        for _ in 0..3 {
            assert!(limiter.allow(key, 3, window));
        }
        assert!(!limiter.allow(key, 3, window));
        assert!(!limiter.allow(key, 3, window));
    }

    #[test]
    fn test_rate_limit_reset() {
        let limiter = RateLimiter::new();
        let key = "test_reset";
        let window = Duration::from_secs(60);

        for _ in 0..2 {
            assert!(limiter.allow(key, 2, window));
        }
        assert!(!limiter.allow(key, 2, window));

        limiter.reset(key);
        assert!(limiter.allow(key, 2, window));
    }

    #[test]
    fn test_rate_limit_cleanup() {
        let limiter = RateLimiter::new();
        let key = "test_cleanup";
        assert!(limiter.allow(key, 5, Duration::from_millis(1)));
        std::thread::sleep(Duration::from_millis(10));
        limiter.cleanup(Duration::from_millis(5));
        assert!(!limiter.windows.contains_key(key));
    }

    #[test]
    fn test_rate_limit_key_format() {
        assert_eq!(
            rate_limit_key("1.2.3.4", "user@test.com"),
            "1.2.3.4|user@test.com"
        );
    }

    #[test]
    fn test_rate_limit_key_empty_account() {
        assert_eq!(rate_limit_key("1.2.3.4", ""), "1.2.3.4|");
    }

    #[test]
    fn test_check_rate_limit_disabled() {
        let config = RateLimitConfig {
            enabled: false,
            max_attempts: 1,
            window_secs: 60,
            login_cooldown_secs: 60,
        };
        let limiter = RateLimiter::with_config(config);
        assert!(limiter.check_rate_limit("k").is_ok());
        assert!(limiter.check_rate_limit("k").is_ok());
    }

    #[test]
    fn test_check_rate_limit_cooldown() {
        let config = RateLimitConfig {
            enabled: true,
            max_attempts: 2,
            window_secs: 60,
            login_cooldown_secs: 60,
        };
        let limiter = RateLimiter::with_config(config);
        assert!(limiter.check_rate_limit("cooldown_key").is_ok());
        assert!(limiter.check_rate_limit("cooldown_key").is_ok());
        let err = limiter.check_rate_limit("cooldown_key").unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_allow_respects_lockout_set_by_cooldown() {
        let config = RateLimitConfig {
            enabled: true,
            max_attempts: 1,
            window_secs: 60,
            login_cooldown_secs: 60,
        };
        let limiter = RateLimiter::with_config(config);
        assert!(limiter.check_rate_limit("shared_key").is_ok());
        // Triggers lockout cooldown
        assert!(limiter.check_rate_limit("shared_key").is_err());
        // allow() on same key must see lockout and reject
        assert!(!limiter.allow("shared_key", 10, Duration::from_secs(60)));
    }

    #[test]
    fn start_cleanup_task_does_not_panic_outside_tokio_runtime() {
        let limiter = Arc::new(RateLimiter::new());
        limiter.start_cleanup_task(Duration::from_secs(60));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_hammer_admits_exactly_max() {
        let config = RateLimitConfig {
            enabled: true,
            max_attempts: 10,
            window_secs: 60,
            login_cooldown_secs: 60,
        };
        let limiter = RateLimiter::with_config(config);
        let mut handles = Vec::new();
        for _ in 0..10 {
            let limiter = limiter.clone();
            handles.push(tokio::spawn(async move {
                let mut admitted = 0u32;
                for _ in 0..20 {
                    if limiter.check_rate_limit("hammer_key").is_ok() {
                        admitted += 1;
                    }
                }
                admitted
            }));
        }
        let mut total = 0u32;
        for handle in handles {
            total += handle.await.expect("worker must not panic");
        }
        assert_eq!(total, 10);
    }

    #[tokio::test]
    async fn cleanup_task_exits_once_limiter_dropped() {
        let limiter = Arc::new(RateLimiter::new());
        let weak = Arc::downgrade(&limiter);
        Arc::clone(&limiter).start_cleanup_task(Duration::from_millis(10));
        drop(limiter);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn test_rate_limit_dual_keying_independence() {
        let config = RateLimitConfig {
            enabled: true,
            max_attempts: 2,
            window_secs: 60,
            login_cooldown_secs: 60,
        };
        let limiter = RateLimiter::with_config(config);

        // IP limit exhaustion
        assert!(limiter.check_ip("192.168.1.1").is_ok());
        assert!(limiter.check_ip("192.168.1.1").is_ok());
        assert!(limiter.check_ip("192.168.1.1").is_err());

        // Different IP is unaffected
        assert!(limiter.check_ip("192.168.1.2").is_ok());

        // Account limit exhaustion
        assert!(limiter.check_account("victim@example.com").is_ok());
        assert!(limiter.check_account("victim@example.com").is_ok());
        assert!(limiter.check_account("victim@example.com").is_err());

        // Different account is unaffected
        assert!(limiter.check_account("other@example.com").is_ok());

        // check_dual checks IP first then account
        // 192.168.1.1 is already exhausted -> rejects at IP stage
        assert!(
            limiter
                .check_dual("192.168.1.1", "fresh@example.com")
                .is_err()
        );
        // 192.168.1.3 has capacity, but victim@example.com is exhausted -> rejects at account stage
        assert!(
            limiter
                .check_dual("192.168.1.3", "victim@example.com")
                .is_err()
        );
        // 192.168.1.3 and fresh@example.com both have capacity -> ok
        assert!(
            limiter
                .check_dual("192.168.1.3", "fresh@example.com")
                .is_ok()
        );
    }

    #[test]
    fn test_rate_limit_reset_account_leaves_ip_intact() {
        let config = RateLimitConfig {
            enabled: true,
            max_attempts: 1,
            window_secs: 60,
            login_cooldown_secs: 60,
        };
        let limiter = RateLimiter::with_config(config);

        let ip = "10.0.0.1";
        let email = "user@example.com";

        assert!(limiter.check_dual(ip, email).is_ok());
        // Both IP and account now tripped
        assert!(limiter.check_ip(ip).is_err());
        assert!(limiter.check_account(email).is_err());

        // Invariant: reset_account ONLY resets account, NEVER IP
        limiter.reset_account(email);
        assert!(limiter.check_account(email).is_ok());
        assert!(limiter.check_ip(ip).is_err());
    }

    #[test]
    fn test_rate_limit_max_entries_admission_rejection() {
        let config = RateLimitConfig {
            enabled: true,
            max_attempts: 5,
            window_secs: 60,
            login_cooldown_secs: 60,
        };
        let limiter = RateLimiter::with_config_and_capacity(config, 2);

        // Fill capacity with 2 keys
        assert!(limiter.check_ip("1.1.1.1").is_ok());
        assert!(limiter.check_ip("2.2.2.2").is_ok());

        // Existing keys can still be accessed and evaluated
        assert!(limiter.check_ip("1.1.1.1").is_ok());

        // 3rd new key must be rejected due to capacity bounds
        let err = limiter.check_ip("3.3.3.3").unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_rate_limit_cooldown_secs_accessor() {
        let config = RateLimitConfig {
            enabled: true,
            max_attempts: 5,
            window_secs: 60,
            login_cooldown_secs: 750,
        };
        let limiter = RateLimiter::with_config(config);
        assert_eq!(limiter.cooldown_secs(), 750);
    }
}
