//! In-process sliding-window rate limiter using DashMap.

use dashmap::DashMap;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
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
    entry_count: Arc<AtomicUsize>,
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
            entry_count: Arc::new(AtomicUsize::new(0)),
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
            if self.entry_count.load(Ordering::Relaxed) >= self.max_entries {
                self.reclaim_expired(self.config.window().min(window), now);
            }
            if self
                .entry_count
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |val| {
                    if val < self.max_entries {
                        Some(val + 1)
                    } else {
                        None
                    }
                })
                .is_err()
            {
                return Err(AppError::from_code(ErrorCode::RateLimitExceeded));
            }
            match self.windows.entry(key.to_string()) {
                dashmap::mapref::entry::Entry::Occupied(occ) => {
                    self.entry_count.fetch_sub(1, Ordering::Release);
                    occ.into_ref()
                }
                dashmap::mapref::entry::Entry::Vacant(vac) => vac.insert(WindowEntry {
                    attempts: Vec::new(),
                    locked_until: None,
                }),
            }
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

    /// Return remaining lockout duration in seconds (minimum 1s) if key is actively locked out.
    pub fn remaining_cooldown(&self, key: &str) -> Option<u64> {
        let entry = self.windows.get(key)?;
        let locked_until = entry.locked_until?;
        let now = Instant::now();
        if locked_until > now {
            let remaining = locked_until.duration_since(now).as_secs();
            Some(remaining.max(1))
        } else {
            None
        }
    }

    /// Return maximum remaining cooldown across two full keys.
    pub fn remaining_cooldown_dual_key(&self, key_a: &str, key_b: &str) -> Option<u64> {
        let cd_a = self.remaining_cooldown(key_a);
        let cd_b = self.remaining_cooldown(key_b);
        match (cd_a, cd_b) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    /// Return maximum remaining cooldown between IP and account keys.
    pub fn remaining_cooldown_dual(&self, ip: &str, account: &str) -> Option<u64> {
        let ip_key = format!("ip:{ip}");
        let bounded_account = if account.len() > 255 {
            &account[..255]
        } else {
            account
        };
        let acct_key = format!("account:{bounded_account}");
        self.remaining_cooldown_dual_key(&ip_key, &acct_key)
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
        let bounded_account = if account.len() > 255 {
            &account[..255]
        } else {
            account
        };
        let key = format!("account:{bounded_account}");
        self.check_internal(
            &key,
            self.config.max_attempts,
            self.config.window(),
            Some(self.config.cooldown()),
        )
    }

    /// Check rate limit for password reset requests (isolated from login attempts).
    pub fn check_password_reset(&self, ip: &str, account: &str) -> Result<(), AppError> {
        if !self.config.enabled {
            return Ok(());
        }
        let ip_key = format!("ip:{ip}");
        let bounded_account = if account.len() > 255 {
            &account[..255]
        } else {
            account
        };
        let acct_key = format!("reset_account:{bounded_account}");
        self.check_dual_keys(&ip_key, &acct_key)
    }

    /// Evaluate dual-key rate limit: checks IP first, then account.
    pub fn check_dual(&self, ip: &str, account: &str) -> Result<(), AppError> {
        let ip_key = format!("ip:{ip}");
        let bounded_account = if account.len() > 255 {
            &account[..255]
        } else {
            account
        };
        let acct_key = format!("account:{bounded_account}");
        self.check_dual_keys(&ip_key, &acct_key)
    }

    /// Internal dual-key evaluation with atomic rollback on capacity failure.
    fn check_dual_keys(&self, first_key: &str, second_key: &str) -> Result<(), AppError> {
        if !self.config.enabled {
            return Ok(());
        }
        let first_existed = self.windows.contains_key(first_key);
        self.check_internal(
            first_key,
            self.config.max_attempts,
            self.config.window(),
            Some(self.config.cooldown()),
        )?;

        if let Err(e) = self.check_internal(
            second_key,
            self.config.max_attempts,
            self.config.window(),
            Some(self.config.cooldown()),
        ) {
            // If second check failed on capacity rather than active lockout,
            // roll back first key if it was newly inserted to prevent leak.
            if !first_existed && self.remaining_cooldown(second_key).is_none() {
                self.reset(first_key);
            }
            return Err(e);
        }
        Ok(())
    }

    /// Reset rate limit counter for an account only, leaving IP counters intact.
    pub fn reset_account(&self, account: &str) {
        let bounded_account = if account.len() > 255 {
            &account[..255]
        } else {
            account
        };
        let key = format!("account:{bounded_account}");
        self.reset(&key);
    }

    /// Reset all rate limit counters and lockouts for a specific key.
    pub fn reset(&self, key: &str) {
        if self.windows.remove(key).is_some() {
            self.entry_count.fetch_sub(1, Ordering::Release);
        }
    }

    /// Synchronously purge stale attempts and empty entries.
    pub fn cleanup(&self, window: Duration) {
        let now = Instant::now();
        self.reclaim_expired(window, now);
    }

    fn reclaim_expired(&self, window: Duration, now: Instant) -> usize {
        let mut removed = 0usize;
        self.windows.retain(|_, entry| {
            if let Some(locked_until) = entry.locked_until {
                if now < locked_until {
                    return true;
                }
                entry.locked_until = None;
            }
            entry.attempts.retain(|&t| now.duration_since(t) < window);
            if entry.attempts.is_empty() {
                removed += 1;
                false
            } else {
                true
            }
        });
        if removed > 0 {
            self.entry_count.fetch_sub(removed, Ordering::Release);
        }
        removed
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

    #[test]
    fn test_rate_limit_inband_reclamation_on_capacity_saturation() {
        let config = RateLimitConfig {
            enabled: true,
            max_attempts: 5,
            window_secs: 60,
            login_cooldown_secs: 60,
        };
        let limiter = RateLimiter::with_config_and_capacity(config, 2);

        // Fill capacity to maximum (2 entries)
        assert!(limiter.allow("temp1", 5, Duration::from_millis(5)));
        assert!(limiter.allow("temp2", 5, Duration::from_millis(5)));

        // Sleep to let temp1 and temp2 expire
        std::thread::sleep(Duration::from_millis(15));

        // Third entry must trigger in-band reclamation and succeed without manual cleanup()
        assert!(limiter.allow("temp3", 5, Duration::from_millis(5)));
    }

    #[test]
    fn test_rate_limit_dual_key_rollback_on_capacity_failure() {
        let config = RateLimitConfig {
            enabled: true,
            max_attempts: 5,
            window_secs: 60,
            login_cooldown_secs: 60,
        };
        // Capacity strictly 1 entry
        let limiter = RateLimiter::with_config_and_capacity(config, 1);

        // check_dual tries to insert IP first, then account.
        // IP succeeds (occupying the only slot), but account fails due to capacity.
        // IP must be rolled back so the slot is released.
        let res = limiter.check_dual("192.0.2.1", "victim@example.com");
        assert!(res.is_err());

        // Slot must not be leaked; another single-key check should be able to acquire it
        assert!(limiter.check_ip("192.0.2.2").is_ok());
    }

    #[test]
    fn test_rate_limit_remaining_cooldown_accuracy() {
        let config = RateLimitConfig {
            enabled: true,
            max_attempts: 1,
            window_secs: 60,
            login_cooldown_secs: 300,
        };
        let limiter = RateLimiter::with_config(config);

        assert!(limiter.check_rate_limit("cd_test").is_ok());
        assert!(limiter.remaining_cooldown("cd_test").is_none());

        // Tripping rate limit activates lockout
        assert!(limiter.check_rate_limit("cd_test").is_err());
        let remaining = limiter.remaining_cooldown("cd_test");
        assert!(remaining.is_some());
        let secs = remaining.unwrap();
        assert!((298..=300).contains(&secs));
    }

    #[test]
    fn test_rate_limit_account_key_bounded() {
        let config = RateLimitConfig {
            enabled: true,
            max_attempts: 5,
            window_secs: 60,
            login_cooldown_secs: 60,
        };
        let limiter = RateLimiter::with_config(config);

        // Huge 100k string
        let massive_email = "a".repeat(100_000);
        assert!(limiter.check_account(&massive_email).is_ok());

        // Stored key must be bounded to prefix + at most 255 bytes
        for entry in limiter.windows.iter() {
            assert!(entry.key().len() <= "account:".len() + 255);
        }
    }

    #[test]
    fn test_rate_limit_password_reset_independent_budget() {
        let config = RateLimitConfig {
            enabled: true,
            max_attempts: 1,
            window_secs: 60,
            login_cooldown_secs: 300,
        };
        let limiter = RateLimiter::with_config(config);

        let email = "victim@example.com";
        // Trip login account lockout
        assert!(limiter.check_account(email).is_ok());
        assert!(limiter.check_account(email).is_err());

        // Password reset budget must remain independent and accessible
        assert!(limiter.check_password_reset("198.51.100.1", email).is_ok());
    }
}
