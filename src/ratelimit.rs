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
    config::{RateLimitConfig, TotpConfig},
    error::{AppError, ErrorCode},
};

/// Default maximum entries maintained in the rate limiter before admission rejection.
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// Truncate `s` to at most `max_bytes` without splitting a multi-byte UTF-8 character boundary.
#[must_use]
pub fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        s
    } else {
        &s[..s.floor_char_boundary(max_bytes)]
    }
}

/// Key admission outcome indicating whether a key was newly inserted or already present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAdmission {
    /// Key was already present in the rate limiter map.
    Existing,
    /// Key was newly inserted as vacant into the rate limiter map.
    NewlyInserted,
}

/// Detailed reason for a rate limit rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitRejection {
    /// Active lockout duration in whole seconds (minimum 1s, ceiling rounded).
    Lockout(u64),
    /// Attempt limit exceeded for the sliding window without cooldown.
    Exceeded,
    /// Maximum capacity of rate limiter entries exceeded.
    CapacityExhausted,
}

impl RateLimitRejection {
    /// Return the `Retry-After` header value in seconds, if applicable.
    ///
    /// Omitted for [`RateLimitRejection::CapacityExhausted`] or [`RateLimitRejection::Exceeded`].
    #[must_use]
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Lockout(secs) => Some(*secs),
            Self::Exceeded | Self::CapacityExhausted => None,
        }
    }

    /// Return HTTP status code corresponding to this rejection.
    #[must_use]
    pub fn status_code(&self) -> axum::http::StatusCode {
        axum::http::StatusCode::TOO_MANY_REQUESTS
    }

    /// Return application error code corresponding to this rejection.
    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        ErrorCode::RateLimitExceeded
    }
}

impl std::fmt::Display for RateLimitRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lockout(secs) => write!(f, "rate limit lockout: retry after {secs}s"),
            Self::Exceeded => write!(f, "rate limit exceeded"),
            Self::CapacityExhausted => write!(f, "rate limiter capacity exhausted"),
        }
    }
}

impl std::error::Error for RateLimitRejection {}

impl From<RateLimitRejection> for AppError {
    fn from(_: RateLimitRejection) -> Self {
        Self::from_code(ErrorCode::RateLimitExceeded)
    }
}

/// Per-key sliding-window state.
#[derive(Debug)]
struct WindowEntry {
    attempts: Vec<Instant>,
    locked_until: Option<Instant>,
    window: Duration,
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

    /// Format a bounded account key for rate limiting: `{prefix}:{truncated_account}`.
    #[must_use]
    pub fn format_account_key(prefix: &str, account: &str) -> String {
        let bounded = truncate_utf8(account, 255);
        format!("{prefix}:{bounded}")
    }

    /// Format the `totp:ip:<ip>` budget key.
    #[must_use]
    pub fn totp_ip_key(ip: &str) -> String {
        Self::format_account_key("totp:ip", ip)
    }

    /// Format the `totp:user:<user_id>` budget key.
    #[must_use]
    pub fn totp_user_key(user_id: uuid::Uuid) -> String {
        Self::format_account_key("totp:user", &user_id.to_string())
    }

    /// Seconds until the oldest admitted attempt leaves `key`'s sliding window.
    ///
    /// `None` when the key is unknown or holds no recorded attempt. A caller that
    /// reopens the budget at that point admits the next request, so the value is the
    /// exact `Retry-After` for a sliding-window rejection.
    #[must_use]
    pub fn remaining_window(&self, key: &str) -> Option<u64> {
        let entry = self.windows.get(key)?;
        let oldest = entry.attempts.iter().min()?;
        let remaining = entry.window.saturating_sub(oldest.elapsed());
        Some((remaining.as_secs_f64().ceil() as u64).max(1))
    }

    /// Evaluate an entry's sliding window and lockout state.
    fn evaluate_entry(
        entry: &mut WindowEntry,
        now: Instant,
        max: u32,
        window: Duration,
        cooldown: Option<Duration>,
    ) -> Result<(), RateLimitRejection> {
        if let Some(locked_until) = entry.locked_until {
            if now < locked_until {
                let dur = locked_until.duration_since(now);
                let secs = (dur.as_secs_f64().ceil() as u64).max(1);
                return Err(RateLimitRejection::Lockout(secs));
            }
            entry.locked_until = None;
            entry.attempts.clear();
        }

        entry.window = window;
        entry.attempts.retain(|&t| now.duration_since(t) < window);

        if entry.attempts.len() as u32 >= max {
            if let Some(cd) = cooldown {
                entry.locked_until = Some(now + cd);
                let secs = (cd.as_secs_f64().ceil() as u64).max(1);
                return Err(RateLimitRejection::Lockout(secs));
            }
            return Err(RateLimitRejection::Exceeded);
        }

        entry.attempts.push(now);
        Ok(())
    }

    /// Internal core sliding-window evaluation with atomic capacity admission.
    fn check_internal(
        &self,
        key: &str,
        max: u32,
        window: Duration,
        cooldown: Option<Duration>,
    ) -> (KeyAdmission, Result<(), RateLimitRejection>) {
        let now = Instant::now();

        // 1. Fast path: check if key is already occupied.
        // If occupied, this request consumes NO new entry capacity and must NOT be rejected by max_entries.
        if let Some(mut existing) = self.windows.get_mut(key) {
            let res = Self::evaluate_entry(&mut existing, now, max, window, cooldown);
            return (KeyAdmission::Existing, res);
        }

        // 2. Slow path: key is not yet present.
        // Before reserving capacity, attempt bounded in-band reclamation if at or above capacity limit.
        if self.entry_count.load(Ordering::Relaxed) >= self.max_entries {
            self.reclaim_expired_bounded(self.config.window(), now, Some(128));
        }

        // 3. Reserve capacity for new entry using CAS loop.
        let mut current = self.entry_count.load(Ordering::Acquire);
        loop {
            if current >= self.max_entries {
                // Key may have been inserted concurrently while reclaiming.
                if let Some(mut existing) = self.windows.get_mut(key) {
                    let res = Self::evaluate_entry(&mut existing, now, max, window, cooldown);
                    return (KeyAdmission::Existing, res);
                }
                return (
                    KeyAdmission::Existing,
                    Err(RateLimitRejection::CapacityExhausted),
                );
            }
            match self.entry_count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }

        // 4. Insert or admit key into DashMap.
        let (admission, mut entry) = match self.windows.entry(key.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(occ) => {
                // Another thread inserted this key in a race; release reserved slot.
                self.entry_count.fetch_sub(1, Ordering::Release);
                (KeyAdmission::Existing, occ.into_ref())
            }
            dashmap::mapref::entry::Entry::Vacant(vac) => {
                let entry = vac.insert(WindowEntry {
                    attempts: Vec::new(),
                    locked_until: None,
                    window,
                });
                (KeyAdmission::NewlyInserted, entry)
            }
        };

        let res = Self::evaluate_entry(&mut entry, now, max, window, cooldown);
        (admission, res)
    }

    /// Check if an action under `key` is allowed given explicit `max` attempts within `window`.
    pub fn allow(&self, key: &str, max: u32, window: Duration) -> bool {
        let (_, res) = self.check_internal(key, max, window, None);
        res.is_ok()
    }

    /// Return the configured cooldown period in seconds for 429 Retry-After headers.
    pub fn cooldown_secs(&self) -> u64 {
        self.config.login_cooldown_secs
    }

    /// Return the current number of tracked rate limit keys.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entry_count.load(Ordering::Acquire)
    }

    /// Return remaining lockout duration in seconds (minimum 1s) if key is actively locked out.
    pub fn remaining_cooldown(&self, key: &str) -> Option<u64> {
        let entry = self.windows.get(key)?;
        let locked_until = entry.locked_until?;
        let now = Instant::now();
        if locked_until > now {
            let dur = locked_until.duration_since(now);
            Some((dur.as_secs_f64().ceil() as u64).max(1))
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
        let acct_key = Self::format_account_key("account", account);
        self.remaining_cooldown_dual_key(&ip_key, &acct_key)
    }

    /// Check rate limit against configured rules and enforce cooldown on exceed.
    pub fn check_rate_limit(&self, key: &str) -> Result<(), AppError> {
        if !self.config.enabled {
            return Ok(());
        }
        let (_, res) = self.check_internal(
            key,
            self.config.max_attempts,
            self.config.window(),
            Some(self.config.cooldown()),
        );
        res.map_err(AppError::from)
    }

    /// Check rate limit for an IP address.
    pub fn check_ip(&self, ip: &str) -> Result<(), RateLimitRejection> {
        if !self.config.enabled {
            return Ok(());
        }
        let key = format!("ip:{ip}");
        let (_, res) = self.check_internal(
            &key,
            self.config.max_attempts,
            self.config.window(),
            Some(self.config.cooldown()),
        );
        res
    }

    /// Check rate limit for an account identifier (normalized email).
    pub fn check_account(&self, account: &str) -> Result<(), RateLimitRejection> {
        if !self.config.enabled {
            return Ok(());
        }
        let key = Self::format_account_key("account", account);
        let (_, res) = self.check_internal(
            &key,
            self.config.max_attempts,
            self.config.window(),
            Some(self.config.cooldown()),
        );
        res
    }

    /// Check the TOTP IP budget (`totp:ip:<ip>`).
    ///
    /// Runs regardless of [`RateLimitConfig::enabled`]: the Phase 5 switch must not
    /// silently disable second-factor brute-force protection, and these keys are
    /// disjoint from the `ip:` / `account:` / `reset_account:` dimensions.
    ///
    /// Rejects with [`RateLimitRejection::Exceeded`], never `Lockout`: the rejection is a
    /// sliding-window exhaustion, so the handler advertises the exact reopening instant
    /// via [`Self::remaining_window`] instead of a synthetic lockout duration.
    pub fn check_totp_ip_limit(
        &self,
        ip: &str,
        totp: &TotpConfig,
    ) -> Result<(), RateLimitRejection> {
        let key = Self::totp_ip_key(ip);
        self.check_totp_window(
            &key,
            totp.rate_limit_ip_max_attempts,
            totp.rate_limit_window_secs,
        )
    }

    /// Check the TOTP per-user budget (`totp:user:<user_id>`).
    ///
    /// Same independence and rejection semantics as [`Self::check_totp_ip_limit`].
    pub fn check_totp_user_limit(
        &self,
        user_id: uuid::Uuid,
        totp: &TotpConfig,
    ) -> Result<(), RateLimitRejection> {
        let key = Self::totp_user_key(user_id);
        self.check_totp_window(
            &key,
            totp.rate_limit_user_max_attempts,
            totp.rate_limit_window_secs,
        )
    }

    fn check_totp_window(
        &self,
        key: &str,
        max: u32,
        window_secs: u64,
    ) -> Result<(), RateLimitRejection> {
        let (_, res) = self.check_internal(key, max, Duration::from_secs(window_secs), None);
        res
    }

    /// Check rate limit for password reset requests.
    ///
    /// The account budget (`reset_account:{account}`) is isolated from login attempts,
    /// while the IP budget (`ip:{ip}`) is intentionally shared across authentication endpoints
    /// to mitigate distributed flooding.
    pub fn check_password_reset(&self, ip: &str, account: &str) -> Result<(), RateLimitRejection> {
        let ip_key = format!("ip:{ip}");
        let acct_key = Self::format_account_key("reset_account", account);
        self.check_dual_keys(&ip_key, &acct_key)
    }

    /// Evaluate dual-key rate limit: checks IP first, then account.
    pub fn check_dual(&self, ip: &str, account: &str) -> Result<(), RateLimitRejection> {
        let ip_key = format!("ip:{ip}");
        let acct_key = Self::format_account_key("account", account);
        self.check_dual_keys(&ip_key, &acct_key)
    }

    /// Internal dual-key evaluation with atomic rollback on capacity failure.
    fn check_dual_keys(&self, first_key: &str, second_key: &str) -> Result<(), RateLimitRejection> {
        if !self.config.enabled {
            return Ok(());
        }
        let (first_admission, first_res) = self.check_internal(
            first_key,
            self.config.max_attempts,
            self.config.window(),
            Some(self.config.cooldown()),
        );
        first_res?;

        let (_, second_res) = self.check_internal(
            second_key,
            self.config.max_attempts,
            self.config.window(),
            Some(self.config.cooldown()),
        );

        if let Err(e) = second_res {
            if e == RateLimitRejection::CapacityExhausted {
                if first_admission == KeyAdmission::NewlyInserted {
                    self.reset(first_key);
                } else if let Some(mut entry) = self.windows.get_mut(first_key) {
                    entry.attempts.pop();
                }
            }
            return Err(e);
        }
        Ok(())
    }

    /// Reset rate limit counter for an account only, leaving IP counters intact.
    pub fn reset_account(&self, account: &str) {
        let key = Self::format_account_key("account", account);
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
        self.reclaim_expired_bounded(window, now, None);
    }

    /// Prune expired entries, bounded by `limit` total removals if specified.
    pub fn reclaim_expired_bounded(
        &self,
        _fallback_window: Duration,
        now: Instant,
        limit: Option<usize>,
    ) -> usize {
        let mut removed = 0usize;
        self.windows.retain(|_, entry| {
            if let Some(max_prune) = limit
                && removed >= max_prune
            {
                return true;
            }
            if let Some(locked_until) = entry.locked_until {
                if now < locked_until {
                    return true;
                }
                entry.locked_until = None;
                entry.attempts.clear();
            }
            let win = entry.window;
            entry.attempts.retain(|&t| now.duration_since(t) < win);
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
                tokio::task::yield_now().await;
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

    #[test]
    fn test_truncate_utf8_respects_char_boundaries() {
        // Multi-byte unicode: 4-byte crab emoji 🦀
        let s = "a".repeat(254) + "🦀";
        let truncated = truncate_utf8(&s, 255);
        assert_eq!(truncated.len(), 254);
        assert_eq!(truncated, &"a".repeat(254));

        // 3-byte Japanese character '日'
        let s2 = "b".repeat(253) + "日";
        let truncated2 = truncate_utf8(&s2, 255);
        assert_eq!(truncated2.len(), 253);

        // 2-byte accented character 'é'
        let s3 = "c".repeat(254) + "é";
        let truncated3 = truncate_utf8(&s3, 255);
        assert_eq!(truncated3.len(), 254);
    }

    #[test]
    fn test_rate_limit_unicode_email_does_not_panic() {
        let limiter = RateLimiter::new();
        let unicode_email = format!("{}\u{1F980}@example.com", "u".repeat(254));
        assert!(limiter.check_account(&unicode_email).is_ok());
        assert!(limiter.check_dual("127.0.0.1", &unicode_email).is_ok());
        assert!(
            limiter
                .check_password_reset("127.0.0.1", &unicode_email)
                .is_ok()
        );
        limiter.reset_account(&unicode_email);
    }

    #[test]
    fn test_occupied_key_admission_at_full_capacity() {
        let config = RateLimitConfig {
            enabled: true,
            max_attempts: 5,
            window_secs: 60,
            login_cooldown_secs: 60,
        };
        // Strict capacity of 2 entries
        let limiter = RateLimiter::with_config_and_capacity(config, 2);

        // Fill capacity with 2 distinct keys
        assert!(limiter.check_ip("1.1.1.1").is_ok());
        assert!(limiter.check_ip("2.2.2.2").is_ok());

        // Key 1.1.1.1 already exists: subsequent evaluations must succeed and not be rejected by max_entries
        for _ in 0..3 {
            assert!(limiter.check_ip("1.1.1.1").is_ok());
        }

        // 3rd new key must be rejected with CapacityExhausted
        let res = limiter.check_ip("3.3.3.3");
        assert_eq!(res.unwrap_err(), RateLimitRejection::CapacityExhausted);
    }

    #[test]
    fn test_retry_after_fractional_ceiling() {
        let now = Instant::now();
        let mut entry = WindowEntry {
            attempts: Vec::new(),
            locked_until: Some(now + Duration::from_millis(1800)),
            window: Duration::from_secs(60),
        };
        let rej = RateLimiter::evaluate_entry(
            &mut entry,
            now,
            5,
            Duration::from_secs(60),
            Some(Duration::from_secs(5)),
        );
        assert_eq!(rej.unwrap_err(), RateLimitRejection::Lockout(2));
    }

    #[test]
    fn test_dual_key_rollback_accuracy_on_capacity_failure() {
        let config = RateLimitConfig {
            enabled: true,
            max_attempts: 5,
            window_secs: 60,
            login_cooldown_secs: 60,
        };
        // Capacity strictly 1 entry
        let limiter = RateLimiter::with_config_and_capacity(config, 1);

        // IP is new, account cannot be admitted -> IP rolled back
        let res = limiter.check_dual("192.0.2.1", "victim@example.com");
        assert_eq!(res.unwrap_err(), RateLimitRejection::CapacityExhausted);

        // IP slot was released: fresh IP can be admitted
        assert!(limiter.check_ip("192.0.2.2").is_ok());

        // Now capacity is full (192.0.2.2 occupies the only slot).
        // 192.0.2.2 already exists. Attempt check_dual with new account.
        // Account fails with CapacityExhausted.
        // Existing IP 192.0.2.2 must NOT be deleted, but the attempt pushed by check_dual must be popped.
        let res2 = limiter.check_dual("192.0.2.2", "another@example.com");
        assert_eq!(res2.unwrap_err(), RateLimitRejection::CapacityExhausted);

        // 192.0.2.2 still exists in the map and the provisional attempt was popped
        assert!(limiter.windows.contains_key("ip:192.0.2.2"));
        assert_eq!(
            limiter.windows.get("ip:192.0.2.2").unwrap().attempts.len(),
            1
        );
    }

    #[test]
    fn test_reclaim_preserves_explicit_duration_zero() {
        let limiter = RateLimiter::with_config_and_capacity(RateLimitConfig::default(), 1);
        assert!(limiter.allow("a", 1, Duration::ZERO));
        assert!(limiter.allow("b", 1, Duration::ZERO));
    }

    #[test]
    fn test_shared_ip_budget_across_login_and_password_reset() {
        let config = RateLimitConfig {
            enabled: true,
            max_attempts: 2,
            window_secs: 60,
            login_cooldown_secs: 60,
        };
        let limiter = RateLimiter::with_config(config);
        let ip = "198.51.100.99";

        // Consume 1 attempt via check_dual (login)
        assert!(limiter.check_dual(ip, "user1@example.com").is_ok());

        // Consume 2nd attempt via check_password_reset (reset)
        assert!(
            limiter
                .check_password_reset(ip, "user2@example.com")
                .is_ok()
        );

        // 3rd attempt from same IP is locked out across both endpoints
        assert!(limiter.check_dual(ip, "user3@example.com").is_err());
        assert!(
            limiter
                .check_password_reset(ip, "user4@example.com")
                .is_err()
        );
    }

    fn totp_test_config() -> TotpConfig {
        TotpConfig {
            rate_limit_ip_max_attempts: 3,
            rate_limit_user_max_attempts: 2,
            rate_limit_window_secs: 60,
            ..TotpConfig::default()
        }
    }

    #[test]
    fn totp_ip_limit_keys_are_bounded_and_disjoint() {
        let limiter = RateLimiter::new();
        let totp = totp_test_config();
        assert!(limiter.check_totp_ip_limit("198.51.100.7", &totp).is_ok());

        assert!(limiter.windows.contains_key("totp:ip:198.51.100.7"));
        assert!(!limiter.windows.contains_key("ip:198.51.100.7"));
        // Phase 5 IP budget untouched by the TOTP dimension.
        assert!(limiter.check_ip("198.51.100.7").is_ok());
        assert_eq!(
            limiter
                .windows
                .get("ip:198.51.100.7")
                .unwrap()
                .attempts
                .len(),
            1
        );
    }

    #[test]
    fn totp_ip_limit_trips_at_configured_max() {
        let limiter = RateLimiter::new();
        let totp = totp_test_config();
        for _ in 0..3 {
            assert!(limiter.check_totp_ip_limit("198.51.100.8", &totp).is_ok());
        }
        assert_eq!(
            limiter.check_totp_ip_limit("198.51.100.8", &totp),
            Err(RateLimitRejection::Exceeded)
        );
        // Another IP still has its own budget.
        assert!(limiter.check_totp_ip_limit("198.51.100.9", &totp).is_ok());
    }

    #[test]
    fn totp_user_limit_is_per_user_and_independent_of_ip() {
        let limiter = RateLimiter::new();
        let totp = totp_test_config();
        let user = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();

        for _ in 0..2 {
            assert!(limiter.check_totp_user_limit(user, &totp).is_ok());
        }
        assert_eq!(
            limiter.check_totp_user_limit(user, &totp),
            Err(RateLimitRejection::Exceeded)
        );
        assert!(
            limiter.windows.contains_key(&format!("totp:user:{user}")),
            "user dimension must use the `totp:user:<user_id>` key"
        );
        // A different user is unaffected, and no IP key was consumed by user checks.
        assert!(limiter.check_totp_user_limit(other, &totp).is_ok());
        assert_eq!(limiter.entry_count(), 2);
    }

    #[test]
    fn remaining_window_tracks_the_oldest_attempt() {
        let limiter = RateLimiter::new();
        let totp = totp_test_config();
        for _ in 0..3 {
            assert!(limiter.check_totp_ip_limit("198.51.100.11", &totp).is_ok());
        }
        assert!(limiter.check_totp_ip_limit("198.51.100.11", &totp).is_err());

        let key = RateLimiter::totp_ip_key("198.51.100.11");
        let secs = limiter.remaining_window(&key).expect("window entry");
        assert!((59..=60).contains(&secs));
        assert!(limiter.remaining_window("totp:ip:unknown").is_none());
    }

    #[test]
    fn totp_limits_ignore_the_phase5_enabled_switch() {
        let limiter = RateLimiter::with_config(RateLimitConfig {
            enabled: false,
            ..RateLimitConfig::default()
        });
        let totp = totp_test_config();
        let user = uuid::Uuid::new_v4();

        for _ in 0..3 {
            assert!(limiter.check_totp_ip_limit("198.51.100.10", &totp).is_ok());
        }
        assert!(
            limiter.check_totp_ip_limit("198.51.100.10", &totp).is_err(),
            "TOTP IP limit must hold while Phase 5 limits are disabled"
        );

        for _ in 0..2 {
            assert!(limiter.check_totp_user_limit(user, &totp).is_ok());
        }
        assert!(
            limiter.check_totp_user_limit(user, &totp).is_err(),
            "TOTP user limit must hold while Phase 5 limits are disabled"
        );
    }
}
