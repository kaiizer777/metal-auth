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
}

impl RateLimiter {
    /// Construct a new rate limiter with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(RateLimitConfig::default())
    }

    /// Construct a new rate limiter with the provided configuration.
    #[must_use]
    pub fn with_config(config: RateLimitConfig) -> Self {
        Self {
            windows: Arc::new(DashMap::new()),
            config,
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
        let mut entry = self
            .windows
            .entry(key.to_string())
            .or_insert_with(|| WindowEntry {
                attempts: Vec::new(),
                locked_until: None,
            });

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
    pub fn start_cleanup_task(self: Arc<Self>, window: Duration) {
        tokio::spawn(async move {
            loop {
                sleep(window).await;
                self.cleanup(window);
                tracing::debug!(
                    event = "rate_limiter_cleanup",
                    remaining_keys = self.windows.len()
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
}
