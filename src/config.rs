use std::str::FromStr;
use std::time::Duration;

use crate::error::ConfigError;

pub const DEFAULT_PORT: u16 = 3000;
pub const DEFAULT_MAX_CONNECTIONS: u32 = 25;
pub const DEFAULT_MIN_CONNECTIONS: u32 = 2;
pub const DEFAULT_EMAIL_DISPATCH_TIMEOUT_SECS: u64 = 10;

// ─── Phase 1 — Infra Config ──────────────────────────────────────────────────

#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    pub database_url: String,
    pub port: u16,

    // CORS
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,

    // DB pool
    pub max_connections: u32,
    pub min_connections: u32,

    // Phase 2: email hook dispatch
    pub base_url: String,
    pub email_dispatch_timeout: Duration,
    /// Whether email dispatch blocks the caller until delivery completes.
    ///
    /// Test-only knob: `false` makes dispatch wait for delivery in the calling task,
    /// which re-introduces the account-existence timing signal. Production request paths
    /// detach dispatch, and [`Config::validate`] rejects `false`, so it is unreachable
    /// outside tests. Never enable it in production.
    pub async_email_dispatch: bool,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &"[REDACTED]")
            .field("port", &self.port)
            .field("allowed_origins", &self.allowed_origins)
            .field("allowed_methods", &self.allowed_methods)
            .field("allowed_headers", &self.allowed_headers)
            .field("max_connections", &self.max_connections)
            .field("min_connections", &self.min_connections)
            .field("base_url", &"[REDACTED]")
            .field("email_dispatch_timeout", &self.email_dispatch_timeout)
            .field("async_email_dispatch", &self.async_email_dispatch)
            .finish()
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.database_url.trim().is_empty() {
            return Err(ConfigError::InvalidValue {
                field: "database_url",
                reason: "must not be empty",
            });
        }
        if self.max_connections == 0 {
            return Err(ConfigError::InvalidValue {
                field: "max_connections",
                reason: "must be greater than 0",
            });
        }
        if self.min_connections > self.max_connections {
            return Err(ConfigError::InvalidValue {
                field: "min_connections",
                reason: "must not exceed max_connections",
            });
        }
        if self.base_url.trim().is_empty() {
            return Err(ConfigError::MissingEnvVar("BASE_URL"));
        }
        let uri = self
            .base_url
            .parse::<axum::http::Uri>()
            .map_err(|_| ConfigError::InvalidEnvVar("BASE_URL"))?;
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || uri.authority().is_none()
            || uri.query().is_some()
            || uri.authority().is_some_and(|a| a.as_str().contains('@'))
        {
            return Err(ConfigError::InvalidEnvVar("BASE_URL"));
        }
        if self.email_dispatch_timeout == Duration::ZERO {
            return Err(ConfigError::InvalidEnvVar("EMAIL_DISPATCH_TIMEOUT_SECS"));
        }
        if !self.async_email_dispatch {
            return Err(ConfigError::InvalidValue {
                field: "async_email_dispatch",
                reason: "sync dispatch waits for delivery and reveals account existence; test-only, never enable in production",
            });
        }
        for origin in &self.allowed_origins {
            let trimmed = origin.trim();
            if trimmed.ends_with('/') {
                return Err(ConfigError::InvalidValue {
                    field: "allowed_origins",
                    reason: "must not contain trailing slash",
                });
            }
            if trimmed != "*" {
                axum::http::HeaderValue::from_str(trimmed).map_err(|source| {
                    ConfigError::InvalidOrigin {
                        value: trimmed.to_string(),
                        source,
                    }
                })?;
            }
        }
        for method in &self.allowed_methods {
            let trimmed = method.trim();
            axum::http::Method::from_str(trimmed).map_err(|source| ConfigError::InvalidMethod {
                value: trimmed.to_string(),
                source,
            })?;
        }
        for header in &self.allowed_headers {
            let trimmed = header.trim();
            axum::http::header::HeaderName::from_str(trimmed).map_err(|source| {
                ConfigError::InvalidHeader {
                    value: trimmed.to_string(),
                    source,
                }
            })?;
        }
        Ok(())
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();

        let database_url = match std::env::var("DATABASE_URL") {
            Ok(val) => val,
            Err(std::env::VarError::NotPresent) => {
                return Err(ConfigError::MissingEnvVar("DATABASE_URL"));
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("DATABASE_URL"));
            }
        };
        let port = match std::env::var("PORT") {
            Ok(val) => val.parse::<u16>().map_err(ConfigError::InvalidPort)?,
            Err(std::env::VarError::NotPresent) => DEFAULT_PORT,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("PORT"));
            }
        };

        let allowed_origins = parse_allowed_origins()?;

        let base_url = match std::env::var("BASE_URL") {
            Ok(val) => val,
            Err(std::env::VarError::NotPresent) => {
                return Err(ConfigError::MissingEnvVar("BASE_URL"));
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("BASE_URL"));
            }
        };

        let email_dispatch_timeout = match std::env::var("EMAIL_DISPATCH_TIMEOUT_SECS") {
            Ok(val) => {
                let secs: u64 = val
                    .parse()
                    .map_err(|_| ConfigError::InvalidEnvVar("EMAIL_DISPATCH_TIMEOUT_SECS"))?;
                if secs == 0 {
                    return Err(ConfigError::InvalidEnvVar("EMAIL_DISPATCH_TIMEOUT_SECS"));
                }
                Duration::from_secs(secs)
            }
            Err(std::env::VarError::NotPresent) => {
                Duration::from_secs(DEFAULT_EMAIL_DISPATCH_TIMEOUT_SECS)
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("EMAIL_DISPATCH_TIMEOUT_SECS"));
            }
        };

        let async_email_dispatch = match std::env::var("ASYNC_EMAIL_DISPATCH") {
            Ok(val) => val
                .parse::<bool>()
                .map_err(|_| ConfigError::InvalidEnvVar("ASYNC_EMAIL_DISPATCH"))?,
            Err(std::env::VarError::NotPresent) => true,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("ASYNC_EMAIL_DISPATCH"));
            }
        };

        let cfg = Self {
            database_url,
            port,
            allowed_origins,
            allowed_methods: vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"]
                .into_iter()
                .map(String::from)
                .collect(),
            allowed_headers: vec!["Authorization", "Content-Type"]
                .into_iter()
                .map(String::from)
                .collect(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            min_connections: DEFAULT_MIN_CONNECTIONS,
            base_url,
            email_dispatch_timeout,
            async_email_dispatch,
        };

        cfg.validate()?;
        Ok(cfg)
    }
}

fn parse_allowed_origins() -> Result<Vec<String>, ConfigError> {
    match std::env::var("ALLOWED_ORIGINS") {
        Ok(val) => Ok(parse_allowed_origins_str(&val)),
        Err(std::env::VarError::NotPresent) => Ok(Vec::new()),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(ConfigError::NonUnicodeEnvVar("ALLOWED_ORIGINS"))
        }
    }
}

fn parse_allowed_origins_str(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().trim_end_matches('/'))
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

// ─── Phase 3 — Auth-specific configuration ───────────────────────────────────

/// Auth-specific runtime configuration validated at construction time.
///
/// # Validation rules (enforced in `AppConfig::new`, bypassed in `AppConfig::default`)
/// - `argon2_m_cost >= 19456`
/// - `argon2_t_cost >= 2`
/// - `argon2_p_cost >= 1`
/// - `8 <= password_min_len <= password_max_len <= 128`
/// - `900 <= verification_token_ttl_secs <= 3600`
/// - `900 <= reset_token_ttl_secs <= 3600`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppConfig {
    /// Argon2id memory cost in KiB. Default: 65536 (64 MiB — RFC 9106 §4 second option).
    pub argon2_m_cost: u32,
    /// Argon2id time cost (iterations). Default: 3.
    pub argon2_t_cost: u32,
    /// Argon2id parallelism lanes. Default: 4.
    pub argon2_p_cost: u32,
    /// Password minimum length in Unicode code points. Must be >= 8. Default: 8.
    pub password_min_len: usize,
    /// Password maximum length in Unicode code points. Must be <= 128. Default: 128.
    pub password_max_len: usize,
    /// Email verification token TTL in seconds. Range: 900–3600. Default: 1800 (30 min).
    pub verification_token_ttl_secs: u64,
    /// Password reset token TTL in seconds. Range: 900–3600. Default: 900 (15 min).
    pub reset_token_ttl_secs: u64,
    /// Controls whether login is blocked for unverified email addresses. Default: true.
    pub require_email_verification: bool,
}

impl AppConfig {
    /// Validates all configuration bounds per OWASP ASVS 5.0 L1 minimums.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.argon2_m_cost < 19456 {
            return Err(ConfigError::InvalidValue {
                field: "argon2_m_cost",
                reason: "must be at least 19456 KiB",
            });
        }
        if self.argon2_t_cost < 2 {
            return Err(ConfigError::InvalidValue {
                field: "argon2_t_cost",
                reason: "must be at least 2 iterations",
            });
        }
        if self.argon2_p_cost < 1 {
            return Err(ConfigError::InvalidValue {
                field: "argon2_p_cost",
                reason: "must be at least 1 lane",
            });
        }
        if self.password_min_len < 8 {
            return Err(ConfigError::InvalidValue {
                field: "password_min_len",
                reason: "must be at least 8 characters",
            });
        }
        if self.password_max_len > 128 {
            return Err(ConfigError::InvalidValue {
                field: "password_max_len",
                reason: "must not exceed 128 characters",
            });
        }
        if self.password_min_len > self.password_max_len {
            return Err(ConfigError::InvalidValue {
                field: "password_min_len",
                reason: "must not exceed password_max_len",
            });
        }
        if !(900..=3600).contains(&self.verification_token_ttl_secs) {
            return Err(ConfigError::InvalidValue {
                field: "verification_token_ttl_secs",
                reason: "must be between 900 and 3600 seconds",
            });
        }
        if !(900..=3600).contains(&self.reset_token_ttl_secs) {
            return Err(ConfigError::InvalidValue {
                field: "reset_token_ttl_secs",
                reason: "must be between 900 and 3600 seconds",
            });
        }
        Ok(())
    }

    /// Fallible constructor — validates all fields per OWASP ASVS 5.0 L1 minimums.
    ///
    /// Returns typed `ConfigError::InvalidValue` on any out-of-range value.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        argon2_m_cost: u32,
        argon2_t_cost: u32,
        argon2_p_cost: u32,
        password_min_len: usize,
        password_max_len: usize,
        verification_token_ttl_secs: u64,
        reset_token_ttl_secs: u64,
        require_email_verification: bool,
    ) -> Result<Self, ConfigError> {
        let config = Self {
            argon2_m_cost,
            argon2_t_cost,
            argon2_p_cost,
            password_min_len,
            password_max_len,
            verification_token_ttl_secs,
            reset_token_ttl_secs,
            require_email_verification,
        };
        config.validate()?;
        Ok(config)
    }

    /// Load `AppConfig` from a custom key-value lookup function.
    pub fn from_lookup<F>(lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Result<String, std::env::VarError>,
    {
        let defaults = Self::default();

        let argon2_m_cost = parse_env_u32(&lookup, "ARGON2_M_COST", defaults.argon2_m_cost)?;
        let argon2_t_cost = parse_env_u32(&lookup, "ARGON2_T_COST", defaults.argon2_t_cost)?;
        let argon2_p_cost = parse_env_u32(&lookup, "ARGON2_P_COST", defaults.argon2_p_cost)?;
        let password_min_len =
            parse_env_usize(&lookup, "PASSWORD_MIN_LEN", defaults.password_min_len)?;
        let password_max_len =
            parse_env_usize(&lookup, "PASSWORD_MAX_LEN", defaults.password_max_len)?;
        let verification_token_ttl_secs = parse_env_u64(
            &lookup,
            "VERIFICATION_TOKEN_TTL_SECS",
            defaults.verification_token_ttl_secs,
        )?;
        let reset_token_ttl_secs = parse_env_u64(
            &lookup,
            "RESET_TOKEN_TTL_SECS",
            defaults.reset_token_ttl_secs,
        )?;
        let require_email_verification = parse_env_bool(
            &lookup,
            "REQUIRE_EMAIL_VERIFICATION",
            defaults.require_email_verification,
        )?;

        Self::new(
            argon2_m_cost,
            argon2_t_cost,
            argon2_p_cost,
            password_min_len,
            password_max_len,
            verification_token_ttl_secs,
            reset_token_ttl_secs,
            require_email_verification,
        )
    }

    /// Load `AppConfig` from environment variables, falling back to defaults.
    pub fn from_env() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();
        Self::from_lookup(|k| std::env::var(k))
    }
}

fn parse_env_u32(
    lookup: &impl Fn(&str) -> Result<String, std::env::VarError>,
    key: &'static str,
    default: u32,
) -> Result<u32, ConfigError> {
    match lookup(key) {
        Ok(val) => val.parse::<u32>().map_err(|_| ConfigError::InvalidValue {
            field: key,
            reason: "must be a valid integer",
        }),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(ConfigError::NonUnicodeEnvVar(key)),
    }
}

fn parse_env_usize(
    lookup: &impl Fn(&str) -> Result<String, std::env::VarError>,
    key: &'static str,
    default: usize,
) -> Result<usize, ConfigError> {
    match lookup(key) {
        Ok(val) => val.parse::<usize>().map_err(|_| ConfigError::InvalidValue {
            field: key,
            reason: "must be a valid integer",
        }),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(ConfigError::NonUnicodeEnvVar(key)),
    }
}

fn parse_env_u64(
    lookup: &impl Fn(&str) -> Result<String, std::env::VarError>,
    key: &'static str,
    default: u64,
) -> Result<u64, ConfigError> {
    match lookup(key) {
        Ok(val) => val.parse::<u64>().map_err(|_| ConfigError::InvalidValue {
            field: key,
            reason: "must be a valid integer",
        }),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(ConfigError::NonUnicodeEnvVar(key)),
    }
}

fn parse_env_bool(
    lookup: &impl Fn(&str) -> Result<String, std::env::VarError>,
    key: &'static str,
    default: bool,
) -> Result<bool, ConfigError> {
    match lookup(key) {
        Ok(val) => match val.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            _ => Err(ConfigError::InvalidValue {
                field: key,
                reason: "must be a boolean (true/false/1/0)",
            }),
        },
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(ConfigError::NonUnicodeEnvVar(key)),
    }
}

impl Default for AppConfig {
    /// Skips validation — for tests only.
    ///
    /// Default parameters meet RFC 9106 §4 second option and OWASP ASVS 5.0 L1 minimums:
    /// m=65536 KiB (64 MiB), t=3, p=4.
    fn default() -> Self {
        Self {
            argon2_m_cost: 65536,
            argon2_t_cost: 3,
            argon2_p_cost: 4,
            password_min_len: 8,
            password_max_len: 128,
            verification_token_ttl_secs: 1800,
            reset_token_ttl_secs: 900,
            require_email_verification: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Phase 1 Config tests ──────────────────────────────────────────────────

    #[test]
    fn test_config_defaults() {
        let cfg = Config {
            database_url: "postgres://user:pass@localhost:5432/metal_auth".into(),
            port: DEFAULT_PORT,
            allowed_origins: vec![],
            allowed_methods: vec!["GET".into(), "POST".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_connections: DEFAULT_MAX_CONNECTIONS,
            min_connections: DEFAULT_MIN_CONNECTIONS,
            base_url: "https://example.com".into(),
            email_dispatch_timeout: Duration::from_secs(10),
            async_email_dispatch: true,
        };
        assert_eq!(cfg.port, 3000);
        assert_eq!(cfg.max_connections, 25);
        assert_eq!(cfg.min_connections, 2);
    }

    #[test]
    fn test_config_debug_redacts_database_url() {
        let cfg = Config {
            database_url: "postgres://secret_user:super_secret_password@localhost:5432/db".into(),
            port: DEFAULT_PORT,
            allowed_origins: vec![],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_connections: DEFAULT_MAX_CONNECTIONS,
            min_connections: DEFAULT_MIN_CONNECTIONS,
            base_url: "https://example.com".into(),
            email_dispatch_timeout: Duration::from_secs(10),
            async_email_dispatch: true,
        };
        let debug_output = format!("{cfg:?}");
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("super_secret_password"));
        assert!(!debug_output.contains("secret_user"));
        assert!(!debug_output.contains("https://example.com"));
    }

    #[test]
    fn test_parse_allowed_origins_str() {
        assert!(parse_allowed_origins_str("").is_empty());
        assert!(parse_allowed_origins_str("   ,   , ").is_empty());
        assert!(parse_allowed_origins_str("   ,   /   , ///, ").is_empty());

        let parsed =
            parse_allowed_origins_str("https://app1.com/, https://app2.com , https://app3.com///");
        assert_eq!(
            parsed,
            vec![
                "https://app1.com".to_string(),
                "https://app2.com".to_string(),
                "https://app3.com".to_string(),
            ]
        );
    }

    #[test]
    fn test_config_validate_success() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec!["https://app.example.com".into(), "*".into()],
            allowed_methods: vec!["GET".into(), "POST".into()],
            allowed_headers: vec!["Authorization".into(), "Content-Type".into()],
            max_connections: 5,
            min_connections: 1,
            base_url: "https://app.example.com".into(),
            email_dispatch_timeout: Duration::from_secs(10),
            async_email_dispatch: true,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_config_validate_rejects_malformed_origin() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec!["bad\norigin".into()],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_connections: 5,
            min_connections: 1,
            base_url: "https://app.example.com".into(),
            email_dispatch_timeout: Duration::from_secs(10),
            async_email_dispatch: true,
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidOrigin { ref value, .. }) if value == "bad\norigin"
        ));
    }

    #[test]
    fn test_config_validate_rejects_malformed_method() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec!["https://app.example.com".into()],
            allowed_methods: vec!["BAD METHOD".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_connections: 5,
            min_connections: 1,
            base_url: "https://app.example.com".into(),
            email_dispatch_timeout: Duration::from_secs(10),
            async_email_dispatch: true,
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidMethod { ref value, .. }) if value == "BAD METHOD"
        ));
    }

    #[test]
    fn test_config_validate_rejects_malformed_header() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec!["https://app.example.com".into()],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Bad Header".into()],
            max_connections: 5,
            min_connections: 1,
            base_url: "https://app.example.com".into(),
            email_dispatch_timeout: Duration::from_secs(10),
            async_email_dispatch: true,
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidHeader { ref value, .. }) if value == "Bad Header"
        ));
    }

    #[test]
    fn test_config_validate_rejects_empty_database_url() {
        let cfg = Config {
            database_url: "".into(),
            port: 3000,
            allowed_origins: vec![],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_connections: 5,
            min_connections: 1,
            base_url: "https://app.example.com".into(),
            email_dispatch_timeout: Duration::from_secs(10),
            async_email_dispatch: true,
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidValue {
                field: "database_url",
                reason: "must not be empty",
            })
        ));
    }

    #[test]
    fn test_config_validate_rejects_whitespace_database_url() {
        let cfg = Config {
            database_url: "   \t\n  ".into(),
            port: 3000,
            allowed_origins: vec![],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_connections: 5,
            min_connections: 1,
            base_url: "https://app.example.com".into(),
            email_dispatch_timeout: Duration::from_secs(10),
            async_email_dispatch: true,
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidValue {
                field: "database_url",
                reason: "must not be empty",
            })
        ));
    }

    #[test]
    fn test_config_validate_rejects_zero_max_connections() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec![],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_connections: 0,
            min_connections: 0,
            base_url: "https://app.example.com".into(),
            email_dispatch_timeout: Duration::from_secs(10),
            async_email_dispatch: true,
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidValue {
                field: "max_connections",
                reason: "must be greater than 0",
            })
        ));
    }

    #[test]
    fn test_config_validate_rejects_min_connections_greater_than_max() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec![],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_connections: 5,
            min_connections: 6,
            base_url: "https://app.example.com".into(),
            email_dispatch_timeout: Duration::from_secs(10),
            async_email_dispatch: true,
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidValue {
                field: "min_connections",
                reason: "must not exceed max_connections",
            })
        ));
    }

    #[test]
    fn test_config_validate_accepts_equal_min_and_max_connections() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec![],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_connections: 5,
            min_connections: 5,
            base_url: "https://app.example.com".into(),
            email_dispatch_timeout: Duration::from_secs(10),
            async_email_dispatch: true,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_validate_rejects_sync_email_dispatch() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec![],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_connections: 5,
            min_connections: 1,
            base_url: "https://app.example.com".into(),
            email_dispatch_timeout: Duration::from_secs(10),
            async_email_dispatch: false,
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidValue {
                field: "async_email_dispatch",
                ..
            })
        ));
    }

    #[test]
    fn test_config_validate_rejects_origin_with_trailing_slash() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec!["https://app.example.com/".into()],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_connections: 5,
            min_connections: 1,
            base_url: "https://app.example.com".into(),
            email_dispatch_timeout: Duration::from_secs(10),
            async_email_dispatch: true,
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidValue {
                field: "allowed_origins",
                reason: "must not contain trailing slash",
            })
        ));
    }

    // ── Phase 3 AppConfig tests ───────────────────────────────────────────────

    /// OWASP ASVS 5.0 L1 doc-check: default params meet or exceed minimums.
    /// RFC 9106 §4 second option: m=65536, t=3, p=4.
    #[test]
    fn default_argon2_params_meet_asvs_l1_minimums() {
        let cfg = AppConfig::default();
        assert!(
            cfg.argon2_m_cost >= 19456,
            "m_cost must be >= 19456 KiB (ASVS L1)"
        );
        assert!(cfg.argon2_t_cost >= 2, "t_cost must be >= 2 (ASVS L1)");
        assert!(cfg.argon2_p_cost >= 1, "p_cost must be >= 1");
        assert_eq!(cfg.argon2_m_cost, 65536, "RFC 9106 §4 second option");
        assert_eq!(cfg.argon2_t_cost, 3, "RFC 9106 §4 second option");
        assert_eq!(cfg.argon2_p_cost, 4, "RFC 9106 §4 second option");
        assert_eq!(cfg.reset_token_ttl_secs, 900);
        assert!(cfg.require_email_verification);
    }

    #[test]
    fn app_config_new_accepts_valid_config() {
        assert!(AppConfig::new(65536, 3, 4, 8, 128, 1800, 900, true).is_ok());
    }

    #[test]
    fn app_config_new_rejects_m_cost_below_minimum() {
        assert!(matches!(
            AppConfig::new(19455, 2, 1, 8, 128, 900, 900, false),
            Err(ConfigError::InvalidValue {
                field: "argon2_m_cost",
                ..
            })
        ));
    }

    #[test]
    fn app_config_new_rejects_t_cost_below_2() {
        assert!(matches!(
            AppConfig::new(65536, 1, 4, 8, 128, 1800, 900, false),
            Err(ConfigError::InvalidValue {
                field: "argon2_t_cost",
                ..
            })
        ));
    }

    #[test]
    fn app_config_new_accepts_t_cost_exactly_2() {
        assert!(AppConfig::new(65536, 2, 4, 8, 128, 1800, 900, false).is_ok());
    }

    #[test]
    fn app_config_new_rejects_p_cost_below_1() {
        assert!(matches!(
            AppConfig::new(65536, 2, 0, 8, 128, 1800, 900, false),
            Err(ConfigError::InvalidValue {
                field: "argon2_p_cost",
                ..
            })
        ));
    }

    #[test]
    fn app_config_new_rejects_password_min_below_8() {
        assert!(matches!(
            AppConfig::new(65536, 3, 4, 7, 128, 1800, 900, false),
            Err(ConfigError::InvalidValue {
                field: "password_min_len",
                ..
            })
        ));
    }

    #[test]
    fn app_config_new_rejects_password_max_above_128() {
        assert!(matches!(
            AppConfig::new(65536, 3, 4, 8, 129, 1800, 900, false),
            Err(ConfigError::InvalidValue {
                field: "password_max_len",
                ..
            })
        ));
    }

    #[test]
    fn app_config_new_rejects_min_greater_than_max() {
        assert!(matches!(
            AppConfig::new(65536, 3, 4, 20, 10, 1800, 900, false),
            Err(ConfigError::InvalidValue {
                field: "password_min_len",
                ..
            })
        ));
    }

    #[test]
    fn app_config_new_rejects_verification_ttl_out_of_range() {
        assert!(matches!(
            AppConfig::new(65536, 3, 4, 8, 128, 899, 900, false),
            Err(ConfigError::InvalidValue {
                field: "verification_token_ttl_secs",
                ..
            })
        ));
        assert!(matches!(
            AppConfig::new(65536, 3, 4, 8, 128, 3601, 900, false),
            Err(ConfigError::InvalidValue {
                field: "verification_token_ttl_secs",
                ..
            })
        ));
    }

    #[test]
    fn app_config_new_rejects_reset_ttl_out_of_range() {
        assert!(matches!(
            AppConfig::new(65536, 3, 4, 8, 128, 1800, 899, false),
            Err(ConfigError::InvalidValue {
                field: "reset_token_ttl_secs",
                ..
            })
        ));
        assert!(matches!(
            AppConfig::new(65536, 3, 4, 8, 128, 1800, 3601, false),
            Err(ConfigError::InvalidValue {
                field: "reset_token_ttl_secs",
                ..
            })
        ));
    }

    #[test]
    fn app_config_new_accepts_boundary_ttl_values() {
        assert!(AppConfig::new(65536, 3, 4, 8, 128, 900, 3600, false).is_ok());
        assert!(AppConfig::new(65536, 3, 4, 8, 128, 3600, 900, false).is_ok());
    }

    #[test]
    fn app_config_from_env_defaults() {
        let cfg = AppConfig::from_lookup(|_| Err(std::env::VarError::NotPresent))
            .expect("load default env config");
        let expected = AppConfig::default();
        assert_eq!(cfg, expected);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn app_config_from_lookup_overrides() {
        let lookup = |key: &str| match key {
            "ARGON2_M_COST" => Ok("32768".to_string()),
            "ARGON2_T_COST" => Ok("4".to_string()),
            "ARGON2_P_COST" => Ok("2".to_string()),
            "PASSWORD_MIN_LEN" => Ok("10".to_string()),
            "PASSWORD_MAX_LEN" => Ok("64".to_string()),
            "VERIFICATION_TOKEN_TTL_SECS" => Ok("1200".to_string()),
            "RESET_TOKEN_TTL_SECS" => Ok("1000".to_string()),
            "REQUIRE_EMAIL_VERIFICATION" => Ok("false".to_string()),
            _ => Err(std::env::VarError::NotPresent),
        };

        let cfg = AppConfig::from_lookup(lookup).expect("load overridden config");
        assert_eq!(cfg.argon2_m_cost, 32768);
        assert_eq!(cfg.argon2_t_cost, 4);
        assert_eq!(cfg.argon2_p_cost, 2);
        assert_eq!(cfg.password_min_len, 10);
        assert_eq!(cfg.password_max_len, 64);
        assert_eq!(cfg.verification_token_ttl_secs, 1200);
        assert_eq!(cfg.reset_token_ttl_secs, 1000);
        assert!(!cfg.require_email_verification);
    }

    #[test]
    fn app_config_validate_rejects_invalid_bounds() {
        let cfg = AppConfig {
            argon2_m_cost: 1000,
            ..Default::default()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidValue {
                field: "argon2_m_cost",
                ..
            })
        ));

        let cfg = AppConfig {
            password_min_len: 5,
            ..Default::default()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidValue {
                field: "password_min_len",
                ..
            })
        ));
    }
}
