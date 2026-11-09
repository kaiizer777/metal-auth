use std::str::FromStr;
use std::time::Duration;

use crate::error::ConfigError;

pub const DEFAULT_PORT: u16 = 3000;
pub const DEFAULT_MAX_CONNECTIONS: u32 = 25;
pub const DEFAULT_MIN_CONNECTIONS: u32 = 2;
pub const DEFAULT_EMAIL_DISPATCH_TIMEOUT_SECS: u64 = 10;

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
            .field("base_url", &self.base_url)
            .field("email_dispatch_timeout", &self.email_dispatch_timeout)
            .field("async_email_dispatch", &self.async_email_dispatch)
            .finish()
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.base_url.trim().is_empty() {
            return Err(ConfigError::MissingEnvVar("BASE_URL"));
        }
        for origin in &self.allowed_origins {
            let trimmed = origin.trim();
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
