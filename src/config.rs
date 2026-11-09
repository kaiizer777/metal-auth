use std::str::FromStr;

pub const DEFAULT_PORT: u16 = 3000;
pub const DEFAULT_MAX_CONNECTIONS: u32 = 25;
pub const DEFAULT_MIN_CONNECTIONS: u32 = 2;

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
            .finish()
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        for origin in &self.allowed_origins {
            let trimmed = origin.trim();
            if trimmed != "*" {
                axum::http::HeaderValue::from_str(trimmed)
                    .map_err(|e| format!("invalid CORS origin '{origin}': {e}"))?;
            }
        }
        for method in &self.allowed_methods {
            axum::http::Method::from_str(method.trim())
                .map_err(|e| format!("invalid CORS method '{method}': {e}"))?;
        }
        for header in &self.allowed_headers {
            axum::http::header::HeaderName::from_str(header.trim())
                .map_err(|e| format!("invalid CORS header '{header}': {e}"))?;
        }
        Ok(())
    }

    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenvy::dotenv().ok();

        let database_url = std::env::var("DATABASE_URL")?;
        let port = match std::env::var("PORT") {
            Ok(val) => val.parse::<u16>()?,
            Err(_) => DEFAULT_PORT,
        };

        let allowed_origins = parse_allowed_origins();

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
        };

        cfg.validate()?;
        Ok(cfg)
    }
}

fn parse_allowed_origins() -> Vec<String> {
    match std::env::var("ALLOWED_ORIGINS") {
        Ok(val) => parse_allowed_origins_str(&val),
        Err(_) => Vec::new(),
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
        };
        assert!(cfg.validate().is_err());
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
        };
        assert!(cfg.validate().is_err());
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
        };
        assert!(cfg.validate().is_err());
    }
}
