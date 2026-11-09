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
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenvy::dotenv().ok();

        let database_url = std::env::var("DATABASE_URL")?;
        let port = match std::env::var("PORT") {
            Ok(val) => val.parse::<u16>()?,
            Err(_) => DEFAULT_PORT,
        };

        let allowed_origins = match std::env::var("ALLOWED_ORIGINS") {
            Ok(val) => parse_allowed_origins(&val),
            Err(_) => Vec::new(),
        };

        Ok(Self {
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
        })
    }
}

fn parse_allowed_origins(val: &str) -> Vec<String> {
    val.split(',')
        .map(str::trim)
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
    fn test_parse_allowed_origins() {
        let empty = parse_allowed_origins("");
        assert!(empty.is_empty());

        let whitespace = parse_allowed_origins("   ,   , ");
        assert!(whitespace.is_empty());

        let parsed = parse_allowed_origins("https://app1.com, https://app2.com , https://app3.com");
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
    fn test_config_from_env_parses_allowed_origins() {
        let prev_db = std::env::var("DATABASE_URL").ok();
        let prev_origins = std::env::var("ALLOWED_ORIGINS").ok();

        // SAFETY: Test modifies environment variables sequentially and restores them before exit.
        unsafe {
            std::env::set_var("DATABASE_URL", "postgres://localhost/test");
            std::env::set_var(
                "ALLOWED_ORIGINS",
                "https://app1.com, https://app2.com , https://app3.com",
            );
        }

        let cfg = Config::from_env().expect("Config::from_env should succeed");
        assert_eq!(
            cfg.allowed_origins,
            vec![
                "https://app1.com".to_string(),
                "https://app2.com".to_string(),
                "https://app3.com".to_string(),
            ]
        );

        // SAFETY: Restoring original environment variable values.
        unsafe {
            if let Some(val) = prev_db {
                std::env::set_var("DATABASE_URL", val);
            } else {
                std::env::remove_var("DATABASE_URL");
            }
            if let Some(val) = prev_origins {
                std::env::set_var("ALLOWED_ORIGINS", val);
            } else {
                std::env::remove_var("ALLOWED_ORIGINS");
            }
        }
    }
}
