use std::time::Duration;

use sqlx::{PgPool, postgres::PgPoolOptions};
use tracing::{error, info, warn};

use crate::{
    config::Config,
    error::{AppError, ConfigError},
};

pub mod models;

pub const DEFAULT_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
pub const DEFAULT_MAX_LIFETIME: Duration = Duration::from_secs(1800);
pub const DEFAULT_MAX_RETRIES: u32 = 2;
pub const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_millis(50);

/// Configuration options for PostgreSQL connection pooling and connection acquisition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbPoolOptions {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout: Duration,
    pub idle_timeout: Option<Duration>,
    pub max_lifetime: Option<Duration>,
    pub max_retries: u32,
    pub initial_backoff: Duration,
}

impl Default for DbPoolOptions {
    fn default() -> Self {
        Self {
            max_connections: 25,
            min_connections: 2,
            acquire_timeout: DEFAULT_ACQUIRE_TIMEOUT,
            idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
            max_lifetime: Some(DEFAULT_MAX_LIFETIME),
            max_retries: DEFAULT_MAX_RETRIES,
            initial_backoff: DEFAULT_INITIAL_BACKOFF,
        }
    }
}

impl From<&Config> for DbPoolOptions {
    fn from(cfg: &Config) -> Self {
        Self {
            max_connections: cfg.max_connections,
            min_connections: cfg.min_connections,
            ..Default::default()
        }
    }
}

/// Initializes a PostgreSQL connection pool using options derived from [`Config`].
pub async fn init_pool(cfg: &Config) -> Result<PgPool, AppError> {
    let options = DbPoolOptions::from(cfg);
    init_pool_with_options(&cfg.database_url, options).await
}

/// Initializes a PostgreSQL connection pool with explicit [`DbPoolOptions`],
/// retrying on transient connection failures with exponential backoff and structured logging.
pub async fn init_pool_with_options(
    database_url: &str,
    options: DbPoolOptions,
) -> Result<PgPool, AppError> {
    if options.max_connections == 0 {
        return Err(AppError::Config(ConfigError::InvalidValue {
            field: "max_connections",
            reason: "must be greater than 0",
        }));
    }

    let pool_options = PgPoolOptions::new()
        .max_connections(options.max_connections)
        .min_connections(options.min_connections)
        .acquire_timeout(options.acquire_timeout)
        .idle_timeout(options.idle_timeout)
        .max_lifetime(options.max_lifetime);

    let mut attempts = 0;
    let mut backoff = options.initial_backoff;
    let pool = loop {
        attempts += 1;
        match pool_options.clone().connect(database_url).await {
            Ok(pool) => {
                info!(
                    op = "db_pool_connect",
                    max_connections = options.max_connections,
                    min_connections = options.min_connections,
                    attempts,
                    "database connection pool established"
                );
                break pool;
            }
            Err(e) => {
                let is_transient = matches!(
                    e,
                    sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut | sqlx::Error::Tls(_)
                );
                if is_transient && attempts <= options.max_retries {
                    warn!(
                        op = "db_pool_connect",
                        attempt = attempts,
                        max_retries = options.max_retries,
                        retry_after_ms = backoff.as_millis(),
                        err = %e,
                        "transient database connection failure; retrying with backoff"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(Duration::from_secs(5));
                } else {
                    error!(
                        op = "db_pool_connect",
                        attempt = attempts,
                        err = %e,
                        is_transient,
                        "failed to connect to database"
                    );
                    return Err(match e {
                        sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut | sqlx::Error::Tls(_) => {
                            AppError::DatabaseUnavailable(e)
                        }
                        other => AppError::Database(other),
                    });
                }
            }
        }
    };

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| {
            error!(op = "db_migrate", err = %e, "database migration failed");
            AppError::Migration(e)
        })?;

    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_pool_options_defaults() {
        let opts = DbPoolOptions::default();
        assert_eq!(opts.max_connections, 25);
        assert_eq!(opts.min_connections, 2);
        assert_eq!(opts.acquire_timeout, DEFAULT_ACQUIRE_TIMEOUT);
        assert_eq!(opts.idle_timeout, Some(DEFAULT_IDLE_TIMEOUT));
        assert_eq!(opts.max_lifetime, Some(DEFAULT_MAX_LIFETIME));
        assert_eq!(opts.max_retries, DEFAULT_MAX_RETRIES);
        assert_eq!(opts.initial_backoff, DEFAULT_INITIAL_BACKOFF);
    }

    #[test]
    fn test_db_pool_options_from_config() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec![],
            allowed_methods: vec![],
            allowed_headers: vec![],
            max_connections: 50,
            min_connections: 10,
            base_url: "https://example.com".into(),
            email_dispatch_timeout: Duration::from_secs(5),
            async_email_dispatch: true,
        };
        let opts = DbPoolOptions::from(&cfg);
        assert_eq!(opts.max_connections, 50);
        assert_eq!(opts.min_connections, 10);
    }

    #[tokio::test]
    async fn test_init_pool_with_options_zero_max_connections() {
        let options = DbPoolOptions {
            max_connections: 0,
            ..Default::default()
        };
        let err = init_pool_with_options("postgres://localhost/test", options)
            .await
            .unwrap_err();
        match err {
            AppError::Config(ConfigError::InvalidValue { field, reason }) => {
                assert_eq!(field, "max_connections");
                assert_eq!(reason, "must be greater than 0");
            }
            other => panic!("expected ConfigError::InvalidValue, got {:?}", other),
        }
    }
}
