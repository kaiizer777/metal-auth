use std::sync::Arc;

use sqlx::{PgPool, postgres::PgConnectOptions};

use crate::{
    auth::service::AuthServiceImpl,
    config::{AppConfig, Config, DatabaseBackend},
    db::DatabaseStore,
    email::{dispatcher::EmailDispatcher, hook::SharedEmailSender},
    error::{AppError, ConfigError},
    oauth::OAuthService,
    ratelimit::RateLimiter,
    session::SessionService,
    totp::service::TotpService,
};

/// Constructs an [`EmailDispatcher`] from application config and optional email sender.
pub fn create_email_dispatcher(
    config: &Config,
    sender: Option<SharedEmailSender>,
) -> Arc<EmailDispatcher> {
    Arc::new(
        EmailDispatcher::new(sender, config.email_dispatch_timeout)
            .with_base_url(&config.base_url)
            .with_outbox_config(config),
    )
}

/// Constructs a default [`EmailDispatcher`] with no sender from application config.
pub fn default_email_dispatcher(config: &Config) -> Arc<EmailDispatcher> {
    create_email_dispatcher(config, None)
}

/// Lazy pool standing in for backends whose services are still pool-typed.
///
/// Opens no connections; #119 removes it with the store-backed retype.
pub(crate) fn placeholder_pool() -> PgPool {
    PgPool::connect_lazy_with(PgConnectOptions::new())
}

#[derive(Clone, Debug)]
pub struct AppState {
    pub pool: PgPool,
    pub store: Arc<dyn DatabaseStore>,
    pub config: Config,
    pub auth_config: Arc<AppConfig>,
    pub auth_service: Arc<AuthServiceImpl>,
    pub email_dispatcher: Option<Arc<EmailDispatcher>>,
    pub session_service: Arc<SessionService>,
    pub rate_limiter: Arc<RateLimiter>,
    pub oauth_service: Arc<OAuthService>,
    pub totp_service: Arc<TotpService>,
}

impl AppState {
    #[cfg(feature = "postgres")]
    pub fn new(pool: PgPool, config: Config) -> Result<Self, AppError> {
        let auth_config = Arc::new(AppConfig::from_env()?);
        let store: Arc<dyn DatabaseStore> =
            Arc::new(crate::db::postgres::PostgresStore::new(pool.clone()));
        Self::with_configs_dispatcher_and_store(pool, config, auth_config, None, store)
    }

    pub fn new_with_store(store: Arc<dyn DatabaseStore>, config: Config) -> Result<Self, AppError> {
        let auth_config = Arc::new(AppConfig::from_env()?);
        // The injected store selects the backend. Only Postgres builds a pool
        // from the URL; other backends get a lazy placeholder that never
        // connects (pool-typed services are #119's scope).
        let pool = match config.backend {
            DatabaseBackend::Postgres => {
                PgPool::connect_lazy(&config.database_url).map_err(AppError::from)?
            }
            DatabaseBackend::Mysql | DatabaseBackend::Mongodb => placeholder_pool(),
        };
        Self::with_configs_dispatcher_and_store(pool, config, auth_config, None, store)
    }

    pub fn with_auth_config(mut self, auth_config: Arc<AppConfig>) -> Result<Self, AppError> {
        let dispatcher = self
            .email_dispatcher
            .clone()
            .unwrap_or_else(|| default_email_dispatcher(&self.config));
        self.auth_service = Arc::new(AuthServiceImpl::new(
            self.pool.clone(),
            Arc::clone(&auth_config),
            dispatcher,
        )?);
        self.auth_config = auth_config;
        Ok(self)
    }

    pub fn with_auth_service(mut self, service: Arc<AuthServiceImpl>) -> Self {
        self.auth_config = Arc::clone(&service.config);
        self.auth_service = service;
        self
    }

    pub fn with_oauth_service(mut self, service: Arc<OAuthService>) -> Self {
        self.oauth_service = service;
        self
    }

    /// Builds an [`AppState`] from config, connecting what the configured backend needs.
    ///
    /// Postgres reuses the pool-typed constructor; other backends pair the backend's
    /// real store with a lazy placeholder pool (pool-typed services are #119's scope;
    /// nothing here connects). `Config::validate` already rejects a backend whose
    /// Cargo feature is off, so the trailing arm is unreachable defense-in-depth.
    pub async fn with_dispatcher_for_backend(
        config: Config,
        auth_config: Arc<AppConfig>,
        email_dispatcher: Arc<EmailDispatcher>,
    ) -> Result<Self, AppError> {
        config.validate().map_err(AppError::Config)?;
        match config.backend {
            #[cfg(feature = "postgres")]
            DatabaseBackend::Postgres => {
                let pool = crate::db::init_pool(&config).await?;
                Self::with_dispatcher(pool, config, auth_config, email_dispatcher)
            }
            #[cfg(feature = "mysql")]
            DatabaseBackend::Mysql => {
                let pool = crate::db::init_mysql_pool(&config).await?;
                let store: Arc<dyn DatabaseStore> = Arc::new(crate::db::MySqlStore::new(pool));
                Self::with_configs_dispatcher_and_store(
                    placeholder_pool(),
                    config,
                    auth_config,
                    Some(email_dispatcher),
                    store,
                )
            }
            #[cfg(feature = "mongodb")]
            DatabaseBackend::Mongodb => {
                let store: Arc<dyn DatabaseStore> =
                    Arc::new(crate::db::mongo::init_mongo_store(&config).await?);
                Self::with_configs_dispatcher_and_store(
                    placeholder_pool(),
                    config,
                    auth_config,
                    Some(email_dispatcher),
                    store,
                )
            }
            #[allow(unreachable_patterns)]
            _ => Err(AppError::Config(ConfigError::InvalidValue {
                field: "database_url",
                reason: "backend requested but its Cargo feature is not enabled",
            })),
        }
    }

    #[cfg(feature = "postgres")]
    pub fn with_dispatcher(
        pool: PgPool,
        config: Config,
        auth_config: Arc<AppConfig>,
        email_dispatcher: Arc<EmailDispatcher>,
    ) -> Result<Self, AppError> {
        Self::with_configs_and_dispatcher(pool, config, auth_config, Some(email_dispatcher))
    }

    #[cfg(feature = "postgres")]
    pub fn with_configs_and_dispatcher(
        pool: PgPool,
        config: Config,
        auth_config: Arc<AppConfig>,
        email_dispatcher: Option<Arc<EmailDispatcher>>,
    ) -> Result<Self, AppError> {
        let store: Arc<dyn DatabaseStore> =
            Arc::new(crate::db::postgres::PostgresStore::new(pool.clone()));
        Self::with_configs_dispatcher_and_store(pool, config, auth_config, email_dispatcher, store)
    }

    pub fn with_configs_dispatcher_and_store(
        pool: PgPool,
        config: Config,
        auth_config: Arc<AppConfig>,
        email_dispatcher: Option<Arc<EmailDispatcher>>,
        store: Arc<dyn DatabaseStore>,
    ) -> Result<Self, AppError> {
        // Single construction choke point for every `AppState` constructor: a router can
        // never be built from a config the dispatcher mode or CORS rules reject.
        if store.backend() != config.backend {
            return Err(AppError::Config(ConfigError::InvalidValue {
                field: "backend",
                reason: "injected store backend does not match configured database backend",
            }));
        }
        config.validate().map_err(AppError::Config)?;

        let dispatcher = email_dispatcher
            .clone()
            .unwrap_or_else(|| default_email_dispatcher(&config));

        let auth_service = Arc::new(AuthServiceImpl::new(
            pool.clone(),
            Arc::clone(&auth_config),
            dispatcher,
        )?);

        let shared_config = Arc::new(config.clone());
        let totp_service = Arc::new(TotpService::new(
            pool.clone(),
            Arc::clone(&shared_config),
            Arc::clone(&auth_config),
        ));
        let session_service = Arc::new(SessionService::new(
            pool.clone(),
            Arc::clone(&shared_config),
        ));
        let oauth_service = Arc::new(OAuthService::new(
            pool.clone(),
            shared_config,
            Arc::clone(&session_service),
            Arc::clone(&totp_service),
        )?);
        let rate_limiter = Arc::new(RateLimiter::with_config(config.rate_limit.clone()));
        if config.rate_limit.enabled {
            match tokio::runtime::Handle::try_current() {
                Ok(_) => {
                    Arc::clone(&rate_limiter).start_cleanup_task(config.rate_limit.window());
                }
                Err(_) => {
                    tracing::warn!(
                        event = "rate_limiter_cleanup_skipped",
                        reason = "no_tokio_runtime",
                    );
                }
            }
        }

        Ok(Self {
            pool,
            store,
            config,
            auth_config,
            auth_service,
            email_dispatcher,
            session_service,
            rate_limiter,
            oauth_service,
            totp_service,
        })
    }

    #[cfg(feature = "postgres")]
    pub fn with_email_dispatcher(
        pool: PgPool,
        config: Config,
        email_dispatcher: Option<Arc<EmailDispatcher>>,
    ) -> Result<Self, AppError> {
        let auth_config = Arc::new(AppConfig::from_env()?);
        Self::with_configs_and_dispatcher(pool, config, auth_config, email_dispatcher)
    }

    pub fn db(&self) -> &PgPool {
        &self.pool
    }

    pub fn store(&self) -> &Arc<dyn DatabaseStore> {
        &self.store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn valid_config() -> Config {
        Config {
            database_url: "postgres://localhost/test".into(),
            backend: crate::config::DatabaseBackend::Postgres,
            mongo: None,
            port: 3000,
            allowed_origins: vec![],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_connections: 5,
            min_connections: 1,
            base_url: "https://example.com".into(),
            email_dispatch_timeout: Duration::from_secs(10),
            async_email_dispatch: true,
            outbox_poll_interval: Duration::from_millis(
                crate::config::DEFAULT_OUTBOX_POLL_INTERVAL_MS,
            ),
            outbox_batch_size: crate::config::DEFAULT_OUTBOX_BATCH_SIZE,
            outbox_max_retries: crate::config::DEFAULT_OUTBOX_MAX_RETRIES,
            outbox_initial_backoff: Duration::from_secs(
                crate::config::DEFAULT_OUTBOX_INITIAL_BACKOFF_SECS,
            ),
            outbox_max_backoff: Duration::from_secs(crate::config::DEFAULT_OUTBOX_MAX_BACKOFF_SECS),
            outbox_sent_retention: Duration::from_secs(
                crate::config::DEFAULT_OUTBOX_SENT_RETENTION_SECS,
            ),
            session: crate::config::SessionConfig::default(),
            rate_limit: crate::config::RateLimitConfig::default(),
            oauth: crate::config::OAuthConfig::default(),
            totp: crate::config::TotpConfig::default(),
        }
    }

    #[test]
    fn create_email_dispatcher_propagates_base_url() {
        let config = valid_config();
        let dispatcher = create_email_dispatcher(&config, None);
        assert_eq!(dispatcher.base_url(), Some("https://example.com"));
    }

    #[tokio::test]
    async fn default_email_dispatcher_has_no_sender() {
        let config = valid_config();
        let dispatcher = default_email_dispatcher(&config);
        // A dispatcher with no sender returns None on dispatch (warns, never panics).
        let payload = crate::email::VerificationEmailPayload {
            user_id: uuid::Uuid::new_v4(),
            to: "user@example.com".into(),
            token: "tok".into(),
            url: "https://example.com/auth/verify/email?token=tok".into(),
            expires_at: chrono::Utc::now(),
        };
        let handle = dispatcher.dispatch_verification(payload).await;
        assert!(handle.is_none(), "no sender → dispatch returns None");
    }

    #[tokio::test]
    async fn with_configs_and_dispatcher_rejects_invalid_config() {
        let bad_config = Config {
            database_url: "".into(), // fails validate()
            ..valid_config()
        };
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let auth_config = Arc::new(AppConfig::default());
        let result = AppState::with_configs_and_dispatcher(pool, bad_config, auth_config, None);
        assert!(
            matches!(result, Err(AppError::Config(_))),
            "invalid config must be rejected"
        );
    }

    #[tokio::test]
    async fn app_state_initializes_session_service_and_rate_limiter() {
        let config = valid_config();
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let auth_config = Arc::new(AppConfig::default());
        let state = AppState::with_configs_and_dispatcher(pool, config, auth_config, None)
            .expect("valid AppState initialization");

        // Verify session_service is constructed and wired
        let _ = state.session_service.clone();

        // Verify rate_limiter is constructed and can evaluate rate limits
        assert!(
            state
                .rate_limiter
                .allow("test_key", 10, Duration::from_secs(60))
        );
    }

    #[tokio::test]
    async fn app_state_initialization_does_not_panic_outside_tokio_runtime() {
        let config = valid_config();
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let auth_config = Arc::new(AppConfig::default());
        let handle = std::thread::spawn(move || {
            AppState::with_configs_and_dispatcher(pool, config, auth_config, None)
        });
        let state = handle
            .join()
            .expect("thread must not panic")
            .expect("valid AppState initialization");
        assert!(
            state
                .rate_limiter
                .allow("sync_key", 5, Duration::from_secs(60))
        );
    }
}
