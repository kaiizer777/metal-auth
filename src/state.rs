use std::sync::Arc;

use sqlx::PgPool;

use crate::{
    auth::service::AuthServiceImpl,
    config::{AppConfig, Config},
    email::{dispatcher::EmailDispatcher, hook::SharedEmailSender},
    error::AppError,
};

/// Constructs an [`EmailDispatcher`] from application config and optional email sender.
pub fn create_email_dispatcher(
    config: &Config,
    sender: Option<SharedEmailSender>,
) -> Arc<EmailDispatcher> {
    Arc::new(
        EmailDispatcher::new(sender, config.email_dispatch_timeout).with_base_url(&config.base_url),
    )
}

/// Constructs a default [`EmailDispatcher`] with no sender from application config.
pub fn default_email_dispatcher(config: &Config) -> Arc<EmailDispatcher> {
    create_email_dispatcher(config, None)
}

#[derive(Clone, Debug)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Config,
    pub auth_config: Arc<AppConfig>,
    pub auth_service: Arc<AuthServiceImpl>,
    pub email_dispatcher: Option<Arc<EmailDispatcher>>,
}

impl AppState {
    pub fn new(pool: PgPool, config: Config) -> Result<Self, AppError> {
        let auth_config = Arc::new(AppConfig::from_env()?);
        Self::with_configs_and_dispatcher(pool, config, auth_config, None)
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

    pub fn with_dispatcher(
        pool: PgPool,
        config: Config,
        auth_config: Arc<AppConfig>,
        email_dispatcher: Arc<EmailDispatcher>,
    ) -> Result<Self, AppError> {
        Self::with_configs_and_dispatcher(pool, config, auth_config, Some(email_dispatcher))
    }

    pub fn with_configs_and_dispatcher(
        pool: PgPool,
        config: Config,
        auth_config: Arc<AppConfig>,
        email_dispatcher: Option<Arc<EmailDispatcher>>,
    ) -> Result<Self, AppError> {
        // Single construction choke point for every `AppState` constructor: a router can
        // never be built from a config the dispatcher mode or CORS rules reject.
        config.validate().map_err(AppError::Config)?;

        let dispatcher = email_dispatcher
            .clone()
            .unwrap_or_else(|| default_email_dispatcher(&config));

        let auth_service = Arc::new(AuthServiceImpl::new(
            pool.clone(),
            Arc::clone(&auth_config),
            dispatcher,
        )?);

        Ok(Self {
            pool,
            config,
            auth_config,
            auth_service,
            email_dispatcher,
        })
    }

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn valid_config() -> Config {
        Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec![],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_connections: 5,
            min_connections: 1,
            base_url: "https://example.com".into(),
            email_dispatch_timeout: Duration::from_secs(10),
            async_email_dispatch: true,
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
            port: 3000,
            allowed_origins: vec![],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_connections: 5,
            min_connections: 1,
            base_url: "https://example.com".into(),
            email_dispatch_timeout: Duration::from_secs(10),
            async_email_dispatch: true,
        };
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let auth_config = Arc::new(AppConfig::default());
        let result = AppState::with_configs_and_dispatcher(pool, bad_config, auth_config, None);
        assert!(
            matches!(result, Err(AppError::Config(_))),
            "invalid config must be rejected"
        );
    }
}
