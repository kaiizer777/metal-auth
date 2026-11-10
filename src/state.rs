use std::sync::Arc;

use sqlx::PgPool;

use crate::{
    auth::service::AuthServiceImpl,
    config::{AppConfig, Config},
    email::dispatcher::EmailDispatcher,
};

#[derive(Clone, Debug)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Config,
    pub auth_config: Arc<AppConfig>,
    pub auth_service: Arc<AuthServiceImpl>,
    pub email_dispatcher: Option<Arc<EmailDispatcher>>,
}

impl AppState {
    pub fn new(pool: PgPool, config: Config) -> Self {
        let auth_config = Arc::new(AppConfig::from_env().unwrap_or_default());
        Self::with_configs_and_dispatcher(pool, config, auth_config, None)
    }

    pub fn with_auth_config(mut self, auth_config: Arc<AppConfig>) -> Self {
        let dispatcher = self.email_dispatcher.clone().unwrap_or_else(|| {
            Arc::new(
                EmailDispatcher::new(
                    None,
                    self.config.email_dispatch_timeout,
                    self.config.async_email_dispatch,
                )
                .with_base_url(&self.config.base_url),
            )
        });
        self.auth_service = Arc::new(
            AuthServiceImpl::new(self.pool.clone(), Arc::clone(&auth_config), dispatcher)
                .expect("auth service initialization must succeed"),
        );
        self.auth_config = auth_config;
        self
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
    ) -> Self {
        let auth_service = Arc::new(
            AuthServiceImpl::new(
                pool.clone(),
                Arc::clone(&auth_config),
                Arc::clone(&email_dispatcher),
            )
            .expect("auth service initialization must succeed"),
        );

        Self {
            pool,
            config,
            auth_config,
            auth_service,
            email_dispatcher: Some(email_dispatcher),
        }
    }

    pub fn with_configs_and_dispatcher(
        pool: PgPool,
        config: Config,
        auth_config: Arc<AppConfig>,
        email_dispatcher: Option<Arc<EmailDispatcher>>,
    ) -> Self {
        let dispatcher = email_dispatcher.clone().unwrap_or_else(|| {
            Arc::new(
                EmailDispatcher::new(
                    None,
                    config.email_dispatch_timeout,
                    config.async_email_dispatch,
                )
                .with_base_url(&config.base_url),
            )
        });

        let auth_service = Arc::new(
            AuthServiceImpl::new(pool.clone(), Arc::clone(&auth_config), dispatcher)
                .expect("auth service initialization must succeed"),
        );

        Self {
            pool,
            config,
            auth_config,
            auth_service,
            email_dispatcher,
        }
    }

    pub fn with_email_dispatcher(
        pool: PgPool,
        config: Config,
        email_dispatcher: Option<Arc<EmailDispatcher>>,
    ) -> Self {
        let auth_config = Arc::new(AppConfig::from_env().unwrap_or_default());
        Self::with_configs_and_dispatcher(pool, config, auth_config, email_dispatcher)
    }

    pub fn db(&self) -> &PgPool {
        &self.pool
    }
}
