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
    pub auth_service: Arc<AuthServiceImpl>,
    pub email_dispatcher: Option<Arc<EmailDispatcher>>,
}

impl AppState {
    pub fn new(pool: PgPool, config: Config) -> Self {
        let dispatcher = Arc::new(
            EmailDispatcher::new(
                None,
                config.email_dispatch_timeout,
                config.async_email_dispatch,
            )
            .with_base_url(&config.base_url),
        );

        let auth_service = Arc::new(
            AuthServiceImpl::new(
                pool.clone(),
                Arc::new(AppConfig::default()),
                Arc::clone(&dispatcher),
            )
            .expect("default auth service initialization must succeed with default config"),
        );

        Self {
            pool,
            config,
            auth_service,
            email_dispatcher: Some(dispatcher),
        }
    }

    pub fn with_auth_service(mut self, service: Arc<AuthServiceImpl>) -> Self {
        self.auth_service = service;
        self
    }

    pub fn with_email_dispatcher(
        pool: PgPool,
        config: Config,
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
            AuthServiceImpl::new(pool.clone(), Arc::new(AppConfig::default()), dispatcher)
                .expect("default auth service initialization must succeed with default config"),
        );

        Self {
            pool,
            config,
            auth_service,
            email_dispatcher,
        }
    }

    pub fn db(&self) -> &PgPool {
        &self.pool
    }
}
