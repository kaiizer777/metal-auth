use std::sync::Arc;

use sqlx::PgPool;

use crate::{
    auth::service::AuthServiceImpl,
    config::{AppConfig, Config},
    email::{EmailDispatcher, NoopEmailSender},
};

#[derive(Clone, Debug)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Config,
    pub auth_service: Arc<AuthServiceImpl>,
}

impl AppState {
    pub fn new(pool: PgPool, config: Config) -> Self {
        let auth_service = Arc::new(
            AuthServiceImpl::new(
                pool.clone(),
                Arc::new(AppConfig::default()),
                Arc::new(EmailDispatcher::new(NoopEmailSender)),
            )
            .expect("default auth service initialization must succeed with default config"),
        );

        Self {
            pool,
            config,
            auth_service,
        }
    }

    pub fn with_auth_service(mut self, service: Arc<AuthServiceImpl>) -> Self {
        self.auth_service = service;
        self
    }

    pub fn db(&self) -> &PgPool {
        &self.pool
    }
}
