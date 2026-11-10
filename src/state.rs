use std::sync::Arc;

use sqlx::PgPool;

use crate::config::Config;
use crate::email::dispatcher::EmailDispatcher;

#[derive(Clone, Debug)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Config,
    pub email_dispatcher: Option<Arc<EmailDispatcher>>,
}

impl AppState {
    pub fn new(pool: PgPool, config: Config) -> Self {
        Self {
            pool,
            config,
            email_dispatcher: None,
        }
    }

    pub fn with_email_dispatcher(
        pool: PgPool,
        config: Config,
        email_dispatcher: Option<Arc<EmailDispatcher>>,
    ) -> Self {
        Self {
            pool,
            config,
            email_dispatcher,
        }
    }

    pub fn db(&self) -> &PgPool {
        &self.pool
    }
}
