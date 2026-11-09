use sqlx::PgPool;

use crate::config::Config;

#[derive(Clone, Debug)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Config,
}

impl AppState {
    pub fn new(pool: PgPool, config: Config) -> Self {
        Self { pool, config }
    }

    pub fn db(&self) -> &PgPool {
        &self.pool
    }
}
