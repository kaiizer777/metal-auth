use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

use crate::config::Config;

pub mod models;

pub async fn init_pool(cfg: &Config) -> Result<PgPool, sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .min_connections(cfg.min_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&cfg.database_url)
        .await
        .map_err(|e| {
            tracing::error!("Failed to connect to database: {e}");
            e
        })?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(pool)
}
