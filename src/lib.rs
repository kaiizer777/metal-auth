//! # metal-auth
//!
//! A composable, modular authentication library for Rust.

pub mod config;
pub mod db;
pub mod error;
pub mod handler;
pub mod state;

pub mod crypto;
pub mod email;
pub mod oauth;
pub mod session;

pub use config::Config;
pub use db::models::*;
pub use error::AppError;
pub use state::AppState;

#[derive(Clone)]
pub struct Auth {
    pub router: axum::Router,
}

impl Auth {
    pub async fn new(cfg: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let pool = db::init_pool(&cfg).await?;
        let state = AppState {
            pool,
            config: cfg,
        };
        let router = handler::create_router(state);
        Ok(Self { router })
    }

    pub fn from_state(state: AppState) -> Self {
        let router = handler::create_router(state);
        Self { router }
    }
}
