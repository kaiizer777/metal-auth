use axum::Router;

use crate::{config::Config, db, error::AppError, handler, state::AppState};

#[derive(Clone)]
pub struct Auth {
    pub router: Router,
}

impl Auth {
    pub async fn new(cfg: Config) -> Result<Self, AppError> {
        cfg.validate()?;
        let pool = db::init_pool(&cfg).await?;
        let state = AppState {
            pool,
            config: cfg,
            email_dispatcher: None,
        };
        let router = handler::create_router(state)?;
        Ok(Self { router })
    }

    pub fn from_state(state: AppState) -> Result<Self, AppError> {
        state.config.validate()?;
        let router = handler::create_router(state)?;
        Ok(Self { router })
    }
}
