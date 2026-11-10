use std::sync::Arc;

use axum::Router;

use crate::{
    config::{AppConfig, Config},
    db,
    email::{dispatcher::EmailDispatcher, hook::SharedEmailSender},
    error::AppError,
    handler,
    state::AppState,
};

pub mod models;
pub mod service;

pub use crate::handler::auth_routes;
pub use models::*;
pub use service::{AuthService, AuthServiceImpl};

/// Main authentication facade providing the configured HTTP [`Router`].
#[derive(Clone)]
pub struct Auth {
    pub router: Router,
}

impl Auth {
    /// Initializes an `Auth` instance with the given configuration and a default `EmailDispatcher`.
    pub async fn new(cfg: Config) -> Result<Self, AppError> {
        Self::with_optional_email_sender(cfg, None).await
    }

    /// Initializes an `Auth` instance with the given configuration and a configured [`SharedEmailSender`].
    pub async fn with_email_sender(
        cfg: Config,
        sender: SharedEmailSender,
    ) -> Result<Self, AppError> {
        Self::with_optional_email_sender(cfg, Some(sender)).await
    }

    /// Initializes an `Auth` instance with an optional [`SharedEmailSender`].
    pub async fn with_optional_email_sender(
        cfg: Config,
        sender: Option<SharedEmailSender>,
    ) -> Result<Self, AppError> {
        cfg.validate()?;
        let pool = db::init_pool(&cfg).await?;
        let dispatcher = Arc::new(
            EmailDispatcher::new(sender, cfg.email_dispatch_timeout, cfg.async_email_dispatch)
                .with_base_url(&cfg.base_url),
        );
        let auth_service = Arc::new(AuthServiceImpl::new(
            pool.clone(),
            Arc::new(AppConfig::default()),
            Arc::clone(&dispatcher),
        )?);
        let state = AppState {
            pool,
            config: cfg,
            auth_service,
            email_dispatcher: Some(dispatcher),
        };
        let router = handler::create_router(state)?;
        Ok(Self { router })
    }

    /// Constructs an `Auth` instance from an existing [`AppState`].
    pub fn from_state(state: AppState) -> Result<Self, AppError> {
        state.config.validate()?;
        let router = handler::create_router(state)?;
        Ok(Self { router })
    }
}
