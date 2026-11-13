use std::sync::Arc;

use axum::Router;

use crate::{
    config::{AppConfig, Config},
    db,
    email::{dispatcher::EmailDispatcher, hook::SharedEmailSender},
    error::AppError,
    handler,
    state::{self, AppState},
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
        let auth_config = Arc::new(AppConfig::from_env()?);
        Self::with_config_and_sender(cfg, auth_config, sender).await
    }

    /// Initializes an `Auth` instance with explicit [`AppConfig`] and optional [`SharedEmailSender`].
    pub async fn with_config_and_sender(
        cfg: Config,
        auth_cfg: Arc<AppConfig>,
        sender: Option<SharedEmailSender>,
    ) -> Result<Self, AppError> {
        let dispatcher = state::create_email_dispatcher(&cfg, sender);
        Self::with_dispatcher(cfg, auth_cfg, dispatcher).await
    }

    /// Constructs an `Auth` instance with explicit [`AppConfig`] and [`EmailDispatcher`].
    pub async fn with_dispatcher(
        cfg: Config,
        auth_cfg: Arc<AppConfig>,
        dispatcher: Arc<EmailDispatcher>,
    ) -> Result<Self, AppError> {
        cfg.validate()?;
        let pool = db::init_pool(&cfg).await?;
        let state = AppState::with_dispatcher(pool, cfg, auth_cfg, dispatcher)?;
        Self::from_state(state)
    }

    /// Constructs an `Auth` instance from an existing [`AppState`].
    pub fn from_state(state: AppState) -> Result<Self, AppError> {
        state.config.validate()?;
        let router = handler::create_router(state)?;
        Ok(Self { router })
    }

    /// Consumes the `Auth` instance and returns the inner [`Router`].
    pub fn into_router(self) -> Router {
        self.router
    }

    /// Returns a clone of the inner [`Router`].
    pub fn router(&self) -> Router {
        self.router.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_router_accessors() {
        let router = Router::new();
        let auth = Auth { router };
        let _cloned: Router = auth.router();
        let _consumed: Router = auth.into_router();
    }
}
