use std::sync::Arc;

use axum::Router;
use tower_http::trace::TraceLayer;

use crate::{error::AppError, state::AppState};

pub mod auth;
pub mod cors;
pub mod session;

pub use auth::routes as auth_routes;
pub use cors::cors_layer;
pub use session::routes as session_routes;

async fn fallback_not_found() -> AppError {
    AppError::NotFound
}

pub fn create_router(state: AppState) -> Result<Router, AppError> {
    // `AppState` fields are public, so validate here too: no router is served from a
    // config that failed validation.
    state.config.validate().map_err(AppError::Config)?;
    let cors = cors_layer(&state.config)?;

    Ok(Router::new()
        .nest("/auth", auth::routes(Arc::clone(&state.auth_service)))
        .fallback(fallback_not_found)
        .layer(cors)
        .layer(TraceLayer::new_for_http()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, Config};
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use sqlx::PgPool;
    use tower::Service;

    fn valid_config() -> Config {
        Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec!["https://example.com".into()],
            allowed_methods: vec!["GET".into(), "POST".into()],
            allowed_headers: vec!["Authorization".into()],
            max_connections: 5,
            min_connections: 1,
            base_url: "https://example.com".into(),
            email_dispatch_timeout: std::time::Duration::from_secs(10),
            async_email_dispatch: true,
            outbox_poll_interval: std::time::Duration::from_millis(
                crate::config::DEFAULT_OUTBOX_POLL_INTERVAL_MS,
            ),
            outbox_batch_size: crate::config::DEFAULT_OUTBOX_BATCH_SIZE,
            outbox_max_retries: crate::config::DEFAULT_OUTBOX_MAX_RETRIES,
            outbox_initial_backoff: std::time::Duration::from_secs(
                crate::config::DEFAULT_OUTBOX_INITIAL_BACKOFF_SECS,
            ),
            outbox_max_backoff: std::time::Duration::from_secs(
                crate::config::DEFAULT_OUTBOX_MAX_BACKOFF_SECS,
            ),
            outbox_sent_retention: std::time::Duration::from_secs(
                crate::config::DEFAULT_OUTBOX_SENT_RETENTION_SECS,
            ),
            session: crate::config::SessionConfig::default(),
            rate_limit: crate::config::RateLimitConfig::default(),
        }
    }

    #[tokio::test]
    async fn test_create_router_construction() {
        let cfg = valid_config();

        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let state =
            AppState::with_configs_and_dispatcher(pool, cfg, Arc::new(AppConfig::default()), None)
                .unwrap();
        let _router: Router = create_router(state).unwrap();
    }

    #[tokio::test]
    async fn test_router_fallback_returns_not_found_envelope() {
        let cfg = Config {
            allowed_origins: vec![],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Authorization".into()],
            ..valid_config()
        };

        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let state =
            AppState::with_configs_and_dispatcher(pool, cfg, Arc::new(AppConfig::default()), None)
                .unwrap();
        let mut router = create_router(state).unwrap();

        let req = Request::builder()
            .uri("/nonexistent-endpoint")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let resp = router.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
