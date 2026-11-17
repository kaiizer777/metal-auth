use axum::{Router, http::HeaderMap};
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

/// Best-effort client IP for audit logs and rate-limit keys only.
///
/// `X-Forwarded-For`/`X-Real-IP` are client-controlled unless an
/// upstream proxy strips them, so treat the result as untrusted: never use it
/// for auth decisions. Takes the leftmost entry (original client per convention)
/// and falls back to `None` when no header is present.
pub(crate) fn untrusted_client_ip(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim())
        .filter(|s| !s.is_empty())
}

pub fn create_router(state: AppState) -> Result<Router, AppError> {
    // `AppState` fields are public, so validate here too: no router is served from a
    // config that failed validation.
    state.config.validate().map_err(AppError::Config)?;
    let cors = cors_layer(&state.config)?;

    let auth_router =
        auth::routes_with_app_state(state.clone()).merge(session::routes(state.clone()));

    Ok(Router::new()
        .nest("/auth", auth_router)
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
    use std::sync::Arc;
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

    #[tokio::test]
    async fn test_create_router_mounts_session_routes_with_require_auth() {
        let cfg = valid_config();
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let state =
            AppState::with_configs_and_dispatcher(pool, cfg, Arc::new(AppConfig::default()), None)
                .unwrap();
        let mut router = create_router(state).unwrap();

        let req = Request::builder()
            .uri("/auth/session")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let resp = router.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn untrusted_client_ip_takes_leftmost_entry() {
        use axum::http::HeaderValue;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, 5.6.7.8"),
        );
        assert_eq!(untrusted_client_ip(&headers), Some("1.2.3.4"));

        let empty = HeaderMap::new();
        assert_eq!(untrusted_client_ip(&empty), None);

        let mut blank = HeaderMap::new();
        blank.insert("x-real-ip", HeaderValue::from_static("   "));
        assert_eq!(untrusted_client_ip(&blank), None);
    }

    #[tokio::test]
    async fn test_session_mutating_routes_require_auth() {
        let cfg = valid_config();
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let state =
            AppState::with_configs_and_dispatcher(pool, cfg, Arc::new(AppConfig::default()), None)
                .unwrap();
        let mut router = create_router(state).unwrap();

        let req = Request::builder()
            .uri("/auth/session/revoke-all")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();

        let resp = router.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
