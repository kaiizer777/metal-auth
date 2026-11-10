use axum::Router;
use tower_http::trace::TraceLayer;

use crate::{error::AppError, state::AppState};

pub mod auth;
pub mod cors;

pub use cors::cors_layer;

async fn fallback_not_found() -> AppError {
    AppError::NotFound
}

pub fn create_router(state: AppState) -> Result<Router, AppError> {
    let cors = cors_layer(&state.config)?;

    Ok(Router::new()
        .fallback(fallback_not_found)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use sqlx::PgPool;
    use tower::Service;

    #[tokio::test]
    async fn test_create_router_construction() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec!["https://example.com".into()],
            allowed_methods: vec!["GET".into(), "POST".into()],
            allowed_headers: vec!["Authorization".into()],
            max_connections: 5,
            min_connections: 1,
        };

        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let state = AppState::new(pool, cfg);
        let _router: Router = create_router(state).unwrap();
    }

    #[tokio::test]
    async fn test_create_router_fails_on_invalid_cors() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec!["bad\norigin".into()],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Authorization".into()],
            max_connections: 5,
            min_connections: 1,
        };

        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let state = AppState::new(pool, cfg);
        assert!(create_router(state).is_err());
    }

    #[tokio::test]
    async fn test_router_fallback_returns_not_found_envelope() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec![],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Authorization".into()],
            max_connections: 5,
            min_connections: 1,
        };

        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let state = AppState::new(pool, cfg);
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
