use axum::Router;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

pub mod cors;

pub use cors::cors_layer;

pub fn create_router(state: AppState) -> Result<Router, Box<dyn std::error::Error>> {
    let cors = cors_layer(&state.config)?;

    Ok(Router::new()
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use sqlx::PgPool;

    #[tokio::test]
    async fn test_create_router_construction() {
        // AppState with dummy pool (non-connected)
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
}
