use std::str::FromStr;
use axum::http::{
    header::{HeaderName, HeaderValue},
    Method,
};
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};

use crate::config::Config;

/// Construct a `CorsLayer` from the application configuration.
///
/// If `cfg.allowed_origins` is empty, cross-origin requests are denied by default
/// using `AllowOrigin::list([])`. Credentials (`allow_credentials(true)`) are enabled
/// for cookie session support.
pub fn cors_layer(cfg: &Config) -> CorsLayer {
    let origins: Vec<HeaderValue> = cfg
        .allowed_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();

    let allow_origin = if origins.is_empty() {
        AllowOrigin::list([])
    } else {
        AllowOrigin::list(origins)
    };

    let methods: Vec<Method> = cfg
        .allowed_methods
        .iter()
        .filter_map(|m| Method::from_str(m).ok())
        .collect();

    let headers: Vec<HeaderName> = cfg
        .allowed_headers
        .iter()
        .filter_map(|h| HeaderName::from_str(h).ok())
        .collect();

    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods(AllowMethods::list(methods))
        .allow_headers(AllowHeaders::list(headers))
        .allow_credentials(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::Service;

    #[tokio::test]
    async fn test_cors_layer_empty_origins_denies_all() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec![],
            allowed_methods: vec!["GET".into(), "POST".into()],
            allowed_headers: vec!["Authorization".into(), "Content-Type".into()],
            max_connections: 5,
            min_connections: 1,
        };

        let mut app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(cors_layer(&cfg));

        let req = Request::builder()
            .uri("/test")
            .method(Method::GET)
            .header(header::ORIGIN, "https://evil.com")
            .body(Body::empty())
            .unwrap();

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    }

    #[tokio::test]
    async fn test_cors_layer_allowed_origin_and_credentials() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec!["https://app.example.com".into()],
            allowed_methods: vec!["GET".into(), "POST".into()],
            allowed_headers: vec!["Authorization".into(), "Content-Type".into()],
            max_connections: 5,
            min_connections: 1,
        };

        let mut app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(cors_layer(&cfg));

        let req = Request::builder()
            .uri("/test")
            .method(Method::GET)
            .header(header::ORIGIN, "https://app.example.com")
            .body(Body::empty())
            .unwrap();

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://app.example.com"
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .unwrap(),
            "true"
        );
    }

    #[tokio::test]
    async fn test_cors_layer_preflight() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec!["https://app.example.com".into()],
            allowed_methods: vec!["GET".into(), "POST".into()],
            allowed_headers: vec!["Authorization".into(), "Content-Type".into()],
            max_connections: 5,
            min_connections: 1,
        };

        let mut app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(cors_layer(&cfg));

        let req = Request::builder()
            .uri("/test")
            .method(Method::OPTIONS)
            .header(header::ORIGIN, "https://app.example.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
            .body(Body::empty())
            .unwrap();

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://app.example.com"
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .unwrap(),
            "true"
        );
    }
}
