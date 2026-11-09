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
///
/// Returns an error if any origin, method, or header in `cfg` cannot be parsed.
pub fn cors_layer(cfg: &Config) -> Result<CorsLayer, Box<dyn std::error::Error>> {
    let mut origins = Vec::with_capacity(cfg.allowed_origins.len());
    for raw in &cfg.allowed_origins {
        let trimmed = raw.trim();
        if trimmed == "*" {
            continue;
        }
        let val = HeaderValue::from_str(trimmed)
            .map_err(|e| format!("invalid CORS origin '{raw}': {e}"))?;
        origins.push(val);
    }

    let allow_origin = if origins.is_empty() {
        AllowOrigin::list([])
    } else {
        AllowOrigin::list(origins)
    };

    let mut methods = Vec::with_capacity(cfg.allowed_methods.len());
    for raw in &cfg.allowed_methods {
        let method = Method::from_str(raw.trim())
            .map_err(|e| format!("invalid CORS method '{raw}': {e}"))?;
        methods.push(method);
    }

    let mut headers = Vec::with_capacity(cfg.allowed_headers.len());
    for raw in &cfg.allowed_headers {
        let header = HeaderName::from_str(raw.trim())
            .map_err(|e| format!("invalid CORS header '{raw}': {e}"))?;
        headers.push(header);
    }

    Ok(CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods(AllowMethods::list(methods))
        .allow_headers(AllowHeaders::list(headers))
        .allow_credentials(true))
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
            .layer(cors_layer(&cfg).unwrap());

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
            .layer(cors_layer(&cfg).unwrap());

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
            .layer(cors_layer(&cfg).unwrap());

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

    #[tokio::test]
    async fn test_cors_layer_wildcard_origin_filtered_out() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec!["*".into(), " * ".into()],
            allowed_methods: vec!["GET".into(), "POST".into()],
            allowed_headers: vec!["Authorization".into(), "Content-Type".into()],
            max_connections: 5,
            min_connections: 1,
        };

        let mut app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(cors_layer(&cfg).unwrap());

        let req = Request::builder()
            .uri("/test")
            .method(Method::GET)
            .header(header::ORIGIN, "https://anywhere.com")
            .body(Body::empty())
            .unwrap();

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    }

    #[test]
    fn test_cors_layer_rejects_malformed_origin() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec!["invalid\norigin".into()],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_connections: 5,
            min_connections: 1,
        };

        let err = cors_layer(&cfg).unwrap_err();
        assert!(err.to_string().contains("invalid CORS origin"));
    }

    #[test]
    fn test_cors_layer_rejects_malformed_method() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec!["https://app.example.com".into()],
            allowed_methods: vec!["INVALID METHOD WITH SPACES".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_connections: 5,
            min_connections: 1,
        };

        let err = cors_layer(&cfg).unwrap_err();
        assert!(err.to_string().contains("invalid CORS method"));
    }

    #[test]
    fn test_cors_layer_rejects_malformed_header() {
        let cfg = Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec!["https://app.example.com".into()],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["Invalid Header With Spaces".into()],
            max_connections: 5,
            min_connections: 1,
        };

        let err = cors_layer(&cfg).unwrap_err();
        assert!(err.to_string().contains("invalid CORS header"));
    }
}
