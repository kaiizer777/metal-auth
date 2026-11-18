//! ASVS L1 security headers middleware.

use axum::{
    body::Body,
    http::{HeaderValue, Method, Request, Response, header},
    middleware::Next,
};

/// Middleware injecting OWASP ASVS Level 1 security headers and auth route cache controls.
pub async fn security_headers_middleware(req: Request<Body>, next: Next) -> Response<Body> {
    let is_options = req.method() == Method::OPTIONS;
    let path = req.uri().path();
    let is_auth_route = path.starts_with("/auth") || path.starts_with("/session");

    let mut res = next.run(req).await;
    let headers = res.headers_mut();

    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    if !headers.contains_key(header::CONTENT_SECURITY_POLICY) {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'self'"),
        );
    }
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    if is_auth_route && !is_options {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }

    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        http::{Method, Request, StatusCode},
        middleware::from_fn,
        routing::{get, post},
    };
    use tower::ServiceExt;

    fn build_test_router() -> Router {
        Router::new()
            .route("/auth/login", post(|| async { StatusCode::OK }))
            .route(
                "/auth/login",
                axum::routing::options(|| async { StatusCode::NO_CONTENT }),
            )
            .route("/public/data", get(|| async { StatusCode::OK }))
            .layer(from_fn(security_headers_middleware))
    }

    #[tokio::test]
    async fn test_asvs_l1_headers_present_on_all_responses() {
        let app = build_test_router();
        let req = Request::builder()
            .uri("/public/data")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let h = res.headers();
        assert_eq!(
            h.get(header::STRICT_TRANSPORT_SECURITY).unwrap(),
            "max-age=63072000; includeSubDomains; preload"
        );
        assert_eq!(h.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
        assert_eq!(h.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
        assert_eq!(
            h.get(header::CONTENT_SECURITY_POLICY).unwrap(),
            "default-src 'self'"
        );
        assert_eq!(
            h.get(header::REFERRER_POLICY).unwrap(),
            "strict-origin-when-cross-origin"
        );
        assert!(h.get(header::CACHE_CONTROL).is_none());
        assert!(h.get(header::PRAGMA).is_none());
    }

    #[tokio::test]
    async fn test_cache_control_and_pragma_injected_on_non_options_auth_routes() {
        let app = build_test_router();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/auth/login")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let h = res.headers();
        assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(h.get(header::PRAGMA).unwrap(), "no-cache");
    }

    #[tokio::test]
    async fn test_options_cors_preflight_on_auth_route_skips_cache_control_no_store() {
        let app = build_test_router();
        let req = Request::builder()
            .method(Method::OPTIONS)
            .uri("/auth/login")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let h = res.headers();
        assert_eq!(
            h.get(header::STRICT_TRANSPORT_SECURITY).unwrap(),
            "max-age=63072000; includeSubDomains; preload"
        );
        assert!(h.get(header::CACHE_CONTROL).is_none());
        assert!(h.get(header::PRAGMA).is_none());
    }

    #[tokio::test]
    async fn test_preserves_custom_downstream_csp() {
        let app = Router::new()
            .route(
                "/custom-csp",
                get(|| async {
                    (
                        [(
                            header::CONTENT_SECURITY_POLICY,
                            "default-src 'none'; frame-ancestors 'none'",
                        )],
                        StatusCode::OK,
                    )
                }),
            )
            .layer(from_fn(security_headers_middleware));

        let req = Request::builder()
            .uri("/custom-csp")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get(header::CONTENT_SECURITY_POLICY).unwrap(),
            "default-src 'none'; frame-ancestors 'none'"
        );
        assert_eq!(
            res.headers().get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
    }
}
