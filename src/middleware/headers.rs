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
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'"),
    );
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
