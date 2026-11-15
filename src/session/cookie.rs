//! Session and CSRF cookie builders and parsers.

use crate::config::{Config, SessionConfig};
use axum::http::{HeaderMap, HeaderValue};

/// Trait abstracting access to session cookie configuration.
///
/// Implemented for both [`Config`] and [`SessionConfig`], enabling cookie helpers
/// to accept either full configuration or the session subset directly.
pub trait SessionCookieSource {
    fn cookie_name(&self) -> &str;
    fn idle_timeout_secs(&self) -> u64;
    fn absolute_lifetime_secs(&self) -> u64;
    fn cookie_path(&self) -> &str;
    fn cookie_same_site(&self) -> &str;
    fn cookie_secure(&self) -> bool;
    fn cookie_domain(&self) -> Option<&str>;
}

impl SessionCookieSource for SessionConfig {
    fn cookie_name(&self) -> &str {
        &self.cookie_name
    }
    fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }
    fn absolute_lifetime_secs(&self) -> u64 {
        self.absolute_lifetime_secs
    }
    fn cookie_path(&self) -> &str {
        &self.cookie_path
    }
    fn cookie_same_site(&self) -> &str {
        &self.cookie_same_site
    }
    fn cookie_secure(&self) -> bool {
        self.cookie_secure
    }
    fn cookie_domain(&self) -> Option<&str> {
        self.cookie_domain.as_deref()
    }
}

impl SessionCookieSource for Config {
    fn cookie_name(&self) -> &str {
        self.session.cookie_name()
    }
    fn idle_timeout_secs(&self) -> u64 {
        self.session.idle_timeout_secs()
    }
    fn absolute_lifetime_secs(&self) -> u64 {
        self.session.absolute_lifetime_secs()
    }
    fn cookie_path(&self) -> &str {
        self.session.cookie_path()
    }
    fn cookie_same_site(&self) -> &str {
        self.session.cookie_same_site()
    }
    fn cookie_secure(&self) -> bool {
        self.session.cookie_secure()
    }
    fn cookie_domain(&self) -> Option<&str> {
        self.session.cookie_domain()
    }
}

/// Helper to build a session cookie `Set-Cookie` header value.
pub fn build_session_cookie(sc: &impl SessionCookieSource, raw_id: &str) -> HeaderValue {
    let mut parts = vec![
        format!("{}={}", sc.cookie_name(), raw_id),
        format!("Max-Age={}", sc.idle_timeout_secs()),
        format!("Path={}", sc.cookie_path()),
        format!("SameSite={}", sc.cookie_same_site()),
        // HttpOnly is UNCONDITIONAL — intentionally not behind a config flag.
        // This prevents client-side scripts from accessing session tokens, mitigating XSS theft.
        "HttpOnly".to_string(),
    ];
    if sc.cookie_secure() {
        parts.push("Secure".to_string());
    }
    if let Some(domain) = sc.cookie_domain() {
        parts.push(format!("Domain={}", domain));
    }

    HeaderValue::from_str(&parts.join("; "))
        .expect("set_session_cookie: header value is always valid ASCII")
}

/// Helper to build a clear session cookie `Set-Cookie` header value.
pub fn build_clear_cookie(sc: &impl SessionCookieSource) -> HeaderValue {
    let mut parts = vec![
        format!("{}=", sc.cookie_name()),
        "Max-Age=0".to_string(),
        "Expires=Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
        format!("Path={}", sc.cookie_path()),
        format!("SameSite={}", sc.cookie_same_site()),
        // HttpOnly is unconditional on clear cookie as well to ensure parity with set cookie.
        "HttpOnly".to_string(),
    ];
    if sc.cookie_secure() {
        parts.push("Secure".to_string());
    }
    if let Some(domain) = sc.cookie_domain() {
        parts.push(format!("Domain={}", domain));
    }

    HeaderValue::from_str(&parts.join("; "))
        .expect("clear_session_cookie: header value is always valid ASCII")
}

/// Helper to build a CSRF cookie `Set-Cookie` header value.
pub fn build_csrf_cookie(sc: &impl SessionCookieSource, csrf_token: &str) -> HeaderValue {
    let mut parts = vec![
        format!("csrf_token={}", csrf_token),
        format!("Path={}", sc.cookie_path()),
        // SameSite=Strict (stricter than session cookie — CSRF token warrants tighter policy).
        "SameSite=Strict".to_string(),
        // CRITICAL INVARIANT: NO HttpOnly here. Client JavaScript on the origin MUST be able
        // to read this cookie to inject its value into the `X-CSRF-Token` header (Double Submit Cookie pattern).
    ];
    if sc.cookie_secure() {
        parts.push("Secure".to_string());
    }
    if let Some(domain) = sc.cookie_domain() {
        parts.push(format!("Domain={}", domain));
    }

    HeaderValue::from_str(&parts.join("; "))
        .expect("set_csrf_cookie: header value is always valid ASCII")
}

/// Trait to support flexible argument order for `set_session_cookie`.
pub trait SetSessionCookieArgs {
    fn into_header_value(self) -> HeaderValue;
}

impl<'a, C: SessionCookieSource> SetSessionCookieArgs for (&'a str, &'a C) {
    fn into_header_value(self) -> HeaderValue {
        build_session_cookie(self.1, self.0)
    }
}

impl<'a, C: SessionCookieSource> SetSessionCookieArgs for (&'a C, &'a str) {
    fn into_header_value(self) -> HeaderValue {
        build_session_cookie(self.0, self.1)
    }
}

/// Trait to support flexible argument order for `set_csrf_cookie`.
pub trait SetCsrfCookieArgs {
    fn into_header_value(self) -> HeaderValue;
}

impl<'a, C: SessionCookieSource> SetCsrfCookieArgs for (&'a str, &'a C) {
    fn into_header_value(self) -> HeaderValue {
        build_csrf_cookie(self.1, self.0)
    }
}

impl<'a, C: SessionCookieSource> SetCsrfCookieArgs for (&'a C, &'a str) {
    fn into_header_value(self) -> HeaderValue {
        build_csrf_cookie(self.0, self.1)
    }
}

/// Build a `Set-Cookie` header value for the session cookie.
///
/// Unconditional `HttpOnly = true`.
pub fn set_session_cookie<A, B>(a: A, b: B) -> HeaderValue
where
    (A, B): SetSessionCookieArgs,
{
    (a, b).into_header_value()
}

/// Build a `Set-Cookie` header that clears the session cookie.
pub fn clear_session_cookie(sc: &impl SessionCookieSource) -> HeaderValue {
    build_clear_cookie(sc)
}

/// Build a `Set-Cookie` header for the CSRF token.
///
/// INTENTIONALLY NOT HttpOnly so client scripts can read it for Double Submit Cookie CSRF defense.
pub fn set_csrf_cookie<A, B>(a: A, b: B) -> HeaderValue
where
    (A, B): SetCsrfCookieArgs,
{
    (a, b).into_header_value()
}

/// Extract the session cookie value from the `Cookie` header.
pub fn read_session_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=')
            && k.trim() == cookie_name
        {
            let value = v.trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::HeaderValue;

    fn test_config() -> Config {
        Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec!["https://app.example.com".into()],
            allowed_methods: vec!["GET".into(), "POST".into()],
            allowed_headers: vec!["Authorization".into(), "Content-Type".into()],
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
            session: SessionConfig::default(),
            rate_limit: crate::config::RateLimitConfig::default(),
        }
    }

    #[test]
    fn test_cookie_flags() {
        let cfg = test_config();
        let cookie = set_session_cookie("rawtoken123", &cfg);
        let s = cookie.to_str().expect("valid ascii");

        assert!(s.contains("sid=rawtoken123"));
        assert!(s.contains("HttpOnly"));
        assert!(s.contains("Secure"));
        assert!(s.contains("SameSite=Lax"));
        assert!(s.contains("Path=/"));
        assert!(s.contains(&format!("Max-Age={}", cfg.session.idle_timeout_secs)));
        assert_eq!(
            s.matches("HttpOnly").count(),
            1,
            "HttpOnly must occur exactly once"
        );

        // Test with SessionConfig directly and inverted argument order
        let sc = SessionConfig::default();
        let cookie2 = set_session_cookie(&sc, "rawtoken123");
        assert_eq!(cookie, cookie2);
    }

    #[test]
    fn test_cookie_domain_and_insecure_option() {
        let sc = SessionConfig {
            cookie_domain: Some("auth.example.com".into()),
            cookie_secure: false,
            ..Default::default()
        };
        let cookie = set_session_cookie("rawtoken123", &sc);
        let s = cookie.to_str().expect("valid ascii");

        assert!(s.contains("Domain=auth.example.com"));
        assert!(!s.contains("Secure"));
        assert!(s.contains("HttpOnly"));
    }

    #[test]
    fn test_clear_cookie() {
        let cfg = test_config();
        let cookie = clear_session_cookie(&cfg);
        let s = cookie.to_str().expect("valid ascii");

        assert!(s.contains("sid="));
        assert!(s.contains("Max-Age=0"));
        assert!(s.contains("Expires=Thu, 01 Jan 1970 00:00:00 GMT"));
        assert!(s.contains("HttpOnly"));
        assert!(s.contains("Path=/"));
    }

    #[test]
    fn test_csrf_cookie_not_httponly() {
        let cfg = test_config();
        let cookie = set_csrf_cookie("csrftoken456", &cfg);
        let s = cookie.to_str().expect("valid ascii");

        assert!(s.contains("csrf_token=csrftoken456"));
        assert!(!s.contains("HttpOnly"), "CSRF cookie must NOT be HttpOnly");
        assert!(s.contains("SameSite=Strict"));
        assert!(s.contains("Secure"));
        assert!(s.contains("Path=/"));

        // Inverted argument order support
        let cookie2 = set_csrf_cookie(&cfg.session, "csrftoken456");
        assert_eq!(cookie, cookie2);
    }

    #[test]
    fn test_read_session_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("theme=dark; sid=abc123xyz; lang=en"),
        );

        assert_eq!(
            read_session_cookie(&headers, "sid"),
            Some("abc123xyz".to_string())
        );
        assert_eq!(
            read_session_cookie(&headers, "theme"),
            Some("dark".to_string())
        );
        assert_eq!(read_session_cookie(&headers, "nonexistent"), None);
    }

    #[test]
    fn test_read_session_cookie_empty_or_missing() {
        let headers = HeaderMap::new();
        assert_eq!(read_session_cookie(&headers, "sid"), None);

        let mut headers2 = HeaderMap::new();
        headers2.insert("cookie", HeaderValue::from_static("sid=; other=val"));
        assert_eq!(read_session_cookie(&headers2, "sid"), None);
    }
}
