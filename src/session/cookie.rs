//! Session and CSRF cookie builders and parsers.

use axum::http::{HeaderMap, HeaderValue};
use crate::config::{Config, SessionConfig};

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
        format!("Max-Age={}", sc.absolute_lifetime_secs()),
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
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim() == cookie_name {
                let value = v.trim().to_string();
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }
    None
}
