//! Session and CSRF cookie builders and parsers.

use crate::{
    config::{Config, SessionConfig},
    error::AppError,
};
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

/// Tokens placed in cookies are hex by construction; anything else is a bug.
/// Values must be RFC 6265 `cookie-octet` (`%x21 / %x23-2B / %x2D-3A /
/// %x3C-5B / %x5D-7E`): graphic ASCII minus `"`, `,`, `;`, `\`, which would
/// split or re-quote the `Set-Cookie` value.
fn valid_token_chars(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| matches!(b, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E))
}

/// Cookie names follow RFC 6265 `token`: letters, digits, and
/// `!#$%&'*+-.^_`|~` only. `Config::validate` enforces this too; builders
/// re-check defensively so an unvalidated `SessionConfig` can never produce
/// a splittable `Set-Cookie`.
fn valid_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Build a session cookie `Set-Cookie` header value, failing closed on invalid content.
///
/// A `HeaderValue` encoding failure (non-ASCII/control bytes in the token or cookie
/// name) is a server-side bug — hex tokens must always encode — so callers surface
/// `AppError::Internal` (500) instead of emitting an empty `Set-Cookie`.
///
/// # Errors
///
/// Returns `AppError::Internal` when the cookie name or token contains characters
/// that cannot appear in a `Set-Cookie` value.
pub fn build_session_cookie(
    sc: &impl SessionCookieSource,
    raw_id: &str,
) -> Result<HeaderValue, AppError> {
    if !valid_cookie_name(sc.cookie_name()) || !valid_token_chars(raw_id) {
        tracing::error!(event = "cookie_build_failed", kind = "session");
        return Err(AppError::Internal);
    }
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

    HeaderValue::from_str(&parts.join("; ")).map_err(|_| {
        tracing::error!(event = "cookie_build_failed", kind = "session");
        AppError::Internal
    })
}

/// Build a clear-session cookie `Set-Cookie` header value, failing closed on invalid content.
///
/// # Errors
///
/// Returns `AppError::Internal` when the cookie name cannot appear in a `Set-Cookie` value.
pub fn build_clear_cookie(sc: &impl SessionCookieSource) -> Result<HeaderValue, AppError> {
    if !valid_cookie_name(sc.cookie_name()) {
        tracing::error!(event = "cookie_build_failed", kind = "clear");
        return Err(AppError::Internal);
    }
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

    HeaderValue::from_str(&parts.join("; ")).map_err(|_| {
        tracing::error!(event = "cookie_build_failed", kind = "clear");
        AppError::Internal
    })
}

/// Build a CSRF cookie `Set-Cookie` header value, failing closed on invalid content.
///
/// # Errors
///
/// Returns `AppError::Internal` when the token contains characters that cannot
/// appear in a `Set-Cookie` value.
pub fn build_csrf_cookie(
    sc: &impl SessionCookieSource,
    csrf_token: &str,
) -> Result<HeaderValue, AppError> {
    if !valid_token_chars(csrf_token) {
        tracing::error!(event = "cookie_build_failed", kind = "csrf");
        return Err(AppError::Internal);
    }
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

    HeaderValue::from_str(&parts.join("; ")).map_err(|_| {
        tracing::error!(event = "cookie_build_failed", kind = "csrf");
        AppError::Internal
    })
}

/// Build a `Set-Cookie` header value for the session cookie.
///
/// Unconditional `HttpOnly = true`.
///
/// # Errors
///
/// Returns `AppError::Internal` when the cookie name or token cannot be encoded.
pub fn set_session_cookie(
    sc: &impl SessionCookieSource,
    raw_id: &str,
) -> Result<HeaderValue, AppError> {
    build_session_cookie(sc, raw_id)
}

/// Build a `Set-Cookie` header that clears the session cookie.
///
/// # Errors
///
/// Returns `AppError::Internal` when the cookie name cannot be encoded.
pub fn clear_session_cookie(sc: &impl SessionCookieSource) -> Result<HeaderValue, AppError> {
    build_clear_cookie(sc)
}

/// Build a `Set-Cookie` header for the CSRF token.
///
/// INTENTIONALLY NOT HttpOnly so client scripts can read it for Double Submit Cookie CSRF defense.
///
/// # Errors
///
/// Returns `AppError::Internal` when the token cannot be encoded.
pub fn set_csrf_cookie(
    sc: &impl SessionCookieSource,
    csrf_token: &str,
) -> Result<HeaderValue, AppError> {
    build_csrf_cookie(sc, csrf_token)
}

/// Build a clear-CSRF cookie `Set-Cookie` header value, expiring the `csrf_token` cookie.
///
/// # Security Invariant
/// Clearing the CSRF cookie must strictly be associated with valid authenticated session
/// invalidation (e.g. successful logout where credentials were verified). Handlers must never
/// emit clear-cookie headers on unauthenticated or rejected requests.
///
/// # Errors
///
/// Returns `AppError::Internal` when the header value cannot be encoded.
pub fn build_clear_csrf_cookie(sc: &impl SessionCookieSource) -> Result<HeaderValue, AppError> {
    let mut parts = vec![
        "csrf_token=".to_string(),
        "Max-Age=0".to_string(),
        "Expires=Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
        format!("Path={}", sc.cookie_path()),
        "SameSite=Strict".to_string(),
    ];
    if sc.cookie_secure() {
        parts.push("Secure".to_string());
    }
    if let Some(domain) = sc.cookie_domain() {
        parts.push(format!("Domain={}", domain));
    }

    HeaderValue::from_str(&parts.join("; ")).map_err(|_| {
        tracing::error!(event = "cookie_build_failed", kind = "clear_csrf");
        AppError::Internal
    })
}

/// Build a `Set-Cookie` header that clears the CSRF token cookie.
///
/// See [`build_clear_csrf_cookie`] for security invariants regarding authenticated logout.
///
/// # Errors
///
/// Returns `AppError::Internal` when the header value cannot be encoded.
pub fn clear_csrf_cookie(sc: &impl SessionCookieSource) -> Result<HeaderValue, AppError> {
    build_clear_csrf_cookie(sc)
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
            oauth: crate::config::OAuthConfig::default(),
        }
    }

    #[test]
    fn test_cookie_flags() {
        let cfg = test_config();
        let cookie = set_session_cookie(&cfg, "rawtoken123").expect("hex token encodes");
        let s = cookie.to_str().expect("valid ascii");

        assert!(s.contains("sid=rawtoken123"));
        assert!(s.contains("HttpOnly"));
        assert!(s.contains("Secure"));
        assert!(s.contains("SameSite=Lax"));
        assert!(s.contains("Path=/"));
        assert!(s.contains(&format!("Max-Age={}", cfg.session.absolute_lifetime_secs)));
        assert_eq!(
            s.matches("HttpOnly").count(),
            1,
            "HttpOnly must occur exactly once"
        );

        // SessionConfig subset builds the identical value
        let cookie2 = set_session_cookie(&cfg.session, "rawtoken123").expect("hex token encodes");
        assert_eq!(cookie, cookie2);
    }

    #[test]
    fn test_cookie_domain_and_insecure_option() {
        let sc = SessionConfig {
            cookie_domain: Some("auth.example.com".into()),
            cookie_secure: false,
            ..Default::default()
        };
        let cookie = set_session_cookie(&sc, "rawtoken123").expect("hex token encodes");
        let s = cookie.to_str().expect("valid ascii");

        assert!(s.contains("Domain=auth.example.com"));
        assert!(!s.contains("Secure"));
        assert!(s.contains("HttpOnly"));
    }

    #[test]
    fn rejects_token_with_crlf() {
        let cfg = test_config();
        assert!(set_session_cookie(&cfg, "abc\r\nSet-Cookie: x=y").is_err());
        assert!(set_csrf_cookie(&cfg, "tok\nen").is_err());
        assert!(build_session_cookie(&cfg, "non-ascii-tökën").is_err());
    }

    #[test]
    fn rejects_cookie_name_with_separator() {
        let sc = SessionConfig {
            cookie_name: "bad;name".into(),
            ..Default::default()
        };
        assert!(set_session_cookie(&sc, "rawtoken123").is_err());
        assert!(clear_session_cookie(&sc).is_err());
    }

    #[test]
    fn rejects_token_with_semicolon() {
        let cfg = test_config();
        assert!(set_session_cookie(&cfg, "abc;HttpOnly").is_err());
        assert!(set_csrf_cookie(&cfg, "tok;en").is_err());
    }

    #[test]
    fn rejects_non_cookie_octet_delimiters() {
        let cfg = test_config();
        for token in ["ab\"cd", "ab,cd", "ab\\cd"] {
            assert!(set_session_cookie(&cfg, token).is_err(), "{token}");
            assert!(set_csrf_cookie(&cfg, token).is_err(), "{token}");
        }
    }

    #[test]
    fn rejects_cookie_name_with_rfc6265_separators() {
        // `'` is a valid RFC 6265 tchar, so it is intentionally absent here.
        for name in [
            "a/b", "a:b", "a\"b", "a(b)", "a)b", "a,b", "a=b", "a b", "a@b", "a[b]", "a]b", "a{b}",
            "a}b", "a?b", "a\\b", "a<b", "a>b",
        ] {
            let sc = SessionConfig {
                cookie_name: name.into(),
                ..Default::default()
            };
            assert!(set_session_cookie(&sc, "rawtoken123").is_err(), "{name}");
            assert!(clear_session_cookie(&sc).is_err(), "{name}");
        }
    }

    #[test]
    fn test_clear_cookie() {
        let cfg = test_config();
        let cookie = clear_session_cookie(&cfg).expect("static parts encode");
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
        let cookie = set_csrf_cookie(&cfg, "csrftoken456").expect("hex token encodes");
        let s = cookie.to_str().expect("valid ascii");

        assert!(s.contains("csrf_token=csrftoken456"));
        assert!(!s.contains("HttpOnly"), "CSRF cookie must NOT be HttpOnly");
        assert!(s.contains("SameSite=Strict"));
        assert!(s.contains("Secure"));
        assert!(s.contains("Path=/"));

        let cookie2 = set_csrf_cookie(&cfg.session, "csrftoken456").expect("hex token encodes");
        assert_eq!(cookie, cookie2);
    }

    #[test]
    fn test_clear_csrf_cookie() {
        let cfg = test_config();
        let cookie = clear_csrf_cookie(&cfg).expect("clear csrf cookie encodes");
        let s = cookie.to_str().expect("valid ascii");

        assert!(s.contains("csrf_token="));
        assert!(s.contains("Max-Age=0"));
        assert!(s.contains("Expires=Thu, 01 Jan 1970 00:00:00 GMT"));
        assert!(s.contains("SameSite=Strict"));
        assert!(s.contains("Path=/"));
        assert!(s.contains("Secure"));
        assert!(
            !s.contains("HttpOnly"),
            "Clear CSRF cookie must not be HttpOnly"
        );

        let cookie2 = clear_csrf_cookie(&cfg.session).expect("clear csrf cookie encodes");
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

    #[test]
    fn ignores_name_prefix_and_keeps_equals_in_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("sid2=wrong; sid=right; tok=a=b=c"),
        );
        assert_eq!(
            read_session_cookie(&headers, "sid"),
            Some("right".to_string())
        );
        assert_eq!(
            read_session_cookie(&headers, "tok"),
            Some("a=b=c".to_string())
        );
    }

    #[test]
    fn first_duplicate_cookie_wins() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("sid=first; sid=second"));
        assert_eq!(
            read_session_cookie(&headers, "sid"),
            Some("first".to_string())
        );
    }
}
