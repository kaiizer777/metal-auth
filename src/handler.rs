use axum::{Router, http::HeaderMap};
use tower_http::trace::TraceLayer;

use crate::{
    config::Config,
    error::{AppError, ConfigError},
    middleware::security_headers_middleware,
    state::AppState,
};

pub mod auth;
pub mod cors;
pub mod oauth;
pub mod session;
pub mod totp;

pub use auth::routes as auth_routes;
pub use cors::cors_layer;
pub use oauth::routes as oauth_routes;
pub use session::routes as session_routes;
pub use totp::routes as totp_routes;

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

/// Refuse a config whose TOTP encryption key is absent or unusable.
///
/// Minting a challenge needs no key, but verifying one decrypts the stored secret, so a
/// keyless router issues challenges it can never redeem. `None` (no config at all) can be
/// proved just as little, so it is refused the same way. Fail at construction instead.
pub(crate) fn require_totp_key(config: Option<&Config>) -> Result<(), AppError> {
    let config = config.ok_or(ConfigError::InvalidValue {
        field: "totp.encryption_key",
        reason: "must be set to enable totp",
    })?;
    config
        .totp
        .encryption_key_bytes()
        .map(|_| ())
        .map_err(AppError::Config)
}

pub fn create_router(state: AppState) -> Result<Router, AppError> {
    // `AppState` fields are public, so validate here too: no router is served from a
    // config that failed validation.
    state.config.validate().map_err(AppError::Config)?;
    require_totp_key(Some(&state.config))?;
    let cors = cors_layer(&state.config)?;

    let oauth_router = oauth::routes(state.clone());
    let auth_router = auth::routes_with_app_state(state.clone())?
        .merge(session::routes(state.clone()))
        .merge(totp::routes(state.clone())?)
        .merge(oauth_router.clone());

    Ok(Router::new()
        .nest("/auth", auth_router)
        .nest("/api/auth", oauth_router)
        .fallback(fallback_not_found)
        .layer(cors)
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .layer(TraceLayer::new_for_http().make_span_with(
            |request: &axum::http::Request<axum::body::Body>| {
                tracing::debug_span!(
                    "request",
                    method = %request.method(),
                    uri = %request.uri().path(),
                    version = ?request.version(),
                )
            },
        )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, Config};
    use crate::error::ConfigError;
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
            oauth: crate::config::OAuthConfig::default(),
            totp: crate::config::TotpConfig {
                encryption_key: Some("00".repeat(crate::config::TOTP_ENCRYPTION_KEY_BYTES)),
                ..crate::config::TotpConfig::default()
            },
        }
    }

    fn state_with_config(cfg: Config) -> AppState {
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        AppState::with_configs_and_dispatcher(pool, cfg, Arc::new(AppConfig::default()), None)
            .expect("valid test AppState")
    }

    /// Returns the reported `reason`, asserting the failure names the TOTP key setting.
    fn totp_key_error_reason<T>(result: Result<T, AppError>) -> &'static str {
        match result {
            Ok(_) => panic!("a config without a usable TOTP key must not build a router"),
            Err(AppError::Config(ConfigError::InvalidValue { field, reason })) => {
                assert_eq!(field, "totp.encryption_key");
                reason
            }
            Err(other) => panic!("expected a totp.encryption_key config error, got {other:?}"),
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
    async fn create_router_rejects_absent_totp_encryption_key() {
        let cfg = Config {
            totp: crate::config::TotpConfig::default(),
            ..valid_config()
        };

        assert_eq!(
            totp_key_error_reason(create_router(state_with_config(cfg))),
            "must be set to enable totp"
        );
    }

    #[test]
    fn require_totp_key_rejects_blank_key() {
        let cfg = Config {
            totp: crate::config::TotpConfig {
                encryption_key: Some(String::new()),
                ..crate::config::TotpConfig::default()
            },
            ..valid_config()
        };

        assert_eq!(
            totp_key_error_reason(require_totp_key(Some(&cfg))),
            "must be exactly 64 hexadecimal characters"
        );
    }

    #[tokio::test]
    async fn routes_with_app_state_rejects_absent_totp_encryption_key() {
        let cfg = Config {
            totp: crate::config::TotpConfig::default(),
            ..valid_config()
        };

        assert_eq!(
            totp_key_error_reason(crate::handler::auth::routes_with_app_state(
                state_with_config(cfg)
            )),
            "must be set to enable totp"
        );
    }

    fn handler_state_with_config(cfg: Config) -> crate::handler::auth::AuthHandlerState {
        let state = state_with_config(cfg);
        crate::handler::auth::AuthHandlerState {
            service: Arc::clone(&state.auth_service),
            session_service: Some(Arc::clone(&state.session_service)),
            rate_limiter: Some(Arc::clone(&state.rate_limiter)),
            config: Some(Arc::new(state.config.clone())),
            totp_service: Arc::clone(&state.totp_service),
        }
    }

    #[tokio::test]
    async fn routes_with_state_rejects_absent_totp_encryption_key() {
        let cfg = Config {
            totp: crate::config::TotpConfig::default(),
            ..valid_config()
        };

        assert_eq!(
            totp_key_error_reason(crate::handler::auth::routes_with_state(
                handler_state_with_config(cfg)
            )),
            "must be set to enable totp"
        );
    }

    #[tokio::test]
    async fn routes_with_state_rejects_a_handler_state_without_config() {
        let mut handler = handler_state_with_config(valid_config());
        handler.config = None;

        assert_eq!(
            totp_key_error_reason(crate::handler::auth::routes_with_state(handler)),
            "must be set to enable totp"
        );
    }

    #[tokio::test]
    async fn routes_with_state_serves_a_keyed_config() {
        let mut router =
            crate::handler::auth::routes_with_state(handler_state_with_config(valid_config()))
                .expect("keyed config builds the auth router");

        let req = Request::builder()
            .uri("/login")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let resp = router.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn totp_routes_rejects_absent_totp_encryption_key() {
        let cfg = Config {
            totp: crate::config::TotpConfig::default(),
            ..valid_config()
        };

        assert_eq!(
            totp_key_error_reason(crate::handler::totp::routes(state_with_config(cfg))),
            "must be set to enable totp"
        );
    }

    #[tokio::test]
    async fn totp_routes_serves_a_keyed_config() {
        let mut router = crate::handler::totp::routes(state_with_config(valid_config()))
            .expect("keyed config builds the totp router");

        let req = Request::builder()
            .uri("/totp/verify")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();

        let resp = router.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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

    #[tokio::test]
    async fn test_oauth_routes_mounted_under_auth_and_api_auth() {
        let cfg = valid_config();
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let state =
            AppState::with_configs_and_dispatcher(pool, cfg, Arc::new(AppConfig::default()), None)
                .unwrap();
        let mut router = create_router(state).unwrap();

        // 1. Canonical /auth/oauth/accounts requires authentication
        let req1 = Request::builder()
            .uri("/auth/oauth/accounts")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        let resp1 = router.call(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::UNAUTHORIZED);

        // 2. Alias /api/auth/oauth/accounts requires authentication
        let req2 = Request::builder()
            .uri("/api/auth/oauth/accounts")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        let resp2 = router.call(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);

        // 3. Unknown provider returns 404
        let req3 = Request::builder()
            .uri("/auth/oauth/unknown_provider")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        let resp3 = router.call(req3).await.unwrap();
        assert_eq!(resp3.status(), StatusCode::NOT_FOUND);
    }
}
