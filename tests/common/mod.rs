#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use metal_auth::{
    AppConfig, AppState, Config, EmailDispatcher, ErrorCode, User,
    email::test_utils::CapturingEmailSender,
};
use sqlx::PgPool;
use uuid::Uuid;

/// In-process database serialization mutex for tests running within the same binary process.
///
/// Note: Cargo compiles each integration test file (`tests/*.rs`) into a separate OS process.
/// Logical cross-binary test isolation is guaranteed by `dynamic_email()` and unique UUID keys.
/// Global table truncation (`truncate_tables`) must not be called during parallel multi-binary
/// test runs without PostgreSQL-level advisory locking (`pg_advisory_lock`).
pub static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Truncates all authentication and session domain tables with CASCADE.
pub async fn truncate_tables(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "TRUNCATE TABLE users, sessions, verification_tokens, password_reset_tokens, email_outbox, oauth_accounts CASCADE",
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Structured test response envelope providing parsed JSON, status, raw body string, and headers.
#[derive(Debug, Clone)]
pub struct TestResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub json: serde_json::Value,
    pub body_str: String,
}

impl TestResponse {
    pub async fn from_response(resp: axum::response::Response) -> Self {
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap_or_default();
        let body_str = String::from_utf8_lossy(&bytes).to_string();
        let json = serde_json::from_str(&body_str).unwrap_or(serde_json::Value::Null);
        Self {
            status,
            headers,
            json,
            body_str,
        }
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn json(&self) -> &serde_json::Value {
        &self.json
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    pub fn error_code(&self) -> Option<ErrorCode> {
        self.json
            .get("code")
            .and_then(|c| c.as_str())
            .and_then(|s| serde_json::from_value(serde_json::Value::String(s.to_string())).ok())
    }
}

/// Shared test harness managing an in-memory Axum router, live PostgreSQL connection pool,
/// capturing email sender, and synchronous dispatch helpers.
#[derive(Clone)]
pub struct TestApp {
    pub router: axum::Router,
    pub pool: PgPool,
    pub state: AppState,
    pub email_sender: Arc<CapturingEmailSender>,
    pub base_url: String,
}

impl TestApp {
    /// Dispatches an arbitrary HTTP request against the test router.
    pub async fn dispatch(&self, req: Request<Body>) -> TestResponse {
        use tower::ServiceExt;
        let resp = self
            .router
            .clone()
            .oneshot(req)
            .await
            .expect("test router oneshot dispatch failed");
        TestResponse::from_response(resp).await
    }

    /// Dispatches a JSON POST request against the test router.
    pub async fn post_json(&self, uri: &str, body: serde_json::Value) -> TestResponse {
        let req = json_request(Method::POST, uri, body);
        self.dispatch(req).await
    }

    /// Dispatches a JSON POST request with an explicit `Origin` header.
    pub async fn post_json_with_origin(
        &self,
        uri: &str,
        body: serde_json::Value,
        origin: &str,
    ) -> TestResponse {
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, origin.parse().expect("valid origin header"));
        let req = json_request_with_headers(Method::POST, uri, body, headers);
        self.dispatch(req).await
    }

    /// Dispatches a JSON POST request with an explicit client IP (`x-forwarded-for`).
    pub async fn post_json_with_ip(
        &self,
        uri: &str,
        body: serde_json::Value,
        ip: &str,
    ) -> TestResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            ip.parse().expect("valid x-forwarded-for header"),
        );
        let req = json_request_with_headers(Method::POST, uri, body, headers);
        self.dispatch(req).await
    }

    /// Dispatches an empty POST request (e.g. for logout or verify).
    pub async fn post_empty(&self, uri: &str) -> TestResponse {
        let req = empty_request(Method::POST, uri);
        self.dispatch(req).await
    }

    /// Dispatches an empty POST request with an `Authorization: Bearer <token>` header.
    pub async fn post_empty_with_bearer(&self, uri: &str, token: &str) -> TestResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}")
                .parse()
                .expect("valid bearer header"),
        );
        let req = empty_request_with_headers(Method::POST, uri, headers);
        self.dispatch(req).await
    }

    /// Convenience truncation helper using the test app's pool.
    pub async fn truncate(&self) -> Result<(), sqlx::Error> {
        truncate_tables(&self.pool).await
    }
}

/// Builds a JSON request with `application/json` Content-Type header.
pub fn json_request(method: Method, uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&body).expect("valid json body"),
        ))
        .expect("valid request")
}

/// Builds a JSON request with additional headers.
pub fn json_request_with_headers(
    method: Method,
    uri: &str,
    body: serde_json::Value,
    headers: HeaderMap,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    for (k, v) in &headers {
        builder = builder.header(k, v);
    }
    builder
        .body(Body::from(
            serde_json::to_vec(&body).expect("valid json body"),
        ))
        .expect("valid request")
}

/// Builds an empty-body request.
pub fn empty_request(method: Method, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .expect("valid empty request")
}

/// Builds an empty-body request with additional headers.
pub fn empty_request_with_headers(method: Method, uri: &str, headers: HeaderMap) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in &headers {
        builder = builder.header(k, v);
    }
    builder.body(Body::empty()).expect("valid empty request")
}

/// Generates a randomized, unique dynamic email address for isolation.
pub fn dynamic_email() -> String {
    format!("journey_{}@example.com", Uuid::new_v4())
}

/// Generates a valid randomized dynamic password satisfying OWASP password policies.
pub fn dynamic_password() -> String {
    format!("JourneyPass!_{}", Uuid::new_v4())
}

/// Generates a randomized, unique client IP address in TEST-NET-2 (198.51.100.0/24) to avoid rate limit collisions.
pub fn dynamic_ip() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static IP_COUNTER: AtomicU32 = AtomicU32::new(1);
    let count = IP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let b = ((count >> 8) & 0xff) as u8;
    let c = (count & 0xff) as u8;
    format!("198.51.{b}.{c}")
}

/// DB query helper: counts total rows in the `users` table.
pub async fn count_users(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
}

/// DB query helper: counts rows in `users` matching the given email.
pub async fn count_users_by_email(pool: &PgPool, email: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(pool)
        .await
}

/// DB query helper: counts verification tokens for a specific user ID.
pub async fn count_verification_tokens_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM verification_tokens WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
}

/// DB query helper: counts password reset tokens for a specific user ID.
pub async fn count_reset_tokens_for_user(pool: &PgPool, user_id: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
}

/// DB query helper: checks whether a user's email has been verified.
pub async fn is_email_verified(pool: &PgPool, user_id: Uuid) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT email_verified FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
}

/// DB query helper: fetches a complete user row by user ID.
pub async fn get_user_by_id(pool: &PgPool, user_id: Uuid) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT id, email, password_hash, email_verified, created_at, updated_at FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
}

/// DB query helper: expires all password reset tokens for a user (sets expires_at to 1 hour in the past).
pub async fn expire_reset_tokens_for_user(pool: &PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE password_reset_tokens SET expires_at = NOW() - INTERVAL '1 hour' WHERE user_id = $1",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// DB query helper: expires all verification tokens for a user (sets expires_at to 1 hour in the past).
pub async fn expire_verification_tokens_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE verification_tokens SET expires_at = NOW() - INTERVAL '1 hour' WHERE user_id = $1",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// DB query helper: returns total count of outbox records.
pub async fn count_outbox_rows(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM email_outbox")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

/// DB query helper: returns all outbox records for a given recipient.
pub async fn get_outbox_rows_for_recipient(
    pool: &PgPool,
    recipient: &str,
) -> Result<Vec<metal_auth::EmailOutbox>, sqlx::Error> {
    sqlx::query_as::<sqlx::Postgres, metal_auth::EmailOutbox>(
        "SELECT id, recipient, email_type, payload, status, retry_count, next_retry_at, created_at, sent_at, error_log FROM email_outbox WHERE recipient = $1 ORDER BY created_at ASC",
    )
    .bind(recipient)
    .fetch_all(pool)
    .await
}

/// Test-only pool ceiling.
///
/// Concurrency tests dispatch five requests at once and each holds more than one connection
/// in flight; the old ceiling of 5 sat exactly at the request count and timed out.
pub const TEST_POOL_MAX_CONNECTIONS: u32 = 10;

/// Test-only Argon2id cost floor: the cheapest parameters `AppConfig::validate` accepts.
///
/// Production defaults (65536/3/4) stay untouched; integration tests would otherwise need
/// ~87 minutes because every signup, dummy hash, and TOTP enrollment pays full cost.
pub fn test_auth_config() -> AppConfig {
    AppConfig {
        argon2_m_cost: 19456,
        argon2_t_cost: 2,
        argon2_p_cost: 1,
        ..AppConfig::default()
    }
}

/// Initializes a live-DB test app with the Argon2 floor and blocking email dispatcher.
pub async fn setup_test_app() -> Option<TestApp> {
    setup_test_app_with(|_| {}).await
}

/// Initializes a live-DB test app after letting the caller adjust its server config.
///
/// `AppState` owns its `Config`, so settings a test depends on — TOTP rate-limit budgets in
/// particular — must be fixed before the state is built.
pub async fn setup_test_app_with(customize: impl FnOnce(&mut Config)) -> Option<TestApp> {
    setup_test_app_with_auth_config_and(Arc::new(test_auth_config()), customize).await
}

/// Initializes a live-DB test app with custom `AppConfig` and blocking email dispatcher.
pub async fn setup_test_app_with_auth_config(auth_config: Arc<AppConfig>) -> Option<TestApp> {
    setup_test_app_with_auth_config_and(auth_config, |_| {}).await
}

async fn setup_test_app_with_auth_config_and(
    auth_config: Arc<AppConfig>,
    customize: impl FnOnce(&mut Config),
) -> Option<TestApp> {
    dotenvy::dotenv().ok();
    let url = match std::env::var("DATABASE_URL") {
        Ok(val) => val,
        Err(std::env::VarError::NotPresent) => {
            assert!(
                std::env::var_os("CI").is_none(),
                "DATABASE_URL must be set in CI: DB-backed tests must never skip silently"
            );
            eprintln!("SKIP: DB-backed tests need DATABASE_URL");
            return None;
        }
        Err(e) => panic!("invalid DATABASE_URL environment variable: {e}"),
    };

    let mut cfg = Config {
        database_url: url.clone(),
        port: 8080,
        allowed_origins: vec!["https://app.example.com".into()],
        allowed_methods: vec!["GET".into(), "POST".into(), "OPTIONS".into()],
        allowed_headers: vec!["Authorization".into(), "Content-Type".into()],
        max_connections: TEST_POOL_MAX_CONNECTIONS,
        min_connections: 1,
        base_url: "https://example.com".into(),
        email_dispatch_timeout: Duration::from_secs(10),
        async_email_dispatch: true,
        outbox_poll_interval: Duration::from_millis(50),
        outbox_batch_size: 50,
        outbox_max_retries: 5,
        outbox_initial_backoff: Duration::from_secs(1),
        outbox_max_backoff: Duration::from_secs(300),
        outbox_sent_retention: Duration::from_secs(7 * 24 * 3600),
        session: metal_auth::SessionConfig::default(),
        rate_limit: metal_auth::RateLimitConfig::default(),
        oauth: metal_auth::OAuthConfig::default(),
        totp: metal_auth::TotpConfig {
            // TOTP handlers resolve the key per operation; without it every call is a 500.
            encryption_key: Some("00".repeat(32)),
            ..metal_auth::TotpConfig::default()
        },
    };

    customize(&mut cfg);

    let pool = metal_auth::db::init_pool_with_options(
        &url,
        metal_auth::db::DbPoolOptions {
            max_connections: cfg.max_connections,
            min_connections: cfg.min_connections,
            ..Default::default()
        },
    )
    .await
    .expect("DATABASE_URL is set, so the DB-backed test must connect");

    let email_sender = Arc::new(CapturingEmailSender::new());
    let dispatcher = Arc::new(
        EmailDispatcher::new_blocking(
            Some(Arc::clone(&email_sender) as metal_auth::SharedEmailSender),
            Duration::from_secs(10),
        )
        .with_base_url("https://example.com"),
    );

    let state = AppState::with_dispatcher(pool.clone(), cfg, auth_config, dispatcher)
        .expect("create test app state");
    let router =
        metal_auth::handler::create_router(state.clone()).expect("create router for test app");

    Some(TestApp {
        router,
        pool,
        state,
        email_sender,
        base_url: "https://example.com".into(),
    })
}
