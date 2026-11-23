#![allow(dead_code)]

use std::future::Future;
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
/// Logical cross-binary test isolation is guaranteed by `dynamic_email()` and unique UUID keys,
/// except for the global two-factor prune (see `PruneIsolationGuard`): it reaps by expiry only.
/// Global table truncation (`truncate_tables`) must not be called during parallel multi-binary
/// test runs without PostgreSQL-level advisory locking (`pg_advisory_lock`).
pub static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Advisory-lock key serializing the global two-factor prune across test binaries.
///
/// `prune_expired_challenges` reaps expired rows table-wide with no owner predicate, and
/// `run_outbox_worker_until` fires it on startup and every poll tick. `DB_LOCK` above is
/// per-process, so without this a worker in one binary reaps expired fixtures seeded by
/// another (flipping `TwoFactorTokenExpired` to `TwoFactorTokenInvalid`). Fixed constant,
/// disjoint by convention from the hashed per-user keys in `TotpService`.
pub const TWO_FACTOR_PRUNE_LOCK_KEY: i64 = 8_700_201_983_700_087;

/// Holds `pg_advisory_xact_lock` on an open transaction for the whole test.
///
/// Transaction-scoped like the production per-user lock: rollback (including drop on panic)
/// releases it, so a failed test cannot poison the pooled connection for the next binary.
/// Every test that exposes an expired `two_factor_tokens` row, or that runs the prune via a
/// spawned worker, holds this for the full test body.
pub struct PruneIsolationGuard<'a> {
    tx: Option<sqlx::Transaction<'a, sqlx::Postgres>>,
}

impl<'a> PruneIsolationGuard<'a> {
    /// Takes the cross-binary prune lock on a dedicated pooled connection.
    pub async fn acquire(pool: &'a PgPool) -> Result<Self, sqlx::Error> {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(TWO_FACTOR_PRUNE_LOCK_KEY)
            .execute(&mut *tx)
            .await?;
        Ok(Self { tx: Some(tx) })
    }

    /// Rolls back, releasing the lock. Drop does the same on panic paths.
    pub async fn release(mut self) -> Result<(), sqlx::Error> {
        if let Some(tx) = self.tx.take() {
            tx.rollback().await?;
        }
        Ok(())
    }
}

/// Worker threads for the concurrency tests.
pub const CONCURRENT_WORKER_THREADS: usize = 5;

/// Runs `body` on a multi-thread runtime so simultaneously dispatched requests actually race.
///
/// A current-thread runtime serializes them at their first await, which would make a
/// concurrency assertion pass without ever racing. Blocks the calling test thread, so use it
/// from a plain `#[test]`, not from `#[tokio::test]`.
pub fn block_on_concurrent<F: Future>(body: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(CONCURRENT_WORKER_THREADS)
        .enable_all()
        .build()
        .expect("build multi-thread test runtime")
        .block_on(body)
}

// ─── Tracing capture support ─────────────────────────────────────────────────

/// Discarding global subscriber that reports maximum interest.
struct DiscardSubscriber;

impl tracing::Subscriber for DiscardSubscriber {
    // Levels above DEBUG stay uninteresting: the capturing subscribers are DEBUG too, so this
    // sink never widens what a capture records.
    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if metadata.level() <= &tracing::Level::DEBUG {
            tracing::subscriber::Interest::always()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.level() <= &tracing::Level::DEBUG
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::DEBUG)
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(0xDEAD)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, _event: &tracing::Event<'_>) {}

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// Installs the permissive global tracing subscriber once per test binary, and repairs the
/// callsite interest cache. Call this before creating a scoped capture subscriber.
///
/// `tracing`'s interest cache is process-global while `set_default` is thread-local: a callsite
/// whose first hit lands on a thread with no subscriber is cached as `Interest::never()` and is
/// then dropped inside the `event!` macro on every thread, so a capture never sees it. With a
/// permissive global default that registration path resolves to `Interest::always()` instead, and
/// the captures — which still point at their own per-test buffers — cannot be disabled by a
/// concurrent test. Nothing is captured by this sink: it discards every event.
pub fn install_global_log_sink() {
    static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALLED.get_or_init(|| {
        // A second install cannot succeed; a host process that already set a global default is
        // equally fine, since the point is only that `get_global` is never `NoSubscriber`.
        let _ = tracing::subscriber::set_global_default(DiscardSubscriber);
        // `set_global_default` does not rebuild the cache, so callsites already disabled by an
        // earlier subscriber-less registration would otherwise stay off for the whole process.
        tracing::callsite::rebuild_interest_cache();
    });
}

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
        database_url: url,
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

    // Built from the customized config so `AppState.config` and the pool can never point at
    // different databases.
    let pool = metal_auth::db::init_pool_with_options(
        &cfg.database_url,
        metal_auth::db::DbPoolOptions {
            max_connections: cfg.max_connections,
            min_connections: cfg.min_connections,
            ..Default::default()
        },
    )
    .await
    .expect("DATABASE_URL is set, so the DB-backed test must connect");

    // The claim is global and the binaries share this database: drop claimable rows a
    // previous binary left behind before this app can deliver them to its own sender.
    metal_auth::db::outbox::discard_claimable_outbox(&pool)
        .await
        .expect("clear claimable outbox residue");

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

// ─── Session and TOTP journey helpers ────────────────────────────────────────

/// The cookies a browser replays after login: session id plus its CSRF pair.
pub struct Session {
    pub sid: String,
    pub csrf: String,
}

pub fn extract_cookie_val(headers: &HeaderMap, name: &str) -> Option<String> {
    for val in headers.get_all(header::SET_COOKIE) {
        if let Ok(s) = val.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some((k, v)) = part.split_once('=')
                    && k.trim() == name
                {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

pub fn extract_cookie_header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    for val in headers.get_all(header::SET_COOKIE) {
        if let Ok(s) = val.to_str()
            && s.starts_with(&format!("{name}="))
        {
            return Some(s.to_string());
        }
    }
    None
}

/// Request carrying the session + CSRF cookies, the `x-csrf-token` header, and a client IP.
///
/// Protected TOTP routes sit behind CSRF middleware; omitting the header would test the CSRF
/// layer instead of the handler.
pub fn session_request(
    app: &TestApp,
    method: Method,
    uri: &str,
    body: serde_json::Value,
    session: &Session,
    ip: &str,
) -> Request<Body> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}={}; csrf_token={}",
            app.state.config.session.cookie_name, session.sid, session.csrf
        )
        .parse()
        .expect("valid cookie header"),
    );
    headers.insert(
        "x-csrf-token",
        session.csrf.parse().expect("valid csrf header"),
    );
    headers.insert("x-forwarded-for", ip.parse().expect("valid ip header"));
    json_request_with_headers(method, uri, body, headers)
}

/// Current six-digit code for an enrolled base32 secret.
pub fn totp_code(secret_base32: &str) -> String {
    code_at(
        secret_base32,
        metal_auth::totp::crypto::current_totp_counter(),
    )
}

pub fn code_at(secret_base32: &str, counter: u64) -> String {
    let secret =
        metal_auth::totp::crypto::decode_totp_secret(secret_base32).expect("valid base32 secret");
    let code = metal_auth::totp::crypto::generate_totp(&secret, counter).expect("code");
    format!("{code:06}")
}

/// Six-digit code outside the acceptance band of the current step, so a rejection test
/// cannot accidentally present a valid code.
///
/// The server verifies against `clock_timestamp()`, not this process's clock, so the band is
/// widened by three steps either side before excluding it.
pub fn invalid_totp_code(secret_base32: &str) -> String {
    let counter = metal_auth::totp::crypto::current_totp_counter();
    let accepted: Vec<String> = (counter.saturating_sub(3)..=counter + 3)
        .map(|step| code_at(secret_base32, step))
        .collect();
    let mut candidate = (accepted[3].parse::<u32>().expect("six-digit code") + 1) % 1_000_000;
    loop {
        let code = format!("{candidate:06}");
        if !accepted.contains(&code) {
            return code;
        }
        candidate = (candidate + 1) % 1_000_000;
    }
}

/// Signs up and verifies the email through the in-process mailer.
pub async fn create_verified_user(app: &TestApp) -> (String, String) {
    let email = dynamic_email();
    let password = dynamic_password();

    let signup_resp = app
        .post_json(
            "/auth/signup",
            serde_json::json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(
        signup_resp.status(),
        StatusCode::OK,
        "signup failed: {}",
        signup_resp.body_str
    );

    let token = app
        .email_sender
        .verification_token_for(&email)
        .expect("signup must capture a verification token");
    let verify_resp = app
        .post_json("/auth/verify", serde_json::json!({ "token": token }))
        .await;
    assert_eq!(
        verify_resp.status(),
        StatusCode::OK,
        "email verification failed: {}",
        verify_resp.body_str
    );

    (email, password)
}

pub async fn login(app: &TestApp, email: &str, password: &str) -> Session {
    let resp = app
        .post_json(
            "/auth/login",
            serde_json::json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "login failed: {}",
        resp.body_str
    );
    Session {
        sid: extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name)
            .expect("session cookie"),
        csrf: extract_cookie_val(&resp.headers, "csrf_token").expect("csrf cookie"),
    }
}

/// Password login for a 2FA user: challenge token, no session cookie.
pub async fn challenge(app: &TestApp, email: &str, password: &str) -> String {
    let resp = app
        .post_json(
            "/auth/login",
            serde_json::json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "login failed: {}",
        resp.body_str
    );
    assert_eq!(resp.json["two_factor_required"], serde_json::json!(true));
    assert!(
        !resp.headers.contains_key(header::SET_COOKIE),
        "2FA login must not issue a session cookie"
    );
    resp.json["challenge_token"]
        .as_str()
        .expect("challenge token")
        .to_string()
}

pub async fn enroll(app: &TestApp, session: &Session, ip: &str) -> serde_json::Value {
    let resp = app
        .dispatch(session_request(
            app,
            Method::POST,
            "/auth/totp/enroll",
            serde_json::json!({}),
            session,
            ip,
        ))
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "enroll failed: {}",
        resp.body_str
    );
    resp.json.clone()
}

pub async fn confirm(app: &TestApp, session: &Session, secret: &str, ip: &str) -> TestResponse {
    let code = totp_code(secret);
    app.dispatch(session_request(
        app,
        Method::POST,
        "/auth/totp/confirm",
        serde_json::json!({ "code": code }),
        session,
        ip,
    ))
    .await
}

/// Create a user, enroll, and confirm so 2FA is enabled.
///
/// Returns the pre-enablement session too: a password login for a 2FA user yields a
/// challenge, not a cookie, so later protected calls must reuse this session.
pub async fn enabled_user(
    app: &TestApp,
    ip: &str,
) -> (String, String, String, Vec<String>, Session) {
    let (email, password) = create_verified_user(app).await;
    let session = login(app, &email, &password).await;
    let enrollment = enroll(app, &session, ip).await;
    let secret = enrollment["secret_base32"]
        .as_str()
        .expect("secret_base32")
        .to_string();
    let backup_codes: Vec<String> = enrollment["backup_codes"]
        .as_array()
        .expect("backup_codes")
        .iter()
        .map(|code| code.as_str().expect("backup code string").to_string())
        .collect();

    let resp = confirm(app, &session, &secret, ip).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "confirm failed: {}",
        resp.body_str
    );

    (email, password, secret, backup_codes, session)
}

/// Resolves the user row behind an email so a journey can assert identity in `sessions`.
pub async fn user_id_for_email(pool: &PgPool, email: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(pool)
        .await
        .expect("user row must exist for the journey email")
}

pub async fn count_sessions_for_user(pool: &PgPool, user_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("count sessions")
}
