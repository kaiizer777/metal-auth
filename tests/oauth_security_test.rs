mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use chrono::Utc;
use common::*;
use metal_auth::{
    AppleProvider, ErrorCode, GoogleProvider, OAuthProvider, OAuthService, ProviderConfig,
    SessionService, User,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Clone)]
struct TestLogWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for TestLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TestLogWriter {
    type Writer = TestLogWriter;
    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

struct TestLogScope {
    buf: Arc<Mutex<Vec<u8>>>,
    _guard: tracing::subscriber::DefaultGuard,
}

impl TestLogScope {
    fn new() -> Self {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(TestLogWriter(buf.clone()))
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        Self { buf, _guard: guard }
    }

    fn text(&self) -> String {
        String::from_utf8(self.buf.lock().unwrap().clone()).unwrap_or_default()
    }
}

fn extract_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for val in headers.get_all(header::SET_COOKIE) {
        if let Ok(s) = val.to_str()
            && let Some(cookie_part) = s.split(';').next()
        {
            let mut parts = cookie_part.splitn(2, '=');
            if let (Some(k), Some(v)) = (parts.next(), parts.next())
                && k.trim() == name
            {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn extract_state_from_location(headers: &HeaderMap) -> String {
    let loc = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("location header present");
    let state_part = loc.split("state=").nth(1).expect("state in location query");
    state_part
        .split('&')
        .next()
        .expect("state parameter value")
        .to_string()
}

async fn setup_oauth_test_app(
    providers: HashMap<String, Arc<dyn OAuthProvider>>,
) -> Option<TestApp> {
    let mut app = setup_test_app().await?;
    let mut cfg = app.state.config.clone();
    cfg.oauth.state_secret = "01234567890123456789012345678901".to_string();
    let cfg_arc = Arc::new(cfg.clone());
    let session_service = Arc::new(SessionService::new(app.pool.clone(), Arc::clone(&cfg_arc)));
    let oauth_service = Arc::new(OAuthService::with_providers(
        app.pool.clone(),
        cfg_arc,
        session_service.clone(),
        providers,
    ));

    app.state.config = cfg;
    app.state.session_service = session_service;
    app.state.oauth_service = oauth_service;
    app.router = metal_auth::handler::create_router(app.state.clone()).unwrap();
    Some(app)
}

#[tokio::test]
async fn test_security_pre_hijacking_unverified_provider_email() {
    let _guard = DB_LOCK.lock().await;
    let server = MockServer::start().await;

    let victim_email = dynamic_email();

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "goog-at-unverified",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": "attacker-sub-999",
            "email": victim_email,
            "email_verified": false, // UNVERIFIED email from provider
            "name": "Attacker"
        })))
        .mount(&server)
        .await;

    let google_cfg = ProviderConfig {
        client_id: "google-id".to_string(),
        client_secret: "google-secret".to_string(),
        redirect_uri: "https://example.com/auth/oauth/google/callback".to_string(),
        scopes: vec![],
        enabled: true,
        team_id: None,
        key_id: None,
        private_key: None,
    };
    let google = GoogleProvider::with_endpoints(
        &google_cfg,
        reqwest::Client::new(),
        format!("{}/auth", server.uri()),
        format!("{}/token", server.uri()),
        format!("{}/userinfo", server.uri()),
    )
    .unwrap();

    let mut providers: HashMap<String, Arc<dyn OAuthProvider>> = HashMap::new();
    providers.insert("google".to_string(), Arc::new(google));

    let Some(app) = setup_oauth_test_app(providers).await else {
        return;
    };

    // Initiate
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/google")
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    let state_token = extract_state_from_location(&resp.headers);
    let state_cookie = extract_cookie_value(&resp.headers, "oauth_state").unwrap();

    // Callback
    let callback_uri = format!("/auth/oauth/google/callback?code=some_code&state={state_token}");
    let req = Request::builder()
        .method(Method::GET)
        .uri(&callback_uri)
        .header(header::ACCEPT, "application/json")
        .header(header::COOKIE, format!("oauth_state={state_cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(resp.error_code(), Some(ErrorCode::OAuthEmailUnverified));
    assert_eq!(
        resp.json()["message"],
        "oauth provider email is not verified"
    );

    // Assert oauth_state cookie was cleared
    assert_eq!(
        extract_cookie_value(&resp.headers, "oauth_state"),
        Some("".to_string())
    );

    // Assert zero records inserted in users or oauth_accounts
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1")
        .bind(&victim_email)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);

    let link_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM oauth_accounts WHERE provider_user_id = $1")
            .bind("attacker-sub-999")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(link_count, 0);
}

#[tokio::test]
async fn test_security_pre_hijacking_collision_unverified_local_account() {
    let _guard = DB_LOCK.lock().await;
    let server = MockServer::start().await;

    let victim_email = dynamic_email();

    let mut providers: HashMap<String, Arc<dyn OAuthProvider>> = HashMap::new();
    let google_cfg = ProviderConfig {
        client_id: "google-id".to_string(),
        client_secret: "google-secret".to_string(),
        redirect_uri: "https://example.com/auth/oauth/google/callback".to_string(),
        scopes: vec![],
        enabled: true,
        team_id: None,
        key_id: None,
        private_key: None,
    };
    let google = GoogleProvider::with_endpoints(
        &google_cfg,
        reqwest::Client::new(),
        format!("{}/auth", server.uri()),
        format!("{}/token", server.uri()),
        format!("{}/userinfo", server.uri()),
    )
    .unwrap();
    providers.insert("google".to_string(), Arc::new(google));

    let Some(app) = setup_oauth_test_app(providers).await else {
        return;
    };

    // Pre-create unverified local account
    let victim_id = uuid::Uuid::new_v4();
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(victim_id)
    .bind(&victim_email)
    .bind("victim_known_password_hash")
    .bind(false) // UNVERIFIED local account
    .bind(now)
    .bind(now)
    .execute(&app.pool)
    .await
    .unwrap();

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "goog-at-attacker",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": "attacker-google-sub",
            "email": victim_email,
            "email_verified": true, // Verified at provider
            "name": "Attacker"
        })))
        .mount(&server)
        .await;

    // Initiate
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/google")
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    let state_token = extract_state_from_location(&resp.headers);
    let state_cookie = extract_cookie_value(&resp.headers, "oauth_state").unwrap();

    // Callback
    let callback_uri = format!("/auth/oauth/google/callback?code=atk_code&state={state_token}");
    let req = Request::builder()
        .method(Method::GET)
        .uri(&callback_uri)
        .header(header::ACCEPT, "application/json")
        .header(header::COOKIE, format!("oauth_state={state_cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;

    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(resp.error_code(), Some(ErrorCode::OAuthAccountLinkConflict));
    assert_eq!(
        resp.json()["message"],
        "cannot link oauth identity to unverified local account"
    );

    // Assert victim password and state were not modified
    let victim_row: User = sqlx::query_as::<_, User>(
        "SELECT id, email, password_hash, email_verified, created_at, updated_at FROM users WHERE id = $1",
    )
    .bind(victim_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(victim_row.password_hash, "victim_known_password_hash");
    assert!(!victim_row.email_verified);

    // Assert zero links in oauth_accounts
    let link_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM oauth_accounts WHERE user_id = $1")
            .bind(victim_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(link_count, 0);

    // Assert state cookie cleared
    assert_eq!(
        extract_cookie_value(&resp.headers, "oauth_state"),
        Some("".to_string())
    );
}

#[tokio::test]
async fn test_security_anti_enumeration_unusable_password() {
    let _guard = DB_LOCK.lock().await;

    let Some(app) = setup_test_app().await else {
        return;
    };

    let test_email = dynamic_email();
    let user_id = uuid::Uuid::new_v4();
    let now = Utc::now();

    // Create user with unusable password hash (OAuth-only account)
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(user_id)
    .bind(&test_email)
    .bind("$unusable$oauth$")
    .bind(true)
    .bind(now)
    .bind(now)
    .execute(&app.pool)
    .await
    .unwrap();

    // Attempt password login against this user
    let login_body = serde_json::json!({
        "email": test_email,
        "password": "AttemptPassword123!",
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body).unwrap()))
        .unwrap();
    let resp = app.dispatch(req).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.error_code(), Some(ErrorCode::InvalidCredentials));
    assert_eq!(resp.json()["message"], "Invalid email or password");
}

#[tokio::test]
async fn test_security_external_callback_csrf_exemption() {
    let _guard = DB_LOCK.lock().await;
    let server = MockServer::start().await;

    let apple_cfg = ProviderConfig {
        client_id: "apple-id".to_string(),
        client_secret: "apple-secret".to_string(),
        redirect_uri: "https://example.com/auth/oauth/apple/callback".to_string(),
        scopes: vec![],
        enabled: true,
        team_id: None,
        key_id: None,
        private_key: None,
    };
    let apple = AppleProvider::with_endpoints(
        &apple_cfg,
        reqwest::Client::new(),
        format!("{}/auth", server.uri()),
        format!("{}/token", server.uri()),
        format!("{}/jwks", server.uri()),
    )
    .unwrap();

    let mut providers: HashMap<String, Arc<dyn OAuthProvider>> = HashMap::new();
    providers.insert("apple".to_string(), Arc::new(apple));

    let Some(app) = setup_oauth_test_app(providers).await else {
        return;
    };

    // Make request to POST /auth/oauth/apple/callback with session cookie but WITHOUT x-csrf-token header
    // Should NOT return CSRF_TOKEN_MISSING (403), but evaluate OAuth state (returning OAUTH_STATE_INVALID since state is missing)
    let form_body = "code=test_code&state=bad_state";
    let req = Request::builder()
        .method(Method::POST)
        .uri("/auth/oauth/apple/callback")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .header(
            header::COOKIE,
            format!(
                "{}=some_active_session_cookie",
                app.state.config.session.cookie_name
            ),
        )
        .body(Body::from(form_body))
        .unwrap();
    let resp = app.dispatch(req).await;

    assert_ne!(
        resp.error_code(),
        Some(ErrorCode::CsrfTokenMissing),
        "external callback POST must be exempt from double-submit CSRF checks"
    );
    assert_eq!(
        resp.error_code(),
        Some(ErrorCode::OAuthStateInvalid),
        "state must be evaluated"
    );
}

#[tokio::test]
async fn test_security_oauth_state_tampering_and_fixation() {
    let _guard = DB_LOCK.lock().await;
    let server = MockServer::start().await;

    let google_cfg = ProviderConfig {
        client_id: "google-id".to_string(),
        client_secret: "google-secret".to_string(),
        redirect_uri: "https://example.com/auth/oauth/google/callback".to_string(),
        scopes: vec![],
        enabled: true,
        team_id: None,
        key_id: None,
        private_key: None,
    };
    let google = GoogleProvider::with_endpoints(
        &google_cfg,
        reqwest::Client::new(),
        format!("{}/auth", server.uri()),
        format!("{}/token", server.uri()),
        format!("{}/userinfo", server.uri()),
    )
    .unwrap();

    let mut providers: HashMap<String, Arc<dyn OAuthProvider>> = HashMap::new();
    providers.insert("google".to_string(), Arc::new(google));

    let Some(app) = setup_oauth_test_app(providers).await else {
        return;
    };

    // 1. Missing state param
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/google/callback?code=some_code")
        .header(header::ACCEPT, "application/json")
        .header(header::COOKIE, "oauth_state=some_cookie")
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.error_code(), Some(ErrorCode::OAuthStateInvalid));
    assert_eq!(
        extract_cookie_value(&resp.headers, "oauth_state"),
        Some("".to_string())
    );

    // 2. Missing cookie header
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/google/callback?code=some_code&state=valid_looking_token")
        .header(header::ACCEPT, "application/json")
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.error_code(), Some(ErrorCode::OAuthStateInvalid));

    // 3. Tampered state cookie HMAC
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/google")
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    let state_token = extract_state_from_location(&resp.headers);
    let state_cookie = extract_cookie_value(&resp.headers, "oauth_state").unwrap();

    // Tamper with cookie
    let tampered_cookie = format!("{state_cookie}tampered");
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/auth/oauth/google/callback?code=some_code&state={state_token}"
        ))
        .header(header::ACCEPT, "application/json")
        .header(header::COOKIE, format!("oauth_state={tampered_cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.error_code(), Some(ErrorCode::OAuthStateInvalid));
    assert_eq!(
        extract_cookie_value(&resp.headers, "oauth_state"),
        Some("".to_string())
    );

    // 4. Mismatched state token (cookie valid for token A, query passes token B)
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/google/callback?code=some_code&state=mismatched_token_b")
        .header(header::ACCEPT, "application/json")
        .header(header::COOKIE, format!("oauth_state={state_cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.error_code(), Some(ErrorCode::OAuthStateInvalid));
}

#[tokio::test]
async fn test_security_pkce_exchange_failure() {
    let _guard = DB_LOCK.lock().await;
    let server = MockServer::start().await;

    // Token exchange returns 400 Bad Request (e.g. invalid code or code_verifier mismatch)
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "PKCE verification failed"
        })))
        .mount(&server)
        .await;

    let google_cfg = ProviderConfig {
        client_id: "google-id".to_string(),
        client_secret: "google-secret".to_string(),
        redirect_uri: "https://example.com/auth/oauth/google/callback".to_string(),
        scopes: vec![],
        enabled: true,
        team_id: None,
        key_id: None,
        private_key: None,
    };
    let google = GoogleProvider::with_endpoints(
        &google_cfg,
        reqwest::Client::new(),
        format!("{}/auth", server.uri()),
        format!("{}/token", server.uri()),
        format!("{}/userinfo", server.uri()),
    )
    .unwrap();

    let mut providers: HashMap<String, Arc<dyn OAuthProvider>> = HashMap::new();
    providers.insert("google".to_string(), Arc::new(google));

    let Some(app) = setup_oauth_test_app(providers).await else {
        return;
    };

    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/google")
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    let state_token = extract_state_from_location(&resp.headers);
    let state_cookie = extract_cookie_value(&resp.headers, "oauth_state").unwrap();

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/auth/oauth/google/callback?code=bad_grant_code&state={state_token}"
        ))
        .header(header::ACCEPT, "application/json")
        .header(header::COOKIE, format!("oauth_state={state_cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(resp.error_code(), Some(ErrorCode::OAuthProviderError));
    assert_eq!(resp.json()["message"], "oauth provider error");
    assert_eq!(
        extract_cookie_value(&resp.headers, "oauth_state"),
        Some("".to_string())
    );
}

#[tokio::test]
async fn test_security_open_redirect_attempts_rejected() {
    let _guard = DB_LOCK.lock().await;
    let server = MockServer::start().await;

    let test_email = dynamic_email();

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "goog-redir-at",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": "google-redir-001",
            "email": test_email,
            "email_verified": true,
            "name": "Redir User"
        })))
        .mount(&server)
        .await;

    let google_cfg = ProviderConfig {
        client_id: "google-id".to_string(),
        client_secret: "google-secret".to_string(),
        redirect_uri: "https://example.com/auth/oauth/google/callback".to_string(),
        scopes: vec![],
        enabled: true,
        team_id: None,
        key_id: None,
        private_key: None,
    };
    let google = GoogleProvider::with_endpoints(
        &google_cfg,
        reqwest::Client::new(),
        format!("{}/auth", server.uri()),
        format!("{}/token", server.uri()),
        format!("{}/userinfo", server.uri()),
    )
    .unwrap();

    let mut providers: HashMap<String, Arc<dyn OAuthProvider>> = HashMap::new();
    providers.insert("google".to_string(), Arc::new(google));

    let Some(app) = setup_oauth_test_app(providers).await else {
        return;
    };

    let hostile_redirects = [
        "//evil.com",
        "/\\evil.com",
        "https://evil.com/phish",
        "/path with space",
        "/path\twith\ttab",
        "/path\rnewline",
        "/path\nnewline",
        "/back\\slash",
    ];

    for (idx, target) in hostile_redirects.iter().enumerate() {
        let client_ip = format!("192.0.2.{}", idx + 1);
        let uri = format!("/auth/oauth/google?redirect_url={}", percent_encode(target));
        let req = Request::builder()
            .method(Method::GET)
            .uri(&uri)
            .header("x-forwarded-for", &client_ip)
            .body(Body::empty())
            .unwrap();
        let resp = app.dispatch(req).await;
        let state_token = extract_state_from_location(&resp.headers);
        let state_cookie = extract_cookie_value(&resp.headers, "oauth_state").unwrap();

        // Browser callback -> Location header must be sanitized to "/"
        let callback_uri =
            format!("/auth/oauth/google/callback?code=good_code&state={state_token}");
        let req = Request::builder()
            .method(Method::GET)
            .uri(&callback_uri)
            .header("x-forwarded-for", &client_ip)
            .header(header::COOKIE, format!("oauth_state={state_cookie}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.dispatch(req).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.header(header::LOCATION.as_str()),
            Some("/"),
            "hostile redirect {target} must be sanitized to /"
        );
    }
}

#[tokio::test]
async fn test_security_unknown_provider_returns_404() {
    let _guard = DB_LOCK.lock().await;

    let Some(app) = setup_test_app().await else {
        return;
    };

    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/discord")
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(resp.error_code(), Some(ErrorCode::OAuthProviderNotFound));
    assert_eq!(resp.json()["message"], "oauth provider not found");

    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/discord/callback?code=c&state=s")
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(resp.error_code(), Some(ErrorCode::OAuthProviderNotFound));
}

#[tokio::test]
async fn test_security_replay_protection() {
    let _guard = DB_LOCK.lock().await;
    let server = MockServer::start().await;

    let test_email = dynamic_email();

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "replay-at-test",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": "replay-user-sub",
            "email": test_email,
            "email_verified": true,
            "name": "Replay User"
        })))
        .mount(&server)
        .await;

    let google_cfg = ProviderConfig {
        client_id: "google-id".to_string(),
        client_secret: "google-secret".to_string(),
        redirect_uri: "https://example.com/auth/oauth/google/callback".to_string(),
        scopes: vec![],
        enabled: true,
        team_id: None,
        key_id: None,
        private_key: None,
    };
    let google = GoogleProvider::with_endpoints(
        &google_cfg,
        reqwest::Client::new(),
        format!("{}/auth", server.uri()),
        format!("{}/token", server.uri()),
        format!("{}/userinfo", server.uri()),
    )
    .unwrap();

    let mut providers: HashMap<String, Arc<dyn OAuthProvider>> = HashMap::new();
    providers.insert("google".to_string(), Arc::new(google));

    let Some(app) = setup_oauth_test_app(providers).await else {
        return;
    };

    // 1. Initiate flow
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/google")
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    let state_token = extract_state_from_location(&resp.headers);
    let state_cookie = extract_cookie_value(&resp.headers, "oauth_state").unwrap();

    // 2. First callback execution: succeeds
    let callback_uri = format!("/auth/oauth/google/callback?code=good_code&state={state_token}");
    let req = Request::builder()
        .method(Method::GET)
        .uri(&callback_uri)
        .header(header::ACCEPT, "application/json")
        .header(header::COOKIE, format!("oauth_state={state_cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. Second callback execution (replay attempt with same state token and original cookie)
    let req_replay = Request::builder()
        .method(Method::GET)
        .uri(&callback_uri)
        .header(header::ACCEPT, "application/json")
        .header(header::COOKIE, format!("oauth_state={state_cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp_replay = app.dispatch(req_replay).await;
    assert_eq!(resp_replay.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp_replay.error_code(), Some(ErrorCode::OAuthStateInvalid));
}

#[tokio::test]
async fn test_security_zero_secret_leakage_in_tracing_logs() {
    let _guard = DB_LOCK.lock().await;
    let server = MockServer::start().await;

    let log_scope = TestLogScope::new();

    let canary_access_token = "canary_access_token_super_secret_998877";
    let canary_refresh_token = "canary_refresh_token_super_secret_112233";
    let canary_client_secret = "canary_client_secret_super_secret_445566";
    let canary_auth_code = "canary_authorization_code_super_secret_778899";
    let test_email = dynamic_email();

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": canary_access_token,
            "refresh_token": canary_refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": "leak-audit-sub-001",
            "email": test_email,
            "email_verified": true,
            "name": "Audit User"
        })))
        .mount(&server)
        .await;

    let google_cfg = ProviderConfig {
        client_id: "google-id".to_string(),
        client_secret: canary_client_secret.to_string(),
        redirect_uri: "https://example.com/auth/oauth/google/callback".to_string(),
        scopes: vec![],
        enabled: true,
        team_id: None,
        key_id: None,
        private_key: None,
    };
    let google = GoogleProvider::with_endpoints(
        &google_cfg,
        reqwest::Client::new(),
        format!("{}/auth", server.uri()),
        format!("{}/token", server.uri()),
        format!("{}/userinfo", server.uri()),
    )
    .unwrap();

    let mut providers: HashMap<String, Arc<dyn OAuthProvider>> = HashMap::new();
    providers.insert("google".to_string(), Arc::new(google));

    let Some(app) = setup_oauth_test_app(providers).await else {
        return;
    };

    // 1. Initiate flow
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/google?redirect_url=/dashboard")
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    let state_token = extract_state_from_location(&resp.headers);
    let state_cookie = extract_cookie_value(&resp.headers, "oauth_state").unwrap();

    // 2. Callback flow
    let callback_uri =
        format!("/auth/oauth/google/callback?code={canary_auth_code}&state={state_token}");
    let req = Request::builder()
        .method(Method::GET)
        .uri(&callback_uri)
        .header(header::ACCEPT, "application/json")
        .header(header::COOKIE, format!("oauth_state={state_cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let logs = log_scope.text();

    // Assert that tracing events were logged
    assert!(
        logs.contains("oauth_initiate"),
        "oauth_initiate event should be recorded in logs"
    );
    assert!(
        logs.contains("oauth_callback_success") || logs.contains("oauth_user_created"),
        "oauth callback success events should be recorded in logs"
    );

    // Strict zero leakage audit
    assert!(
        !logs.contains(canary_access_token),
        "access token leaked in tracing logs: {logs}"
    );
    assert!(
        !logs.contains(canary_refresh_token),
        "refresh token leaked in tracing logs: {logs}"
    );
    assert!(
        !logs.contains(canary_client_secret),
        "client secret leaked in tracing logs: {logs}"
    );
    assert!(
        !logs.contains(canary_auth_code),
        "authorization code leaked in tracing logs: {logs}"
    );
}
