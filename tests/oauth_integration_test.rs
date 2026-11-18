mod common;

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use chrono::Utc;
use common::*;
use jsonwebtoken::{Algorithm, Header, encode};
use metal_auth::{
    AppleProvider, GitHubProvider, GoogleProvider, OAuthAccount, OAuthProvider, OAuthService,
    ProviderConfig, SessionService, User,
};
use serde::Serialize;
use wiremock::matchers::{header as wm_header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_EC_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg80bQVIVk8j478T1G\nbpAeMo50IbEghq+GGg0l0/0rPlahRANCAAQH8ORbGJ8Lv2FAtRIwd1UhQcFxjSut\nhcBWj2+0aSbPnGktPO19SuWvGeqDUtSF95/eUScRQ9Ww6XHj+fWMn8R+\n-----END PRIVATE KEY-----";

const TEST_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC9JztAtKCKHeqw\nO/NFph+PsTY+DkJrhrvgcnbt9NleRcJ1qPNi6ADQ8y8QCEZPz+GBrKJ57dCJRhqW\nIA8rA9dbm7vlH5wRVOj5M9p3Wt7dGZmDxSPxZ35yzgMhH+Q13j245NW5CbnVRgr8\nxMt3Sdc6ObmcioBAnzzLCA0h2VWJIbbgWdzQb+IWqt+rNjzDlMNCwIowHfsNyLK5\nKPCw4XUCKXKKzsly9XGJp/L1dNVjzSROdu8RZXn/swiAgEZ3hXi564dJcrj+FXsx\nehXGhNnUYKw6QNMKG5bzb0rZuIAEVS4hpkuc6yVVYXBzD6q2HXSjn+FibXRx2wPI\nGbDUTVKJAgMBAAECggEAGNJFHECXsIgse+PiEIm0Ko7+pzYH0URk8xcSNDelLpHI\n6te42InJUaIX0urDD0YgOXwF9ioW62yfoIOkeeiPIh5VkcOMH1odGFaNnIv4Ittx\nIbGE/fCuzzHphzdAIzF+t/yPbzCviiUe2/yXFphB/goFKV2jZtd+isYLsx1p9AyW\nwSXlWpRC0ont8exXVy57QwKamIUJ9Avqkg/OM+BDCJm+YjH/aDXDJ3MbWkQ1HjNx\n7JeZzPO9ILoRoGeZ3KtsNV9DOtpHmKqxOqPcGkphRcL+KXtRXkDfJGj3haRtJXEA\nlJb0kzFfUimSSyja2fxLWg7TwKz+HlB/YfOXkaf8YQKBgQDj2jiGJyD7nnf2/TZ2\nR1BnkjwwYkQrG/HJ0KlGg8jfxS8UahHHeZqSMOU0Bb4Z5jP7TNwyqNMTC2zx35vP\nXZQyyBcZM/yVbQX+/3BsxIv6q2klz/+HiI88hT9nHOURKXdcSA3yYu5y9ZQU96Ib\nwJRe8bxu12S/7dxAQYMht4XiSwKBgQDUhSiG/VLJsLwQGJ4ZurlzOI7mc5tYmr5s\nLurR1fuP+TREDa0BMaPhkq4us7c6G/G+jomjRK+hpEhmVOOu799i+VjRUza4jeWE\nIitGeRZLgmFhXsfCSniqSb+b3GGE8kJfnVwQh66DHgyR4BE4MRiGJVI/W58+xrcm\n/sKR0Fl5+wKBgB8E5FEPHqRirH5JdpKfnsia1erYVeNwiHgrGgBpjH06QPCMiCMZ\n4PsqAOoWJg0sk8MQcaHL7gBXu9spz/JpEPXg25QoyagmEXznlYyZLV1Q3J2zNVxk\nMOvSUBFfk6fEd2VuwcdPxJqN6Dz6gW05yHkse7SzShn+7c8pnAqJC4cFAoGAFqxe\nNoiwXHROnCkENRqGzpQqKswKttlLl58pzllWDXY47UnIO2hgY6CSlMj3s2tnzzzF\n0nVxh31PfBtybyeIXbbckvidzfLVmdNLaqlgh43RdeH2zfPEC+byWl6YyOZPzoOr\nXtga9kIudSHCtIwIYcd5jujnhHsO70oe2A+yfCECgYBSZcbi2qrjyHTahqqWQkx1\nZPvNNEfsMUT+61vwCTCKvtYoFurP1qHMwwGNQU1jb0z66beBq2JzsMs25EopkAJ4\nzzllk6vQJkvzYkPDb9ntLDK7fpM3MeuDlq79VsJKpPhK/GxUDZiXRKnVOx13RXG5\nqaFHQWXrR+Tne43oPjXUXw==\n-----END PRIVATE KEY-----";

const TEST_RSA_N: &str = "vSc7QLSgih3qsDvzRaYfj7E2Pg5Ca4a74HJ27fTZXkXCdajzYugA0PMvEAhGT8_hgayiee3QiUYaliAPKwPXW5u75R-cEVTo-TPad1re3RmZg8Uj8Wd-cs4DIR_kNd49uOTVuQm51UYK_MTLd0nXOjm5nIqAQJ88ywgNIdlViSG24Fnc0G_iFqrfqzY8w5TDQsCKMB37DciyuSjwsOF1Ailyis7JcvVxiafy9XTVY80kTnbvEWV5_7MIgIBGd4V4ueuHSXK4_hV7MXoVxoTZ1GCsOkDTChuW829K2biABFUuIaZLnOslVWFwcw-qth10o5_hYm10cdsDyBmw1E1SiQ";
const TEST_RSA_E: &str = "AQAB";

#[derive(Debug, Serialize)]
struct MockAppleClaims {
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
    sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<serde_json::Value>,
}

fn mint_test_apple_id_token(kid: &str, claims: MockAppleClaims) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_PEM.as_bytes()).unwrap();
    encode(&header, &claims, &encoding_key).unwrap()
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
async fn test_oauth_google_end_to_end_flow() {
    let _guard = DB_LOCK.lock().await;
    let server = MockServer::start().await;

    let test_email = dynamic_email();
    let test_sub = format!("google-user-{}", uuid::Uuid::new_v4());

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "goog-at-test",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .and(wm_header("Authorization", "Bearer goog-at-test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": &test_sub,
            "email": test_email,
            "email_verified": true,
            "name": "Test Google User"
        })))
        .mount(&server)
        .await;

    let google_cfg = ProviderConfig {
        client_id: "google-id".to_string(),
        client_secret: "google-secret".to_string(),
        redirect_uri: "https://example.com/auth/oauth/google/callback".to_string(),
        redirect_url: "https://example.com/auth/oauth/google/callback".to_string(),
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

    // 1. Initiate flow: GET /auth/oauth/google?redirect_url=/dashboard
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/google?redirect_url=/dashboard")
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::FOUND);

    let state_token = extract_state_from_location(&resp.headers);
    let state_cookie = extract_cookie_value(&resp.headers, "oauth_state")
        .expect("oauth_state cookie set on initiate");

    // 2. Callback flow: GET /auth/oauth/google/callback (Browser flow -> 302 redirect)
    let callback_uri = format!("/auth/oauth/google/callback?code=good_code&state={state_token}");
    let req = Request::builder()
        .method(Method::GET)
        .uri(&callback_uri)
        .header(header::COOKIE, format!("oauth_state={state_cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(resp.header(header::LOCATION.as_str()), Some("/dashboard"));

    // Verify session cookie set and oauth_state cookie cleared
    let session_cookie_name = &app.state.config.session.cookie_name;
    let session_cookie = extract_cookie_value(&resp.headers, session_cookie_name)
        .expect("session cookie set on callback");
    let cleared_state_cookie = extract_cookie_value(&resp.headers, "oauth_state")
        .expect("oauth_state cleared on callback");
    assert_eq!(cleared_state_cookie, "");

    // 3. Verify user and oauth_accounts row created in DB
    let user_row: User = sqlx::query_as::<_, User>(
        "SELECT id, email, password_hash, email_verified, created_at, updated_at FROM users WHERE email = $1",
    )
    .bind(&test_email)
    .fetch_one(&app.pool)
    .await
    .expect("user provisioned in users table");
    assert!(user_row.email_verified);
    assert!(
        user_row.password_hash.starts_with("$unusable$oauth$") || user_row.password_hash.is_empty()
    );

    let oauth_row: OAuthAccount = sqlx::query_as::<_, OAuthAccount>(
        "SELECT id, user_id, provider_id, provider_user_id, email, created_at, updated_at FROM oauth_accounts WHERE user_id = $1",
    )
    .bind(user_row.id)
    .fetch_one(&app.pool)
    .await
    .expect("oauth link row created");
    assert_eq!(oauth_row.provider_id, "google");
    assert_eq!(oauth_row.provider_user_id, test_sub);

    // 4. Authenticated request: GET /auth/oauth/accounts
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/accounts")
        .header(
            header::COOKIE,
            format!("{session_cookie_name}={session_cookie}"),
        )
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let accounts: Vec<serde_json::Value> =
        serde_json::from_str(&resp.body_str).expect("accounts list json");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["provider_id"], "google");
    assert_eq!(accounts[0]["provider_user_id"], test_sub);
}

#[tokio::test]
async fn test_oauth_bearer_flow_transport() {
    let _guard = DB_LOCK.lock().await;
    let server = MockServer::start().await;

    let test_email = dynamic_email();

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "goog-bearer-at",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": "google-bearer-002",
            "email": test_email,
            "email_verified": true,
            "name": "Bearer Google User"
        })))
        .mount(&server)
        .await;

    let google_cfg = ProviderConfig {
        client_id: "google-id".to_string(),
        client_secret: "google-secret".to_string(),
        redirect_uri: "https://example.com/auth/oauth/google/callback".to_string(),
        redirect_url: "https://example.com/auth/oauth/google/callback".to_string(),
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

    // Callback with X-Auth-Type: bearer
    let callback_uri = format!("/auth/oauth/google/callback?code=bearer_code&state={state_token}");
    let req = Request::builder()
        .method(Method::GET)
        .uri(&callback_uri)
        .header("x-auth-type", "bearer")
        .header(header::COOKIE, format!("oauth_state={state_cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify raw token returned in response body and no session cookie set
    let json = resp.json();
    let raw_token = json["token"].as_str().expect("raw token in body");
    assert!(!raw_token.is_empty());
    assert!(extract_cookie_value(&resp.headers, &app.state.config.session.cookie_name).is_none());

    // Verify session works via Authorization: Bearer <token>
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/session")
        .header(header::AUTHORIZATION, format!("Bearer {raw_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.json()["session_type"], "bearer");
}

#[tokio::test]
async fn test_oauth_auto_links_verified_existing_local_user() {
    let _guard = DB_LOCK.lock().await;
    let server = MockServer::start().await;

    let test_email = dynamic_email();
    let test_sub = format!("google-existing-user-{}", uuid::Uuid::new_v4());

    let mut providers: HashMap<String, Arc<dyn OAuthProvider>> = HashMap::new();
    let google_cfg = ProviderConfig {
        client_id: "google-id".to_string(),
        client_secret: "google-secret".to_string(),
        redirect_uri: "https://example.com/auth/oauth/google/callback".to_string(),
        redirect_url: "https://example.com/auth/oauth/google/callback".to_string(),
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

    // Pre-create verified local user
    let existing_user_id = uuid::Uuid::new_v4();
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(existing_user_id)
    .bind(&test_email)
    .bind("some_hash")
    .bind(true)
    .bind(now)
    .bind(now)
    .execute(&app.pool)
    .await
    .unwrap();

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "goog-link-at",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": &test_sub,
            "email": test_email,
            "email_verified": true,
            "name": "Existing User"
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
    let callback_uri = format!("/auth/oauth/google/callback?code=link_code&state={state_token}");
    let req = Request::builder()
        .method(Method::GET)
        .uri(&callback_uri)
        .header(header::ACCEPT, "application/json")
        .header(header::COOKIE, format!("oauth_state={state_cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Assert existing user ID was linked, not duplicated
    assert_eq!(
        resp.json()["user_id"].as_str().unwrap(),
        existing_user_id.to_string()
    );

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1")
        .bind(&test_email)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);

    let link: OAuthAccount = sqlx::query_as::<_, OAuthAccount>(
        "SELECT id, user_id, provider_id, provider_user_id, email, created_at, updated_at FROM oauth_accounts WHERE user_id = $1"
    )
    .bind(existing_user_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(link.provider_id, "google");
    assert_eq!(link.provider_user_id, test_sub);
}

#[tokio::test]
async fn test_oauth_multi_provider_link_and_unlink_lifecycle() {
    let _guard = DB_LOCK.lock().await;
    let server = MockServer::start().await;

    let test_email = dynamic_email();
    let google_sub = format!("google-multi-{}", uuid::Uuid::new_v4());
    let github_id: u64 =
        Utc::now().timestamp_nanos_opt().unwrap_or(0).unsigned_abs() % 900_000_000 + 100_000_000;

    // Google mocks
    Mock::given(method("POST"))
        .and(path("/google/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "google-at-multi",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/google/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": &google_sub,
            "email": test_email,
            "email_verified": true,
            "name": "Multi User"
        })))
        .mount(&server)
        .await;

    // GitHub mocks
    Mock::given(method("POST"))
        .and(path("/github/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "github-at-multi",
            "token_type": "Bearer",
            "scope": "read:user,user:email"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/github/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": github_id,
            "login": "multiverse",
            "email": null
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/github/user/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "email": test_email,
                "primary": true,
                "verified": true
            }
        ])))
        .mount(&server)
        .await;

    let google_cfg = ProviderConfig {
        client_id: "google-id".to_string(),
        client_secret: "google-secret".to_string(),
        redirect_uri: "https://example.com/auth/oauth/google/callback".to_string(),
        redirect_url: "https://example.com/auth/oauth/google/callback".to_string(),
        scopes: vec![],
        enabled: true,
        team_id: None,
        key_id: None,
        private_key: None,
    };
    let google = GoogleProvider::with_endpoints(
        &google_cfg,
        reqwest::Client::new(),
        format!("{}/google/auth", server.uri()),
        format!("{}/google/token", server.uri()),
        format!("{}/google/userinfo", server.uri()),
    )
    .unwrap();

    let github_cfg = ProviderConfig {
        client_id: "github-id".to_string(),
        client_secret: "github-secret".to_string(),
        redirect_uri: "https://example.com/auth/oauth/github/callback".to_string(),
        redirect_url: "https://example.com/auth/oauth/github/callback".to_string(),
        scopes: vec![],
        enabled: true,
        team_id: None,
        key_id: None,
        private_key: None,
    };
    let github = GitHubProvider::with_endpoints(
        &github_cfg,
        reqwest::Client::new(),
        format!("{}/github/auth", server.uri()),
        format!("{}/github/token", server.uri()),
        format!("{}/github/user", server.uri()),
        format!("{}/github/user/emails", server.uri()),
    )
    .unwrap();

    let mut providers: HashMap<String, Arc<dyn OAuthProvider>> = HashMap::new();
    providers.insert("google".to_string(), Arc::new(google));
    providers.insert("github".to_string(), Arc::new(github));

    let Some(app) = setup_oauth_test_app(providers).await else {
        return;
    };

    // 1. Log in with Google
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/google")
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    let state_token = extract_state_from_location(&resp.headers);
    let state_cookie = extract_cookie_value(&resp.headers, "oauth_state").unwrap();

    let callback_uri = format!("/auth/oauth/google/callback?code=gcode&state={state_token}");
    let req = Request::builder()
        .method(Method::GET)
        .uri(&callback_uri)
        .header(header::ACCEPT, "application/json")
        .header(header::COOKIE, format!("oauth_state={state_cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let session_cookie_name = &app.state.config.session.cookie_name;
    let session_cookie = extract_cookie_value(&resp.headers, session_cookie_name).unwrap();
    let csrf_cookie = extract_cookie_value(&resp.headers, "csrf_token").unwrap();

    // 2. Initiate GitHub flow to get valid state cookie and token for linking
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/github")
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    let gh_state_token = extract_state_from_location(&resp.headers);
    let gh_state_cookie = extract_cookie_value(&resp.headers, "oauth_state").unwrap();

    // 3. Link GitHub account via POST /auth/oauth/github/link (requires session + CSRF)
    let link_body = serde_json::json!({
        "code": "gh_code_valid",
        "state": gh_state_token,
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/auth/oauth/github/link")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-csrf-token", &csrf_cookie)
        .header(
            header::COOKIE,
            format!("{session_cookie_name}={session_cookie}; csrf_token={csrf_cookie}; oauth_state={gh_state_cookie}"),
        )
        .body(Body::from(serde_json::to_vec(&link_body).unwrap()))
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.json()["provider_id"], "github");
    let state_cleared = resp.headers.get_all(header::SET_COOKIE).iter().any(|v| {
        let s = v.to_str().unwrap_or("");
        s.contains("oauth_state=") && s.contains("Max-Age=0")
    });
    assert!(
        state_cleared,
        "oauth_state cookie must be cleared upon linking"
    );

    // 4. Verify list accounts returns both Google and GitHub
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/accounts")
        .header(
            header::COOKIE,
            format!("{session_cookie_name}={session_cookie}"),
        )
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let accounts: Vec<serde_json::Value> = serde_json::from_str(&resp.body_str).unwrap();
    assert_eq!(accounts.len(), 2);

    // 5. Unlink GitHub account via POST /auth/oauth/github/unlink
    let req = Request::builder()
        .method(Method::POST)
        .uri("/auth/oauth/github/unlink")
        .header("x-csrf-token", &csrf_cookie)
        .header(
            header::COOKIE,
            format!("{session_cookie_name}={session_cookie}; csrf_token={csrf_cookie}"),
        )
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.json()["message"], "account unlinked");

    // 6. Verify list accounts now returns 1 account (Google)
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/accounts")
        .header(
            header::COOKIE,
            format!("{session_cookie_name}={session_cookie}"),
        )
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    let accounts: Vec<serde_json::Value> = serde_json::from_str(&resp.body_str).unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["provider_id"], "google");

    // 7. Lockout prevention: attempt to unlink remaining Google account without a password
    let req = Request::builder()
        .method(Method::POST)
        .uri("/auth/oauth/google/unlink")
        .header("x-csrf-token", &csrf_cookie)
        .header(
            header::COOKIE,
            format!("{session_cookie_name}={session_cookie}; csrf_token={csrf_cookie}"),
        )
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.json()["message"],
        "Cannot unlink the only authentication method"
    );

    // Assert Google account is still linked
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/accounts")
        .header(
            header::COOKIE,
            format!("{session_cookie_name}={session_cookie}"),
        )
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    let accounts: Vec<serde_json::Value> = serde_json::from_str(&resp.body_str).unwrap();
    assert_eq!(accounts.len(), 1);
}

#[tokio::test]
async fn test_oauth_apple_form_post_callback() {
    let _guard = DB_LOCK.lock().await;
    let server = MockServer::start().await;

    let test_email = dynamic_email();

    let now = Utc::now().timestamp();
    let claims = MockAppleClaims {
        iss: "https://appleid.apple.com".to_string(),
        aud: "com.example.app".to_string(),
        exp: now + 3600,
        iat: now,
        sub: "apple-form-post-001".to_string(),
        email: Some(test_email.clone()),
        email_verified: Some(serde_json::Value::Bool(true)),
    };
    let id_token = mint_test_apple_id_token("kid-apple-1", claims);

    Mock::given(method("POST"))
        .and(path("/auth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "apple-at-test",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/auth/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "kid-apple-1",
                    "use": "sig",
                    "alg": "RS256",
                    "n": TEST_RSA_N,
                    "e": TEST_RSA_E
                }
            ]
        })))
        .mount(&server)
        .await;

    let apple_cfg = ProviderConfig {
        client_id: "com.example.app".to_string(),
        client_secret: "".to_string(),
        redirect_uri: "https://example.com/auth/oauth/apple/callback".to_string(),
        redirect_url: "https://example.com/auth/oauth/apple/callback".to_string(),
        scopes: vec![],
        enabled: true,
        team_id: Some("TEAM123456".to_string()),
        key_id: Some("KEY1234567".to_string()),
        private_key: Some(TEST_EC_PEM.to_string()),
    };

    let apple = AppleProvider::with_endpoints(
        &apple_cfg,
        reqwest::Client::new(),
        format!("{}/auth", server.uri()),
        format!("{}/auth/token", server.uri()),
        format!("{}/auth/keys", server.uri()),
    )
    .unwrap();

    let mut providers: HashMap<String, Arc<dyn OAuthProvider>> = HashMap::new();
    providers.insert("apple".to_string(), Arc::new(apple));

    let Some(app) = setup_oauth_test_app(providers).await else {
        return;
    };

    // Initiate Apple flow
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/apple")
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    let state_token = extract_state_from_location(&resp.headers);
    let state_cookie = extract_cookie_value(&resp.headers, "oauth_state").unwrap();

    // Apple form_post: POST /auth/oauth/apple/callback (no CSRF token, raw POST)
    let form_body = format!("code=apple_code_001&state={state_token}");
    let req = Request::builder()
        .method(Method::POST)
        .uri("/auth/oauth/apple/callback")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .header(header::COOKIE, format!("oauth_state={state_cookie}"))
        .body(Body::from(form_body))
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let session_cookie = extract_cookie_value(&resp.headers, &app.state.config.session.cookie_name)
        .expect("session cookie set on Apple form_post callback");

    // Verify session
    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth/oauth/accounts")
        .header(
            header::COOKIE,
            format!("{}={session_cookie}", app.state.config.session.cookie_name),
        )
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let accounts: Vec<serde_json::Value> = serde_json::from_str(&resp.body_str).unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["provider_id"], "apple");
}

#[tokio::test]
async fn test_oauth_api_alias_routes() {
    let _guard = DB_LOCK.lock().await;
    let server = MockServer::start().await;

    let test_email = dynamic_email();
    let test_sub = format!("google-alias-{}", uuid::Uuid::new_v4());

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "goog-alias-at",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": &test_sub,
            "email": test_email,
            "email_verified": true,
            "name": "Alias User"
        })))
        .mount(&server)
        .await;

    let google_cfg = ProviderConfig {
        client_id: "google-id".to_string(),
        client_secret: "google-secret".to_string(),
        redirect_uri: "https://example.com/api/auth/oauth/google/callback".to_string(),
        redirect_url: "https://example.com/api/auth/oauth/google/callback".to_string(),
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

    // 1. Alias Initiate: GET /api/auth/oauth/google
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/auth/oauth/google")
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let state_token = extract_state_from_location(&resp.headers);
    let state_cookie = extract_cookie_value(&resp.headers, "oauth_state").unwrap();

    // 2. Alias Callback: GET /api/auth/oauth/google/callback
    let callback_uri =
        format!("/api/auth/oauth/google/callback?code=alias_code&state={state_token}");
    let req = Request::builder()
        .method(Method::GET)
        .uri(&callback_uri)
        .header(header::ACCEPT, "application/json")
        .header(header::COOKIE, format!("oauth_state={state_cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.json()["user_id"].is_string());
}
