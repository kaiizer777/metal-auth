use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::config::ProviderConfig;
use crate::error::AppError;

pub use crate::config::SUPPORTED_PROVIDERS;
pub const OAUTH_HTTP_TIMEOUT: Duration = Duration::from_secs(10);
pub const OAUTH_BODY_LIMIT: usize = 1024 * 1024; // 1 MiB
pub const USER_AGENT: &str = "metal-auth";

/// Normalized user profile data retrieved from an OAuth provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    pub provider_id: String,
    pub provider_user_id: String,
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

pub type OAuthUserInfo = UserInfo;

/// Token credentials received from the provider's token exchange endpoint.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub id_token: Option<String>,
    #[serde(default)]
    pub raw: HashMap<String, serde_json::Value>,
}

pub type OAuthTokenResponse = TokenResponse;

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_in", &self.expires_in)
            .field("id_token", &self.id_token.as_ref().map(|_| "[REDACTED]"))
            .field("raw", &"[REDACTED]")
            .finish()
    }
}

/// Trait defining the contract required for any OAuth2 / OIDC identity provider.
///
/// - `id` is the canonical slug and must match both `ProviderConfig` key and `SUPPORTED_PROVIDERS`.
/// - `provider_user_id` must be stable across logins: Google `sub`, GitHub numeric id, Apple `sub`.
/// - `email_verified` is `true` only when the provider asserts the address is verified **and** the
///   address is non-empty; callers refuse to provision or link an identity on `false`.
/// - `fetch_user_info` rejects malformed provider responses with `AppError::OAuthProviderError`.
#[async_trait]
pub trait OAuthProvider: Send + Sync + std::fmt::Debug {
    /// Canonical provider slug (e.g. "google", "github", "apple").
    fn id(&self) -> &'static str;

    /// Constructs the provider authorization URL with PKCE challenge, state, and scopes.
    fn auth_url(&self, state: &str, code_challenge: &str) -> String;

    /// Alias for `auth_url`, retained for API compatibility.
    fn get_authorization_url(&self, state: &str, code_challenge: &str) -> String {
        self.auth_url(state, code_challenge)
    }

    /// Exchanges an authorization code and PKCE code verifier for tokens.
    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, AppError>;

    /// Retrieves and normalizes user profile information using the granted access/ID tokens.
    async fn fetch_user_info(&self, tokens: &TokenResponse) -> Result<UserInfo, AppError>;

    /// Alias for `fetch_user_info`.
    async fn get_user_info(&self, token_response: &TokenResponse) -> Result<UserInfo, AppError> {
        self.fetch_user_info(token_response).await
    }
}

/// Builds an HTTP client configured with bounded timeout and library user-agent.
pub fn build_oauth_http_client() -> Result<reqwest::Client, AppError> {
    reqwest::Client::builder()
        .timeout(OAUTH_HTTP_TIMEOUT)
        .user_agent(USER_AGENT)
        .build()
        .map_err(|_| AppError::OAuthProviderError)
}

/// Joins configured scopes, falling back to provider defaults.
pub fn scopes_or_default(configured: &[String], defaults: &[&str]) -> String {
    if !configured.is_empty() {
        configured.join(" ")
    } else {
        defaults.join(" ")
    }
}

/// Parses a provider endpoint at construction time.
///
/// A malformed endpoint is a configuration error: it must never degrade into a redirect to the
/// hardcoded canonical host, which would start a real login round-trip at a provider the operator
/// did not configure.
pub(crate) fn parse_endpoint(endpoint: &str) -> Result<reqwest::Url, AppError> {
    reqwest::Url::parse(endpoint).map_err(|_| AppError::OAuthProviderError)
}

/// Appends `params` as query pairs to an already-validated authorize endpoint.
pub(crate) fn authorize_url(base: &reqwest::Url, params: &[(&str, &str)]) -> String {
    let mut url = base.clone(); // a clone per authorize call is the allocation the former parse paid
    url.query_pairs_mut().extend_pairs(params);
    url.to_string()
}

/// Form fields for the authorization-code token exchange, identical across providers.
pub(crate) fn token_exchange_params<'a>(
    client_id: &'a str,
    client_secret: &'a str,
    code: &'a str,
    redirect_uri: &'a str,
    code_verifier: &'a str,
) -> [(&'a str, &'a str); 6] {
    [
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code", code),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect_uri),
        ("code_verifier", code_verifier),
    ]
}

/// Reads an HTTP response body up to `OAUTH_BODY_LIMIT` (1 MiB) and parses it as JSON.
/// Returns AppError::OAuthProviderError if the Content-Length or streamed body exceeds the limit.
pub async fn read_json_limited<T: serde::de::DeserializeOwned>(
    mut resp: reqwest::Response,
) -> Result<T, AppError> {
    if let Some(len) = resp.content_length()
        && len > OAUTH_BODY_LIMIT as u64
    {
        return Err(AppError::OAuthProviderError);
    }

    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|_| AppError::OAuthProviderError)?
    {
        if body.len() + chunk.len() > OAUTH_BODY_LIMIT {
            return Err(AppError::OAuthProviderError);
        }
        body.extend_from_slice(&chunk);
    }

    serde_json::from_slice(&body).map_err(|_| AppError::OAuthProviderError)
}

/// GETs `url`, attaching a bearer token when supplied, and parses the JSON body under the 1 MiB cap.
pub(crate) async fn get_json_limited<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    accept: &str,
    bearer: Option<&str>,
) -> Result<T, AppError> {
    let mut request = client
        .get(url)
        .header(reqwest::header::ACCEPT, accept)
        .header(reqwest::header::USER_AGENT, USER_AGENT);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }

    let resp = request
        .send()
        .await
        .map_err(|_| AppError::OAuthProviderError)?;

    if !resp.status().is_success() {
        return Err(AppError::OAuthProviderError);
    }

    read_json_limited(resp).await
}

/// Sends an HTTP POST form request for token exchange, parsing the JSON token response.
pub async fn post_token_form(
    client: &reqwest::Client,
    endpoint: &str,
    params: &[(&str, &str)],
) -> Result<TokenResponse, AppError> {
    let resp = client
        .post(endpoint)
        .header(reqwest::header::ACCEPT, "application/json")
        .form(params)
        .send()
        .await
        .map_err(|_| AppError::OAuthProviderError)?;

    if !resp.status().is_success() {
        return Err(AppError::OAuthProviderError);
    }

    let raw: HashMap<String, serde_json::Value> = read_json_limited(resp).await?;

    if let Some(err) = raw.get("error")
        && !err.is_null()
    {
        return Err(AppError::OAuthProviderError);
    }

    Ok(token_from_raw(raw))
}

/// Parses a token response from a generic JSON map.
pub fn token_from_raw(raw: HashMap<String, serde_json::Value>) -> TokenResponse {
    // A missing or non-string `access_token` yields `""` rather than an error: Apple authorizes on
    // `id_token` alone and every provider checks emptiness where it matters.
    let access_token = raw
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .map_or_else(String::new, ToString::to_string);

    let token_type = raw
        .get("token_type")
        .and_then(|v| v.as_str())
        .unwrap_or("Bearer")
        .to_string();

    let refresh_token = raw
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);

    let id_token = raw
        .get("id_token")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);

    let expires_in = raw.get("expires_in").and_then(|v| {
        v.as_i64()
            .or_else(|| v.as_u64().map(|u| u as i64))
            .or_else(|| v.as_f64().map(|f| f as i64))
            .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
    });

    TokenResponse {
        access_token,
        token_type,
        refresh_token,
        expires_in,
        id_token,
        raw,
    }
}

/// Instantiates a concrete OAuth provider strictly matching the locked Big 3.
/// Deferred (e.g. "microsoft", "discord") or unknown providers return AppError::OAuthProviderNotFound.
pub fn create_provider(
    id: &str,
    cfg: &ProviderConfig,
    client: reqwest::Client,
) -> Result<Arc<dyn OAuthProvider>, AppError> {
    if !cfg.enabled {
        return Err(AppError::OAuthProviderNotFound);
    }
    match id {
        "google" => Ok(Arc::new(crate::oauth::google::GoogleProvider::new(
            cfg, client,
        )?)),
        "github" => Ok(Arc::new(crate::oauth::github::GitHubProvider::new(
            cfg, client,
        )?)),
        "apple" => Ok(Arc::new(crate::oauth::apple::AppleProvider::new(
            cfg, client,
        )?)),
        _ => Err(AppError::OAuthProviderNotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_provider_cfg(enabled: bool) -> ProviderConfig {
        ProviderConfig {
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            scopes: vec![],
            enabled,
            team_id: None,
            key_id: None,
            private_key: None,
        }
    }

    #[test]
    fn test_supported_providers_constant() {
        assert_eq!(SUPPORTED_PROVIDERS, &["google", "github", "apple"]);
    }

    #[test]
    fn test_create_provider_supported() {
        let client = reqwest::Client::new();
        let cfg = test_provider_cfg(true);

        let google = create_provider("google", &cfg, client.clone()).unwrap();
        assert_eq!(google.id(), "google");

        let github = create_provider("github", &cfg, client.clone()).unwrap();
        assert_eq!(github.id(), "github");

        let apple = create_provider("apple", &cfg, client).unwrap();
        assert_eq!(apple.id(), "apple");
    }

    #[test]
    fn test_create_provider_disabled_returns_not_found() {
        let client = reqwest::Client::new();
        let cfg = test_provider_cfg(false);

        let err = create_provider("google", &cfg, client).unwrap_err();
        assert!(matches!(err, AppError::OAuthProviderNotFound));
    }

    #[test]
    fn test_create_provider_unsupported_slugs() {
        let client = reqwest::Client::new();
        let cfg = test_provider_cfg(true);

        for unknown in &["microsoft", "discord", "facebook", "unknown", ""] {
            let err = create_provider(unknown, &cfg, client.clone()).unwrap_err();
            assert!(matches!(err, AppError::OAuthProviderNotFound));
        }
    }

    /// Guards the three provider tables (constant, env parsing, factory) against drift: a slug
    /// added to only one of them would compile, pass every other test, and 404 at runtime.
    #[test]
    fn every_supported_provider_round_trips_config_and_factory() {
        let config = crate::config::Config::from_lookup(|key| match key {
            "DATABASE_URL" => Ok("postgres://localhost/test".into()),
            "BASE_URL" => Ok("https://app.example.com".into()),
            _ => Err(std::env::VarError::NotPresent),
        })
        .expect("minimal config");

        let client = reqwest::Client::new();
        let provider_cfg = test_provider_cfg(true);

        for slug in SUPPORTED_PROVIDERS {
            assert!(
                config.oauth.providers.contains_key(*slug),
                "config env parsing has no provider entry for {slug}"
            );
            let provider = create_provider(slug, &provider_cfg, client.clone())
                .unwrap_or_else(|e| panic!("provider factory rejects {slug}: {e:?}"));
            assert_eq!(provider.id(), *slug);
        }
    }

    #[test]
    fn test_token_from_raw_parsing() {
        let mut raw = HashMap::new();
        raw.insert("access_token".to_string(), serde_json::json!("tok_123"));
        raw.insert("token_type".to_string(), serde_json::json!("Bearer"));
        raw.insert("refresh_token".to_string(), serde_json::json!("ref_456"));
        raw.insert("id_token".to_string(), serde_json::json!("id_jwt_789"));
        raw.insert("expires_in".to_string(), serde_json::json!(3600));

        let tok = token_from_raw(raw);
        assert_eq!(tok.access_token, "tok_123");
        assert_eq!(tok.token_type, "Bearer");
        assert_eq!(tok.refresh_token.as_deref(), Some("ref_456"));
        assert_eq!(tok.id_token.as_deref(), Some("id_jwt_789"));
        assert_eq!(tok.expires_in, Some(3600));

        // Test string expires_in fallback
        let mut raw_str = HashMap::new();
        raw_str.insert("access_token".to_string(), serde_json::json!("tok"));
        raw_str.insert("expires_in".to_string(), serde_json::json!("7200"));
        let tok2 = token_from_raw(raw_str);
        assert_eq!(tok2.expires_in, Some(7200));
    }

    #[test]
    fn test_scopes_or_default() {
        let defaults = &["scope1", "scope2"];
        assert_eq!(scopes_or_default(&[], defaults), "scope1 scope2");

        let custom = vec!["custom_a".to_string(), "custom_b".to_string()];
        assert_eq!(scopes_or_default(&custom, defaults), "custom_a custom_b");
    }

    #[test]
    fn test_token_from_raw_missing_or_non_string_access_token() {
        let missing = token_from_raw(HashMap::new());
        assert!(missing.access_token.is_empty());
        assert_eq!(missing.token_type, "Bearer");

        let mut non_string = HashMap::new();
        non_string.insert("access_token".to_string(), serde_json::json!(123));
        assert!(token_from_raw(non_string).access_token.is_empty());
    }

    #[test]
    fn test_token_response_debug_redacts_secrets() {
        let tok = TokenResponse {
            access_token: "secret-access-token".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: Some("secret-refresh-token".to_string()),
            expires_in: Some(3600),
            id_token: Some("secret-id-jwt".to_string()),
            raw: HashMap::new(),
        };

        let debug_str = format!("{tok:?}");
        assert!(!debug_str.contains("secret-access-token"));
        assert!(!debug_str.contains("secret-refresh-token"));
        assert!(!debug_str.contains("secret-id-jwt"));
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn test_read_json_limited_enforces_body_limit() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // Oversized body (> 1 MiB)
        let oversized = vec![b'a'; OAUTH_BODY_LIMIT + 10];
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(oversized))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let resp = client.get(server.uri()).send().await.unwrap();

        let res: Result<serde_json::Value, AppError> = read_json_limited(resp).await;
        assert!(matches!(res, Err(AppError::OAuthProviderError)));
    }

    #[tokio::test]
    async fn test_read_json_limited_accepts_body_at_exact_limit() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // `{"k":"..."}` padded to exactly OAUTH_BODY_LIMIT: the cap is inclusive.
        let prefix = r#"{"k":""#;
        let suffix = r#""}"#;
        let payload_len = OAUTH_BODY_LIMIT - prefix.len() - suffix.len();
        let mut body = String::from(prefix);
        body.push_str(&"a".repeat(payload_len));
        body.push_str(suffix);
        assert_eq!(body.len(), OAUTH_BODY_LIMIT);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let resp = client.get(server.uri()).send().await.unwrap();

        let parsed: serde_json::Value = read_json_limited(resp).await.expect("at-limit body");
        assert_eq!(parsed["k"].as_str().map(str::len), Some(payload_len));
    }

    #[tokio::test]
    async fn test_post_token_form_rejects_error_field_with_200() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(wiremock::matchers::path("/error"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error": "invalid_grant"
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(wiremock::matchers::path("/null-error"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error": null,
                "access_token": "tok_ok"
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();

        let rejected = post_token_form(&client, &format!("{}/error", server.uri()), &[]).await;
        assert!(matches!(rejected, Err(AppError::OAuthProviderError)));

        let accepted = post_token_form(&client, &format!("{}/null-error", server.uri()), &[]).await;
        assert_eq!(
            accepted.expect("null error is not a failure").access_token,
            "tok_ok"
        );
    }
}
