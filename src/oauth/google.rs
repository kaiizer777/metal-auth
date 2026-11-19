use async_trait::async_trait;
use serde::Deserialize;

use crate::config::ProviderConfig;
use crate::error::AppError;
use crate::oauth::provider::{
    OAuthProvider, TokenResponse, UserInfo, post_token_form, scopes_or_default,
};

pub const GOOGLE_AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
pub const GOOGLE_USERINFO_ENDPOINT: &str = "https://openidconnect.googleapis.com/v1/userinfo";

const DEFAULT_SCOPES: &[&str] = &["openid", "email", "profile"];

#[derive(Debug, Deserialize)]
struct GoogleProfile {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    picture: Option<String>,
}

#[derive(Clone, Debug)]
pub struct GoogleProvider {
    cfg: ProviderConfig,
    client: reqwest::Client,
    auth_url: String,
    token_url: String,
    userinfo_url: String,
}

impl GoogleProvider {
    pub fn new(cfg: &ProviderConfig, client: reqwest::Client) -> Result<Self, AppError> {
        Ok(Self {
            cfg: cfg.clone(),
            client,
            auth_url: GOOGLE_AUTH_ENDPOINT.to_string(),
            token_url: GOOGLE_TOKEN_ENDPOINT.to_string(),
            userinfo_url: GOOGLE_USERINFO_ENDPOINT.to_string(),
        })
    }

    pub fn with_endpoints(
        cfg: &ProviderConfig,
        client: reqwest::Client,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
        userinfo_url: impl Into<String>,
    ) -> Result<Self, AppError> {
        Ok(Self {
            cfg: cfg.clone(),
            client,
            auth_url: auth_url.into(),
            token_url: token_url.into(),
            userinfo_url: userinfo_url.into(),
        })
    }
}

#[async_trait]
impl OAuthProvider for GoogleProvider {
    fn id(&self) -> &'static str {
        "google"
    }

    fn auth_url(&self, state: &str, code_challenge: &str) -> String {
        let redirect_uri = &self.cfg.redirect_uri;
        let scope = scopes_or_default(&self.cfg.scopes, DEFAULT_SCOPES);

        let params = [
            ("response_type", "code"),
            ("client_id", self.cfg.client_id.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("scope", scope.as_str()),
            ("state", state),
            ("code_challenge", code_challenge),
            ("code_challenge_method", "S256"),
            ("access_type", "offline"),
            ("prompt", "select_account"),
        ];

        let mut url = reqwest::Url::parse(&self.auth_url)
            .unwrap_or_else(|_| reqwest::Url::parse(GOOGLE_AUTH_ENDPOINT).expect("valid auth url"));
        url.query_pairs_mut().extend_pairs(&params);
        url.to_string()
    }

    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, AppError> {
        let redirect_uri = &self.cfg.redirect_uri;

        let params = [
            ("code", code),
            ("client_id", self.cfg.client_id.as_str()),
            ("client_secret", self.cfg.client_secret.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", code_verifier),
        ];

        post_token_form(&self.client, &self.token_url, &params).await
    }

    async fn fetch_user_info(&self, tokens: &TokenResponse) -> Result<UserInfo, AppError> {
        if tokens.access_token.is_empty() {
            return Err(AppError::OAuthProviderError);
        }

        let resp = self
            .client
            .get(&self.userinfo_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .bearer_auth(&tokens.access_token)
            .send()
            .await
            .map_err(|_| AppError::OAuthProviderError)?;

        if !resp.status().is_success() {
            return Err(AppError::OAuthProviderError);
        }

        let profile: GoogleProfile = crate::oauth::provider::read_json_limited(resp).await?;

        if profile.sub.trim().is_empty() {
            return Err(AppError::OAuthProviderError);
        }

        let email = profile.email.unwrap_or_default();
        let verified = profile.email_verified.unwrap_or(false) && !email.trim().is_empty();

        Ok(UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: profile.sub,
            email,
            email_verified: verified,
            name: profile.name,
            avatar_url: profile.picture,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_google_config() -> ProviderConfig {
        ProviderConfig {
            client_id: "google-id".to_string(),
            client_secret: "google-secret".to_string(),
            redirect_uri: "https://app.example.com/auth/google/callback".to_string(),
            scopes: vec![],
            enabled: true,
            team_id: None,
            key_id: None,
            private_key: None,
        }
    }

    #[test]
    fn test_google_auth_url_parameters() {
        let p = GoogleProvider::new(&test_google_config(), reqwest::Client::new()).unwrap();
        let auth_url = p.auth_url("state123", "challenge123");

        let url = reqwest::Url::parse(&auth_url).expect("valid auth url");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("accounts.google.com"));
        assert_eq!(url.path(), "/o/oauth2/v2/auth");

        let q: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q.get("response_type").map(|s| s.as_str()), Some("code"));
        assert_eq!(q.get("client_id").map(|s| s.as_str()), Some("google-id"));
        assert_eq!(
            q.get("redirect_uri").map(|s| s.as_str()),
            Some("https://app.example.com/auth/google/callback")
        );
        assert_eq!(
            q.get("scope").map(|s| s.as_str()),
            Some("openid email profile")
        );
        assert_eq!(q.get("state").map(|s| s.as_str()), Some("state123"));
        assert_eq!(
            q.get("code_challenge").map(|s| s.as_str()),
            Some("challenge123")
        );
        assert_eq!(
            q.get("code_challenge_method").map(|s| s.as_str()),
            Some("S256")
        );
        assert_eq!(q.get("access_type").map(|s| s.as_str()), Some("offline"));
        assert_eq!(q.get("prompt").map(|s| s.as_str()), Some("select_account"));

        // Custom scopes override defaults
        let mut custom_cfg = test_google_config();
        custom_cfg.scopes = vec!["openid".to_string(), "email".to_string()];
        let p_custom = GoogleProvider::new(&custom_cfg, reqwest::Client::new()).unwrap();
        let custom_url = reqwest::Url::parse(&p_custom.auth_url("s", "c")).unwrap();
        let custom_q: HashMap<_, _> = custom_url.query_pairs().into_owned().collect();
        assert_eq!(
            custom_q.get("scope").map(|s| s.as_str()),
            Some("openid email")
        );
    }

    #[tokio::test]
    async fn test_google_exchange_and_userinfo_success() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "goog-at-123",
                "token_type": "Bearer",
                "refresh_token": "goog-rt-456",
                "expires_in": 3600
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .and(header("Authorization", "Bearer goog-at-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sub": "10492837491823749",
                "email": "user@example.com",
                "email_verified": true,
                "name": "Jane Doe",
                "picture": "https://lh3.googleusercontent.com/pic"
            })))
            .mount(&server)
            .await;

        let token_endpoint = format!("{}/token", server.uri());
        let userinfo_endpoint = format!("{}/userinfo", server.uri());

        let p = GoogleProvider::with_endpoints(
            &test_google_config(),
            reqwest::Client::new(),
            GOOGLE_AUTH_ENDPOINT,
            &token_endpoint,
            &userinfo_endpoint,
        )
        .unwrap();

        let tok = p.exchange_code("code123", "verifier123").await.unwrap();
        assert_eq!(tok.access_token, "goog-at-123");
        assert_eq!(tok.token_type, "Bearer");
        assert_eq!(tok.refresh_token.as_deref(), Some("goog-rt-456"));
        assert_eq!(tok.expires_in, Some(3600));

        let user = p.fetch_user_info(&tok).await.unwrap();
        assert_eq!(user.provider_id, "google");
        assert_eq!(user.provider_user_id, "10492837491823749");
        assert_eq!(user.email, "user@example.com");
        assert!(user.email_verified);
        assert_eq!(user.name.as_deref(), Some("Jane Doe"));
        assert_eq!(
            user.avatar_url.as_deref(),
            Some("https://lh3.googleusercontent.com/pic")
        );
    }

    #[tokio::test]
    async fn test_google_errors() {
        let server = MockServer::start().await;

        // 1. Token 400 error
        Mock::given(method("POST"))
            .and(path("/token-error"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant"
            })))
            .mount(&server)
            .await;

        let p_err = GoogleProvider::with_endpoints(
            &test_google_config(),
            reqwest::Client::new(),
            GOOGLE_AUTH_ENDPOINT,
            format!("{}/token-error", server.uri()),
            format!("{}/userinfo", server.uri()),
        )
        .unwrap();

        let err = p_err.exchange_code("bad_code", "v").await.unwrap_err();
        assert!(matches!(err, AppError::OAuthProviderError));

        // 2. Token invalid JSON
        Mock::given(method("POST"))
            .and(path("/token-invalid-json"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json{"))
            .mount(&server)
            .await;

        let p_bad_json = GoogleProvider::with_endpoints(
            &test_google_config(),
            reqwest::Client::new(),
            GOOGLE_AUTH_ENDPOINT,
            format!("{}/token-invalid-json", server.uri()),
            format!("{}/userinfo", server.uri()),
        )
        .unwrap();

        let err = p_bad_json.exchange_code("code", "v").await.unwrap_err();
        assert!(matches!(err, AppError::OAuthProviderError));

        // 3. UserInfo 500 error
        Mock::given(method("GET"))
            .and(path("/userinfo-500"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let p_500 = GoogleProvider::with_endpoints(
            &test_google_config(),
            reqwest::Client::new(),
            GOOGLE_AUTH_ENDPOINT,
            format!("{}/token", server.uri()),
            format!("{}/userinfo-500", server.uri()),
        )
        .unwrap();

        let dummy_tok = TokenResponse {
            access_token: "at".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: None,
            expires_in: None,
            id_token: None,
            raw: HashMap::new(),
        };

        let err = p_500.fetch_user_info(&dummy_tok).await.unwrap_err();
        assert!(matches!(err, AppError::OAuthProviderError));

        // 4. Missing sub field in UserInfo
        Mock::given(method("GET"))
            .and(path("/userinfo-missing-sub"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "email": "user@example.com",
                "email_verified": true
            })))
            .mount(&server)
            .await;

        let p_no_sub = GoogleProvider::with_endpoints(
            &test_google_config(),
            reqwest::Client::new(),
            GOOGLE_AUTH_ENDPOINT,
            format!("{}/token", server.uri()),
            format!("{}/userinfo-missing-sub", server.uri()),
        )
        .unwrap();

        let err = p_no_sub.fetch_user_info(&dummy_tok).await.unwrap_err();
        assert!(matches!(err, AppError::OAuthProviderError));

        // 5. Empty access token
        let empty_tok = TokenResponse {
            access_token: "".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: None,
            expires_in: None,
            id_token: None,
            raw: HashMap::new(),
        };
        let err = p_500.fetch_user_info(&empty_tok).await.unwrap_err();
        assert!(matches!(err, AppError::OAuthProviderError));

        // 6. Unverified email surfaces false
        Mock::given(method("GET"))
            .and(path("/userinfo-unverified"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sub": "123",
                "email": "u@example.com",
                "email_verified": false
            })))
            .mount(&server)
            .await;

        let p_unverified = GoogleProvider::with_endpoints(
            &test_google_config(),
            reqwest::Client::new(),
            GOOGLE_AUTH_ENDPOINT,
            format!("{}/token", server.uri()),
            format!("{}/userinfo-unverified", server.uri()),
        )
        .unwrap();

        let user = p_unverified.fetch_user_info(&dummy_tok).await.unwrap();
        assert_eq!(user.provider_user_id, "123");
        assert_eq!(user.email, "u@example.com");
        assert!(!user.email_verified);

        // 7. Empty or missing email surfaces email_verified: false even if claim is true
        Mock::given(method("GET"))
            .and(path("/userinfo-empty-email"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sub": "124",
                "email": "",
                "email_verified": true
            })))
            .mount(&server)
            .await;

        let p_empty_email = GoogleProvider::with_endpoints(
            &test_google_config(),
            reqwest::Client::new(),
            GOOGLE_AUTH_ENDPOINT,
            format!("{}/token", server.uri()),
            format!("{}/userinfo-empty-email", server.uri()),
        )
        .unwrap();

        let user_empty = p_empty_email.fetch_user_info(&dummy_tok).await.unwrap();
        assert_eq!(user_empty.email, "");
        assert!(!user_empty.email_verified);
    }
}
