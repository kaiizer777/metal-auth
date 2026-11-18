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
        let redirect_uri = if !self.cfg.redirect_uri.is_empty() {
            &self.cfg.redirect_uri
        } else {
            &self.cfg.redirect_url
        };
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
        let redirect_uri = if !self.cfg.redirect_uri.is_empty() {
            &self.cfg.redirect_uri
        } else {
            &self.cfg.redirect_url
        };

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

        let profile: GoogleProfile = resp
            .json()
            .await
            .map_err(|_| AppError::OAuthProviderError)?;

        if profile.sub.trim().is_empty() {
            return Err(AppError::OAuthProviderError);
        }

        Ok(UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: profile.sub,
            email: profile.email.unwrap_or_default(),
            email_verified: profile.email_verified.unwrap_or(false),
            name: profile.name,
            avatar_url: profile.picture,
        })
    }
}
