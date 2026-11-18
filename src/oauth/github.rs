use std::collections::HashMap;

use async_trait::async_trait;
use serde::Deserialize;

use crate::config::ProviderConfig;
use crate::error::AppError;
use crate::oauth::provider::{
    OAuthProvider, TokenResponse, UserInfo, post_token_form, scopes_or_default,
};

pub const GITHUB_AUTH_ENDPOINT: &str = "https://github.com/login/oauth/authorize";
pub const GITHUB_TOKEN_ENDPOINT: &str = "https://github.com/login/oauth/access_token";
pub const GITHUB_USER_ENDPOINT: &str = "https://api.github.com/user";
pub const GITHUB_EMAILS_ENDPOINT: &str = "https://api.github.com/user/emails";

const DEFAULT_SCOPES: &[&str] = &["read:user", "user:email"];

#[derive(Debug, Deserialize)]
struct GitHubUser {
    id: i64,
    login: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    avatar_url: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GitHubEmail {
    pub email: String,
    #[serde(default)]
    pub primary: bool,
    #[serde(default)]
    pub verified: bool,
}

#[derive(Clone, Debug)]
pub struct GitHubProvider {
    cfg: ProviderConfig,
    client: reqwest::Client,
    auth_url: String,
    token_url: String,
    user_url: String,
    emails_url: String,
}

impl GitHubProvider {
    pub fn new(cfg: &ProviderConfig, client: reqwest::Client) -> Result<Self, AppError> {
        Ok(Self {
            cfg: cfg.clone(),
            client,
            auth_url: GITHUB_AUTH_ENDPOINT.to_string(),
            token_url: GITHUB_TOKEN_ENDPOINT.to_string(),
            user_url: GITHUB_USER_ENDPOINT.to_string(),
            emails_url: GITHUB_EMAILS_ENDPOINT.to_string(),
        })
    }

    pub fn with_endpoints(
        cfg: &ProviderConfig,
        client: reqwest::Client,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
        user_url: impl Into<String>,
        emails_url: impl Into<String>,
    ) -> Result<Self, AppError> {
        Ok(Self {
            cfg: cfg.clone(),
            client,
            auth_url: auth_url.into(),
            token_url: token_url.into(),
            user_url: user_url.into(),
            emails_url: emails_url.into(),
        })
    }
}

/// Resolves the user's primary verified email address from the GitHub email list.
pub fn resolve_github_email(
    public_email: Option<&str>,
    emails: &[GitHubEmail],
) -> (String, bool) {
    let mut verified_by_address = HashMap::new();
    for entry in emails {
        if entry.email.is_empty() {
            continue;
        }
        if entry.verified {
            verified_by_address.insert(entry.email.as_str(), true);
        }
        if entry.primary && entry.verified {
            return (entry.email.clone(), true);
        }
    }

    if let Some(pub_email) = public_email {
        if !pub_email.is_empty() {
            if verified_by_address.get(pub_email).copied().unwrap_or(false) {
                return (pub_email.to_string(), true);
            }
            return (pub_email.to_string(), false);
        }
    }

    (String::new(), false)
}

#[async_trait]
impl OAuthProvider for GitHubProvider {
    fn id(&self) -> &'static str {
        "github"
    }

    fn auth_url(&self, state: &str, code_challenge: &str) -> String {
        let redirect_uri = if !self.cfg.redirect_uri.is_empty() {
            &self.cfg.redirect_uri
        } else {
            &self.cfg.redirect_url
        };
        let scope = scopes_or_default(&self.cfg.scopes, DEFAULT_SCOPES);

        let params = [
            ("client_id", self.cfg.client_id.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("scope", scope.as_str()),
            ("state", state),
            ("code_challenge", code_challenge),
            ("code_challenge_method", "S256"),
        ];

        let mut url = reqwest::Url::parse(&self.auth_url)
            .unwrap_or_else(|_| reqwest::Url::parse(GITHUB_AUTH_ENDPOINT).expect("valid auth url"));
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
            ("client_id", self.cfg.client_id.as_str()),
            ("client_secret", self.cfg.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", redirect_uri.as_str()),
            ("code_verifier", code_verifier),
        ];

        post_token_form(&self.client, &self.token_url, &params).await
    }

    async fn fetch_user_info(&self, tokens: &TokenResponse) -> Result<UserInfo, AppError> {
        if tokens.access_token.is_empty() {
            return Err(AppError::OAuthProviderError);
        }

        // 1. Fetch user profile
        let user_resp = self
            .client
            .get(&self.user_url)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .bearer_auth(&tokens.access_token)
            .send()
            .await
            .map_err(|_| AppError::OAuthProviderError)?;

        if !user_resp.status().is_success() {
            return Err(AppError::OAuthProviderError);
        }

        let user: GitHubUser = user_resp
            .json()
            .await
            .map_err(|_| AppError::OAuthProviderError)?;

        if user.id <= 0 {
            return Err(AppError::OAuthProviderError);
        }

        // 2. Fetch user emails
        let emails_resp = self
            .client
            .get(&self.emails_url)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .bearer_auth(&tokens.access_token)
            .send()
            .await
            .map_err(|_| AppError::OAuthProviderError)?;

        if !emails_resp.status().is_success() {
            return Err(AppError::OAuthProviderError);
        }

        let emails: Vec<GitHubEmail> = emails_resp
            .json()
            .await
            .map_err(|_| AppError::OAuthProviderError)?;

        let (email, verified) = resolve_github_email(user.email.as_deref(), &emails);

        let name = user
            .name
            .filter(|n| !n.trim().is_empty())
            .unwrap_or(user.login);

        Ok(UserInfo {
            provider_id: "github".to_string(),
            provider_user_id: user.id.to_string(),
            email,
            email_verified: verified,
            name: Some(name),
            avatar_url: user.avatar_url,
        })
    }
}
