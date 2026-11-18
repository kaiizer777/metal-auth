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
pub fn resolve_github_email(public_email: Option<&str>, emails: &[GitHubEmail]) -> (String, bool) {
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

    if let Some(pub_email) = public_email
        && !pub_email.is_empty()
    {
        if verified_by_address.get(pub_email).copied().unwrap_or(false) {
            return (pub_email.to_string(), true);
        }
        return (pub_email.to_string(), false);
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
            .header(
                reqwest::header::USER_AGENT,
                crate::oauth::provider::USER_AGENT,
            )
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
            .header(
                reqwest::header::USER_AGENT,
                crate::oauth::provider::USER_AGENT,
            )
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_github_config() -> ProviderConfig {
        ProviderConfig {
            client_id: "github-id".to_string(),
            client_secret: "github-secret".to_string(),
            redirect_uri: "https://app.example.com/auth/github/callback".to_string(),
            redirect_url: "https://app.example.com/auth/github/callback".to_string(),
            scopes: vec![],
            enabled: true,
            team_id: None,
            key_id: None,
            private_key: None,
        }
    }

    #[test]
    fn test_github_auth_url_parameters() {
        let p = GitHubProvider::new(&test_github_config(), reqwest::Client::new()).unwrap();
        let auth_url = p.auth_url("state123", "challenge123");

        let url = reqwest::Url::parse(&auth_url).expect("valid auth url");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("github.com"));
        assert_eq!(url.path(), "/login/oauth/authorize");

        let q: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q.get("client_id").map(|s| s.as_str()), Some("github-id"));
        assert_eq!(
            q.get("redirect_uri").map(|s| s.as_str()),
            Some("https://app.example.com/auth/github/callback")
        );
        assert_eq!(
            q.get("scope").map(|s| s.as_str()),
            Some("read:user user:email")
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

        // Custom scopes override defaults
        let mut custom_cfg = test_github_config();
        custom_cfg.scopes = vec!["read:user".to_string()];
        let p_custom = GitHubProvider::new(&custom_cfg, reqwest::Client::new()).unwrap();
        let custom_url = reqwest::Url::parse(&p_custom.auth_url("s", "c")).unwrap();
        let custom_q: HashMap<_, _> = custom_url.query_pairs().into_owned().collect();
        assert_eq!(custom_q.get("scope").map(|s| s.as_str()), Some("read:user"));
    }

    #[test]
    fn test_resolve_github_email_combinations() {
        // 1. Primary and verified present
        let emails1 = vec![
            GitHubEmail {
                email: "other@example.com".to_string(),
                primary: false,
                verified: true,
            },
            GitHubEmail {
                email: "primary@example.com".to_string(),
                primary: true,
                verified: true,
            },
        ];
        let (email, verified) = resolve_github_email(None, &emails1);
        assert_eq!(email, "primary@example.com");
        assert!(verified);

        // 2. Public email matches a verified secondary email
        let emails2 = vec![GitHubEmail {
            email: "pub@example.com".to_string(),
            primary: false,
            verified: true,
        }];
        let (email, verified) = resolve_github_email(Some("pub@example.com"), &emails2);
        assert_eq!(email, "pub@example.com");
        assert!(verified);

        // 3. Public email exists but is not verified
        let emails3 = vec![GitHubEmail {
            email: "pub@example.com".to_string(),
            primary: false,
            verified: false,
        }];
        let (email, verified) = resolve_github_email(Some("pub@example.com"), &emails3);
        assert_eq!(email, "pub@example.com");
        assert!(!verified);

        // 4. No emails
        let (email, verified) = resolve_github_email(None, &[]);
        assert_eq!(email, "");
        assert!(!verified);
    }

    #[tokio::test]
    async fn test_github_exchange_and_userinfo_with_hidden_email() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .and(header("Accept", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "gh-at-999",
                "token_type": "bearer",
                "scope": "read:user,user:email"
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/user"))
            .and(header("Authorization", "Bearer gh-at-999"))
            .and(header("User-Agent", "metal-auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 583231,
                "login": "octocat",
                "name": "The Octocat",
                "avatar_url": "https://avatars.githubusercontent.com/u/583231",
                "email": null
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/user/emails"))
            .and(header("Authorization", "Bearer gh-at-999"))
            .and(header("User-Agent", "metal-auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "email": "secondary@example.com",
                    "primary": false,
                    "verified": true,
                    "visibility": null
                },
                {
                    "email": "hidden-primary@example.com",
                    "primary": true,
                    "verified": true,
                    "visibility": "private"
                }
            ])))
            .mount(&server)
            .await;

        let token_endpoint = format!("{}/login/oauth/access_token", server.uri());
        let user_endpoint = format!("{}/user", server.uri());
        let emails_endpoint = format!("{}/user/emails", server.uri());

        let p = GitHubProvider::with_endpoints(
            &test_github_config(),
            reqwest::Client::new(),
            GITHUB_AUTH_ENDPOINT,
            &token_endpoint,
            &user_endpoint,
            &emails_endpoint,
        )
        .unwrap();

        let tok = p.exchange_code("gh_code", "gh_verifier").await.unwrap();
        assert_eq!(tok.access_token, "gh-at-999");

        let user = p.fetch_user_info(&tok).await.unwrap();
        assert_eq!(user.provider_id, "github");
        assert_eq!(user.provider_user_id, "583231");
        assert_eq!(user.email, "hidden-primary@example.com");
        assert!(user.email_verified);
        assert_eq!(user.name.as_deref(), Some("The Octocat"));
        assert_eq!(
            user.avatar_url.as_deref(),
            Some("https://avatars.githubusercontent.com/u/583231")
        );
    }

    #[tokio::test]
    async fn test_github_name_fallback_and_unverified_email() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 100,
                "login": "monalisa",
                "name": "",
                "email": null
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/user/emails"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "email": "unverified@example.com",
                    "primary": true,
                    "verified": false
                }
            ])))
            .mount(&server)
            .await;

        let p = GitHubProvider::with_endpoints(
            &test_github_config(),
            reqwest::Client::new(),
            GITHUB_AUTH_ENDPOINT,
            format!("{}/token", server.uri()),
            format!("{}/user", server.uri()),
            format!("{}/user/emails", server.uri()),
        )
        .unwrap();

        let tok = TokenResponse {
            access_token: "token123".to_string(),
            token_type: "bearer".to_string(),
            refresh_token: None,
            expires_in: None,
            id_token: None,
            raw: HashMap::new(),
        };

        let user = p.fetch_user_info(&tok).await.unwrap();
        assert_eq!(user.name.as_deref(), Some("monalisa"));
        assert_eq!(user.email, "");
        assert!(!user.email_verified);
    }

    #[tokio::test]
    async fn test_github_errors() {
        let server = MockServer::start().await;

        // 1. Invalid id in userinfo (id == 0)
        Mock::given(method("GET"))
            .and(path("/user-bad-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 0,
                "login": "bad"
            })))
            .mount(&server)
            .await;

        let p_bad_id = GitHubProvider::with_endpoints(
            &test_github_config(),
            reqwest::Client::new(),
            GITHUB_AUTH_ENDPOINT,
            format!("{}/token", server.uri()),
            format!("{}/user-bad-id", server.uri()),
            format!("{}/emails", server.uri()),
        )
        .unwrap();

        let tok = TokenResponse {
            access_token: "token123".to_string(),
            token_type: "bearer".to_string(),
            refresh_token: None,
            expires_in: None,
            id_token: None,
            raw: HashMap::new(),
        };

        let err = p_bad_id.fetch_user_info(&tok).await.unwrap_err();
        assert!(matches!(err, AppError::OAuthProviderError));

        // 2. User info 403
        Mock::given(method("GET"))
            .and(path("/user-403"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let p_403 = GitHubProvider::with_endpoints(
            &test_github_config(),
            reqwest::Client::new(),
            GITHUB_AUTH_ENDPOINT,
            format!("{}/token", server.uri()),
            format!("{}/user-403", server.uri()),
            format!("{}/emails", server.uri()),
        )
        .unwrap();

        let err = p_403.fetch_user_info(&tok).await.unwrap_err();
        assert!(matches!(err, AppError::OAuthProviderError));

        // 3. Emails 500
        Mock::given(method("GET"))
            .and(path("/user-ok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 123,
                "login": "ok"
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/emails-500"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let p_emails_err = GitHubProvider::with_endpoints(
            &test_github_config(),
            reqwest::Client::new(),
            GITHUB_AUTH_ENDPOINT,
            format!("{}/token", server.uri()),
            format!("{}/user-ok", server.uri()),
            format!("{}/emails-500", server.uri()),
        )
        .unwrap();

        let err = p_emails_err.fetch_user_info(&tok).await.unwrap_err();
        assert!(matches!(err, AppError::OAuthProviderError));
    }
}
