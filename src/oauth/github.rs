use async_trait::async_trait;
use serde::Deserialize;

use crate::config::ProviderConfig;
use crate::error::AppError;
use crate::oauth::provider::{
    OAuthProvider, TokenResponse, UserInfo, authorize_url, get_json_limited, parse_endpoint,
    post_token_form, token_exchange_params,
};

pub const GITHUB_AUTH_ENDPOINT: &str = "https://github.com/login/oauth/authorize";
pub const GITHUB_TOKEN_ENDPOINT: &str = "https://github.com/login/oauth/access_token";
pub const GITHUB_USER_ENDPOINT: &str = "https://api.github.com/user";
pub const GITHUB_EMAILS_ENDPOINT: &str = "https://api.github.com/user/emails";

const ID: &str = "github";
const DEFAULT_SCOPES: &[&str] = &["read:user", "user:email"];
const USER_EMAIL_SCOPE: &str = "user:email";
const ACCEPT_GITHUB_JSON: &str = "application/vnd.github+json";

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
    auth_url: reqwest::Url,
    token_url: String,
    user_url: String,
    emails_url: String,
}

impl GitHubProvider {
    fn build(
        cfg: &ProviderConfig,
        client: reqwest::Client,
        auth_url: String,
        token_url: String,
        user_url: String,
        emails_url: String,
    ) -> Result<Self, AppError> {
        Ok(Self {
            cfg: cfg.clone(),
            client,
            auth_url: parse_endpoint(&auth_url)?,
            token_url,
            user_url,
            emails_url,
        })
    }

    pub fn new(cfg: &ProviderConfig, client: reqwest::Client) -> Result<Self, AppError> {
        Self::build(
            cfg,
            client,
            GITHUB_AUTH_ENDPOINT.to_string(),
            GITHUB_TOKEN_ENDPOINT.to_string(),
            GITHUB_USER_ENDPOINT.to_string(),
            GITHUB_EMAILS_ENDPOINT.to_string(),
        )
    }

    pub fn with_endpoints(
        cfg: &ProviderConfig,
        client: reqwest::Client,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
        user_url: impl Into<String>,
        emails_url: impl Into<String>,
    ) -> Result<Self, AppError> {
        Self::build(
            cfg,
            client,
            auth_url.into(),
            token_url.into(),
            user_url.into(),
            emails_url.into(),
        )
    }
}

/// GitHub only exposes the primary address through the emails API, which requires the `user:email`
/// scope; it is force-appended when a custom scope list omits it.
fn github_scopes(configured: &[String]) -> String {
    if configured.is_empty() {
        return DEFAULT_SCOPES.join(" ");
    }

    let mut scopes = configured.to_vec();
    if !scopes.iter().any(|scope| scope == USER_EMAIL_SCOPE) {
        scopes.push(USER_EMAIL_SCOPE.to_string());
    }
    scopes.join(" ")
}

/// Resolves the user's primary verified email address from the GitHub email list.
/// Strictly requires both `primary == true` and `verified == true`.
/// Never falls back to secondary or unverified emails.
pub fn resolve_github_email(_public_email: Option<&str>, emails: &[GitHubEmail]) -> (String, bool) {
    for entry in emails {
        if entry.email.trim().is_empty() {
            continue;
        }
        if entry.primary && entry.verified {
            return (entry.email.clone(), true);
        }
    }

    (String::new(), false)
}

#[async_trait]
impl OAuthProvider for GitHubProvider {
    fn id(&self) -> &'static str {
        ID
    }

    fn auth_url(&self, state: &str, code_challenge: &str) -> String {
        let scope = github_scopes(&self.cfg.scopes);

        let params = [
            ("response_type", "code"),
            ("client_id", self.cfg.client_id.as_str()),
            ("redirect_uri", self.cfg.redirect_uri.as_str()),
            ("scope", scope.as_str()),
            ("state", state),
            ("code_challenge", code_challenge),
            ("code_challenge_method", "S256"),
        ];

        authorize_url(&self.auth_url, &params)
    }

    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, AppError> {
        let params = token_exchange_params(
            &self.cfg.client_id,
            &self.cfg.client_secret,
            code,
            &self.cfg.redirect_uri,
            code_verifier,
        );

        post_token_form(&self.client, &self.token_url, &params).await
    }

    async fn fetch_user_info(&self, tokens: &TokenResponse) -> Result<UserInfo, AppError> {
        if tokens.access_token.is_empty() {
            return Err(AppError::OAuthProviderError);
        }

        let user: GitHubUser = get_json_limited(
            &self.client,
            &self.user_url,
            ACCEPT_GITHUB_JSON,
            Some(&tokens.access_token),
        )
        .await?;

        if user.id <= 0 {
            return Err(AppError::OAuthProviderError);
        }

        let emails: Vec<GitHubEmail> = get_json_limited(
            &self.client,
            &self.emails_url,
            ACCEPT_GITHUB_JSON,
            Some(&tokens.access_token),
        )
        .await?;

        let (email, verified) = resolve_github_email(user.email.as_deref(), &emails);

        let name = user
            .name
            .filter(|n| !n.trim().is_empty())
            .unwrap_or(user.login);

        Ok(UserInfo {
            provider_id: ID.to_string(),
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
        assert_eq!(q.get("response_type").map(|s| s.as_str()), Some("code"));
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

        // Custom scopes ensure user:email is always present
        let mut custom_cfg = test_github_config();
        custom_cfg.scopes = vec!["read:user".to_string()];
        let p_custom = GitHubProvider::new(&custom_cfg, reqwest::Client::new()).unwrap();
        let custom_url = reqwest::Url::parse(&p_custom.auth_url("s", "c")).unwrap();
        let custom_q: HashMap<_, _> = custom_url.query_pairs().into_owned().collect();
        assert_eq!(
            custom_q.get("scope").map(|s| s.as_str()),
            Some("read:user user:email")
        );

        // When user:email already present, no duplicate is added
        custom_cfg.scopes = vec!["read:user".to_string(), "user:email".to_string()];
        let p_custom2 = GitHubProvider::new(&custom_cfg, reqwest::Client::new()).unwrap();
        let custom_url2 = reqwest::Url::parse(&p_custom2.auth_url("s", "c")).unwrap();
        let custom_q2: HashMap<_, _> = custom_url2.query_pairs().into_owned().collect();
        assert_eq!(
            custom_q2.get("scope").map(|s| s.as_str()),
            Some("read:user user:email")
        );
    }

    #[test]
    fn test_github_scopes_policy() {
        assert_eq!(github_scopes(&[]), "read:user user:email");

        let custom = vec!["read:user".to_string()];
        assert_eq!(github_scopes(&custom), "read:user user:email");

        let already_present = vec!["read:user".to_string(), "user:email".to_string()];
        assert_eq!(github_scopes(&already_present), "read:user user:email");
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

        // 2. Public email matches a verified secondary email (must NOT be treated as verified primary)
        let emails2 = vec![GitHubEmail {
            email: "pub@example.com".to_string(),
            primary: false,
            verified: true,
        }];
        let (email, verified) = resolve_github_email(Some("pub@example.com"), &emails2);
        assert_eq!(email, "");
        assert!(!verified);

        // 3. Public email exists but is not verified
        let emails3 = vec![GitHubEmail {
            email: "pub@example.com".to_string(),
            primary: false,
            verified: false,
        }];
        let (email, verified) = resolve_github_email(Some("pub@example.com"), &emails3);
        assert_eq!(email, "");
        assert!(!verified);

        // 4. No emails
        let (email, verified) = resolve_github_email(None, &[]);
        assert_eq!(email, "");
        assert!(!verified);
    }

    #[tokio::test]
    async fn test_github_rejects_empty_access_token() {
        let server = MockServer::start().await;
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
            access_token: String::new(),
            token_type: "bearer".to_string(),
            refresh_token: None,
            expires_in: None,
            id_token: None,
            raw: HashMap::new(),
        };

        let err = p.fetch_user_info(&tok).await.unwrap_err();
        assert!(matches!(err, AppError::OAuthProviderError));
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "an empty access token must not issue userinfo or emails requests"
        );
    }

    #[test]
    fn test_github_rejects_malformed_auth_endpoint() {
        let err = GitHubProvider::with_endpoints(
            &test_github_config(),
            reqwest::Client::new(),
            "github.com/login/oauth/authorize",
            GITHUB_TOKEN_ENDPOINT,
            GITHUB_USER_ENDPOINT,
            GITHUB_EMAILS_ENDPOINT,
        )
        .expect_err("malformed endpoint must fail construction");
        assert!(matches!(err, AppError::OAuthProviderError));
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
