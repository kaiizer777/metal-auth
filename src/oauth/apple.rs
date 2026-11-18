use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use jsonwebtoken::{Algorithm, Header, Validation, decode, decode_header, encode};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::config::ProviderConfig;
use crate::error::AppError;
use crate::oauth::provider::{
    OAuthProvider, TokenResponse, UserInfo, post_token_form, scopes_or_default,
};

pub const APPLE_AUTH_ENDPOINT: &str = "https://appleid.apple.com/auth/authorize";
pub const APPLE_TOKEN_ENDPOINT: &str = "https://appleid.apple.com/auth/token";
pub const APPLE_JWKS_ENDPOINT: &str = "https://appleid.apple.com/auth/keys";
pub const APPLE_ISSUER: &str = "https://appleid.apple.com";
pub const APPLE_JWKS_TTL: Duration = Duration::from_secs(86400); // 24 hours

const DEFAULT_SCOPES: &[&str] = &["name", "email"];

#[derive(Debug, Serialize)]
struct AppleSecretClaims<'a> {
    iss: &'a str,
    iat: i64,
    exp: i64,
    aud: &'a str,
    sub: &'a str,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    #[serde(default)]
    keys: Vec<JwksKey>,
}

#[derive(Debug, Deserialize)]
struct JwksKey {
    kid: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct AppleTokenClaims {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<serde_json::Value>,
}

#[derive(Debug, Default)]
struct JwksCache {
    keys: HashMap<String, (String, String)>,
    expires_at: Option<Instant>,
}

#[derive(Clone, Debug)]
pub struct AppleProvider {
    cfg: ProviderConfig,
    client: reqwest::Client,
    auth_url: String,
    token_url: String,
    jwks_url: String,
    cache: Arc<RwLock<JwksCache>>,
}

impl AppleProvider {
    pub fn new(cfg: &ProviderConfig, client: reqwest::Client) -> Result<Self, AppError> {
        Ok(Self {
            cfg: cfg.clone(),
            client,
            auth_url: APPLE_AUTH_ENDPOINT.to_string(),
            token_url: APPLE_TOKEN_ENDPOINT.to_string(),
            jwks_url: APPLE_JWKS_ENDPOINT.to_string(),
            cache: Arc::new(RwLock::new(JwksCache::default())),
        })
    }

    pub fn with_endpoints(
        cfg: &ProviderConfig,
        client: reqwest::Client,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
        jwks_url: impl Into<String>,
    ) -> Result<Self, AppError> {
        Ok(Self {
            cfg: cfg.clone(),
            client,
            auth_url: auth_url.into(),
            token_url: token_url.into(),
            jwks_url: jwks_url.into(),
            cache: Arc::new(RwLock::new(JwksCache::default())),
        })
    }

    /// Dynamically signs an ES256 client secret JWT using Apple credentials.
    pub fn generate_client_secret(
        team_id: &str,
        key_id: &str,
        client_id: &str,
        private_key_pem: &str,
    ) -> Result<String, AppError> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(key_id.to_string());

        let now = Utc::now().timestamp();
        let claims = AppleSecretClaims {
            iss: team_id,
            iat: now,
            exp: now + 300, // 5 minutes
            aud: APPLE_ISSUER,
            sub: client_id,
        };

        let encoding_key = jsonwebtoken::EncodingKey::from_ec_pem(private_key_pem.as_bytes())
            .map_err(|_| AppError::OAuthProviderError)?;

        encode(&header, &claims, &encoding_key).map_err(|_| AppError::OAuthProviderError)
    }

    /// Resolves the client secret, either static or freshly minted via ES256.
    pub fn get_client_secret(&self) -> Result<String, AppError> {
        if !self.cfg.client_secret.is_empty() {
            return Ok(self.cfg.client_secret.clone());
        }

        let team_id = self.cfg.team_id.as_deref().unwrap_or_default();
        let key_id = self.cfg.key_id.as_deref().unwrap_or_default();
        let private_key = self.cfg.private_key.as_deref().unwrap_or_default();

        if team_id.is_empty() || key_id.is_empty() || private_key.is_empty() {
            return Err(AppError::OAuthProviderError);
        }

        Self::generate_client_secret(
            team_id,
            key_id,
            &self.cfg.client_id,
            private_key,
        )
    }

    /// Fetches and updates the in-memory JWKS cache.
    async fn refresh_jwks(&self) -> Result<(), AppError> {
        let resp = self
            .client
            .get(&self.jwks_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| AppError::OAuthProviderError)?;

        if !resp.status().is_success() {
            return Err(AppError::OAuthProviderError);
        }

        let jwks: JwksResponse = resp
            .json()
            .await
            .map_err(|_| AppError::OAuthProviderError)?;

        let mut keys = HashMap::new();
        for k in jwks.keys {
            if !k.kid.is_empty() && !k.n.is_empty() && !k.e.is_empty() {
                keys.insert(k.kid, (k.n, k.e));
            }
        }

        let mut write_guard = self.cache.write().await;
        write_guard.keys = keys;
        write_guard.expires_at = Some(Instant::now() + APPLE_JWKS_TTL);

        Ok(())
    }

    /// Resolves RSA public key components for `kid`, auto-refreshing cache if missing.
    async fn get_jwks_key(&self, kid: &str) -> Result<(String, String), AppError> {
        {
            let read_guard = self.cache.read().await;
            let fresh = read_guard
                .expires_at
                .map(|exp| Instant::now() < exp)
                .unwrap_or(false);

            if fresh {
                if let Some(components) = read_guard.keys.get(kid) {
                    return Ok(components.clone());
                }
            }
        }

        // Cache expired or kid unknown: refresh once
        self.refresh_jwks().await?;

        let read_guard = self.cache.read().await;
        read_guard
            .keys
            .get(kid)
            .cloned()
            .ok_or(AppError::OAuthProviderError)
    }
}

/// Normalizes Apple's `email_verified` claim, supporting bool or string "true".
fn normalize_email_verified(val: Option<&serde_json::Value>) -> bool {
    match val {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => s.trim().eq_ignore_ascii_case("true"),
        _ => false,
    }
}

#[async_trait]
impl OAuthProvider for AppleProvider {
    fn id(&self) -> &'static str {
        "apple"
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
            ("response_mode", "form_post"),
            ("client_id", self.cfg.client_id.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("scope", scope.as_str()),
            ("state", state),
            ("code_challenge", code_challenge),
            ("code_challenge_method", "S256"),
        ];

        let mut url = reqwest::Url::parse(&self.auth_url)
            .unwrap_or_else(|_| reqwest::Url::parse(APPLE_AUTH_ENDPOINT).expect("valid auth url"));
        url.query_pairs_mut().extend_pairs(&params);
        url.to_string()
    }

    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, AppError> {
        let client_secret = self.get_client_secret()?;
        let redirect_uri = if !self.cfg.redirect_uri.is_empty() {
            &self.cfg.redirect_uri
        } else {
            &self.cfg.redirect_url
        };

        let params = [
            ("client_id", self.cfg.client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri.as_str()),
            ("code_verifier", code_verifier),
        ];

        let token_resp = post_token_form(&self.client, &self.token_url, &params).await?;

        if token_resp.id_token.is_none() {
            return Err(AppError::OAuthProviderError);
        }

        Ok(token_resp)
    }

    async fn fetch_user_info(&self, tokens: &TokenResponse) -> Result<UserInfo, AppError> {
        let id_token = match &tokens.id_token {
            Some(tok) if !tok.trim().is_empty() => tok,
            _ => return Err(AppError::OAuthProviderError),
        };

        let header = decode_header(id_token).map_err(|_| AppError::OAuthProviderError)?;

        if header.alg != Algorithm::RS256 {
            return Err(AppError::OAuthProviderError);
        }

        let kid = header.kid.ok_or(AppError::OAuthProviderError)?;
        let (n, e) = self.get_jwks_key(&kid).await?;

        let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(&n, &e)
            .map_err(|_| AppError::OAuthProviderError)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[APPLE_ISSUER]);
        validation.set_audience(&[&self.cfg.client_id]);

        let token_data = decode::<AppleTokenClaims>(id_token, &decoding_key, &validation)
            .map_err(|_| AppError::OAuthProviderError)?;

        if token_data.claims.sub.trim().is_empty() {
            return Err(AppError::OAuthProviderError);
        }

        let verified = normalize_email_verified(token_data.claims.email_verified.as_ref());

        Ok(UserInfo {
            provider_id: "apple".to_string(),
            provider_user_id: token_data.claims.sub,
            email: token_data.claims.email.unwrap_or_default(),
            email_verified: verified,
            name: None,
            avatar_url: None,
        })
    }
}
