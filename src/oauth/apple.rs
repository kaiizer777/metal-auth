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

        Self::generate_client_secret(team_id, key_id, &self.cfg.client_id, private_key)
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

            if fresh && let Some(components) = read_guard.keys.get(kid) {
                return Ok(components.clone());
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_EC_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg80bQVIVk8j478T1G\nbpAeMo50IbEghq+GGg0l0/0rPlahRANCAAQH8ORbGJ8Lv2FAtRIwd1UhQcFxjSut\nhcBWj2+0aSbPnGktPO19SuWvGeqDUtSF95/eUScRQ9Ww6XHj+fWMn8R+\n-----END PRIVATE KEY-----";

    const TEST_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC9JztAtKCKHeqw\nO/NFph+PsTY+DkJrhrvgcnbt9NleRcJ1qPNi6ADQ8y8QCEZPz+GBrKJ57dCJRhqW\nIA8rA9dbm7vlH5wRVOj5M9p3Wt7dGZmDxSPxZ35yzgMhH+Q13j245NW5CbnVRgr8\nxMt3Sdc6ObmcioBAnzzLCA0h2VWJIbbgWdzQb+IWqt+rNjzDlMNCwIowHfsNyLK5\nKPCw4XUCKXKKzsly9XGJp/L1dNVjzSROdu8RZXn/swiAgEZ3hXi564dJcrj+FXsx\nehXGhNnUYKw6QNMKG5bzb0rZuIAEVS4hpkuc6yVVYXBzD6q2HXSjn+FibXRx2wPI\nGbDUTVKJAgMBAAECggEAGNJFHECXsIgse+PiEIm0Ko7+pzYH0URk8xcSNDelLpHI\n6te42InJUaIX0urDD0YgOXwF9ioW62yfoIOkeeiPIh5VkcOMH1odGFaNnIv4Ittx\nIbGE/fCuzzHphzdAIzF+t/yPbzCviiUe2/yXFphB/goFKV2jZtd+isYLsx1p9AyW\nwSXlWpRC0ont8exXVy57QwKamIUJ9Avqkg/OM+BDCJm+YjH/aDXDJ3MbWkQ1HjNx\n7JeZzPO9ILoRoGeZ3KtsNV9DOtpHmKqxOqPcGkphRcL+KXtRXkDfJGj3haRtJXEA\nlJb0kzFfUimSSyja2fxLWg7TwKz+HlB/YfOXkaf8YQKBgQDj2jiGJyD7nnf2/TZ2\nR1BnkjwwYkQrG/HJ0KlGg8jfxS8UahHHeZqSMOU0Bb4Z5jP7TNwyqNMTC2zx35vP\nXZQyyBcZM/yVbQX+/3BsxIv6q2klz/+HiI88hT9nHOURKXdcSA3yYu5y9ZQU96Ib\nwJRe8bxu12S/7dxAQYMht4XiSwKBgQDUhSiG/VLJsLwQGJ4ZurlzOI7mc5tYmr5s\nLurR1fuP+TREDa0BMaPhkq4us7c6G/G+jomjRK+hpEhmVOOu799i+VjRUza4jeWE\nIitGeRZLgmFhXsfCSniqSb+b3GGE8kJfnVwQh66DHgyR4BE4MRiGJVI/W58+xrcm\n/sKR0Fl5+wKBgB8E5FEPHqRirH5JdpKfnsia1erYVeNwiHgrGgBpjH06QPCMiCMZ\n4PsqAOoWJg0sk8MQcaHL7gBXu9spz/JpEPXg25QoyagmEXznlYyZLV1Q3J2zNVxk\nMOvSUBFfk6fEd2VuwcdPxJqN6Dz6gW05yHkse7SzShn+7c8pnAqJC4cFAoGAFqxe\nNoiwXHROnCkENRqGzpQqKswKttlLl58pzllWDXY47UnIO2hgY6CSlMj3s2tnzzzF\n0nVxh31PfBtybyeIXbbckvidzfLVmdNLaqlgh43RdeH2zfPEC+byWl6YyOZPzoOr\nXtga9kIudSHCtIwIYcd5jujnhHsO70oe2A+yfCECgYBSZcbi2qrjyHTahqqWQkx1\nZPvNNEfsMUT+61vwCTCKvtYoFurP1qHMwwGNQU1jb0z66beBq2JzsMs25EopkAJ4\nzzllk6vQJkvzYkPDb9ntLDK7fpM3MeuDlq79VsJKpPhK/GxUDZiXRKnVOx13RXG5\nqaFHQWXrR+Tne43oPjXUXw==\n-----END PRIVATE KEY-----";

    const TEST_RSA_N: &str = "vSc7QLSgih3qsDvzRaYfj7E2Pg5Ca4a74HJ27fTZXkXCdajzYugA0PMvEAhGT8_hgayiee3QiUYaliAPKwPXW5u75R-cEVTo-TPad1re3RmZg8Uj8Wd-cs4DIR_kNd49uOTVuQm51UYK_MTLd0nXOjm5nIqAQJ88ywgNIdlViSG24Fnc0G_iFqrfqzY8w5TDQsCKMB37DciyuSjwsOF1Ailyis7JcvVxiafy9XTVY80kTnbvEWV5_7MIgIBGd4V4ueuHSXK4_hV7MXoVxoTZ1GCsOkDTChuW829K2biABFUuIaZLnOslVWFwcw-qth10o5_hYm10cdsDyBmw1E1SiQ";
    const TEST_RSA_E: &str = "AQAB";

    fn test_apple_config() -> ProviderConfig {
        ProviderConfig {
            client_id: "com.example.app".to_string(),
            client_secret: "static-secret".to_string(),
            redirect_uri: "https://app.example.com/auth/apple/callback".to_string(),
            redirect_url: "https://app.example.com/auth/apple/callback".to_string(),
            scopes: vec![],
            enabled: true,
            team_id: Some("TEAM123456".to_string()),
            key_id: Some("KEY1234567".to_string()),
            private_key: Some(TEST_EC_PEM.to_string()),
        }
    }

    #[derive(Debug, Serialize)]
    struct MockClaims {
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

    fn mint_test_id_token(kid: &str, claims: MockClaims) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());

        let encoding_key =
            jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_PEM.as_bytes()).unwrap();
        encode(&header, &claims, &encoding_key).unwrap()
    }

    #[test]
    fn test_apple_auth_url_parameters() {
        let p = AppleProvider::new(&test_apple_config(), reqwest::Client::new()).unwrap();
        let auth_url = p.auth_url("state123", "challenge123");

        let url = reqwest::Url::parse(&auth_url).expect("valid auth url");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("appleid.apple.com"));
        assert_eq!(url.path(), "/auth/authorize");

        let q: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q.get("response_type").map(|s| s.as_str()), Some("code"));
        assert_eq!(
            q.get("response_mode").map(|s| s.as_str()),
            Some("form_post")
        );
        assert_eq!(
            q.get("client_id").map(|s| s.as_str()),
            Some("com.example.app")
        );
        assert_eq!(
            q.get("redirect_uri").map(|s| s.as_str()),
            Some("https://app.example.com/auth/apple/callback")
        );
        assert_eq!(q.get("scope").map(|s| s.as_str()), Some("name email"));
        assert_eq!(q.get("state").map(|s| s.as_str()), Some("state123"));
        assert_eq!(
            q.get("code_challenge").map(|s| s.as_str()),
            Some("challenge123")
        );
        assert_eq!(
            q.get("code_challenge_method").map(|s| s.as_str()),
            Some("S256")
        );
    }

    #[test]
    fn test_apple_dynamic_client_secret_jwt() {
        let secret = AppleProvider::generate_client_secret(
            "TEAM123456",
            "KEY1234567",
            "com.example.app",
            TEST_EC_PEM,
        )
        .unwrap();

        let header = decode_header(&secret).unwrap();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some("KEY1234567"));

        // Validate payload structure
        let parts: Vec<&str> = secret.split('.').collect();
        assert_eq!(parts.len(), 3);

        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(claims["iss"], "TEAM123456");
        assert_eq!(claims["sub"], "com.example.app");
        assert_eq!(claims["aud"], "https://appleid.apple.com");
        let iat = claims["iat"].as_i64().unwrap();
        let exp = claims["exp"].as_i64().unwrap();
        assert_eq!(exp - iat, 300);
    }

    #[tokio::test]
    async fn test_apple_valid_id_token_and_jwks() {
        let server = MockServer::start().await;

        let now = Utc::now().timestamp();
        let claims = MockClaims {
            iss: "https://appleid.apple.com".to_string(),
            aud: "com.example.app".to_string(),
            exp: now + 3600,
            iat: now,
            sub: "apple-sub-123".to_string(),
            email: Some("user@privaterelay.appleid.com".to_string()),
            email_verified: Some(serde_json::Value::Bool(true)),
        };

        let id_token = mint_test_id_token("kid-1", claims);

        Mock::given(method("POST"))
            .and(path("/auth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "apple-at-123",
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
                        "kid": "kid-1",
                        "use": "sig",
                        "alg": "RS256",
                        "n": TEST_RSA_N,
                        "e": TEST_RSA_E
                    }
                ]
            })))
            .mount(&server)
            .await;

        let p = AppleProvider::with_endpoints(
            &test_apple_config(),
            reqwest::Client::new(),
            APPLE_AUTH_ENDPOINT,
            format!("{}/auth/token", server.uri()),
            format!("{}/auth/keys", server.uri()),
        )
        .unwrap();

        let tok = p.exchange_code("code", "verifier").await.unwrap();
        assert_eq!(tok.access_token, "apple-at-123");

        let user = p.fetch_user_info(&tok).await.unwrap();
        assert_eq!(user.provider_id, "apple");
        assert_eq!(user.provider_user_id, "apple-sub-123");
        assert_eq!(user.email, "user@privaterelay.appleid.com");
        assert!(user.email_verified);
    }

    #[tokio::test]
    async fn test_apple_email_verified_forms() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/auth/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "kid": "kid-1",
                        "n": TEST_RSA_N,
                        "e": TEST_RSA_E
                    }
                ]
            })))
            .mount(&server)
            .await;

        let p = AppleProvider::with_endpoints(
            &test_apple_config(),
            reqwest::Client::new(),
            APPLE_AUTH_ENDPOINT,
            format!("{}/auth/token", server.uri()),
            format!("{}/auth/keys", server.uri()),
        )
        .unwrap();

        let test_cases = [
            (Some(serde_json::Value::Bool(true)), true),
            (Some(serde_json::json!("true")), true),
            (Some(serde_json::json!("TRUE")), true),
            (Some(serde_json::Value::Bool(false)), false),
            (Some(serde_json::json!("false")), false),
            (None, false),
        ];

        let now = Utc::now().timestamp();
        for (flag, expected) in test_cases {
            let claims = MockClaims {
                iss: "https://appleid.apple.com".to_string(),
                aud: "com.example.app".to_string(),
                exp: now + 3600,
                iat: now,
                sub: "sub123".to_string(),
                email: Some("u@example.com".to_string()),
                email_verified: flag,
            };

            let tok = TokenResponse {
                access_token: "at".to_string(),
                token_type: "Bearer".to_string(),
                refresh_token: None,
                expires_in: None,
                id_token: Some(mint_test_id_token("kid-1", claims)),
                raw: HashMap::new(),
            };

            let user = p.fetch_user_info(&tok).await.unwrap();
            assert_eq!(user.email_verified, expected);
        }
    }

    #[tokio::test]
    async fn test_apple_unknown_kid_refresh() {
        let server = MockServer::start().await;

        // JWKS returns kid-2
        Mock::given(method("GET"))
            .and(path("/auth/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "kid": "kid-2",
                        "n": TEST_RSA_N,
                        "e": TEST_RSA_E
                    }
                ]
            })))
            .mount(&server)
            .await;

        let p = AppleProvider::with_endpoints(
            &test_apple_config(),
            reqwest::Client::new(),
            APPLE_AUTH_ENDPOINT,
            format!("{}/auth/token", server.uri()),
            format!("{}/auth/keys", server.uri()),
        )
        .unwrap();

        let now = Utc::now().timestamp();
        let claims = MockClaims {
            iss: "https://appleid.apple.com".to_string(),
            aud: "com.example.app".to_string(),
            exp: now + 3600,
            iat: now,
            sub: "sub-rotated".to_string(),
            email: Some("rotated@example.com".to_string()),
            email_verified: Some(serde_json::Value::Bool(true)),
        };

        // ID token carries kid-2 which is not initially cached
        let tok = TokenResponse {
            access_token: "at".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: None,
            expires_in: None,
            id_token: Some(mint_test_id_token("kid-2", claims)),
            raw: HashMap::new(),
        };

        let user = p.fetch_user_info(&tok).await.unwrap();
        assert_eq!(user.provider_user_id, "sub-rotated");
        assert_eq!(user.email, "rotated@example.com");
    }

    #[tokio::test]
    async fn test_apple_id_token_rejections() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/auth/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "kid": "kid-1",
                        "n": TEST_RSA_N,
                        "e": TEST_RSA_E
                    }
                ]
            })))
            .mount(&server)
            .await;

        let p = AppleProvider::with_endpoints(
            &test_apple_config(),
            reqwest::Client::new(),
            APPLE_AUTH_ENDPOINT,
            format!("{}/auth/token", server.uri()),
            format!("{}/auth/keys", server.uri()),
        )
        .unwrap();

        let now = Utc::now().timestamp();

        // 1. Wrong issuer
        let bad_iss = MockClaims {
            iss: "https://evil.example.com".to_string(),
            aud: "com.example.app".to_string(),
            exp: now + 3600,
            iat: now,
            sub: "sub".to_string(),
            email: None,
            email_verified: None,
        };
        let tok_bad_iss = TokenResponse {
            access_token: "at".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: None,
            expires_in: None,
            id_token: Some(mint_test_id_token("kid-1", bad_iss)),
            raw: HashMap::new(),
        };
        assert!(matches!(
            p.fetch_user_info(&tok_bad_iss).await.unwrap_err(),
            AppError::OAuthProviderError
        ));

        // 2. Wrong audience
        let bad_aud = MockClaims {
            iss: "https://appleid.apple.com".to_string(),
            aud: "com.evil.app".to_string(),
            exp: now + 3600,
            iat: now,
            sub: "sub".to_string(),
            email: None,
            email_verified: None,
        };
        let tok_bad_aud = TokenResponse {
            access_token: "at".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: None,
            expires_in: None,
            id_token: Some(mint_test_id_token("kid-1", bad_aud)),
            raw: HashMap::new(),
        };
        assert!(matches!(
            p.fetch_user_info(&tok_bad_aud).await.unwrap_err(),
            AppError::OAuthProviderError
        ));

        // 3. Expired token
        let expired = MockClaims {
            iss: "https://appleid.apple.com".to_string(),
            aud: "com.example.app".to_string(),
            exp: now - 3600,
            iat: now - 7200,
            sub: "sub".to_string(),
            email: None,
            email_verified: None,
        };
        let tok_expired = TokenResponse {
            access_token: "at".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: None,
            expires_in: None,
            id_token: Some(mint_test_id_token("kid-1", expired)),
            raw: HashMap::new(),
        };
        assert!(matches!(
            p.fetch_user_info(&tok_expired).await.unwrap_err(),
            AppError::OAuthProviderError
        ));

        // 4. Empty sub
        let empty_sub = MockClaims {
            iss: "https://appleid.apple.com".to_string(),
            aud: "com.example.app".to_string(),
            exp: now + 3600,
            iat: now,
            sub: "".to_string(),
            email: None,
            email_verified: None,
        };
        let tok_empty_sub = TokenResponse {
            access_token: "at".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: None,
            expires_in: None,
            id_token: Some(mint_test_id_token("kid-1", empty_sub)),
            raw: HashMap::new(),
        };
        assert!(matches!(
            p.fetch_user_info(&tok_empty_sub).await.unwrap_err(),
            AppError::OAuthProviderError
        ));

        // 5. Tampered token
        let valid_claims = MockClaims {
            iss: "https://appleid.apple.com".to_string(),
            aud: "com.example.app".to_string(),
            exp: now + 3600,
            iat: now,
            sub: "sub".to_string(),
            email: None,
            email_verified: None,
        };
        let mut tampered_jwt = mint_test_id_token("kid-1", valid_claims);
        tampered_jwt.push('A');
        let tok_tampered = TokenResponse {
            access_token: "at".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: None,
            expires_in: None,
            id_token: Some(tampered_jwt),
            raw: HashMap::new(),
        };
        assert!(matches!(
            p.fetch_user_info(&tok_tampered).await.unwrap_err(),
            AppError::OAuthProviderError
        ));
    }
}
