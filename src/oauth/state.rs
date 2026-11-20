use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, HeaderValue};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::error::AppError;

type HmacSha256 = Hmac<Sha256>;

/// Browser cap (attributes included) for a single `Set-Cookie` value. Anything
/// larger is dropped silently, which would fail the callback after a full
/// provider round-trip.
const MAX_STATE_COOKIE_LEN: usize = 4096;

/// High-entropy OAuth state payload bound to user's browser session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthStatePayload {
    /// 32-byte CSPRNG token (base64url unpadded) matched against query `state`.
    #[serde(rename = "t")]
    pub token: String,
    /// Canonical provider slug (e.g. "google", "github", "apple").
    #[serde(rename = "p")]
    pub provider_id: String,
    /// PKCE code verifier (RFC 7636) used for code exchange on callback.
    #[serde(rename = "v")]
    pub code_verifier: String,
    /// Optional post-login application redirect destination.
    #[serde(rename = "r", default, skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    /// State expiration timestamp serialized as Unix epoch seconds.
    #[serde(rename = "e", with = "chrono::serde::ts_seconds")]
    pub expires_at: DateTime<Utc>,
    /// Optional authenticated user ID if this state represents an account linking intent.
    #[serde(rename = "u", default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    /// SHA-256 hash of the initiating session token; binds link intent to a live session.
    #[serde(rename = "s", default, skip_serializing_if = "Option::is_none")]
    pub session_hash: Option<String>,
}

/// Generates a 32-byte CSPRNG state token encoded as unpadded base64url.
#[must_use]
pub fn generate_state_token() -> String {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);
    crate::crypto::zeroize_bytes(&mut raw);
    token
}

/// Creates a signed OAuth state cookie value `<payload_b64>.<hmac_sig_b64>`.
pub fn create_state_cookie_value(
    payload: &OAuthStatePayload,
    secret: &[u8],
) -> Result<String, AppError> {
    let json_bytes = serde_json::to_vec(payload).map_err(|_| AppError::OAuthStateInvalid)?;

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| AppError::OAuthStateInvalid)?;
    mac.update(&json_bytes);
    let sig_bytes = mac.finalize().into_bytes();

    let payload_b64 = URL_SAFE_NO_PAD.encode(&json_bytes);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);

    Ok(format!("{payload_b64}.{sig_b64}"))
}

/// Validates an incoming OAuth state cookie against the query state parameter.
pub fn validate_state(
    cookie_val: &str,
    incoming_state: &str,
    expected_provider: &str,
    secret: &[u8],
) -> Result<OAuthStatePayload, AppError> {
    let parts: Vec<&str> = cookie_val.split('.').collect();
    if parts.len() != 2 {
        return Err(AppError::OAuthStateInvalid);
    }
    let payload_b64 = parts[0];
    let sig_b64 = parts[1];

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| AppError::OAuthStateInvalid)?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| AppError::OAuthStateInvalid)?;

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| AppError::OAuthStateInvalid)?;
    mac.update(&payload_bytes);
    if mac.verify_slice(&sig_bytes).is_err() {
        return Err(AppError::OAuthStateInvalid);
    }

    let payload: OAuthStatePayload =
        serde_json::from_slice(&payload_bytes).map_err(|_| AppError::OAuthStateInvalid)?;

    if payload.token.len() != incoming_state.len()
        || payload
            .token
            .as_bytes()
            .ct_eq(incoming_state.as_bytes())
            .unwrap_u8()
            != 1
    {
        return Err(AppError::OAuthStateInvalid);
    }

    if Utc::now() > payload.expires_at {
        return Err(AppError::OAuthStateInvalid);
    }

    if payload.provider_id != expected_provider {
        return Err(AppError::OAuthStateInvalid);
    }

    Ok(payload)
}

/// Cookie variants emitted for the state cookie: set with a value, or cleared.
enum CookieShape<'a> {
    Set { value: &'a str, max_age_secs: u64 },
    Clear,
}

/// Renders the one OAuth state cookie format shared by every set/clear, plain/provider variant.
///
/// `SameSite=None; Secure` is required for Apple's `form_post` cross-site POST and only emitted when
/// the cookie is actually secure; every other combination stays `SameSite=Lax`.
fn format_state_cookie(
    name: &str,
    path: &str,
    shape: CookieShape<'_>,
    secure: bool,
    provider_id: &str,
) -> String {
    let same_site = if provider_id == "apple" && secure {
        "None"
    } else {
        "Lax"
    };

    let mut cookie = match shape {
        CookieShape::Set {
            value,
            max_age_secs,
        } => format!("{name}={value}; Path={path}; Max-Age={max_age_secs}"),
        CookieShape::Clear => {
            format!("{name}=; Path={path}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
        }
    };

    cookie.push_str("; HttpOnly; SameSite=");
    cookie.push_str(same_site);
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Builds a `Set-Cookie` header string for setting the signed OAuth state cookie for a specific provider.
/// For Apple (`response_mode=form_post`), if HTTPS is enabled (`secure == true`), `SameSite=None; Secure`
/// is set so the cross-site POST can carry the cookie. For GET-based providers, `SameSite=Lax` is maintained.
#[must_use]
pub fn build_state_cookie_for_provider(
    name: &str,
    value: &str,
    path: &str,
    max_age_secs: u64,
    secure: bool,
    provider_id: &str,
) -> String {
    format_state_cookie(
        name,
        path,
        CookieShape::Set {
            value,
            max_age_secs,
        },
        secure,
        provider_id,
    )
}

/// Builds a `Set-Cookie` header string for setting the signed OAuth state cookie.
#[must_use]
pub fn build_state_cookie(
    name: &str,
    value: &str,
    path: &str,
    max_age_secs: u64,
    secure: bool,
) -> String {
    build_state_cookie_for_provider(name, value, path, max_age_secs, secure, "")
}

/// Builds a `Set-Cookie` header string for immediately invalidating the OAuth state cookie for a specific provider.
#[must_use]
pub fn build_clear_state_cookie_for_provider(
    name: &str,
    path: &str,
    secure: bool,
    provider_id: &str,
) -> String {
    format_state_cookie(name, path, CookieShape::Clear, secure, provider_id)
}

/// Builds a `Set-Cookie` header string for immediately invalidating the OAuth state cookie.
#[must_use]
pub fn build_clear_state_cookie(name: &str, path: &str, secure: bool) -> String {
    build_clear_state_cookie_for_provider(name, path, secure, "")
}

fn cookie_header_value(raw: String) -> Result<HeaderValue, AppError> {
    HeaderValue::from_str(&raw).map_err(|_| AppError::Internal)
}

/// Builds a `HeaderValue` for setting the signed OAuth state cookie.
pub fn build_state_cookie_header(
    name: &str,
    value: &str,
    path: &str,
    max_age_secs: u64,
    secure: bool,
) -> Result<HeaderValue, AppError> {
    cookie_header_value(build_state_cookie(name, value, path, max_age_secs, secure))
}

/// Builds a `HeaderValue` for setting the signed OAuth state cookie for a specific provider.
pub fn build_state_cookie_header_for_provider(
    name: &str,
    value: &str,
    path: &str,
    max_age_secs: u64,
    secure: bool,
    provider_id: &str,
) -> Result<HeaderValue, AppError> {
    cookie_header_value(build_state_cookie_for_provider(
        name,
        value,
        path,
        max_age_secs,
        secure,
        provider_id,
    ))
}

/// Builds a `HeaderValue` for invalidating the OAuth state cookie.
pub fn build_clear_state_cookie_header(
    name: &str,
    path: &str,
    secure: bool,
) -> Result<HeaderValue, AppError> {
    cookie_header_value(build_clear_state_cookie(name, path, secure))
}

/// Builds a `HeaderValue` for invalidating the OAuth state cookie for a specific provider.
pub fn build_clear_state_cookie_header_for_provider(
    name: &str,
    path: &str,
    secure: bool,
    provider_id: &str,
) -> Result<HeaderValue, AppError> {
    cookie_header_value(build_clear_state_cookie_for_provider(
        name,
        path,
        secure,
        provider_id,
    ))
}

/// Finds `name` in a raw `Cookie:` header value.
fn cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    cookie_header.split(';').find_map(|pair| {
        let (key, val) = pair.trim().split_once('=')?;
        (key == name).then_some(val)
    })
}

/// Extracts an OAuth state cookie value from HTTP request headers.
#[must_use]
pub fn extract_state_cookie<'a>(headers: &'a HeaderMap, cookie_name: &str) -> Option<&'a str> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|cookie_header| cookie_header.to_str().ok())
        .find_map(|cookie_str| cookie_value(cookie_str, cookie_name))
}

/// State manager bundling OAuth state configuration and helper methods.
#[derive(Clone)]
pub struct OAuthStateManager {
    pub cookie_name: String,
    pub cookie_path: String,
    pub state_ttl: std::time::Duration,
    pub state_secret: String,
    pub cookie_secure: bool,
    consumed_states: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
}

impl std::fmt::Debug for OAuthStateManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthStateManager")
            .field("cookie_name", &self.cookie_name)
            .field("cookie_path", &self.cookie_path)
            .field("state_ttl", &self.state_ttl)
            .field("state_secret", &"[REDACTED]")
            .field("cookie_secure", &self.cookie_secure)
            .finish()
    }
}

impl OAuthStateManager {
    #[must_use]
    pub fn new(cfg: &crate::config::OAuthConfig, cookie_secure: bool) -> Self {
        Self {
            cookie_name: cfg.state_cookie_name.clone(),
            cookie_path: cfg.state_cookie_path.clone(),
            state_ttl: cfg.state_ttl,
            state_secret: cfg.state_secret.clone(),
            cookie_secure,
            consumed_states: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn create_state(
        &self,
        provider_id: &str,
        code_verifier: &str,
        redirect_url: Option<String>,
    ) -> Result<(String, String), AppError> {
        self.create_state_with_user(provider_id, code_verifier, redirect_url, None, None)
    }

    pub fn create_state_with_user(
        &self,
        provider_id: &str,
        code_verifier: &str,
        redirect_url: Option<String>,
        user_id: Option<Uuid>,
        session_hash: Option<String>,
    ) -> Result<(String, String), AppError> {
        let token = generate_state_token();
        let expires_at = Utc::now()
            + chrono::Duration::from_std(self.state_ttl)
                .unwrap_or_else(|_| chrono::Duration::minutes(10));
        let payload = OAuthStatePayload {
            token: token.clone(),
            provider_id: provider_id.to_string(),
            code_verifier: code_verifier.to_string(),
            redirect_url,
            expires_at,
            user_id,
            session_hash,
        };
        let cookie_val = create_state_cookie_value(&payload, self.state_secret.as_bytes())?;
        let set_cookie_str = build_state_cookie_for_provider(
            &self.cookie_name,
            &cookie_val,
            &self.cookie_path,
            self.state_ttl.as_secs(),
            self.cookie_secure,
            provider_id,
        );
        if set_cookie_str.len() > MAX_STATE_COOKIE_LEN {
            return Err(AppError::ValidationError(format!(
                "oauth state cookie exceeds {MAX_STATE_COOKIE_LEN} bytes"
            )));
        }
        Ok((token, set_cookie_str))
    }

    pub fn validate(
        &self,
        cookie_header: &str,
        state_param: &str,
        provider_id: &str,
    ) -> Result<OAuthStatePayload, AppError> {
        let Some(cookie_val) = cookie_value(cookie_header, &self.cookie_name) else {
            return Err(AppError::OAuthStateInvalid);
        };

        let payload = validate_state(
            cookie_val,
            state_param,
            provider_id,
            self.state_secret.as_bytes(),
        )?;

        let mut consumed = self
            .consumed_states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Utc::now();
        consumed.retain(|_, exp| *exp > now);
        if consumed.contains_key(&payload.token) {
            return Err(AppError::OAuthStateInvalid);
        }
        consumed.insert(payload.token.clone(), payload.expires_at);

        Ok(payload)
    }

    /// Checks if a state token has already been marked as consumed.
    #[must_use]
    pub fn is_consumed(&self, token: &str) -> bool {
        let mut consumed = self
            .consumed_states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Utc::now();
        consumed.retain(|_, exp| *exp > now);
        consumed.contains_key(token)
    }

    /// Manually marks a state token as consumed with an explicit expiration.
    pub fn mark_consumed(&self, token: &str, expires_at: DateTime<Utc>) {
        let mut consumed = self
            .consumed_states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Utc::now();
        consumed.retain(|_, exp| *exp > now);
        consumed.insert(token.to_string(), expires_at);
    }

    #[must_use]
    pub fn build_clear_cookie(&self) -> String {
        build_clear_state_cookie(&self.cookie_name, &self.cookie_path, self.cookie_secure)
    }

    #[must_use]
    pub fn build_clear_cookie_for_provider(&self, provider_id: &str) -> String {
        build_clear_state_cookie_for_provider(
            &self.cookie_name,
            &self.cookie_path,
            self.cookie_secure,
            provider_id,
        )
    }

    pub fn build_clear_cookie_header(&self) -> Result<HeaderValue, AppError> {
        build_clear_state_cookie_header(&self.cookie_name, &self.cookie_path, self.cookie_secure)
    }

    pub fn build_clear_cookie_header_for_provider(
        &self,
        provider_id: &str,
    ) -> Result<HeaderValue, AppError> {
        build_clear_state_cookie_header_for_provider(
            &self.cookie_name,
            &self.cookie_path,
            self.cookie_secure,
            provider_id,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    const TEST_SECRET: &[u8] = b"01234567890123456789012345678901";

    #[test]
    fn test_state_cookie_lifecycle_and_validation() {
        let token = generate_state_token();
        assert_eq!(token.len(), 43);

        let expires_at = Utc::now() + ChronoDuration::minutes(10);
        let payload = OAuthStatePayload {
            token: token.clone(),
            provider_id: "google".to_string(),
            code_verifier: "test_code_verifier_1234567890_43chars_len_pkce".to_string(),
            redirect_url: Some("/dashboard".to_string()),
            expires_at,
            user_id: None,
            session_hash: None,
        };

        let cookie_val =
            create_state_cookie_value(&payload, TEST_SECRET).expect("create state cookie");
        assert!(cookie_val.contains('.'));

        let validated = validate_state(&cookie_val, &token, "google", TEST_SECRET)
            .expect("validate valid state");

        assert_eq!(validated.token, token);
        assert_eq!(validated.provider_id, "google");
        assert_eq!(
            validated.code_verifier,
            "test_code_verifier_1234567890_43chars_len_pkce"
        );
        assert_eq!(validated.redirect_url.as_deref(), Some("/dashboard"));
        assert_eq!(validated.expires_at.timestamp(), expires_at.timestamp());
    }

    #[test]
    fn test_state_tamper_signature_rejection() {
        let token = generate_state_token();
        let payload = OAuthStatePayload {
            token: token.clone(),
            provider_id: "google".to_string(),
            code_verifier: "verifier".to_string(),
            redirect_url: None,
            expires_at: Utc::now() + ChronoDuration::minutes(10),
            user_id: None,
            session_hash: None,
        };

        let cookie_val =
            create_state_cookie_value(&payload, TEST_SECRET).expect("create state cookie");
        let parts: Vec<&str> = cookie_val.split('.').collect();

        // Tamper signature
        let tampered_sig = format!("{}.{}", parts[0], "tampered_signature_bytes");
        assert!(validate_state(&tampered_sig, &token, "google", TEST_SECRET).is_err());

        // Tamper payload
        let tampered_payload = format!("tampered_payload.{}", parts[1]);
        assert!(validate_state(&tampered_payload, &token, "google", TEST_SECRET).is_err());

        // Wrong secret
        let wrong_secret = b"wrong_secret_key_32_bytes_long!!";
        assert!(validate_state(&cookie_val, &token, "google", wrong_secret).is_err());
    }

    #[test]
    fn test_state_expired_rejection() {
        let token = generate_state_token();
        let payload = OAuthStatePayload {
            token: token.clone(),
            provider_id: "google".to_string(),
            code_verifier: "verifier".to_string(),
            redirect_url: None,
            expires_at: Utc::now() - ChronoDuration::seconds(5),
            user_id: None,
            session_hash: None,
        };

        let cookie_val =
            create_state_cookie_value(&payload, TEST_SECRET).expect("create state cookie");
        assert!(validate_state(&cookie_val, &token, "google", TEST_SECRET).is_err());
    }

    #[test]
    fn test_state_provider_mismatch_rejection() {
        let token = generate_state_token();
        let payload = OAuthStatePayload {
            token: token.clone(),
            provider_id: "google".to_string(),
            code_verifier: "verifier".to_string(),
            redirect_url: None,
            expires_at: Utc::now() + ChronoDuration::minutes(10),
            user_id: None,
            session_hash: None,
        };

        let cookie_val =
            create_state_cookie_value(&payload, TEST_SECRET).expect("create state cookie");
        assert!(validate_state(&cookie_val, &token, "github", TEST_SECRET).is_err());
    }

    #[test]
    fn test_state_token_mismatch_rejection() {
        let token = generate_state_token();
        let payload = OAuthStatePayload {
            token,
            provider_id: "google".to_string(),
            code_verifier: "verifier".to_string(),
            redirect_url: None,
            expires_at: Utc::now() + ChronoDuration::minutes(10),
            user_id: None,
            session_hash: None,
        };

        let cookie_val =
            create_state_cookie_value(&payload, TEST_SECRET).expect("create state cookie");
        assert!(
            validate_state(&cookie_val, "attacker_state_token", "google", TEST_SECRET).is_err()
        );
    }

    #[test]
    fn test_cookie_string_generation_and_headers() {
        let set_cookie = build_state_cookie("oauth_state", "val123", "/", 600, true);
        assert!(set_cookie.contains("oauth_state=val123"));
        assert!(set_cookie.contains("Path=/"));
        assert!(set_cookie.contains("Max-Age=600"));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Lax"));
        assert!(set_cookie.contains("Secure"));

        let clear_cookie = build_clear_state_cookie("oauth_state", "/", true);
        assert!(clear_cookie.contains("oauth_state="));
        assert!(clear_cookie.contains("Max-Age=0"));
        assert!(clear_cookie.contains("Expires=Thu, 01 Jan 1970 00:00:00 GMT"));
        assert!(clear_cookie.contains("HttpOnly"));
        assert!(clear_cookie.contains("SameSite=Lax"));
        assert!(clear_cookie.contains("Secure"));

        let header = build_state_cookie_header("oauth_state", "val123", "/", 600, false)
            .expect("build header");
        assert!(!header.to_str().unwrap().contains("Secure"));

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("other=foo; oauth_state=val123; session=bar"),
        );
        let extracted = extract_state_cookie(&headers, "oauth_state");
        assert_eq!(extracted, Some("val123"));
        assert_eq!(extract_state_cookie(&headers, "nonexistent"), None);
    }

    #[test]
    fn test_cookie_strings_are_byte_exact() {
        assert_eq!(
            build_state_cookie("oauth_state", "val123", "/", 600, false),
            "oauth_state=val123; Path=/; Max-Age=600; HttpOnly; SameSite=Lax"
        );
        assert_eq!(
            build_state_cookie_for_provider("oauth_state", "val123", "/", 600, true, "apple"),
            "oauth_state=val123; Path=/; Max-Age=600; HttpOnly; SameSite=None; Secure"
        );
        assert_eq!(
            build_clear_state_cookie("oauth_state", "/", false),
            "oauth_state=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax"
        );
        assert_eq!(
            build_clear_state_cookie_for_provider("oauth_state", "/", true, "apple"),
            "oauth_state=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=None; Secure"
        );
    }

    #[test]
    fn create_state_rejects_cookie_above_browser_limit_for_escaped_redirect() {
        // Largest redirect the HTTP handler accepts (handler::oauth::MAX_REDIRECT_URL_LEN).
        const MAX_REDIRECT_URL_LEN: usize = 2048;
        let cfg = crate::config::OAuthConfig {
            state_secret: "01234567890123456789012345678901".to_string(),
            ..Default::default()
        };
        let mgr = OAuthStateManager::new(&cfg, true);

        let plain = format!("/{}", "a".repeat(MAX_REDIRECT_URL_LEN - 1));
        let (_, cookie) = mgr
            .create_state("google", "verifier", Some(plain))
            .expect("a plain redirect at the limit fits");
        assert!(cookie.len() <= MAX_STATE_COOKIE_LEN);

        // JSON escaping doubles every quote, so the raw limit no longer bounds the cookie.
        let escaped = format!("/{}", "\"".repeat(MAX_REDIRECT_URL_LEN - 1));
        assert_eq!(escaped.len(), MAX_REDIRECT_URL_LEN);
        assert!(matches!(
            mgr.create_state("google", "verifier", Some(escaped)),
            Err(AppError::ValidationError(_))
        ));
    }

    #[test]
    fn extract_state_cookie_scans_every_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.append(
            axum::http::header::COOKIE,
            HeaderValue::from_static("session=abc"),
        );
        headers.append(
            axum::http::header::COOKIE,
            HeaderValue::from_static("other=1; oauth_state=from_second"),
        );

        assert_eq!(
            extract_state_cookie(&headers, "oauth_state"),
            Some("from_second")
        );
    }

    #[test]
    fn test_oauth_state_manager_lifecycle() {
        let cfg = crate::config::OAuthConfig {
            state_secret: "01234567890123456789012345678901".to_string(),
            ..Default::default()
        };
        let mgr = OAuthStateManager::new(&cfg, false);

        let (state_token, set_cookie) = mgr
            .create_state("google", "pkce_verifier_val", Some("/profile".to_string()))
            .expect("create state");
        assert!(set_cookie.contains("oauth_state="));

        // Validate using full Cookie header string
        let payload = mgr
            .validate(&set_cookie, &state_token, "google")
            .expect("validate state");
        assert_eq!(payload.provider_id, "google");
        assert_eq!(payload.code_verifier, "pkce_verifier_val");
        assert_eq!(payload.redirect_url, Some("/profile".to_string()));

        // Second validation must fail due to replay protection
        assert!(mgr.is_consumed(&state_token));
        let replay_err = mgr.validate(&set_cookie, &state_token, "google");
        assert!(matches!(replay_err, Err(AppError::OAuthStateInvalid)));

        let clear_cookie = mgr.build_clear_cookie();
        assert!(clear_cookie.contains("Max-Age=0"));

        // Verify Debug redacts state_secret
        let debug_str = format!("{mgr:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("01234567890123456789012345678901"));
    }

    #[test]
    fn test_apple_samesite_none_secure_handling() {
        let cfg = crate::config::OAuthConfig {
            state_secret: "01234567890123456789012345678901".to_string(),
            ..Default::default()
        };

        // 1. Apple with HTTPS (secure = true): SameSite=None; Secure
        let mgr_secure = OAuthStateManager::new(&cfg, true);
        let (_, apple_cookie_secure) = mgr_secure
            .create_state("apple", "verifier_apple", None)
            .expect("create apple state");
        assert!(apple_cookie_secure.contains("SameSite=None"));
        assert!(apple_cookie_secure.contains("Secure"));

        let apple_clear_secure = mgr_secure.build_clear_cookie_for_provider("apple");
        assert!(apple_clear_secure.contains("SameSite=None"));
        assert!(apple_clear_secure.contains("Secure"));

        // 2. Apple with HTTP (secure = false): SameSite=Lax (browsers reject SameSite=None without Secure)
        let mgr_insecure = OAuthStateManager::new(&cfg, false);
        let (_, apple_cookie_insecure) = mgr_insecure
            .create_state("apple", "verifier_apple", None)
            .expect("create apple state");
        assert!(apple_cookie_insecure.contains("SameSite=Lax"));
        assert!(!apple_cookie_insecure.contains("Secure"));

        // 3. GET providers (e.g. google, github) with secure = true: SameSite=Lax; Secure
        let (_, google_cookie_secure) = mgr_secure
            .create_state("google", "verifier_google", None)
            .expect("create google state");
        assert!(google_cookie_secure.contains("SameSite=Lax"));
        assert!(google_cookie_secure.contains("Secure"));
    }

    #[test]
    fn rejects_header_without_state_cookie() {
        let cfg = crate::config::OAuthConfig {
            state_secret: "01234567890123456789012345678901".to_string(),
            ..Default::default()
        };
        let mgr = OAuthStateManager::new(&cfg, false);
        let (token, set_cookie) = mgr
            .create_state("google", "verifier", None)
            .expect("create");
        let cookie_val = set_cookie
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1;

        // bare cookie value with no `=` is not a Cookie header → reject
        assert!(matches!(
            mgr.validate(cookie_val, &token, "google"),
            Err(AppError::OAuthStateInvalid)
        ));

        // jar carrying other cookies but not ours → reject
        let (token2, _) = mgr
            .create_state("google", "verifier", None)
            .expect("create");
        assert!(matches!(
            mgr.validate("unrelated=1; other=2", &token2, "google"),
            Err(AppError::OAuthStateInvalid)
        ));
    }

    #[test]
    fn rejects_own_cookie_under_a_different_name() {
        let cfg = crate::config::OAuthConfig {
            state_secret: "01234567890123456789012345678901".to_string(),
            ..Default::default()
        };
        let mgr = OAuthStateManager::new(&cfg, false);
        let (token, set_cookie) = mgr
            .create_state("google", "verifier", None)
            .expect("create");
        let cookie_val = set_cookie
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1;

        // A validly signed value planted under another cookie name is still not our state cookie.
        let jar = format!("x_oauth_state={cookie_val}; session=abc");
        assert!(matches!(
            mgr.validate(&jar, &token, "google"),
            Err(AppError::OAuthStateInvalid)
        ));
    }

    #[test]
    fn test_state_with_user_link_intent() {
        let cfg = crate::config::OAuthConfig {
            state_secret: "01234567890123456789012345678901".to_string(),
            ..Default::default()
        };
        let mgr = OAuthStateManager::new(&cfg, false);
        let link_user_id = Uuid::new_v4();

        let (token, cookie_str) = mgr
            .create_state_with_user(
                "google",
                "pkce_val",
                Some("/settings".to_string()),
                Some(link_user_id),
                Some("session-hash-abc".to_string()),
            )
            .expect("create state with user");

        let payload = mgr
            .validate(&cookie_str, &token, "google")
            .expect("validate state with user");

        assert_eq!(payload.user_id, Some(link_user_id));
        assert_eq!(payload.session_hash.as_deref(), Some("session-hash-abc"));
        assert_eq!(payload.redirect_url.as_deref(), Some("/settings"));
    }
}
