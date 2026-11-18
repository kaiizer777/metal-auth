use axum::http::{HeaderMap, HeaderValue};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::AppError;

type HmacSha256 = Hmac<Sha256>;

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
        || payload.token.as_bytes().ct_eq(incoming_state.as_bytes()).unwrap_u8() != 1
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

/// Builds a `Set-Cookie` header string for setting the signed OAuth state cookie.
#[must_use]
pub fn build_state_cookie(
    name: &str,
    value: &str,
    path: &str,
    max_age_secs: u64,
    secure: bool,
) -> String {
    let mut cookie = format!(
        "{name}={value}; Path={path}; Max-Age={max_age_secs}; HttpOnly; SameSite=Lax"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Builds a `Set-Cookie` header string for immediately invalidating the OAuth state cookie.
#[must_use]
pub fn build_clear_state_cookie(name: &str, path: &str, secure: bool) -> String {
    let mut cookie = format!(
        "{name}=; Path={path}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Builds a `HeaderValue` for setting the signed OAuth state cookie.
pub fn build_state_cookie_header(
    name: &str,
    value: &str,
    path: &str,
    max_age_secs: u64,
    secure: bool,
) -> Result<HeaderValue, AppError> {
    let raw = build_state_cookie(name, value, path, max_age_secs, secure);
    HeaderValue::from_str(&raw).map_err(|_| AppError::Internal)
}

/// Builds a `HeaderValue` for invalidating the OAuth state cookie.
pub fn build_clear_state_cookie_header(
    name: &str,
    path: &str,
    secure: bool,
) -> Result<HeaderValue, AppError> {
    let raw = build_clear_state_cookie(name, path, secure);
    HeaderValue::from_str(&raw).map_err(|_| AppError::Internal)
}

/// Extracts an OAuth state cookie value from HTTP request headers.
#[must_use]
pub fn extract_state_cookie<'a>(headers: &'a HeaderMap, cookie_name: &str) -> Option<&'a str> {
    for cookie_header in headers.get_all(axum::http::header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for pair in cookie_str.split(';') {
                let mut parts = pair.trim().splitn(2, '=');
                if let (Some(name), Some(val)) = (parts.next(), parts.next()) {
                    if name == cookie_name {
                        return Some(val);
                    }
                }
            }
        }
    }
    None
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
        };

        let cookie_val =
            create_state_cookie_value(&payload, TEST_SECRET).expect("create state cookie");
        assert!(validate_state(&cookie_val, "attacker_state_token", "google", TEST_SECRET).is_err());
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
}
