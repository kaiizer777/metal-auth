//! RFC 6750 Bearer token extraction and verification helpers.

use axum::http::HeaderMap;

/// Extract a bearer token from the `Authorization: Bearer <token>` header.
///
/// Returns `Some(token_string)` on success, or `None` if the header is absent,
/// malformed, or the token portion is empty.
///
/// RFC 6750 requires the "Bearer " scheme prefix (case-sensitive) with a single space.
/// Trailing whitespace is not trimmed per RFC 6750 token syntax.
pub fn read_bearer_token(headers: &HeaderMap) -> Option<String> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())?;

    let token = auth_header.strip_prefix("Bearer ")?;
    if token.is_empty() {
        return None;
    }

    Some(token.to_string())
}

/// Returns true if the `Authorization: Bearer <token>` header is present and non-empty.
pub fn has_bearer_token(headers: &HeaderMap) -> bool {
    read_bearer_token(headers).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::HeaderValue;

    #[test]
    fn test_bearer_extraction_valid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer my-secret-token-123"),
        );

        assert_eq!(read_bearer_token(&headers), Some("my-secret-token-123".to_string()));
        assert!(has_bearer_token(&headers));
    }

    #[test]
    fn test_bearer_extraction_missing() {
        let headers = HeaderMap::new();
        assert_eq!(read_bearer_token(&headers), None);
        assert!(!has_bearer_token(&headers));
    }

    #[test]
    fn test_bearer_extraction_malformed() {
        let cases = [
            "Bearer",
            "Bearer ",
            "bearer validtoken",
            "BEARER validtoken",
            "Basic dXNlcjpwYXNz",
            "Token validtoken",
            "",
        ];

        for val in cases {
            let mut headers = HeaderMap::new();
            if let Ok(hv) = HeaderValue::from_str(val) {
                headers.insert("authorization", hv);
            }
            assert_eq!(read_bearer_token(&headers), None, "Failed for header: {val}");
            assert!(!has_bearer_token(&headers), "Failed for header: {val}");
        }
    }

    #[test]
    fn test_bearer_preserves_exact_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer token.with_special-characters+123=="),
        );
        assert_eq!(
            read_bearer_token(&headers),
            Some("token.with_special-characters+123==".to_string())
        );
    }
}
