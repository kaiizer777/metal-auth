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
