//! Secure token generation and SHA-256 hashing for verification and reset flows.

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::error::AppError;

/// Generate a secure single-use token for email verification or password reset.
///
/// Returns `(raw_hex_token, stored_hash)` where:
/// - `raw_hex_token` — 64-char lowercase hex string sent to the user via email
/// - `stored_hash` — 32-byte SHA-256 digest of the raw bytes stored in DB
#[must_use]
pub fn generate_token() -> (String, [u8; 32]) {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    let raw_hex = hex::encode(buf);
    let stored_hash = Sha256::digest(buf).into();
    (raw_hex, stored_hash)
}

/// Validate whether `token` is a 64-character ASCII hexadecimal string.
#[must_use]
pub fn is_valid_token_format(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Decode hex token and compute its SHA-256 digest for DB lookup.
///
/// Validates that the input is valid hex and decodes to exactly 32 bytes (64 hex characters).
pub fn hash_token(hex_token: &str) -> Result<[u8; 32], AppError> {
    if !is_valid_token_format(hex_token) {
        return Err(AppError::InvalidToken);
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex_token, &mut bytes).map_err(|_| AppError::InvalidToken)?;
    Ok(Sha256::digest(bytes).into())
}

/// Alias for [`hash_token`] for backward compatibility with existing callers.
pub fn sha256_of_hex_token(hex_token: &str) -> Result<[u8; 32], AppError> {
    hash_token(hex_token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hex_is_64_chars() {
        let (hex, _) = generate_token();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hex, hex.to_lowercase());
    }

    #[test]
    fn stored_hash_is_32_bytes() {
        let (_, hash) = generate_token();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn two_successive_tokens_are_distinct() {
        let (h1, _) = generate_token();
        let (h2, _) = generate_token();
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_token_round_trips() {
        let (hex, stored_hash) = generate_token();
        let derived = hash_token(&hex).unwrap();
        assert_eq!(derived, stored_hash);
        let derived_alias = sha256_of_hex_token(&hex).unwrap();
        assert_eq!(derived_alias, stored_hash);
    }

    #[test]
    fn hash_token_rejects_invalid_hex() {
        assert!(matches!(
            hash_token("not-valid-hex!"),
            Err(AppError::InvalidToken)
        ));
        // Odd length
        assert!(matches!(hash_token("123"), Err(AppError::InvalidToken)));
        // 62 chars (too short)
        let too_short = "0".repeat(62);
        assert!(matches!(
            hash_token(&too_short),
            Err(AppError::InvalidToken)
        ));
        // 66 chars (too long)
        let too_long = "0".repeat(66);
        assert!(matches!(hash_token(&too_long), Err(AppError::InvalidToken)));
        // Valid length (64 chars) but non-hex char
        let invalid_char = format!("{}z", "0".repeat(63));
        assert_eq!(invalid_char.len(), 64);
        assert!(matches!(
            hash_token(&invalid_char),
            Err(AppError::InvalidToken)
        ));
    }

    #[test]
    fn deterministic_known_input() {
        let zero_bytes = [0u8; 32];
        let hex_input = hex::encode(zero_bytes);
        let got = hash_token(&hex_input).unwrap();
        let mut expected = [0u8; 32];
        hex::decode_to_slice(
            "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
            &mut expected,
        )
        .unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn is_valid_token_format_validates_correctly() {
        let (valid_token, _) = generate_token();
        assert!(is_valid_token_format(&valid_token));
        assert!(is_valid_token_format(&valid_token.to_uppercase()));

        // Empty string
        assert!(!is_valid_token_format(""));

        // Length variations
        assert!(!is_valid_token_format(&"a".repeat(63)));
        assert!(!is_valid_token_format(&"a".repeat(65)));

        // Non-hex chars
        let with_g = format!("{}g", "a".repeat(63));
        assert!(!is_valid_token_format(&with_g));

        // Multibyte unicode
        let with_unicode = format!("{}🦀", "a".repeat(60));
        assert!(!is_valid_token_format(&with_unicode));
        assert!(!is_valid_token_format("🔐".repeat(16).as_str()));

        // Whitespace and symbols
        let with_space = format!("{} ", "a".repeat(63));
        assert!(!is_valid_token_format(&with_space));
    }

    #[test]
    fn hash_token_rejects_empty_string_and_unicode() {
        assert!(matches!(hash_token(""), Err(AppError::InvalidToken)));
        assert!(matches!(
            hash_token("🦀".repeat(16).as_str()),
            Err(AppError::InvalidToken)
        ));
    }

    #[test]
    fn hash_token_accepts_uppercase_hex() {
        let (token, stored_hash) = generate_token();
        let upper = token.to_uppercase();
        assert!(is_valid_token_format(&upper));
        let hash = hash_token(&upper).unwrap();
        assert_eq!(hash, stored_hash);
    }
}
