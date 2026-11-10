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

/// Decode hex token and compute its SHA-256 digest for DB lookup.
///
/// Validates that the input is valid hex and decodes to exactly 32 bytes (64 hex characters).
pub fn hash_token(hex_token: &str) -> Result<[u8; 32], AppError> {
    if hex_token.len() != 64 {
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
        assert!(matches!(
            hash_token("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"),
            Err(AppError::InvalidToken)
        ));
        // 66 chars (too long)
        assert!(matches!(
            hash_token("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"),
            Err(AppError::InvalidToken)
        ));
        // Valid length but non-hex char
        assert!(matches!(
            hash_token("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1z"),
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
}
