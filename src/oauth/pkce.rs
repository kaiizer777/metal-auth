use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::AppError;

/// RFC 7636 PKCE Challenge and Verifier pair.
#[derive(Clone, PartialEq, Eq)]
pub struct PKCEChallenge {
    /// 43-character URL-safe unpadded base64 string derived from 32 CSPRNG bytes.
    pub verifier: String,
    /// SHA-256 digest of the verifier, URL-safe unpadded base64 encoded.
    pub challenge: String,
    /// Strictly "S256" (RFC 7636 §4.2). Plain method is prohibited.
    pub method: &'static str,
}

impl std::fmt::Debug for PKCEChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PKCEChallenge")
            .field("verifier", &"[REDACTED]")
            .field("challenge", &self.challenge)
            .field("method", &self.method)
            .finish()
    }
}

/// Generates a 32-byte CSPRNG verifier and computes its RFC 7636 S256 code challenge.
pub fn generate_pkce() -> Result<PKCEChallenge, AppError> {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let verifier = URL_SAFE_NO_PAD.encode(raw);
    crate::crypto::zeroize_bytes(&mut raw);

    let challenge = compute_challenge(&verifier);

    Ok(PKCEChallenge {
        verifier,
        challenge,
        method: "S256",
    })
}

/// Computes the RFC 7636 S256 code challenge for a given code verifier.
#[must_use]
pub fn compute_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    URL_SAFE_NO_PAD.encode(digest)
}

/// Constant-time verification of a code verifier against an expected S256 challenge.
#[must_use]
pub fn verify_pkce(verifier: &str, expected_challenge: &str) -> bool {
    let computed = compute_challenge(verifier);
    computed
        .as_bytes()
        .ct_eq(expected_challenge.as_bytes())
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_pkce_entropy_and_format() {
        let pkce = generate_pkce().expect("generate pkce");
        assert_eq!(pkce.method, "S256");
        // 32 bytes base64url unpadded is exactly 43 characters
        assert_eq!(pkce.verifier.len(), 43);
        // SHA-256 (32 bytes) base64url unpadded is exactly 43 characters
        assert_eq!(pkce.challenge.len(), 43);
        // Ensure only URL-safe characters
        assert!(
            pkce.verifier
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert!(
            pkce.challenge
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        // Verify challenge matches computed
        assert_eq!(compute_challenge(&pkce.verifier), pkce.challenge);
        assert!(verify_pkce(&pkce.verifier, &pkce.challenge));
    }

    #[test]
    fn test_pkce_challenge_computation_golden_vector() {
        // RFC 7636 Appendix B test vector
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        let computed = compute_challenge(verifier);
        assert_eq!(computed, expected_challenge);
        assert!(verify_pkce(verifier, expected_challenge));
        assert!(!verify_pkce(verifier, "tampered-challenge-value"));
    }

    #[test]
    fn test_pkce_challenge_debug_redaction() {
        let pkce = generate_pkce().expect("generate pkce");
        let debug_str = format!("{pkce:?}");
        assert!(!debug_str.contains(&pkce.verifier));
        assert!(debug_str.contains("[REDACTED]"));
        assert!(debug_str.contains(&pkce.challenge));
        assert!(debug_str.contains("S256"));
    }
}
