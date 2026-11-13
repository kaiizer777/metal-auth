//! Session management primitives, storage abstractions, and lifecycle tracking.
//!
//! # Architectural Boundary
//!
//! This module is an architectural extension point reserved for future phase stateful session management.
//!
//! ## Planned Capabilities
//! - Pluggable session store traits (e.g., Redis, PostgreSQL, distributed cache).
//! - Lifecycle tracking: sliding window expiration, idle timeouts, and absolute limits.
//! - Multi-device session enumeration, revocation lists, and concurrent session caps.
//!
//! ## Boundaries & Constraints
//! - Storage backends operate on the [`Session`](crate::Session) model while remaining decoupled
//!   from core Axum HTTP handler bindings.

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

/// Generates a URL-safe, CSPRNG-based session ID with ≥ 32 bytes of entropy.
///
/// Returns a 64-character lowercase hex string (32 raw bytes → 64 hex chars).
pub fn generate_session_id() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Returns the SHA-256 hex digest of `id`.
///
/// Deterministic: same input always yields the same output.
pub fn hash_session_id(id: &str) -> String {
    let digest = Sha256::digest(id.as_bytes());
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_length_and_charset() {
        let id = generate_session_id();
        assert_eq!(id.len(), 64, "must be 64 hex chars (32 bytes)");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "must be hex");
    }

    #[test]
    fn session_id_uniqueness() {
        let a = generate_session_id();
        let b = generate_session_id();
        assert_ne!(a, b, "successive calls must differ");
    }

    #[test]
    fn hash_session_id_deterministic() {
        let id = "some-session-token";
        assert_eq!(hash_session_id(id), hash_session_id(id));
        assert_eq!(
            hash_session_id(id),
            "17afed9ae6329b2a14997a13ff22cfb53cc93bd85c84b83053374a9b2d3df519"
        );
        assert_ne!(
            hash_session_id(id),
            hash_session_id("another-session-token")
        );
    }
}
