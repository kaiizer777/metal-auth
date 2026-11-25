//! Time-based one-time password (TOTP) two-factor authentication.
//!
//! # Architectural Boundary
//!
//! This module owns the RFC 6238 primitive layer: AES-256-GCM encryption of TOTP
//! secrets at rest, code generation/verification, replay hashes, and single-use
//! backup codes. Storage models live in [`crate::db::models`]; HTTP routing belongs
//! to [`crate::handler`].
pub mod backup;
pub mod crypto;
#[cfg(feature = "postgres")]
pub mod service;
