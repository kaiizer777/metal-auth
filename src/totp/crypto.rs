//! Cryptographic primitives for TOTP two-factor authentication.
//!
//! - AES-256-GCM for reversible encryption of TOTP secrets at rest
//! - RFC 6238 / RFC 4226 code generation and verification

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use rand_core::{OsRng, RngCore};

use crate::{config::TOTP_ENCRYPTION_KEY_BYTES, error::AppError};

/// AES-GCM nonce length in bytes (96-bit nonce, per NIST SP 800-38D §8.2).
const NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length in bytes.
const TAG_LEN: usize = 16;
/// Smallest valid blob: nonce plus tag, i.e. an empty plaintext.
const MIN_BLOB_LEN: usize = NONCE_LEN + TAG_LEN;

/// Parse a 64-character hex string into a raw AES-256-GCM key.
pub fn parse_encryption_key(
    hex_key: &str,
) -> Result<[u8; TOTP_ENCRYPTION_KEY_BYTES], AppError> {
    if hex_key.len() != TOTP_ENCRYPTION_KEY_BYTES * 2
        || !hex_key.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(AppError::Internal);
    }
    let mut key = [0u8; TOTP_ENCRYPTION_KEY_BYTES];
    hex::decode_to_slice(hex_key, &mut key).map_err(|_| AppError::Internal)?;
    Ok(key)
}

/// Encrypt `plaintext` with AES-256-GCM under a fresh CSPRNG nonce.
///
/// Output layout: `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
pub fn encrypt_secret(
    key: &[u8; TOTP_ENCRYPTION_KEY_BYTES],
    plaintext: &[u8],
) -> Result<Vec<u8>, AppError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|err| {
            tracing::error!(error = %err, "totp secret encryption failed");
            AppError::Internal
        })?;

    let mut blob = Vec::with_capacity(MIN_BLOB_LEN + plaintext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt a `nonce || ciphertext || tag` blob produced by [`encrypt_secret`].
///
/// Fails on truncation, tampering, and wrong keys alike: distinguishing them would
/// tell an attacker whether a guessed key was close, so all map to an internal error.
pub fn decrypt_secret(
    key: &[u8; TOTP_ENCRYPTION_KEY_BYTES],
    blob: &[u8],
) -> Result<Vec<u8>, AppError> {
    if blob.len() < MIN_BLOB_LEN {
        return Err(AppError::Internal);
    }
    let (nonce_bytes, payload) = blob.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), payload)
        .map_err(|err| {
            tracing::warn!(error = %err, "totp secret decryption failed");
            AppError::Internal
        })
}
