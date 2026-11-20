//! Cryptographic primitives for TOTP two-factor authentication.
//!
//! - AES-256-GCM for reversible encryption of TOTP secrets at rest
//! - RFC 6238 / RFC 4226 code generation and verification

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{config::TOTP_ENCRYPTION_KEY_BYTES, error::AppError};

/// AES-GCM nonce length in bytes (96-bit nonce, per NIST SP 800-38D §8.2).
const NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length in bytes.
const TAG_LEN: usize = 16;
/// Smallest valid blob: nonce plus tag, i.e. an empty plaintext.
const MIN_BLOB_LEN: usize = NONCE_LEN + TAG_LEN;

/// RFC 6238 time step in seconds.
pub const TOTP_STEP_SECS: u64 = 30;
/// TOTP code length in decimal digits.
pub const TOTP_DIGITS: u32 = 6;
/// Accepted clock-drift window in steps (±1, i.e. three steps total).
const TOTP_WINDOW_STEPS: i64 = 1;
/// Raw TOTP secret entropy in bytes (160-bit, RFC 4226 §4 recommendation).
const TOTP_SECRET_BYTES: usize = 20;
/// RFC 4648 base32 without padding, as authenticator apps expect secrets.
const TOTP_ALPHABET: base32::Alphabet = base32::Alphabet::RFC4648 { padding: false };

type HmacSha1 = Hmac<Sha1>;

/// Parse a 64-character hex string into a raw AES-256-GCM key.
pub fn parse_encryption_key(hex_key: &str) -> Result<[u8; TOTP_ENCRYPTION_KEY_BYTES], AppError> {
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

/// Generate a fresh 160-bit TOTP secret as unpadded base32 (32 characters).
#[must_use]
pub fn generate_totp_secret() -> String {
    let mut secret = [0u8; TOTP_SECRET_BYTES];
    OsRng.fill_bytes(&mut secret);
    let encoded = base32::encode(TOTP_ALPHABET, &secret);
    crate::crypto::zeroize_bytes(&mut secret);
    encoded
}

/// Current TOTP step counter: Unix time divided by the step, `T0 = 0`.
#[must_use]
pub fn current_totp_counter() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / TOTP_STEP_SECS
}

/// Generate the TOTP code for `secret` at `counter` (RFC 4226 §5.3 dynamic truncation).
pub fn generate_totp(secret: &[u8], counter: u64) -> Result<u32, AppError> {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(secret).map_err(|_| AppError::Internal)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let offset = usize::from(digest[19] & 0x0f);
    let truncated = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    Ok(truncated % 10u32.pow(TOTP_DIGITS))
}

/// Verify `code` against `secret` within ±1 step of the current time.
///
/// Returns the matching step, which the caller stores to reject replays.
pub fn verify_totp_code(secret: &[u8], code: &str) -> Result<u64, AppError> {
    verify_totp_code_at(secret, code, current_totp_counter())
}

/// Verify `code` against `secret` within ±1 step of `counter`.
pub fn verify_totp_code_at(secret: &[u8], code: &str, counter: u64) -> Result<u64, AppError> {
    let candidate = parse_totp_code(code)?;
    for delta in -TOTP_WINDOW_STEPS..=TOTP_WINDOW_STEPS {
        let Some(step) = counter.checked_add_signed(delta) else {
            continue;
        };
        if generate_totp(secret, step)? == candidate {
            return Ok(step);
        }
    }
    Err(AppError::TotpCodeInvalid)
}

/// Parse a user-supplied code, requiring exactly six ASCII digits.
///
/// Without the length check, `"12345"` would parse as `12345` and match a code that
/// renders as `012345`.
fn parse_totp_code(code: &str) -> Result<u32, AppError> {
    let trimmed = code.trim();
    if trimmed.len() != TOTP_DIGITS as usize || !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AppError::TotpCodeInvalid);
    }
    trimmed.parse().map_err(|_| AppError::TotpCodeInvalid)
}

/// Replay-tracking hash: `SHA-256(code || "::" || step)`.
#[must_use]
pub fn compute_code_replay_hash(code: &str, step: u64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(code.trim().as_bytes());
    hasher.update(b"::");
    hasher.update(step.to_string().as_bytes());
    hasher.finalize().to_vec()
}

/// Build the `otpauth://` provisioning URI for QR rendering.
#[must_use]
pub fn build_otpauth_uri(secret_base32: &str, account_email: &str, issuer: &str) -> String {
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECS}",
        percent_encode(&format!("{issuer}:{account_email}")),
        percent_encode(secret_base32),
        percent_encode(issuer),
    )
}

/// Percent-encode a URI component, keeping RFC 3986 unreserved characters.
fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}
