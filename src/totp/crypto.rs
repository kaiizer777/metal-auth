//! Cryptographic primitives for TOTP two-factor authentication.
//!
//! - AES-256-GCM for reversible encryption of TOTP secrets at rest
//! - RFC 6238 / RFC 4226 code generation and verification

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit},
};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::AppError;

/// AES-256-GCM key length in bytes.
pub const AES_KEY_BYTES: usize = 32;

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
/// Minimum used-code prune horizon: the three accepted steps plus one margin step.
///
/// A code stays valid at `T-1`, `T`, and `T+1`; pruning at the bare three-step span
/// would delete the row exactly when the last accepted step begins.
pub const MIN_USED_CODE_PRUNE_AGE_SECS: u64 = 3 * TOTP_STEP_SECS + TOTP_STEP_SECS;
/// Raw TOTP secret entropy in bytes (160-bit, RFC 4226 §4 recommendation).
const TOTP_SECRET_BYTES: usize = 20;
/// RFC 4648 base32 without padding, as authenticator apps expect secrets.
const TOTP_ALPHABET: base32::Alphabet = base32::Alphabet::RFC4648 { padding: false };

type HmacSha1 = Hmac<Sha1>;

/// Decrypted TOTP secret that zeroes its bytes on drop.
///
/// [`decrypt_secret`] returns this guard so no caller can leave the seed resident in the
/// heap after use. Deref to borrow it as `&[u8]`.
pub struct DecryptedSecret(Vec<u8>);

impl std::ops::Deref for DecryptedSecret {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for DecryptedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for DecryptedSecret {
    fn drop(&mut self) {
        crate::crypto::zeroize_bytes(&mut self.0);
    }
}

// Manual `Debug`: the contained bytes are the live TOTP seed.
impl std::fmt::Debug for DecryptedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedSecret")
            .field("bytes", &"[redacted]")
            .field("len", &self.0.len())
            .finish()
    }
}

/// Encrypt `plaintext` with AES-256-GCM under a fresh CSPRNG nonce.
///
/// Output layout: `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
pub fn encrypt_secret(key: &[u8; AES_KEY_BYTES], plaintext: &[u8]) -> Result<Vec<u8>, AppError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    // Drawn straight from the CSPRNG: no caller-visible buffer exists before it is filled.
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|err| {
        tracing::error!(error = %err, "totp secret encryption failed");
        AppError::Internal
    })?;

    let mut blob = Vec::with_capacity(MIN_BLOB_LEN + plaintext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt a `nonce || ciphertext || tag` blob produced by [`encrypt_secret`].
///
/// Fails on truncation, tampering, and wrong keys alike: distinguishing them would
/// tell an attacker whether a guessed key was close, so all map to an internal error.
/// The returned guard zeroes the plaintext when dropped.
pub fn decrypt_secret(key: &[u8; AES_KEY_BYTES], blob: &[u8]) -> Result<DecryptedSecret, AppError> {
    if blob.len() < MIN_BLOB_LEN {
        return Err(AppError::Internal);
    }
    let (nonce_bytes, payload) = blob.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), payload)
        .map_err(|err| {
            tracing::warn!(error = %err, "totp secret decryption failed");
            AppError::Internal
        })?;
    Ok(DecryptedSecret(plaintext))
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

/// Decode an unpadded RFC 4648 base32 TOTP secret into its raw HMAC key bytes.
///
/// Accepts upper- and lower-case input, rejects padding, whitespace, non-alphabet
/// characters, and non-canonical trailing bits. HMAC must run over these bytes, never
/// over the base32 ASCII that authenticator apps display.
pub fn decode_totp_secret(secret_base32: &str) -> Result<Vec<u8>, AppError> {
    if secret_base32.is_empty() {
        return Err(AppError::Internal);
    }

    let mut accumulator: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut decoded = Vec::with_capacity(secret_base32.len() * 5 / 8);

    for character in secret_base32.chars() {
        let value = match character {
            'A'..='Z' => character as u32 - 'A' as u32,
            'a'..='z' => character as u32 - 'a' as u32,
            '2'..='7' => character as u32 - '2' as u32 + 26,
            _ => return Err(AppError::Internal),
        };
        accumulator = (accumulator << 5) | value;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            decoded.push((accumulator >> bit_count) as u8);
            accumulator &= (1 << bit_count) - 1;
        }
    }

    // Fewer than five trailing bits is the only valid remainder; any set bit or a
    // five-plus-bit leftover encodes a partial symbol and is non-canonical.
    if bit_count >= 5 || accumulator != 0 {
        return Err(AppError::Internal);
    }
    // RFC 4226 seeds are 160 bits; a shorter or longer canonical string is not a TOTP key.
    if decoded.len() != TOTP_SECRET_BYTES {
        return Err(AppError::Internal);
    }
    Ok(decoded)
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
///
/// The result is a plain `u32` with leading zeros already stripped: render it for
/// display or comparison as `format!("{code:06}")`, never with `{}`, or roughly 10% of
/// codes lose a digit.
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

/// Replay-tracking hash: `SHA-256(code)` scoped by the row's `user_id`.
///
/// The time step is deliberately excluded: a code is valid at `T-1`, `T`, and `T+1`,
/// so hashing the step would let one captured code be redeemed three times. The unique
/// constraint on `(user_id, code_hash)` is the single arbiter.
#[must_use]
pub fn compute_code_replay_hash(code: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(code.trim().as_bytes());
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

/// Percent-encode a URI component, keeping RFC 3986 unreserved characters plus `:` and `@`.
///
/// Both are legal in path and query tokens, and the canonical `otpauth://` label keeps
/// them literal (`Issuer:account@example.com`). Everything that could break either
/// component — spaces, `&`, `=`, `#`, `?` — is encoded.
fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b':' | b'@') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; AES_KEY_BYTES] {
        // Test-only AES key, never a production secret.
        // codeql[rust/hard-coded-cryptographic-value]
        *b"0123456789abcdef0123456789abcdef"
    }

    /// RFC 6238 Appendix B SHA-1 seed. Test vector, never a production secret.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn aes_gcm_round_trips() {
        let plaintext = b"JBSWY3DPEHPK3PXP";
        let blob = encrypt_secret(&test_key(), plaintext).expect("encrypt");
        assert_eq!(blob.len(), plaintext.len() + MIN_BLOB_LEN);

        let decrypted = decrypt_secret(&test_key(), &blob).expect("decrypt");
        assert_eq!(&*decrypted, &plaintext[..]);
    }

    #[test]
    fn decrypted_secret_debug_redacts_bytes() {
        let plaintext = b"JBSWY3DPEHPK3PXP";
        let blob = encrypt_secret(&test_key(), plaintext).expect("encrypt");
        let decrypted = decrypt_secret(&test_key(), &blob).expect("decrypt");
        let rendered = format!("{decrypted:?}");
        assert!(!rendered.contains("JBSWY3DPEHPK3PXP"));
        assert!(rendered.contains("bytes: \"[redacted]\""));
        assert!(rendered.contains("len: 16"));
    }

    #[test]
    fn aes_gcm_uses_a_fresh_nonce_per_call() {
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..100 {
            let blob = encrypt_secret(&test_key(), b"same plaintext").expect("encrypt");
            assert!(nonces.insert(blob[..NONCE_LEN].to_vec()), "nonce reused");
        }
    }

    #[test]
    fn aes_gcm_rejects_tampered_tag() {
        let mut blob = encrypt_secret(&test_key(), b"secret").expect("encrypt");
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(
            decrypt_secret(&test_key(), &blob),
            Err(AppError::Internal)
        ));
    }

    #[test]
    fn aes_gcm_rejects_tampered_nonce() {
        let mut blob = encrypt_secret(&test_key(), b"secret").expect("encrypt");
        blob[0] ^= 0x01;
        assert!(matches!(
            decrypt_secret(&test_key(), &blob),
            Err(AppError::Internal)
        ));
    }

    #[test]
    fn aes_gcm_rejects_wrong_key() {
        let blob = encrypt_secret(&test_key(), b"secret").expect("encrypt");
        let mut wrong_key = test_key();
        wrong_key[0] ^= 0xff;
        assert!(matches!(
            decrypt_secret(&wrong_key, &blob),
            Err(AppError::Internal)
        ));
    }

    #[test]
    fn aes_gcm_rejects_truncated_blob() {
        for len in 0..MIN_BLOB_LEN {
            assert!(matches!(
                decrypt_secret(&test_key(), &vec![0u8; len]),
                Err(AppError::Internal)
            ));
        }
    }

    #[test]
    fn rfc6238_known_vectors_match() {
        // Published 8-digit vectors reduced mod 10^6 for six digits.
        let vectors = [
            (59 / TOTP_STEP_SECS, 287_082),
            (1_111_111_109 / TOTP_STEP_SECS, 81_804),
            (1_111_111_111 / TOTP_STEP_SECS, 50_471),
            (1_234_567_890 / TOTP_STEP_SECS, 5_924),
            (2_000_000_000 / TOTP_STEP_SECS, 279_037),
            (20_000_000_000 / TOTP_STEP_SECS, 353_130),
        ];
        for (counter, expected) in vectors {
            assert_eq!(
                generate_totp(RFC_SECRET, counter).expect("generate"),
                expected,
                "counter {counter}"
            );
        }
    }

    #[test]
    fn codes_render_as_six_digits() {
        assert_eq!(
            format!("{:06}", generate_totp(RFC_SECRET, 1).expect("generate")),
            "287082"
        );
        assert_eq!(
            format!(
                "{:06}",
                generate_totp(RFC_SECRET, 1_111_111_109 / TOTP_STEP_SECS).expect("generate")
            ),
            "081804"
        );
    }

    #[test]
    fn prune_horizon_outlives_the_acceptance_window() {
        assert_eq!(MIN_USED_CODE_PRUNE_AGE_SECS, 120);
    }

    #[test]
    fn verify_accepts_one_step_drift() {
        let base = 987_654u64;
        for delta in -TOTP_WINDOW_STEPS..=TOTP_WINDOW_STEPS {
            let step = base.checked_add_signed(delta).expect("step");
            let code = format!("{:06}", generate_totp(RFC_SECRET, step).expect("generate"));
            assert_eq!(
                verify_totp_code_at(RFC_SECRET, &code, base).expect("accepted"),
                step
            );
        }
    }

    #[test]
    fn verify_rejects_two_step_drift() {
        let base = 987_654u64;
        for delta in [-2i64, 2] {
            let step = base.checked_add_signed(delta).expect("step");
            let code = format!("{:06}", generate_totp(RFC_SECRET, step).expect("generate"));
            assert!(matches!(
                verify_totp_code_at(RFC_SECRET, &code, base),
                Err(AppError::TotpCodeInvalid)
            ));
        }
    }

    #[test]
    fn verify_rejects_malformed_codes() {
        for code in ["", "12345", "1234567", "abcdef", "12 345", "12345x"] {
            assert!(matches!(
                verify_totp_code_at(RFC_SECRET, code, 100),
                Err(AppError::TotpCodeInvalid)
            ));
        }
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let code = format!("{:06}", generate_totp(RFC_SECRET, 500).expect("generate"));
        assert!(
            verify_totp_code_at(b"another-secret-value", &code, 500).is_err(),
            "code from a different secret must not verify"
        );
    }

    #[test]
    fn replay_hash_is_code_only() {
        let hash = compute_code_replay_hash("012345");
        assert_eq!(hash.len(), 32);
        assert_eq!(hash, compute_code_replay_hash("012345"));
        assert_ne!(hash, compute_code_replay_hash("012346"));
        assert_eq!(
            hash,
            compute_code_replay_hash(" 012345 "),
            "surrounding whitespace must not fork the hash"
        );
    }

    #[test]
    fn totp_secret_is_unpadded_base32_of_160_bits() {
        let mut secrets = std::collections::HashSet::new();
        for _ in 0..32 {
            let secret = generate_totp_secret();
            assert_eq!(secret.len(), 32);
            assert!(
                secret
                    .bytes()
                    .all(|byte| matches!(byte, b'A'..=b'Z' | b'2'..=b'7'))
            );
            assert!(secrets.insert(secret), "secret reused");
        }
    }

    /// RFC 6238 Appendix B eight-digit SHA-1 vector, for the decoder proof.
    fn rfc6238_eight_digit(secret: &[u8], counter: u64) -> u32 {
        let mut mac = <HmacSha1 as Mac>::new_from_slice(secret).expect("hmac key");
        mac.update(&counter.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = usize::from(digest[19] & 0x0f);
        u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]) % 100_000_000
    }

    #[test]
    fn base32_decoder_recovers_rfc6238_seed() {
        let raw = decode_totp_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").expect("decode");
        assert_eq!(raw, RFC_SECRET);
        assert_eq!(rfc6238_eight_digit(&raw, 59 / TOTP_STEP_SECS), 94_287_082);
        assert_eq!(
            format!(
                "{:06}",
                generate_totp(&raw, 59 / TOTP_STEP_SECS).expect("generate")
            ),
            "287082"
        );
    }

    #[test]
    fn base32_decoder_is_case_insensitive() {
        let uppercase = decode_totp_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").expect("decode");
        let lowercase = decode_totp_secret("gezdgnbvgy3tqojqgezdgnbvgy3tqojq").expect("decode");
        assert_eq!(uppercase, lowercase);
    }

    #[test]
    fn base32_decoder_round_trips_generated_secrets() {
        for _ in 0..16 {
            let secret = generate_totp_secret();
            let raw = decode_totp_secret(&secret).expect("decode");
            assert_eq!(raw.len(), TOTP_SECRET_BYTES);
            assert_eq!(base32::encode(TOTP_ALPHABET, &raw), secret);
        }
    }

    #[test]
    fn base32_decoder_requires_exactly_160_bits() {
        for raw in [
            vec![0x42u8; TOTP_SECRET_BYTES - 1],
            vec![0x42u8; TOTP_SECRET_BYTES + 1],
        ] {
            let encoded = base32::encode(TOTP_ALPHABET, &raw);
            assert!(
                matches!(decode_totp_secret(&encoded), Err(AppError::Internal)),
                "accepted {}-byte secret ({encoded})",
                raw.len()
            );
        }

        let raw = [0x42u8; TOTP_SECRET_BYTES];
        let encoded = base32::encode(TOTP_ALPHABET, &raw);
        assert_eq!(decode_totp_secret(&encoded).expect("20-byte secret"), raw);
    }

    #[test]
    fn base32_decoder_rejects_non_canonical_input() {
        for input in [
            "",
            "A",                                 // five-bit partial symbol
            "AB",                                // non-zero trailing bits
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ=", // padding
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ0", // '0' is outside RFC 4648
            "GEZD GNBV",                         // whitespace
            "GEZD-GNBV",                         // separator
        ] {
            assert!(
                matches!(decode_totp_secret(input), Err(AppError::Internal)),
                "accepted {input:?}"
            );
        }
    }

    #[test]
    fn otpauth_uri_carries_rfc6238_parameters() {
        let uri = build_otpauth_uri("JBSWY3DPEHPK3PXP", "alice@example.com", "metal-auth");
        assert_eq!(
            uri,
            "otpauth://totp/metal-auth:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=metal-auth&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn otpauth_uri_percent_encodes_label_parts() {
        let uri = build_otpauth_uri("JBSWY3DPEHPK3PXP", "alice@example.com", "Acme Corp");
        assert!(
            uri.starts_with("otpauth://totp/Acme%20Corp:alice@example.com?secret="),
            "{uri}"
        );
        assert!(uri.contains("issuer=Acme%20Corp"), "{uri}");
    }
}
