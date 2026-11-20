//! Single-use backup codes: CSPRNG generation, Argon2id hashing, constant-time verification.

use base32::Alphabet;
use rand_core::{OsRng, RngCore};

use crate::{
    config::AppConfig,
    crypto::{hash_password, verify_password},
    error::AppError,
};

/// Backup codes issued per enrollment.
pub const BACKUP_CODE_COUNT: usize = 10;
/// Characters in a rendered backup code.
pub const BACKUP_CODE_LEN: usize = 10;
/// Random bytes per code: 7 bytes encode to 12 base32 chars, trimmed to 10 (50 bits).
const BACKUP_CODE_RAW_BYTES: usize = 7;
const BACKUP_CODE_ALPHABET: Alphabet = Alphabet::RFC4648 { padding: false };

/// Generate [`BACKUP_CODE_COUNT`] codes, returning `(raw_codes, phc_hashes)`.
///
/// Raw codes go to the user once and must never be persisted; only the Argon2id PHC
/// strings belong in `totp_secrets.backup_codes`.
pub fn generate_backup_codes(config: &AppConfig) -> Result<(Vec<String>, Vec<String>), AppError> {
    let mut raw_codes = Vec::with_capacity(BACKUP_CODE_COUNT);
    let mut hashed_codes = Vec::with_capacity(BACKUP_CODE_COUNT);

    for _ in 0..BACKUP_CODE_COUNT {
        let mut bytes = [0u8; BACKUP_CODE_RAW_BYTES];
        OsRng.fill_bytes(&mut bytes);
        let mut code = base32::encode(BACKUP_CODE_ALPHABET, &bytes);
        crate::crypto::zeroize_bytes(&mut bytes);
        code.truncate(BACKUP_CODE_LEN);

        hashed_codes.push(hash_password(&code, config)?);
        raw_codes.push(code);
    }

    Ok((raw_codes, hashed_codes))
}

/// Verify `code` against every stored hash, returning the index of the match.
///
/// The full list is always traversed, even after a match, so the response time does
/// not reveal the matching position. The caller deletes that entry to consume the code.
pub fn verify_backup_code(code: &str, hashed_codes: &[String]) -> Result<usize, AppError> {
    let normalized = normalize_backup_code(code);
    // Cheap format gate: rejects malformed input before paying ten Argon2 verifications.
    if !is_valid_backup_code_format(&normalized) {
        return Err(AppError::TotpBackupCodeInvalid);
    }

    let mut matched_index = None;
    for (index, phc_hash) in hashed_codes.iter().enumerate() {
        match verify_password(&normalized, phc_hash) {
            Ok(true) => {
                if matched_index.is_none() {
                    matched_index = Some(index);
                }
            }
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(error = ?err, index, "unparsable backup code hash skipped");
            }
        }
    }

    matched_index.ok_or(AppError::TotpBackupCodeInvalid)
}

/// Canonical form for comparison: uppercase, no whitespace or hyphen separators.
fn normalize_backup_code(code: &str) -> String {
    code.chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

fn is_valid_backup_code_format(code: &str) -> bool {
    code.len() == BACKUP_CODE_LEN
        && code
            .bytes()
            .all(|byte| matches!(byte, b'A'..=b'Z' | b'2'..=b'7'))
}
