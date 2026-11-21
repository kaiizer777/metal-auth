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
/// Base32 alphabet selector, not cryptographic key material.
// codeql[rust/hard-coded-cryptographic-value]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal Argon2id cost accepted by `Params` (8 KiB, one lane) so the suite stays fast
    /// in unoptimised builds; hashing behaviour and PHC round-tripping are unchanged.
    fn test_config() -> AppConfig {
        AppConfig {
            argon2_m_cost: 8,
            argon2_t_cost: 1,
            argon2_p_cost: 1,
            ..AppConfig::default()
        }
    }

    #[test]
    fn generates_ten_well_formed_unique_codes() {
        let (raw, hashed) = generate_backup_codes(&test_config()).expect("generate");

        assert_eq!(raw.len(), BACKUP_CODE_COUNT);
        assert_eq!(hashed.len(), BACKUP_CODE_COUNT);
        for code in &raw {
            assert_eq!(code.len(), BACKUP_CODE_LEN, "code: {code}");
            assert!(is_valid_backup_code_format(code), "code: {code}");
        }
        let unique: std::collections::HashSet<_> = raw.iter().collect();
        assert_eq!(unique.len(), BACKUP_CODE_COUNT, "codes must be unique");
    }

    #[test]
    fn raw_codes_are_never_persisted_verbatim() {
        let (raw, hashed) = generate_backup_codes(&test_config()).expect("generate");
        for (code, phc_hash) in raw.iter().zip(&hashed) {
            assert!(phc_hash.starts_with("$argon2id$"), "PHC: {phc_hash}");
            assert!(!phc_hash.contains(code.as_str()));
        }
    }

    #[test]
    fn verifies_every_generated_code_at_its_index() {
        let (raw, hashed) = generate_backup_codes(&test_config()).expect("generate");
        for (index, code) in raw.iter().enumerate() {
            assert_eq!(
                verify_backup_code(code, &hashed).expect("verify"),
                index,
                "code {index}"
            );
        }
    }

    #[test]
    fn normalizes_case_whitespace_and_hyphens() {
        let (raw, hashed) = generate_backup_codes(&test_config()).expect("generate");
        let code = &raw[0];
        let messy = format!(
            " {}-{} \n",
            code[..5].to_lowercase(),
            code[5..].to_lowercase()
        );
        assert_eq!(verify_backup_code(&messy, &hashed).expect("verify"), 0);
    }

    #[test]
    fn rejects_unknown_and_malformed_codes() {
        let (_, hashed) = generate_backup_codes(&test_config()).expect("generate");

        assert!(matches!(
            verify_backup_code("AAAAAAAAAA", &hashed),
            Err(AppError::TotpBackupCodeInvalid)
        ));
        for code in ["", "SHORT", "AAAAAAAAAAA", "AAAAAAAAA0", "AAAAAAAA1"] {
            assert!(matches!(
                verify_backup_code(code, &hashed),
                Err(AppError::TotpBackupCodeInvalid)
            ));
        }
    }

    #[test]
    fn rejects_every_code_when_store_is_empty() {
        assert!(matches!(
            verify_backup_code("AAAAAAAAAA", &[]),
            Err(AppError::TotpBackupCodeInvalid)
        ));
    }

    #[test]
    fn duplicate_hashes_resolve_to_the_first_index() {
        let (raw, hashed) = generate_backup_codes(&test_config()).expect("generate");
        let mut store = hashed;
        store[9] = store[2].clone();
        assert_eq!(verify_backup_code(&raw[2], &store).expect("verify"), 2);
    }

    #[test]
    fn verify_traverses_every_hash_after_a_match() {
        let (raw, mut store) = generate_backup_codes(&test_config()).expect("generate");
        // Match first, unparsable last: a loop that exits on match never reaches index 9
        // and therefore emits no warning for it.
        store.truncate(1);
        store.extend(std::iter::repeat_n("not-a-phc-hash".to_string(), 9));

        let logs = capture_logs(|| {
            assert_eq!(verify_backup_code(&raw[0], &store).expect("verify"), 0);
        });

        assert!(
            logs.contains("unparsable backup code hash skipped"),
            "no traversal past the match; logs: {logs}"
        );
        assert!(logs.contains("index=9"), "last hash not visited: {logs}");
    }

    /// Run `body` with a subscriber that captures formatted log lines.
    fn capture_logs<F: FnOnce()>(body: F) -> String {
        use std::io;
        use std::sync::{Arc, Mutex};

        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl io::Write for Capture {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0
                    .lock()
                    .expect("log buffer poisoned")
                    .extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt::Subscriber::builder()
            .with_ansi(false)
            .with_writer({
                let buffer = Arc::clone(&buffer);
                move || Capture(Arc::clone(&buffer))
            })
            .finish();

        tracing::dispatcher::with_default(&tracing::dispatcher::Dispatch::new(subscriber), body);

        String::from_utf8(buffer.lock().expect("log buffer poisoned").clone())
            .expect("logs are UTF-8")
    }

    #[test]
    fn unparsable_hash_does_not_break_verification() {
        let (raw, mut hashed) = generate_backup_codes(&test_config()).expect("generate");
        hashed[0] = "not-a-phc-hash".to_string();
        assert_eq!(verify_backup_code(&raw[1], &hashed).expect("verify"), 1);
    }
}
