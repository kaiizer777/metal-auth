//! Argon2id password hashing and constant-time verification.
//!
//! Parameters are driven by `AppConfig` (defaults: m=65536 KiB, t=3, p=4) per RFC 9106 §4.

use argon2::{
    Argon2, Params, Version,
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
        rand_core::{OsRng, RngCore},
    },
};

use crate::{config::AppConfig, error::AppError};

/// Hash `password` using Argon2id with parameters from `config`.
///
/// Returns a PHC string (`$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`).
/// Salt is 16-byte random per-call via `OsRng`. Output tag length is 32 bytes.
pub fn hash_password(password: &str, config: &AppConfig) -> Result<String, AppError> {
    hash_password_with_params(
        password,
        config.argon2_m_cost,
        config.argon2_t_cost,
        config.argon2_p_cost,
    )
}

/// Hash `password` using Argon2id with caller-supplied parameters.
pub fn hash_password_with_params(
    password: &str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<String, AppError> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32)).map_err(|_| AppError::Internal)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| AppError::Internal)?;
    Ok(hash.to_string())
}

/// Verify `password` against an existing PHC string in constant time.
///
/// NOTE parameter order: `(password, phc_hash)`.
/// Returns `Ok(true)` on match, `Ok(false)` on mismatch, and `Err(AppError::Internal)`
/// on a malformed PHC string.
pub fn verify_password(password: &str, phc_hash: &str) -> Result<bool, AppError> {
    let parsed = PasswordHash::new(phc_hash).map_err(|_| AppError::Internal)?;
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    match result {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(_) => Err(AppError::Internal),
    }
}

/// Pre-compute a dummy PHC hash for constant-time anti-enumeration on login miss.
///
/// Generates a 32-byte random dummy secret using `OsRng`, and hashes it using
/// the exact `AppConfig` parameters to ensure timing parity with real verification attempts.
pub fn generate_dummy_hash(config: &AppConfig) -> Result<String, AppError> {
    let mut dummy_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut dummy_bytes);
    let dummy_secret = hex::encode(dummy_bytes);
    hash_password(&dummy_secret, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_produces_phc_string_with_correct_params() {
        let config = AppConfig::default();
        let hash = hash_password("correct-horse-battery-staple", &config).unwrap();
        assert!(
            hash.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"),
            "PHC: {hash}"
        );
    }

    #[test]
    fn verify_correct_password_returns_true() {
        let config = AppConfig::default();
        let pw = "correct-horse-battery-staple";
        let hash = hash_password(pw, &config).unwrap();
        assert!(verify_password(pw, &hash).unwrap());
    }

    #[test]
    fn verify_wrong_password_returns_false() {
        let config = AppConfig::default();
        let hash = hash_password("correct-horse-battery-staple", &config).unwrap();
        assert!(!verify_password("wrong-password", &hash).unwrap());
    }

    #[test]
    fn verify_malformed_phc_returns_error() {
        assert!(verify_password("password", "not-a-valid-phc").is_err());
    }

    #[test]
    fn two_hashes_of_same_password_differ_salts() {
        let config = AppConfig::default();
        let pw = "correct-horse-battery-staple";
        let h1 = hash_password(pw, &config).unwrap();
        let h2 = hash_password(pw, &config).unwrap();
        assert_ne!(h1, h2, "each call must use a fresh random salt");
    }

    #[test]
    fn hash_with_params_uses_supplied_params() {
        let hash = hash_password_with_params("pw", 19456, 2, 1).unwrap();
        assert!(
            hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "PHC: {hash}"
        );
    }

    #[test]
    fn dummy_hash_has_configured_parameters() {
        let config = AppConfig::default();
        let dummy = generate_dummy_hash(&config).unwrap();
        assert!(
            dummy.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"),
            "Dummy PHC: {dummy}"
        );
    }

    #[test]
    fn accepts_multibyte_unicode_password() {
        let config = AppConfig::default();
        let pw = "🔐🔑🗝️🔒🔓🛡️⚔️🏰";
        let hash = hash_password(pw, &config).unwrap();
        assert!(verify_password(pw, &hash).unwrap());
    }
}
