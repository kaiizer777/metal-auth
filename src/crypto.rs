//! Cryptographic helpers: Argon2id hashing, secure token generation, and common password blocklist.

pub mod argon2;
pub mod blocklist;
pub mod token;

pub use argon2::{generate_dummy_hash, hash_password, verify_password};
pub use blocklist::is_common_password;
pub use token::{generate_token, hash_token, is_valid_token_format, sha256_of_hex_token};

/// Overwrite `buf` with zeros, resisting dead-store elimination.
///
/// Volatile writes plus a compiler fence keep the zeroing under optimization.
/// Prefer the `zeroize` crate once it becomes a direct dependency.
pub(crate) fn zeroize_bytes(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a live exclusive `&mut u8`; volatile byte writes are always sound.
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_bytes_clears_buffer() {
        let mut buf = [0xA5u8; 32];
        zeroize_bytes(&mut buf);
        assert_eq!(buf, [0u8; 32]);
    }
}
