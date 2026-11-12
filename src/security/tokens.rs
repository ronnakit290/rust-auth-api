//! Opaque token helpers. Refresh tokens and one-time tokens are 256-bit random
//! values; only their SHA-256 digest is stored so a database leak cannot be
//! replayed.

use rand::RngCore;
use sha2::{Digest, Sha256};

/// 32 random bytes rendered as 64 hex characters (256 bits of entropy).
pub fn random_token() -> String {
    random_hex(32)
}

pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    hex::encode(digest)
}

/// Human friendly recovery code: two groups of five base-32 characters.
pub fn random_recovery_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    let mut code = String::with_capacity(11);
    for i in 0..10 {
        if i == 5 {
            code.push('-');
        }
        let idx = (rng.next_u32() as usize) % ALPHABET.len();
        code.push(ALPHABET[idx] as char);
    }
    code
}

pub fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_hashed() {
        let a = random_token();
        let b = random_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert_eq!(sha256_hex(&a).len(), 64);
        assert_ne!(sha256_hex(&a), a);
    }

    #[test]
    fn recovery_codes_are_grouped() {
        let code = random_recovery_code();
        assert_eq!(code.len(), 11);
        assert_eq!(code.chars().filter(|c| *c == '-').count(), 1);
        assert_eq!(normalize_recovery_code(&code).len(), 10);
    }
}
