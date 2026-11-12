//! Password hashing (Argon2id) and password policy enforcement.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};

use crate::error::{ApiError, FieldIssue};

/// Small blocklist of passwords that show up in every credential-stuffing list.
const WEAK_PASSWORDS: &[&str] = &[
    "password",
    "password1",
    "password123",
    "12345678",
    "123456789",
    "qwerty123",
    "letmein1",
    "iloveyou",
    "admin123",
    "welcome1",
];

fn argon2() -> Argon2<'static> {
    // Argon2id with the OWASP-recommended (19 MiB, t=2, p=1) baseline.
    let params = Params::new(19 * 1024, 2, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash_password(plain: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    argon2()
        .hash_password(plain.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| ApiError::internal(anyhow::anyhow!("password hashing failed: {e}")))
}

/// Verifies a password against a stored PHC hash.
///
/// When `hash` is `None` (unknown account) a dummy verification is still run so
/// that the response time does not reveal whether the e-mail exists.
pub fn verify_password(plain: &str, hash: Option<&str>) -> bool {
    const DUMMY_HASH: &str =
        "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$Wl1oY2x6a1FjV0hFc2FsdHNvbWU";
    let target = hash.unwrap_or(DUMMY_HASH);
    match PasswordHash::new(target) {
        Ok(parsed) => argon2().verify_password(plain.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

/// Password policy: length bounds plus a letter and a digit, and a tiny
/// blocklist. Returns every violated rule at once so the UI can show all hints.
pub fn validate_password_policy(
    password: &str,
    min_len: usize,
    max_len: usize,
) -> Result<(), ApiError> {
    let mut issues = Vec::new();

    if password.chars().count() < min_len {
        issues.push(FieldIssue {
            field: "password".to_string(),
            message: format!("must be at least {min_len} characters long"),
        });
    }
    if password.chars().count() > max_len {
        issues.push(FieldIssue {
            field: "password".to_string(),
            message: format!("must be at most {max_len} characters long"),
        });
    }
    if !password.chars().any(|c| c.is_alphabetic()) {
        issues.push(FieldIssue {
            field: "password".to_string(),
            message: "must contain at least one letter".to_string(),
        });
    }
    if !password.chars().any(|c| c.is_numeric()) {
        issues.push(FieldIssue {
            field: "password".to_string(),
            message: "must contain at least one digit".to_string(),
        });
    }
    if password.trim() != password {
        issues.push(FieldIssue {
            field: "password".to_string(),
            message: "must not start or end with whitespace".to_string(),
        });
    }
    if WEAK_PASSWORDS.contains(&password.to_ascii_lowercase().as_str()) {
        issues.push(FieldIssue {
            field: "password".to_string(),
            message: "is too common; choose something less predictable".to_string(),
        });
    }

    if issues.is_empty() {
        Ok(())
    } else {
        Err(ApiError::validation(issues))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_roundtrip() {
        let hash = hash_password("Sup3rSecret").unwrap();
        assert!(verify_password("Sup3rSecret", Some(&hash)));
        assert!(!verify_password("wrong-password", Some(&hash)));
        assert!(!verify_password("Sup3rSecret", None));
    }

    #[test]
    fn policy_rejects_weak_passwords() {
        assert!(validate_password_policy("short1", 8, 128).is_err());
        assert!(validate_password_policy("alllettersonly", 8, 128).is_err());
        assert!(validate_password_policy("password123", 8, 128).is_err());
        assert!(validate_password_policy("Str0ngEnough", 8, 128).is_ok());
    }
}
