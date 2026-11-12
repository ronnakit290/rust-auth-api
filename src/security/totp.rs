//! TOTP (RFC 6238) helpers built on `totp-rs`.

use rand::RngCore;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::ApiError;

pub const DIGITS: usize = 6;
pub const STEP_SECONDS: u64 = 30;
/// One step of clock skew either side, per RFC 6238 §5.2.
pub const SKEW: u8 = 1;

pub struct TotpSetup {
    pub secret_base32: String,
    pub otpauth_url: String,
}

fn build(secret: Vec<u8>, issuer: &str, account: &str) -> Result<TOTP, ApiError> {
    TOTP::new(
        Algorithm::SHA1,
        DIGITS,
        SKEW,
        STEP_SECONDS,
        secret,
        Some(issuer.to_string()),
        account.to_string(),
    )
    .map_err(|e| ApiError::internal(anyhow::anyhow!("cannot build TOTP: {e}")))
}

/// Generates a fresh 160-bit secret plus the `otpauth://` URI for authenticator
/// apps.
pub fn generate(issuer: &str, account: &str) -> Result<TotpSetup, ApiError> {
    let mut secret = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut secret);
    let totp = build(secret.to_vec(), issuer, account)?;
    Ok(TotpSetup {
        secret_base32: totp.get_secret_base32(),
        otpauth_url: totp.get_url(),
    })
}

/// Verifies a 6-digit code against a base32 secret with ±1 step of skew.
pub fn verify(
    secret_base32: &str,
    code: &str,
    issuer: &str,
    account: &str,
) -> Result<bool, ApiError> {
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS || !code.chars().all(|c| c.is_ascii_digit()) {
        return Ok(false);
    }
    let bytes = Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .map_err(|e| ApiError::internal(anyhow::anyhow!("invalid stored TOTP secret: {e}")))?;
    let totp = build(bytes, issuer, account)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ApiError::internal(anyhow::anyhow!("clock error: {e}")))?
        .as_secs();
    Ok(totp.check(&code, now))
}
