//! Two-factor authentication payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TwoFactorSetupResponse {
    /// Base32 secret for manual entry.
    pub secret: String,
    /// `otpauth://` URI for authenticator apps / QR generation.
    pub otpauth_url: String,
    pub issuer: String,
    pub account: String,
    pub digits: usize,
    pub step_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct EnableTwoFactorRequest {
    #[validate(length(min = 6, max = 8, message = "must be a 6 digit code"))]
    pub code: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EnableTwoFactorResponse {
    pub enabled: bool,
    /// Shown exactly once — store them somewhere safe.
    pub recovery_codes: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct DisableTwoFactorRequest {
    #[validate(length(min = 1, message = "is required"))]
    pub password: String,
    /// Current TOTP code. Either this or `recovery_code` must be supplied.
    pub code: Option<String>,
    pub recovery_code: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct RegenerateRecoveryCodesRequest {
    #[validate(length(min = 1, message = "is required"))]
    pub password: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RecoveryCodesResponse {
    pub recovery_codes: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TwoFactorStatusResponse {
    pub enabled: bool,
    /// True when a secret was generated but never confirmed with a code.
    pub pending_setup: bool,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub recovery_codes_remaining: i64,
}
