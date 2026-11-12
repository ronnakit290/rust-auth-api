//! Authentication request/response payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::dto::UserDto;

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct RegisterRequest {
    #[validate(email(message = "must be a valid email address"))]
    #[validate(length(max = 254))]
    pub email: String,
    #[validate(length(min = 8, max = 128, message = "must be between 8 and 128 characters"))]
    pub password: String,
    #[validate(length(max = 120, message = "must be at most 120 characters"))]
    pub full_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct LoginRequest {
    #[validate(email(message = "must be a valid email address"))]
    pub email: String,
    #[validate(length(min = 1, message = "is required"))]
    pub password: String,
    /// Optional label shown in the session list (defaults to the User-Agent).
    #[validate(length(max = 200))]
    pub device_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct MfaVerifyRequest {
    #[validate(length(min = 1, message = "is required"))]
    pub mfa_token: String,
    /// Six digit TOTP code, or a recovery code when `use_recovery_code` is true.
    #[validate(length(min = 6, max = 20))]
    pub code: String,
    #[serde(default)]
    pub use_recovery_code: bool,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RefreshRequest {
    pub refresh_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct LogoutRequest {
    /// Optional: revoke this refresh token too (useful when the access token is
    /// still valid but the client wants the session gone).
    pub refresh_token: Option<String>,
    /// Revoke every session of the account, not just the current one.
    #[serde(default)]
    pub all_sessions: bool,
}

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct ForgotPasswordRequest {
    #[validate(email(message = "must be a valid email address"))]
    pub email: String,
}

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct ResetPasswordRequest {
    #[validate(length(min = 10, message = "is required"))]
    pub token: String,
    #[validate(length(min = 8, max = 128))]
    pub new_password: String,
}

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct VerifyEmailRequest {
    #[validate(length(min = 10, message = "is required"))]
    pub token: String,
}

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct ResendVerificationRequest {
    #[validate(email(message = "must be a valid email address"))]
    pub email: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    /// Access token lifetime in seconds.
    pub expires_in: i64,
    /// Refresh token lifetime in seconds.
    pub refresh_expires_in: i64,
    pub session_id: String,
}

impl TokenPair {
    pub fn bearer_type() -> String {
        "Bearer".to_string()
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuthResponse {
    pub user: UserDto,
    pub tokens: TokenPair,
}

/// Login can either complete or stop at the second factor.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LoginResponse {
    pub mfa_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_expires_in: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<TokenPair>,
}

impl LoginResponse {
    pub fn complete(user: UserDto, tokens: TokenPair) -> Self {
        LoginResponse {
            mfa_required: false,
            mfa_token: None,
            mfa_expires_in: None,
            user: Some(user),
            tokens: Some(tokens),
        }
    }

    pub fn mfa_required(mfa_token: String, expires_in: i64) -> Self {
        LoginResponse {
            mfa_required: true,
            mfa_token: Some(mfa_token),
            mfa_expires_in: Some(expires_in),
            user: None,
            tokens: None,
        }
    }
}

/// One-time token delivered by e-mail. Only ever returned when
/// `EMAIL_MODE=console` so that local development and tests can follow the flow
/// without an SMTP server.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DebugToken {
    pub kind: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RegisterResponse {
    pub user: UserDto,
    /// True when a verification e-mail was sent and login is blocked until it is
    /// confirmed (only if REQUIRE_EMAIL_VERIFICATION is enabled).
    pub verification_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_token: Option<DebugToken>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ForgotPasswordResponse {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_token: Option<DebugToken>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LogoutResponse {
    pub revoked_sessions: u64,
    pub message: String,
}
