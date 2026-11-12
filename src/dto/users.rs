//! User-facing profile and session payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::{
    db::{
        sessions::SessionRow,
        users::{Role, UserStatus, UserWithSecurity},
    },
    response::MessageResponse,
};

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserDto {
    pub id: String,
    pub email: String,
    pub full_name: Option<String>,
    pub role: Role,
    pub status: UserStatus,
    pub email_verified: bool,
    pub two_factor_enabled: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl UserDto {
    pub fn from_parts(user: &crate::db::users::UserRow, two_factor_enabled: bool) -> Self {
        UserDto {
            id: user.id.clone(),
            email: user.email.clone(),
            full_name: user.full_name.clone(),
            role: user.role,
            status: user.status,
            email_verified: user.email_verified_at.is_some(),
            two_factor_enabled,
            last_login_at: user.last_login_at.map(crate::db::users::ts_to_datetime),
            created_at: crate::db::users::ts_to_datetime(user.created_at),
            updated_at: crate::db::users::ts_to_datetime(user.updated_at),
        }
    }

    pub fn from_row(row: &UserWithSecurity) -> Self {
        UserDto::from_parts(&row.user, row.two_factor_enabled())
    }
}

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct UpdateProfileRequest {
    /// New display name. Send an empty string to clear it.
    #[validate(length(max = 120, message = "must be at most 120 characters"))]
    pub full_name: Option<String>,
    /// Changing the e-mail address forces re-verification.
    #[validate(email(message = "must be a valid email address"))]
    #[validate(length(max = 254))]
    pub email: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct ChangePasswordRequest {
    #[validate(length(min = 1, message = "is required"))]
    pub current_password: String,
    #[validate(length(min = 8, max = 128))]
    pub new_password: String,
}

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct DeleteAccountRequest {
    #[validate(length(min = 1, message = "is required"))]
    pub password: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SessionDto {
    pub id: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    /// True for the session that authenticated the current request.
    pub current: bool,
}

impl SessionDto {
    pub fn from_row(row: &SessionRow, current_session_id: &str) -> Self {
        SessionDto {
            id: row.id.clone(),
            user_agent: row.user_agent.clone(),
            ip_address: row.ip_address.clone(),
            created_at: crate::db::users::ts_to_datetime(row.created_at),
            last_used_at: row.last_used_at.map(crate::db::users::ts_to_datetime),
            expires_at: crate::db::users::ts_to_datetime(row.expires_at),
            current: row.id == current_session_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SessionsResponse {
    pub sessions: Vec<SessionDto>,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UpdateProfileResponse {
    pub user: UserDto,
    /// Present when the e-mail changed and verification is pending.
    pub verification_required: bool,
    pub message: MessageResponse,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RevokedSessionsResponse {
    pub revoked: u64,
    pub message: String,
}
