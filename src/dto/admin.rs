//! Administrator-facing payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::{
    db::{
        audit::AuditRow,
        users::{Role, UserStatus},
    },
    dto::{UserDto, DEFAULT_PER_PAGE, MAX_PER_PAGE},
};

fn default_page() -> Option<u32> {
    Some(1)
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ListUsersQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    /// Case-insensitive match on e-mail or full name.
    pub search: Option<String>,
    pub role: Option<Role>,
    pub status: Option<UserStatus>,
    pub email_verified: Option<bool>,
    pub two_factor: Option<bool>,
    /// created_at (default) | email | last_login_at | role | status | updated_at
    pub sort: Option<String>,
    /// asc | desc (default desc)
    pub order: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct AdminUpdateUserRequest {
    pub role: Option<Role>,
    pub status: Option<UserStatus>,
    #[validate(length(max = 120))]
    pub full_name: Option<String>,
    /// Restore an account by resetting its failed-login lockout.
    #[serde(default)]
    pub unlock: bool,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct DeleteUserQuery {
    /// Purge the row instead of marking the account as deleted.
    #[serde(default)]
    pub hard: bool,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AuditLogQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub action: Option<String>,
    pub actor_id: Option<String>,
    pub target_id: Option<String>,
    /// Unix seconds (inclusive).
    pub from: Option<i64>,
    /// Unix seconds (inclusive).
    pub to: Option<i64>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuditLogDto {
    pub id: String,
    pub actor_id: Option<String>,
    pub actor_email: Option<String>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

impl From<AuditRow> for AuditLogDto {
    fn from(row: AuditRow) -> Self {
        AuditLogDto {
            id: row.id,
            actor_id: row.actor_id,
            actor_email: row.actor_email,
            action: row.action,
            target_type: row.target_type,
            target_id: row.target_id,
            ip_address: row.ip_address,
            user_agent: row.user_agent,
            metadata: row
                .metadata
                .as_deref()
                .and_then(|raw| serde_json::from_str(raw).ok()),
            created_at: crate::db::users::ts_to_datetime(row.created_at),
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AdminStatsResponse {
    pub users: crate::db::users::AdminStats,
    pub active_sessions: i64,
    pub logins_24h: i64,
    pub failed_logins_24h: i64,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AdminUserResponse {
    pub user: UserDto,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AdminSessionsQuery {
    #[serde(default = "default_page")]
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

impl ListUsersQuery {
    pub fn page(&self) -> u32 {
        self.page.unwrap_or(1).max(1)
    }

    pub fn per_page(&self) -> u32 {
        self.per_page
            .unwrap_or(DEFAULT_PER_PAGE)
            .clamp(1, MAX_PER_PAGE)
    }

    pub fn limit(&self) -> i64 {
        self.per_page() as i64
    }

    pub fn offset(&self) -> i64 {
        ((self.page() - 1) as i64) * self.per_page() as i64
    }
}

impl AuditLogQuery {
    pub fn page(&self) -> u32 {
        self.page.unwrap_or(1).max(1)
    }

    pub fn per_page(&self) -> u32 {
        self.per_page
            .unwrap_or(DEFAULT_PER_PAGE)
            .clamp(1, MAX_PER_PAGE)
    }

    pub fn limit(&self) -> i64 {
        self.per_page() as i64
    }

    pub fn offset(&self) -> i64 {
        ((self.page() - 1) as i64) * self.per_page() as i64
    }
}
