//! `users` aggregate: role/status enums, rows and queries.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use utoipa::ToSchema;

use crate::{db::now_ts, error::ApiError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Moderator,
    Admin,
    Superadmin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Moderator => "moderator",
            Role::Admin => "admin",
            Role::Superadmin => "superadmin",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Role::User => 0,
            Role::Moderator => 1,
            Role::Admin => 2,
            Role::Superadmin => 3,
        }
    }

    pub fn is_staff(self) -> bool {
        self.rank() >= Role::Moderator.rank()
    }

    pub fn is_admin(self) -> bool {
        self.rank() >= Role::Admin.rank()
    }

    /// Whether `self` is allowed to manage (modify/delete) an account with the
    /// given role. Superadmins manage everybody; admins manage everyone below
    /// their own rank, so an admin can never escalate or demote another admin.
    pub fn can_manage(self, other: Role) -> bool {
        match self {
            Role::Superadmin => true,
            Role::Admin => other.rank() < Role::Admin.rank(),
            _ => false,
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidRole(pub String);

impl std::fmt::Display for InvalidRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid role `{}`", self.0)
    }
}
impl std::error::Error for InvalidRole {}

impl FromStr for Role {
    type Err = InvalidRole;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "user" => Ok(Role::User),
            "moderator" => Ok(Role::Moderator),
            "admin" => Ok(Role::Admin),
            "superadmin" => Ok(Role::Superadmin),
            other => Err(InvalidRole(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    Active,
    Suspended,
    Deleted,
}

impl UserStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            UserStatus::Active => "active",
            UserStatus::Suspended => "suspended",
            UserStatus::Deleted => "deleted",
        }
    }
}

impl std::fmt::Display for UserStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidStatus(pub String);

impl std::fmt::Display for InvalidStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid user status `{}`", self.0)
    }
}
impl std::error::Error for InvalidStatus {}

impl FromStr for UserStatus {
    type Err = InvalidStatus;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "active" => Ok(UserStatus::Active),
            "suspended" => Ok(UserStatus::Suspended),
            "deleted" => Ok(UserStatus::Deleted),
            other => Err(InvalidStatus(other.to_string())),
        }
    }
}

/// Manual SQLite mappings: the enums are stored as plain TEXT, which keeps the
/// schema readable and the queries grep-able.
macro_rules! sqlite_text_enum {
    ($t:ty) => {
        impl sqlx::Type<sqlx::Sqlite> for $t {
            fn type_info() -> <sqlx::Sqlite as sqlx::Database>::TypeInfo {
                <&str as sqlx::Type<sqlx::Sqlite>>::type_info()
            }
            fn compatible(ty: &<sqlx::Sqlite as sqlx::Database>::TypeInfo) -> bool {
                <&str as sqlx::Type<sqlx::Sqlite>>::compatible(ty)
            }
        }

        impl<'q> sqlx::Encode<'q, sqlx::Sqlite> for $t {
            fn encode_by_ref(
                &self,
                buf: &mut <sqlx::Sqlite as sqlx::Database>::ArgumentBuffer<'q>,
            ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
                <&str as sqlx::Encode<'q, sqlx::Sqlite>>::encode(self.as_str(), buf)
            }
        }

        impl<'r> sqlx::Decode<'r, sqlx::Sqlite> for $t {
            fn decode(
                value: <sqlx::Sqlite as sqlx::Database>::ValueRef<'r>,
            ) -> Result<Self, sqlx::error::BoxDynError> {
                let raw = <&str as sqlx::Decode<'r, sqlx::Sqlite>>::decode(value)?;
                <$t>::from_str(raw).map_err(|e| sqlx::error::BoxDynError::from(e.to_string()))
            }
        }
    };
}

sqlite_text_enum!(Role);
sqlite_text_enum!(UserStatus);

#[derive(Debug, Clone, FromRow)]
pub struct UserRow {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub full_name: Option<String>,
    pub role: Role,
    pub status: UserStatus,
    pub email_verified_at: Option<i64>,
    pub last_login_at: Option<i64>,
    pub failed_login_attempts: i64,
    pub locked_until: Option<i64>,
    pub password_changed_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl UserRow {
    pub fn is_active(&self) -> bool {
        matches!(self.status, UserStatus::Active)
    }

    pub fn is_email_verified(&self) -> bool {
        self.email_verified_at.is_some()
    }

    pub fn is_locked(&self, now: i64) -> bool {
        self.locked_until.map(|until| until > now).unwrap_or(false)
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct UserWithSecurity {
    #[sqlx(flatten)]
    pub user: UserRow,
    pub two_factor_enabled: i64,
}

impl UserWithSecurity {
    pub fn two_factor_enabled(&self) -> bool {
        self.two_factor_enabled != 0
    }
}

pub struct NewUser<'a> {
    pub id: &'a str,
    pub email: &'a str,
    pub password_hash: &'a str,
    pub full_name: Option<&'a str>,
    pub role: Role,
    pub email_verified_at: Option<i64>,
}

pub async fn insert(db: &SqlitePool, user: &NewUser<'_>) -> Result<(), ApiError> {
    let now = now_ts();
    sqlx::query(
        r#"
        INSERT INTO users (
            id, email, password_hash, full_name, role, status,
            email_verified_at, failed_login_attempts, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'active', ?, 0, ?, ?)
        "#,
    )
    .bind(user.id)
    .bind(user.email)
    .bind(user.password_hash)
    .bind(user.full_name)
    .bind(user.role)
    .bind(user.email_verified_at)
    .bind(now)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

const SELECT_USER: &str = "SELECT id, email, password_hash, full_name, role, status, \
     email_verified_at, last_login_at, failed_login_attempts, locked_until, password_changed_at, \
     created_at, updated_at FROM users";

pub async fn find_by_id(db: &SqlitePool, id: &str) -> Result<Option<UserRow>, ApiError> {
    Ok(
        sqlx::query_as::<_, UserRow>(&format!("{SELECT_USER} WHERE id = ?"))
            .bind(id)
            .fetch_optional(db)
            .await?,
    )
}

pub async fn find_by_email(db: &SqlitePool, email: &str) -> Result<Option<UserRow>, ApiError> {
    Ok(
        sqlx::query_as::<_, UserRow>(&format!("{SELECT_USER} WHERE email = ?"))
            .bind(email.trim().to_ascii_lowercase())
            .fetch_optional(db)
            .await?,
    )
}

pub async fn email_taken(
    db: &SqlitePool,
    email: &str,
    exclude_user_id: Option<&str>,
) -> Result<bool, ApiError> {
    let found: Option<String> = sqlx::query_scalar(
        "SELECT id FROM users WHERE email = ? AND (? IS NULL OR id <> ?) LIMIT 1",
    )
    .bind(email.trim().to_ascii_lowercase())
    .bind(exclude_user_id)
    .bind(exclude_user_id)
    .fetch_optional(db)
    .await?;
    Ok(found.is_some())
}

pub async fn touch(db: &SqlitePool, id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET updated_at = ? WHERE id = ?")
        .bind(now_ts())
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn update_full_name(
    db: &SqlitePool,
    id: &str,
    full_name: Option<&str>,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET full_name = ?, updated_at = ? WHERE id = ?")
        .bind(full_name)
        .bind(now_ts())
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn update_email(db: &SqlitePool, id: &str, email: &str) -> Result<(), ApiError> {
    let now = now_ts();
    sqlx::query(
        "UPDATE users SET email = ?, email_verified_at = NULL, updated_at = ? WHERE id = ?",
    )
    .bind(email.trim().to_ascii_lowercase())
    .bind(now)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn update_password(
    db: &SqlitePool,
    id: &str,
    password_hash: &str,
) -> Result<(), ApiError> {
    let now = now_ts();
    sqlx::query(
        "UPDATE users SET password_hash = ?, password_changed_at = ?, updated_at = ? WHERE id = ?",
    )
    .bind(password_hash)
    .bind(now)
    .bind(now)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn mark_email_verified(db: &SqlitePool, id: &str) -> Result<(), ApiError> {
    let now = now_ts();
    sqlx::query("UPDATE users SET email_verified_at = ?, updated_at = ? WHERE id = ?")
        .bind(now)
        .bind(now)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn record_login_success(db: &SqlitePool, id: &str) -> Result<(), ApiError> {
    let now = now_ts();
    sqlx::query(
        "UPDATE users SET last_login_at = ?, failed_login_attempts = 0, locked_until = NULL, \
         updated_at = ? WHERE id = ?",
    )
    .bind(now)
    .bind(now)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

/// Increments the failure counter and returns the new attempt count.
pub async fn record_login_failure(db: &SqlitePool, id: &str) -> Result<i64, ApiError> {
    let now = now_ts();
    let (count,): (i64,) = sqlx::query_as::<_, (i64,)>(
        "UPDATE users SET failed_login_attempts = failed_login_attempts + 1, updated_at = ? \
         WHERE id = ? RETURNING failed_login_attempts",
    )
    .bind(now)
    .bind(id)
    .fetch_one(db)
    .await?;
    Ok(count)
}

pub async fn lock_until(db: &SqlitePool, id: &str, until: i64) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET locked_until = ?, updated_at = ? WHERE id = ?")
        .bind(until)
        .bind(now_ts())
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn clear_lockout(db: &SqlitePool, id: &str) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE users SET locked_until = NULL, failed_login_attempts = 0, updated_at = ? WHERE id = ?",
    )
    .bind(now_ts())
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn set_role(db: &SqlitePool, id: &str, role: Role) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET role = ?, updated_at = ? WHERE id = ?")
        .bind(role)
        .bind(now_ts())
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn set_status(db: &SqlitePool, id: &str, status: UserStatus) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET status = ?, updated_at = ? WHERE id = ?")
        .bind(status)
        .bind(now_ts())
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete(db: &SqlitePool, id: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn count_with_role(db: &SqlitePool, role: Role) -> Result<i64, ApiError> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = ? AND status = 'active'")
            .bind(role)
            .fetch_one(db)
            .await?;
    Ok(count)
}

#[derive(Debug, Clone, Default)]
pub struct UserFilter {
    pub search: Option<String>,
    pub role: Option<Role>,
    pub status: Option<UserStatus>,
    pub email_verified: Option<bool>,
    pub two_factor: Option<bool>,
    pub sort: Option<String>,
    pub order: Option<String>,
}

pub async fn list(
    db: &SqlitePool,
    filter: &UserFilter,
    limit: i64,
    offset: i64,
) -> Result<(Vec<UserWithSecurity>, i64), ApiError> {
    use sqlx::{QueryBuilder, Sqlite};

    const BASE: &str = "SELECT u.id, u.email, u.password_hash, u.full_name, u.role, u.status, \
        u.email_verified_at, u.last_login_at, u.failed_login_attempts, u.locked_until, \
        u.password_changed_at, u.created_at, u.updated_at, \
        COALESCE(t.enabled, 0) AS two_factor_enabled \
        FROM users u LEFT JOIN two_factor_settings t ON t.user_id = u.id WHERE 1 = 1";

    let mut builder: QueryBuilder<Sqlite> = QueryBuilder::new(BASE);
    push_user_filters(&mut builder, filter);

    let sort_column = match filter.sort.as_deref() {
        Some("email") => "u.email",
        Some("last_login_at") => "u.last_login_at",
        Some("role") => "u.role",
        Some("status") => "u.status",
        Some("updated_at") => "u.updated_at",
        _ => "u.created_at",
    };
    let direction = match filter.order.as_deref() {
        Some(o) if o.eq_ignore_ascii_case("asc") => "ASC",
        _ => "DESC",
    };
    builder.push(format!(" ORDER BY {sort_column} {direction} LIMIT "));
    builder.push_bind(limit);
    builder.push(" OFFSET ");
    builder.push_bind(offset);

    let items = builder
        .build_query_as::<UserWithSecurity>()
        .fetch_all(db)
        .await?;

    let mut count_builder: QueryBuilder<Sqlite> =
        QueryBuilder::new("SELECT COUNT(*) FROM users u WHERE 1 = 1");
    push_user_filters(&mut count_builder, filter);
    let total: i64 = count_builder
        .build_query_scalar::<i64>()
        .fetch_one(db)
        .await?;

    Ok((items, total))
}

fn push_user_filters<'a>(
    builder: &mut sqlx::QueryBuilder<'a, sqlx::Sqlite>,
    filter: &'a UserFilter,
) {
    if let Some(search) = &filter.search {
        let pattern = format!("%{}%", search.trim().to_ascii_lowercase());
        builder.push(" AND (LOWER(u.email) LIKE ");
        builder.push_bind(pattern.clone());
        builder.push(" OR LOWER(COALESCE(u.full_name, '')) LIKE ");
        builder.push_bind(pattern);
        builder.push(")");
    }
    if let Some(role) = filter.role {
        builder.push(" AND u.role = ");
        builder.push_bind(role);
    }
    if let Some(status) = filter.status {
        builder.push(" AND u.status = ");
        builder.push_bind(status);
    }
    match filter.email_verified {
        Some(true) => {
            builder.push(" AND u.email_verified_at IS NOT NULL");
        }
        Some(false) => {
            builder.push(" AND u.email_verified_at IS NULL");
        }
        None => {}
    }
    if let Some(two_factor) = filter.two_factor {
        builder.push(if two_factor {
            " AND EXISTS (SELECT 1 FROM two_factor_settings t WHERE t.user_id = u.id AND t.enabled = 1)"
        } else {
            " AND NOT EXISTS (SELECT 1 FROM two_factor_settings t WHERE t.user_id = u.id AND t.enabled = 1)"
        });
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AdminStats {
    pub total_users: i64,
    pub active_users: i64,
    pub suspended_users: i64,
    pub deleted_users: i64,
    pub verified_users: i64,
    pub two_factor_users: i64,
    pub new_users_24h: i64,
    pub admin_users: i64,
}

pub async fn stats(db: &SqlitePool) -> Result<AdminStats, ApiError> {
    let since = now_ts() - 86_400;
    let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64, i64, i64)>(
        r#"
        SELECT
            (SELECT COUNT(*) FROM users),
            (SELECT COUNT(*) FROM users WHERE status = 'active'),
            (SELECT COUNT(*) FROM users WHERE status = 'suspended'),
            (SELECT COUNT(*) FROM users WHERE status = 'deleted'),
            (SELECT COUNT(*) FROM users WHERE email_verified_at IS NOT NULL),
            (SELECT COUNT(*) FROM two_factor_settings WHERE enabled = 1),
            (SELECT COUNT(*) FROM users WHERE created_at >= ?),
            (SELECT COUNT(*) FROM users WHERE role IN ('admin', 'superadmin'))
        "#,
    )
    .bind(since)
    .fetch_one(db)
    .await?;

    Ok(AdminStats {
        total_users: row.0,
        active_users: row.1,
        suspended_users: row.2,
        deleted_users: row.3,
        verified_users: row.4,
        two_factor_users: row.5,
        new_users_24h: row.6,
        admin_users: row.7,
    })
}

pub fn ts_to_datetime(ts: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(ts, 0).unwrap_or_else(Utc::now)
}
