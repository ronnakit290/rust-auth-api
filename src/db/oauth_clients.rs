//! OAuth2 applications ("clients") and the app keys issued for them.

use std::{str::FromStr, time::Duration};

use sqlx::{FromRow, QueryBuilder, Sqlite, SqlitePool};
use utoipa::ToSchema;

use crate::{db::now_ts, error::ApiError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ClientType {
    Confidential,
    Public,
}

impl ClientType {
    pub fn as_str(self) -> &'static str {
        match self {
            ClientType::Confidential => "confidential",
            ClientType::Public => "public",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidClientType(pub String);

impl std::fmt::Display for InvalidClientType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid client type `{}`", self.0)
    }
}
impl std::error::Error for InvalidClientType {}

impl FromStr for ClientType {
    type Err = InvalidClientType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "confidential" => Ok(ClientType::Confidential),
            "public" => Ok(ClientType::Public),
            other => Err(InvalidClientType(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ClientStatus {
    Active,
    Disabled,
}

impl ClientStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ClientStatus::Active => "active",
            ClientStatus::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidClientStatus(pub String);

impl std::fmt::Display for InvalidClientStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid client status `{}`", self.0)
    }
}
impl std::error::Error for InvalidClientStatus {}

impl FromStr for ClientStatus {
    type Err = InvalidClientStatus;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "active" => Ok(ClientStatus::Active),
            "disabled" => Ok(ClientStatus::Disabled),
            other => Err(InvalidClientStatus(other.to_string())),
        }
    }
}

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

sqlite_text_enum!(ClientType);
sqlite_text_enum!(ClientStatus);

#[derive(Debug, Clone, FromRow)]
pub struct ClientRow {
    pub id: String,
    pub client_id: String,
    pub client_secret_hash: String,
    pub name: String,
    pub description: Option<String>,
    pub client_type: ClientType,
    pub redirect_uris: String,
    pub allowed_scopes: String,
    pub owner_id: Option<String>,
    pub status: ClientStatus,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_used_at: Option<i64>,
    pub secret_rotated_at: Option<i64>,
}

impl ClientRow {
    pub fn redirect_uris(&self) -> Vec<String> {
        serde_json::from_str(&self.redirect_uris).unwrap_or_default()
    }

    pub fn allowed_scopes(&self) -> Vec<String> {
        serde_json::from_str(&self.allowed_scopes).unwrap_or_default()
    }

    pub fn is_active(&self) -> bool {
        matches!(self.status, ClientStatus::Active)
    }

    pub fn allows_redirect(&self, uri: &str) -> bool {
        self.redirect_uris()
            .iter()
            .any(|registered| registered == uri)
    }
}

pub struct NewClient<'a> {
    pub id: &'a str,
    pub client_id: &'a str,
    pub client_secret_hash: &'a str,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub client_type: ClientType,
    pub redirect_uris: &'a [String],
    pub allowed_scopes: &'a [String],
    pub owner_id: Option<&'a str>,
}

pub async fn insert(db: &SqlitePool, client: &NewClient<'_>) -> Result<(), ApiError> {
    let now = now_ts();
    sqlx::query(
        r#"
        INSERT INTO oauth_clients (
            id, client_id, client_secret_hash, name, description, client_type,
            redirect_uris, allowed_scopes, owner_id, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
        "#,
    )
    .bind(client.id)
    .bind(client.client_id)
    .bind(client.client_secret_hash)
    .bind(client.name)
    .bind(client.description)
    .bind(client.client_type)
    .bind(serde_json::to_string(client.redirect_uris).unwrap_or_else(|_| "[]".into()))
    .bind(serde_json::to_string(client.allowed_scopes).unwrap_or_else(|_| "[]".into()))
    .bind(client.owner_id)
    .bind(now)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

const SELECT_CLIENT: &str = "SELECT id, client_id, client_secret_hash, name, description, \
    client_type, redirect_uris, allowed_scopes, owner_id, status, created_at, updated_at, \
    last_used_at, secret_rotated_at FROM oauth_clients";

pub async fn find_by_id(db: &SqlitePool, id: &str) -> Result<Option<ClientRow>, ApiError> {
    Ok(
        sqlx::query_as::<_, ClientRow>(&format!("{SELECT_CLIENT} WHERE id = ?"))
            .bind(id)
            .fetch_optional(db)
            .await?,
    )
}

pub async fn find_by_client_id(
    db: &SqlitePool,
    client_id: &str,
) -> Result<Option<ClientRow>, ApiError> {
    Ok(
        sqlx::query_as::<_, ClientRow>(&format!("{SELECT_CLIENT} WHERE client_id = ?"))
            .bind(client_id)
            .fetch_optional(db)
            .await?,
    )
}

pub async fn touch(db: &SqlitePool, id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE oauth_clients SET last_used_at = ? WHERE id = ?")
        .bind(now_ts())
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn update_metadata(
    db: &SqlitePool,
    id: &str,
    name: &str,
    description: Option<&str>,
    redirect_uris: &[String],
    allowed_scopes: &[String],
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE oauth_clients SET name = ?, description = ?, redirect_uris = ?, \
         allowed_scopes = ?, updated_at = ? WHERE id = ?",
    )
    .bind(name)
    .bind(description)
    .bind(serde_json::to_string(redirect_uris).unwrap_or_else(|_| "[]".into()))
    .bind(serde_json::to_string(allowed_scopes).unwrap_or_else(|_| "[]".into()))
    .bind(now_ts())
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn set_status(db: &SqlitePool, id: &str, status: ClientStatus) -> Result<(), ApiError> {
    sqlx::query("UPDATE oauth_clients SET status = ?, updated_at = ? WHERE id = ?")
        .bind(status)
        .bind(now_ts())
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn rotate_secret(db: &SqlitePool, id: &str, secret_hash: &str) -> Result<(), ApiError> {
    let now = now_ts();
    sqlx::query(
        "UPDATE oauth_clients SET client_secret_hash = ?, secret_rotated_at = ?, updated_at = ? \
         WHERE id = ?",
    )
    .bind(secret_hash)
    .bind(now)
    .bind(now)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete(db: &SqlitePool, id: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM oauth_clients WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

#[derive(Debug, Default, Clone)]
pub struct ClientFilter {
    pub search: Option<String>,
    pub status: Option<ClientStatus>,
}

pub async fn list(
    db: &SqlitePool,
    filter: &ClientFilter,
    limit: i64,
    offset: i64,
) -> Result<(Vec<ClientRow>, i64), ApiError> {
    let mut builder: QueryBuilder<Sqlite> = QueryBuilder::new(SELECT_CLIENT);
    builder.push(" WHERE 1 = 1");
    push_filters(&mut builder, filter);
    builder.push(" ORDER BY created_at DESC LIMIT ");
    builder.push_bind(limit);
    builder.push(" OFFSET ");
    builder.push_bind(offset);
    let items = builder.build_query_as::<ClientRow>().fetch_all(db).await?;

    let mut count: QueryBuilder<Sqlite> =
        QueryBuilder::new("SELECT COUNT(*) FROM oauth_clients WHERE 1 = 1");
    push_filters(&mut count, filter);
    let total = count.build_query_scalar::<i64>().fetch_one(db).await?;

    Ok((items, total))
}

fn push_filters<'a>(builder: &mut QueryBuilder<'a, Sqlite>, filter: &'a ClientFilter) {
    if let Some(search) = &filter.search {
        let pattern = format!("%{}%", search.trim().to_ascii_lowercase());
        builder.push(" AND (LOWER(name) LIKE ");
        builder.push_bind(pattern.clone());
        builder.push(" OR LOWER(client_id) LIKE ");
        builder.push_bind(pattern);
        builder.push(")");
    }
    if let Some(status) = filter.status {
        builder.push(" AND status = ");
        builder.push_bind(status);
    }
}

// ---------------------------------------------------------------------------
// App keys
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, FromRow)]
pub struct ApiKeyRow {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub key_prefix: String,
    pub key_hash: String,
    pub scopes: String,
    pub environment: String,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub created_by: Option<String>,
    pub created_at: i64,
}

impl ApiKeyRow {
    pub fn scopes(&self) -> Vec<String> {
        serde_json::from_str(&self.scopes).unwrap_or_default()
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        let scopes = self.scopes();
        scopes.iter().any(|s| s == scope) || scopes.iter().any(|s| s == "*")
    }

    pub fn is_usable(&self, now: i64) -> bool {
        self.revoked_at.is_none() && self.expires_at.map(|exp| exp > now).unwrap_or(true)
    }
}

pub struct NewApiKey<'a> {
    pub id: &'a str,
    pub client_id: &'a str,
    pub name: &'a str,
    pub key_prefix: &'a str,
    pub key_hash: &'a str,
    pub scopes: &'a [String],
    pub environment: &'a str,
    pub expires_at: Option<i64>,
    pub created_by: Option<&'a str>,
}

pub async fn insert_key(db: &SqlitePool, key: &NewApiKey<'_>) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        INSERT INTO api_keys (
            id, client_id, name, key_prefix, key_hash, scopes, environment,
            expires_at, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(key.id)
    .bind(key.client_id)
    .bind(key.name)
    .bind(key.key_prefix)
    .bind(key.key_hash)
    .bind(serde_json::to_string(key.scopes).unwrap_or_else(|_| "[]".into()))
    .bind(key.environment)
    .bind(key.expires_at)
    .bind(key.created_by)
    .bind(now_ts())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn find_key_by_hash(db: &SqlitePool, hash: &str) -> Result<Option<ApiKeyRow>, ApiError> {
    Ok(sqlx::query_as::<_, ApiKeyRow>(
        "SELECT id, client_id, name, key_prefix, key_hash, scopes, environment, expires_at, \
         last_used_at, revoked_at, created_by, created_at FROM api_keys WHERE key_hash = ?",
    )
    .bind(hash)
    .fetch_optional(db)
    .await?)
}

pub async fn find_key_by_id(db: &SqlitePool, id: &str) -> Result<Option<ApiKeyRow>, ApiError> {
    Ok(sqlx::query_as::<_, ApiKeyRow>(
        "SELECT id, client_id, name, key_prefix, key_hash, scopes, environment, expires_at, \
         last_used_at, revoked_at, created_by, created_at FROM api_keys WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await?)
}

pub async fn list_keys(db: &SqlitePool, client_id: &str) -> Result<Vec<ApiKeyRow>, ApiError> {
    Ok(sqlx::query_as::<_, ApiKeyRow>(
        "SELECT id, client_id, name, key_prefix, key_hash, scopes, environment, expires_at, \
         last_used_at, revoked_at, created_by, created_at FROM api_keys \
         WHERE client_id = ? ORDER BY created_at DESC",
    )
    .bind(client_id)
    .fetch_all(db)
    .await?)
}

pub async fn count_keys(db: &SqlitePool, client_id: &str) -> Result<i64, ApiError> {
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_keys WHERE client_id = ? AND revoked_at IS NULL",
    )
    .bind(client_id)
    .fetch_one(db)
    .await?;
    Ok(total)
}

pub async fn revoke_key(db: &SqlitePool, id: &str) -> Result<bool, ApiError> {
    let result =
        sqlx::query("UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
            .bind(now_ts())
            .bind(id)
            .execute(db)
            .await?;
    Ok(result.rows_affected() > 0)
}

/// Revokes every live key of a client (used when an app is disabled/deleted).
pub async fn revoke_all_keys(db: &SqlitePool, client_id: &str) -> Result<u64, ApiError> {
    let result = sqlx::query(
        "UPDATE api_keys SET revoked_at = ? WHERE client_id = ? AND revoked_at IS NULL",
    )
    .bind(now_ts())
    .bind(client_id)
    .execute(db)
    .await?;
    Ok(result.rows_affected())
}

pub async fn touch_key(db: &SqlitePool, id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE api_keys SET last_used_at = ? WHERE id = ?")
        .bind(now_ts())
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Extends the expiry of a key (used by rotation).
pub async fn set_key_expiry(
    db: &SqlitePool,
    id: &str,
    expires_at: Option<i64>,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE api_keys SET expires_at = ? WHERE id = ?")
        .bind(expires_at)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub fn default_key_ttl() -> Duration {
    Duration::from_secs(60 * 60 * 24 * 365)
}
