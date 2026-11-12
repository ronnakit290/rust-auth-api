//! Authorization codes, user consents, SSO refresh tokens and the JWT denylist.

use sqlx::{FromRow, SqlitePool};

use crate::{db::now_ts, error::ApiError};

#[derive(Debug, Clone, FromRow)]
pub struct CodeRow {
    pub id: String,
    pub code_hash: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scopes: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub created_at: i64,
}

impl CodeRow {
    pub fn scopes(&self) -> Vec<String> {
        serde_json::from_str(&self.scopes).unwrap_or_default()
    }
}

pub struct NewCode<'a> {
    pub id: &'a str,
    pub code_hash: &'a str,
    pub client_id: &'a str,
    pub user_id: &'a str,
    pub redirect_uri: &'a str,
    pub scopes: &'a [String],
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: Option<&'a str>,
    pub expires_at: i64,
}

pub async fn insert_code(db: &SqlitePool, code: &NewCode<'_>) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        INSERT INTO oauth_authorization_codes (
            id, code_hash, client_id, user_id, redirect_uri, scopes,
            code_challenge, code_challenge_method, expires_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(code.id)
    .bind(code.code_hash)
    .bind(code.client_id)
    .bind(code.user_id)
    .bind(code.redirect_uri)
    .bind(serde_json::to_string(code.scopes).unwrap_or_else(|_| "[]".into()))
    .bind(code.code_challenge)
    .bind(code.code_challenge_method)
    .bind(code.expires_at)
    .bind(now_ts())
    .execute(db)
    .await?;
    Ok(())
}

/// Burns the code atomically; `None` means unknown, expired or already used.
pub async fn consume_code(db: &SqlitePool, code_hash: &str) -> Result<Option<CodeRow>, ApiError> {
    Ok(sqlx::query_as::<_, CodeRow>(
        "UPDATE oauth_authorization_codes SET used_at = ? \
         WHERE code_hash = ? AND used_at IS NULL AND expires_at > ? \
         RETURNING id, code_hash, client_id, user_id, redirect_uri, scopes, \
                   code_challenge, code_challenge_method, expires_at, used_at, created_at",
    )
    .bind(now_ts())
    .bind(code_hash)
    .bind(now_ts())
    .fetch_optional(db)
    .await?)
}

#[derive(Debug, Clone, FromRow)]
pub struct ConsentRow {
    pub user_id: String,
    pub client_id: String,
    pub scopes: String,
    pub created_at: i64,
    pub updated_at: i64,
}

pub async fn get_consent(
    db: &SqlitePool,
    user_id: &str,
    client_id: &str,
) -> Result<Option<ConsentRow>, ApiError> {
    Ok(sqlx::query_as::<_, ConsentRow>(
        "SELECT user_id, client_id, scopes, created_at, updated_at FROM oauth_consents \
         WHERE user_id = ? AND client_id = ?",
    )
    .bind(user_id)
    .bind(client_id)
    .fetch_optional(db)
    .await?)
}

pub async fn upsert_consent(
    db: &SqlitePool,
    user_id: &str,
    client_id: &str,
    scopes: &[String],
) -> Result<(), ApiError> {
    let now = now_ts();
    sqlx::query(
        "INSERT INTO oauth_consents (id, user_id, client_id, scopes, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = excluded.scopes, \
             updated_at = excluded.updated_at",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(user_id)
    .bind(client_id)
    .bind(serde_json::to_string(scopes).unwrap_or_else(|_| "[]".into()))
    .bind(now)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Refresh tokens (authorization_code + offline_access)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, FromRow)]
pub struct RefreshTokenRow {
    pub id: String,
    pub token_hash: String,
    pub client_id: String,
    pub user_id: String,
    pub scopes: String,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub replaced_by: Option<String>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

impl RefreshTokenRow {
    pub fn scopes(&self) -> Vec<String> {
        serde_json::from_str(&self.scopes).unwrap_or_default()
    }
}

pub struct NewRefreshToken<'a> {
    pub id: &'a str,
    pub token_hash: &'a str,
    pub client_id: &'a str,
    pub user_id: &'a str,
    pub scopes: &'a [String],
    pub expires_at: i64,
}

pub async fn insert_refresh(db: &SqlitePool, token: &NewRefreshToken<'_>) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO oauth_refresh_tokens (id, token_hash, client_id, user_id, scopes, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(token.id)
    .bind(token.token_hash)
    .bind(token.client_id)
    .bind(token.user_id)
    .bind(serde_json::to_string(token.scopes).unwrap_or_else(|_| "[]".into()))
    .bind(token.expires_at)
    .bind(now_ts())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn find_refresh(
    db: &SqlitePool,
    token_hash: &str,
) -> Result<Option<RefreshTokenRow>, ApiError> {
    Ok(sqlx::query_as::<_, RefreshTokenRow>(
        "SELECT id, token_hash, client_id, user_id, scopes, expires_at, revoked_at, replaced_by, \
         created_at, last_used_at FROM oauth_refresh_tokens WHERE token_hash = ?",
    )
    .bind(token_hash)
    .fetch_optional(db)
    .await?)
}

pub async fn revoke_refresh(
    db: &SqlitePool,
    id: &str,
    replaced_by: Option<&str>,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE oauth_refresh_tokens SET revoked_at = ?, replaced_by = ? \
         WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(now_ts())
    .bind(replaced_by)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn revoke_refresh_for_client(
    db: &SqlitePool,
    user_id: &str,
    client_id: &str,
) -> Result<u64, ApiError> {
    let result = sqlx::query(
        "UPDATE oauth_refresh_tokens SET revoked_at = ? \
         WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL",
    )
    .bind(now_ts())
    .bind(user_id)
    .bind(client_id)
    .execute(db)
    .await?;
    Ok(result.rows_affected())
}

/// Revokes every refresh token issued to a client, regardless of user.
pub async fn revoke_refresh_for_client_all(
    db: &SqlitePool,
    client_id: &str,
) -> Result<u64, ApiError> {
    let result = sqlx::query(
        "UPDATE oauth_refresh_tokens SET revoked_at = ? \
         WHERE client_id = ? AND revoked_at IS NULL",
    )
    .bind(now_ts())
    .bind(client_id)
    .execute(db)
    .await?;
    Ok(result.rows_affected())
}

// ---------------------------------------------------------------------------
// JWT denylist
// ---------------------------------------------------------------------------

pub async fn revoke_jti(
    db: &SqlitePool,
    jti: &str,
    expires_at: i64,
    reason: &str,
) -> Result<(), ApiError> {
    let now = now_ts();
    sqlx::query(
        "INSERT INTO revoked_tokens (jti, expires_at, revoked_at, reason) VALUES (?, ?, ?, ?) \
         ON CONFLICT (jti) DO NOTHING",
    )
    .bind(jti)
    .bind(expires_at)
    .bind(now)
    .bind(reason)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn is_jti_revoked(db: &SqlitePool, jti: &str) -> Result<bool, ApiError> {
    let found: Option<String> = sqlx::query_scalar("SELECT jti FROM revoked_tokens WHERE jti = ?")
        .bind(jti)
        .fetch_optional(db)
        .await?;
    Ok(found.is_some())
}

/// Housekeeping for codes, refresh tokens and the denylist.
pub async fn purge_expired(db: &SqlitePool) -> Result<u64, ApiError> {
    let now = now_ts();
    let mut removed = 0;
    removed += sqlx::query("DELETE FROM oauth_authorization_codes WHERE expires_at < ?")
        .bind(now - 3600)
        .execute(db)
        .await?
        .rows_affected();
    removed += sqlx::query("DELETE FROM oauth_refresh_tokens WHERE expires_at < ?")
        .bind(now - 86_400)
        .execute(db)
        .await?
        .rows_affected();
    removed += sqlx::query("DELETE FROM revoked_tokens WHERE expires_at < ?")
        .bind(now)
        .execute(db)
        .await?
        .rows_affected();
    Ok(removed)
}
