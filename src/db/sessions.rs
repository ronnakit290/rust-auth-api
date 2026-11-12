//! `sessions` aggregate — refresh-token families, rotation and revocation.

use sqlx::{FromRow, SqlitePool};

use crate::{db::now_ts, error::ApiError};

#[derive(Debug, Clone, FromRow)]
pub struct SessionRow {
    pub id: String,
    pub user_id: String,
    pub family_id: String,
    pub refresh_token_hash: String,
    pub replaced_by: Option<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub revoke_reason: Option<String>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

impl SessionRow {
    pub fn is_active(&self, now: i64) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

pub struct NewSession<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub family_id: &'a str,
    pub refresh_token_hash: &'a str,
    pub user_agent: Option<&'a str>,
    pub ip_address: Option<&'a str>,
    pub expires_at: i64,
}

pub async fn insert(db: &SqlitePool, session: &NewSession<'_>) -> Result<(), ApiError> {
    let now = now_ts();
    sqlx::query(
        r#"
        INSERT INTO sessions (
            id, user_id, family_id, refresh_token_hash, user_agent, ip_address,
            expires_at, created_at, last_used_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(session.id)
    .bind(session.user_id)
    .bind(session.family_id)
    .bind(session.refresh_token_hash)
    .bind(session.user_agent)
    .bind(session.ip_address)
    .bind(session.expires_at)
    .bind(now)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

const SELECT_SESSION: &str = "SELECT id, user_id, family_id, refresh_token_hash, replaced_by, \
    user_agent, ip_address, expires_at, revoked_at, revoke_reason, created_at, last_used_at \
    FROM sessions";

pub async fn find_by_hash(
    db: &SqlitePool,
    token_hash: &str,
) -> Result<Option<SessionRow>, ApiError> {
    Ok(
        sqlx::query_as::<_, SessionRow>(&format!("{SELECT_SESSION} WHERE refresh_token_hash = ?"))
            .bind(token_hash)
            .fetch_optional(db)
            .await?,
    )
}

pub async fn find_by_id(db: &SqlitePool, id: &str) -> Result<Option<SessionRow>, ApiError> {
    Ok(
        sqlx::query_as::<_, SessionRow>(&format!("{SELECT_SESSION} WHERE id = ?"))
            .bind(id)
            .fetch_optional(db)
            .await?,
    )
}

pub async fn touch(db: &SqlitePool, id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE sessions SET last_used_at = ? WHERE id = ?")
        .bind(now_ts())
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn revoke(
    db: &SqlitePool,
    id: &str,
    reason: &str,
    replaced_by: Option<&str>,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE sessions SET revoked_at = ?, revoke_reason = ?, replaced_by = ? \
         WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(now_ts())
    .bind(reason)
    .bind(replaced_by)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

/// Revokes every token in a rotation family — used when replay is detected.
pub async fn revoke_family(
    db: &SqlitePool,
    family_id: &str,
    reason: &str,
) -> Result<u64, ApiError> {
    let result = sqlx::query(
        "UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE family_id = ? AND revoked_at IS NULL",
    )
    .bind(now_ts())
    .bind(reason)
    .bind(family_id)
    .execute(db)
    .await?;
    Ok(result.rows_affected())
}

pub async fn revoke_all_for_user(
    db: &SqlitePool,
    user_id: &str,
    reason: &str,
    except_session: Option<&str>,
) -> Result<u64, ApiError> {
    let result = sqlx::query(
        "UPDATE sessions SET revoked_at = ?, revoke_reason = ? \
         WHERE user_id = ? AND revoked_at IS NULL AND (? IS NULL OR id <> ?)",
    )
    .bind(now_ts())
    .bind(reason)
    .bind(user_id)
    .bind(except_session)
    .bind(except_session)
    .execute(db)
    .await?;
    Ok(result.rows_affected())
}

pub async fn list_active(
    db: &SqlitePool,
    user_id: &str,
    limit: i64,
) -> Result<Vec<SessionRow>, ApiError> {
    Ok(sqlx::query_as::<_, SessionRow>(&format!(
        "{SELECT_SESSION} WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? \
         ORDER BY COALESCE(last_used_at, created_at) DESC LIMIT ?"
    ))
    .bind(user_id)
    .bind(now_ts())
    .bind(limit)
    .fetch_all(db)
    .await?)
}

pub async fn list_active_for_admin(
    db: &SqlitePool,
    user_id: &str,
) -> Result<Vec<SessionRow>, ApiError> {
    list_active(db, user_id, 200).await
}

pub async fn count_active(db: &SqlitePool) -> Result<i64, ApiError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > ?",
    )
    .bind(now_ts())
    .fetch_one(db)
    .await?;
    Ok(count)
}

/// Housekeeping: drops rows that can no longer be used.
pub async fn purge_expired(db: &SqlitePool) -> Result<u64, ApiError> {
    let cutoff = now_ts() - 86_400;
    let result = sqlx::query("DELETE FROM sessions WHERE expires_at < ?")
        .bind(cutoff)
        .execute(db)
        .await?;
    Ok(result.rows_affected())
}
