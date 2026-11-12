//! TOTP settings and recovery codes.

use sqlx::{FromRow, SqlitePool};

use crate::{db::now_ts, error::ApiError};

#[derive(Debug, Clone, FromRow)]
pub struct TwoFactorRow {
    pub user_id: String,
    pub secret: String,
    pub enabled: i64,
    pub confirmed_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl TwoFactorRow {
    pub fn is_enabled(&self) -> bool {
        self.enabled != 0
    }
}

pub async fn get(db: &SqlitePool, user_id: &str) -> Result<Option<TwoFactorRow>, ApiError> {
    Ok(sqlx::query_as::<_, TwoFactorRow>(
        "SELECT user_id, secret, enabled, confirmed_at, created_at, updated_at \
         FROM two_factor_settings WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?)
}

pub async fn is_enabled(db: &SqlitePool, user_id: &str) -> Result<bool, ApiError> {
    let enabled: Option<i64> = sqlx::query_scalar(
        "SELECT enabled FROM two_factor_settings WHERE user_id = ? AND enabled = 1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?;
    Ok(enabled.is_some())
}

/// Creates a pending (not yet enabled) secret, replacing any previous pending one.
pub async fn upsert_pending(db: &SqlitePool, user_id: &str, secret: &str) -> Result<(), ApiError> {
    let now = now_ts();
    sqlx::query(
        "INSERT INTO two_factor_settings (user_id, secret, enabled, confirmed_at, created_at, updated_at) \
         VALUES (?, ?, 0, NULL, ?, ?) \
         ON CONFLICT (user_id) DO UPDATE SET secret = excluded.secret, enabled = 0, \
             confirmed_at = NULL, updated_at = excluded.updated_at",
    )
    .bind(user_id)
    .bind(secret)
    .bind(now)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn enable(db: &SqlitePool, user_id: &str) -> Result<(), ApiError> {
    let now = now_ts();
    sqlx::query(
        "UPDATE two_factor_settings SET enabled = 1, confirmed_at = ?, updated_at = ? \
         WHERE user_id = ?",
    )
    .bind(now)
    .bind(now)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete(db: &SqlitePool, user_id: &str) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM two_factor_settings WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn replace_recovery_codes(
    db: &SqlitePool,
    user_id: &str,
    code_hashes: &[String],
) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    for hash in code_hashes {
        sqlx::query(
            "INSERT INTO recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(hash)
        .bind(now_ts())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn count_unused_codes(db: &SqlitePool, user_id: &str) -> Result<i64, ApiError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(db)
    .await?;
    Ok(count)
}

pub async fn consume_recovery_code(
    db: &SqlitePool,
    user_id: &str,
    code_hash: &str,
) -> Result<bool, ApiError> {
    let result = sqlx::query(
        "UPDATE recovery_codes SET used_at = ? \
         WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
    )
    .bind(now_ts())
    .bind(user_id)
    .bind(code_hash)
    .execute(db)
    .await?;
    Ok(result.rows_affected() > 0)
}
