//! Single-use tokens (e-mail verification, password reset).
//!
//! Only the SHA-256 hash is persisted; the plaintext token exists only in the
//! e-mail we send to the user.

use std::str::FromStr;

use sqlx::{FromRow, SqlitePool};

use crate::{db::now_ts, error::ApiError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    EmailVerification,
    PasswordReset,
}

impl TokenKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenKind::EmailVerification => "email_verification",
            TokenKind::PasswordReset => "password_reset",
        }
    }
}

impl std::fmt::Display for TokenKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidTokenKind(pub String);

impl std::fmt::Display for InvalidTokenKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid token kind `{}`", self.0)
    }
}
impl std::error::Error for InvalidTokenKind {}

impl FromStr for TokenKind {
    type Err = InvalidTokenKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "email_verification" => Ok(TokenKind::EmailVerification),
            "password_reset" => Ok(TokenKind::PasswordReset),
            other => Err(InvalidTokenKind(other.to_string())),
        }
    }
}

impl sqlx::Type<sqlx::Sqlite> for TokenKind {
    fn type_info() -> <sqlx::Sqlite as sqlx::Database>::TypeInfo {
        <&str as sqlx::Type<sqlx::Sqlite>>::type_info()
    }
    fn compatible(ty: &<sqlx::Sqlite as sqlx::Database>::TypeInfo) -> bool {
        <&str as sqlx::Type<sqlx::Sqlite>>::compatible(ty)
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Sqlite> for TokenKind {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Sqlite as sqlx::Database>::ArgumentBuffer<'q>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <&str as sqlx::Encode<'q, sqlx::Sqlite>>::encode(self.as_str(), buf)
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Sqlite> for TokenKind {
    fn decode(
        value: <sqlx::Sqlite as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let raw = <&str as sqlx::Decode<'r, sqlx::Sqlite>>::decode(value)?;
        TokenKind::from_str(raw).map_err(|e| sqlx::error::BoxDynError::from(e.to_string()))
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct OneTimeTokenRow {
    pub id: String,
    pub user_id: String,
    pub kind: TokenKind,
    pub token_hash: String,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub created_at: i64,
}

pub async fn insert(
    db: &SqlitePool,
    id: &str,
    user_id: &str,
    kind: TokenKind,
    token_hash: &str,
    expires_at: i64,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO one_time_tokens (id, user_id, kind, token_hash, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(user_id)
    .bind(kind)
    .bind(token_hash)
    .bind(expires_at)
    .bind(now_ts())
    .execute(db)
    .await?;
    Ok(())
}

/// Atomically validates and burns a token. Returns `None` when the token is
/// unknown, expired, of the wrong kind, or already used.
pub async fn consume(
    db: &SqlitePool,
    kind: TokenKind,
    token_hash: &str,
) -> Result<Option<OneTimeTokenRow>, ApiError> {
    let row = sqlx::query_as::<_, OneTimeTokenRow>(
        "UPDATE one_time_tokens SET used_at = ? \
         WHERE token_hash = ? AND kind = ? AND used_at IS NULL AND expires_at > ? \
         RETURNING id, user_id, kind, token_hash, expires_at, used_at, created_at",
    )
    .bind(now_ts())
    .bind(token_hash)
    .bind(kind)
    .bind(now_ts())
    .fetch_optional(db)
    .await?;
    Ok(row)
}

/// Invalidates every outstanding token of one kind for a user (e.g. when a new
/// reset link is requested the old ones must stop working).
pub async fn invalidate(db: &SqlitePool, user_id: &str, kind: TokenKind) -> Result<u64, ApiError> {
    let result = sqlx::query(
        "UPDATE one_time_tokens SET used_at = ? WHERE user_id = ? AND kind = ? AND used_at IS NULL",
    )
    .bind(now_ts())
    .bind(user_id)
    .bind(kind)
    .execute(db)
    .await?;
    Ok(result.rows_affected())
}
