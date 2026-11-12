//! Database bootstrap and per-entity query modules.
//!
//! Deliberately thin: each module owns one aggregate, exposes plain async
//! functions that take a pool, and returns typed rows. Services orchestrate
//! these functions inside transactions when a workflow spans several writes.

pub mod audit;
pub mod oauth_clients;
pub mod oauth_flow;
pub mod sessions;
pub mod tokens;
pub mod two_factor;
pub mod users;

use std::{str::FromStr, time::Duration};

use anyhow::{Context, Result};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};

use crate::config::Config;

/// Every timestamp in the schema is a unix timestamp in seconds (UTC).
pub fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

pub async fn connect(config: &Config) -> Result<SqlitePool> {
    let mut options = SqliteConnectOptions::from_str(&config.database_url)
        .with_context(|| format!("invalid DATABASE_URL `{}`", config.database_url))?
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(10));

    let in_memory = config.database_url.contains(":memory:");
    if !in_memory {
        if let Some(dir) = sqlite_parent_dir(&config.database_url) {
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("cannot create database directory {}", dir.display()))?;
        }
        options = options
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal);
    }

    // An in-memory SQLite database lives inside a single connection, so the
    // pool must never open a second one.
    let max_connections = if in_memory {
        1
    } else {
        config.db_max_connections.max(1)
    };

    SqlitePoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(options)
        .await
        .context("failed to open the SQLite database")
}

pub async fn migrate(pool: &SqlitePool) -> Result<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .context("database migration failed")?;
    Ok(())
}

pub async fn ping(pool: &SqlitePool) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(pool)
        .await
        .map(|v| v == 1)
        .unwrap_or(false)
}

fn sqlite_parent_dir(url: &str) -> Option<std::path::PathBuf> {
    let without_scheme = url
        .trim_start_matches("sqlite://")
        .trim_start_matches("sqlite:");
    let path = without_scheme.split('?').next().unwrap_or("");
    if path.is_empty() || path == ":memory:" || path.starts_with("file:") {
        return None;
    }
    std::path::Path::new(path).parent().map(|p| p.to_path_buf())
}
