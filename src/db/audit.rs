//! Append-only audit trail.

use sqlx::{FromRow, QueryBuilder, Sqlite, SqlitePool};
use utoipa::ToSchema;

use crate::{db::now_ts, error::ApiError};

#[derive(Debug, Clone, FromRow, ToSchema)]
pub struct AuditRow {
    pub id: String,
    pub actor_id: Option<String>,
    pub actor_email: Option<String>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Default, Clone)]
pub struct NewAudit<'a> {
    pub actor_id: Option<&'a str>,
    pub actor_email: Option<&'a str>,
    pub action: &'a str,
    pub target_type: Option<&'a str>,
    pub target_id: Option<&'a str>,
    pub ip_address: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Default, Clone)]
pub struct AuditFilter {
    pub action: Option<String>,
    pub actor_id: Option<String>,
    pub target_id: Option<String>,
    pub from: Option<i64>,
    pub to: Option<i64>,
}

pub async fn insert(db: &SqlitePool, entry: &NewAudit<'_>) -> Result<(), ApiError> {
    let metadata = entry.metadata.as_ref().map(|value| value.to_string());
    sqlx::query(
        r#"
        INSERT INTO audit_logs (
            id, actor_id, actor_email, action, target_type, target_id,
            ip_address, user_agent, metadata, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(entry.actor_id)
    .bind(entry.actor_email)
    .bind(entry.action)
    .bind(entry.target_type)
    .bind(entry.target_id)
    .bind(entry.ip_address)
    .bind(entry.user_agent)
    .bind(metadata)
    .bind(now_ts())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn list(
    db: &SqlitePool,
    filter: &AuditFilter,
    limit: i64,
    offset: i64,
) -> Result<(Vec<AuditRow>, i64), ApiError> {
    const BASE: &str = "SELECT id, actor_id, actor_email, action, target_type, target_id, \
        ip_address, user_agent, metadata, created_at FROM audit_logs WHERE 1 = 1";

    let mut builder: QueryBuilder<Sqlite> = QueryBuilder::new(BASE);
    push_filters(&mut builder, filter);
    builder.push(" ORDER BY created_at DESC LIMIT ");
    builder.push_bind(limit);
    builder.push(" OFFSET ");
    builder.push_bind(offset);

    let items = builder.build_query_as::<AuditRow>().fetch_all(db).await?;

    let mut count_builder: QueryBuilder<Sqlite> =
        QueryBuilder::new("SELECT COUNT(*) FROM audit_logs WHERE 1 = 1");
    push_filters(&mut count_builder, filter);
    let total: i64 = count_builder
        .build_query_scalar::<i64>()
        .fetch_one(db)
        .await?;

    Ok((items, total))
}

fn push_filters<'a>(builder: &mut QueryBuilder<'a, Sqlite>, filter: &'a AuditFilter) {
    if let Some(action) = &filter.action {
        builder.push(" AND action = ");
        builder.push_bind(action.clone());
    }
    if let Some(actor) = &filter.actor_id {
        builder.push(" AND actor_id = ");
        builder.push_bind(actor.clone());
    }
    if let Some(target) = &filter.target_id {
        builder.push(" AND target_id = ");
        builder.push_bind(target.clone());
    }
    if let Some(from) = filter.from {
        builder.push(" AND created_at >= ");
        builder.push_bind(from);
    }
    if let Some(to) = filter.to {
        builder.push(" AND created_at <= ");
        builder.push_bind(to);
    }
}

pub async fn count_action_since(
    db: &SqlitePool,
    action: &str,
    since: i64,
) -> Result<i64, ApiError> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE action = ? AND created_at >= ?")
            .bind(action)
            .bind(since)
            .fetch_one(db)
            .await?;
    Ok(count)
}
