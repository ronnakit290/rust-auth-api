//! `/api/v1/admin/*` — user administration, audit trail, statistics.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use validator::Validate;

use crate::{
    dto::*,
    error::{ApiResult, ErrorResponse},
    extract::{AdminUser, ApiJson, ClientInfo},
    response::{message, ok},
    services::admin as admin_service,
    state::AppState,
};

#[utoipa::path(
    get,
    path = "/api/v1/admin/users",
    tag = "admin",
    summary = "List users",
    description = "Paginated, filterable by search term, role, status, verification and 2FA. Requires admin.",
    params(
        ("page" = Option<u32>, Query, description = "1-based page number"),
        ("per_page" = Option<u32>, Query, description = "Items per page (max 100)"),
        ("search" = Option<String>, Query, description = "Substring of e-mail or full name"),
        ("role" = Option<String>, Query, description = "user|moderator|admin|superadmin"),
        ("status" = Option<String>, Query, description = "active|suspended|deleted"),
        ("email_verified" = Option<bool>, Query),
        ("two_factor" = Option<bool>, Query),
        ("sort" = Option<String>, Query, description = "created_at|email|last_login_at|role|status|updated_at"),
        ("order" = Option<String>, Query, description = "asc|desc")
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = Vec<UserDto>),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse)
    )
)]
pub async fn list_users(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(query): Query<ListUsersQuery>,
) -> ApiResult<impl IntoResponse> {
    let page = admin_service::list_users(&state, query).await?;
    Ok(ok(page))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/users/{user_id}",
    tag = "admin",
    summary = "Fetch one user",
    params(("user_id" = String, Path)),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = UserDto),
        (status = 404, body = ErrorResponse)
    )
)]
pub async fn get_user(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(user_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let user = admin_service::get_user(&state, &user_id).await?;
    Ok(ok(user))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/users/{user_id}",
    tag = "admin",
    summary = "Update role, status, name or clear a lockout",
    params(("user_id" = String, Path)),
    request_body = AdminUpdateUserRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = UserDto),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 409, body = ErrorResponse)
    )
)]
pub async fn update_user(
    State(state): State<AppState>,
    admin: AdminUser,
    client: ClientInfo,
    Path(user_id): Path<String>,
    ApiJson(payload): ApiJson<AdminUpdateUserRequest>,
) -> ApiResult<impl IntoResponse> {
    payload.validate()?;
    let user = admin_service::update_user(&state, &admin.0, &user_id, payload, &client).await?;
    Ok(ok(user))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/users/{user_id}",
    tag = "admin",
    summary = "Delete a user",
    description = "Soft-deletes by default; `?hard=true` purges the row (cascades sessions and tokens).",
    params(
        ("user_id" = String, Path),
        ("hard" = Option<bool>, Query)
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = MessageResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 409, body = ErrorResponse)
    )
)]
pub async fn delete_user(
    State(state): State<AppState>,
    admin: AdminUser,
    client: ClientInfo,
    Path(user_id): Path<String>,
    Query(query): Query<DeleteUserQuery>,
) -> ApiResult<impl IntoResponse> {
    admin_service::delete_user(&state, &admin.0, &user_id, query.hard, &client).await?;
    Ok((
        StatusCode::OK,
        ok(message(if query.hard {
            "User permanently deleted"
        } else {
            "User marked as deleted"
        })),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/users/{user_id}/sessions/revoke",
    tag = "admin",
    summary = "Revoke every session of a user",
    params(("user_id" = String, Path)),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = RevokedSessionsResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse)
    )
)]
pub async fn revoke_user_sessions(
    State(state): State<AppState>,
    admin: AdminUser,
    client: ClientInfo,
    Path(user_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let revoked = admin_service::revoke_user_sessions(&state, &admin.0, &user_id, &client).await?;
    Ok((
        StatusCode::OK,
        ok(RevokedSessionsResponse {
            revoked,
            message: "Sessions revoked".to_string(),
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/audit-logs",
    tag = "admin",
    summary = "Query the audit trail",
    params(
        ("page" = Option<u32>, Query),
        ("per_page" = Option<u32>, Query),
        ("action" = Option<String>, Query),
        ("actor_id" = Option<String>, Query),
        ("target_id" = Option<String>, Query),
        ("from" = Option<i64>, Query, description = "Unix seconds, inclusive"),
        ("to" = Option<i64>, Query, description = "Unix seconds, inclusive")
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = Vec<AuditLogDto>),
        (status = 403, body = ErrorResponse)
    )
)]
pub async fn audit_logs(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(query): Query<AuditLogQuery>,
) -> ApiResult<impl IntoResponse> {
    let page = admin_service::list_audit(&state, query).await?;
    Ok(ok(page))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/stats",
    tag = "admin",
    summary = "Platform statistics",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = AdminStatsResponse),
        (status = 403, body = ErrorResponse)
    )
)]
pub async fn stats(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> ApiResult<impl IntoResponse> {
    let stats = admin_service::stats(&state).await?;
    Ok(ok(stats))
}
