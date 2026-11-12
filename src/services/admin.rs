//! Administration: user management, audit trail and platform statistics.

use serde_json::json;

use crate::{
    db::{
        self,
        audit::{AuditFilter, NewAudit},
        sessions,
        users::{self, AdminStats, Role, UserFilter, UserStatus},
    },
    dto::*,
    error::{ApiError, ApiResult},
    extract::{ClientInfo, Principal},
    services::audit,
    state::AppState,
};

pub async fn list_users(state: &AppState, query: ListUsersQuery) -> ApiResult<Page<UserDto>> {
    let filter = UserFilter {
        search: query.search.clone(),
        role: query.role,
        status: query.status,
        email_verified: query.email_verified,
        two_factor: query.two_factor,
        sort: query.sort.clone(),
        order: query.order.clone(),
    };
    let (rows, total) = users::list(&state.pool, &filter, query.limit(), query.offset()).await?;

    let items = rows.iter().map(UserDto::from_row).collect();
    Ok(Page::new(items, query.page(), query.per_page(), total))
}

pub async fn get_user(state: &AppState, user_id: &str) -> ApiResult<UserDto> {
    let user = users::find_by_id(&state.pool, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))?;
    let two_factor = db::two_factor::is_enabled(&state.pool, &user.id).await?;
    Ok(UserDto::from_parts(&user, two_factor))
}

pub async fn update_user(
    state: &AppState,
    admin: &Principal,
    user_id: &str,
    payload: AdminUpdateUserRequest,
    client: &ClientInfo,
) -> ApiResult<UserDto> {
    let target = users::find_by_id(&state.pool, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))?;

    if target.id == admin.id() {
        if payload.role.is_some() || payload.status.is_some() {
            return Err(ApiError::forbidden(
                "CANNOT_MODIFY_SELF",
                "You cannot change your own role or status",
            ));
        }
    } else if !admin.user.role.can_manage(target.role) {
        return Err(ApiError::forbidden(
            "INSUFFICIENT_ROLE",
            "You cannot manage an account with an equal or higher role",
        ));
    }

    if let Some(new_role) = payload.role {
        if new_role != target.role {
            if new_role.rank() > admin.user.role.rank() {
                return Err(ApiError::forbidden(
                    "ROLE_ESCALATION_DENIED",
                    "You cannot grant a role higher than your own",
                ));
            }
            ensure_not_last_admin(state, &target, "demote").await?;
            users::set_role(&state.pool, &target.id, new_role).await?;
            // Privileges are embedded in the access token; force a re-login.
            sessions::revoke_all_for_user(&state.pool, &target.id, "role_changed", None).await?;
        }
    }

    if let Some(new_status) = payload.status {
        if new_status != target.status {
            if matches!(new_status, UserStatus::Suspended | UserStatus::Deleted) {
                ensure_not_last_admin(state, &target, "suspend").await?;
            }
            users::set_status(&state.pool, &target.id, new_status).await?;
            if matches!(new_status, UserStatus::Suspended | UserStatus::Deleted) {
                sessions::revoke_all_for_user(&state.pool, &target.id, "status_changed", None)
                    .await?;
            }
        }
    }

    if let Some(full_name) = payload.full_name.as_deref() {
        let normalized = crate::services::normalize_full_name(Some(full_name));
        users::update_full_name(&state.pool, &target.id, normalized.as_deref()).await?;
    }

    if payload.unlock {
        users::clear_lockout(&state.pool, &target.id).await?;
    }

    let updated = users::find_by_id(&state.pool, &target.id)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))?;
    let two_factor = db::two_factor::is_enabled(&state.pool, &updated.id).await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(admin.id()),
            actor_email: Some(&admin.user.email),
            action: "admin.user_updated",
            target_type: Some("user"),
            target_id: Some(&updated.id),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: Some(json!({
                "before": { "role": target.role.to_string(), "status": target.status.to_string() },
                "after": { "role": updated.role.to_string(), "status": updated.status.to_string() },
                "unlocked": payload.unlock,
            })),
        },
    )
    .await;

    Ok(UserDto::from_parts(&updated, two_factor))
}

pub async fn delete_user(
    state: &AppState,
    admin: &Principal,
    user_id: &str,
    hard: bool,
    client: &ClientInfo,
) -> ApiResult<()> {
    let target = users::find_by_id(&state.pool, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))?;

    if target.id == admin.id() {
        return Err(ApiError::forbidden(
            "CANNOT_DELETE_SELF",
            "You cannot delete your own account through the admin API",
        ));
    }
    if !admin.user.role.can_manage(target.role) {
        return Err(ApiError::forbidden(
            "INSUFFICIENT_ROLE",
            "You cannot delete an account with an equal or higher role",
        ));
    }
    ensure_not_last_admin(state, &target, "delete").await?;

    sessions::revoke_all_for_user(&state.pool, &target.id, "account_deleted", None).await?;

    if hard {
        users::delete(&state.pool, &target.id).await?;
    } else {
        users::set_status(&state.pool, &target.id, UserStatus::Deleted).await?;
    }

    audit::record(
        state,
        NewAudit {
            actor_id: Some(admin.id()),
            actor_email: Some(&admin.user.email),
            action: if hard {
                "admin.user_purged"
            } else {
                "admin.user_deleted"
            },
            target_type: Some("user"),
            target_id: Some(&target.id),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: Some(json!({ "email": target.email, "hard": hard })),
        },
    )
    .await;

    Ok(())
}

pub async fn revoke_user_sessions(
    state: &AppState,
    admin: &Principal,
    user_id: &str,
    client: &ClientInfo,
) -> ApiResult<u64> {
    let target = users::find_by_id(&state.pool, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))?;
    if !admin.user.role.can_manage(target.role) && target.id != admin.id() {
        return Err(ApiError::forbidden(
            "INSUFFICIENT_ROLE",
            "You cannot manage an account with an equal or higher role",
        ));
    }

    let revoked =
        sessions::revoke_all_for_user(&state.pool, &target.id, "admin_revoked", None).await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(admin.id()),
            actor_email: Some(&admin.user.email),
            action: "admin.sessions_revoked",
            target_type: Some("user"),
            target_id: Some(&target.id),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: Some(json!({ "revoked": revoked })),
        },
    )
    .await;

    Ok(revoked)
}

pub async fn list_audit(state: &AppState, query: AuditLogQuery) -> ApiResult<Page<AuditLogDto>> {
    let filter = AuditFilter {
        action: query.action.clone(),
        actor_id: query.actor_id.clone(),
        target_id: query.target_id.clone(),
        from: query.from,
        to: query.to,
    };
    let (rows, total) =
        db::audit::list(&state.pool, &filter, query.limit(), query.offset()).await?;

    let items = rows.into_iter().map(AuditLogDto::from).collect();
    Ok(Page::new(items, query.page(), query.per_page(), total))
}

pub async fn stats(state: &AppState) -> ApiResult<AdminStatsResponse> {
    let users: AdminStats = users::stats(&state.pool).await?;
    let since = db::now_ts() - 86_400;
    Ok(AdminStatsResponse {
        users,
        active_sessions: sessions::count_active(&state.pool).await?,
        logins_24h: db::audit::count_action_since(&state.pool, "auth.login", since).await?,
        failed_logins_24h: db::audit::count_action_since(&state.pool, "auth.login_failed", since)
            .await?,
        generated_at: chrono::Utc::now(),
    })
}

/// Prevents locking the platform out by removing its final administrator.
async fn ensure_not_last_admin(
    state: &AppState,
    target: &crate::db::users::UserRow,
    action: &str,
) -> ApiResult<()> {
    if !target.role.is_admin() {
        return Ok(());
    }
    let admins = users::count_with_role(&state.pool, Role::Admin).await?
        + users::count_with_role(&state.pool, Role::Superadmin).await?;
    if admins <= 1 {
        return Err(ApiError::conflict(
            "LAST_ADMIN",
            format!("Cannot {action} the last remaining administrator"),
        ));
    }
    Ok(())
}
