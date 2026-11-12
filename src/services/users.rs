//! Self-service account operations for the authenticated user.

use serde_json::json;

use crate::{
    db::{
        self,
        audit::NewAudit,
        sessions,
        users::{self, UserStatus},
    },
    dto::*,
    error::{ApiError, ApiResult},
    extract::{ClientInfo, Principal},
    security::{hash_password, validate_password_policy, verify_password},
    services::{audit, normalize_email, normalize_full_name},
    state::AppState,
};

pub async fn get_me(state: &AppState, principal: &Principal) -> ApiResult<UserDto> {
    let two_factor = db::two_factor::is_enabled(&state.pool, principal.id()).await?;
    Ok(UserDto::from_parts(&principal.user, two_factor))
}

pub async fn update_me(
    state: &AppState,
    principal: &Principal,
    payload: UpdateProfileRequest,
    client: &ClientInfo,
) -> ApiResult<UpdateProfileResponse> {
    let mut email_changed = false;
    let mut debug_token = None;

    if let Some(raw_email) = payload.email.as_deref() {
        let email = normalize_email(raw_email);
        if email != principal.user.email {
            if users::email_taken(&state.pool, &email, Some(principal.id())).await? {
                return Err(ApiError::email_taken());
            }
            users::update_email(&state.pool, principal.id(), &email).await?;
            email_changed = true;
        }
    }

    if let Some(full_name) = payload.full_name.as_deref() {
        let normalized = normalize_full_name(Some(full_name));
        users::update_full_name(&state.pool, principal.id(), normalized.as_deref()).await?;
    }

    if email_changed {
        let user = users::find_by_id(&state.pool, principal.id())
            .await?
            .ok_or_else(|| ApiError::not_found("Account not found"))?;
        debug_token =
            crate::services::auth::resend_verification(state, &user.email, client).await?;
    }

    let user = users::find_by_id(&state.pool, principal.id())
        .await?
        .ok_or_else(|| ApiError::not_found("Account not found"))?;
    let two_factor = db::two_factor::is_enabled(&state.pool, &user.id).await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(&user.id),
            actor_email: Some(&user.email),
            action: "user.profile_updated",
            target_type: Some("user"),
            target_id: Some(&user.id),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: Some(json!({ "email_changed": email_changed })),
        },
    )
    .await;

    let message = if email_changed {
        MessageResponse {
            message: "Profile updated. Please verify your new e-mail address.".to_string(),
        }
    } else {
        MessageResponse {
            message: "Profile updated".to_string(),
        }
    };

    let mut response = UpdateProfileResponse {
        user: UserDto::from_parts(&user, two_factor),
        verification_required: email_changed,
        message,
    };
    // Keep the debug token out of the public shape; handlers surface it only in
    // development via the outbox endpoint.
    if debug_token.is_some() {
        response
            .message
            .message
            .push_str(" Verification e-mail sent.");
    }
    Ok(response)
}

pub async fn change_password(
    state: &AppState,
    principal: &Principal,
    payload: ChangePasswordRequest,
    client: &ClientInfo,
) -> ApiResult<()> {
    if !verify_password(
        &payload.current_password,
        Some(&principal.user.password_hash),
    ) {
        audit::record(
            state,
            NewAudit {
                actor_id: Some(principal.id()),
                actor_email: Some(&principal.user.email),
                action: "user.password_change_failed",
                target_type: Some("user"),
                target_id: Some(principal.id()),
                ip_address: client.ip.as_deref(),
                user_agent: client.user_agent.as_deref(),
                metadata: Some(json!({ "reason": "wrong_current_password" })),
            },
        )
        .await;
        return Err(ApiError::unauthorized(
            "INVALID_CURRENT_PASSWORD",
            "The current password is incorrect",
        ));
    }

    if payload.current_password == payload.new_password {
        return Err(ApiError::field(
            "new_password",
            "must be different from the current password",
        ));
    }

    validate_password_policy(
        &payload.new_password,
        state.config.security.password_min_len,
        state.config.security.password_max_len,
    )?;

    let hash = hash_password(&payload.new_password)?;
    users::update_password(&state.pool, principal.id(), &hash).await?;

    // Changing the password invalidates every other session.
    let revoked = sessions::revoke_all_for_user(
        &state.pool,
        principal.id(),
        "password_changed",
        Some(&principal.session_id),
    )
    .await?;

    let _ = state
        .emails
        .send_password_changed_email(&principal.user.email);

    audit::record(
        state,
        NewAudit {
            actor_id: Some(principal.id()),
            actor_email: Some(&principal.user.email),
            action: "user.password_changed",
            target_type: Some("user"),
            target_id: Some(principal.id()),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: Some(json!({ "revoked_sessions": revoked })),
        },
    )
    .await;

    Ok(())
}

pub async fn delete_me(
    state: &AppState,
    principal: &Principal,
    payload: DeleteAccountRequest,
    client: &ClientInfo,
) -> ApiResult<()> {
    if !verify_password(&payload.password, Some(&principal.user.password_hash)) {
        return Err(ApiError::unauthorized(
            "INVALID_CURRENT_PASSWORD",
            "The password is incorrect",
        ));
    }

    users::set_status(&state.pool, principal.id(), UserStatus::Deleted).await?;
    sessions::revoke_all_for_user(&state.pool, principal.id(), "account_deleted", None).await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(principal.id()),
            actor_email: Some(&principal.user.email),
            action: "user.account_deleted",
            target_type: Some("user"),
            target_id: Some(principal.id()),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: None,
        },
    )
    .await;

    Ok(())
}

pub async fn list_sessions(state: &AppState, principal: &Principal) -> ApiResult<SessionsResponse> {
    let rows = sessions::list_active(&state.pool, principal.id(), 100).await?;
    let sessions: Vec<SessionDto> = rows
        .iter()
        .map(|row| SessionDto::from_row(row, &principal.session_id))
        .collect();
    Ok(SessionsResponse {
        count: sessions.len(),
        sessions,
    })
}

pub async fn revoke_session(
    state: &AppState,
    principal: &Principal,
    session_id: &str,
    client: &ClientInfo,
) -> ApiResult<()> {
    let session = sessions::find_by_id(&state.pool, session_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Session not found"))?;

    if session.user_id != principal.id() {
        // Do not confirm the existence of another user's session.
        return Err(ApiError::not_found("Session not found"));
    }

    sessions::revoke(&state.pool, &session.id, "revoked_by_user", None).await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(principal.id()),
            actor_email: Some(&principal.user.email),
            action: "user.session_revoked",
            target_type: Some("session"),
            target_id: Some(&session.id),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: None,
        },
    )
    .await;

    Ok(())
}

pub async fn revoke_all_sessions(
    state: &AppState,
    principal: &Principal,
    client: &ClientInfo,
) -> ApiResult<u64> {
    let revoked = sessions::revoke_all_for_user(
        &state.pool,
        principal.id(),
        "revoked_by_user_all",
        Some(&principal.session_id),
    )
    .await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(principal.id()),
            actor_email: Some(&principal.user.email),
            action: "user.sessions_revoked_all",
            target_type: Some("user"),
            target_id: Some(principal.id()),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: Some(json!({ "revoked": revoked })),
        },
    )
    .await;

    Ok(revoked)
}
