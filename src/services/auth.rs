//! Registration, login, token rotation, password reset and e-mail verification.

use serde_json::json;
use uuid::Uuid;

use crate::{
    db::{
        self,
        audit::NewAudit,
        sessions::{self, NewSession},
        tokens::{self, TokenKind},
        users::{self, NewUser, UserRow, UserStatus},
    },
    dto::*,
    error::{ApiError, ApiResult},
    extract::{ClientInfo, Principal},
    security::{
        hash_password, random_token, sha256_hex, validate_password_policy, verify_password,
    },
    services::{audit, normalize_email, normalize_full_name},
    state::AppState,
};

#[derive(Debug)]
pub struct RegisterOutcome {
    pub user: UserDto,
    pub verification_required: bool,
    pub debug_token: Option<DebugToken>,
}

pub async fn register(
    state: &AppState,
    payload: RegisterRequest,
    client: &ClientInfo,
) -> ApiResult<RegisterOutcome> {
    let email = normalize_email(&payload.email);
    validate_password_policy(
        &payload.password,
        state.config.security.password_min_len,
        state.config.security.password_max_len,
    )?;

    if users::email_taken(&state.pool, &email, None).await? {
        return Err(ApiError::email_taken());
    }

    let user_id = Uuid::new_v4().to_string();
    let password_hash = hash_password(&payload.password)?;
    let full_name = normalize_full_name(payload.full_name.as_deref());
    let email_verified_at = if state.config.security.require_email_verification {
        None
    } else {
        Some(db::now_ts())
    };

    users::insert(
        &state.pool,
        &NewUser {
            id: &user_id,
            email: &email,
            password_hash: &password_hash,
            full_name: full_name.as_deref(),
            role: db::users::Role::User,
            email_verified_at,
        },
    )
    .await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(&user_id),
            actor_email: Some(&email),
            action: "auth.register",
            target_type: Some("user"),
            target_id: Some(&user_id),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: Some(json!({ "email_verified": email_verified_at.is_some() })),
        },
    )
    .await;

    let mut debug_token = None;
    let verification_required = email_verified_at.is_none();
    if verification_required {
        debug_token = send_verification_email(state, &user_id, &email).await?;
    }

    let user = users::find_by_id(&state.pool, &user_id)
        .await?
        .ok_or_else(|| ApiError::internal(anyhow::anyhow!("user vanished after insert")))?;

    Ok(RegisterOutcome {
        user: UserDto::from_parts(&user, false),
        verification_required,
        debug_token,
    })
}

pub async fn login(
    state: &AppState,
    payload: LoginRequest,
    client: &ClientInfo,
) -> ApiResult<LoginResponse> {
    let email = normalize_email(&payload.email);
    let now = db::now_ts();
    let user = users::find_by_email(&state.pool, &email).await?;

    let Some(user) = user else {
        // Equalize timing so an attacker cannot enumerate accounts.
        verify_password(&payload.password, None);
        audit::record(
            state,
            NewAudit {
                actor_email: Some(&email),
                action: "auth.login_failed",
                target_type: Some("user"),
                ip_address: client.ip.as_deref(),
                user_agent: client.user_agent.as_deref(),
                metadata: Some(json!({ "reason": "unknown_email" })),
                ..Default::default()
            },
        )
        .await;
        return Err(ApiError::invalid_credentials());
    };

    if user.status == UserStatus::Deleted {
        audit::record(
            state,
            NewAudit {
                actor_id: Some(&user.id),
                actor_email: Some(&user.email),
                action: "auth.login_failed",
                target_type: Some("user"),
                target_id: Some(&user.id),
                ip_address: client.ip.as_deref(),
                user_agent: client.user_agent.as_deref(),
                metadata: Some(json!({ "reason": "deleted_account" })),
            },
        )
        .await;
        return Err(ApiError::invalid_credentials());
    }

    if user.status == UserStatus::Suspended {
        audit::record(
            state,
            NewAudit {
                actor_id: Some(&user.id),
                actor_email: Some(&user.email),
                action: "auth.login_blocked",
                target_type: Some("user"),
                target_id: Some(&user.id),
                ip_address: client.ip.as_deref(),
                user_agent: client.user_agent.as_deref(),
                metadata: Some(json!({ "reason": "suspended" })),
            },
        )
        .await;
        return Err(ApiError::forbidden(
            "ACCOUNT_SUSPENDED",
            "This account has been suspended. Contact support.",
        ));
    }

    if let Some(until) = user.locked_until.filter(|until| *until > now) {
        let retry_after = (until - now) as u64;
        return Err(ApiError::locked(
            format!("Too many failed attempts. Try again in {retry_after} seconds."),
            Some(retry_after),
        ));
    }

    if !verify_password(&payload.password, Some(&user.password_hash)) {
        let attempts = users::record_login_failure(&state.pool, &user.id).await?;
        let max_attempts = state.config.security.max_login_attempts;
        let lockout_seconds = state.config.security.lockout.as_secs();

        if attempts >= max_attempts {
            users::lock_until(&state.pool, &user.id, now + lockout_seconds as i64).await?;
            audit::record(
                state,
                NewAudit {
                    actor_id: Some(&user.id),
                    actor_email: Some(&user.email),
                    action: "auth.account_locked",
                    target_type: Some("user"),
                    target_id: Some(&user.id),
                    ip_address: client.ip.as_deref(),
                    user_agent: client.user_agent.as_deref(),
                    metadata: Some(
                        json!({ "attempts": attempts, "lockout_seconds": lockout_seconds }),
                    ),
                },
            )
            .await;
            return Err(ApiError::locked(
                "Too many failed attempts; the account is temporarily locked",
                Some(lockout_seconds),
            ));
        }

        audit::record(
            state,
            NewAudit {
                actor_id: Some(&user.id),
                actor_email: Some(&user.email),
                action: "auth.login_failed",
                target_type: Some("user"),
                target_id: Some(&user.id),
                ip_address: client.ip.as_deref(),
                user_agent: client.user_agent.as_deref(),
                metadata: Some(json!({ "reason": "wrong_password", "attempts": attempts })),
            },
        )
        .await;
        return Err(ApiError::invalid_credentials());
    }

    if state.config.security.require_email_verification && !user.is_email_verified() {
        audit::record(
            state,
            NewAudit {
                actor_id: Some(&user.id),
                actor_email: Some(&user.email),
                action: "auth.login_blocked",
                target_type: Some("user"),
                target_id: Some(&user.id),
                ip_address: client.ip.as_deref(),
                user_agent: client.user_agent.as_deref(),
                metadata: Some(json!({ "reason": "email_not_verified" })),
            },
        )
        .await;
        return Err(ApiError::forbidden(
            "EMAIL_NOT_VERIFIED",
            "Please verify your e-mail address before signing in",
        ));
    }

    let two_factor_enabled = db::two_factor::is_enabled(&state.pool, &user.id).await?;
    if two_factor_enabled {
        let (mfa_token, expires_at) = state.jwt.issue_mfa_challenge(&user)?;
        audit::record(
            state,
            NewAudit {
                actor_id: Some(&user.id),
                actor_email: Some(&user.email),
                action: "auth.mfa_challenge",
                target_type: Some("user"),
                target_id: Some(&user.id),
                ip_address: client.ip.as_deref(),
                user_agent: client.user_agent.as_deref(),
                metadata: None,
            },
        )
        .await;
        return Ok(LoginResponse::mfa_required(mfa_token, expires_at - now));
    }

    finish_login(state, &user, client, false).await
}

/// Completes a login that stopped at the second factor.
pub async fn verify_mfa(
    state: &AppState,
    payload: MfaVerifyRequest,
    client: &ClientInfo,
) -> ApiResult<AuthResponse> {
    let claims = state.jwt.decode_mfa(&payload.mfa_token)?;
    let user = users::find_by_id(&state.pool, &claims.sub)
        .await?
        .ok_or_else(|| ApiError::unauthenticated("The account no longer exists"))?;

    if !user.is_active() {
        return Err(ApiError::forbidden(
            "ACCOUNT_SUSPENDED",
            "This account cannot sign in",
        ));
    }

    let settings = db::two_factor::get(&state.pool, &user.id)
        .await?
        .filter(|settings| settings.is_enabled())
        .ok_or_else(|| {
            ApiError::bad_request(
                "TWO_FACTOR_NOT_ENABLED",
                "Two-factor authentication is not enabled for this account",
            )
        })?;

    let valid = if payload.use_recovery_code {
        let normalized = crate::security::tokens::normalize_recovery_code(&payload.code);
        let hash = sha256_hex(&normalized);
        db::two_factor::consume_recovery_code(&state.pool, &user.id, &hash).await?
    } else {
        crate::security::totp::verify(
            &settings.secret,
            &payload.code,
            &state.config.app_name,
            &user.email,
        )?
    };

    if !valid {
        audit::record(
            state,
            NewAudit {
                actor_id: Some(&user.id),
                actor_email: Some(&user.email),
                action: "auth.mfa_failed",
                target_type: Some("user"),
                target_id: Some(&user.id),
                ip_address: client.ip.as_deref(),
                user_agent: client.user_agent.as_deref(),
                metadata: Some(json!({ "recovery_code": payload.use_recovery_code })),
            },
        )
        .await;
        return Err(ApiError::unauthorized(
            "INVALID_MFA_CODE",
            "The verification code is incorrect or has expired",
        ));
    }

    let response = finish_login(state, &user, client, true).await?;
    match response {
        LoginResponse {
            user: Some(user),
            tokens: Some(tokens),
            ..
        } => Ok(AuthResponse { user, tokens }),
        _ => Err(ApiError::internal(anyhow::anyhow!(
            "unexpected login response while completing MFA"
        ))),
    }
}

async fn finish_login(
    state: &AppState,
    user: &UserRow,
    client: &ClientInfo,
    two_factor_enabled: bool,
) -> ApiResult<LoginResponse> {
    users::record_login_success(&state.pool, &user.id).await?;
    let tokens = issue_token_pair(state, user, client, None).await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(&user.id),
            actor_email: Some(&user.email),
            action: "auth.login",
            target_type: Some("session"),
            target_id: Some(&tokens.session_id),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: Some(json!({ "two_factor": two_factor_enabled })),
        },
    )
    .await;

    let refreshed = users::find_by_id(&state.pool, &user.id)
        .await?
        .unwrap_or_else(|| user.clone());

    Ok(LoginResponse::complete(
        UserDto::from_parts(&refreshed, two_factor_enabled),
        tokens,
    ))
}

/// Creates a session row plus a matching access token.
pub async fn issue_token_pair(
    state: &AppState,
    user: &UserRow,
    client: &ClientInfo,
    family_id: Option<&str>,
) -> ApiResult<TokenPair> {
    let session_id = Uuid::new_v4().to_string();
    let family = family_id
        .map(|value| value.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let refresh_token = random_token();
    let refresh_hash = sha256_hex(&refresh_token);
    let refresh_ttl = state.config.jwt.refresh_ttl.as_secs() as i64;
    let expires_at = db::now_ts() + refresh_ttl;

    sessions::insert(
        &state.pool,
        &NewSession {
            id: &session_id,
            user_id: &user.id,
            family_id: &family,
            refresh_token_hash: &refresh_hash,
            user_agent: client.user_agent.as_deref(),
            ip_address: client.ip.as_deref(),
            expires_at,
        },
    )
    .await?;

    let (access_token, access_expires_at) =
        state.jwt.issue_access(&user.id, user.role, &session_id)?;

    Ok(TokenPair {
        access_token,
        refresh_token,
        token_type: TokenPair::bearer_type(),
        expires_in: access_expires_at - db::now_ts(),
        refresh_expires_in: refresh_ttl,
        session_id,
    })
}

/// Rotates a refresh token. Reuse of an already-rotated token revokes the whole
/// family (RFC 6819 §5.2.2.3 style detection).
pub async fn refresh(
    state: &AppState,
    payload: RefreshRequest,
    client: &ClientInfo,
) -> ApiResult<TokenPair> {
    let raw = payload
        .refresh_token
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| {
            ApiError::bad_request("REFRESH_TOKEN_REQUIRED", "refresh_token is required")
        })?;

    let hash = sha256_hex(raw.trim());
    let session = sessions::find_by_hash(&state.pool, &hash)
        .await?
        .ok_or_else(|| ApiError::unauthenticated("Refresh token is invalid"))?;

    let now = db::now_ts();

    if session.revoked_at.is_some() {
        sessions::revoke_family(&state.pool, &session.family_id, "refresh_reuse_detected").await?;
        audit::record(
            state,
            NewAudit {
                actor_id: Some(&session.user_id),
                action: "auth.refresh_reuse_detected",
                target_type: Some("session"),
                target_id: Some(&session.id),
                ip_address: client.ip.as_deref(),
                user_agent: client.user_agent.as_deref(),
                metadata: Some(json!({ "family_id": session.family_id })),
                ..Default::default()
            },
        )
        .await;
        return Err(ApiError::unauthenticated(
            "Refresh token has already been used; all sessions in this family were revoked",
        ));
    }

    if session.expires_at <= now {
        sessions::revoke(&state.pool, &session.id, "expired", None).await?;
        return Err(ApiError::unauthenticated("Refresh token has expired"));
    }

    let user = users::find_by_id(&state.pool, &session.user_id)
        .await?
        .ok_or_else(|| ApiError::unauthenticated("The account no longer exists"))?;

    if !user.is_active() {
        sessions::revoke_all_for_user(&state.pool, &user.id, "account_inactive", None).await?;
        return Err(ApiError::forbidden(
            "ACCOUNT_SUSPENDED",
            "This account cannot refresh tokens",
        ));
    }

    let tokens = issue_token_pair(state, &user, client, Some(&session.family_id)).await?;
    sessions::revoke(
        &state.pool,
        &session.id,
        "rotated",
        Some(&tokens.session_id),
    )
    .await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(&user.id),
            actor_email: Some(&user.email),
            action: "auth.refresh",
            target_type: Some("session"),
            target_id: Some(&tokens.session_id),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: Some(json!({ "previous_session": session.id })),
        },
    )
    .await;

    Ok(tokens)
}

pub async fn logout(
    state: &AppState,
    principal: &Principal,
    payload: LogoutRequest,
    client: &ClientInfo,
) -> ApiResult<u64> {
    let revoked = if payload.all_sessions {
        sessions::revoke_all_for_user(&state.pool, principal.id(), "logout_all", None).await?
    } else {
        sessions::revoke(&state.pool, &principal.session_id, "logout", None).await?;
        if let Some(token) = payload.refresh_token.as_deref().map(str::trim) {
            if !token.is_empty() {
                if let Some(session) =
                    sessions::find_by_hash(&state.pool, &sha256_hex(token)).await?
                {
                    if session.user_id == principal.id() {
                        sessions::revoke(&state.pool, &session.id, "logout", None).await?;
                    }
                }
            }
        }
        1
    };

    audit::record(
        state,
        NewAudit {
            actor_id: Some(principal.id()),
            actor_email: Some(&principal.user.email),
            action: if payload.all_sessions {
                "auth.logout_all"
            } else {
                "auth.logout"
            },
            target_type: Some("session"),
            target_id: Some(&principal.session_id),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: Some(json!({ "revoked": revoked })),
        },
    )
    .await;

    Ok(revoked)
}

pub async fn forgot_password(
    state: &AppState,
    email: &str,
    client: &ClientInfo,
) -> ApiResult<Option<DebugToken>> {
    let email = normalize_email(email);
    let Some(user) = users::find_by_email(&state.pool, &email).await? else {
        // Same shape and status as the success path: no account enumeration.
        return Ok(None);
    };

    if !user.is_active() {
        return Ok(None);
    }

    let raw = random_token();
    let hash = sha256_hex(&raw);
    let ttl = state.config.email.reset_ttl.as_secs() as i64;
    tokens::invalidate(&state.pool, &user.id, TokenKind::PasswordReset).await?;
    tokens::insert(
        &state.pool,
        &Uuid::new_v4().to_string(),
        &user.id,
        TokenKind::PasswordReset,
        &hash,
        db::now_ts() + ttl,
    )
    .await?;

    let debug_token = state
        .emails
        .send_password_reset_email(&user.email, &raw, ttl)?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(&user.id),
            actor_email: Some(&user.email),
            action: "auth.password_reset_requested",
            target_type: Some("user"),
            target_id: Some(&user.id),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: None,
        },
    )
    .await;

    Ok(debug_token)
}

pub async fn reset_password(
    state: &AppState,
    payload: ResetPasswordRequest,
    client: &ClientInfo,
) -> ApiResult<()> {
    validate_password_policy(
        &payload.new_password,
        state.config.security.password_min_len,
        state.config.security.password_max_len,
    )?;

    let hash = sha256_hex(payload.token.trim());
    let Some(token) = tokens::consume(&state.pool, TokenKind::PasswordReset, &hash).await? else {
        return Err(ApiError::bad_request(
            "INVALID_TOKEN",
            "This password reset link is invalid, expired or already used",
        ));
    };

    let user = users::find_by_id(&state.pool, &token.user_id)
        .await?
        .ok_or_else(|| ApiError::bad_request("INVALID_TOKEN", "The account no longer exists"))?;

    if !user.is_active() {
        return Err(ApiError::forbidden(
            "ACCOUNT_SUSPENDED",
            "This account cannot reset its password",
        ));
    }

    let password_hash = hash_password(&payload.new_password)?;
    users::update_password(&state.pool, &user.id, &password_hash).await?;
    users::clear_lockout(&state.pool, &user.id).await?;
    sessions::revoke_all_for_user(&state.pool, &user.id, "password_reset", None).await?;

    let _ = state.emails.send_password_changed_email(&user.email);

    audit::record(
        state,
        NewAudit {
            actor_id: Some(&user.id),
            actor_email: Some(&user.email),
            action: "auth.password_reset",
            target_type: Some("user"),
            target_id: Some(&user.id),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: None,
        },
    )
    .await;

    Ok(())
}

pub async fn verify_email(
    state: &AppState,
    payload: VerifyEmailRequest,
    client: &ClientInfo,
) -> ApiResult<()> {
    let hash = sha256_hex(payload.token.trim());
    let Some(token) = tokens::consume(&state.pool, TokenKind::EmailVerification, &hash).await?
    else {
        return Err(ApiError::bad_request(
            "INVALID_TOKEN",
            "This verification link is invalid, expired or already used",
        ));
    };

    users::mark_email_verified(&state.pool, &token.user_id).await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(&token.user_id),
            action: "auth.email_verified",
            target_type: Some("user"),
            target_id: Some(&token.user_id),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: None,
            ..Default::default()
        },
    )
    .await;

    Ok(())
}

pub async fn resend_verification(
    state: &AppState,
    email: &str,
    client: &ClientInfo,
) -> ApiResult<Option<DebugToken>> {
    let email = normalize_email(email);
    let Some(user) = users::find_by_email(&state.pool, &email).await? else {
        return Ok(None);
    };
    if user.is_email_verified() || !user.is_active() {
        return Ok(None);
    }

    audit::record(
        state,
        NewAudit {
            actor_id: Some(&user.id),
            actor_email: Some(&user.email),
            action: "auth.verification_resent",
            target_type: Some("user"),
            target_id: Some(&user.id),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: None,
        },
    )
    .await;

    send_verification_email(state, &user.id, &user.email).await
}

async fn send_verification_email(
    state: &AppState,
    user_id: &str,
    email: &str,
) -> ApiResult<Option<DebugToken>> {
    let raw = random_token();
    let hash = sha256_hex(&raw);
    let ttl = state.config.email.verify_ttl.as_secs() as i64;
    tokens::invalidate(&state.pool, user_id, TokenKind::EmailVerification).await?;
    tokens::insert(
        &state.pool,
        &Uuid::new_v4().to_string(),
        user_id,
        TokenKind::EmailVerification,
        &hash,
        db::now_ts() + ttl,
    )
    .await?;

    state.emails.send_verification_email(email, &raw, ttl)
}
