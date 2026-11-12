//! Two-factor authentication lifecycle: setup → enable → disable/recovery codes.

use serde_json::json;

use crate::{
    db::{self, audit::NewAudit, two_factor},
    dto::*,
    error::{ApiError, ApiResult},
    extract::{ClientInfo, Principal},
    security::{
        sha256_hex,
        tokens::{normalize_recovery_code, random_recovery_code},
        totp,
    },
    services::audit,
    state::AppState,
};

const RECOVERY_CODE_COUNT: usize = 10;

pub async fn status(state: &AppState, principal: &Principal) -> ApiResult<TwoFactorStatusResponse> {
    let settings = two_factor::get(&state.pool, principal.id()).await?;
    let remaining = two_factor::count_unused_codes(&state.pool, principal.id()).await?;

    Ok(TwoFactorStatusResponse {
        enabled: settings.as_ref().map(|s| s.is_enabled()).unwrap_or(false),
        pending_setup: settings.as_ref().map(|s| !s.is_enabled()).unwrap_or(false),
        confirmed_at: settings
            .and_then(|s| s.confirmed_at)
            .map(db::users::ts_to_datetime),
        recovery_codes_remaining: remaining,
    })
}

pub async fn setup(state: &AppState, principal: &Principal) -> ApiResult<TwoFactorSetupResponse> {
    if two_factor::is_enabled(&state.pool, principal.id()).await? {
        return Err(ApiError::conflict(
            "TWO_FACTOR_ALREADY_ENABLED",
            "Disable two-factor authentication before generating a new secret",
        ));
    }

    let setup = totp::generate(&state.config.app_name, &principal.user.email)?;
    two_factor::upsert_pending(&state.pool, principal.id(), &setup.secret_base32).await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(principal.id()),
            actor_email: Some(&principal.user.email),
            action: "user.2fa_setup_started",
            target_type: Some("user"),
            target_id: Some(principal.id()),
            metadata: None,
            ..Default::default()
        },
    )
    .await;

    Ok(TwoFactorSetupResponse {
        secret: setup.secret_base32,
        otpauth_url: setup.otpauth_url,
        issuer: state.config.app_name.clone(),
        account: principal.user.email.clone(),
        digits: totp::DIGITS,
        step_seconds: totp::STEP_SECONDS,
    })
}

pub async fn enable(
    state: &AppState,
    principal: &Principal,
    payload: EnableTwoFactorRequest,
    client: &ClientInfo,
) -> ApiResult<EnableTwoFactorResponse> {
    let settings = two_factor::get(&state.pool, principal.id())
        .await?
        .ok_or_else(|| {
            ApiError::bad_request(
                "TWO_FACTOR_NOT_SETUP",
                "Call /api/v1/2fa/setup before enabling two-factor authentication",
            )
        })?;

    if settings.is_enabled() {
        return Err(ApiError::conflict(
            "TWO_FACTOR_ALREADY_ENABLED",
            "Two-factor authentication is already enabled",
        ));
    }

    let valid = totp::verify(
        &settings.secret,
        &payload.code,
        &state.config.app_name,
        &principal.user.email,
    )?;
    if !valid {
        return Err(ApiError::unauthorized(
            "INVALID_MFA_CODE",
            "The verification code is incorrect or has expired",
        ));
    }

    two_factor::enable(&state.pool, principal.id()).await?;

    let codes: Vec<String> = (0..RECOVERY_CODE_COUNT)
        .map(|_| random_recovery_code())
        .collect();
    let hashes: Vec<String> = codes
        .iter()
        .map(|code| sha256_hex(&normalize_recovery_code(code)))
        .collect();
    two_factor::replace_recovery_codes(&state.pool, principal.id(), &hashes).await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(principal.id()),
            actor_email: Some(&principal.user.email),
            action: "user.2fa_enabled",
            target_type: Some("user"),
            target_id: Some(principal.id()),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: Some(json!({ "recovery_codes": RECOVERY_CODE_COUNT })),
        },
    )
    .await;

    Ok(EnableTwoFactorResponse {
        enabled: true,
        recovery_codes: codes,
        message: "Two-factor authentication enabled. Store the recovery codes safely — they are shown only once."
            .to_string(),
    })
}

pub async fn disable(
    state: &AppState,
    principal: &Principal,
    payload: DisableTwoFactorRequest,
    client: &ClientInfo,
) -> ApiResult<()> {
    if !crate::security::verify_password(&payload.password, Some(&principal.user.password_hash)) {
        return Err(ApiError::unauthorized(
            "INVALID_CURRENT_PASSWORD",
            "The password is incorrect",
        ));
    }

    let settings = two_factor::get(&state.pool, principal.id())
        .await?
        .filter(|settings| settings.is_enabled())
        .ok_or_else(|| {
            ApiError::bad_request(
                "TWO_FACTOR_NOT_ENABLED",
                "Two-factor authentication is not enabled",
            )
        })?;

    let mut verified = false;

    if let Some(code) = payload
        .code
        .as_deref()
        .filter(|code| !code.trim().is_empty())
    {
        verified = totp::verify(
            &settings.secret,
            code,
            &state.config.app_name,
            &principal.user.email,
        )?;
    }

    if !verified {
        if let Some(recovery) = payload
            .recovery_code
            .as_deref()
            .filter(|code| !code.trim().is_empty())
        {
            let hash = sha256_hex(&normalize_recovery_code(recovery));
            verified =
                two_factor::consume_recovery_code(&state.pool, principal.id(), &hash).await?;
        }
    }

    if !verified {
        return Err(ApiError::unauthorized(
            "INVALID_MFA_CODE",
            "Provide a valid authenticator code or recovery code",
        ));
    }

    two_factor::delete(&state.pool, principal.id()).await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(principal.id()),
            actor_email: Some(&principal.user.email),
            action: "user.2fa_disabled",
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

pub async fn regenerate_recovery_codes(
    state: &AppState,
    principal: &Principal,
    payload: RegenerateRecoveryCodesRequest,
    client: &ClientInfo,
) -> ApiResult<RecoveryCodesResponse> {
    if !crate::security::verify_password(&payload.password, Some(&principal.user.password_hash)) {
        return Err(ApiError::unauthorized(
            "INVALID_CURRENT_PASSWORD",
            "The password is incorrect",
        ));
    }

    if !two_factor::is_enabled(&state.pool, principal.id()).await? {
        return Err(ApiError::bad_request(
            "TWO_FACTOR_NOT_ENABLED",
            "Two-factor authentication is not enabled",
        ));
    }

    let codes: Vec<String> = (0..RECOVERY_CODE_COUNT)
        .map(|_| random_recovery_code())
        .collect();
    let hashes: Vec<String> = codes
        .iter()
        .map(|code| sha256_hex(&normalize_recovery_code(code)))
        .collect();
    two_factor::replace_recovery_codes(&state.pool, principal.id(), &hashes).await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(principal.id()),
            actor_email: Some(&principal.user.email),
            action: "user.2fa_recovery_codes_regenerated",
            target_type: Some("user"),
            target_id: Some(principal.id()),
            ip_address: client.ip.as_deref(),
            user_agent: client.user_agent.as_deref(),
            metadata: Some(json!({ "recovery_codes": RECOVERY_CODE_COUNT })),
        },
    )
    .await;

    Ok(RecoveryCodesResponse {
        recovery_codes: codes,
        message: "New recovery codes generated; previous codes are no longer valid.".to_string(),
    })
}
