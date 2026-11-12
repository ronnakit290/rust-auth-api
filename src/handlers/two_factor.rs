//! `/api/v1/2fa` — TOTP enrolment and recovery codes.

use axum::{extract::State, http::StatusCode, response::IntoResponse};
use validator::Validate;

use crate::{
    dto::*,
    error::{ApiResult, ErrorResponse},
    extract::{ApiJson, AuthUser, ClientInfo},
    response::{message, ok},
    services::two_factor as two_factor_service,
    state::AppState,
};

#[utoipa::path(
    get,
    path = "/api/v1/2fa",
    tag = "2fa",
    summary = "Two-factor status",
    security(("bearer_auth" = [])),
    responses((status = 200, body = TwoFactorStatusResponse), (status = 401, body = ErrorResponse))
)]
pub async fn status(State(state): State<AppState>, auth: AuthUser) -> ApiResult<impl IntoResponse> {
    let status = two_factor_service::status(&state, &auth.0).await?;
    Ok(ok(status))
}

#[utoipa::path(
    post,
    path = "/api/v1/2fa/setup",
    tag = "2fa",
    summary = "Generate a TOTP secret",
    description = "Returns the base32 secret and otpauth:// URI. Nothing is enabled until /2fa/enable succeeds.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = TwoFactorSetupResponse),
        (status = 409, body = ErrorResponse, description = "Already enabled")
    )
)]
pub async fn setup(State(state): State<AppState>, auth: AuthUser) -> ApiResult<impl IntoResponse> {
    let setup = two_factor_service::setup(&state, &auth.0).await?;
    Ok(ok(setup))
}

#[utoipa::path(
    post,
    path = "/api/v1/2fa/enable",
    tag = "2fa",
    summary = "Confirm the first TOTP code and enable 2FA",
    request_body = EnableTwoFactorRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = EnableTwoFactorResponse),
        (status = 401, body = ErrorResponse),
        (status = 409, body = ErrorResponse)
    )
)]
pub async fn enable(
    State(state): State<AppState>,
    auth: AuthUser,
    client: ClientInfo,
    ApiJson(payload): ApiJson<EnableTwoFactorRequest>,
) -> ApiResult<impl IntoResponse> {
    payload.validate()?;
    let response = two_factor_service::enable(&state, &auth.0, payload, &client).await?;
    Ok((StatusCode::OK, ok(response)))
}

#[utoipa::path(
    post,
    path = "/api/v1/2fa/disable",
    tag = "2fa",
    summary = "Disable 2FA",
    description = "Requires the account password plus a valid TOTP or recovery code.",
    request_body = DisableTwoFactorRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = MessageResponse),
        (status = 401, body = ErrorResponse)
    )
)]
pub async fn disable(
    State(state): State<AppState>,
    auth: AuthUser,
    client: ClientInfo,
    ApiJson(payload): ApiJson<DisableTwoFactorRequest>,
) -> ApiResult<impl IntoResponse> {
    payload.validate()?;
    two_factor_service::disable(&state, &auth.0, payload, &client).await?;
    Ok((
        StatusCode::OK,
        ok(message("Two-factor authentication disabled")),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/2fa/recovery-codes",
    tag = "2fa",
    summary = "Regenerate recovery codes",
    description = "Invalidates all previous recovery codes and returns ten new ones.",
    request_body = RegenerateRecoveryCodesRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = RecoveryCodesResponse),
        (status = 401, body = ErrorResponse)
    )
)]
pub async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    auth: AuthUser,
    client: ClientInfo,
    ApiJson(payload): ApiJson<RegenerateRecoveryCodesRequest>,
) -> ApiResult<impl IntoResponse> {
    payload.validate()?;
    let response =
        two_factor_service::regenerate_recovery_codes(&state, &auth.0, payload, &client).await?;
    Ok((StatusCode::OK, ok(response)))
}
