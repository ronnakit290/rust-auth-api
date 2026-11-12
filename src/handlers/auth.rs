//! `/api/v1/auth/*` — the public authentication surface.

use axum::{extract::State, http::StatusCode, response::IntoResponse};
use validator::Validate;

use crate::{
    dto::*,
    error::{ApiResult, ErrorResponse},
    extract::{ApiJson, AuthUser, ClientInfo},
    response::{message, ok},
    services::auth as auth_service,
    state::AppState,
};

#[utoipa::path(
    post,
    path = "/api/v1/auth/register",
    tag = "auth",
    summary = "Create an account",
    description = "Registers a user, applies the password policy and (when REQUIRE_EMAIL_VERIFICATION is on) sends a verification e-mail. The response envelope is `{ success, data }`.",
    request_body = RegisterRequest,
    responses(
        (status = 201, body = RegisterResponse, description = "Account created"),
        (status = 409, body = ErrorResponse, description = "E-mail already registered"),
        (status = 422, body = ErrorResponse, description = "Validation failed"),
        (status = 429, body = ErrorResponse, description = "Rate limited")
    )
)]
pub async fn register(
    State(state): State<AppState>,
    client: ClientInfo,
    ApiJson(payload): ApiJson<RegisterRequest>,
) -> ApiResult<impl IntoResponse> {
    payload.validate()?;
    state.enforce_rate(
        "register",
        &client.rate_key(),
        state.config.security.register_rate_limit,
        state.config.security.register_rate_window,
    )?;

    let outcome = auth_service::register(&state, payload, &client).await?;
    Ok((
        StatusCode::CREATED,
        ok(RegisterResponse {
            user: outcome.user,
            verification_required: outcome.verification_required,
            debug_token: outcome.debug_token,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "auth",
    summary = "Sign in with e-mail and password",
    description = "Returns a token pair, or `{ mfa_required: true, mfa_token }` when the account has TOTP enabled.",
    request_body = LoginRequest,
    responses(
        (status = 200, body = LoginResponse),
        (status = 401, body = ErrorResponse, description = "Invalid credentials"),
        (status = 403, body = ErrorResponse, description = "Account suspended / e-mail not verified"),
        (status = 423, body = ErrorResponse, description = "Account locked"),
        (status = 429, body = ErrorResponse)
    )
)]
pub async fn login(
    State(state): State<AppState>,
    client: ClientInfo,
    ApiJson(payload): ApiJson<LoginRequest>,
) -> ApiResult<impl IntoResponse> {
    payload.validate()?;
    state.enforce_rate(
        "login",
        &client.rate_key(),
        state.config.security.login_rate_limit,
        state.config.security.login_rate_window,
    )?;

    let response = auth_service::login(&state, payload, &client).await?;
    Ok((StatusCode::OK, ok(response)))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/2fa/verify",
    tag = "auth",
    summary = "Complete a two-factor login",
    description = "Exchanges a short lived `mfa_token` plus a TOTP (or recovery) code for a token pair.",
    request_body = MfaVerifyRequest,
    responses(
        (status = 200, body = AuthResponse),
        (status = 401, body = ErrorResponse),
        (status = 429, body = ErrorResponse)
    )
)]
pub async fn verify_mfa(
    State(state): State<AppState>,
    client: ClientInfo,
    ApiJson(payload): ApiJson<MfaVerifyRequest>,
) -> ApiResult<impl IntoResponse> {
    payload.validate()?;
    state.enforce_rate(
        "mfa",
        &client.rate_key(),
        state.config.security.login_rate_limit,
        state.config.security.login_rate_window,
    )?;

    let response = auth_service::verify_mfa(&state, payload, &client).await?;
    Ok((StatusCode::OK, ok(response)))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/refresh",
    tag = "auth",
    summary = "Rotate a refresh token",
    description = "Single-use rotation. Replaying an already rotated token revokes the whole token family.",
    request_body = RefreshRequest,
    responses(
        (status = 200, body = TokenPair),
        (status = 401, body = ErrorResponse)
    )
)]
pub async fn refresh(
    State(state): State<AppState>,
    client: ClientInfo,
    ApiJson(payload): ApiJson<RefreshRequest>,
) -> ApiResult<impl IntoResponse> {
    state.enforce_rate(
        "refresh",
        &client.rate_key(),
        state.config.security.login_rate_limit * 6,
        state.config.security.login_rate_window,
    )?;

    let tokens = auth_service::refresh(&state, payload, &client).await?;
    Ok((StatusCode::OK, ok(tokens)))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "auth",
    summary = "Sign out",
    description = "Revokes the current session, or every session when `all_sessions` is true.",
    request_body = LogoutRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = LogoutResponse),
        (status = 401, body = ErrorResponse)
    )
)]
pub async fn logout(
    State(state): State<AppState>,
    auth: AuthUser,
    client: ClientInfo,
    body: Option<ApiJson<LogoutRequest>>,
) -> ApiResult<impl IntoResponse> {
    let payload = body.map(|ApiJson(body)| body).unwrap_or(LogoutRequest {
        refresh_token: None,
        all_sessions: false,
    });
    let all_sessions = payload.all_sessions;
    let revoked = auth_service::logout(&state, &auth.0, payload, &client).await?;

    Ok((
        StatusCode::OK,
        ok(LogoutResponse {
            revoked_sessions: revoked,
            message: if all_sessions {
                "Signed out of every session".to_string()
            } else {
                "Signed out".to_string()
            },
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/forgot-password",
    tag = "auth",
    summary = "Request a password reset link",
    description = "Always returns 200 so that accounts cannot be enumerated. When EMAIL_MODE=console the generated token is echoed in `debug_token`.",
    request_body = ForgotPasswordRequest,
    responses(
        (status = 200, body = ForgotPasswordResponse),
        (status = 429, body = ErrorResponse)
    )
)]
pub async fn forgot_password(
    State(state): State<AppState>,
    client: ClientInfo,
    ApiJson(payload): ApiJson<ForgotPasswordRequest>,
) -> ApiResult<impl IntoResponse> {
    payload.validate()?;
    let key = format!(
        "{}:{}",
        client.rate_key(),
        payload.email.to_ascii_lowercase()
    );
    state.enforce_rate(
        "forgot_password",
        &key,
        state.config.security.reset_rate_limit,
        state.config.security.reset_rate_window,
    )?;

    let debug_token = auth_service::forgot_password(&state, &payload.email, &client).await?;
    Ok((
        StatusCode::OK,
        ok(ForgotPasswordResponse {
            message: "If an account exists for that e-mail, a reset link has been sent."
                .to_string(),
            debug_token,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/reset-password",
    tag = "auth",
    summary = "Consume a reset token and set a new password",
    description = "Burns the token, revokes every session and clears any login lockout.",
    request_body = ResetPasswordRequest,
    responses(
        (status = 200, body = MessageResponse),
        (status = 400, body = ErrorResponse, description = "Invalid or expired token"),
        (status = 422, body = ErrorResponse)
    )
)]
pub async fn reset_password(
    State(state): State<AppState>,
    client: ClientInfo,
    ApiJson(payload): ApiJson<ResetPasswordRequest>,
) -> ApiResult<impl IntoResponse> {
    payload.validate()?;
    auth_service::reset_password(&state, payload, &client).await?;
    Ok((
        StatusCode::OK,
        ok(message(
            "Password updated. Please sign in with the new password.",
        )),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/verify-email",
    tag = "auth",
    summary = "Verify an e-mail address",
    request_body = VerifyEmailRequest,
    responses(
        (status = 200, body = MessageResponse),
        (status = 400, body = ErrorResponse)
    )
)]
pub async fn verify_email(
    State(state): State<AppState>,
    client: ClientInfo,
    ApiJson(payload): ApiJson<VerifyEmailRequest>,
) -> ApiResult<impl IntoResponse> {
    payload.validate()?;
    auth_service::verify_email(&state, payload, &client).await?;
    Ok((StatusCode::OK, ok(message("E-mail address verified"))))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/resend-verification",
    tag = "auth",
    summary = "Resend the verification e-mail",
    request_body = ResendVerificationRequest,
    responses(
        (status = 200, body = ForgotPasswordResponse),
        (status = 429, body = ErrorResponse)
    )
)]
pub async fn resend_verification(
    State(state): State<AppState>,
    client: ClientInfo,
    ApiJson(payload): ApiJson<ResendVerificationRequest>,
) -> ApiResult<impl IntoResponse> {
    payload.validate()?;
    let key = format!(
        "{}:{}",
        client.rate_key(),
        payload.email.to_ascii_lowercase()
    );
    state.enforce_rate(
        "resend_verification",
        &key,
        state.config.security.reset_rate_limit,
        state.config.security.reset_rate_window,
    )?;

    let debug_token = auth_service::resend_verification(&state, &payload.email, &client).await?;
    Ok((
        StatusCode::OK,
        ok(ForgotPasswordResponse {
            message: "If the address needs verification, a new link has been sent.".to_string(),
            debug_token,
        }),
    ))
}
