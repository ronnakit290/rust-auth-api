//! `/api/v1/users/me` — self-service profile operations.

use axum::{extract::State, http::StatusCode, response::IntoResponse};
use validator::Validate;

use crate::{
    dto::*,
    error::{ApiResult, ErrorResponse},
    extract::{ApiJson, AuthUser, ClientInfo},
    response::{message, ok},
    services::users as user_service,
    state::AppState,
};

#[utoipa::path(
    get,
    path = "/api/v1/users/me",
    tag = "users",
    summary = "Current user profile",
    security(("bearer_auth" = [])),
    responses((status = 200, body = UserDto), (status = 401, body = ErrorResponse))
)]
pub async fn me(State(state): State<AppState>, auth: AuthUser) -> ApiResult<impl IntoResponse> {
    let user = user_service::get_me(&state, &auth.0).await?;
    Ok(ok(user))
}

#[utoipa::path(
    patch,
    path = "/api/v1/users/me",
    tag = "users",
    summary = "Update display name or e-mail",
    description = "Changing the e-mail resets verification and sends a new link.",
    request_body = UpdateProfileRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = UpdateProfileResponse),
        (status = 401, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    )
)]
pub async fn update_me(
    State(state): State<AppState>,
    auth: AuthUser,
    client: ClientInfo,
    ApiJson(payload): ApiJson<UpdateProfileRequest>,
) -> ApiResult<impl IntoResponse> {
    payload.validate()?;
    let response = user_service::update_me(&state, &auth.0, payload, &client).await?;
    Ok(ok(response))
}

#[utoipa::path(
    post,
    path = "/api/v1/users/me/change-password",
    tag = "users",
    summary = "Change the password",
    description = "Requires the current password and revokes every other session.",
    request_body = ChangePasswordRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = MessageResponse),
        (status = 401, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    )
)]
pub async fn change_password(
    State(state): State<AppState>,
    auth: AuthUser,
    client: ClientInfo,
    ApiJson(payload): ApiJson<ChangePasswordRequest>,
) -> ApiResult<impl IntoResponse> {
    payload.validate()?;
    user_service::change_password(&state, &auth.0, payload, &client).await?;
    Ok((
        StatusCode::OK,
        ok(message("Password changed; other sessions were signed out")),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/users/me/deactivate",
    tag = "users",
    summary = "Close the account",
    description = "Soft-deletes the account (status=deleted) and revokes all sessions. Requires the password in the body.",
    request_body = DeleteAccountRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "Account closed"),
        (status = 401, body = ErrorResponse)
    )
)]
pub async fn delete_me(
    State(state): State<AppState>,
    auth: AuthUser,
    client: ClientInfo,
    ApiJson(payload): ApiJson<DeleteAccountRequest>,
) -> ApiResult<impl IntoResponse> {
    payload.validate()?;
    user_service::delete_me(&state, &auth.0, payload, &client).await?;
    Ok(StatusCode::NO_CONTENT)
}
