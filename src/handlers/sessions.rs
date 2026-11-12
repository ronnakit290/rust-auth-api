//! `/api/v1/users/me/sessions` — inspect and revoke active sessions.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::{
    dto::*,
    error::{ApiResult, ErrorResponse},
    extract::{AuthUser, ClientInfo},
    response::{message, ok},
    services::users as user_service,
    state::AppState,
};

#[utoipa::path(
    get,
    path = "/api/v1/users/me/sessions",
    tag = "sessions",
    summary = "List active sessions",
    security(("bearer_auth" = [])),
    responses((status = 200, body = SessionsResponse), (status = 401, body = ErrorResponse))
)]
pub async fn list(State(state): State<AppState>, auth: AuthUser) -> ApiResult<impl IntoResponse> {
    let sessions = user_service::list_sessions(&state, &auth.0).await?;
    Ok(ok(sessions))
}

#[utoipa::path(
    delete,
    path = "/api/v1/users/me/sessions/{session_id}",
    tag = "sessions",
    summary = "Revoke one session",
    params(("session_id" = String, Path, description = "Session id")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = MessageResponse),
        (status = 404, body = ErrorResponse)
    )
)]
pub async fn revoke(
    State(state): State<AppState>,
    auth: AuthUser,
    client: ClientInfo,
    Path(session_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    user_service::revoke_session(&state, &auth.0, &session_id, &client).await?;
    Ok((StatusCode::OK, ok(message("Session revoked"))))
}

#[utoipa::path(
    delete,
    path = "/api/v1/users/me/sessions",
    tag = "sessions",
    summary = "Revoke every other session",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = RevokedSessionsResponse),
        (status = 401, body = ErrorResponse)
    )
)]
pub async fn revoke_all(
    State(state): State<AppState>,
    auth: AuthUser,
    client: ClientInfo,
) -> ApiResult<impl IntoResponse> {
    let revoked = user_service::revoke_all_sessions(&state, &auth.0, &client).await?;
    Ok((
        StatusCode::OK,
        ok(RevokedSessionsResponse {
            revoked,
            message: "All other sessions were revoked".to_string(),
        }),
    ))
}
