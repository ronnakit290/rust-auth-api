//! `/api/v1/admin/clients*` — register applications and mint their app keys.
//!
//! This is the "SSO console" API: an administrator registers each system that
//! will consume the SSO server, then issues one or more app keys per system.

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
    response::{created, ok},
    services::clients as clients_service,
    state::AppState,
};

// ---------------------------------------------------------------------------
// Applications
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/clients",
    tag = "sso-admin",
    summary = "List registered applications",
    description = "Every system that may obtain tokens from this SSO server.",
    params(
        ("page" = Option<u32>, Query),
        ("per_page" = Option<u32>, Query),
        ("search" = Option<String>, Query, description = "Matches name or client_id"),
        ("status" = Option<String>, Query, description = "active|disabled")
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = Page<ClientDto>),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse)
    )
)]
pub async fn list_clients(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(query): Query<ListClientsQuery>,
) -> ApiResult<impl IntoResponse> {
    Ok(ok(clients_service::list_clients(&state, query).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/clients",
    tag = "sso-admin",
    summary = "Register an application",
    description = "Returns the one-time client secret. `client_type=public` requires at least one redirect URI and forces PKCE.",
    request_body = CreateClientRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 201, body = ClientCreatedResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    )
)]
pub async fn create_client(
    State(state): State<AppState>,
    admin: AdminUser,
    client_info: ClientInfo,
    ApiJson(payload): ApiJson<CreateClientRequest>,
) -> ApiResult<impl IntoResponse> {
    payload.validate()?;
    let response = clients_service::create_client(&state, &admin.0, payload, &client_info).await?;
    Ok(created(response))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/clients/{client_ref}",
    tag = "sso-admin",
    summary = "Fetch one application",
    description = "`client_ref` accepts the internal id or the public `client_id`.",
    params(("client_ref" = String, Path)),
    security(("bearer_auth" = [])),
    responses((status = 200, body = ClientDto), (status = 404, body = ErrorResponse))
)]
pub async fn get_client(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(client_ref): Path<String>,
) -> ApiResult<impl IntoResponse> {
    Ok(ok(clients_service::get_client(&state, &client_ref).await?))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/clients/{client_ref}",
    tag = "sso-admin",
    summary = "Update name, redirect URIs, scopes or status",
    description = "Setting `status=disabled` immediately revokes every app key and refresh token of the application.",
    params(("client_ref" = String, Path)),
    request_body = UpdateClientRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = ClientDto),
        (status = 404, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    )
)]
pub async fn update_client(
    State(state): State<AppState>,
    admin: AdminUser,
    client_info: ClientInfo,
    Path(client_ref): Path<String>,
    ApiJson(payload): ApiJson<UpdateClientRequest>,
) -> ApiResult<impl IntoResponse> {
    payload.validate()?;
    let client =
        clients_service::update_client(&state, &admin.0, &client_ref, payload, &client_info)
            .await?;
    Ok(ok(client))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/clients/{client_ref}",
    tag = "sso-admin",
    summary = "Delete an application",
    description = "Removes the application with its codes, refresh tokens and app keys. Audit history is kept.",
    params(("client_ref" = String, Path)),
    security(("bearer_auth" = [])),
    responses((status = 204), (status = 404, body = ErrorResponse))
)]
pub async fn delete_client(
    State(state): State<AppState>,
    admin: AdminUser,
    client_info: ClientInfo,
    Path(client_ref): Path<String>,
) -> ApiResult<impl IntoResponse> {
    clients_service::delete_client(&state, &admin.0, &client_ref, &client_info).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/clients/{client_ref}/secret/rotate",
    tag = "sso-admin",
    summary = "Rotate the client secret",
    description = "Confidential clients only. The previous secret stops working immediately.",
    params(("client_ref" = String, Path)),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = RotateSecretResponse),
        (status = 409, body = ErrorResponse)
    )
)]
pub async fn rotate_client_secret(
    State(state): State<AppState>,
    admin: AdminUser,
    client_info: ClientInfo,
    Path(client_ref): Path<String>,
) -> ApiResult<impl IntoResponse> {
    Ok(ok(clients_service::rotate_client_secret(
        &state,
        &admin.0,
        &client_ref,
        &client_info,
    )
    .await?))
}

// ---------------------------------------------------------------------------
// App keys
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/clients/{client_ref}/keys",
    tag = "sso-admin",
    summary = "List an application's keys",
    description = "Secrets are never returned here — only the display prefix.",
    params(("client_ref" = String, Path)),
    security(("bearer_auth" = [])),
    responses((status = 200, body = Vec<ApiKeyDto>), (status = 404, body = ErrorResponse))
)]
pub async fn list_keys(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(client_ref): Path<String>,
) -> ApiResult<impl IntoResponse> {
    Ok(ok(
        clients_service::list_api_keys(&state, &client_ref).await?
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/clients/{client_ref}/keys",
    tag = "sso-admin",
    summary = "Issue an app key",
    description = "The secret is returned once. Clients send it as `X-API-Key: <secret>`.",
    params(("client_ref" = String, Path)),
    request_body = CreateApiKeyRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 201, body = ApiKeyCreatedResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    )
)]
pub async fn create_key(
    State(state): State<AppState>,
    admin: AdminUser,
    client_info: ClientInfo,
    Path(client_ref): Path<String>,
    ApiJson(payload): ApiJson<CreateApiKeyRequest>,
) -> ApiResult<impl IntoResponse> {
    payload.validate()?;
    let response =
        clients_service::create_api_key(&state, &admin.0, &client_ref, payload, &client_info)
            .await?;
    Ok(created(response))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/clients/{client_ref}/keys/{key_id}",
    tag = "sso-admin",
    summary = "Revoke an app key",
    params(("client_ref" = String, Path), ("key_id" = String, Path)),
    security(("bearer_auth" = [])),
    responses(
        (status = 204),
        (status = 404, body = ErrorResponse),
        (status = 409, body = ErrorResponse)
    )
)]
pub async fn revoke_key(
    State(state): State<AppState>,
    admin: AdminUser,
    client_info: ClientInfo,
    Path((client_ref, key_id)): Path<(String, String)>,
) -> ApiResult<impl IntoResponse> {
    clients_service::revoke_api_key(&state, &admin.0, &client_ref, &key_id, &client_info).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/clients/{client_ref}/keys/{key_id}/rotate",
    tag = "sso-admin",
    summary = "Rotate an app key",
    description = "Issues a replacement with the same name and scopes, then revokes the old key.",
    params(("client_ref" = String, Path), ("key_id" = String, Path)),
    security(("bearer_auth" = [])),
    responses(
        (status = 201, body = ApiKeyCreatedResponse),
        (status = 404, body = ErrorResponse)
    )
)]
pub async fn rotate_key(
    State(state): State<AppState>,
    admin: AdminUser,
    client_info: ClientInfo,
    Path((client_ref, key_id)): Path<(String, String)>,
) -> ApiResult<impl IntoResponse> {
    let response =
        clients_service::rotate_api_key(&state, &admin.0, &client_ref, &key_id, &client_info)
            .await?;
    Ok(created(response))
}
