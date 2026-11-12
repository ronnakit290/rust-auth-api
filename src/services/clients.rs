//! Administration of SSO applications (OAuth2 clients) and their app keys.
//!
//! Only administrators reach these functions; the handler layer enforces that
//! with the `AdminUser` extractor.

use std::time::Duration;

use crate::{
    db::{
        audit::NewAudit,
        now_ts,
        oauth_clients::{
            self, ApiKeyRow, ClientFilter, ClientRow, ClientStatus, ClientType, NewApiKey,
            NewClient,
        },
    },
    dto::{
        ApiKeyCreatedResponse, ApiKeyDto, ClientCreatedResponse, ClientDto, CreateApiKeyRequest,
        CreateClientRequest, ListClientsQuery, RotateSecretResponse, UpdateClientRequest,
    },
    error::{ApiError, ApiResult},
    extract::{ClientInfo, Principal},
    response::Page,
    security::tokens::{random_hex, random_token, sha256_hex},
    services::{audit, sso},
    state::AppState,
};

/// Scopes any application may be granted. Keeping a closed list stops typos from
/// silently producing tokens that no resource server understands.
pub const KNOWN_SCOPES: &[&str] = &[
    "openid",
    "profile",
    "email",
    "offline_access",
    "users:read",
    "users:write",
    "audit:read",
    "tokens:verify",
];

const MAX_KEYS_PER_CLIENT: i64 = 25;

pub fn is_known_scope(scope: &str) -> bool {
    KNOWN_SCOPES.contains(&scope) || scope.starts_with("read:") || scope.starts_with("write:")
}

pub fn validate_scope_list(scopes: &[String]) -> ApiResult<Vec<String>> {
    let mut cleaned: Vec<String> = Vec::new();
    for raw in scopes {
        let scope = raw.trim();
        if scope.is_empty() {
            continue;
        }
        if !is_known_scope(scope) {
            return Err(ApiError::validation(vec![crate::error::FieldIssue {
                field: "scopes".to_string(),
                message: format!(
                    "unknown scope `{scope}`; supported: {}",
                    KNOWN_SCOPES.join(", ")
                ),
            }]));
        }
        if !cleaned.iter().any(|existing| existing == scope) {
            cleaned.push(scope.to_string());
        }
    }
    if cleaned.is_empty() {
        return Err(ApiError::field("scopes", "at least one scope is required"));
    }
    Ok(cleaned)
}

fn validate_redirect_uris(uris: &[String]) -> ApiResult<Vec<String>> {
    let mut cleaned = Vec::new();
    for raw in uris {
        let uri = raw.trim();
        if uri.is_empty() {
            continue;
        }
        // Native apps legitimately use custom schemes (`myapp://callback`), so
        // accept any well-formed scheme except the executable ones.
        let well_formed = uri
            .split_once("://")
            .map(|(scheme, rest)| {
                !rest.is_empty()
                    && !scheme.is_empty()
                    && scheme
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
                    && !matches!(
                        scheme.to_ascii_lowercase().as_str(),
                        "javascript" | "data" | "file" | "vbscript" | "about"
                    )
            })
            .unwrap_or(false);
        if !well_formed || uri.contains(' ') || uri.contains('#') {
            return Err(ApiError::field(
                "redirect_uris",
                format!("`{uri}` must be an absolute URI (https://… or a custom app scheme) without a fragment"),
            ));
        }
        if !cleaned.iter().any(|existing| existing == uri) {
            cleaned.push(uri.to_string());
        }
    }
    Ok(cleaned)
}

/// Accepts either the internal UUID or the public `client_id`.
pub async fn client_or_404(state: &AppState, reference: &str) -> ApiResult<ClientRow> {
    if let Some(client) = oauth_clients::find_by_id(&state.pool, reference).await? {
        return Ok(client);
    }
    oauth_clients::find_by_client_id(&state.pool, reference)
        .await?
        .ok_or_else(|| ApiError::not_found("Application not found"))
}

async fn to_dto(state: &AppState, client: &ClientRow) -> ApiResult<ClientDto> {
    let keys = oauth_clients::count_keys(&state.pool, &client.id).await?;
    Ok(ClientDto::from_row(client, keys))
}

pub async fn create_client(
    state: &AppState,
    actor: &Principal,
    payload: CreateClientRequest,
    client_info: &ClientInfo,
) -> ApiResult<ClientCreatedResponse> {
    validator::Validate::validate(&payload)?;

    let client_type = payload.client_type.unwrap_or(ClientType::Confidential);
    let redirect_uris = validate_redirect_uris(payload.redirect_uris.as_deref().unwrap_or(&[]))?;
    if client_type == ClientType::Public && redirect_uris.is_empty() {
        return Err(ApiError::field(
            "redirect_uris",
            "public clients (SPA/mobile) need at least one redirect URI",
        ));
    }

    let allowed_scopes = match payload.allowed_scopes.as_deref() {
        Some(scopes) if !scopes.is_empty() => validate_scope_list(scopes)?,
        _ => state.config.sso.default_scopes.clone(),
    };

    // Guard against two applications claiming the same redirect target with the
    // same name: this is almost always a duplicated registration.
    let existing = oauth_clients::list(
        &state.pool,
        &ClientFilter {
            search: Some(payload.name.trim().to_string()),
            status: None,
        },
        50,
        0,
    )
    .await?
    .0;
    if existing
        .iter()
        .any(|client| client.name.eq_ignore_ascii_case(payload.name.trim()))
    {
        return Err(ApiError::conflict(
            "CLIENT_NAME_TAKEN",
            "An application with this name already exists",
        ));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let client_id = format!("app_{}", random_hex(12));
    let secret = format!("cs_{}", random_token());
    let secret_hash = sha256_hex(&secret);

    oauth_clients::insert(
        &state.pool,
        &NewClient {
            id: &id,
            client_id: &client_id,
            client_secret_hash: &secret_hash,
            name: payload.name.trim(),
            description: payload.description.as_deref().map(str::trim),
            client_type,
            redirect_uris: &redirect_uris,
            allowed_scopes: &allowed_scopes,
            owner_id: Some(actor.id()),
        },
    )
    .await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(actor.id()),
            actor_email: Some(actor.user.email.as_str()),
            action: "sso.client_created",
            target_type: Some("oauth_client"),
            target_id: Some(&id),
            ip_address: client_info.ip.as_deref(),
            user_agent: client_info.user_agent.as_deref(),
            metadata: Some(serde_json::json!({
                "client_id": client_id,
                "client_type": client_type.as_str(),
                "scopes": allowed_scopes,
            })),
        },
    )
    .await;

    let created = client_or_404(state, &id).await?;
    Ok(ClientCreatedResponse {
        client: to_dto(state, &created).await?,
        client_secret: secret,
        warning: "Store this client secret now; it is not recoverable later.".to_string(),
    })
}

pub async fn list_clients(
    state: &AppState,
    query: ListClientsQuery,
) -> ApiResult<Page<ClientDto>> {
    let pagination = query.pagination();
    let filter = ClientFilter {
        search: query.search.clone(),
        status: query.status,
    };
    let (rows, total) = oauth_clients::list(
        &state.pool,
        &filter,
        pagination.limit(),
        pagination.offset(),
    )
    .await?;

    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        items.push(to_dto(state, row).await?);
    }
    Ok(Page::new(
        items,
        pagination.page(),
        pagination.per_page(),
        total,
    ))
}

pub async fn get_client(state: &AppState, reference: &str) -> ApiResult<ClientDto> {
    let client = client_or_404(state, reference).await?;
    to_dto(state, &client).await
}

pub async fn update_client(
    state: &AppState,
    actor: &Principal,
    reference: &str,
    payload: UpdateClientRequest,
    client_info: &ClientInfo,
) -> ApiResult<ClientDto> {
    payload.validate()?;

    let client = client_or_404(state, reference).await?;
    let name = payload.name.as_deref().unwrap_or(&client.name).trim().to_string();
    if name.len() < 3 {
        return Err(ApiError::field("name", "must be at least 3 characters"));
    }

    let redirect_uris = match payload.redirect_uris.as_deref() {
        Some(uris) => validate_redirect_uris(uris)?,
        None => client.redirect_uris(),
    };
    if client.client_type == ClientType::Public && redirect_uris.is_empty() {
        return Err(ApiError::field(
            "redirect_uris",
            "public clients need at least one redirect URI",
        ));
    }

    let allowed_scopes = match payload.allowed_scopes.as_deref() {
        Some(scopes) => validate_scope_list(scopes)?,
        None => client.allowed_scopes(),
    };

    oauth_clients::update_metadata(
        &state.pool,
        &client.id,
        &name,
        payload
            .description
            .as_deref()
            .map(str::trim)
            .or(client.description.as_deref()),
        &redirect_uris,
        &allowed_scopes,
    )
    .await?;

    if let Some(status) = payload.status {
        oauth_clients::set_status(&state.pool, &client.id, status).await?;
        if status == ClientStatus::Disabled {
            // Disabling an application must also kill its machine credentials.
            sso::revoke_client_credentials(state, &client.id, "application disabled").await?;
        }
    }

    audit::record(
        state,
        NewAudit {
            actor_id: Some(actor.id()),
            actor_email: Some(actor.user.email.as_str()),
            action: "sso.client_updated",
            target_type: Some("oauth_client"),
            target_id: Some(&client.id),
            ip_address: client_info.ip.as_deref(),
            user_agent: client_info.user_agent.as_deref(),
            metadata: Some(serde_json::json!({
                "name": name,
                "redirect_uris": redirect_uris,
                "scopes": allowed_scopes,
                "status": payload.status.map(|status| status.as_str()),
            })),
        },
    )
    .await;

    let updated = client_or_404(state, &client.id).await?;
    to_dto(state, &updated).await
}

pub async fn delete_client(
    state: &AppState,
    actor: &Principal,
    reference: &str,
    client_info: &ClientInfo,
) -> ApiResult<()> {
    let client = client_or_404(state, reference).await?;
    sso::revoke_client_credentials(state, &client.id, "application deleted").await?;
    oauth_clients::delete(&state.pool, &client.id).await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(actor.id()),
            actor_email: Some(actor.user.email.as_str()),
            action: "sso.client_deleted",
            target_type: Some("oauth_client"),
            target_id: Some(&client.id),
            ip_address: client_info.ip.as_deref(),
            user_agent: client_info.user_agent.as_deref(),
            metadata: Some(serde_json::json!({ "name": client.name, "client_id": client.client_id })),
        },
    )
    .await;
    Ok(())
}

pub async fn rotate_client_secret(
    state: &AppState,
    actor: &Principal,
    reference: &str,
    client_info: &ClientInfo,
) -> ApiResult<RotateSecretResponse> {
    let client = client_or_404(state, reference).await?;
    if client.client_type != ClientType::Confidential {
        return Err(ApiError::conflict(
            "PUBLIC_CLIENT",
            "Public clients do not use a client secret; rotate nothing.",
        ));
    }

    let secret = format!("cs_{}", random_token());
    oauth_clients::rotate_secret(&state.pool, &client.id, &sha256_hex(&secret)).await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(actor.id()),
            actor_email: Some(actor.user.email.as_str()),
            action: "sso.client_secret_rotated",
            target_type: Some("oauth_client"),
            target_id: Some(&client.id),
            ip_address: client_info.ip.as_deref(),
            user_agent: client_info.user_agent.as_deref(),
            metadata: None,
        },
    )
    .await;

    Ok(RotateSecretResponse {
        client_id: client.client_id,
        client_secret: secret,
        rotated_at: now_datetime(),
        warning: "All previously issued client credentials stop working immediately.".to_string(),
    })
}

// ---------------------------------------------------------------------------
// App keys
// ---------------------------------------------------------------------------

pub async fn create_api_key(
    state: &AppState,
    actor: &Principal,
    reference: &str,
    payload: CreateApiKeyRequest,
    client_info: &ClientInfo,
) -> ApiResult<ApiKeyCreatedResponse> {
    payload.validate()?;
    let client = client_or_404(state, reference).await?;
    if !client.is_active() {
        return Err(ApiError::conflict(
            "CLIENT_DISABLED",
            "Enable the application before issuing keys",
        ));
    }

    let allowed = client.allowed_scopes();
    let scopes = match payload.scopes.as_deref() {
        Some(requested) => {
            let cleaned = validate_scope_list(requested)?;
            for scope in &cleaned {
                if !allowed.iter().any(|candidate| candidate == scope) {
                    return Err(ApiError::field(
                        "scopes",
                        format!("`{scope}` is not allowed for this application"),
                    ));
                }
            }
            cleaned
        }
        None => allowed,
    };

    let expires_at = match payload.expires_in_days {
        Some(days) => {
            if days == 0 || days > 3650 {
                return Err(ApiError::field(
                    "expires_in_days",
                    "must be between 1 and 3650",
                ));
            }
            Some(now_ts() + Duration::from_secs(days as u64 * 86_400).as_secs() as i64)
        }
        None => None,
    };

    let environment = payload
        .environment
        .as_deref()
        .unwrap_or("live")
        .trim()
        .to_ascii_lowercase();
    if environment != "live" && environment != "test" {
        return Err(ApiError::field("environment", "must be `live` or `test`"));
    }

    if oauth_clients::count_keys(&state.pool, &client.id).await? >= MAX_KEYS_PER_CLIENT {
        return Err(ApiError::conflict(
            "TOO_MANY_KEYS",
            format!("An application may hold at most {MAX_KEYS_PER_CLIENT} active keys"),
        ));
    }

    let issued = issue_api_key(state, &client, &payload.name, &scopes, &environment, expires_at).await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(actor.id()),
            actor_email: Some(actor.user.email.as_str()),
            action: "sso.api_key_created",
            target_type: Some("api_key"),
            target_id: Some(&issued.api_key.id),
            ip_address: client_info.ip.as_deref(),
            user_agent: client_info.user_agent.as_deref(),
            metadata: Some(serde_json::json!({
                "client_id": client.client_id,
                "key_prefix": issued.api_key.key_prefix,
                "scopes": scopes,
                "environment": environment,
            })),
        },
    )
    .await;

    Ok(issued)
}

async fn issue_api_key(
    state: &AppState,
    client: &ClientRow,
    name: &str,
    scopes: &[String],
    environment: &str,
    expires_at: Option<i64>,
) -> ApiResult<ApiKeyCreatedResponse> {
    let id = uuid::Uuid::new_v4().to_string();
    // `<prefix>_<env>_<8 hex>` is the visible part, the rest is the secret.
    let key_prefix = format!(
        "{}_{}_{}",
        state.config.sso.app_key_prefix, environment, random_hex(4)
    );
    let secret = format!("{key_prefix}_{}", random_token());
    let key_hash = sha256_hex(&secret);

    oauth_clients::insert_key(
        &state.pool,
        &NewApiKey {
            id: &id,
            client_id: &client.id,
            name: name.trim(),
            key_prefix: &key_prefix,
            key_hash: &key_hash,
            scopes,
            environment,
            expires_at,
            created_by: None,
        },
    )
    .await?;

    let row: ApiKeyRow = oauth_clients::find_key_by_id(&state.pool, &id)
        .await?
        .ok_or_else(|| ApiError::internal(anyhow::anyhow!("api key vanished after insert")))?;

    Ok(ApiKeyCreatedResponse {
        api_key: ApiKeyDto::from_row(&row),
        secret,
        warning: "Copy this key now — it is stored only as a SHA-256 hash.".to_string(),
    })
}

pub async fn list_api_keys(state: &AppState, reference: &str) -> ApiResult<Vec<ApiKeyDto>> {
    let client = client_or_404(state, reference).await?;
    let rows = oauth_clients::list_keys(&state.pool, &client.id).await?;
    Ok(rows.iter().map(ApiKeyDto::from_row).collect())
}

pub async fn revoke_api_key(
    state: &AppState,
    actor: &Principal,
    reference: &str,
    key_id: &str,
    client_info: &ClientInfo,
) -> ApiResult<()> {
    let client = client_or_404(state, reference).await?;
    let key = oauth_clients::find_key_by_id(&state.pool, key_id)
        .await?
        .filter(|key| key.client_id == client.id)
        .ok_or_else(|| ApiError::not_found("API key not found"))?;

    if !oauth_clients::revoke_key(&state.pool, &key.id).await? {
        return Err(ApiError::conflict(
            "KEY_ALREADY_REVOKED",
            "This key is already revoked",
        ));
    }

    audit::record(
        state,
        NewAudit {
            actor_id: Some(actor.id()),
            actor_email: Some(actor.user.email.as_str()),
            action: "sso.api_key_revoked",
            target_type: Some("api_key"),
            target_id: Some(&key.id),
            ip_address: client_info.ip.as_deref(),
            user_agent: client_info.user_agent.as_deref(),
            metadata: Some(serde_json::json!({
                "client_id": client.client_id,
                "key_prefix": key.key_prefix,
            })),
        },
    )
    .await;
    Ok(())
}

/// Issues a replacement key and revokes the old one in the same call so that
/// integrations can rotate without a window where no key works.
pub async fn rotate_api_key(
    state: &AppState,
    actor: &Principal,
    reference: &str,
    key_id: &str,
    client_info: &ClientInfo,
) -> ApiResult<ApiKeyCreatedResponse> {
    let client = client_or_404(state, reference).await?;
    let key = oauth_clients::find_key_by_id(&state.pool, key_id)
        .await?
        .filter(|key| key.client_id == client.id)
        .ok_or_else(|| ApiError::not_found("API key not found"))?;

    let issued = issue_api_key(
        state,
        &client,
        &key.name,
        &key.scopes(),
        &key.environment,
        key.expires_at,
    )
    .await?;
    oauth_clients::revoke_key(&state.pool, &key.id).await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(actor.id()),
            actor_email: Some(actor.user.email.as_str()),
            action: "sso.api_key_rotated",
            target_type: Some("api_key"),
            target_id: Some(&issued.api_key.id),
            ip_address: client_info.ip.as_deref(),
            user_agent: client_info.user_agent.as_deref(),
            metadata: Some(serde_json::json!({
                "client_id": client.client_id,
                "replaced": key.key_prefix,
                "key_prefix": issued.api_key.key_prefix,
            })),
        },
    )
    .await;

    Ok(issued)
}

fn now_datetime() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

trait ValidateExt {
    fn validate(&self) -> ApiResult<()>;
}

impl<T: validator::Validate> ValidateExt for T {
    fn validate(&self) -> ApiResult<()> {
        validator::Validate::validate(self).map_err(ApiError::from)
    }
}
