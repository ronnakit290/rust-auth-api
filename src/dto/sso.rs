//! Payloads for the central SSO server: OAuth2 clients, app keys and the
//! authorization-code / client-credentials flows.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::{
    db::{
        oauth_clients::{ApiKeyRow, ClientRow, ClientStatus, ClientType},
        users::ts_to_datetime,
    },
    dto::PaginationQuery,
};

// ---------------------------------------------------------------------------
// Clients (applications)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct CreateClientRequest {
    /// Human readable application name shown in the console and audit trail.
    #[validate(length(min = 3, max = 80, message = "must be between 3 and 80 characters"))]
    pub name: String,
    #[validate(length(max = 500, message = "must be at most 500 characters"))]
    pub description: Option<String>,
    /// `confidential` (server-side, has a secret) or `public` (SPA/mobile, PKCE only).
    pub client_type: Option<ClientType>,
    /// Exact-match redirect URIs. Required for public clients.
    #[validate(length(max = 20, message = "at most 20 redirect URIs"))]
    pub redirect_uris: Option<Vec<String>>,
    /// Scopes this application may ever request. Defaults to the server default set.
    pub allowed_scopes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct UpdateClientRequest {
    #[validate(length(min = 3, max = 80, message = "must be between 3 and 80 characters"))]
    pub name: Option<String>,
    #[validate(length(max = 500))]
    pub description: Option<String>,
    #[validate(length(max = 20, message = "at most 20 redirect URIs"))]
    pub redirect_uris: Option<Vec<String>>,
    pub allowed_scopes: Option<Vec<String>>,
    pub status: Option<ClientStatus>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClientDto {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub description: Option<String>,
    pub client_type: ClientType,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub status: ClientStatus,
    pub active_api_keys: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub secret_rotated_at: Option<DateTime<Utc>>,
}

impl ClientDto {
    pub fn from_row(row: &ClientRow, active_api_keys: i64) -> Self {
        ClientDto {
            id: row.id.clone(),
            client_id: row.client_id.clone(),
            name: row.name.clone(),
            description: row.description.clone(),
            client_type: row.client_type,
            redirect_uris: row.redirect_uris(),
            allowed_scopes: row.allowed_scopes(),
            status: row.status,
            active_api_keys,
            created_at: ts_to_datetime(row.created_at),
            updated_at: ts_to_datetime(row.updated_at),
            last_used_at: row.last_used_at.map(ts_to_datetime),
            secret_rotated_at: row.secret_rotated_at.map(ts_to_datetime),
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClientCreatedResponse {
    pub client: ClientDto,
    /// Returned exactly once. Store it now; only its hash is kept.
    pub client_secret: String,
    pub warning: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RotateSecretResponse {
    pub client_id: String,
    pub client_secret: String,
    pub rotated_at: DateTime<Utc>,
    pub warning: String,
}

#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct ListClientsQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub search: Option<String>,
    pub status: Option<ClientStatus>,
}

impl ListClientsQuery {
    pub fn pagination(&self) -> PaginationQuery {
        PaginationQuery {
            page: self.page,
            per_page: self.per_page,
        }
    }
}

// ---------------------------------------------------------------------------
// App keys
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct CreateApiKeyRequest {
    #[validate(length(min = 3, max = 80, message = "must be between 3 and 80 characters"))]
    pub name: String,
    /// Subset of the client's allowed scopes. Defaults to all of them.
    pub scopes: Option<Vec<String>>,
    /// `1`–`3650` days. Omit for a non-expiring key.
    pub expires_in_days: Option<u32>,
    /// `live` (default) or `test`.
    pub environment: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiKeyDto {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub environment: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

impl ApiKeyDto {
    pub fn from_row(row: &ApiKeyRow) -> Self {
        ApiKeyDto {
            id: row.id.clone(),
            client_id: row.client_id.clone(),
            name: row.name.clone(),
            key_prefix: row.key_prefix.clone(),
            scopes: row.scopes(),
            environment: row.environment.clone(),
            expires_at: row.expires_at.map(ts_to_datetime),
            last_used_at: row.last_used_at.map(ts_to_datetime),
            revoked_at: row.revoked_at.map(ts_to_datetime),
            created_at: ts_to_datetime(row.created_at),
            is_active: row.is_usable(crate::db::now_ts()),
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiKeyCreatedResponse {
    pub api_key: ApiKeyDto,
    /// The only time the secret is visible. `Authorization: X-API-Key <secret>`.
    pub secret: String,
    pub warning: String,
}

// ---------------------------------------------------------------------------
// Authorization endpoint
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AuthorizeQuery {
    /// Must be `code`.
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    /// Space separated scopes. Defaults to `openid profile email`.
    pub scope: Option<String>,
    pub state: Option<String>,
    /// PKCE challenge (required for public clients).
    pub code_challenge: Option<String>,
    /// `S256` (recommended) or `plain`.
    pub code_challenge_method: Option<String>,
    /// Send `consent` to re-record the user's consent even if it is cached.
    pub prompt: Option<String>,
}

impl AuthorizeQuery {
    pub fn scopes(&self) -> Vec<String> {
        self.scope
            .as_deref()
            .unwrap_or("")
            .split_whitespace()
            .map(|scope| scope.to_string())
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClientSummary {
    pub client_id: String,
    pub name: String,
    pub description: Option<String>,
    pub client_type: ClientType,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuthorizeInfoResponse {
    pub client: ClientSummary,
    pub requested_scopes: Vec<String>,
    pub redirect_uri: String,
    pub already_consented: bool,
    pub requires_pkce: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuthorizeResponse {
    /// Redirect the user agent here; the code and `state` are already appended.
    pub redirect_url: String,
    pub code: String,
    pub state: Option<String>,
    pub scopes: Vec<String>,
    pub expires_in: i64,
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct TokenRequestForm {
    /// `authorization_code` | `refresh_token` | `client_credentials`
    pub grant_type: String,
    pub client_id: Option<String>,
    /// Required for confidential clients when Basic auth is not used.
    pub client_secret: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct IntrospectRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
    /// Only needed when HTTP Basic auth is not used.
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct IntrospectResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct RevokeRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserInfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub scopes: Vec<String>,
    pub client_id: String,
}

// ---------------------------------------------------------------------------
// API-key protected app endpoints
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AppMeResponse {
    pub client: ClientSummary,
    pub allowed_scopes: Vec<String>,
    pub key_name: String,
    pub key_prefix: String,
    pub key_scopes: Vec<String>,
    pub environment: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct AppIntrospectRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct JwksResponse {
    pub keys: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DiscoveryResponse {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub introspection_endpoint: String,
    pub revocation_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
}
