//! Authentication extractors: `AuthUser`, `StaffUser`, `AdminUser`, `ClientInfo`.
//!
//! Everything is derived from the `Authorization: Bearer <jwt>` header plus a
//! database lookup so that role changes and account suspensions take effect
//! immediately instead of waiting for the access token to expire.

use axum::{
    extract::{
        rejection::JsonRejection, FromRequest, FromRequestParts, OptionalFromRequest, Request,
    },
    http::{header, request::Parts, StatusCode},
    Json,
};
use std::net::SocketAddr;

use crate::{
    db::{sessions, users::UserRow},
    error::ApiError,
    security::Claims,
    state::AppState,
};

/// Network metadata for the current request, used for audit trails and rate
/// limiting keys.
#[derive(Debug, Clone, Default)]
pub struct ClientInfo {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

impl ClientInfo {
    /// Stable identity for rate limiting. Falls back to a shared bucket when the
    /// peer address is unknown (e.g. behind a misconfigured proxy).
    pub fn rate_key(&self) -> String {
        self.ip.clone().unwrap_or_else(|| "unknown".to_string())
    }
}

impl FromRequestParts<AppState> for ClientInfo {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let user_agent = parts
            .headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.chars().take(300).collect::<String>());

        let ip = if state.config.trust_proxy {
            parts
                .headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(',').next())
                .map(|value| value.trim().to_string())
                .or_else(|| {
                    parts
                        .headers
                        .get("x-real-ip")
                        .and_then(|value| value.to_str().ok())
                        .map(|value| value.trim().to_string())
                })
        } else {
            None
        }
        .or_else(|| {
            parts
                .extensions
                .get::<axum::extract::ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip().to_string())
        });

        Ok(ClientInfo { ip, user_agent })
    }
}

/// The authenticated caller, loaded fresh from the database.
#[derive(Debug, Clone)]
pub struct Principal {
    pub user: UserRow,
    pub claims: Claims,
    pub session_id: String,
}

impl Principal {
    pub fn id(&self) -> &str {
        &self.user.id
    }
}

#[derive(Debug, Clone)]
pub struct AuthUser(pub Principal);

impl std::ops::Deref for AuthUser {
    type Target = Principal;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Requires `moderator` or above.
#[derive(Debug, Clone)]
pub struct StaffUser(pub Principal);

impl std::ops::Deref for StaffUser {
    type Target = Principal;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Requires `admin` or above.
#[derive(Debug, Clone)]
pub struct AdminUser(pub Principal);

impl std::ops::Deref for AdminUser {
    type Target = Principal;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn bearer_token(parts: &Parts) -> Result<String, ApiError> {
    let raw = parts
        .headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| ApiError::unauthenticated("Missing Authorization header"))?
        .to_str()
        .map_err(|_| ApiError::unauthenticated("Malformed Authorization header"))?;

    let (scheme, token) = raw
        .split_once(' ')
        .ok_or_else(|| ApiError::unauthenticated("Expected `Bearer <token>`"))?;

    if !scheme.eq_ignore_ascii_case("bearer") || token.trim().is_empty() {
        return Err(ApiError::unauthenticated("Expected `Bearer <token>`"));
    }
    Ok(token.trim().to_string())
}

async fn authenticate(parts: &mut Parts, state: &AppState) -> Result<Principal, ApiError> {
    let token = bearer_token(parts)?;
    let claims = state.jwt.decode_access(&token)?;

    let user = crate::db::users::find_by_id(&state.pool, &claims.sub)
        .await?
        .ok_or_else(|| ApiError::unauthenticated("The account no longer exists"))?;

    match user.status {
        crate::db::users::UserStatus::Active => {}
        crate::db::users::UserStatus::Suspended => {
            return Err(ApiError::forbidden(
                "ACCOUNT_SUSPENDED",
                "This account has been suspended",
            ))
        }
        crate::db::users::UserStatus::Deleted => {
            return Err(ApiError::unauthenticated("The account no longer exists"))
        }
    }

    if claims.sid.is_empty() {
        return Err(ApiError::unauthenticated("Invalid session"));
    }

    if state.config.security.verify_session_on_request {
        let session = sessions::find_by_id(&state.pool, &claims.sid)
            .await?
            .ok_or_else(|| ApiError::unauthenticated("The session is no longer valid"))?;
        if !session.is_active(crate::db::now_ts()) {
            return Err(ApiError::unauthenticated(
                "The session has been revoked or has expired",
            ));
        }
    }

    Ok(Principal {
        user,
        session_id: claims.sid.clone(),
        claims,
    })
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        Ok(AuthUser(authenticate(parts, state).await?))
    }
}

impl FromRequestParts<AppState> for StaffUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let principal = authenticate(parts, state).await?;
        if !principal.user.role.is_staff() {
            return Err(ApiError::forbidden(
                "INSUFFICIENT_ROLE",
                "This endpoint requires a staff role",
            ));
        }
        Ok(StaffUser(principal))
    }
}

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let principal = authenticate(parts, state).await?;
        if !principal.user.role.is_admin() {
            return Err(ApiError::forbidden(
                "INSUFFICIENT_ROLE",
                "This endpoint requires an administrator role",
            ));
        }
        Ok(AdminUser(principal))
    }
}

/// Optional authentication: never fails, yields `None` without a valid token.
#[derive(Debug, Clone)]
pub struct MaybeUser(pub Option<Principal>);

impl FromRequestParts<AppState> for MaybeUser {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, std::convert::Infallible> {
        Ok(MaybeUser(authenticate(parts, state).await.ok()))
    }
}

/// `Json` with rejections mapped onto the API error envelope, so malformed
/// bodies never leak axum's plain-text rejection.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApiJson<T>(pub T);

fn map_json_rejection(rejection: JsonRejection) -> ApiError {
    match rejection {
        JsonRejection::JsonDataError(error) => {
            ApiError::bad_request("INVALID_BODY", error.body_text())
        }
        JsonRejection::JsonSyntaxError(error) => {
            ApiError::bad_request("INVALID_JSON", error.body_text())
        }
        JsonRejection::MissingJsonContentType(_) => ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            "Content-Type must be application/json",
        ),
        other => ApiError::bad_request("INVALID_BODY", other.body_text()),
    }
}

impl<S, T> FromRequest<S> for ApiJson<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(ApiJson(value)),
            Err(rejection) => Err(map_json_rejection(rejection)),
        }
    }
}

impl<S, T> OptionalFromRequest<S> for ApiJson<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Option<Self>, Self::Rejection> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Some(ApiJson(value))),
            // No body / no JSON content type is fine for endpoints where the
            // payload is optional; a broken body is reported as `None` too so
            // the handler still receives its defaults.
            Err(_) => Ok(None),
        }
    }
}

/// Tiny helper so handlers can return `StatusCode` without importing axum types.
pub const NO_CONTENT: StatusCode = StatusCode::NO_CONTENT;

// ---------------------------------------------------------------------------
// Machine authentication: application keys (SSO)
// ---------------------------------------------------------------------------

/// An authenticated application, resolved from an `X-API-Key` header (or
/// `Authorization: ApiKey <key>`).
#[derive(Debug, Clone)]
pub struct ApiClient {
    pub client: crate::db::oauth_clients::ClientRow,
    pub key: crate::db::oauth_clients::ApiKeyRow,
}

impl ApiClient {
    pub fn scopes(&self) -> Vec<String> {
        self.key.scopes()
    }

    /// Every API-key endpoint calls this first; a key only ever carries the
    /// scopes it was minted with, never the full set of its application.
    pub fn require_scope(&self, scope: &str) -> Result<(), ApiError> {
        if self.key.has_scope(scope) {
            return Ok(());
        }
        Err(ApiError::new(
            axum::http::StatusCode::FORBIDDEN,
            "INSUFFICIENT_SCOPE",
            format!("This application key is missing the `{scope}` scope"),
        ))
    }
}

impl FromRequestParts<AppState> for ApiClient {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header_key = parts
            .headers
            .get("x-api-key")
            .or_else(|| parts.headers.get("x-app-key"))
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim().to_string());

        let auth_key = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("apikey"))
            .map(|(_, token)| token.trim().to_string());

        let raw = header_key
            .or(auth_key)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                ApiError::unauthenticated("Provide an application key in the `X-API-Key` header")
            })?;

        if raw.len() < 24 || !raw.is_ascii() {
            return Err(ApiError::unauthorized(
                "INVALID_API_KEY",
                "The application key is malformed",
            ));
        }

        let key = crate::db::oauth_clients::find_key_by_hash(
            &state.pool,
            &crate::security::tokens::sha256_hex(&raw),
        )
        .await?
        .ok_or_else(|| {
            ApiError::unauthorized("INVALID_API_KEY", "The application key is not recognised")
        })?;

        if !key.is_usable(crate::db::now_ts()) {
            return Err(ApiError::unauthorized(
                "API_KEY_INACTIVE",
                "The application key is revoked or expired",
            ));
        }

        let client = crate::db::oauth_clients::find_by_id(&state.pool, &key.client_id)
            .await?
            .ok_or_else(|| {
                ApiError::unauthorized("INVALID_API_KEY", "The application no longer exists")
            })?;

        if !client.is_active() {
            return Err(ApiError::new(
                axum::http::StatusCode::FORBIDDEN,
                "CLIENT_DISABLED",
                "This application is disabled",
            ));
        }

        // Best effort: usage metadata must not break a valid request.
        if let Err(error) = crate::db::oauth_clients::touch_key(&state.pool, &key.id).await {
            tracing::warn!(error = %error, "failed to record API key usage");
        }

        Ok(ApiClient { client, key })
    }
}
