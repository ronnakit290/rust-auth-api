//! OAuth2 / SSO endpoints.
//!
//! Everything here speaks the standard wire formats (RFC 6749, 7662, 7009,
//! 8414) so third-party systems can integrate without custom glue:
//!
//! * `GET  /.well-known/openid-configuration` — discovery document
//! * `GET  /.well-known/jwks.json`            — RS256 public keys
//! * `GET  /oauth/authorize/info`             — what the consent screen shows
//! * `POST /oauth/authorize`                  — issue an authorization code
//! * `POST /oauth/token`                      — code / refresh / client_credentials
//! * `POST /oauth/introspect`                 — is this token still good?
//! * `POST /oauth/revoke`                     — kill a token
//! * `GET  /oauth/userinfo`                   — profile of the token's subject

use axum::{
    extract::{
        rejection::{FormRejection, JsonRejection},
        Form, Path, Query, State,
    },
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, PRAGMA},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::{
    dto::*,
    error::{ApiResult, ErrorResponse},
    extract::{ApiClient, ApiJson, AuthUser, ClientInfo},
    oauth_error::{OAuthError, OAuthResult},
    response::{ok, Page},
    services::sso as sso_service,
    state::AppState,
};

fn no_store<T: Serialize>(status: StatusCode, body: T) -> Response {
    let mut response = (status, Json(body)).into_response();
    let headers = response.headers_mut();
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| sso_service::parse_basic_auth(Some(value)))
}

fn bearer_token(headers: &HeaderMap) -> OAuthResult<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim().to_string())
        .filter(|token| !token.is_empty())
        .ok_or_else(|| OAuthError::invalid_token("Missing `Authorization: Bearer <token>` header"))
}

fn form_error(rejection: FormRejection) -> OAuthError {
    OAuthError::invalid_request(format!("Malformed form body: {}", rejection.body_text()))
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/.well-known/openid-configuration",
    tag = "sso",
    summary = "Discovery document",
    description = "Advertises every endpoint so client libraries can configure themselves.",
    responses((status = 200, body = DiscoveryResponse))
)]
pub async fn discovery(State(state): State<AppState>) -> impl IntoResponse {
    let issuer = state.config.sso.issuer.clone();
    let document = DiscoveryResponse {
        issuer: issuer.clone(),
        authorization_endpoint: format!("{issuer}/oauth/authorize"),
        token_endpoint: format!("{issuer}/oauth/token"),
        userinfo_endpoint: format!("{issuer}/oauth/userinfo"),
        introspection_endpoint: format!("{issuer}/oauth/introspect"),
        revocation_endpoint: format!("{issuer}/oauth/revoke"),
        jwks_uri: format!("{issuer}/.well-known/jwks.json"),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
            "client_credentials".to_string(),
        ],
        code_challenge_methods_supported: vec!["S256".to_string(), "plain".to_string()],
        scopes_supported: crate::services::clients::KNOWN_SCOPES
            .iter()
            .map(|scope| scope.to_string())
            .collect(),
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic".to_string(),
            "client_secret_post".to_string(),
            "none".to_string(),
        ],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["RS256".to_string()],
    };
    no_store(StatusCode::OK, document)
}

#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    tag = "sso",
    summary = "JSON Web Key Set",
    description = "RS256 public key(s). Resource servers cache this and verify access tokens locally.",
    responses((status = 200, body = JwksResponse))
)]
pub async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    let mut response = Json(state.sso.public_jwks_json()).into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    response
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/oauth/authorize/info",
    tag = "sso",
    summary = "Consent-screen data",
    description = "Validates the authorization request and reports the application, its scopes and whether consent is already on file.",
    params(
        ("response_type" = String, Query),
        ("client_id" = String, Query),
        ("redirect_uri" = String, Query),
        ("scope" = Option<String>, Query),
        ("state" = Option<String>, Query),
        ("code_challenge" = Option<String>, Query),
        ("code_challenge_method" = Option<String>, Query),
        ("prompt" = Option<String>, Query)
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = AuthorizeInfoResponse),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse)
    )
)]
pub async fn authorize_info(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Response, OAuthError> {
    let info = sso_service::authorize_info(&state, &auth.0, query).await?;
    Ok(no_store(StatusCode::OK, info))
}

#[utoipa::path(
    post,
    path = "/oauth/authorize",
    tag = "sso",
    summary = "Approve an application and get a code",
    description = "The authenticated user consents to the requested scopes. Returns the redirect URL with `code` and `state` appended, plus the raw code.",
    request_body = AuthorizeQuery,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, body = AuthorizeResponse),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse)
    )
)]
pub async fn authorize(
    State(state): State<AppState>,
    auth: AuthUser,
    client_info: ClientInfo,
    payload: Result<Json<AuthorizeQuery>, JsonRejection>,
) -> Result<Response, OAuthError> {
    let Json(query) = payload.map_err(|rejection| {
        OAuthError::invalid_request(format!("Malformed JSON body: {}", rejection.body_text()))
    })?;
    let response = sso_service::authorize(&state, &auth.0, query, &client_info).await?;
    Ok(no_store(StatusCode::OK, response))
}

// ---------------------------------------------------------------------------
// Token / introspection / revocation
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/oauth/token",
    tag = "sso",
    summary = "Token endpoint",
    description = "Supports `authorization_code` (+PKCE), `refresh_token` and `client_credentials`. Authenticate with HTTP Basic or `client_id`/`client_secret` in the body.",
    request_body(content = TokenRequestForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, body = TokenResponse),
        (status = 400),
        (status = 401)
    )
)]
pub async fn token(
    State(state): State<AppState>,
    client_info: ClientInfo,
    headers: HeaderMap,
    form: Result<Form<TokenRequestForm>, FormRejection>,
) -> Result<Response, OAuthError> {
    let Form(form) = form.map_err(form_error)?;
    let tokens = sso_service::token(&state, form, basic_auth(&headers), &client_info).await?;
    Ok(no_store(StatusCode::OK, tokens))
}

#[utoipa::path(
    post,
    path = "/oauth/introspect",
    tag = "sso",
    summary = "Introspect a token (RFC 7662)",
    description = "Requires client authentication. Returns `active:false` for unknown, revoked or foreign tokens.",
    request_body(content = IntrospectRequest, content_type = "application/x-www-form-urlencoded"),
    responses((status = 200, body = IntrospectResponse), (status = 401))
)]
pub async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<IntrospectRequest>, FormRejection>,
) -> Result<Response, OAuthError> {
    let Form(form) = form.map_err(form_error)?;
    let result = sso_service::introspect(&state, form, basic_auth(&headers)).await?;
    Ok(no_store(StatusCode::OK, result))
}

#[utoipa::path(
    post,
    path = "/oauth/revoke",
    tag = "sso",
    summary = "Revoke a token (RFC 7009)",
    description = "Access tokens are added to a denylist; refresh tokens are marked revoked. Unknown tokens still return 200.",
    request_body(content = RevokeRequest, content_type = "application/x-www-form-urlencoded"),
    responses((status = 200), (status = 401))
)]
pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    form: Result<Form<RevokeRequest>, FormRejection>,
) -> Result<Response, OAuthError> {
    let Form(form) = form.map_err(form_error)?;
    sso_service::revoke(&state, form, basic_auth(&headers)).await?;
    Ok(no_store(StatusCode::OK, serde_json::json!({})))
}

#[utoipa::path(
    get,
    path = "/oauth/userinfo",
    tag = "sso",
    summary = "Profile of the token subject",
    description = "Fields are filtered by scope: `email` exposes the address, `profile` exposes name and role.",
    security(("sso_bearer" = [])),
    responses((status = 200, body = UserInfoResponse), (status = 401))
)]
pub async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, OAuthError> {
    let token = bearer_token(&headers)?;
    let info = sso_service::userinfo(&state, &token).await?;
    Ok(no_store(StatusCode::OK, info))
}

// ---------------------------------------------------------------------------
// Application (app key) endpoints — for systems that cannot do an OAuth dance
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/app/me",
    tag = "app",
    summary = "Who am I, as an application",
    description = "Resolves the `X-API-Key` header into the owning application, its scopes and key metadata.",
    security(("api_key" = [])),
    responses(
        (status = 200, body = AppMeResponse),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse)
    )
)]
pub async fn app_me(State(state): State<AppState>, api: ApiClient) -> ApiResult<impl IntoResponse> {
    Ok(ok(sso_service::app_me(&state, &api).await?))
}

#[utoipa::path(
    get,
    path = "/api/v1/app/users",
    tag = "app",
    summary = "List users (requires `users:read`)",
    params(("page" = Option<u32>, Query), ("per_page" = Option<u32>, Query)),
    security(("api_key" = [])),
    responses(
        (status = 200, body = Page<UserDto>),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse)
    )
)]
pub async fn app_users(
    State(state): State<AppState>,
    api: ApiClient,
    Query(pagination): Query<PaginationQuery>,
) -> ApiResult<impl IntoResponse> {
    let page =
        sso_service::app_list_users(&state, &api, pagination.page(), pagination.per_page()).await?;
    Ok(ok(page))
}

#[utoipa::path(
    get,
    path = "/api/v1/app/users/{user_id}",
    tag = "app",
    summary = "Fetch one user (requires `users:read`)",
    params(("user_id" = String, Path)),
    security(("api_key" = [])),
    responses(
        (status = 200, body = UserDto),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse)
    )
)]
pub async fn app_user(
    State(state): State<AppState>,
    api: ApiClient,
    Path(user_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    Ok(ok(sso_service::app_get_user(&state, &api, &user_id).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/app/introspect",
    tag = "app",
    summary = "Validate a token with an app key (requires `tokens:verify`)",
    request_body = AppIntrospectRequest,
    security(("api_key" = [])),
    responses(
        (status = 200, body = IntrospectResponse),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse)
    )
)]
pub async fn app_introspect(
    State(state): State<AppState>,
    api: ApiClient,
    ApiJson(payload): ApiJson<AppIntrospectRequest>,
) -> ApiResult<impl IntoResponse> {
    Ok(ok(sso_service::app_introspect(&state, &api, payload).await?))
}
