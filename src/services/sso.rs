//! The SSO protocol itself: authorization code + PKCE, client credentials,
//! refresh-token rotation, token introspection/revocation and userinfo.
//!
//! This module speaks RFC 6749/7662 shapes (`OAuthError`) instead of the public
//! API envelope so that standard OAuth2 clients can be pointed straight at it.

use std::collections::HashSet;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::{
    db::{
        self,
        audit::NewAudit,
        oauth_clients::{self, ClientRow, ClientType},
        oauth_flow::{self, NewCode, NewRefreshToken},
        users::{self, UserRow},
    },
    dto::{
        AppIntrospectRequest, AppMeResponse, AuthorizeInfoResponse, AuthorizeQuery,
        AuthorizeResponse, ClientSummary, IntrospectRequest, IntrospectResponse, RevokeRequest,
        TokenRequestForm, TokenResponse, UserDto, UserInfoResponse,
    },
    error::{ApiError, ApiResult},
    extract::{ApiClient, ClientInfo},
    oauth_error::{OAuthError, OAuthResult},
    security::sso_jwt::SsoClaims,
    services::audit,
    state::AppState,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compares two hashes without leaking their common prefix length.
fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = Sha256::digest(left.as_bytes());
    let right = Sha256::digest(right.as_bytes());
    left.iter()
        .zip(right.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

pub fn parse_basic_auth(header: Option<&str>) -> Option<(String, String)> {
    let raw = header?.trim();
    let encoded = raw
        .strip_prefix("Basic ")
        .or_else(|| raw.strip_prefix("basic "))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded.trim()))
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    // RFC 6749 §2.3.1 asks clients to URL-encode both halves.
    Some((percent_decode(id), percent_decode(secret)))
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[index + 1..index + 3], 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

pub fn verify_pkce(verifier: &str, challenge: &str, method: &str) -> bool {
    if verifier.len() < 43 || verifier.len() > 128 {
        return false;
    }
    match method {
        "S256" => {
            let digest = Sha256::digest(verifier.as_bytes());
            URL_SAFE_NO_PAD.encode(digest) == challenge
        }
        "plain" => constant_time_eq(verifier, challenge),
        _ => false,
    }
}

fn scope_string(scopes: &[String]) -> String {
    scopes.join(" ")
}

fn parse_scopes(raw: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    raw.split_whitespace()
        .filter(|scope| seen.insert(scope.to_string()))
        .map(|scope| scope.to_string())
        .collect()
}

fn scope_subset(requested: &[String], allowed: &[String]) -> Vec<String> {
    requested
        .iter()
        .filter(|scope| allowed.iter().any(|candidate| candidate == *scope))
        .cloned()
        .collect()
}

async fn load_active_client(state: &AppState, client_id: &str) -> OAuthResult<ClientRow> {
    let client = oauth_clients::find_by_client_id(&state.pool, client_id)
        .await?
        .ok_or_else(|| OAuthError::invalid_client("Unknown client_id"))?;
    if !client.is_active() {
        return Err(OAuthError::invalid_client("This application is disabled"));
    }
    Ok(client)
}

/// Resolves and authenticates the calling application. Basic auth wins over
/// body credentials, matching RFC 6749 §2.3.1.
async fn authenticated_client(
    state: &AppState,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
    basic: Option<&(String, String)>,
) -> OAuthResult<ClientRow> {
    let (client_id, supplied_secret) = match basic {
        Some((id, secret)) => (id.clone(), Some(secret.clone())),
        None => (
            form_client_id
                .map(|value| value.to_string())
                .ok_or_else(|| OAuthError::invalid_client("client_id is required"))?,
            form_client_secret.map(|value| value.to_string()),
        ),
    };

    let client = load_active_client(state, &client_id).await?;

    if client.client_type == ClientType::Confidential {
        let secret = supplied_secret
            .ok_or_else(|| OAuthError::invalid_client("client_secret is required"))?;
        if !constant_time_eq(
            &crate::security::tokens::sha256_hex(&secret),
            &client.client_secret_hash,
        ) {
            tracing::warn!(client_id = %client.client_id, "SSO: wrong client secret");
            return Err(OAuthError::invalid_client("Invalid client secret"));
        }
    }

    Ok(client)
}

// ---------------------------------------------------------------------------
// Authorization endpoint
// ---------------------------------------------------------------------------

struct AuthorizeContext {
    client: ClientRow,
    scopes: Vec<String>,
    redirect_uri: String,
}

async fn prepare_authorize(
    state: &AppState,
    query: &AuthorizeQuery,
) -> OAuthResult<AuthorizeContext> {
    if query.response_type.trim() != "code" {
        return Err(OAuthError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "Only response_type=code is supported",
        ));
    }
    if query.client_id.trim().is_empty() {
        return Err(OAuthError::invalid_request("client_id is required"));
    }
    if query.redirect_uri.trim().is_empty() {
        return Err(OAuthError::invalid_request("redirect_uri is required"));
    }

    let client = load_active_client(state, &query.client_id).await?;
    if !client.allows_redirect(&query.redirect_uri) {
        // Never redirect to an unregistered URI, even on error.
        return Err(OAuthError::invalid_request(
            "redirect_uri is not registered for this application",
        ));
    }

    let allowed = client.allowed_scopes();
    let requested = {
        let asked = query.scopes();
        if asked.is_empty() {
            let intersection = scope_subset(&state.config.sso.default_scopes, &allowed);
            if intersection.is_empty() {
                allowed.clone()
            } else {
                intersection
            }
        } else {
            asked
        }
    };

    for scope in &requested {
        if !allowed.iter().any(|candidate| candidate == scope) {
            return Err(OAuthError::invalid_scope(format!(
                "`{scope}` is not allowed for this application"
            )));
        }
    }
    if requested.is_empty() {
        return Err(OAuthError::invalid_scope("No scopes requested or allowed"));
    }

    match query.code_challenge.as_deref() {
        Some(challenge) => {
            let method = query.code_challenge_method.as_deref().unwrap_or("S256");
            if method != "S256" && method != "plain" {
                return Err(OAuthError::invalid_request(
                    "code_challenge_method must be S256 or plain",
                ));
            }
            if challenge.len() < 32 {
                return Err(OAuthError::invalid_request("code_challenge is too short"));
            }
        }
        None => {
            if client.client_type == ClientType::Public {
                return Err(OAuthError::invalid_request(
                    "public clients must use PKCE (code_challenge)",
                ));
            }
        }
    }

    Ok(AuthorizeContext {
        client,
        scopes: requested,
        redirect_uri: query.redirect_uri.clone(),
    })
}

pub async fn authorize_info(
    state: &AppState,
    principal: &crate::extract::Principal,
    query: AuthorizeQuery,
) -> OAuthResult<AuthorizeInfoResponse> {
    let context = prepare_authorize(state, &query).await?;
    let consent = oauth_flow::get_consent(&state.pool, principal.id(), &context.client.id).await?;
    let already_consented = consent
        .as_ref()
        .map(|row| {
            let granted: Vec<String> = serde_json::from_str(&row.scopes).unwrap_or_default();
            context
                .scopes
                .iter()
                .all(|scope| granted.iter().any(|candidate| candidate == scope))
        })
        .unwrap_or(false);

    Ok(AuthorizeInfoResponse {
        client: ClientSummary {
            client_id: context.client.client_id.clone(),
            name: context.client.name.clone(),
            description: context.client.description.clone(),
            client_type: context.client.client_type,
        },
        requested_scopes: context.scopes,
        redirect_uri: context.redirect_uri,
        already_consented,
        requires_pkce: context.client.client_type == ClientType::Public,
    })
}

pub async fn authorize(
    state: &AppState,
    principal: &crate::extract::Principal,
    query: AuthorizeQuery,
    client_info: &ClientInfo,
) -> OAuthResult<AuthorizeResponse> {
    if !principal.user.is_active() {
        return Err(OAuthError::new(
            axum::http::StatusCode::FORBIDDEN,
            "access_denied",
            "The account is not active",
        ));
    }

    let method = query.code_challenge.as_ref().map(|_| {
        query
            .code_challenge_method
            .clone()
            .unwrap_or_else(|| "S256".to_string())
    });

    let context = prepare_authorize(state, &query).await?;
    let code = format!("ac_{}", crate::security::tokens::random_token());
    let expires_at = Utc::now().timestamp() + state.config.sso.code_ttl.as_secs() as i64;
    let code_id = uuid::Uuid::new_v4().to_string();

    oauth_flow::insert_code(
        &state.pool,
        &NewCode {
            id: &code_id,
            code_hash: &crate::security::tokens::sha256_hex(&code),
            client_id: &context.client.id,
            user_id: principal.id(),
            redirect_uri: &context.redirect_uri,
            scopes: &context.scopes,
            code_challenge: query.code_challenge.as_deref(),
            code_challenge_method: method.as_deref(),
            expires_at,
        },
    )
    .await?;

    oauth_flow::upsert_consent(
        &state.pool,
        principal.id(),
        &context.client.id,
        &context.scopes,
    )
    .await?;

    audit::record(
        state,
        NewAudit {
            actor_id: Some(principal.id()),
            actor_email: Some(principal.user.email.as_str()),
            action: "sso.authorization_granted",
            target_type: Some("oauth_client"),
            target_id: Some(&context.client.id),
            ip_address: client_info.ip.as_deref(),
            user_agent: client_info.user_agent.as_deref(),
            metadata: Some(serde_json::json!({
                "client_id": context.client.client_id,
                "scopes": context.scopes,
                "pkce": query.code_challenge.is_some(),
            })),
        },
    )
    .await;

    let mut redirect_url = context.redirect_uri.clone();
    let separator = if redirect_url.contains('?') { '&' } else { '?' };
    redirect_url.push(separator);
    redirect_url.push_str(&format!("code={}", urlencode(&code)));
    if let Some(state_param) = query.state.as_deref() {
        redirect_url.push_str(&format!("&state={}", urlencode(state_param)));
    }

    Ok(AuthorizeResponse {
        redirect_url,
        code,
        state: query.state.clone(),
        scopes: context.scopes,
        expires_in: state.config.sso.code_ttl.as_secs() as i64,
    })
}

fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

pub async fn token(
    state: &AppState,
    form: TokenRequestForm,
    basic: Option<(String, String)>,
    client_info: &ClientInfo,
) -> OAuthResult<TokenResponse> {
    if !state.config.sso.enabled {
        return Err(OAuthError::unauthorized_client(
            "The SSO server is disabled (SSO_ENABLED=false)",
        ));
    }

    match form.grant_type.trim() {
        "authorization_code" => exchange_code(state, &form, basic.as_ref(), client_info).await,
        "refresh_token" => exchange_refresh(state, &form, basic.as_ref(), client_info).await,
        "client_credentials" => client_credentials(state, &form, basic.as_ref(), client_info).await,
        "" => Err(OAuthError::invalid_request("grant_type is required")),
        _ => Err(OAuthError::unsupported_grant_type()),
    }
}

async fn exchange_code(
    state: &AppState,
    form: &TokenRequestForm,
    basic: Option<&(String, String)>,
    client_info: &ClientInfo,
) -> OAuthResult<TokenResponse> {
    let client = authenticated_client(
        state,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        basic,
    )
    .await?;

    let code = form
        .code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| OAuthError::invalid_request("code is required"))?;

    let row = oauth_flow::consume_code(&state.pool, &crate::security::tokens::sha256_hex(code))
        .await?
        .ok_or_else(|| {
            OAuthError::invalid_grant(
                "The authorization code is invalid, expired or has already been used",
            )
        })?;

    if row.client_id != client.id {
        return Err(OAuthError::invalid_grant(
            "This authorization code was issued to another application",
        ));
    }

    let redirect_uri = form
        .redirect_uri
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("redirect_uri is required"))?;
    if redirect_uri != row.redirect_uri {
        return Err(OAuthError::invalid_grant(
            "redirect_uri does not match the authorization request",
        ));
    }

    match row.code_challenge.as_deref() {
        Some(challenge) => {
            let verifier = form.code_verifier.as_deref().ok_or_else(|| {
                OAuthError::invalid_grant("code_verifier is required for this code")
            })?;
            let method = row.code_challenge_method.as_deref().unwrap_or("S256");
            if !verify_pkce(verifier, challenge, method) {
                return Err(OAuthError::invalid_grant("PKCE verification failed"));
            }
        }
        None => {
            if client.client_type == ClientType::Public {
                return Err(OAuthError::invalid_grant(
                    "public clients must present a PKCE code_verifier",
                ));
            }
        }
    }

    let user = users::find_by_id(&state.pool, &row.user_id)
        .await?
        .ok_or_else(|| OAuthError::invalid_grant("The user no longer exists"))?;
    if !user.is_active() {
        return Err(OAuthError::invalid_grant("The user account is not active"));
    }

    let scopes = row.scopes();
    let tokens = issue_user_tokens(state, &client, &user, &scopes, None).await?;

    oauth_clients::touch(&state.pool, &client.id).await?;
    audit::record(
        state,
        NewAudit {
            actor_id: Some(&user.id),
            actor_email: Some(user.email.as_str()),
            action: "sso.token_issued",
            target_type: Some("oauth_client"),
            target_id: Some(&client.id),
            ip_address: client_info.ip.as_deref(),
            user_agent: client_info.user_agent.as_deref(),
            metadata: Some(serde_json::json!({
                "grant_type": "authorization_code",
                "client_id": client.client_id,
                "scopes": scopes,
            })),
        },
    )
    .await;

    Ok(tokens)
}

async fn exchange_refresh(
    state: &AppState,
    form: &TokenRequestForm,
    basic: Option<&(String, String)>,
    client_info: &ClientInfo,
) -> OAuthResult<TokenResponse> {
    let client = authenticated_client(
        state,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        basic,
    )
    .await?;

    let raw = form
        .refresh_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| OAuthError::invalid_request("refresh_token is required"))?;

    let row = oauth_flow::find_refresh(&state.pool, &crate::security::tokens::sha256_hex(raw))
        .await?
        .ok_or_else(|| OAuthError::invalid_grant("Unknown refresh token"))?;

    if row.client_id != client.id {
        return Err(OAuthError::invalid_grant(
            "This refresh token belongs to another application",
        ));
    }

    if row.revoked_at.is_some() {
        // Reuse of a rotated token is a strong signal of theft: burn the family.
        let revoked =
            oauth_flow::revoke_refresh_for_client(&state.pool, &row.user_id, &row.client_id)
                .await?;
        tracing::warn!(
            user_id = %row.user_id,
            client_id = %client.client_id,
            revoked,
            "SSO: refresh token reuse detected, all tokens for this app revoked"
        );
        audit::record(
            state,
            NewAudit {
                actor_id: Some(&row.user_id),
                actor_email: None,
                action: "sso.refresh_reuse_detected",
                target_type: Some("oauth_client"),
                target_id: Some(&client.id),
                ip_address: client_info.ip.as_deref(),
                user_agent: client_info.user_agent.as_deref(),
                metadata: Some(serde_json::json!({ "client_id": client.client_id })),
            },
        )
        .await;
        return Err(OAuthError::invalid_grant(
            "This refresh token was already used; all tokens for this application have been revoked",
        ));
    }

    if row.expires_at <= Utc::now().timestamp() {
        return Err(OAuthError::invalid_grant("The refresh token has expired"));
    }

    let user = users::find_by_id(&state.pool, &row.user_id)
        .await?
        .ok_or_else(|| OAuthError::invalid_grant("The user no longer exists"))?;
    if !user.is_active() {
        return Err(OAuthError::invalid_grant("The user account is not active"));
    }

    let granted = row.scopes();
    let scopes = match form.scope.as_deref() {
        Some(requested) if !requested.trim().is_empty() => {
            let asked = parse_scopes(requested);
            let narrowed = scope_subset(&asked, &granted);
            if narrowed.len() != asked.len() {
                return Err(OAuthError::invalid_scope(
                    "The requested scopes exceed the original grant",
                ));
            }
            narrowed
        }
        _ => granted,
    };

    let tokens = issue_user_tokens(state, &client, &user, &scopes, Some(&row.id)).await?;

    oauth_clients::touch(&state.pool, &client.id).await?;
    audit::record(
        state,
        NewAudit {
            actor_id: Some(&user.id),
            actor_email: Some(user.email.as_str()),
            action: "sso.token_refreshed",
            target_type: Some("oauth_client"),
            target_id: Some(&client.id),
            ip_address: client_info.ip.as_deref(),
            user_agent: client_info.user_agent.as_deref(),
            metadata: Some(serde_json::json!({
                "grant_type": "refresh_token",
                "client_id": client.client_id,
                "scopes": scopes,
            })),
        },
    )
    .await;

    Ok(tokens)
}

async fn client_credentials(
    state: &AppState,
    form: &TokenRequestForm,
    basic: Option<&(String, String)>,
    client_info: &ClientInfo,
) -> OAuthResult<TokenResponse> {
    let client = authenticated_client(
        state,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        basic,
    )
    .await?;

    let allowed = client.allowed_scopes();
    let scopes = match form.scope.as_deref() {
        Some(requested) if !requested.trim().is_empty() => {
            let asked = parse_scopes(requested);
            let granted = scope_subset(&asked, &allowed);
            if granted.len() != asked.len() {
                return Err(OAuthError::invalid_scope(
                    "One or more requested scopes are not allowed for this application",
                ));
            }
            granted
        }
        _ => allowed,
    };
    if scopes.is_empty() {
        return Err(OAuthError::invalid_scope(
            "This application has no scopes configured",
        ));
    }

    let now = Utc::now().timestamp();
    let exp = now + state.config.sso.access_ttl.as_secs() as i64;
    let claims = SsoClaims {
        iss: state.sso.issuer().to_string(),
        sub: format!("client:{}", client.client_id),
        aud: client.client_id.clone(),
        azp: client.client_id.clone(),
        scope: scope_string(&scopes),
        typ: "sso".to_string(),
        jti: uuid::Uuid::new_v4().to_string(),
        iat: now,
        exp,
        email: None,
        name: Some(client.name.clone()),
        role: Some("service".to_string()),
    };
    let access_token = state.sso.sign(&claims)?;

    oauth_clients::touch(&state.pool, &client.id).await?;
    audit::record(
        state,
        NewAudit {
            actor_id: None,
            actor_email: None,
            action: "sso.token_issued",
            target_type: Some("oauth_client"),
            target_id: Some(&client.id),
            ip_address: client_info.ip.as_deref(),
            user_agent: client_info.user_agent.as_deref(),
            metadata: Some(serde_json::json!({
                "grant_type": "client_credentials",
                "client_id": client.client_id,
                "scopes": scopes,
            })),
        },
    )
    .await;

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.config.sso.access_ttl.as_secs() as i64,
        scope: scope_string(&scopes),
        refresh_token: None,
        id_token: None,
    })
}

/// Signs an access token (+ optional id_token and refresh token) for a user.
async fn issue_user_tokens(
    state: &AppState,
    client: &ClientRow,
    user: &UserRow,
    scopes: &[String],
    previous_refresh_id: Option<&str>,
) -> OAuthResult<TokenResponse> {
    let now = Utc::now().timestamp();
    let exp = now + state.config.sso.access_ttl.as_secs() as i64;
    let include_profile = scopes.iter().any(|scope| scope == "profile");

    let mut claims = SsoClaims {
        iss: state.sso.issuer().to_string(),
        sub: user.id.clone(),
        aud: client.client_id.clone(),
        azp: client.client_id.clone(),
        scope: scope_string(scopes),
        typ: "sso".to_string(),
        jti: uuid::Uuid::new_v4().to_string(),
        iat: now,
        exp,
        email: Some(user.email.clone()),
        name: if include_profile {
            user.full_name.clone()
        } else {
            None
        },
        role: if include_profile {
            Some(user.role.as_str().to_string())
        } else {
            None
        },
    };
    let access_token = state.sso.sign(&claims)?;

    let id_token = if scopes.iter().any(|scope| scope == "openid") {
        claims.typ = "id".to_string();
        claims.jti = uuid::Uuid::new_v4().to_string();
        Some(state.sso.sign(&claims)?)
    } else {
        None
    };

    let refresh_token = format!("rt_{}", crate::security::tokens::random_token());
    let refresh_id = uuid::Uuid::new_v4().to_string();
    let refresh_exp = now + state.config.sso.refresh_ttl.as_secs() as i64;
    oauth_flow::insert_refresh(
        &state.pool,
        &NewRefreshToken {
            id: &refresh_id,
            token_hash: &crate::security::tokens::sha256_hex(&refresh_token),
            client_id: &client.id,
            user_id: &user.id,
            scopes,
            expires_at: refresh_exp,
        },
    )
    .await?;

    if let Some(previous) = previous_refresh_id {
        oauth_flow::revoke_refresh(&state.pool, previous, Some(&refresh_id)).await?;
    }

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.config.sso.access_ttl.as_secs() as i64,
        scope: scope_string(scopes),
        refresh_token: Some(refresh_token),
        id_token,
    })
}

// ---------------------------------------------------------------------------
// Introspection / revocation / userinfo
// ---------------------------------------------------------------------------

pub async fn introspect(
    state: &AppState,
    form: IntrospectRequest,
    basic: Option<(String, String)>,
) -> OAuthResult<IntrospectResponse> {
    let client = authenticated_client(
        state,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        basic.as_ref(),
    )
    .await?;

    let token = form.token.trim();
    if token.is_empty() {
        return Err(OAuthError::invalid_request("token is required"));
    }

    if let Ok(claims) = state.sso.verify(token) {
        if claims.aud != client.client_id {
            // Do not leak whether another application's token is valid.
            return Ok(IntrospectResponse {
                active: false,
                ..Default::default()
            });
        }
        if oauth_flow::is_jti_revoked(&state.pool, &claims.jti).await? {
            return Ok(IntrospectResponse {
                active: false,
                ..Default::default()
            });
        }
        let username = if let Some(sub) = claims.sub.strip_prefix("client:") {
            Some(sub.to_string())
        } else {
            users::find_by_id(&state.pool, &claims.sub)
                .await?
                .map(|user| user.email)
        };

        return Ok(IntrospectResponse {
            active: true,
            scope: Some(claims.scope.clone()),
            client_id: Some(claims.aud.clone()),
            username,
            token_type: Some("Bearer".to_string()),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            sub: Some(claims.sub.clone()),
            aud: Some(claims.aud.clone()),
            iss: Some(claims.iss.clone()),
            jti: Some(claims.jti.clone()),
        });
    }

    // Opaque refresh token?
    if let Some(row) =
        oauth_flow::find_refresh(&state.pool, &crate::security::tokens::sha256_hex(token)).await?
    {
        if row.client_id != client.id
            || row.revoked_at.is_some()
            || row.expires_at <= Utc::now().timestamp()
        {
            return Ok(IntrospectResponse {
                active: false,
                ..Default::default()
            });
        }
        let username = users::find_by_id(&state.pool, &row.user_id)
            .await?
            .map(|user| user.email);
        return Ok(IntrospectResponse {
            active: true,
            scope: Some(scope_string(&row.scopes())),
            client_id: Some(client.client_id.clone()),
            username,
            token_type: Some("refresh_token".to_string()),
            exp: Some(row.expires_at),
            iat: Some(row.created_at),
            sub: Some(row.user_id.clone()),
            aud: Some(client.client_id.clone()),
            iss: Some(state.sso.issuer().to_string()),
            jti: Some(row.id.clone()),
        });
    }

    Ok(IntrospectResponse {
        active: false,
        ..Default::default()
    })
}

pub async fn revoke(
    state: &AppState,
    form: RevokeRequest,
    basic: Option<(String, String)>,
) -> OAuthResult<()> {
    let client = authenticated_client(
        state,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        basic.as_ref(),
    )
    .await?;

    let token = form.token.trim();
    if token.is_empty() {
        return Err(OAuthError::invalid_request("token is required"));
    }

    if let Ok(claims) = state.sso.verify(token) {
        if claims.aud == client.client_id {
            oauth_flow::revoke_jti(&state.pool, &claims.jti, claims.exp, "client request").await?;
        }
        return Ok(());
    }

    if let Some(row) =
        oauth_flow::find_refresh(&state.pool, &crate::security::tokens::sha256_hex(token)).await?
    {
        if row.client_id == client.id {
            oauth_flow::revoke_refresh(&state.pool, &row.id, None).await?;
        }
    }

    // RFC 7009: unknown tokens are not an error.
    Ok(())
}

pub async fn userinfo(state: &AppState, bearer: &str) -> OAuthResult<UserInfoResponse> {
    let claims = state
        .sso
        .verify(bearer)
        .map_err(|_| OAuthError::invalid_token("The access token is invalid or has expired"))?;

    if claims.is_machine_token() {
        return Err(OAuthError::invalid_token(
            "Machine tokens have no userinfo; use introspection instead",
        ));
    }
    if oauth_flow::is_jti_revoked(&state.pool, &claims.jti).await? {
        return Err(OAuthError::invalid_token("The access token was revoked"));
    }

    let user = users::find_by_id(&state.pool, &claims.sub)
        .await?
        .ok_or_else(|| OAuthError::invalid_token("The user no longer exists"))?;
    if !user.is_active() {
        return Err(OAuthError::invalid_token("The user account is not active"));
    }

    let scopes = claims.scopes();
    let wants_email = scopes
        .iter()
        .any(|scope| scope == "email" || scope == "openid");
    let wants_profile = scopes.iter().any(|scope| scope == "profile");

    let sub = user.id.clone();
    Ok(UserInfoResponse {
        sub,
        email: wants_email.then(|| user.email.clone()),
        email_verified: wants_email.then(|| user.is_email_verified()),
        name: wants_profile.then(|| user.full_name.clone()).flatten(),
        role: wants_profile.then(|| user.role.as_str().to_string()),
        scopes,
        client_id: claims.aud,
    })
}

/// Kills every machine credential of an application (disable/delete path).
///
/// Access tokens that were already signed stay valid until they expire; the
/// default lifetime is one hour, which is the trade-off for stateless JWTs.
pub async fn revoke_client_credentials(
    state: &AppState,
    client_pk_id: &str,
    reason: &str,
) -> ApiResult<()> {
    let refresh = oauth_flow::revoke_refresh_for_client_all(&state.pool, client_pk_id).await?;
    let keys = oauth_clients::revoke_all_keys(&state.pool, client_pk_id).await?;
    tracing::info!(
        client = %client_pk_id,
        refresh_tokens = refresh,
        api_keys = keys,
        reason,
        "SSO: application credentials revoked"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// API-key protected endpoints
// ---------------------------------------------------------------------------

pub async fn app_me(state: &AppState, api: &ApiClient) -> ApiResult<AppMeResponse> {
    let _ = state;
    let client = &api.client;
    Ok(AppMeResponse {
        client: ClientSummary {
            client_id: client.client_id.clone(),
            name: client.name.clone(),
            description: client.description.clone(),
            client_type: client.client_type,
        },
        allowed_scopes: client.allowed_scopes(),
        key_name: api.key.name.clone(),
        key_prefix: api.key.key_prefix.clone(),
        key_scopes: api.key.scopes(),
        environment: api.key.environment.clone(),
        expires_at: api.key.expires_at.map(db::users::ts_to_datetime),
        last_used_at: api.key.last_used_at.map(db::users::ts_to_datetime),
    })
}

pub async fn app_list_users(
    state: &AppState,
    api: &ApiClient,
    page: u32,
    per_page: u32,
) -> ApiResult<crate::response::Page<UserDto>> {
    api.require_scope("users:read")?;
    let page = page.max(1);
    let offset = ((page - 1) as i64) * per_page as i64;
    let (rows, total) = users::list(
        &state.pool,
        &users::UserFilter::default(),
        per_page as i64,
        offset,
    )
    .await?;
    let items = rows.iter().map(UserDto::from_row).collect();
    Ok(crate::response::Page::new(items, page, per_page, total))
}

pub async fn app_get_user(state: &AppState, api: &ApiClient, user_id: &str) -> ApiResult<UserDto> {
    api.require_scope("users:read")?;
    let user = users::find_by_id(&state.pool, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("User not found"))?;
    let two_factor = db::two_factor::is_enabled(&state.pool, &user.id).await?;
    Ok(UserDto::from_parts(&user, two_factor))
}

/// Introspection for API-key holders. Scoped to the calling application: an
/// application can never introspect a token that belongs to someone else.
pub async fn app_introspect(
    state: &AppState,
    api: &ApiClient,
    payload: AppIntrospectRequest,
) -> ApiResult<IntrospectResponse> {
    api.require_scope("tokens:verify")?;
    let token = payload.token.trim().to_string();
    if token.is_empty() {
        return Err(ApiError::field("token", "must not be empty"));
    }

    let Ok(claims) = state.sso.verify(&token) else {
        return Ok(IntrospectResponse {
            active: false,
            ..Default::default()
        });
    };

    if claims.aud != api.client.client_id
        || oauth_flow::is_jti_revoked(&state.pool, &claims.jti).await?
    {
        return Ok(IntrospectResponse {
            active: false,
            ..Default::default()
        });
    }

    let username = if let Some(client) = claims.sub.strip_prefix("client:") {
        Some(client.to_string())
    } else {
        users::find_by_id(&state.pool, &claims.sub)
            .await?
            .map(|user| user.email)
    };

    Ok(IntrospectResponse {
        active: true,
        scope: Some(claims.scope.clone()),
        client_id: Some(claims.aud.clone()),
        username,
        token_type: Some("Bearer".to_string()),
        exp: Some(claims.exp),
        iat: Some(claims.iat),
        sub: Some(claims.sub.clone()),
        aud: Some(claims.aud.clone()),
        iss: Some(claims.iss.clone()),
        jti: Some(claims.jti.clone()),
    })
}
