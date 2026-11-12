//! Cross-cutting HTTP middleware: request ids, security headers, global rate
//! limiting.

use std::net::SocketAddr;

use axum::{
    extract::{Request, State},
    http::{header, HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::{error::ApiError, state::AppState};

pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Accepts an inbound `x-request-id` (so traces survive a gateway hop) or
/// generates a fresh one; always echoes it back.
pub async fn request_id(mut request: Request, next: Next) -> Response {
    let inbound = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .map(|value| value.to_string());

    let id = inbound.unwrap_or_else(|| Uuid::new_v4().to_string());
    request.extensions_mut().insert(RequestId(id.clone()));

    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
    }
    response
}

#[derive(Debug, Clone)]
pub struct RequestId(pub String);

/// Hardening headers that are safe for a JSON API.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let is_production = request
        .extensions()
        .get::<ProductionFlag>()
        .map(|flag| flag.0)
        .unwrap_or(false);
    let is_api = request.uri().path().starts_with("/api/");

    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );
    if is_api {
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, private"),
        );
    }
    if is_production {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    response
}

/// Injected by the router so `security_headers` does not need access to state.
#[derive(Debug, Clone, Copy)]
pub struct ProductionFlag(pub bool);

/// Coarse global limiter; per-endpoint limits live in the handlers.
pub async fn global_rate_limit(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some((limit, window)) = state.config.security.global_rate_limit else {
        return next.run(request).await;
    };

    let path = request.uri().path();
    if path == "/healthz" || path == "/readyz" || path.starts_with("/docs") {
        return next.run(request).await;
    }

    let identity =
        client_ip(&request, state.config.trust_proxy).unwrap_or_else(|| "unknown".into());
    if let Err(retry_after) = state.limiter.check("global", &identity, limit, window) {
        return ApiError::rate_limited(retry_after).into_response();
    }
    next.run(request).await
}

/// Brute-forcing a client secret or a TOTP code is the realistic attack against
/// the token endpoint, so it gets its own, much tighter, per-IP budget.
pub async fn sso_rate_limit(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let guarded = matches!(path, "/oauth/token" | "/oauth/introspect" | "/oauth/revoke");
    if !guarded {
        return next.run(request).await;
    }

    let identity =
        client_ip(&request, state.config.trust_proxy).unwrap_or_else(|| "unknown".into());
    if let Err(retry_after) =
        state
            .limiter
            .check("sso", &identity, 60, std::time::Duration::from_secs(60))
    {
        tracing::warn!(ip = %identity, path, "SSO rate limit hit");
        return ApiError::rate_limited(retry_after).into_response();
    }
    next.run(request).await
}

pub fn client_ip(request: &Request, trust_proxy: bool) -> Option<String> {
    if trust_proxy {
        if let Some(forwarded) = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
        {
            let candidate = forwarded.trim();
            if !candidate.is_empty() {
                return Some(candidate.to_string());
            }
        }
    }
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string())
}

/// Terminal 404 for unknown routes so clients always receive the JSON envelope.
pub async fn not_found(request: Request) -> Response {
    let path = request.uri().path().to_string();
    let error = ApiError::new(
        StatusCode::NOT_FOUND,
        "ROUTE_NOT_FOUND",
        format!("No route matches {path}"),
    );
    error.into_response()
}
