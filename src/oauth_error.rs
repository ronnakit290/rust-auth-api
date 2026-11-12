//! RFC 6749 / RFC 7662 error payloads.
//!
//! The rest of the API uses the `{success:false,error:{...}}` envelope, but the
//! OAuth2 endpoints speak the standard `{"error":"invalid_grant", ...}` shape so
//! that off-the-shelf OAuth clients (passport, oauthlib, spring-security, …)
//! understand them without a custom adapter.

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::error::ApiError;

#[derive(Debug, Serialize)]
pub struct OAuthErrorBody {
    pub error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("{error}: {description}")]
pub struct OAuthError {
    pub status: StatusCode,
    pub error: &'static str,
    pub description: String,
    pub www_authenticate: Option<String>,
}

pub type OAuthResult<T> = Result<T, OAuthError>;

impl OAuthError {
    pub fn new(status: StatusCode, error: &'static str, description: impl Into<String>) -> Self {
        OAuthError {
            status,
            error,
            description: description.into(),
            www_authenticate: None,
        }
    }

    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", description)
    }

    pub fn invalid_client(description: impl Into<String>) -> Self {
        let mut error = Self::new(StatusCode::UNAUTHORIZED, "invalid_client", description);
        error.www_authenticate = Some("Basic realm=\"sso\"".to_string());
        error
    }

    pub fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_grant", description)
    }

    pub fn unauthorized_client(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "unauthorized_client", description)
    }

    pub fn unsupported_grant_type() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Supported grants: authorization_code, refresh_token, client_credentials",
        )
    }

    pub fn invalid_scope(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_scope", description)
    }

    pub fn invalid_token(description: impl Into<String>) -> Self {
        let mut error = Self::new(StatusCode::UNAUTHORIZED, "invalid_token", description);
        error.www_authenticate = Some("Bearer error=\"invalid_token\"".to_string());
        error
    }

    pub fn insufficient_scope(scope: &str) -> Self {
        let mut error = Self::new(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            format!("The token is missing the `{scope}` scope"),
        );
        error.www_authenticate = Some(format!(
            "Bearer error=\"insufficient_scope\", scope=\"{scope}\""
        ));
        error
    }

    pub fn server_error(error: impl std::fmt::Display) -> Self {
        tracing::error!(error = %error, "SSO request failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "The authorization server encountered an unexpected condition",
        )
    }
}

/// Lets the protocol services bubble up storage/validation failures while still
/// answering in the OAuth error shape.
impl From<ApiError> for OAuthError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::Client {
                status,
                code,
                message,
                details,
                ..
            } => {
                let description = match details {
                    Some(details) if !details.is_empty() => format!(
                        "{message}: {}",
                        details
                            .iter()
                            .map(|issue| format!("{} {}", issue.field, issue.message))
                            .collect::<Vec<_>>()
                            .join("; ")
                    ),
                    _ => message,
                };
                let slug = match code {
                    "TOKEN_EXPIRED" => "invalid_grant",
                    "UNAUTHENTICATED" | "INVALID_TOKEN" => "invalid_token",
                    "INVALID_CLIENT" => "invalid_client",
                    "FORBIDDEN" => "access_denied",
                    _ => "invalid_request",
                };
                let mut mapped = OAuthError::new(status, slug, description);
                if slug == "invalid_client" {
                    mapped.www_authenticate = Some("Basic realm=\"sso\"".to_string());
                }
                mapped
            }
            other => OAuthError::server_error(other),
        }
    }
}

impl From<sqlx::Error> for OAuthError {
    fn from(error: sqlx::Error) -> Self {
        OAuthError::server_error(error)
    }
}

impl From<anyhow::Error> for OAuthError {
    fn from(error: anyhow::Error) -> Self {
        OAuthError::server_error(error)
    }
}

impl From<jsonwebtoken::errors::Error> for OAuthError {
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        tracing::debug!(error = %error, "SSO token encoding failed");
        OAuthError::server_error(error)
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(OAuthErrorBody {
                error: self.error,
                error_description: Some(self.description),
            }),
        )
            .into_response();

        let headers = response.headers_mut();
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, no-cache, must-revalidate"),
        );
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        if let Some(value) = self.www_authenticate {
            if let Ok(value) = HeaderValue::from_str(&value) {
                headers.insert(header::WWW_AUTHENTICATE, value);
            }
        }
        response
    }
}
