//! Uniform error type for every handler. Errors are rendered as
//! `{"success": false, "error": {"code": "...", "message": "...", "details": [...]}}`
//! with a stable machine readable `code` so clients never have to parse prose.

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FieldIssue {
    pub field: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ErrorDetail {
    /// Stable, machine readable error identifier (e.g. `INVALID_CREDENTIALS`).
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<FieldIssue>>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub success: bool,
    pub error: ErrorDetail,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{code}: {message}")]
    Client {
        status: StatusCode,
        code: &'static str,
        message: String,
        details: Option<Vec<FieldIssue>>,
        retry_after: Option<u64>,
    },
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        ApiError::Client {
            status,
            code,
            message: message.into(),
            details: None,
            retry_after: None,
        }
    }

    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    pub fn validation(details: Vec<FieldIssue>) -> Self {
        ApiError::Client {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "VALIDATION_ERROR",
            message: "One or more fields are invalid".to_string(),
            details: Some(details),
            retry_after: None,
        }
    }

    pub fn field(field: &str, message: impl Into<String>) -> Self {
        Self::validation(vec![FieldIssue {
            field: field.to_string(),
            message: message.into(),
        }])
    }

    pub fn unauthorized(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code, message)
    }

    pub fn invalid_credentials() -> Self {
        Self::unauthorized("INVALID_CREDENTIALS", "Email or password is incorrect")
    }

    pub fn unauthenticated(message: impl Into<String>) -> Self {
        Self::unauthorized("UNAUTHENTICATED", message)
    }

    pub fn token_expired() -> Self {
        Self::unauthorized("TOKEN_EXPIRED", "The access token has expired")
    }

    pub fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "NOT_FOUND", message)
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    pub fn email_taken() -> Self {
        Self::conflict(
            "EMAIL_ALREADY_EXISTS",
            "An account with this email already exists",
        )
    }

    pub fn locked(message: impl Into<String>, retry_after: Option<u64>) -> Self {
        ApiError::Client {
            status: StatusCode::LOCKED,
            code: "ACCOUNT_LOCKED",
            message: message.into(),
            details: None,
            retry_after,
        }
    }

    pub fn rate_limited(retry_after: u64) -> Self {
        ApiError::Client {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "RATE_LIMITED",
            message: "Too many requests; slow down and retry later".to_string(),
            details: None,
            retry_after: Some(retry_after.max(1)),
        }
    }

    pub fn internal(err: impl Into<anyhow::Error>) -> Self {
        ApiError::Internal(err.into())
    }

    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::Client { status, .. } => *status,
            ApiError::Internal(_) | ApiError::Database(_) | ApiError::Jwt(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    pub fn code(&self) -> &str {
        match self {
            ApiError::Client { code, .. } => code,
            ApiError::Internal(_) => "INTERNAL_ERROR",
            ApiError::Database(_) => "DATABASE_ERROR",
            ApiError::Jwt(_) => "INVALID_TOKEN",
        }
    }

    fn into_parts(self) -> (StatusCode, ErrorDetail, Option<u64>) {
        match self {
            ApiError::Client {
                status,
                code,
                message,
                details,
                retry_after,
            } => (
                status,
                ErrorDetail {
                    code: code.to_string(),
                    message,
                    details,
                },
                retry_after,
            ),
            other => {
                // Never leak internal details to clients; log them instead.
                tracing::error!(error = %other, "unhandled internal error");
                let (code, message) = match &other {
                    ApiError::Database(sqlx::Error::RowNotFound) => {
                        ("NOT_FOUND", "Resource not found".to_string())
                    }
                    ApiError::Jwt(_) => (
                        "INVALID_TOKEN",
                        "The token is invalid or malformed".to_string(),
                    ),
                    _ => ("INTERNAL_ERROR", "An unexpected error occurred".to_string()),
                };
                (
                    if matches!(&other, ApiError::Database(sqlx::Error::RowNotFound)) {
                        StatusCode::NOT_FOUND
                    } else {
                        StatusCode::INTERNAL_SERVER_ERROR
                    },
                    ErrorDetail {
                        code: code.to_string(),
                        message,
                        details: None,
                    },
                    None,
                )
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, detail, retry_after) = self.into_parts();
        let body = Json(ErrorResponse {
            success: false,
            error: detail,
        });
        let mut response = (status, body).into_response();
        if let Some(seconds) = retry_after {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from_str(&seconds.to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("60")),
            );
        }
        response
    }
}

/// Convenience: any `anyhow::Error` becomes a 500 while keeping the `?` operator
/// ergonomic inside services.
impl From<validator::ValidationErrors> for ApiError {
    fn from(errors: validator::ValidationErrors) -> Self {
        let mut issues = Vec::new();
        for (field, errs) in errors.field_errors() {
            for err in errs {
                let message = err
                    .message
                    .as_ref()
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| format!("{} is invalid", field));
                issues.push(FieldIssue {
                    field: field.to_string(),
                    message,
                });
            }
        }
        if issues.is_empty() {
            ApiError::bad_request("VALIDATION_ERROR", "The request body is invalid")
        } else {
            ApiError::validation(issues)
        }
    }
}
