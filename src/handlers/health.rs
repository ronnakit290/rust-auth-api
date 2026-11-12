//! Unauthenticated probes plus a small metadata endpoint.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{config::EmailMode, db, response::ok, state::AppState};

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub version: String,
    pub uptime_seconds: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReadinessResponse {
    pub status: String,
    pub database: String,
    pub version: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MetaResponse {
    pub service: String,
    pub version: String,
    pub environment: String,
    pub features: MetaFeatures,
    pub tokens: MetaTokens,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MetaFeatures {
    pub email_verification_required: bool,
    pub two_factor: bool,
    pub password_reset: bool,
    pub email_transport: String,
    pub swagger: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MetaTokens {
    pub access_ttl_seconds: u64,
    pub refresh_ttl_seconds: u64,
    pub mfa_ttl_seconds: u64,
    pub token_type: String,
}

#[utoipa::path(
    get,
    path = "/healthz",
    tag = "health",
    summary = "Liveness probe",
    responses((status = 200, body = HealthResponse))
)]
pub async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        service: state.config.app_name.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.started_at.elapsed().as_secs(),
    })
}

#[utoipa::path(
    get,
    path = "/readyz",
    tag = "health",
    summary = "Readiness probe (checks the database)",
    responses(
        (status = 200, body = ReadinessResponse),
        (status = 503, body = ReadinessResponse)
    )
)]
pub async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    let healthy = db::ping(&state.pool).await;
    let body = ReadinessResponse {
        status: if healthy { "ready" } else { "degraded" }.to_string(),
        database: if healthy { "up" } else { "down" }.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    if healthy {
        (StatusCode::OK, Json(body))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(body))
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/meta",
    tag = "health",
    summary = "Service metadata and capabilities",
    responses((status = 200, body = MetaResponse))
)]
pub async fn meta(State(state): State<AppState>) -> impl IntoResponse {
    Json(ok(MetaResponse {
        service: state.config.app_name.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        environment: match state.config.env {
            crate::config::Environment::Development => "development",
            crate::config::Environment::Test => "test",
            crate::config::Environment::Production => "production",
        }
        .to_string(),
        features: MetaFeatures {
            email_verification_required: state.config.security.require_email_verification,
            two_factor: true,
            password_reset: true,
            email_transport: match state.config.email.mode {
                EmailMode::Console => "console",
                EmailMode::Disabled => "disabled",
            }
            .to_string(),
            swagger: state.config.swagger_enabled,
        },
        tokens: MetaTokens {
            access_ttl_seconds: state.config.jwt.access_ttl.as_secs(),
            refresh_ttl_seconds: state.config.jwt.refresh_ttl.as_secs(),
            mfa_ttl_seconds: state.config.jwt.mfa_ttl.as_secs(),
            token_type: "Bearer".to_string(),
        },
    }))
}
