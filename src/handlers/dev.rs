//! Development-only inspection endpoints.
//!
//! Mounted only when `EMAIL_MODE=console` and `APP_ENV` is not production, so a
//! deployed service can never leak verification or reset tokens.

use axum::{extract::State, response::IntoResponse, Json};
use serde_json::json;

use crate::{error::ApiError, response::ok, services::email::OutboxMessage, state::AppState};

pub async fn outbox(State(state): State<AppState>) -> impl IntoResponse {
    Json(ok(state.emails.outbox()))
}

pub async fn clear_outbox(State(state): State<AppState>) -> impl IntoResponse {
    state.emails.clear_outbox();
    Json(ok(json!({ "cleared": true })))
}

/// Returns the newest message for an address, which keeps smoke tests short.
pub async fn latest_for(
    State(state): State<AppState>,
    axum::extract::Path(email): axum::extract::Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let target = email.trim().to_ascii_lowercase();
    let messages: Vec<OutboxMessage> = state
        .emails
        .outbox()
        .into_iter()
        .filter(|message| message.to.to_ascii_lowercase() == target)
        .collect();
    Ok(Json(ok(messages)))
}
