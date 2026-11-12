//! Audit-trail helper. Failing to write an audit entry must never fail the
//! business operation, so errors are logged and swallowed.

use crate::{
    db::audit::{self, NewAudit},
    state::AppState,
};

pub async fn record(state: &AppState, entry: NewAudit<'_>) {
    if let Err(error) = audit::insert(&state.pool, &entry).await {
        tracing::warn!(error = %error, action = entry.action, "failed to write audit log");
    }
}
