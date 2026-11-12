use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use rust_auth_api::{build_router, config::Config, db, AppState};

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let config = Config::from_env().context("invalid configuration")?;
    let addr = config.bind_addr()?;
    let environment = format!("{:?}", config.env);

    let state = AppState::bootstrap(config).await?;
    spawn_maintenance(state.clone());

    let app = build_router(state.clone());
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("cannot bind {addr}"))?;

    tracing::info!(
        service = %state.config.app_name,
        environment = %environment,
        address = %addr,
        docs = if state.config.swagger_enabled { "/docs" } else { "disabled" },
        "listening"
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server error")?;

    tracing::info!("shutdown complete");
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=debug,sqlx=warn,rust_auth_api=debug"));

    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_level(true),
        )
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("Ctrl+C received, shutting down"),
        _ = terminate => tracing::info!("SIGTERM received, shutting down"),
    }
}

/// Hourly housekeeping: drop expired sessions so the table stays small.
fn spawn_maintenance(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(3600));
        ticker.tick().await; // the first tick completes immediately
        loop {
            ticker.tick().await;
            match db::sessions::purge_expired(&state.pool).await {
                Ok(0) => tracing::debug!("session cleanup: nothing to purge"),
                Ok(rows) => tracing::info!(rows, "session cleanup: purged expired sessions"),
                Err(error) => tracing::warn!(%error, "session cleanup failed"),
            }
            // SSO artefacts: expired authorization codes, dead refresh tokens and
            // JWTs whose expiry has passed no longer need to sit in the denylist.
            match db::oauth_flow::purge_expired(&state.pool).await {
                Ok(0) => tracing::debug!("sso cleanup: nothing to purge"),
                Ok(rows) => tracing::info!(rows, "sso cleanup: purged expired SSO artefacts"),
                Err(error) => tracing::warn!(%error, "sso cleanup failed"),
            }
        }
    });
}
