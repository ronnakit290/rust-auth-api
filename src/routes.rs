//! Router assembly. Every route the service exposes is declared here.

use std::time::Duration;

use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderName, HeaderValue, Method},
    middleware::{from_fn, from_fn_with_state},
    routing::{delete, get, post},
    Router,
};
use tower_http::{
    compression::CompressionLayer, cors::CorsLayer, timeout::TimeoutLayer, trace::TraceLayer,
};
use utoipa::OpenApi;

use crate::{
    config::EmailMode,
    handlers,
    middleware::{
        global_rate_limit, not_found, request_id, security_headers, sso_rate_limit,
        ProductionFlag,
    },
    openapi::ApiDoc,
    state::AppState,
};

pub fn build_router(state: AppState) -> Router {
    let swagger_enabled = state.config.swagger_enabled;
    let production = state.is_production();
    let cors = build_cors(&state);

    let router = Router::new()
        // ---- probes ------------------------------------------------------
        .route("/healthz", get(handlers::health::healthz))
        .route("/readyz", get(handlers::health::readyz))
        // ---- auth (public) -----------------------------------------------
        .route("/api/v1/meta", get(handlers::health::meta))
        .route("/api/v1/auth/register", post(handlers::auth::register))
        .route("/api/v1/auth/login", post(handlers::auth::login))
        .route("/api/v1/auth/refresh", post(handlers::auth::refresh))
        .route("/api/v1/auth/2fa/verify", post(handlers::auth::verify_mfa))
        .route(
            "/api/v1/auth/forgot-password",
            post(handlers::auth::forgot_password),
        )
        .route(
            "/api/v1/auth/reset-password",
            post(handlers::auth::reset_password),
        )
        .route(
            "/api/v1/auth/verify-email",
            post(handlers::auth::verify_email),
        )
        .route(
            "/api/v1/auth/resend-verification",
            post(handlers::auth::resend_verification),
        )
        // ---- auth (protected) --------------------------------------------
        .route("/api/v1/auth/logout", post(handlers::auth::logout))
        // ---- profile -----------------------------------------------------
        .route(
            "/api/v1/users/me",
            get(handlers::users::me).patch(handlers::users::update_me),
        )
        .route(
            "/api/v1/users/me/deactivate",
            post(handlers::users::delete_me),
        )
        .route(
            "/api/v1/users/me/change-password",
            post(handlers::users::change_password),
        )
        // ---- sessions ----------------------------------------------------
        .route(
            "/api/v1/users/me/sessions",
            get(handlers::sessions::list).delete(handlers::sessions::revoke_all),
        )
        .route(
            "/api/v1/users/me/sessions/{session_id}",
            delete(handlers::sessions::revoke),
        )
        // ---- two factor --------------------------------------------------
        .route("/api/v1/2fa", get(handlers::two_factor::status))
        .route("/api/v1/2fa/setup", post(handlers::two_factor::setup))
        .route("/api/v1/2fa/enable", post(handlers::two_factor::enable))
        .route("/api/v1/2fa/disable", post(handlers::two_factor::disable))
        .route(
            "/api/v1/2fa/recovery-codes",
            post(handlers::two_factor::regenerate_recovery_codes),
        )
        // ---- admin -------------------------------------------------------
        .route("/api/v1/admin/users", get(handlers::admin::list_users))
        .route(
            "/api/v1/admin/users/{user_id}",
            get(handlers::admin::get_user)
                .patch(handlers::admin::update_user)
                .delete(handlers::admin::delete_user),
        )
        .route(
            "/api/v1/admin/users/{user_id}/sessions/revoke",
            post(handlers::admin::revoke_user_sessions),
        )
        .route("/api/v1/admin/audit-logs", get(handlers::admin::audit_logs))
        .route("/api/v1/admin/stats", get(handlers::admin::stats))
        // ---- SSO: discovery + protocol -----------------------------------
        .route(
            "/.well-known/openid-configuration",
            get(handlers::sso::discovery),
        )
        .route("/.well-known/jwks.json", get(handlers::sso::jwks))
        .route(
            "/oauth/authorize/info",
            get(handlers::sso::authorize_info),
        )
        .route("/oauth/authorize", post(handlers::sso::authorize))
        .route("/oauth/token", post(handlers::sso::token))
        .route("/oauth/introspect", post(handlers::sso::introspect))
        .route("/oauth/revoke", post(handlers::sso::revoke))
        .route("/oauth/userinfo", get(handlers::sso::userinfo))
        // ---- SSO admin: applications + app keys --------------------------
        .route(
            "/api/v1/admin/clients",
            get(handlers::clients::list_clients).post(handlers::clients::create_client),
        )
        .route(
            "/api/v1/admin/clients/{client_ref}",
            get(handlers::clients::get_client)
                .patch(handlers::clients::update_client)
                .delete(handlers::clients::delete_client),
        )
        .route(
            "/api/v1/admin/clients/{client_ref}/secret/rotate",
            post(handlers::clients::rotate_client_secret),
        )
        .route(
            "/api/v1/admin/clients/{client_ref}/keys",
            get(handlers::clients::list_keys).post(handlers::clients::create_key),
        )
        .route(
            "/api/v1/admin/clients/{client_ref}/keys/{key_id}",
            delete(handlers::clients::revoke_key),
        )
        .route(
            "/api/v1/admin/clients/{client_ref}/keys/{key_id}/rotate",
            post(handlers::clients::rotate_key),
        )
        // ---- SSO: app-key protected ("other systems connect here") -------
        .route("/api/v1/app/me", get(handlers::sso::app_me))
        .route("/api/v1/app/users", get(handlers::sso::app_users))
        .route("/api/v1/app/users/{user_id}", get(handlers::sso::app_user))
        .route("/api/v1/app/introspect", post(handlers::sso::app_introspect));

    // Development-only mailbox inspector.
    let router = if state.config.email.mode == EmailMode::Console && !production {
        router
            .route(
                "/api/v1/dev/outbox",
                get(handlers::dev::outbox).delete(handlers::dev::clear_outbox),
            )
            .route("/api/v1/dev/outbox/{email}", get(handlers::dev::latest_for))
    } else {
        router
    };

    let router = router
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(CompressionLayer::new())
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(from_fn_with_state(state.clone(), global_rate_limit))
        .layer(from_fn_with_state(state.clone(), sso_rate_limit))
        .layer(from_fn(security_headers))
        .layer(from_fn(request_id))
        .layer(axum::Extension(ProductionFlag(production)))
        .with_state(state);

    if swagger_enabled {
        router.merge(
            utoipa_swagger_ui::SwaggerUi::new("/docs")
                .url("/api-docs/openapi.json", ApiDoc::openapi()),
        )
    } else {
        router
    }
}

fn build_cors(state: &AppState) -> CorsLayer {
    let mut layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::USER_AGENT,
            HeaderName::from_static("x-request-id"),
            HeaderName::from_static("x-api-key"),
            HeaderName::from_static("x-app-key"),
        ])
        .expose_headers([HeaderName::from_static("x-request-id"), header::RETRY_AFTER])
        .max_age(Duration::from_secs(3600));

    let origins: Vec<HeaderValue> = state
        .config
        .cors_origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect();

    if state.config.cors_origins.iter().any(|origin| origin == "*") {
        layer = layer.allow_origin(tower_http::cors::Any);
    } else if !origins.is_empty() {
        layer = layer.allow_origin(origins);
    }

    layer
}
