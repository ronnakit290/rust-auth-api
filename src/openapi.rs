//! The OpenAPI document served at `/api-docs/openapi.json` and rendered by
//! Swagger UI at `/docs`.

use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};

use crate::{
    db::{
        audit::AuditRow,
        oauth_clients::{ClientStatus, ClientType},
        users::{AdminStats, Role, UserStatus},
    },
    dto::*,
    error::{ErrorDetail, ErrorResponse, FieldIssue},
    handlers,
    handlers::health::{HealthResponse, MetaFeatures, MetaResponse, MetaTokens, ReadinessResponse},
    services::email::OutboxMessage,
};

pub struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "api_key",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("app-key")
                        .description(Some(
                            "Application key from /api/v1/admin/clients/{id}/keys, sent as X-API-Key",
                        ))
                        .build(),
                ),
            );
            components.add_security_scheme(
                "sso_bearer",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some(
                            "Access token issued by /oauth/token (RS256, verify with the JWKS)",
                        ))
                        .build(),
                ),
            );
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some("Access token from /api/v1/auth/login"))
                        .build(),
                ),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Rust Auth API",
        version = "0.1.0",
        description = "A complete authentication and user-management API: JWT access tokens, rotating refresh tokens with reuse detection, e-mail verification, password reset, TOTP two-factor with recovery codes, session management, RBAC and an audit trail.\n\nAll responses are wrapped in `{ \"success\": true, \"data\": ... }`; errors use `{ \"success\": false, \"error\": { \"code\", \"message\", \"details\" } }`.",
        contact(name = "Nisia Studio")
    ),
    servers(
        (url = "http://localhost:8080", description = "Local development")
    ),
    tags(
        (name = "auth", description = "Registration, login, token rotation, verification and password reset"),
        (name = "users", description = "Current user profile"),
        (name = "sessions", description = "Active session management"),
        (name = "2fa", description = "TOTP two-factor authentication"),
        (name = "admin", description = "User administration, audit trail and statistics"),
        (name = "health", description = "Probes and service metadata"),
        (name = "sso", description = "Central SSO: discovery, JWKS, authorize, token, introspect, revoke, userinfo"),
        (name = "sso-admin", description = "Register applications and issue app keys for other systems"),
        (name = "app", description = "Endpoints consumed by integrated systems using an app key")
    ),
    paths(
        handlers::auth::register,
        handlers::auth::login,
        handlers::auth::verify_mfa,
        handlers::auth::refresh,
        handlers::auth::logout,
        handlers::auth::forgot_password,
        handlers::auth::reset_password,
        handlers::auth::verify_email,
        handlers::auth::resend_verification,
        handlers::users::me,
        handlers::users::update_me,
        handlers::users::change_password,
        handlers::users::delete_me,
        handlers::sessions::list,
        handlers::sessions::revoke,
        handlers::sessions::revoke_all,
        handlers::two_factor::status,
        handlers::two_factor::setup,
        handlers::two_factor::enable,
        handlers::two_factor::disable,
        handlers::two_factor::regenerate_recovery_codes,
        handlers::admin::list_users,
        handlers::admin::get_user,
        handlers::admin::update_user,
        handlers::admin::delete_user,
        handlers::admin::revoke_user_sessions,
        handlers::admin::audit_logs,
        handlers::admin::stats,
        handlers::health::healthz,
        handlers::health::readyz,
        handlers::health::meta,
        handlers::sso::discovery,
        handlers::sso::jwks,
        handlers::sso::authorize_info,
        handlers::sso::authorize,
        handlers::sso::token,
        handlers::sso::introspect,
        handlers::sso::revoke,
        handlers::sso::userinfo,
        handlers::sso::app_me,
        handlers::sso::app_users,
        handlers::sso::app_user,
        handlers::sso::app_introspect,
        handlers::clients::list_clients,
        handlers::clients::create_client,
        handlers::clients::get_client,
        handlers::clients::update_client,
        handlers::clients::delete_client,
        handlers::clients::rotate_client_secret,
        handlers::clients::list_keys,
        handlers::clients::create_key,
        handlers::clients::revoke_key,
        handlers::clients::rotate_key
    ),
    components(schemas(
        RegisterRequest,
        LoginRequest,
        MfaVerifyRequest,
        RefreshRequest,
        LogoutRequest,
        ForgotPasswordRequest,
        ResetPasswordRequest,
        VerifyEmailRequest,
        ResendVerificationRequest,
        UpdateProfileRequest,
        ChangePasswordRequest,
        DeleteAccountRequest,
        EnableTwoFactorRequest,
        DisableTwoFactorRequest,
        RegenerateRecoveryCodesRequest,
        AdminUpdateUserRequest,
        ListUsersQuery,
        AuditLogQuery,
        DeleteUserQuery,
        AdminSessionsQuery,
        PaginationQuery,
        UserDto,
        SessionDto,
        SessionsResponse,
        TokenPair,
        AuthResponse,
        LoginResponse,
        RegisterResponse,
        ForgotPasswordResponse,
        LogoutResponse,
        DebugToken,
        TwoFactorSetupResponse,
        EnableTwoFactorResponse,
        RecoveryCodesResponse,
        TwoFactorStatusResponse,
        UpdateProfileResponse,
        RevokedSessionsResponse,
        AuditLogDto,
        AdminStatsResponse,
        AdminUserResponse,
        MessageResponse,
        ErrorResponse,
        ErrorDetail,
        FieldIssue,
        Role,
        UserStatus,
        AuditRow,
        AdminStats,
        HealthResponse,
        ReadinessResponse,
        MetaResponse,
        MetaFeatures,
        MetaTokens,
        OutboxMessage,
        // SSO
        CreateClientRequest,
        UpdateClientRequest,
        ClientDto,
        ClientCreatedResponse,
        RotateSecretResponse,
        ListClientsQuery,
        CreateApiKeyRequest,
        ApiKeyDto,
        ApiKeyCreatedResponse,
        ClientSummary,
        AuthorizeQuery,
        AuthorizeInfoResponse,
        AuthorizeResponse,
        TokenRequestForm,
        TokenResponse,
        IntrospectRequest,
        IntrospectResponse,
        RevokeRequest,
        UserInfoResponse,
        AppMeResponse,
        AppIntrospectRequest,
        JwksResponse,
        DiscoveryResponse,
        ClientType,
        ClientStatus
    )),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;
