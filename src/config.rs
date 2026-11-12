//! Configuration is read from the environment once at start-up and validated.
//! Nothing else in the code base reads `std::env` directly.

use std::{env, net::SocketAddr, str::FromStr, time::Duration};

use anyhow::{anyhow, bail, Context, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Test,
    Production,
}

impl Environment {
    pub fn is_production(self) -> bool {
        matches!(self, Environment::Production)
    }
}

impl FromStr for Environment {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "development" | "dev" | "local" => Ok(Environment::Development),
            "test" | "testing" => Ok(Environment::Test),
            "production" | "prod" => Ok(Environment::Production),
            other => bail!("unknown APP_ENV `{other}` (expected development|test|production)"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub issuer: String,
    pub audience: String,
    pub access_ttl: Duration,
    pub refresh_ttl: Duration,
    pub mfa_ttl: Duration,
    pub leeway: u64,
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub max_login_attempts: i64,
    pub lockout: Duration,
    pub password_min_len: usize,
    pub password_max_len: usize,
    pub require_email_verification: bool,
    pub verify_session_on_request: bool,
    pub login_rate_limit: u32,
    pub login_rate_window: Duration,
    pub register_rate_limit: u32,
    pub register_rate_window: Duration,
    pub reset_rate_limit: u32,
    pub reset_rate_window: Duration,
    pub global_rate_limit: Option<(u32, Duration)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailMode {
    /// Print e-mails to the tracing log and keep them in an in-memory outbox
    /// (`GET /api/v1/dev/outbox`, only mounted when enabled).
    Console,
    /// Drop e-mails silently (still logged at debug level).
    Disabled,
}

#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub mode: EmailMode,
    pub from: String,
    pub frontend_url: String,
    pub verify_ttl: Duration,
    pub reset_ttl: Duration,
}

/// Deterministic 2048-bit RSA key used only by the test suite so that every
/// in-memory app does not spend time on key generation.
#[cfg(test)]
const TEST_RSA_PRIVATE_KEY: &str = '-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCanTTyD41J+AKa\nxZmTWLSVvtQVKx5CMHCdtY3NjEFqRr+R4FC3TcJuc4zYZCNU2ZYb4q52AGjgcQhH\niI1tYfRZv5mugeLOtAiGx1x4dSEovKuHNI1qhx5zG11165+SM6qDj0/0javEqcYU\nMscq1CDkmEs+hH/gTsesj8550ZKI48pfJcK4L9rkwLk0Fc9TXXV68d/olwqXYNt8\nVdFhZX56SGQrzzRIabIcSr5tzLmgCuDJ9P4UVCSS9aatKefaWcmkb3jvIONep6yT\nthLDC9+ZBdvQWYBNK+yGq6hCjaH4XMxYF4IUcRVJ+r95wlmn8PrE7aGSjV0nA455\nt0Z7V3brAgMBAAECggEAag6qUdzfIz0vtDEVbqBrh0iWPEsOf4KwzU3LjpLGEHul\nTxBa7dI2LAOxOoI+RibXNBujZqhTSJngfwkpUj3eGm42oiDQjs+qBaHdSXe3HjWF\nR8KBuvAir/y2eHv/Qo+USJhW1T8U81st148ZVcSbJ5NcEe9btGb1yuX+UUuzw5fE\nmvY8LELQi26+CHAhGjzbcdZeCBHhONvT40tci3Tv0hlUDARD6tkXv5EkTmIFoPJk\ndGD1E6BibwCB//tP5oOIIFb+XUY80nIw+2ceR+3HvkXP+zGDPS1VaFHsgC3rUJlr\nZ/DG9XjlqMiJ/61TbiE6NrIgiFfVjaMSnQGaBz3fYQKBgQDM5kpFyJdicG6C8HIO\ngGO4W7YjhOLdUOp2+r8G9G+jhZw7r88/NwRZdmQg3zbrZenNAfxWNMgjL7ghOyUh\nUU7g5rqbBokiz5ZiEmxZ1na6rVB5RnDy/idL/D6bV+/toHXQoBwJgKFSe3FMmwHh\n3mIBWKN+lC8zjR7qSTCT8mVPewKBgQDBLHcnhpZpAl7ytstrKgMEXOyAkLyxvQpe\nJ/L8qJjVK3tlBA2UQPISuHLfr2gp1gSv/wqRfX0+pdVGtghxiflcSO1QL5nOsF0b\nNUgkHO9ZKZx2xvf2+qe+wKF+Ll+dFW/F2Ir7FCgrKuP6DAKyAB7IiogWNllkGsfg\naMmUgKqjUQKBgFGd1a3wVeS/NjXwAu6l05Lm7Sk+0IMprQtRm+/wQ9vV58KaqCnd\nB11/XCj/4MdpY/TmOpY4FhR1+Jk8DvEziwDoxyHjO5LjL1rHTeOHGuoHCUwVc/5G\noG6S/nkwUQDNbsB4VlKuqxPI2fuSrvBCfbVdklpkOl0FdHAMUU5NOm+rAoGAczYA\n7ur/ZCvM0zeghQ6uc/iz+U3ZrKwRtexfqL8pP+JKGwpayvQdLHsj0DM+jc0eSJV1\nCSbt/uJLHHxO9uCSf67jEvMA6dwX+7VAjIFRYz1FGzY6B+yhBUzARJCF6Bsz6azn\n3y27c1uGUsi9Bsq5kWPGHHFXyTOLyFTW/SHsI7ECgYBIDt9VfkUHFx1JsZYUAPx/\nHOwQjxdMDSt4SeDbGJVo2zXQUoqtweuuCEJ+N5XsGRGpCylk9hUdwQ/acQ7UGxqd\n4GFKjAaZdhea6hdFB9SnWc3r6FWGTojPbBlYIXMNjaN5d9x3Djsj9FckIkvZz9ks\nmRyfLk6RRK+kjy0iUz0neA==\n-----END PRIVATE KEY-----';

#[derive(Debug, Clone)]
pub struct SsoConfig {
    pub enabled: bool,
    /// Public base URL of this SSO server; used as `iss` and in discovery docs.
    pub issuer: String,
    pub access_ttl: Duration,
    pub code_ttl: Duration,
    pub refresh_ttl: Duration,
    /// PEM encoded RSA private key. Generated (ephemeral) when omitted.
    pub private_key_pem: Option<String>,
    /// Prefix of issued app keys, e.g. `ssok`.
    pub app_key_prefix: String,
    /// Default scopes granted to a new client when none are requested.
    pub default_scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BootstrapAdmin {
    pub email: String,
    pub password: String,
    pub full_name: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub app_name: String,
    pub env: Environment,
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub db_max_connections: u32,
    pub jwt: JwtConfig,
    pub security: SecurityConfig,
    pub email: EmailConfig,
    pub cors_origins: Vec<String>,
    pub trust_proxy: bool,
    pub swagger_enabled: bool,
    pub bootstrap_admin: Option<BootstrapAdmin>,
    pub sso: SsoConfig,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let env = var("APP_ENV")
            .as_deref()
            .unwrap_or("development")
            .parse::<Environment>()?;

        let jwt_secret = match var("JWT_SECRET") {
            Some(secret) if secret.len() >= 32 => secret,
            Some(secret) => {
                bail!(
                    "JWT_SECRET is too short ({} chars); use at least 32 characters",
                    secret.len()
                )
            }
            None if env.is_production() => {
                bail!("JWT_SECRET is required when APP_ENV=production")
            }
            None => {
                let generated = crate::security::tokens::random_hex(32);
                tracing::warn!(
                    "JWT_SECRET not set; generated an ephemeral development secret. \
                     Access tokens are invalidated on every restart."
                );
                generated
            }
        };

        let email_mode = match var("EMAIL_MODE")
            .unwrap_or_else(|| "console".to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "console" | "log" => EmailMode::Console,
            "disabled" | "off" | "none" => EmailMode::Disabled,
            other => bail!("unknown EMAIL_MODE `{other}` (expected console|disabled)"),
        };

        let cors_origins = var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|| "http://localhost:3000,http://localhost:5173".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();

        let bootstrap_admin = match (
            var("BOOTSTRAP_ADMIN_EMAIL"),
            var("BOOTSTRAP_ADMIN_PASSWORD"),
        ) {
            (Some(email), Some(password)) => {
                if password.len() < 8 {
                    bail!("BOOTSTRAP_ADMIN_PASSWORD must be at least 8 characters");
                }
                Some(BootstrapAdmin {
                    email: email.trim().to_ascii_lowercase(),
                    password,
                    full_name: var("BOOTSTRAP_ADMIN_NAME")
                        .unwrap_or_else(|| "Platform Admin".to_string()),
                })
            }
            (None, None) => None,
            _ => bail!(
                "BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD must be provided together"
            ),
        };

        let sso_issuer = var("SSO_ISSUER").unwrap_or_else(|| {
            format!(
                "http://{}:{}",
                var("HOST").unwrap_or_else(|| "127.0.0.1".to_string()),
                parse_var("PORT", 8080u16).unwrap_or(8080)
            )
        });

        Ok(Config {
            app_name: var("APP_NAME").unwrap_or_else(|| "rust-auth-api".to_string()),
            env,
            host: var("HOST").unwrap_or_else(|| "127.0.0.1".to_string()),
            port: parse_var("PORT", 8080u16)?,
            database_url: var("DATABASE_URL")
                .unwrap_or_else(|| "sqlite://./data/auth.db?mode=rwc".to_string()),
            db_max_connections: parse_var("DB_MAX_CONNECTIONS", 10u32)?,
            jwt: JwtConfig {
                secret: jwt_secret,
                issuer: var("JWT_ISSUER").unwrap_or_else(|| "rust-auth-api".to_string()),
                audience: var("JWT_AUDIENCE")
                    .unwrap_or_else(|| "rust-auth-api-clients".to_string()),
                access_ttl: ttl_secs("ACCESS_TOKEN_TTL_SECONDS", 900),
                refresh_ttl: ttl_secs("REFRESH_TOKEN_TTL_SECONDS", 60 * 60 * 24 * 30),
                mfa_ttl: ttl_secs("MFA_TOKEN_TTL_SECONDS", 300),
                leeway: parse_var("JWT_LEEWAY_SECONDS", 5u64)?,
            },
            security: SecurityConfig {
                max_login_attempts: parse_var("MAX_LOGIN_ATTEMPTS", 5i64)?,
                lockout: ttl_secs("LOCKOUT_SECONDS", 900),
                password_min_len: parse_var("PASSWORD_MIN_LENGTH", 8usize)?,
                password_max_len: parse_var("PASSWORD_MAX_LENGTH", 128usize)?,
                require_email_verification: bool_var("REQUIRE_EMAIL_VERIFICATION", false)?,
                verify_session_on_request: bool_var("VERIFY_SESSION_ON_REQUEST", true)?,
                login_rate_limit: parse_var("LOGIN_RATE_LIMIT", 10u32)?,
                login_rate_window: ttl_secs("LOGIN_RATE_WINDOW_SECONDS", 60),
                register_rate_limit: parse_var("REGISTER_RATE_LIMIT", 5u32)?,
                register_rate_window: ttl_secs("REGISTER_RATE_WINDOW_SECONDS", 3600),
                reset_rate_limit: parse_var("RESET_RATE_LIMIT", 5u32)?,
                reset_rate_window: ttl_secs("RESET_RATE_WINDOW_SECONDS", 3600),
                global_rate_limit: match parse_var("GLOBAL_RATE_LIMIT", 300u32)? {
                    0 => None,
                    limit => Some((limit, ttl_secs("GLOBAL_RATE_WINDOW_SECONDS", 60))),
                },
            },
            email: EmailConfig {
                mode: email_mode,
                from: var("EMAIL_FROM").unwrap_or_else(|| "no-reply@localhost".to_string()),
                frontend_url: var("FRONTEND_URL")
                    .unwrap_or_else(|| "http://localhost:5173".to_string())
                    .trim_end_matches('/')
                    .to_string(),
                verify_ttl: ttl_secs("EMAIL_VERIFICATION_TTL_SECONDS", 60 * 60 * 24),
                reset_ttl: ttl_secs("PASSWORD_RESET_TTL_SECONDS", 60 * 60),
            },
            cors_origins,
            trust_proxy: bool_var("TRUST_PROXY", false)?,
            swagger_enabled: bool_var("SWAGGER_ENABLED", true)?,
            bootstrap_admin,
            sso: SsoConfig {
                enabled: bool_var("SSO_ENABLED", true)?,
                issuer: sso_issuer.trim_end_matches('/').to_string(),
                access_ttl: ttl_secs("SSO_ACCESS_TTL_SECONDS", 3600),
                code_ttl: ttl_secs("SSO_CODE_TTL_SECONDS", 300),
                refresh_ttl: ttl_secs("SSO_REFRESH_TTL_SECONDS", 60 * 60 * 24 * 30),
                private_key_pem: var("SSO_RSA_PRIVATE_KEY"),
                app_key_prefix: var("APP_KEY_PREFIX").unwrap_or_else(|| "ssok".to_string()),
                default_scopes: vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                ],
            },
        })
    }

    pub fn bind_addr(&self) -> Result<SocketAddr> {
        format!("{}:{}", self.host, self.port)
            .parse()
            .with_context(|| format!("invalid bind address {}:{}", self.host, self.port))
    }

    /// Deterministic configuration used by the integration tests.
    pub fn for_test(database_url: &str) -> Self {
        Config {
            app_name: "rust-auth-api-test".to_string(),
            env: Environment::Test,
            host: "127.0.0.1".to_string(),
            port: 0,
            database_url: database_url.to_string(),
            db_max_connections: 1,
            jwt: JwtConfig {
                secret: "test-secret-test-secret-test-secret-test-secret".to_string(),
                issuer: "rust-auth-api".to_string(),
                audience: "rust-auth-api-clients".to_string(),
                access_ttl: Duration::from_secs(900),
                refresh_ttl: Duration::from_secs(60 * 60 * 24),
                mfa_ttl: Duration::from_secs(300),
                leeway: 0,
            },
            security: SecurityConfig {
                max_login_attempts: 3,
                lockout: Duration::from_secs(60),
                password_min_len: 8,
                password_max_len: 128,
                require_email_verification: false,
                verify_session_on_request: true,
                login_rate_limit: 1000,
                login_rate_window: Duration::from_secs(60),
                register_rate_limit: 1000,
                register_rate_window: Duration::from_secs(60),
                reset_rate_limit: 1000,
                reset_rate_window: Duration::from_secs(60),
                global_rate_limit: None,
            },
            email: EmailConfig {
                mode: EmailMode::Console,
                from: "no-reply@test.local".to_string(),
                frontend_url: "http://localhost:5173".to_string(),
                verify_ttl: Duration::from_secs(3600),
                reset_ttl: Duration::from_secs(3600),
            },
            cors_origins: vec!["http://localhost:5173".to_string()],
            trust_proxy: false,
            swagger_enabled: true,
            bootstrap_admin: None,
            sso: SsoConfig {
                enabled: true,
                issuer: "http://localhost:8080".to_string(),
                access_ttl: Duration::from_secs(3600),
                code_ttl: Duration::from_secs(300),
                refresh_ttl: Duration::from_secs(86_400),
                private_key_pem: Some(TEST_RSA_PRIVATE_KEY.to_string()),
                app_key_prefix: "ssok".to_string(),
                default_scopes: vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                ],
            },
        }
    }
}

fn var(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn parse_var<T>(key: &str, default: T) -> Result<T>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    match var(key) {
        Some(raw) => raw.parse::<T>().map_err(|e| anyhow!("invalid {key}: {e}")),
        None => Ok(default),
    }
}

fn ttl_secs(key: &str, default_secs: u64) -> Duration {
    let secs = var(key)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default_secs);
    Duration::from_secs(secs)
}

fn bool_var(key: &str, default: bool) -> Result<bool> {
    match var(key) {
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => bail!("invalid boolean for {key}: `{other}`"),
        },
        None => Ok(default),
    }
}
