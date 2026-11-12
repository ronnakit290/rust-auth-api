//! Shared application state handed to every handler.

use std::sync::Arc;

use sqlx::SqlitePool;

use crate::{
    config::Config,
    db::{self, users::NewUser},
    error::ApiError,
    security::{hash_password, JwtService, RateLimiter, SsoKeys},
    services::email::EmailService,
};

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<Config>,
    pub jwt: Arc<JwtService>,
    /// RS256 keypair used to sign SSO tokens and to publish JWKS.
    pub sso: Arc<SsoKeys>,
    pub emails: Arc<EmailService>,
    pub limiter: Arc<RateLimiter>,
    pub started_at: std::time::Instant,
}

impl AppState {
    /// Connects, migrates and seeds the optional bootstrap administrator.
    pub async fn bootstrap(config: Config) -> anyhow::Result<Self> {
        let pool = db::connect(&config).await?;
        db::migrate(&pool).await?;
        let state = Self::from_pool(pool, config);
        state.seed_bootstrap_admin().await?;
        Ok(state)
    }

    pub fn from_pool(pool: SqlitePool, config: Config) -> Self {
        let jwt = Arc::new(JwtService::new(&config.jwt));
        let sso = Arc::new(
            SsoKeys::from_config(&config.sso)
                .expect("SSO signing key configuration is invalid (check SSO_RSA_PRIVATE_KEY)"),
        );
        let emails = Arc::new(EmailService::new(
            config.email.clone(),
            config.app_name.clone(),
        ));
        AppState {
            pool,
            config: Arc::new(config),
            jwt,
            sso,
            emails,
            limiter: Arc::new(RateLimiter::new()),
            started_at: std::time::Instant::now(),
        }
    }

    async fn seed_bootstrap_admin(&self) -> anyhow::Result<()> {
        let Some(bootstrap) = self.config.bootstrap_admin.as_ref() else {
            return Ok(());
        };

        match db::users::find_by_email(&self.pool, &bootstrap.email).await {
            Ok(Some(existing)) => {
                if !existing.role.is_admin() {
                    tracing::warn!(
                        email = %existing.email,
                        "bootstrap admin e-mail already belongs to a non-admin account; leaving it untouched"
                    );
                } else {
                    tracing::info!(email = %existing.email, "bootstrap admin already present");
                }
            }
            Ok(None) => {
                let id = uuid::Uuid::new_v4().to_string();
                let password_hash = hash_password(&bootstrap.password)
                    .map_err(|e| anyhow::anyhow!("cannot hash bootstrap password: {e}"))?;
                db::users::insert(
                    &self.pool,
                    &NewUser {
                        id: &id,
                        email: &bootstrap.email,
                        password_hash: &password_hash,
                        full_name: Some(&bootstrap.full_name),
                        role: db::users::Role::Superadmin,
                        email_verified_at: Some(db::now_ts()),
                    },
                )
                .await
                .map_err(|e| anyhow::anyhow!("cannot create bootstrap admin: {e}"))?;
                tracing::info!(email = %bootstrap.email, "bootstrap superadmin created");
            }
            Err(err) => return Err(anyhow::anyhow!("bootstrap admin lookup failed: {err}")),
        }
        Ok(())
    }

    /// Enforces an in-process rate limit bucket, returning a 429 with a
    /// `Retry-After` header when exceeded.
    pub fn enforce_rate(
        &self,
        scope: &str,
        identity: &str,
        limit: u32,
        window: std::time::Duration,
    ) -> Result<(), ApiError> {
        self.limiter
            .check(scope, identity, limit, window)
            .map_err(ApiError::rate_limited)
    }

    pub fn is_production(&self) -> bool {
        self.config.env.is_production()
    }
}
