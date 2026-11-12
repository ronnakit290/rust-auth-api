//! Outgoing e-mail.
//!
//! The transport is intentionally pluggable: everything funnels through
//! `EmailService::deliver`. Today we support a console transport (used in dev,
//! tests and the `/api/v1/dev/outbox` debug endpoint). Swap `deliver` for an
//! SMTP/API client (lettre, SES, Resend, ...) without touching any caller.

use std::{collections::VecDeque, sync::Mutex};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{
    config::{EmailConfig, EmailMode},
    dto::DebugToken,
    error::ApiError,
};

const OUTBOX_CAPACITY: usize = 100;

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct OutboxMessage {
    pub id: String,
    pub to: String,
    pub subject: String,
    pub kind: String,
    pub token: String,
    pub url: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
}

pub struct EmailService {
    config: EmailConfig,
    app_name: String,
    outbox: Mutex<VecDeque<OutboxMessage>>,
}

impl EmailService {
    pub fn new(config: EmailConfig, app_name: String) -> Self {
        EmailService {
            config,
            app_name,
            outbox: Mutex::new(VecDeque::new()),
        }
    }

    pub fn mode(&self) -> EmailMode {
        self.config.mode
    }

    pub fn send_verification_email(
        &self,
        to: &str,
        token: &str,
        expires_in_seconds: i64,
    ) -> Result<Option<DebugToken>, ApiError> {
        let url = format!("{}/verify-email?token={}", self.config.frontend_url, token);
        let body = format!(
            "Welcome to {app}!\n\nConfirm your e-mail address by opening:\n{url}\n\n\
             This link expires in {hours} hour(s).\n\nIf you did not create an account, ignore this message.",
            app = self.app_name,
            hours = expires_in_seconds / 3600
        );
        self.deliver(OutboxMessage {
            id: uuid::Uuid::new_v4().to_string(),
            to: to.to_string(),
            subject: format!("Verify your {} account", self.app_name),
            kind: "email_verification".to_string(),
            token: token.to_string(),
            url,
            body,
            created_at: Utc::now(),
        })
    }

    pub fn send_password_reset_email(
        &self,
        to: &str,
        token: &str,
        expires_in_seconds: i64,
    ) -> Result<Option<DebugToken>, ApiError> {
        let url = format!(
            "{}/reset-password?token={}",
            self.config.frontend_url, token
        );
        let body = format!(
            "A password reset was requested for your {app} account.\n\nOpen:\n{url}\n\n\
             The link expires in {minutes} minutes. If this was not you, no action is needed — \
             your password has not changed.",
            app = self.app_name,
            minutes = expires_in_seconds / 60
        );
        self.deliver(OutboxMessage {
            id: uuid::Uuid::new_v4().to_string(),
            to: to.to_string(),
            subject: format!("Reset your {} password", self.app_name),
            kind: "password_reset".to_string(),
            token: token.to_string(),
            url,
            body,
            created_at: Utc::now(),
        })
    }

    pub fn send_password_changed_email(&self, to: &str) -> Result<Option<DebugToken>, ApiError> {
        let body = format!(
            "The password for your {app} account was just changed, and all sessions were signed out.\n\n\
             If you did not make this change, reset your password immediately.",
            app = self.app_name
        );
        self.deliver(OutboxMessage {
            id: uuid::Uuid::new_v4().to_string(),
            to: to.to_string(),
            subject: format!("Your {} password changed", self.app_name),
            kind: "password_changed".to_string(),
            token: String::new(),
            url: String::new(),
            body,
            created_at: Utc::now(),
        })
    }

    pub fn outbox(&self) -> Vec<OutboxMessage> {
        self.outbox
            .lock()
            .map(|messages| messages.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn clear_outbox(&self) {
        if let Ok(mut messages) = self.outbox.lock() {
            messages.clear();
        }
    }

    fn deliver(&self, message: OutboxMessage) -> Result<Option<DebugToken>, ApiError> {
        match self.config.mode {
            EmailMode::Console => {
                tracing::info!(
                    to = %message.to,
                    subject = %message.subject,
                    kind = %message.kind,
                    url = %message.url,
                    "outgoing email (console transport)\n{}",
                    message.body
                );
                if let Ok(mut outbox) = self.outbox.lock() {
                    if outbox.len() >= OUTBOX_CAPACITY {
                        outbox.pop_front();
                    }
                    outbox.push_back(message.clone());
                }
                Ok(Some(DebugToken {
                    kind: message.kind,
                    token: message.token,
                    expires_at: message.created_at + chrono::Duration::hours(24),
                    url: message.url,
                }))
            }
            EmailMode::Disabled => {
                tracing::debug!(to = %message.to, kind = %message.kind, "email suppressed (EMAIL_MODE=disabled)");
                Ok(None)
            }
        }
    }
}
