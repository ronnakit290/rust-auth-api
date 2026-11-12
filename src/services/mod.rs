//! Domain services. Handlers stay thin: parse → delegate here → render.

pub mod admin;
pub mod audit;
pub mod auth;
pub mod clients;
pub mod email;
pub mod sso;
pub mod two_factor;
pub mod users;

/// E-mail addresses are stored normalized so uniqueness and lookups are exact.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// Trims and collapses blank display names to `None`.
pub fn normalize_full_name(name: Option<&str>) -> Option<String> {
    name.map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}
