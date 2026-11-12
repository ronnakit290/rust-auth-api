//! Rust Auth API — a complete authentication and user-management service.
//!
//! Layering:
//! - `config`   → validated environment configuration
//! - `db`       → schema access, one module per aggregate
//! - `security` → hashing, JWT, opaque tokens, TOTP, rate limiting
//! - `services` → business workflows (transactions, audit, e-mail)
//! - `handlers` → HTTP parsing/validation only
//! - `routes` / `middleware` → wiring, headers, CORS, limits

pub mod config;
pub mod db;
pub mod dto;
pub mod error;
pub mod extract;
pub mod handlers;
pub mod middleware;
pub mod oauth_error;
pub mod openapi;
pub mod response;
pub mod routes;
pub mod security;
pub mod services;
pub mod state;

pub use config::Config;
pub use routes::build_router;
pub use state::AppState;
