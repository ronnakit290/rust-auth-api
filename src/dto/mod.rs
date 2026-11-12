//! Request/response bodies. Every struct here is part of the public API and is
//! registered in the OpenAPI document.

pub mod admin;
pub mod auth;
pub mod common;
pub mod sso;
pub mod two_factor;
pub mod users;

pub use admin::*;
pub use auth::*;
pub use common::*;
pub use sso::*;

// Convenience re-exports so handlers need a single `use crate::dto::*;`.
pub use crate::response::{MessageResponse, Page};
pub use two_factor::*;
pub use users::*;
