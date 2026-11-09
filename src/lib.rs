//! # metal-auth
//!
//! A composable, modular authentication library for Rust.

pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod handler;
pub mod state;

pub mod crypto;
pub mod email;
pub mod oauth;
pub mod session;

pub use auth::Auth;
pub use config::Config;
pub use db::models::*;
pub use error::{AppError, ConfigError, ErrorCode, ErrorResponse};
pub use state::AppState;
