//! # metal-auth
//!
//! A composable, modular authentication library for Rust.

pub mod auth;
pub mod config;
pub mod crypto;
pub mod db;
pub mod email;
pub mod error;
pub mod handler;
pub mod oauth;
pub mod session;
pub mod state;

pub use auth::Auth;
pub use config::{AppConfig, Config};
pub use db::models::*;
pub use email::EmailDispatcher;
pub use error::{AppError, AppResult, ConfigError, ErrorCode, ErrorResponse};
pub use state::AppState;
