//! # metal-auth
//!
//! A composable, modular authentication library for Rust.

pub mod config;
pub mod crypto;
pub mod db;
pub mod email;
pub mod error;
pub mod oauth;
pub mod session;
pub mod state;

pub use config::Config;
pub use error::AppError;
