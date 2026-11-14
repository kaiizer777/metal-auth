//! # metal-auth
//!
//! A modular authentication and identity library for Rust built on Axum and SQLx.
//!
//! ## Architectural Layers
//!
//! - **Configuration** ([`Config`], [`AppConfig`]): Infrastructure parameters (database connection pool,
//!   CORS rules, base URLs) and OWASP-compliant authentication security bounds (Argon2id cost parameters,
//!   password length constraints, token TTLs).
//! - **Security & Cryptography** ([`crypto`]): Argon2id password hashing with timing-parity verification,
//!   cryptographically secure token generation, and password blocklist validation.
//! - **State & Services** ([`AppState`], [`Auth`], [`AuthService`], [`AuthServiceImpl`]): Centralized application
//!   state and transactional authentication business logic with anti-enumeration safeguards.
//! - **Email Dispatch** ([`EmailDispatcher`], [`EmailSender`], [`NoopEmailSender`]): Configurable email hooks
//!   for verification and password reset workflows; delivery is always detached from the request path.
//! - **Persistence Models** ([`User`], [`Session`], [`VerificationToken`], [`PasswordResetToken`]): Strongly-typed
//!   PostgreSQL entities preventing credential leaks across serialization boundaries, paired with client-facing
//!   DTOs ([`UserResponse`]).
//! - **Error Handling** ([`AppError`], [`ConfigError`], [`ErrorCode`], [`ErrorResponse`]): Standardized typed
//!   error codes, field-level configuration failures, and unified JSON response envelopes.
//! - **HTTP Routing** ([`auth_routes`]): Preconfigured Axum authentication route definitions (callers must attach [`cors_layer`](handler::cors_layer) if not using [`handler::create_router`]).
//!
//! ## Extension Boundaries
//!
//! - [`session`]: Extension module reserved for future phase stateful session storage backends and lifecycle policies.
//! - [`oauth`]: Extension module reserved for future phase OAuth2 and OpenID Connect (OIDC) identity provider integrations.

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

pub use auth::{Auth, AuthService, AuthServiceImpl, UserResponse};
pub use config::{AppConfig, Config};
pub use db::models::{PasswordResetToken, Session, User, VerificationToken};
pub use email::{
    DynError, EmailDispatcher, EmailSender, NoopEmailSender, PasswordResetEmailPayload,
    SharedEmailSender, VerificationEmailPayload,
};
pub use error::{AppError, AppResult, ConfigError, ErrorCode, ErrorResponse};
pub use handler::auth_routes;
pub use state::AppState;

#[cfg(any(test, feature = "test-utils"))]
pub use email::test_utils;
