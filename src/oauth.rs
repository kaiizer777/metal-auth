//! OAuth2 and OpenID Connect (OIDC) integration flows and provider interfaces.
//!
//! # Architectural Boundary
//!
//! This module is an architectural extension point reserved for future phase authentication flows.
//!
//! ## Planned Capabilities
//! - Provider interface definitions for third-party identity providers (e.g., Google, GitHub, generic OIDC).
//! - Authorization code grant flow state machine with PKCE (RFC 7636) verification.
//! - External token exchange, profile mapping, and account linking against [`User`](crate::User).
//!
pub mod pkce;
pub mod state;

pub use pkce::{PKCEChallenge, compute_challenge, generate_pkce, verify_pkce};
pub use state::{
    OAuthStatePayload, build_clear_state_cookie, build_clear_state_cookie_header,
    build_state_cookie, build_state_cookie_header, create_state_cookie_value, extract_state_cookie,
    generate_state_token, validate_state,
};
