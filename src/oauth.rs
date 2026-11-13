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
//! ## Boundaries & Constraints
//! - Extensions in this module must integrate via [`AuthService`](crate::AuthService) rather than
//!   directly manipulating database state or bypassing password/email verification invariants.
