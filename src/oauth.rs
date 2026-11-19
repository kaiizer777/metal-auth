//! OAuth2 and OpenID Connect (OIDC) integration flows and provider interfaces.
//!
//! # Architectural Boundary
//!
//! This module provides OAuth2 and OIDC identity delegation with PKCE (RFC 7636) and
//! CSRF state validation (RFC 6749) across Google, GitHub, and Apple identity providers.
//!
pub mod apple;
pub mod github;
pub mod google;
pub mod pkce;
pub mod provider;
pub mod service;
pub mod state;

pub use apple::AppleProvider;
pub use github::GitHubProvider;
pub use google::GoogleProvider;
pub use pkce::{PKCEChallenge, compute_challenge, generate_pkce, verify_pkce};
pub use provider::{
    OAUTH_BODY_LIMIT, OAuthProvider, OAuthTokenResponse, OAuthUserInfo, SUPPORTED_PROVIDERS,
    TokenResponse, UserInfo, build_oauth_http_client, create_provider,
};
pub use service::{OAuthCallbackResult, OAuthService};
pub use state::{
    OAuthStateManager, OAuthStatePayload, build_clear_state_cookie,
    build_clear_state_cookie_for_provider, build_clear_state_cookie_header,
    build_clear_state_cookie_header_for_provider, build_state_cookie,
    build_state_cookie_for_provider, build_state_cookie_header,
    build_state_cookie_header_for_provider, create_state_cookie_value, extract_state_cookie,
    generate_state_token, validate_state,
};
