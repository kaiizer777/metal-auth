//! HTTP middleware components.

#[cfg(any(feature = "postgres", feature = "mysql", feature = "mongodb"))]
pub mod auth;
#[cfg(any(feature = "postgres", feature = "mysql", feature = "mongodb"))]
pub mod csrf;
pub mod headers;

#[cfg(any(feature = "postgres", feature = "mysql", feature = "mongodb"))]
pub use auth::{AuthUser, require_auth};
#[cfg(any(feature = "postgres", feature = "mysql", feature = "mongodb"))]
pub use csrf::csrf_middleware;
pub use headers::security_headers_middleware;
