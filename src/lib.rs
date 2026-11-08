//! # metal-auth
//!
//! A composable, honest-about-its-limits authentication library for Rust,
//! inspired by Better Auth. Sibling project to `go-auth`.
//!
//! This crate follows strict facade discipline: `lib.rs` acts purely as an export
//! gateway and entrypoint facade. All concrete implementations reside in dedicated
//! single-purpose modules.

pub mod adapters;
pub mod crypto;
pub mod oauth;
pub mod plugins;
pub mod ratelimit;
pub mod schema;
pub mod session;

/// Configuration options for the `MetalAuth` instance.
#[derive(Debug, Clone, Default)]
pub struct Config {
    // TODO: Define base configuration fields (e.g. secret keys, base URLs, cookie options).
}

/// Primary authentication facade and entry point.
#[derive(Debug)]
pub struct MetalAuth {
    // TODO: Hold initialized adapters, plugins, and configuration.
}

/// Builder for constructing a configured [`MetalAuth`] instance.
#[derive(Debug, Default)]
pub struct MetalAuthBuilder {
    // TODO: Implement builder state for adapters, plugins, and configuration.
}

impl MetalAuth {
    /// Creates a new [`MetalAuthBuilder`] instance.
    #[must_use]
    pub fn builder() -> MetalAuthBuilder {
        MetalAuthBuilder::default()
    }
}
