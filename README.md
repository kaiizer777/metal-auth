# **Metal-Auth** — A composable, modular authentication library for Rust.

[![Crates.io](https://img.shields.io/crates/v/metal-auth.svg)](https://crates.io/crates/metal-auth)
[![Documentation](https://docs.rs/metal-auth/badge.svg)](https://docs.rs/metal-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://img.shields.io/badge/CI-planned-lightgrey)](https://github.com/kaiizer777/metal-auth/actions)

---

> [!WARNING]
> **Status: Early development — not yet usable in production.**
> APIs and internal structures are subject to breaking changes.

---

## Project Structure

This project strictly enforces modern Rust module conventions and facade discipline:

```text
metal-auth/
├── src/
│   ├── lib.rs                 # Public facade ONLY (re-exports, MetalAuth builder, Config stub)
│   ├── session.rs             # Session token generation, validation, and lifecycle
│   ├── crypto.rs              # Password hashing (Argon2id) and constant-time comparisons
│   ├── schema.rs              # Domain models (User, Session, Account)
│   ├── oauth.rs               # OAuth core abstractions
│   ├── oauth/
│   │   └── providers.rs       # Provider integrations (Google, GitHub, Apple)
│   ├── ratelimit.rs           # Sliding-window and token-bucket rate limiting
│   ├── adapters.rs            # Storage interface definitions
│   ├── adapters/
│   │   └── sql.rs             # Relational SQL adapter implementations
│   ├── plugins.rs             # Plugin interface definition
│   └── plugins/
│       └── credential_password.rs # Email/password authentication plugin
├── examples/
│   └── basic_axum.rs          # Basic example integration with Axum
└── docs/                      # Documentation and architecture guides
```

### Why this structure?
1. **Zero Logic in `lib.rs`**: Keeps the crate root as a clean API entry point and avoids monlithic file bloat.
2. **Modern Module Layout**: Follows the Rust 2018+ idiom (`name.rs` + `name/` folder). No `mod.rs` files are permitted.
3. **Single-Purpose Isolation**: Auth mechanisms, crypto routines, and DB adapters stay decoupled and independently testable.

## Installation

Coming soon (not yet published to crates.io).

```toml
[dependencies]
metal-auth = "0.1.0" # Not yet published
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines and development workflow. Please review our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Distributed under the [MIT License](LICENSE).
