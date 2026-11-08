# metal-auth Roadmap

> **Note**: This crate's feature scope mirrors the sibling `go-auth` project.

| Feature | Status | Target | Notes |
| :--- | :--- | :--- | :--- |
| Email/Password Auth | Planned | v1 | Argon2id hashing, secure credential validation |
| Session Management | Planned | v1 | Database-backed sessions with sliding expiry |
| CSRF Protection | Planned | v1 | Double-submit cookie / origin header verification |
| Rate Limiting (basic) | Planned | v1 | Token bucket / sliding window protection |
| OAuth - Google | Planned | v1 | Standard OIDC flow |
| OAuth - GitHub | Planned | v1 | Standard OAuth2 flow |
| OAuth - Apple | Planned | v1 | Sign in with Apple flow |
| OAuth - 4th provider (TBD) | Planned | v1 | Provider selection TBD |
| SQL Database Adapter | Planned | v1 | Core SQL migrations and schema interface |
| Framework-agnostic handler | Planned | v1 | Decoupled core with Axum/Tower compatibility |
| Documentation Site | Planned | v1 | Comprehensive guides and API reference |
