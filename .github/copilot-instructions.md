# GitHub Copilot Review Guidelines — metal-auth

When reviewing Pull Requests in this repository, enforce the following engineering, architectural, and security standards:

## 1. Technology Stack
- **Language**: Rust (2021/2024 edition) with latest stable compiler toolchain.
- **Web Framework**: Axum 0.8 with Tower HTTP middleware.
- **Async Runtime**: Tokio (`tokio = "1"`).
- **Database & Storage**: SQLx 0.9 with PostgreSQL, connection pooling, and managed migrations.
- **Cryptography & Hashing**: Argon2id for password hashing (`argon2 = "0.5"`), SHA-256 for token hashing.

## 2. Code Quality & Standards
- **Strict Error Typing**:
  - All fallible operations must return `Result<T, AppError>` (or `AppResult<T>`).
  - Do not use ad-hoc string or untyped errors; map foreign errors explicitly to `AppError` variants (e.g., `AppError::Database`, `AppError::Config`, `AppError::InvalidCredentials`).
- **Zero Panics in Library Code**:
  - `unwrap()` and `expect()` are forbidden in production and library code paths (`src/**`). Use `?`, `ok_or()`, or explicit pattern matching.
- **Linter & Formatter Compliance**:
  - Code must pass `cargo clippy --locked --all-targets --all-features -- -D warnings` with zero warnings.
  - Code must strictly satisfy `cargo fmt --check`.
  - Avoid dead code, unreferenced imports, and unnecessary allocations on hot paths.

## 3. Test Sync & Security Hygiene
- **Mandatory Test Sync**:
  - Every new feature, logic branch, or bug fix requires corresponding unit/integration tests in `#[cfg(test)]` modules.
  - Bug fixes must include a regression test asserting the fix.
- **Zero Hardcoded Secrets in Tests**:
  - Never commit static passwords, fixed auth tokens, or dummy API keys.
  - Use dynamic values and UUIDs (e.g., `Uuid::new_v4().to_string()`, random bytes) for test identifiers, emails, and credentials.
- **Security Invariants**:
  - Validate and sanitize external input at application boundaries.
  - Ensure constant-time comparison for sensitive tokens and hashes where applicable.
  - Never log credentials, hashed passwords, or session tokens.

## 4. Scope Discipline & Diff Precision
- **Surgical Changes**: Keep diffs minimal, focused, and reviewable. Do not combine unrelated refactoring or formatting changes with feature work.
- **Public API Stability**: Do not introduce breaking public API changes without explicit authorization and versioning considerations.
