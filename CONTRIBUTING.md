# Contributing to metal-auth

Thank you for contributing to `metal-auth`. We welcome contributions that maintain our high standards of architectural cleanliness, type safety, and code discipline.

Please review our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

---

## Architectural & Module Rules (Strict Enforcement)

To keep `metal-auth` maintainable, extensible, and clean as it grows, we strictly enforce the following architectural rules:

1. **Facade Discipline in `src/lib.rs`**:
   - `src/lib.rs` is strictly a thin facade.
   - It only contains public re-exports (`pub use`), the top-level `MetalAuth` struct/builder, and top-level configuration type stubs (`Config`).
   - **No implementation logic in `src/lib.rs` beyond the public facade.**
2. **Modern Module Structure (No `mod.rs`)**:
   - We use modern Rust module conventions (Rust 2018+ style: `name.rs` + `name/` folder for children).
   - **No `mod.rs` files anywhere in this project.** PRs violating this will be asked to restructure.
   - For a module with no children yet, it is just `src/modulename.rs` — no folder is needed until it has submodules.
3. **Dedicated Module Implementation**:
   - ALL implementation logic — session handling, crypto, schema, OAuth providers, rate limiting, database adapters, plugins — MUST live in its own dedicated module.
4. **Naming Conventions**:
   - Rust module names cannot contain hyphens. Use snake_case / underscores for all module files and folder names (e.g. `credential_password.rs`), even though the crate name uses hyphens (`metal-auth`).
5. **Single-Purpose Modules**:
   - Each module should stay single-purpose. If a module grows past ~10–15 files, split it further into submodules rather than flattening it.

---

## Pull Request Process

1. **Fork & Branch**: Create a feature or fix branch from `main` (e.g. `feat/oauth-google` or `fix/session-expiry`).
2. **Formatting & Linting**:
   - Run `cargo fmt --all -- --check` to ensure all files conform to the style guide.
   - Run `cargo clippy --all-targets --all-features -- -D warnings` to catch lints and potential bugs.
   - Run `cargo test` to ensure all tests pass.
3. **Verification**: Verify that zero `mod.rs` files are introduced and no business logic has been placed into `src/lib.rs`.
4. **Pull Request**: Open a PR with a concise, clear description of the change, linking any related issues.
