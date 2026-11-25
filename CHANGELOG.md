# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** the two-factor public surface gained variants and attributes. `OAuthCallbackOutcome`
  has a `TwoFactorRequired { challenge_token, clear_cookie_header }` arm, `RateLimitRejection::Exceeded`
  carries the sliding window's remaining whole seconds (`Exceeded(u64)`, previously a unit variant), and
  `ErrorCode`/`AppError` carry the TOTP codes. `ErrorCode`, `AppError`, `RateLimitRejection`, and
  `OAuthCallbackOutcome` are now `#[non_exhaustive]`, so an exhaustive `match` on any of them must add a
  wildcard arm.
- **Breaking:** `OAuthService::new`, `OAuthService::with_providers`, and `OAuthService::new_with_manager`
  take a required `Arc<TotpService>`; session issuance is gated on the account's second factor, so a
  service built without it could not enforce that gate.
- **Breaking:** `ASYNC_EMAIL_DISPATCH=false` is now rejected at boot (`Config::validate`). Email
  delivery is always detached, so the flag no longer controls anything. Migration: unset
  `ASYNC_EMAIL_DISPATCH` or set it to `true`.
- **Breaking:** `EmailDispatcher::new` no longer takes a dispatch-mode flag; it always delivers on a
  detached task. Inline (blocking) dispatch moved to `EmailDispatcher::new_blocking`, available only
  with the `test-utils` feature.
- **Breaking:** `OAuthService::link_account` is removed; use `OAuthService::link_account_identity`,
  which takes the provider slug, authorization code, state, and state cookie header explicitly.
- **Breaking:** the `metal_auth::oauth::create_provider` re-export is removed; use
  `metal_auth::oauth::provider::create_provider`. The crate root never exported it.
- **Breaking:** the `handler::oauth::link_account` and `handler::oauth::unlink_account` handlers now
  return `Response` instead of `Result<_, AppError>`. They build their error responses internally so
  a failed call can also clear the provider-scoped `oauth_state` cookie; router registration is
  unchanged.
- **Breaking:** building a router without a TOTP encryption key now fails at startup. `create_router`,
  `routes_with_app_state`, `routes_with_state`, and `totp::routes`/`totp_routes` all reject a keyless
  configuration, and the three that previously returned a bare `Router` now return
  `Result<Router, AppError>`.
- **Breaking:** `OAuthCallbackOutcome::TwoFactorRequired` now carries the saved destination. A browser
  OAuth login that requires a second factor answers `302` to `<destination>#totp_challenge=<token>`
  instead of `200` JSON; bearer and JSON clients are unchanged. The pending challenge reaches the
  client through the URL fragment and never through a query parameter.
- **Breaking:** `TotpService::generate_two_factor_token` takes the credential that authorized the
  challenge, and each challenge is bound to a snapshot of it and rejected once that no longer
  matches. The accompanying migration deletes every existing challenge row before adding
  `credential_hash TEXT NOT NULL`, so any challenge in flight at deploy time is invalidated and the
  affected user must sign in again to receive a new one. Direct inserts into `two_factor_tokens` must
  now supply `credential_hash`.
- Signup and password-reset responses no longer wait for the mailer, and delivery survives a client
  disconnect.

### Fixed

- A link callback whose initiating user no longer exists now returns 403 instead of a 500.
- OAuth state that would render a cookie above the browser size budget is rejected with 400 instead
  of emitting an over-limit `Set-Cookie`.
- A password reset purges outstanding two-factor challenge tokens for that user, so a challenge
  issued before the reset can no longer mint a session afterwards.
- Expired two-factor challenge tokens are pruned by the background worker at startup and on each
  tick instead of accumulating indefinitely.
- `405 Method Not Allowed` responses advertise the route's actual method set in the `Allow` header
  instead of a hardcoded `POST`.
- A failure while minting an OAuth challenge logs the underlying database error instead of only
  "database error".
- The TOTP used-code prune age rustdoc documents the correct SQL bind position.
- User-row locks are narrowed so unrelated child-row inserts no longer block.
- The test outbox worker no longer leaks rows into the shared test schema that other tests assert on.
- Log-capture tests no longer depend on process-global callsite interest state.
- The failure-injection cleanup is bounded, so a stalled connect fails instead of hanging the suite.
- Two-factor concurrency tests fail with a clear message instead of hanging, and prove lock ordering
  from `pg_locks` rather than elapsed time.

<!-- e2e: unrelated touch for M8 no-op push proof -->
