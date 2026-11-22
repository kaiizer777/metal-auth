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
- Signup and password-reset responses no longer wait for the mailer, and delivery survives a client
  disconnect.

### Fixed

- A link callback whose initiating user no longer exists now returns 403 instead of a 500.
- OAuth state that would render a cookie above the browser size budget is rejected with 400 instead
  of emitting an over-limit `Set-Cookie`.
