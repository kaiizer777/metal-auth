# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** `ASYNC_EMAIL_DISPATCH=false` is now rejected at boot (`Config::validate`). Email
  delivery is always detached, so the flag no longer controls anything. Migration: unset
  `ASYNC_EMAIL_DISPATCH` or set it to `true`.
- **Breaking:** `EmailDispatcher::new` no longer takes a dispatch-mode flag; it always delivers on a
  detached task. Inline (blocking) dispatch moved to `EmailDispatcher::new_blocking`, available only
  with the `test-utils` feature.
- Signup and password-reset responses no longer wait for the mailer, and delivery survives a client
  disconnect.
