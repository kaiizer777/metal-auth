//! Email delivery abstraction — the library generates tokens and constructs payloads;
//! the consuming app supplies the actual transport implementation.
//!
//! `EmailDispatcher` is a trait object wrapping the app's email sending logic.
//! Dispatches are always fire-and-forget via `tokio::spawn` — the HTTP request
//! path never awaits email delivery.

use std::sync::Arc;
use uuid::Uuid;

/// Payload delivered to the app-supplied send callback for email verification.
#[derive(Debug, Clone)]
pub struct VerificationEmailPayload {
    /// The user's email address to send to.
    pub to_email: String,
    /// The 64-char hex token to embed in the verification URL.
    pub token: String,
    pub user_id: Uuid,
}

/// Payload delivered to the app-supplied send callback for password reset.
#[derive(Debug, Clone)]
pub struct PasswordResetEmailPayload {
    /// The user's email address to send to.
    pub to_email: String,
    /// The 64-char hex token to embed in the reset URL.
    pub token: String,
    pub user_id: Uuid,
}

/// App-supplied email dispatch callbacks.
///
/// Implement this trait and pass it to `AuthService::new`. The library calls
/// `dispatch_verification` / `dispatch_password_reset` on the happy path and
/// on the anti-enumeration path (duplicate signup / unknown email reset-request)
/// for timing parity — the callback must be fast enough to not block `tokio::spawn`.
pub trait EmailSender: Send + Sync + 'static {
    fn send_verification(&self, payload: VerificationEmailPayload);
    fn send_password_reset(&self, payload: PasswordResetEmailPayload);
}

/// Type-erased, `Arc`-wrapped email sender. Cloneable and `Send + Sync`.
///
/// Constructed via `EmailDispatcher::new(impl EmailSender)`.
#[derive(Clone)]
pub struct EmailDispatcher {
    inner: Arc<dyn EmailSender>,
}

impl EmailDispatcher {
    pub fn new(sender: impl EmailSender) -> Self {
        Self {
            inner: Arc::new(sender),
        }
    }

    /// Dispatch verification email (fire-and-forget via caller's `tokio::spawn`).
    pub fn dispatch_verification(&self, payload: VerificationEmailPayload) {
        self.inner.send_verification(payload);
    }

    /// Dispatch password reset email (fire-and-forget via caller's `tokio::spawn`).
    pub fn dispatch_password_reset(&self, payload: PasswordResetEmailPayload) {
        self.inner.send_password_reset(payload);
    }
}

impl std::fmt::Debug for EmailDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailDispatcher").finish_non_exhaustive()
    }
}

/// No-op dispatcher for testing — records nothing, sends nothing.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct CapturingEmailSender {
        pub verification_calls: Mutex<Vec<VerificationEmailPayload>>,
        pub reset_calls: Mutex<Vec<PasswordResetEmailPayload>>,
    }

    impl EmailSender for CapturingEmailSender {
        fn send_verification(&self, payload: VerificationEmailPayload) {
            self.verification_calls.lock().unwrap().push(payload);
        }
        fn send_password_reset(&self, payload: PasswordResetEmailPayload) {
            self.reset_calls.lock().unwrap().push(payload);
        }
    }
}
