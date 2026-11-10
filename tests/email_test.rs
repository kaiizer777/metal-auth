use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use axum::http::StatusCode;
use chrono::Utc;
use metal_auth::{
    AppError, Config, ConfigError, EmailDispatcher, ErrorCode, PasswordResetEmailPayload,
    SharedEmailSender, VerificationEmailPayload,
};
use tokio::time::sleep;
use tracing::Level;
use uuid::Uuid;

#[derive(Clone)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

static LOG_BUF: OnceLock<LogBuf> = OnceLock::new();
static LOG_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn init_logs() {
    let buf = LOG_BUF.get_or_init(|| LogBuf(Arc::new(Mutex::new(Vec::new()))));
    let _ = tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_writer(buf.clone())
        .with_ansi(false)
        .try_init();
}

fn clear_logs() {
    if let Some(buf) = LOG_BUF.get() {
        buf.0.lock().unwrap().clear();
    }
}

fn log_text() -> String {
    if let Some(buf) = LOG_BUF.get() {
        String::from_utf8(buf.0.lock().unwrap().clone()).unwrap_or_default()
    } else {
        String::new()
    }
}

#[derive(Clone)]
struct MockSender {
    delay_ms: u64,
    fail: bool,
    captured_v: Arc<Mutex<Option<VerificationEmailPayload>>>,
    captured_r: Arc<Mutex<Option<PasswordResetEmailPayload>>>,
}

#[async_trait]
impl metal_auth::EmailSender for MockSender {
    async fn send_verification_email(
        &self,
        payload: VerificationEmailPayload,
    ) -> Result<(), metal_auth::DynError> {
        let this = self.clone();
        if this.delay_ms > 0 {
            sleep(Duration::from_millis(this.delay_ms)).await;
        }
        this.captured_v.lock().unwrap().replace(payload);
        if this.fail {
            return Err(Box::new(std::io::Error::other("boom")));
        }
        Ok(())
    }

    async fn send_password_reset_email(
        &self,
        payload: PasswordResetEmailPayload,
    ) -> Result<(), metal_auth::DynError> {
        let this = self.clone();
        if this.delay_ms > 0 {
            sleep(Duration::from_millis(this.delay_ms)).await;
        }
        this.captured_r.lock().unwrap().replace(payload);
        if this.fail {
            return Err(Box::new(std::io::Error::other("boom")));
        }
        Ok(())
    }
}

struct NonBlockingSignalSender {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    captured: Arc<Mutex<Option<VerificationEmailPayload>>>,
}

#[async_trait]
impl metal_auth::EmailSender for NonBlockingSignalSender {
    async fn send_verification_email(
        &self,
        payload: VerificationEmailPayload,
    ) -> Result<(), metal_auth::DynError> {
        self.entered.notify_one();
        self.release.notified().await;
        self.captured.lock().unwrap().replace(payload);
        Ok(())
    }

    async fn send_password_reset_email(
        &self,
        _payload: PasswordResetEmailPayload,
    ) -> Result<(), metal_auth::DynError> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(())
    }
}

struct HangingSender;

#[async_trait]
impl metal_auth::EmailSender for HangingSender {
    async fn send_verification_email(
        &self,
        _payload: VerificationEmailPayload,
    ) -> Result<(), metal_auth::DynError> {
        let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
        let _ = rx.await;
        Ok(())
    }

    async fn send_password_reset_email(
        &self,
        _payload: PasswordResetEmailPayload,
    ) -> Result<(), metal_auth::DynError> {
        let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
        let _ = rx.await;
        Ok(())
    }
}

fn sample_verification() -> VerificationEmailPayload {
    VerificationEmailPayload {
        user_id: Uuid::new_v4(),
        to: "user@example.com".into(),
        token: "token-123".into(),
        url: "https://example.com/auth/verify/email?token=token-123".into(),
        expires_at: Utc::now(),
    }
}

fn sample_reset() -> PasswordResetEmailPayload {
    PasswordResetEmailPayload {
        user_id: Uuid::new_v4(),
        to: "user@example.com".into(),
        token: "token-456".into(),
        url: "https://example.com/auth/password/reset?token=token-456".into(),
        expires_at: Utc::now(),
    }
}

#[test]
fn payload_serialization_roundtrip() {
    let v = sample_verification();
    let json = serde_json::to_string(&v).unwrap();
    let back: VerificationEmailPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);

    let r = sample_reset();
    let json = serde_json::to_string(&r).unwrap();
    let back: PasswordResetEmailPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[tokio::test]
async fn full_payload_assertion() {
    let _guard = LOG_LOCK.lock().await;
    init_logs();
    clear_logs();
    let captured = Arc::new(Mutex::new(None));
    let mock = MockSender {
        delay_ms: 0,
        fail: false,
        captured_v: captured.clone(),
        captured_r: Arc::new(Mutex::new(None)),
    };
    let sender: SharedEmailSender = Arc::new(mock);
    let dispatcher = EmailDispatcher::new(Some(sender), Duration::from_secs(10), true);

    let payload = sample_verification();
    let handle = dispatcher
        .dispatch_verification(payload.clone())
        .await
        .expect("should return handle");
    handle.await.unwrap();

    let got = captured.lock().unwrap().clone().unwrap();
    assert_eq!(got.user_id, payload.user_id);
    assert_eq!(got.to, payload.to);
    assert_eq!(got.token, payload.token);
    assert_eq!(got.url, payload.url);
    assert_eq!(got.expires_at, payload.expires_at);
}

#[tokio::test]
async fn full_reset_payload_assertion() {
    let _guard = LOG_LOCK.lock().await;
    init_logs();
    clear_logs();
    let captured = Arc::new(Mutex::new(None));
    let mock = MockSender {
        delay_ms: 0,
        fail: false,
        captured_v: Arc::new(Mutex::new(None)),
        captured_r: captured.clone(),
    };
    let sender: SharedEmailSender = Arc::new(mock);
    let dispatcher = EmailDispatcher::new(Some(sender), Duration::from_secs(10), true);

    let payload = sample_reset();
    let handle = dispatcher
        .dispatch_password_reset(payload.clone())
        .await
        .expect("should return handle");
    handle.await.unwrap();

    let got = captured.lock().unwrap().clone().unwrap();
    assert_eq!(got.user_id, payload.user_id);
    assert_eq!(got.to, payload.to);
    assert_eq!(got.token, payload.token);
    assert_eq!(got.url, payload.url);
    assert_eq!(got.expires_at, payload.expires_at);
}

#[tokio::test]
async fn sync_dispatch_awaits_and_logs_error() {
    let _guard = LOG_LOCK.lock().await;
    init_logs();
    clear_logs();
    let captured = Arc::new(Mutex::new(None));
    let mock = MockSender {
        delay_ms: 0,
        fail: true,
        captured_v: captured.clone(),
        captured_r: Arc::new(Mutex::new(None)),
    };
    let sender: SharedEmailSender = Arc::new(mock);
    let dispatcher = EmailDispatcher::new(Some(sender), Duration::from_secs(10), false);

    let h = dispatcher
        .dispatch_verification(sample_verification())
        .await;
    assert!(h.is_none());
    assert!(log_text().contains("email dispatch failed"));
}

#[tokio::test]
async fn none_sender_warns_no_panic() {
    let _guard = LOG_LOCK.lock().await;
    init_logs();
    clear_logs();
    let dispatcher = EmailDispatcher::new(None, Duration::from_secs(10), true);
    let h1 = dispatcher
        .dispatch_verification(sample_verification())
        .await;
    assert!(h1.is_none());
    let h2 = dispatcher.dispatch_password_reset(sample_reset()).await;
    assert!(h2.is_none());
    assert!(log_text().contains("no email sender configured"));
}

#[tokio::test]
async fn hook_returns_err_is_logged() {
    let _guard = LOG_LOCK.lock().await;
    init_logs();
    clear_logs();
    let captured = Arc::new(Mutex::new(None));
    let mock = MockSender {
        delay_ms: 0,
        fail: true,
        captured_v: captured,
        captured_r: Arc::new(Mutex::new(None)),
    };
    let sender: SharedEmailSender = Arc::new(mock);
    let dispatcher = EmailDispatcher::new(Some(sender), Duration::from_secs(10), true);
    let handle = dispatcher
        .dispatch_verification(sample_verification())
        .await
        .expect("should return handle");
    handle.await.unwrap();
    assert!(log_text().contains("email dispatch failed"));
}

#[tokio::test]
async fn async_dispatch_non_blocking() {
    let _guard = LOG_LOCK.lock().await;
    init_logs();
    clear_logs();

    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let captured = Arc::new(Mutex::new(None));

    let sender: SharedEmailSender = Arc::new(NonBlockingSignalSender {
        entered: entered.clone(),
        release: release.clone(),
        captured: captured.clone(),
    });
    let dispatcher = EmailDispatcher::new(Some(sender), Duration::from_secs(10), true);

    let handle = dispatcher
        .dispatch_verification(sample_verification())
        .await
        .expect("should return handle immediately");

    // Wait until background task starts executing send_verification_email
    entered.notified().await;

    // Sender has entered and is suspended waiting on `release`, proving dispatch returned before completion
    assert!(
        captured.lock().unwrap().is_none(),
        "dispatch returned immediately without waiting for sender completion"
    );
    assert!(!handle.is_finished());

    // Release the mock sender to complete
    release.notify_one();
    handle.await.unwrap();

    assert!(
        captured.lock().unwrap().is_some(),
        "mock sender executed to completion once released"
    );
}

#[tokio::test]
async fn timeout_does_not_panic() {
    let _guard = LOG_LOCK.lock().await;
    init_logs();
    clear_logs();

    let sender: SharedEmailSender = Arc::new(HangingSender);
    let dispatcher = EmailDispatcher::new(Some(sender), Duration::from_millis(20), true);
    let handle = dispatcher
        .dispatch_verification(sample_verification())
        .await
        .expect("should return handle");
    handle.await.unwrap();
    assert!(log_text().contains("timed out"));
}

#[test]
fn zero_timeout_rejected() {
    let cfg = Config {
        database_url: "postgres://localhost/test".into(),
        port: 3000,
        allowed_origins: vec![],
        allowed_methods: vec!["GET".into()],
        allowed_headers: vec!["Content-Type".into()],
        max_connections: 5,
        min_connections: 1,
        base_url: "https://example.com".into(),
        email_dispatch_timeout: Duration::ZERO,
        async_email_dispatch: true,
    };
    assert!(matches!(
        cfg.validate(),
        Err(ConfigError::InvalidEnvVar("EMAIL_DISPATCH_TIMEOUT_SECS"))
    ));
}

#[test]
fn email_app_error_methods_do_not_panic() {
    let variants: [AppError; 3] = [
        AppError::EmailHookNotConfigured,
        AppError::EmailDispatchFailed(Box::new(std::io::Error::other("fail"))),
        AppError::EmailDispatchTimeout,
    ];

    for err in variants {
        assert_eq!(err.error_code(), ErrorCode::InternalError);
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.response_message(), "Internal error");
    }
}

#[test]
fn empty_base_url_rejected() {
    let cfg = Config {
        database_url: "postgres://localhost/test".into(),
        port: 3000,
        allowed_origins: vec![],
        allowed_methods: vec!["GET".into()],
        allowed_headers: vec!["Content-Type".into()],
        max_connections: 5,
        min_connections: 1,
        base_url: "".into(),
        email_dispatch_timeout: Duration::from_secs(10),
        async_email_dispatch: true,
    };
    assert!(matches!(
        cfg.validate(),
        Err(ConfigError::MissingEnvVar("BASE_URL"))
    ));
}

#[test]
fn base_url_validation_rejects_invalid_urls() {
    let make_cfg = |url: &str| Config {
        database_url: "postgres://localhost/test".into(),
        port: 3000,
        allowed_origins: vec![],
        allowed_methods: vec!["GET".into()],
        allowed_headers: vec!["Content-Type".into()],
        max_connections: 5,
        min_connections: 1,
        base_url: url.into(),
        email_dispatch_timeout: Duration::from_secs(10),
        async_email_dispatch: true,
    };

    assert!(matches!(
        make_cfg("").validate(),
        Err(ConfigError::MissingEnvVar("BASE_URL"))
    ));
    assert!(matches!(
        make_cfg("   ").validate(),
        Err(ConfigError::MissingEnvVar("BASE_URL"))
    ));
    assert!(matches!(
        make_cfg("ftp://example.com").validate(),
        Err(ConfigError::InvalidEnvVar("BASE_URL"))
    ));
    assert!(matches!(
        make_cfg("not-a-url").validate(),
        Err(ConfigError::InvalidEnvVar("BASE_URL"))
    ));
    assert!(matches!(
        make_cfg("https://").validate(),
        Err(ConfigError::InvalidEnvVar("BASE_URL"))
    ));
    assert!(matches!(
        make_cfg("https://example.com?tenant=x").validate(),
        Err(ConfigError::InvalidEnvVar("BASE_URL"))
    ));
    assert!(make_cfg("https://example.com").validate().is_ok());
    assert!(make_cfg("http://localhost:3000").validate().is_ok());
}

#[test]
fn base_url_validation_rejects_query_string() {
    let cfg = Config {
        database_url: "postgres://localhost/test".into(),
        port: 3000,
        allowed_origins: vec![],
        allowed_methods: vec!["GET".into()],
        allowed_headers: vec!["Content-Type".into()],
        max_connections: 5,
        min_connections: 1,
        base_url: "https://example.com?tenant=x".into(),
        email_dispatch_timeout: Duration::from_secs(10),
        async_email_dispatch: true,
    };
    assert!(matches!(
        cfg.validate(),
        Err(ConfigError::InvalidEnvVar("BASE_URL"))
    ));
}

#[test]
fn dispatcher_with_base_url_builder() {
    let dispatcher = EmailDispatcher::new(None, Duration::from_secs(5), true)
        .with_base_url("https://auth.example.com");
    assert_eq!(dispatcher.base_url(), Some("https://auth.example.com"));
}

#[test]
fn build_verification_url_formatting() {
    let url = EmailDispatcher::build_verification_url("https://auth.example.com", "token-xyz");
    assert_eq!(
        url,
        "https://auth.example.com/auth/verify/email?token=token-xyz"
    );
    let trailing_slash_url =
        EmailDispatcher::build_verification_url("https://auth.example.com/", "token-xyz");
    assert_eq!(
        trailing_slash_url,
        "https://auth.example.com/auth/verify/email?token=token-xyz"
    );
    let encoded_url = EmailDispatcher::build_verification_url(
        "https://auth.example.com/",
        "token with spaces+symbols",
    );
    assert_eq!(
        encoded_url,
        "https://auth.example.com/auth/verify/email?token=token%20with%20spaces%2Bsymbols"
    );
}

#[test]
fn build_reset_url_formatting() {
    let url = EmailDispatcher::build_reset_url("https://auth.example.com", "token-abc");
    assert_eq!(
        url,
        "https://auth.example.com/auth/password/reset?token=token-abc"
    );
    let trailing_slash_url =
        EmailDispatcher::build_reset_url("https://auth.example.com/", "token-abc");
    assert_eq!(
        trailing_slash_url,
        "https://auth.example.com/auth/password/reset?token=token-abc"
    );
    let encoded_url =
        EmailDispatcher::build_reset_url("https://auth.example.com/", "token with spaces+symbols");
    assert_eq!(
        encoded_url,
        "https://auth.example.com/auth/password/reset?token=token%20with%20spaces%2Bsymbols"
    );
}
