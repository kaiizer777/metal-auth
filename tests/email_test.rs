use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use metal_auth::{
    Config, ConfigError, EmailDispatcher, PasswordResetEmailPayload, SharedEmailSender,
    VerificationEmailPayload,
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
    let handle = dispatcher.dispatch_verification(payload.clone()).await;
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
    let handle = dispatcher.dispatch_password_reset(payload.clone()).await;
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

    let handle = dispatcher
        .dispatch_verification(sample_verification())
        .await;
    handle.await.unwrap();
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
    h1.await.unwrap();
    let h2 = dispatcher.dispatch_password_reset(sample_reset()).await;
    h2.await.unwrap();
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
        .await;
    handle.await.unwrap();
    assert!(log_text().contains("email dispatch failed"));
}

#[tokio::test]
async fn async_dispatch_non_blocking() {
    let _guard = LOG_LOCK.lock().await;
    init_logs();
    clear_logs();
    let captured = Arc::new(Mutex::new(None));
    let mock = MockSender {
        delay_ms: 500,
        fail: false,
        captured_v: captured,
        captured_r: Arc::new(Mutex::new(None)),
    };
    let sender: SharedEmailSender = Arc::new(mock);
    let dispatcher = EmailDispatcher::new(Some(sender), Duration::from_secs(10), true);

    let handle_res = tokio::time::timeout(
        Duration::from_millis(100),
        dispatcher.dispatch_verification(sample_verification()),
    )
    .await;
    assert!(
        handle_res.is_ok(),
        "dispatch_verification must return immediately in async mode"
    );
    let handle = handle_res.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn timeout_does_not_panic() {
    let _guard = LOG_LOCK.lock().await;
    init_logs();
    clear_logs();
    let captured = Arc::new(Mutex::new(None));
    let mock = MockSender {
        delay_ms: 200,
        fail: false,
        captured_v: captured,
        captured_r: Arc::new(Mutex::new(None)),
    };
    let sender: SharedEmailSender = Arc::new(mock);
    let dispatcher = EmailDispatcher::new(Some(sender), Duration::from_millis(50), true);
    let handle = dispatcher
        .dispatch_verification(sample_verification())
        .await;
    handle.await.unwrap();
    assert!(log_text().contains("timed out"));
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
