mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::http::StatusCode;
use common::*;
use metal_auth::{
    AppError, ErrorCode, OAuthCallbackOutcome, OAuthProvider, OAuthService, SessionService,
    TokenResponse, UserInfo,
};
use uuid::Uuid;

fn generate_test_password() -> String {
    format!("T3st!{}", Uuid::new_v4().simple())
}

#[derive(Debug)]
struct MockOAuthProvider {
    id: &'static str,
    user_info: tokio::sync::RwLock<UserInfo>,
    fail_exchange: AtomicBool,
}

impl MockOAuthProvider {
    fn new(id: &'static str, user_info: UserInfo) -> Self {
        Self {
            id,
            user_info: tokio::sync::RwLock::new(user_info),
            fail_exchange: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl OAuthProvider for MockOAuthProvider {
    fn id(&self) -> &'static str {
        self.id
    }

    fn auth_url(&self, state: &str, code_challenge: &str) -> String {
        format!(
            "https://mock.{}.com/auth?state={state}&code_challenge={code_challenge}",
            self.id
        )
    }

    async fn exchange_code(
        &self,
        code: &str,
        _code_verifier: &str,
    ) -> Result<TokenResponse, AppError> {
        if self.fail_exchange.load(Ordering::SeqCst) || code == "bad_code" {
            return Err(AppError::OAuthProviderError);
        }
        Ok(TokenResponse {
            access_token: format!("mock_token_for_{}", self.id),
            token_type: "Bearer".to_string(),
            refresh_token: None,
            expires_in: Some(3600),
            id_token: None,
            raw: HashMap::new(),
        })
    }

    async fn fetch_user_info(&self, _tokens: &TokenResponse) -> Result<UserInfo, AppError> {
        let r = self.user_info.read().await;
        Ok(r.clone())
    }
}

fn create_test_oauth_service(
    app: &TestApp,
    google_mock: Arc<MockOAuthProvider>,
    github_mock: Option<Arc<MockOAuthProvider>>,
) -> OAuthService {
    let mut providers: HashMap<String, Arc<dyn OAuthProvider>> = HashMap::new();
    providers.insert("google".to_string(), google_mock as Arc<dyn OAuthProvider>);
    if let Some(gh) = github_mock {
        providers.insert("github".to_string(), gh as Arc<dyn OAuthProvider>);
    }

    let mut cfg = app.state.config.clone();
    cfg.oauth.state_secret = "01234567890123456789012345678901".to_string();
    let cfg_arc = Arc::new(cfg);
    let session_service = Arc::new(SessionService::new(app.pool.clone(), Arc::clone(&cfg_arc)));

    OAuthService::with_providers(
        app.pool.clone(),
        cfg_arc,
        session_service,
        Arc::clone(&app.state.totp_service),
        providers,
    )
}

fn extract_state_from_url(url: &str) -> &str {
    url.split("state=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
}

#[tokio::test]
async fn test_oauth_pre_hijacking_rejected_on_unverified_provider_email() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let victim_email = dynamic_email();
    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog_unverified_1".to_string(),
            email: victim_email.clone(),
            email_verified: false, // Provider reports unverified email!
            name: None,
            avatar_url: None,
        },
    ));

    let svc = create_test_oauth_service(&app, google_mock, None);

    let (auth_url, set_cookie) = svc
        .get_authorization_url("google", None)
        .expect("get auth url");
    let state_token = extract_state_from_url(&auth_url);

    // Act: callback must reject before database mutations
    let res = svc
        .handle_callback_extended(
            "google",
            "valid_code",
            state_token,
            Some(&set_cookie),
            "cookie",
            None,
            None,
        )
        .await;

    assert!(matches!(res, Err(AppError::OAuthEmailUnverified)));

    // Verify zero database records created
    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(user_count.0, 0);

    let link_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_accounts")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(link_count.0, 0);
}

#[tokio::test]
async fn test_oauth_pre_hijacking_collision_rejected_on_unverified_local_account() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let victim_email = dynamic_email();
    let local_user_id = Uuid::new_v4();

    // Attacker pre-registered victim_email locally, but email is UNVERIFIED
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, $3, $4)",
    )
    .bind(local_user_id)
    .bind(&victim_email)
    .bind("argon2id$hashedpassword")
    .bind(false) // email_verified: false
    .execute(&app.pool)
    .await
    .unwrap();

    // Victim attempts OAuth login with verified Google email
    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog_victim_sub".to_string(),
            email: victim_email.clone(),
            email_verified: true,
            name: Some("Victim".to_string()),
            avatar_url: None,
        },
    ));

    let svc = create_test_oauth_service(&app, google_mock, None);

    let (auth_url, set_cookie) = svc
        .get_authorization_url("google", None)
        .expect("get auth url");
    let state_token = extract_state_from_url(&auth_url);

    // Act: must reject with 409 Conflict to prevent account hijacking
    let res = svc
        .handle_callback_extended(
            "google",
            "valid_code",
            state_token,
            Some(&set_cookie),
            "cookie",
            None,
            None,
        )
        .await;

    assert!(matches!(res, Err(AppError::OAuthAccountLinkConflict)));

    // Verify no oauth_account was linked
    let link_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_accounts")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(link_count.0, 0);
}

#[tokio::test]
async fn test_oauth_auto_links_verified_existing_local_user() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email = dynamic_email();
    let local_user_id = Uuid::new_v4();

    // Pre-existing verified local user
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, $3, $4)",
    )
    .bind(local_user_id)
    .bind(&email)
    .bind("argon2id$hashedpassword")
    .bind(true) // email_verified: true
    .execute(&app.pool)
    .await
    .unwrap();

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog_existing_sub".to_string(),
            email: email.clone(),
            email_verified: true,
            name: Some("Existing User".to_string()),
            avatar_url: None,
        },
    ));

    let svc = create_test_oauth_service(&app, google_mock, None);

    let (auth_url, set_cookie) = svc
        .get_authorization_url("google", None)
        .expect("get auth url");
    let state_token = extract_state_from_url(&auth_url);

    // Act: link verified user
    let OAuthCallbackOutcome::Login(res) = svc
        .handle_callback_extended(
            "google",
            "valid_code",
            state_token,
            Some(&set_cookie),
            "cookie",
            None,
            None,
        )
        .await
        .expect("handle callback")
    else {
        panic!("expected login outcome");
    };
    let (session, user, clear_cookie) = (res.session, res.user, res.clear_cookie_header);

    assert!(res.is_linked);
    assert!(!res.is_created);
    assert_eq!(user.id, local_user_id);
    assert_eq!(session.user_id, local_user_id);
    assert!(clear_cookie.contains("Max-Age=0"));

    // Verify exactly 1 user and 1 oauth_account in DB
    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(user_count.0, 1);

    let link: (Uuid, String) = sqlx::query_as(
        "SELECT user_id, provider_user_id FROM oauth_accounts WHERE provider_id = 'google'",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(link.0, local_user_id);
    assert_eq!(link.1, "goog_existing_sub");

    // Second callback for same identity converges idempotently
    let (auth_url2, set_cookie2) = svc
        .get_authorization_url("google", None)
        .expect("get auth url");
    let state_token2 = extract_state_from_url(&auth_url2);

    let OAuthCallbackOutcome::Login(res2) = svc
        .handle_callback_extended(
            "google",
            "valid_code",
            state_token2,
            Some(&set_cookie2),
            "cookie",
            None,
            None,
        )
        .await
        .expect("second callback")
    else {
        panic!("expected login outcome");
    };
    let (session2, user2) = (res2.session, res2.user);

    assert_eq!(user2.id, local_user_id);
    assert_ne!(session.id, session2.id); // New session minted

    let link_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_accounts")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(link_count.0, 1);
}

#[tokio::test]
async fn test_oauth_auto_provisions_new_verified_user() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email = dynamic_email();
    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog_new_user_sub".to_string(),
            email: email.clone(),
            email_verified: true,
            name: Some("Newbie".to_string()),
            avatar_url: None,
        },
    ));

    let svc = create_test_oauth_service(&app, google_mock, None);

    let (auth_url, set_cookie) = svc
        .get_authorization_url("google", Some("/onboarding".to_string()))
        .expect("get auth url");
    let state_token = extract_state_from_url(&auth_url);

    let outcome = svc
        .handle_callback_extended(
            "google",
            "valid_code",
            state_token,
            Some(&set_cookie),
            "cookie",
            Some("127.0.0.1"),
            Some("test-agent"),
        )
        .await
        .expect("handle callback");
    let res = match outcome {
        OAuthCallbackOutcome::Login(r) => r,
        OAuthCallbackOutcome::TwoFactorRequired { .. } => panic!("expected login"),
        OAuthCallbackOutcome::Linked { .. } => panic!("expected login"),
    };

    assert!(res.is_created);
    assert!(res.is_linked);
    assert_eq!(res.redirect_url, "/onboarding");
    assert!(res.user.email_verified);
    assert_eq!(res.user.password_hash, "$unusable$oauth$");

    // Verify row in database
    let db_user: (String, bool, String) =
        sqlx::query_as("SELECT email, email_verified, password_hash FROM users WHERE id = $1")
            .bind(res.user.id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(db_user.0, email);
    assert!(db_user.1);
    assert_eq!(db_user.2, "$unusable$oauth$");
}

#[tokio::test]
async fn test_oauth_login_for_totp_user_issues_challenge_and_no_session() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: format!("goog_totp_{}", Uuid::new_v4().simple()),
            email: dynamic_email(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));
    let svc = create_test_oauth_service(&app, google_mock, None);

    let (auth_url, set_cookie) = svc
        .get_authorization_url("google", None)
        .expect("get auth url");
    let state_token = extract_state_from_url(&auth_url);
    let first = svc
        .handle_callback_extended(
            "google",
            "valid_code",
            state_token,
            Some(&set_cookie),
            "cookie",
            Some("127.0.0.1"),
            Some("test-agent"),
        )
        .await
        .expect("first callback");
    let user_id = match first {
        OAuthCallbackOutcome::Login(result) => result.user.id,
        other => panic!("expected login, got {other:?}"),
    };

    let enrollment = app
        .state
        .totp_service
        .enroll_totp(user_id)
        .await
        .expect("enroll");
    let code = totp_code(&enrollment.secret_base32);
    app.state
        .totp_service
        .confirm_enrollment(user_id, &code, "127.0.0.1")
        .await
        .expect("confirm");

    let sessions_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&app.pool)
            .await
            .expect("count sessions");
    assert_eq!(sessions_before, 1, "the first login mints one session");

    let (auth_url, set_cookie) = svc
        .get_authorization_url("google", None)
        .expect("get auth url");
    let state_token = extract_state_from_url(&auth_url);
    let second = svc
        .handle_callback_extended(
            "google",
            "valid_code",
            state_token,
            Some(&set_cookie),
            "cookie",
            Some("127.0.0.1"),
            Some("test-agent"),
        )
        .await
        .expect("second callback");

    let OAuthCallbackOutcome::TwoFactorRequired {
        challenge_token, ..
    } = second
    else {
        panic!("a TOTP-enabled account must not receive a session from OAuth");
    };
    assert_eq!(
        app.state
            .totp_service
            .validate_two_factor_token(&challenge_token)
            .await
            .expect("challenge token is redeemable"),
        user_id
    );

    let sessions_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&app.pool)
            .await
            .expect("count sessions");
    assert_eq!(sessions_after, sessions_before, "no session may be created");
}

#[tokio::test]
async fn oauth_login_cannot_issue_a_session_while_an_activation_is_in_flight() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: format!("goog_race_{}", Uuid::new_v4().simple()),
            email: dynamic_email(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));
    let svc = create_test_oauth_service(&app, google_mock, None);

    let (auth_url, set_cookie) = svc
        .get_authorization_url("google", None)
        .expect("get auth url");
    let state_token = extract_state_from_url(&auth_url).to_string();
    let first = svc
        .handle_callback_extended(
            "google",
            "valid_code",
            &state_token,
            Some(&set_cookie),
            "cookie",
            Some("127.0.0.1"),
            Some("test-agent"),
        )
        .await
        .expect("first callback");
    let user_id = match first {
        OAuthCallbackOutcome::Login(result) => result.user.id,
        other => panic!("expected login, got {other:?}"),
    };

    // Pending enrollment: the factor row exists and `enabled` is still FALSE.
    app.state
        .totp_service
        .enroll_totp(user_id)
        .await
        .expect("enroll");

    // The activation is committed by `confirm_enrollment`, here held open to race the gate.
    let mut activation = app.pool.begin().await.expect("activation transaction");
    sqlx::query(
        "UPDATE totp_secrets SET enabled = TRUE, updated_at = CURRENT_TIMESTAMP \
         WHERE user_id = $1",
    )
    .bind(user_id)
    .execute(&mut *activation)
    .await
    .expect("hold the activation");

    let sessions_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&app.pool)
            .await
            .expect("count sessions");

    let (auth_url, set_cookie) = svc
        .get_authorization_url("google", None)
        .expect("get auth url");
    let state_token = extract_state_from_url(&auth_url).to_string();
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    let worker = svc.clone();
    tokio::spawn(async move {
        let outcome = worker
            .handle_callback_extended(
                "google",
                "valid_code",
                &state_token,
                Some(&set_cookie),
                "cookie",
                Some("127.0.0.1"),
                Some("test-agent"),
            )
            .await;
        let _ = tx.send(outcome);
    });

    // Give the callback time to reach the gate, then require the gate to still be open.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let early = tokio::time::timeout(Duration::from_millis(300), &mut rx).await;
    assert!(
        early.is_err(),
        "the oauth gate must wait for an in-flight enrollment activation"
    );

    activation.commit().await.expect("release the activation");

    let outcome = rx.await.expect("callback task").expect("callback result");
    let OAuthCallbackOutcome::TwoFactorRequired { .. } = outcome else {
        panic!("an account activated during the callback must not receive a session");
    };
    let sessions_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&app.pool)
            .await
            .expect("count sessions");
    assert_eq!(sessions_after, sessions_before, "no session may be created");
}

#[tokio::test]
async fn test_oauth_link_and_unlink_account_lifecycle() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email = dynamic_email();
    let user_id = Uuid::new_v4();

    // User with unusable password ($unusable$oauth$)
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(&email)
    .bind("$unusable$oauth$")
    .bind(true)
    .execute(&app.pool)
    .await
    .unwrap();

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog_uid_1".to_string(),
            email: email.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));
    let github_mock = Arc::new(MockOAuthProvider::new(
        "github",
        UserInfo {
            provider_id: "github".to_string(),
            provider_user_id: "gh_uid_2".to_string(),
            email: email.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));

    let svc = create_test_oauth_service(&app, google_mock, Some(github_mock));

    // 1. Link Google
    let (auth_url_g, cookie_g) = svc.get_authorization_url("google", None).unwrap();
    let state_g = extract_state_from_url(&auth_url_g);
    svc.link_account_identity(user_id, "google", "code_g", state_g, Some(&cookie_g))
        .await
        .expect("link google");

    // 2. Lockout Guard Check: cannot unlink the only login method
    let unlink_err = svc.unlink_account(user_id, "google").await;
    assert!(matches!(unlink_err, Err(AppError::ValidationError(_))));

    // 3. Link GitHub (now 2 linked accounts)
    let (auth_url_gh, cookie_gh) = svc.get_authorization_url("github", None).unwrap();
    let state_gh = extract_state_from_url(&auth_url_gh);
    svc.link_account_identity(user_id, "github", "code_gh", state_gh, Some(&cookie_gh))
        .await
        .expect("link github");

    // Verify 2 linked accounts
    let accounts = svc.list_linked_accounts(user_id).await.unwrap();
    assert_eq!(accounts.len(), 2);

    // 4. Unlinking Google now succeeds because GitHub remains
    svc.unlink_account(user_id, "google")
        .await
        .expect("unlink google");

    // Verify 1 linked account remaining
    let remaining = svc.list_linked_accounts(user_id).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].provider_id, "github");

    // 5. Unlinking the remaining GitHub fails again with lockout guard
    let unlink_err2 = svc.unlink_account(user_id, "github").await;
    assert!(matches!(unlink_err2, Err(AppError::ValidationError(_))));

    // 6. User sets a password
    let valid_password = generate_test_password();
    let password_hash = metal_auth::crypto::hash_password(&valid_password, &app.state.auth_config)
        .expect("hash password");
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(&password_hash)
        .bind(user_id)
        .execute(&app.pool)
        .await
        .unwrap();

    // 7. Now unlinking GitHub succeeds because user has a usable password!
    svc.unlink_account(user_id, "github")
        .await
        .expect("unlink github with password");
    let accounts_empty = svc.list_linked_accounts(user_id).await.unwrap();
    assert_eq!(accounts_empty.len(), 0);

    let login_res = app.state.auth_service.login(&email, &valid_password).await;
    assert!(login_res.is_ok());
}

#[tokio::test]
async fn test_oauth_unusable_password_login_returns_invalid_credentials() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email = dynamic_email();
    let user_id = Uuid::new_v4();
    let attempted_password = generate_test_password();

    // 1. User created via OAuth with sentinel $unusable$oauth$ password hash
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(&email)
    .bind("$unusable$oauth$")
    .bind(true)
    .execute(&app.pool)
    .await
    .unwrap();

    // Direct auth service login call: executes dummy verification without leaking account state
    let res = app
        .state
        .auth_service
        .login(&email, &attempted_password)
        .await;
    assert!(matches!(res, Err(AppError::InvalidCredentials)));

    // HTTP login dispatch check
    let resp = app
        .post_json(
            "/auth/login",
            serde_json::json!({
                "email": email,
                "password": &attempted_password
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.error_code(), Some(ErrorCode::InvalidCredentials));

    // 2. Also test user with empty password hash
    let email_empty_hash = dynamic_email();
    let user_id_2 = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id_2)
    .bind(&email_empty_hash)
    .bind("")
    .bind(true)
    .execute(&app.pool)
    .await
    .unwrap();

    let res_empty = app
        .state
        .auth_service
        .login(&email_empty_hash, &attempted_password)
        .await;
    assert!(matches!(res_empty, Err(AppError::InvalidCredentials)));
}

#[tokio::test]
async fn test_oauth_email_normalization_on_provisioning() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let mixed_email = format!("MixedCase.{}@EXAMPLE.COM", Uuid::new_v4());
    let normalized_expected = mixed_email.trim().to_lowercase();

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog_mixed_sub".to_string(),
            email: mixed_email.clone(),
            email_verified: true,
            name: Some("Mixed Case".to_string()),
            avatar_url: None,
        },
    ));

    let svc = create_test_oauth_service(&app, google_mock, None);

    let (auth_url, set_cookie) = svc
        .get_authorization_url("google", None)
        .expect("get auth url");
    let state_token = extract_state_from_url(&auth_url);

    let outcome = svc
        .handle_callback_extended(
            "google",
            "valid_code",
            state_token,
            Some(&set_cookie),
            "cookie",
            None,
            None,
        )
        .await
        .expect("handle callback");
    let res = match outcome {
        OAuthCallbackOutcome::Login(r) => r,
        OAuthCallbackOutcome::TwoFactorRequired { .. } => panic!("expected login"),
        OAuthCallbackOutcome::Linked { .. } => panic!("expected login"),
    };

    assert_eq!(res.user.email, normalized_expected);

    // Verify database row has lowercased email
    let db_email: (String,) = sqlx::query_as("SELECT email FROM users WHERE id = $1")
        .bind(res.user.id)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(db_email.0, normalized_expected);

    let oauth_email: (String,) =
        sqlx::query_as("SELECT email FROM oauth_accounts WHERE user_id = $1")
            .bind(res.user.id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(oauth_email.0, normalized_expected);

    // Verify clear_state_cookie helper on OAuthService
    let clear_header = svc.clear_state_cookie();
    assert!(clear_header.contains("Max-Age=0"));
    assert!(clear_header.contains("oauth_state="));
}

#[tokio::test]
async fn test_oauth_link_intent_in_callback_attaches_identity_without_session() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email = dynamic_email();
    let user_id = Uuid::new_v4();

    // Verified local user
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(&email)
    .bind("argon2id$somehash")
    .bind(true)
    .execute(&app.pool)
    .await
    .unwrap();

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog_link_sub_99".to_string(),
            email: email.clone(),
            email_verified: true,
            name: Some("Linked User".to_string()),
            avatar_url: None,
        },
    ));

    let svc = create_test_oauth_service(&app, google_mock, None);

    // 1. Initiate link flow with authenticated user_id
    let session_svc = SessionService::new(app.pool.clone(), Arc::new(app.state.config.clone()));
    let (session, _raw) = session_svc
        .create_session(user_id, "cookie", None, None)
        .await
        .unwrap();
    let (auth_url, set_cookie) = svc
        .initiate_link_flow(
            "google",
            user_id,
            Some("/settings".to_string()),
            Some(session.token_hash.clone()),
        )
        .expect("initiate link flow");
    let state_token = extract_state_from_url(&auth_url);

    // 2. Process callback with link intent
    let outcome = svc
        .handle_callback_extended(
            "google",
            "valid_code",
            state_token,
            Some(&set_cookie),
            "cookie",
            None,
            None,
        )
        .await
        .expect("handle callback with link intent");

    match outcome {
        OAuthCallbackOutcome::Linked {
            user,
            account,
            redirect_url,
            clear_cookie_header,
        } => {
            assert_eq!(user.id, user_id);
            assert_eq!(account.user_id, user_id);
            assert_eq!(account.provider_id, "google");
            assert_eq!(account.provider_user_id, "goog_link_sub_99");
            assert_eq!(redirect_url, "/settings");
            assert!(clear_cookie_header.contains("Max-Age=0"));
        }
        OAuthCallbackOutcome::Login(_) => panic!("expected Linked outcome, got Login"),
        OAuthCallbackOutcome::TwoFactorRequired { .. } => {
            panic!("expected Linked outcome, got TwoFactorRequired")
        }
    }

    // 3. Invariant: the callback issued no session beyond the initiating one
    let session_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND token_hash != $2")
            .bind(user_id)
            .bind(&session.token_hash)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(
        session_count.0, 0,
        "link callback must not issue a login session"
    );
}

#[tokio::test]
async fn link_callback_succeeds_without_500_after_commit() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email = dynamic_email();
    let user_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(&email)
    .bind("argon2id$somehash")
    .bind(true)
    .execute(&app.pool)
    .await
    .unwrap();

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog_link_sub_500".to_string(),
            email: email.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));

    let svc = create_test_oauth_service(&app, google_mock, None);

    let session_svc = SessionService::new(app.pool.clone(), Arc::new(app.state.config.clone()));
    let (session, _raw) = session_svc
        .create_session(user_id, "cookie", None, None)
        .await
        .unwrap();
    let (auth_url, set_cookie) = svc
        .initiate_link_flow(
            "google",
            user_id,
            Some("/settings".to_string()),
            Some(session.token_hash.clone()),
        )
        .expect("initiate link flow");
    let state_token = extract_state_from_url(&auth_url);

    // link intent commits oauth_accounts: callback must succeed, not 500
    let outcome = svc
        .handle_callback_extended(
            "google",
            "valid_code",
            state_token,
            Some(&set_cookie),
            "cookie",
            None,
            None,
        )
        .await
        .expect("link callback succeeds");
    let (linked_user, redirect_url, clear_cookie_header) = match outcome {
        OAuthCallbackOutcome::Linked {
            user,
            redirect_url,
            clear_cookie_header,
            ..
        } => (user, redirect_url, clear_cookie_header),
        OAuthCallbackOutcome::Login(_) => panic!("expected Linked outcome, got Login"),
        OAuthCallbackOutcome::TwoFactorRequired { .. } => {
            panic!("expected Linked outcome, got TwoFactorRequired")
        }
    };
    assert_eq!(linked_user.id, user_id);
    assert_eq!(redirect_url, "/settings");
    assert!(clear_cookie_header.contains("Max-Age=0"));

    let link_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM oauth_accounts WHERE user_id = $1 AND provider_id = 'google'",
    )
    .bind(user_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(link_count.0, 1);
}

#[tokio::test]
async fn link_callback_for_unknown_initiator_rejects_before_commit() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let missing_user_id = Uuid::new_v4();
    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: format!("goog-missing-user-{}", Uuid::new_v4()),
            email: dynamic_email(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));

    let svc = create_test_oauth_service(&app, google_mock, None);

    let (auth_url, set_cookie) = svc
        // The intent carries no session hash, so the pre-commit session gate
        // rejects before the missing-initiator lookup would run.
        .initiate_link_flow("google", missing_user_id, Some("/settings".to_string()), None)
        .expect("initiate link flow");
    let state_token = extract_state_from_url(&auth_url);

    // An absent initiator is an invalid state, never a server fault.
    let err = svc
        .handle_callback_extended(
            "google",
            "valid_code",
            state_token,
            Some(&set_cookie),
            "cookie",
            None,
            None,
        )
        .await
        .expect_err("missing user must fail");
    assert!(
        matches!(err, AppError::OAuthStateInvalid),
        "expected OAuthStateInvalid for a missing initiator, got {err:?}"
    );

    let link_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_accounts")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(link_count.0, 0, "no link row may be committed");
}

#[tokio::test]
async fn link_callback_revoked_session_rejected_before_commit() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email = dynamic_email();
    let user_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(&email)
    .bind("argon2id$somehash")
    .bind(true)
    .execute(&app.pool)
    .await
    .unwrap();

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: format!("goog-revoked-session-{}", Uuid::new_v4()),
            email: email.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));

    let svc = create_test_oauth_service(&app, google_mock, None);

    let session_svc = SessionService::new(app.pool.clone(), Arc::new(app.state.config.clone()));
    let (session, _raw) = session_svc
        .create_session(user_id, "cookie", None, None)
        .await
        .unwrap();
    let (auth_url, set_cookie) = svc
        .initiate_link_flow(
            "google",
            user_id,
            Some("/settings".to_string()),
            Some(session.token_hash.clone()),
        )
        .expect("initiate link flow");
    let state_token = extract_state_from_url(&auth_url);

    // initiating session revoked in-flight (logout / revoke-all)
    session_svc
        .invalidate_by_hash(&session.token_hash)
        .await
        .unwrap();

    // revoked session must block the link pre-commit, never Err-after-write
    let err = svc
        .handle_callback_extended(
            "google",
            "valid_code",
            state_token,
            Some(&set_cookie),
            "cookie",
            None,
            None,
        )
        .await
        .expect_err("revoked session must fail");
    assert!(
        matches!(err, AppError::OAuthStateInvalid),
        "expected OAuthStateInvalid for revoked initiating session, got {err:?}"
    );

    let link_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_accounts")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(link_count.0, 0, "no link row may be committed");
}

// Revoke-before-link ordering: the revocation commits while the callback is
// in flight, before its session check executes. The link must be rejected.
#[tokio::test]
async fn link_callback_rejects_when_revoke_commits_before_link_check() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email = dynamic_email();
    let user_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(&email)
    .bind("argon2id$somehash")
    .bind(true)
    .execute(&app.pool)
    .await
    .unwrap();

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: format!("goog-revoke-race-{}", Uuid::new_v4()),
            email: email.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));

    let svc = create_test_oauth_service(&app, google_mock, None);

    let session_svc = SessionService::new(app.pool.clone(), Arc::new(app.state.config.clone()));
    let (session, _raw) = session_svc
        .create_session(user_id, "cookie", None, None)
        .await
        .unwrap();
    let (auth_url, set_cookie) = svc
        .initiate_link_flow(
            "google",
            user_id,
            Some("/settings".to_string()),
            Some(session.token_hash.clone()),
        )
        .expect("initiate link flow");
    let state_token = extract_state_from_url(&auth_url).to_string();

    // Stage the revocation in an open transaction: deleted but uncommitted.
    let mut holder = app.pool.begin().await.expect("revoke txn");
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(&session.token_hash)
        .execute(&mut *holder)
        .await
        .expect("stage session delete");

    // Callback runs concurrently with the in-flight revocation.
    let callback = tokio::spawn(async move {
        svc.handle_callback_extended(
            "google",
            "valid_code",
            &state_token,
            Some(&set_cookie),
            "cookie",
            None,
            None,
        )
        .await
    });

    // Let the callback reach its session check, then commit the revocation
    // before that check executes.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    holder.commit().await.expect("commit revocation");

    let err = callback
        .await
        .expect("callback task")
        .expect_err("in-flight revoke must fail");
    assert!(
        matches!(err, AppError::OAuthStateInvalid),
        "expected OAuthStateInvalid for revoked initiating session, got {err:?}"
    );

    let link_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_accounts")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(link_count.0, 0, "no link row may be committed");
}

// Deleted initiator: the account and its session cascade away between link
// initiation and the callback. The link must fail as invalid state, not a 500.
#[tokio::test]
async fn link_callback_rejects_deleted_initiating_user() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email = dynamic_email();
    let user_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(&email)
    .bind("argon2id$somehash")
    .bind(true)
    .execute(&app.pool)
    .await
    .unwrap();

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: format!("goog-deleted-user-{}", Uuid::new_v4()),
            email: email.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));

    let svc = create_test_oauth_service(&app, google_mock, None);

    let session_svc = SessionService::new(app.pool.clone(), Arc::new(app.state.config.clone()));
    let (session, _raw) = session_svc
        .create_session(user_id, "cookie", None, None)
        .await
        .unwrap();
    let (auth_url, set_cookie) = svc
        .initiate_link_flow(
            "google",
            user_id,
            Some("/settings".to_string()),
            Some(session.token_hash.clone()),
        )
        .expect("initiate link flow");
    let state_token = extract_state_from_url(&auth_url).to_string();

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&app.pool)
        .await
        .expect("delete initiating user");

    let err = svc
        .handle_callback_extended(
            "google",
            "valid_code",
            &state_token,
            Some(&set_cookie),
            "cookie",
            None,
            None,
        )
        .await
        .expect_err("deleted initiating user must reject the link");
    assert!(
        matches!(err, AppError::OAuthStateInvalid),
        "expected OAuthStateInvalid for a deleted initiator, got {err:?}"
    );

    let link_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_accounts")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(link_count.0, 0, "no link row may be committed");
}

// Link-before-revoke ordering: the callback and the revocation race from a
// barrier. Exactly one serialization is legal, and the callback outcome must
// match the committed link row (no Err after a committed write).
#[tokio::test]
async fn link_callback_race_with_revoke_stays_legal() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email = dynamic_email();
    let user_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(&email)
    .bind("argon2id$somehash")
    .bind(true)
    .execute(&app.pool)
    .await
    .unwrap();

    let provider_sub = format!("goog-link-revoke-race-{}", Uuid::new_v4());
    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: provider_sub.clone(),
            email: email.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));

    let svc = create_test_oauth_service(&app, google_mock, None);

    let session_svc = SessionService::new(app.pool.clone(), Arc::new(app.state.config.clone()));
    let (session, _raw) = session_svc
        .create_session(user_id, "cookie", None, None)
        .await
        .unwrap();
    let (auth_url, set_cookie) = svc
        .initiate_link_flow(
            "google",
            user_id,
            Some("/settings".to_string()),
            Some(session.token_hash.clone()),
        )
        .expect("initiate link flow");
    let state_token = extract_state_from_url(&auth_url).to_string();

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let callback_barrier = Arc::clone(&barrier);
    let callback = tokio::spawn(async move {
        callback_barrier.wait().await;
        svc.handle_callback_extended(
            "google",
            "valid_code",
            &state_token,
            Some(&set_cookie),
            "cookie",
            None,
            None,
        )
        .await
    });

    let pool = app.pool.clone();
    let token_hash = session.token_hash.clone();
    let revoker_barrier = Arc::clone(&barrier);
    let revoker = tokio::spawn(async move {
        revoker_barrier.wait().await;
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(&token_hash)
            .execute(&pool)
            .await
            .expect("revoke executes")
    });

    let (callback_res, revoker_res) =
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            (callback.await, revoker.await)
        })
        .await
        .expect("callback and revocation must complete, not deadlock");
    let outcome = callback_res.expect("callback task");
    revoker_res.expect("revoker task");

    let link_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM oauth_accounts WHERE provider_user_id = $1")
            .bind(&provider_sub)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    let session_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE token_hash = $1")
            .bind(&session.token_hash)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    // The revocation always commits, so the session row is always gone.
    assert_eq!(session_count.0, 0);
    match outcome {
        Ok(OAuthCallbackOutcome::Linked { .. }) => {
            assert_eq!(link_count.0, 1, "committed link must have its row");
        }
        Ok(OAuthCallbackOutcome::Login(_)) => panic!("link intent must not log in"),
        Ok(OAuthCallbackOutcome::TwoFactorRequired { .. }) => {
            panic!("link intent must not issue a challenge")
        }
        Err(AppError::OAuthStateInvalid) => {
            assert_eq!(link_count.0, 0, "rejected link must leave no row");
        }
        Err(e) => panic!("unexpected callback error under revoke race: {e:?}"),
    }
}

#[tokio::test]
async fn test_unlink_disabled_provider_lockout_prevention() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email = dynamic_email();
    let user_id = Uuid::new_v4();

    // Passwordless user
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(&email)
    .bind("$unusable$oauth$")
    .bind(true)
    .execute(&app.pool)
    .await
    .unwrap();

    // Link Google and GitHub
    sqlx::query(
        "INSERT INTO oauth_accounts (id, user_id, provider_id, provider_user_id, email) VALUES ($1, $2, $3, $4, $5), ($6, $7, $8, $9, $10)",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind("google")
    .bind("goog-sub-1")
    .bind(&email)
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind("github")
    .bind("gh-sub-1")
    .bind(&email)
    .execute(&app.pool)
    .await
    .unwrap();

    // Service where ONLY google is active (github is disabled)
    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog-sub-1".to_string(),
            email: email.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));

    let svc = create_test_oauth_service(&app, google_mock, None);

    // Unlinking Google must be rejected because GitHub is disabled and user has no usable password
    let res = svc.unlink_account(user_id, "google").await;
    assert!(matches!(res, Err(AppError::ValidationError(_))));
}

#[tokio::test]
async fn test_unlink_multi_identities_same_provider_lockout_prevention() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email = dynamic_email();
    let user_id = Uuid::new_v4();

    // Passwordless user
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(&email)
    .bind("$unusable$oauth$")
    .bind(true)
    .execute(&app.pool)
    .await
    .unwrap();

    // User linked two different Google accounts, no password, no other provider
    sqlx::query(
        "INSERT INTO oauth_accounts (id, user_id, provider_id, provider_user_id, email) VALUES ($1, $2, $3, $4, $5), ($6, $7, $8, $9, $10)",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind("google")
    .bind("goog-sub-1")
    .bind(&email)
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind("google")
    .bind("goog-sub-2")
    .bind(&email)
    .execute(&app.pool)
    .await
    .unwrap();

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog-sub-1".to_string(),
            email: email.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));

    let svc = create_test_oauth_service(&app, google_mock, None);

    // Unlinking Google would remove both Google rows, leaving user with 0 auth methods. Must be rejected!
    let res = svc.unlink_account(user_id, "google").await;
    assert!(matches!(res, Err(AppError::ValidationError(_))));
}

async fn insert_verified_user(app: &TestApp, email: &str, password_hash: &str) -> Uuid {
    let user_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(email)
    .bind(password_hash)
    .bind(true)
    .execute(&app.pool)
    .await
    .unwrap();
    user_id
}

async fn link_count_for_identity(app: &TestApp, provider_user_id: &str) -> i64 {
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM oauth_accounts WHERE provider_user_id = $1")
            .bind(provider_user_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    count.0
}

/// Deadline for observing a backend blocked by a staged transaction. Generous
/// by design: the gate must fail on a missed race, never on a slow executor.
const BLOCK_EVIDENCE_TIMEOUT: Duration = Duration::from_secs(15);

/// `pg_stat_activity` row: pid, state, wait event type, wait event, query head.
type BackendRow = (i32, Option<String>, Option<String>, Option<String>, String);

/// Backend pid of a holding transaction, usable as a stable blocker id: the
/// worker runs on a pooled connection whose pid the test cannot know up front.
async fn holder_backend_pid(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut **tx)
        .await
        .expect("holder backend pid readable")
}

/// Waits until a backend running `statement_prefix` is blocked by `blocker_pid`.
///
/// Without this gate a staged-race test converges through the read-only paths
/// whenever the worker arrives after the commit, leaving the unique-violation
/// branch unexercised while the test still passes. Expiry is a hard failure
/// naming the missing evidence, never a skip.
async fn wait_until_blocked_by(
    pool: &sqlx::PgPool,
    blocker_pid: i32,
    statement_prefix: &str,
    branch: &str,
) {
    let pattern = format!("{statement_prefix}%");
    let deadline = Instant::now() + BLOCK_EVIDENCE_TIMEOUT;
    loop {
        let blocked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_stat_activity \
             WHERE datname = current_database() \
               AND query LIKE $2 \
               AND $1 = ANY (pg_blocking_pids(pid))",
        )
        .bind(blocker_pid)
        .bind(&pattern)
        .fetch_one(pool)
        .await
        .expect("pg_stat_activity must be readable");

        if blocked > 0 {
            return;
        }
        if Instant::now() > deadline {
            let backends: Vec<BackendRow> = sqlx::query_as(
                // No `state` filter: the holder is idle with an open transaction and
                // a finished worker is idle too, so filtering hides exactly the
                // backends that explain the miss.
                "SELECT pid, state, wait_event_type, wait_event, left(query, 120) \
                 FROM pg_stat_activity WHERE datname = current_database() ORDER BY pid",
            )
            .fetch_all(pool)
            .await
            .unwrap_or_default();
            panic!(
                "{branch}: no backend was blocked by pg_backend_pid {blocker_pid} while running \
                 `{statement_prefix}...`, so the race branch was never entered; \
                 holder pid {blocker_pid}; backends: {backends:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn unlink_unknown_provider_returns_not_found() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email = dynamic_email();
    let user_id = insert_verified_user(&app, &email, "argon2id$somehash").await;

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog-unlinked".to_string(),
            email: email.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));
    let svc = create_test_oauth_service(&app, google_mock, None);

    let res = svc.unlink_account(user_id, "google").await;
    assert!(matches!(res, Err(AppError::NotFound)));
}

#[tokio::test]
async fn link_intent_without_session_hash_is_rejected() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email = dynamic_email();
    let user_id = insert_verified_user(&app, &email, "argon2id$somehash").await;
    let provider_sub = format!("goog-no-session-hash-{}", Uuid::new_v4());

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: provider_sub.clone(),
            email: email.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));
    let svc = create_test_oauth_service(&app, google_mock, None);

    let (auth_url, set_cookie) = svc
        .initiate_link_flow("google", user_id, Some("/settings".to_string()), None)
        .expect("initiate link flow");
    let state_token = extract_state_from_url(&auth_url);

    let err = svc
        .handle_callback_extended(
            "google",
            "valid_code",
            state_token,
            Some(&set_cookie),
            "cookie",
            None,
            None,
        )
        .await
        .expect_err("link intent without session binding must fail");
    assert!(matches!(err, AppError::OAuthStateInvalid));
    assert_eq!(link_count_for_identity(&app, &provider_sub).await, 0);
}

#[tokio::test]
async fn link_race_same_user_converges() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email = dynamic_email();
    let user_id = insert_verified_user(&app, &email, "argon2id$somehash").await;
    let provider_sub = format!("goog-race-same-{}", Uuid::new_v4());

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: provider_sub.clone(),
            email: email.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));
    let svc = create_test_oauth_service(&app, google_mock, None);

    // Stage the winning row uncommitted so the service's insert must wait and
    // lose to the unique constraint.
    let mut holder = app.pool.begin().await.expect("holder txn");
    sqlx::query(
        "INSERT INTO oauth_accounts (id, user_id, provider_id, provider_user_id, email) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind("google")
    .bind(&provider_sub)
    .bind(&email)
    .execute(&mut *holder)
    .await
    .expect("stage winning link");
    let blocker_pid = holder_backend_pid(&mut holder).await;

    let svc_task = svc.clone();
    let info = UserInfo {
        provider_id: "google".to_string(),
        provider_user_id: provider_sub.clone(),
        email: email.clone(),
        email_verified: true,
        name: None,
        avatar_url: None,
    };
    let task = tokio::spawn(async move {
        svc_task
            .link_identity_to_user(user_id, "google", &info)
            .await
    });

    // Hold the transaction open until the worker's insert is provably waiting
    // on it: only then does the unique violation decide the outcome.
    wait_until_blocked_by(
        &app.pool,
        blocker_pid,
        "INSERT INTO oauth_accounts",
        "link_race_same_user_converges",
    )
    .await;
    holder.commit().await.expect("commit winning link");

    let account = task
        .await
        .expect("link task")
        .expect("same-user race converges");
    assert_eq!(account.user_id, user_id);
    assert_eq!(link_count_for_identity(&app, &provider_sub).await, 1);
}

#[tokio::test]
async fn link_race_other_user_conflicts() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email_a = dynamic_email();
    let email_b = dynamic_email();
    let user_a = insert_verified_user(&app, &email_a, "argon2id$somehash").await;
    let user_b = insert_verified_user(&app, &email_b, "argon2id$somehash").await;
    let provider_sub = format!("goog-race-other-{}", Uuid::new_v4());

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: provider_sub.clone(),
            email: email_a.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));
    let svc = create_test_oauth_service(&app, google_mock, None);

    let mut holder = app.pool.begin().await.expect("holder txn");
    sqlx::query(
        "INSERT INTO oauth_accounts (id, user_id, provider_id, provider_user_id, email) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(user_b)
    .bind("google")
    .bind(&provider_sub)
    .bind(&email_b)
    .execute(&mut *holder)
    .await
    .expect("stage rival link");
    let blocker_pid = holder_backend_pid(&mut holder).await;

    let svc_task = svc.clone();
    let info = UserInfo {
        provider_id: "google".to_string(),
        provider_user_id: provider_sub.clone(),
        email: email_a.clone(),
        email_verified: true,
        name: None,
        avatar_url: None,
    };
    let task = tokio::spawn(async move {
        svc_task
            .link_identity_to_user(user_a, "google", &info)
            .await
    });

    // The conflict must come from the post-rollback race resolution, not from
    // the pre-insert read, so wait until the insert is blocked on the rival.
    wait_until_blocked_by(
        &app.pool,
        blocker_pid,
        "INSERT INTO oauth_accounts",
        "link_race_other_user_conflicts",
    )
    .await;
    holder.commit().await.expect("commit rival link");

    let res = task.await.expect("link task");
    assert!(matches!(res, Err(AppError::OAuthAccountLinkConflict)));
    assert_eq!(link_count_for_identity(&app, &provider_sub).await, 1);

    let owner: (Uuid,) =
        sqlx::query_as("SELECT user_id FROM oauth_accounts WHERE provider_user_id = $1")
            .bind(&provider_sub)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(owner.0, user_b);
}

// Link-intent unique race: the callback's identity insert loses to a rival row
// committed by another user. The post-rollback resolution is read-only, so the
// link must fail with a conflict rather than report a success that would echo
// the rival's account (including its email) back to the linking user.
#[tokio::test]
async fn link_callback_rival_identity_race_conflicts() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email_a = dynamic_email();
    let email_b = dynamic_email();
    let user_a = insert_verified_user(&app, &email_a, "argon2id$somehash").await;
    let user_b = insert_verified_user(&app, &email_b, "argon2id$somehash").await;
    let provider_sub = format!("goog-link-callback-race-{}", Uuid::new_v4());

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: provider_sub.clone(),
            email: email_a.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));
    let svc = create_test_oauth_service(&app, google_mock, None);

    let session_svc = SessionService::new(app.pool.clone(), Arc::new(app.state.config.clone()));
    let (session, _raw) = session_svc
        .create_session(user_a, "cookie", None, None)
        .await
        .unwrap();
    let (auth_url, set_cookie) = svc
        .initiate_link_flow(
            "google",
            user_a,
            Some("/settings".to_string()),
            Some(session.token_hash.clone()),
        )
        .expect("initiate link flow");
    let state_token = extract_state_from_url(&auth_url).to_string();

    let mut holder = app.pool.begin().await.expect("holder txn");
    sqlx::query(
        "INSERT INTO oauth_accounts (id, user_id, provider_id, provider_user_id, email) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(user_b)
    .bind("google")
    .bind(&provider_sub)
    .bind(&email_b)
    .execute(&mut *holder)
    .await
    .expect("stage rival link");
    let blocker_pid = holder_backend_pid(&mut holder).await;

    let callback = tokio::spawn(async move {
        svc.handle_callback_extended(
            "google",
            "valid_code",
            &state_token,
            Some(&set_cookie),
            "cookie",
            None,
            None,
        )
        .await
    });

    // The pre-insert read cannot see the uncommitted rival, so the conflict has
    // to come from the unique violation and its post-rollback resolution. The
    // lock gate below is the sole discriminator: a worker arriving after the
    // commit takes the pre-insert conflict path and proves nothing about the race.
    wait_until_blocked_by(
        &app.pool,
        blocker_pid,
        "INSERT INTO oauth_accounts",
        "link_callback_rival_identity_race_conflicts",
    )
    .await;
    holder.commit().await.expect("commit rival link");

    let err = callback
        .await
        .expect("callback task")
        .expect_err("a rival identity must never be reported as linked");
    assert!(
        matches!(err, AppError::OAuthAccountLinkConflict),
        "expected OAuthAccountLinkConflict from the race resolution, got {err:?}"
    );

    let rival_email: (String,) =
        sqlx::query_as("SELECT email FROM oauth_accounts WHERE provider_user_id = $1")
            .bind(&provider_sub)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(
        rival_email.0, email_b,
        "the rival row must be left untouched"
    );
    assert_eq!(link_count_for_identity(&app, &provider_sub).await, 1);

    let linking_user_links: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM oauth_accounts WHERE user_id = $1")
            .bind(user_a)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(
        linking_user_links.0, 0,
        "the rejected link must write nothing"
    );

    let session_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND token_hash != $2")
            .bind(user_a)
            .bind(&session.token_hash)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(
        session_count.0, 0,
        "link callback must not issue a login session"
    );
}

#[tokio::test]
async fn login_with_linked_identity_returns_owner_not_conflict() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let owner_email = dynamic_email();
    let owner_id = insert_verified_user(&app, &owner_email, "argon2id$somehash").await;
    let other_email = dynamic_email();
    let _other_id = insert_verified_user(&app, &other_email, "argon2id$somehash").await;
    let provider_sub = format!("goog-login-owner-{}", Uuid::new_v4());

    sqlx::query(
        "INSERT INTO oauth_accounts (id, user_id, provider_id, provider_user_id, email) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(owner_id)
    .bind("google")
    .bind(&provider_sub)
    .bind(&owner_email)
    .execute(&app.pool)
    .await
    .expect("seed owner link");

    // Provider now reports a different local email for the same federated
    // principal: the login path resolves the identity owner, never a conflict.
    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: provider_sub.clone(),
            email: other_email.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));
    let svc = create_test_oauth_service(&app, google_mock, None);

    let (auth_url, set_cookie) = svc.get_authorization_url("google", None).unwrap();
    let state_token = extract_state_from_url(&auth_url);

    let OAuthCallbackOutcome::Login(res) = svc
        .handle_callback_extended(
            "google",
            "valid_code",
            state_token,
            Some(&set_cookie),
            "cookie",
            None,
            None,
        )
        .await
        .expect("login converges to the identity owner")
    else {
        panic!("expected login outcome");
    };

    assert_eq!(res.user.id, owner_id);
    assert!(!res.is_linked);
    assert!(!res.is_created);
    assert_eq!(link_count_for_identity(&app, &provider_sub).await, 1);
}

#[tokio::test]
async fn concurrent_link_same_identity_exactly_one_wins() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email_a = dynamic_email();
    let email_b = dynamic_email();
    let user_a = insert_verified_user(&app, &email_a, "argon2id$somehash").await;
    let user_b = insert_verified_user(&app, &email_b, "argon2id$somehash").await;
    let provider_sub = format!("goog-concurrent-{}", Uuid::new_v4());

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: provider_sub.clone(),
            email: email_a.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));
    let svc = create_test_oauth_service(&app, google_mock, None);

    let info_a = UserInfo {
        provider_id: "google".to_string(),
        provider_user_id: provider_sub.clone(),
        email: email_a.clone(),
        email_verified: true,
        name: None,
        avatar_url: None,
    };
    let info_b = UserInfo {
        provider_id: "google".to_string(),
        provider_user_id: provider_sub.clone(),
        email: email_b.clone(),
        email_verified: true,
        name: None,
        avatar_url: None,
    };

    let (res_a, res_b) = tokio::join!(
        svc.link_identity_to_user(user_a, "google", &info_a),
        svc.link_identity_to_user(user_b, "google", &info_b),
    );

    let wins = usize::from(res_a.is_ok()) + usize::from(res_b.is_ok());
    assert_eq!(wins, 1, "exactly one link may win: {res_a:?} / {res_b:?}");
    let loser = if res_a.is_ok() { res_b } else { res_a };
    assert!(matches!(loser, Err(AppError::OAuthAccountLinkConflict)));
    assert_eq!(link_count_for_identity(&app, &provider_sub).await, 1);

    // No provisioning happened on the link path: the two seeded users remain.
    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(user_count.0, 2);
}

// Login-path identity race: the provider email resolves to one local account
// while a concurrent insert links the same federated identity to another. The
// login trusts the unique-constraint winner instead of turning into a conflict,
// which is the deliberate asymmetry against the link path. This is the branch
// that reports the cross-owner adoption; the event itself is not assertable
// without a process-wide subscriber, so the adoption is pinned through its
// observable result.
#[tokio::test]
async fn login_adopts_identity_won_by_concurrent_insert() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let resolved_email = dynamic_email();
    let rival_email = dynamic_email();
    let resolved_id = insert_verified_user(&app, &resolved_email, "argon2id$somehash").await;
    let rival_id = insert_verified_user(&app, &rival_email, "argon2id$somehash").await;
    let provider_sub = format!("goog-login-adopt-{}", Uuid::new_v4());

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: provider_sub.clone(),
            email: resolved_email.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));
    let svc = create_test_oauth_service(&app, google_mock, None);

    let (auth_url, set_cookie) = svc.get_authorization_url("google", None).unwrap();
    let state_token = extract_state_from_url(&auth_url).to_string();

    // The rival owns the identity but reports a different email, so the login
    // resolves to `resolved_id` and only the unique violation decides.
    let mut holder = app.pool.begin().await.expect("holder txn");
    sqlx::query(
        "INSERT INTO oauth_accounts (id, user_id, provider_id, provider_user_id, email) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(rival_id)
    .bind("google")
    .bind(&provider_sub)
    .bind(&rival_email)
    .execute(&mut *holder)
    .await
    .expect("stage rival link");
    let blocker_pid = holder_backend_pid(&mut holder).await;

    let callback = tokio::spawn(async move {
        svc.handle_callback_extended(
            "google",
            "valid_code",
            &state_token,
            Some(&set_cookie),
            "cookie",
            None,
            None,
        )
        .await
    });

    wait_until_blocked_by(
        &app.pool,
        blocker_pid,
        "INSERT INTO oauth_accounts",
        "login_adopts_identity_won_by_concurrent_insert",
    )
    .await;
    holder.commit().await.expect("commit rival link");

    let OAuthCallbackOutcome::Login(res) = callback
        .await
        .expect("callback task")
        .expect("a concurrent identity insert must not fail the login")
    else {
        panic!("expected login outcome");
    };

    // `relink_winner` is the only adoption path that reports `is_linked: false`.
    assert_eq!(res.user.id, rival_id, "the login must adopt the winner");
    assert!(
        !res.is_linked,
        "adoption by unique-race is not a fresh link"
    );
    assert!(!res.is_created);
    assert_eq!(link_count_for_identity(&app, &provider_sub).await, 1);

    let resolved_links: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM oauth_accounts WHERE user_id = $1")
            .bind(resolved_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(
        resolved_links.0, 0,
        "the losing insert must leave no row behind"
    );

    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(user_count.0, 2, "no third user may be provisioned");
}

// Login-path user race: two logins provision the same normalized email at once.
// The loser must converge on the committed user and attach its identity there,
// not fail and not create a duplicate account.
#[tokio::test]
async fn login_adopts_user_won_by_concurrent_insert() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };
    truncate_tables(&app.pool).await.expect("truncate");

    let email = dynamic_email();
    let provider_sub = format!("goog-login-user-race-{}", Uuid::new_v4());
    let raced_id = Uuid::new_v4();

    let google_mock = Arc::new(MockOAuthProvider::new(
        "google",
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: provider_sub.clone(),
            email: email.clone(),
            email_verified: true,
            name: None,
            avatar_url: None,
        },
    ));
    let svc = create_test_oauth_service(&app, google_mock, None);

    let (auth_url, set_cookie) = svc.get_authorization_url("google", None).unwrap();
    let state_token = extract_state_from_url(&auth_url).to_string();

    // A concurrent flow has already staged the user for this email but not the
    // identity: the callback's user insert blocks, then loses to the index.
    let mut holder = app.pool.begin().await.expect("holder txn");
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, $3, $4)",
    )
    .bind(raced_id)
    .bind(&email)
    .bind("argon2id$somehash")
    .bind(true)
    .execute(&mut *holder)
    .await
    .expect("stage raced user");
    let blocker_pid = holder_backend_pid(&mut holder).await;

    let callback = tokio::spawn(async move {
        svc.handle_callback_extended(
            "google",
            "valid_code",
            &state_token,
            Some(&set_cookie),
            "cookie",
            None,
            None,
        )
        .await
    });

    wait_until_blocked_by(
        &app.pool,
        blocker_pid,
        "INSERT INTO users",
        "login_adopts_user_won_by_concurrent_insert",
    )
    .await;
    holder.commit().await.expect("commit raced user");

    let OAuthCallbackOutcome::Login(res) = callback
        .await
        .expect("callback task")
        .expect("a concurrent user insert must not fail the login")
    else {
        panic!("expected login outcome");
    };

    assert_eq!(res.user.id, raced_id, "the login must adopt the raced user");
    assert!(res.is_linked, "the adopted user gains the identity");
    assert!(!res.is_created, "the stale attempt created no user");
    assert_eq!(link_count_for_identity(&app, &provider_sub).await, 1);

    let users_for_email: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM users WHERE LOWER(email) = LOWER($1)")
            .bind(&email)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(users_for_email.0, 1, "email must stay unique");
}
