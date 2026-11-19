mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use axum::http::StatusCode;
use common::*;
use metal_auth::{
    AppError, ErrorCode, OAuthProvider, OAuthService, SessionService, TokenResponse, UserInfo,
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

    OAuthService::with_providers(app.pool.clone(), cfg_arc, session_service, providers)
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
        .handle_callback("google", "valid_code", state_token, Some(&set_cookie))
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
        .handle_callback("google", "valid_code", state_token, Some(&set_cookie))
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
    let (session, user, clear_cookie) = svc
        .handle_callback("google", "valid_code", state_token, Some(&set_cookie))
        .await
        .expect("handle callback");

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

    let (session2, user2, _) = svc
        .handle_callback("google", "valid_code", state_token2, Some(&set_cookie2))
        .await
        .expect("second callback");

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

    let res = svc
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
    svc.link_account(user_id, "google", "code_g", state_g, Some(&cookie_g))
        .await
        .expect("link google");

    // 2. Lockout Guard Check: cannot unlink the only login method
    let unlink_err = svc.unlink_account(user_id, "google").await;
    assert!(matches!(unlink_err, Err(AppError::ValidationError(_))));

    // 3. Link GitHub (now 2 linked accounts)
    let (auth_url_gh, cookie_gh) = svc.get_authorization_url("github", None).unwrap();
    let state_gh = extract_state_from_url(&auth_url_gh);
    svc.link_account(user_id, "github", "code_gh", state_gh, Some(&cookie_gh))
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
        .await
        .expect("handle callback");

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
