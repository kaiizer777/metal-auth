mod common;

use std::time::Duration;

use chrono::Utc;
use common::setup_test_app;
use metal_auth::{DatabaseBackend, DatabaseStore};
use sha2::Digest;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Generic Store Contract Assertion Helpers
// ─────────────────────────────────────────────────────────────────────────────

async fn assert_users_lifecycle(store: &dyn DatabaseStore) {
    let email = format!("store_user_{}@example.com", Uuid::new_v4());
    let password_hash = "$argon2id$v=19$m=19456,t=2,p=1$fake_hash_value";

    // 1. Create
    let user = store
        .users()
        .create_user(&email, password_hash)
        .await
        .expect("create user via store");
    assert_eq!(user.email, email);
    assert!(!user.email_verified);

    // 2. Fetch by ID and Email
    let by_id = store
        .users()
        .get_user_by_id(user.id)
        .await
        .expect("fetch by id")
        .expect("user exists");
    assert_eq!(by_id.id, user.id);

    let by_email = store
        .users()
        .get_user_by_email(&email)
        .await
        .expect("fetch by email")
        .expect("user exists");
    assert_eq!(by_email.id, user.id);

    // 3. Set email verified
    store
        .users()
        .set_email_verified(user.id, true)
        .await
        .expect("set verified");
    let verified = store
        .users()
        .get_user_by_id(user.id)
        .await
        .expect("fetch verified")
        .expect("user exists");
    assert!(verified.email_verified);

    // 4. Update password hash
    let new_hash = "$argon2id$v=19$m=19456,t=2,p=1$updated_hash";
    store
        .users()
        .update_password_hash(user.id, new_hash)
        .await
        .expect("update password");
    let updated = store
        .users()
        .get_user_by_id(user.id)
        .await
        .expect("fetch updated")
        .expect("user exists");
    assert_eq!(updated.password_hash, new_hash);

    // 5. Delete user
    let deleted = store
        .users()
        .delete_user(user.id)
        .await
        .expect("delete user");
    assert!(deleted);
    let after_delete = store
        .users()
        .get_user_by_id(user.id)
        .await
        .expect("fetch deleted user");
    assert!(after_delete.is_none());

    let deleted_again = store
        .users()
        .delete_user(user.id)
        .await
        .expect("delete non-existent user");
    assert!(!deleted_again);
}

async fn assert_sessions_lifecycle(store: &dyn DatabaseStore) {
    let email = format!("store_session_{}@example.com", Uuid::new_v4());
    let user = store
        .users()
        .create_user(&email, "hash")
        .await
        .expect("create user");

    let token_hash = hex::encode(sha2::Sha256::digest(b"test_session_token"));
    let expires = Utc::now() + chrono::Duration::hours(1);

    // 1. Create session
    let session = store
        .sessions()
        .create_session(
            user.id,
            &token_hash,
            "cookie",
            Some("csrf_token_abc"),
            expires,
        )
        .await
        .expect("create session");
    assert_eq!(session.user_id, user.id);
    assert_eq!(session.token_hash, token_hash);

    // 2. Fetch by token hash
    let fetched = store
        .sessions()
        .get_session_by_token_hash(&token_hash)
        .await
        .expect("fetch session")
        .expect("session exists");
    assert_eq!(fetched.id, session.id);

    // 3. List user sessions
    let list = store
        .sessions()
        .list_user_sessions(user.id)
        .await
        .expect("list sessions");
    assert_eq!(list.len(), 1);

    // 4. Rotate session
    let new_token_hash = hex::encode(sha2::Sha256::digest(b"rotated_session_token"));
    store
        .sessions()
        .rotate_session(session.id, &new_token_hash, Some("new_csrf"), Utc::now())
        .await
        .expect("rotate session");

    assert!(
        store
            .sessions()
            .get_session_by_token_hash(&token_hash)
            .await
            .expect("fetch old")
            .is_none()
    );
    assert!(
        store
            .sessions()
            .get_session_by_token_hash(&new_token_hash)
            .await
            .expect("fetch new")
            .is_some()
    );

    // 5. Delete session
    store
        .sessions()
        .delete_session(session.id)
        .await
        .expect("delete session");
    assert!(
        store
            .sessions()
            .get_session_by_token_hash(&new_token_hash)
            .await
            .expect("fetch deleted")
            .is_none()
    );

    // 6. Delete by token hash
    let token_hash_2 = hex::encode(sha2::Sha256::digest(b"test_session_token_2"));
    let session_2 = store
        .sessions()
        .create_session(user.id, &token_hash_2, "cookie", None, expires)
        .await
        .expect("create second session");
    assert_eq!(session_2.user_id, user.id);

    let deleted_by_hash = store
        .sessions()
        .delete_by_token_hash(&token_hash_2)
        .await
        .expect("delete by token hash");
    assert!(deleted_by_hash);
    assert!(
        store
            .sessions()
            .get_session_by_token_hash(&token_hash_2)
            .await
            .expect("fetch deleted by hash")
            .is_none()
    );

    let deleted_again = store
        .sessions()
        .delete_by_token_hash(&token_hash_2)
        .await
        .expect("delete already deleted session by hash");
    assert!(!deleted_again);

    let _ = store.users().delete_user(user.id).await;
}

async fn assert_tokens_lifecycle(store: &dyn DatabaseStore) {
    let email = format!("store_tokens_{}@example.com", Uuid::new_v4());
    let user = store
        .users()
        .create_user(&email, "hash")
        .await
        .expect("create user");

    let v_hash = [42u8; 32];
    let expires = Utc::now() + chrono::Duration::hours(1);

    // Verification token
    let v_token = store
        .tokens()
        .create_verification_token(user.id, &v_hash, expires)
        .await
        .expect("create vtoken");
    assert_eq!(v_token.user_id, user.id);

    let consumed = store
        .tokens()
        .consume_verification_token(&v_hash)
        .await
        .expect("consume vtoken")
        .expect("vtoken was present");
    assert_eq!(consumed.user_id, user.id);

    let double_consumed = store
        .tokens()
        .consume_verification_token(&v_hash)
        .await
        .expect("second consume call");
    assert!(double_consumed.is_none());

    // Password reset token
    let r_hash = [99u8; 32];
    let r_token = store
        .tokens()
        .create_password_reset_token(user.id, &r_hash, expires)
        .await
        .expect("create rtoken");
    assert_eq!(r_token.user_id, user.id);

    let deleted = store
        .tokens()
        .delete_user_password_reset_tokens(user.id)
        .await
        .expect("delete user rtokens");
    assert_eq!(deleted, 1);

    // Verification tokens deletion for user
    let v_hash_2 = [77u8; 32];
    store
        .tokens()
        .create_verification_token(user.id, &v_hash_2, expires)
        .await
        .expect("create second vtoken");
    let deleted_vtokens = store
        .tokens()
        .delete_verification_tokens_for_user(user.id)
        .await
        .expect("delete user verification tokens");
    assert_eq!(deleted_vtokens, 1);
    let consumed_after_delete = store
        .tokens()
        .consume_verification_token(&v_hash_2)
        .await
        .expect("consume after delete");
    assert!(consumed_after_delete.is_none());

    let _ = store.users().delete_user(user.id).await;
}

async fn assert_two_factor_token_round_trip(store: &dyn DatabaseStore) {
    let email = format!("store_2fa_{}@example.com", Uuid::new_v4());
    let user = store
        .users()
        .create_user(&email, "hash")
        .await
        .expect("create user");

    // Consume of a hash that was never stored returns None, not an error.
    let missing = store
        .totp()
        .consume_two_factor_token(&[7u8; 32])
        .await
        .expect("consume missing");
    assert!(missing.is_none());

    let token_hash = sha2::Sha256::digest(Uuid::new_v4().as_bytes()).to_vec();
    let expires = Utc::now() + chrono::Duration::minutes(5);

    let created = store
        .totp()
        .create_two_factor_token(user.id, &token_hash, "test-credential-hash", expires)
        .await
        .expect("create two-factor token");
    assert_eq!(created.user_id, user.id);
    assert_eq!(created.token_hash, token_hash);

    let consumed = store
        .totp()
        .consume_two_factor_token(&token_hash)
        .await
        .expect("consume two-factor token")
        .expect("token was present");
    assert_eq!(consumed.id, created.id);

    let second = store
        .totp()
        .consume_two_factor_token(&token_hash)
        .await
        .expect("second consume call");
    assert!(second.is_none());

    let _ = store.users().delete_user(user.id).await;
}

async fn assert_outbox_lifecycle(store: &dyn DatabaseStore) {
    let recipient = format!("outbox_{}@example.com", Uuid::new_v4());
    let payload = serde_json::json!({"action": "verify", "link": "https://example.com"});

    let outbox = store
        .outbox()
        .insert_outbox(&recipient, "verification", payload)
        .await
        .expect("insert outbox");
    assert_eq!(outbox.recipient, recipient);
    assert_eq!(outbox.status, "pending");

    let claimed = store
        .outbox()
        .claim_pending_outbox(10, Duration::from_secs(30))
        .await
        .expect("claim outbox");
    assert!(claimed.iter().any(|item| item.id == outbox.id));

    store
        .outbox()
        .mark_outbox_sent(outbox.id)
        .await
        .expect("mark outbox sent");
}

async fn assert_transaction_commit_and_rollback(store: &dyn DatabaseStore) {
    let tx_res = store.begin().await;
    match tx_res {
        Ok(mut tx) => {
            // 1. Rollback test
            let email_aborted = format!("tx_abort_{}@example.com", Uuid::new_v4());
            tx.users()
                .create_user(&email_aborted, "hash")
                .await
                .expect("create user in tx");
            tx.rollback().await.expect("rollback tx");

            let aborted_user = store
                .users()
                .get_user_by_email(&email_aborted)
                .await
                .expect("fetch aborted user");
            assert!(aborted_user.is_none(), "rolled back user must not exist");

            // 2. Commit test
            let email_committed = format!("tx_commit_{}@example.com", Uuid::new_v4());
            let mut tx = store.begin().await.expect("begin tx");
            let created = tx
                .users()
                .create_user(&email_committed, "hash")
                .await
                .expect("create user in tx");
            tx.commit().await.expect("commit tx");

            let committed_user = store
                .users()
                .get_user_by_email(&email_committed)
                .await
                .expect("fetch committed user");
            assert!(committed_user.is_some(), "committed user must exist");
            let _ = store.users().delete_user(created.id).await;

            // 3. Tx outbox unsupported methods return proper database errors (on Postgres)
            {
                let mut tx = store.begin().await.expect("begin tx");
                let claim_err = tx
                    .outbox()
                    .claim_pending_outbox(10, Duration::from_secs(30))
                    .await;
                if store.backend() == DatabaseBackend::Postgres {
                    assert!(claim_err.is_err());
                }
                let recover_err = tx
                    .outbox()
                    .recover_stale_processing(Duration::from_secs(30))
                    .await;
                if store.backend() == DatabaseBackend::Postgres {
                    assert!(recover_err.is_err());
                }
                tx.rollback().await.expect("rollback tx");
            }

            // 4. Tx delete methods with rollback
            let email_to_delete = format!("tx_del_{}@example.com", Uuid::new_v4());
            let u = store
                .users()
                .create_user(&email_to_delete, "hash")
                .await
                .expect("create user");
            let mut tx = store.begin().await.expect("begin tx");
            let deleted_in_tx = tx
                .users()
                .delete_user(u.id)
                .await
                .expect("delete user in tx");
            assert!(deleted_in_tx);
            tx.rollback().await.expect("rollback tx");
            assert!(
                store
                    .users()
                    .get_user_by_id(u.id)
                    .await
                    .expect("get user")
                    .is_some()
            );
            let _ = store.users().delete_user(u.id).await;
        }
        Err(metal_auth::AppError::TransactionNotSupported) => {
            // Standalone without replica set correctly fails closed
        }
        Err(e) => panic!("unexpected error beginning tx: {:?}", e),
    }
}

async fn assert_oauth_round_trip(store: &dyn DatabaseStore) {
    let email = format!("store_oauth_{}@example.com", Uuid::new_v4());
    let user = store
        .users()
        .create_user(&email, "hash")
        .await
        .expect("create user");

    let p_uid = format!("uid_{}", Uuid::new_v4());
    let account = store
        .oauth()
        .link_account(user.id, "google", &p_uid, &email)
        .await
        .expect("link oauth account");
    assert_eq!(account.user_id, user.id);

    let duplicate_err = store
        .oauth()
        .link_account(user.id, "google", &p_uid, &email)
        .await
        .unwrap_err();
    assert!(matches!(
        duplicate_err,
        metal_auth::AppError::OAuthAccountLinkConflict
    ));

    let missing = store
        .oauth()
        .get_account("google", &format!("uid_{}", Uuid::new_v4()))
        .await
        .expect("get missing account");
    assert!(missing.is_none());

    let fetched = store
        .oauth()
        .get_account("google", &p_uid)
        .await
        .expect("get account")
        .expect("account exists");
    assert_eq!(fetched.id, account.id);

    let listed = store
        .oauth()
        .list_accounts_for_user(user.id)
        .await
        .expect("list accounts");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, account.id);

    let unlinked = store
        .oauth()
        .unlink_account(user.id, "google")
        .await
        .expect("unlink account");
    assert!(unlinked);

    let after_unlink = store
        .oauth()
        .get_account("google", &p_uid)
        .await
        .expect("get after unlink");
    assert!(after_unlink.is_none());

    store
        .users()
        .delete_user(user.id)
        .await
        .expect("delete user");
}

async fn assert_totp_upsert_enabled_row_rejected(store: &dyn DatabaseStore) {
    let email = format!("store_totp_{}@example.com", Uuid::new_v4());
    let user = store
        .users()
        .create_user(&email, "hash")
        .await
        .expect("create user");

    let encrypted_secret = vec![1, 2, 3, 4, 5];
    let backup_codes = serde_json::json!(["code1", "code2"]);

    let secret = store
        .totp()
        .upsert_secret(user.id, &encrypted_secret, backup_codes.clone())
        .await
        .expect("upsert secret");
    assert!(!secret.enabled);

    store
        .totp()
        .enable_totp(user.id)
        .await
        .expect("enable totp");

    let already_enabled_err = store
        .totp()
        .upsert_secret(user.id, &encrypted_secret, backup_codes)
        .await
        .unwrap_err();
    assert!(
        matches!(
            already_enabled_err,
            metal_auth::AppError::TotpAlreadyEnabled
        ),
        "expected TotpAlreadyEnabled, got {:?}",
        already_enabled_err
    );

    let _ = store.users().delete_user(user.id).await;
}

async fn assert_get_user_by_email_case_insensitive(store: &dyn DatabaseStore) {
    let email = format!("store_ci_{}@example.com", Uuid::new_v4());
    let user = store
        .users()
        .create_user(&email, "hash")
        .await
        .expect("create user");

    let upper = email.to_uppercase();
    let mixed: String = email
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    for variant in [&upper, &mixed, &format!("  {email}  ")] {
        let fetched = store
            .users()
            .get_user_by_email(variant)
            .await
            .expect("fetch by email variant")
            .expect("user exists");
        assert_eq!(fetched.id, user.id);
    }

    let tx_res = store.begin().await;
    match tx_res {
        Ok(mut tx) => {
            for variant in [&upper, &mixed, &format!("  {email}  ")] {
                let in_tx = tx
                    .users()
                    .get_user_by_email(variant)
                    .await
                    .expect("fetch by email in tx")
                    .expect("user exists");
                assert_eq!(in_tx.id, user.id);
            }
            tx.rollback().await.expect("rollback tx");
        }
        Err(metal_auth::AppError::TransactionNotSupported) => {}
        Err(e) => panic!("unexpected error beginning tx: {:?}", e),
    }

    let unknown = format!("unknown_{}@example.com", Uuid::new_v4());
    let missing = store
        .users()
        .get_user_by_email(&unknown)
        .await
        .expect("fetch unknown email");
    assert!(missing.is_none());

    let _ = store.users().delete_user(user.id).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// PostgreSQL Store Tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_store_backend_and_ping() {
    let app = setup_test_app().await.expect("test app initialization");
    let store = app.state.store();

    assert_eq!(store.backend(), DatabaseBackend::Postgres);
    assert!(store.ping().await.is_ok());
}

#[tokio::test]
async fn test_store_users_lifecycle() {
    let app = setup_test_app().await.expect("test app initialization");
    assert_users_lifecycle(app.state.store().as_ref()).await;
}

#[tokio::test]
async fn test_store_sessions_lifecycle() {
    let app = setup_test_app().await.expect("test app initialization");
    assert_sessions_lifecycle(app.state.store().as_ref()).await;
}

#[tokio::test]
async fn test_store_tokens_lifecycle() {
    let app = setup_test_app().await.expect("test app initialization");
    assert_tokens_lifecycle(app.state.store().as_ref()).await;
}

#[tokio::test]
async fn test_store_two_factor_token_round_trip() {
    let app = setup_test_app().await.expect("test app initialization");
    assert_two_factor_token_round_trip(app.state.store().as_ref()).await;
}

#[tokio::test]
async fn test_store_outbox_lifecycle() {
    let app = setup_test_app().await.expect("test app initialization");
    assert_outbox_lifecycle(app.state.store().as_ref()).await;
}

#[tokio::test]
async fn test_store_transaction_commit_and_rollback() {
    let app = setup_test_app().await.expect("test app initialization");
    assert_transaction_commit_and_rollback(app.state.store().as_ref()).await;

    let store_arc: std::sync::Arc<dyn DatabaseStore> = app.state.store().clone();
    let config = app.state.config.clone();
    let custom_state = metal_auth::AppState::new_with_store(store_arc.clone(), config)
        .expect("AppState::new_with_store");
    assert_eq!(custom_state.store().backend(), DatabaseBackend::Postgres);
    assert!(custom_state.store().ping().await.is_ok());
}

#[cfg(feature = "mysql")]
fn mysql_test_config() -> metal_auth::Config {
    metal_auth::Config {
        database_url: "mysql://user:pass@localhost:3306/metal_auth_test".into(),
        backend: DatabaseBackend::Mysql,
        mongo: None,
        port: 3000,
        allowed_origins: vec![],
        allowed_methods: vec!["GET".into()],
        allowed_headers: vec!["Content-Type".into()],
        max_connections: 5,
        min_connections: 1,
        base_url: "https://example.com".into(),
        email_dispatch_timeout: Duration::from_secs(10),
        async_email_dispatch: true,
        outbox_poll_interval: Duration::from_millis(50),
        outbox_batch_size: 50,
        outbox_max_retries: 5,
        outbox_initial_backoff: Duration::from_secs(1),
        outbox_max_backoff: Duration::from_secs(300),
        outbox_sent_retention: Duration::from_secs(7 * 24 * 3600),
        session: metal_auth::SessionConfig::default(),
        rate_limit: metal_auth::RateLimitConfig::default(),
        oauth: metal_auth::OAuthConfig::default(),
        totp: metal_auth::TotpConfig::default(),
    }
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn new_with_store_accepts_mysql_store() {
    let pool = sqlx::MySqlPool::connect_lazy("mysql://user:pass@localhost:3306/metal_auth_test")
        .expect("lazy mysql pool");
    let store: std::sync::Arc<dyn DatabaseStore> =
        std::sync::Arc::new(metal_auth::MySqlStore::new(pool));
    let state = metal_auth::AppState::new_with_store(store, mysql_test_config())
        .expect("mysql store construction");
    assert_eq!(state.store().backend(), DatabaseBackend::Mysql);
}

#[tokio::test]
async fn test_store_oauth_round_trip() {
    let app = setup_test_app().await.expect("test app initialization");
    assert_oauth_round_trip(app.state.store().as_ref()).await;
}

#[tokio::test]
async fn test_store_totp_upsert_enabled_row_rejected() {
    let app = setup_test_app().await.expect("test app initialization");
    assert_totp_upsert_enabled_row_rejected(app.state.store().as_ref()).await;
}

#[tokio::test]
async fn test_store_get_user_by_email_case_insensitive() {
    let app = setup_test_app().await.expect("test app initialization");
    assert_get_user_by_email_case_insensitive(app.state.store().as_ref()).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// MySQL Store Contract Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "mysql")]
async fn get_mysql_store() -> Option<metal_auth::MySqlStore> {
    if std::env::var("TEST_SKIP_DOTENV").is_err() {
        dotenvy::dotenv().ok();
    }
    let url = std::env::var("MYSQL_DATABASE_URL")
        .or_else(|_| std::env::var("MYSQL_URL"))
        .ok()?;
    if !url.starts_with("mysql://") {
        return None;
    }
    let opts = metal_auth::db::DbPoolOptions {
        max_connections: 5,
        min_connections: 1,
        acquire_timeout: Duration::from_secs(3),
        max_retries: 1,
        ..Default::default()
    };
    let pool = metal_auth::db::init_mysql_pool_with_options(&url, opts)
        .await
        .ok()?;
    Some(metal_auth::MySqlStore::new(pool))
}

#[cfg(feature = "mysql")]
mod mysql_contract_tests {
    use super::*;

    #[tokio::test]
    async fn test_mysql_users_lifecycle() {
        let Some(store) = get_mysql_store().await else {
            eprintln!("skipping test_mysql_users_lifecycle: MYSQL_DATABASE_URL not set");
            return;
        };
        assert_users_lifecycle(&store).await;
    }

    #[tokio::test]
    async fn test_mysql_sessions_lifecycle() {
        let Some(store) = get_mysql_store().await else {
            eprintln!("skipping test_mysql_sessions_lifecycle: MYSQL_DATABASE_URL not set");
            return;
        };
        assert_sessions_lifecycle(&store).await;
    }

    #[tokio::test]
    async fn test_mysql_tokens_lifecycle() {
        let Some(store) = get_mysql_store().await else {
            eprintln!("skipping test_mysql_tokens_lifecycle: MYSQL_DATABASE_URL not set");
            return;
        };
        assert_tokens_lifecycle(&store).await;
    }

    #[tokio::test]
    async fn test_mysql_two_factor_token_round_trip() {
        let Some(store) = get_mysql_store().await else {
            eprintln!(
                "skipping test_mysql_two_factor_token_round_trip: MYSQL_DATABASE_URL not set"
            );
            return;
        };
        assert_two_factor_token_round_trip(&store).await;
    }

    #[tokio::test]
    async fn test_mysql_outbox_lifecycle() {
        let Some(store) = get_mysql_store().await else {
            eprintln!("skipping test_mysql_outbox_lifecycle: MYSQL_DATABASE_URL not set");
            return;
        };
        assert_outbox_lifecycle(&store).await;
    }

    #[tokio::test]
    async fn test_mysql_transaction_commit_and_rollback() {
        let Some(store) = get_mysql_store().await else {
            eprintln!(
                "skipping test_mysql_transaction_commit_and_rollback: MYSQL_DATABASE_URL not set"
            );
            return;
        };
        assert_transaction_commit_and_rollback(&store).await;
    }

    #[tokio::test]
    async fn test_mysql_oauth_round_trip() {
        let Some(store) = get_mysql_store().await else {
            eprintln!("skipping test_mysql_oauth_round_trip: MYSQL_DATABASE_URL not set");
            return;
        };
        assert_oauth_round_trip(&store).await;
    }

    #[tokio::test]
    async fn test_mysql_totp_upsert_enabled_row_rejected() {
        let Some(store) = get_mysql_store().await else {
            eprintln!(
                "skipping test_mysql_totp_upsert_enabled_row_rejected: MYSQL_DATABASE_URL not set"
            );
            return;
        };
        assert_totp_upsert_enabled_row_rejected(&store).await;
    }

    #[tokio::test]
    async fn test_mysql_get_user_by_email_case_insensitive() {
        let Some(store) = get_mysql_store().await else {
            eprintln!(
                "skipping test_mysql_get_user_by_email_case_insensitive: MYSQL_DATABASE_URL not set"
            );
            return;
        };
        assert_get_user_by_email_case_insensitive(&store).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MongoDB Store Contract Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "mongodb")]
async fn get_mongo_store() -> Option<common::MongoTestFixture> {
    if std::env::var("TEST_SKIP_DOTENV").is_err() {
        dotenvy::dotenv().ok();
    }
    let url = std::env::var("MONGODB_URI")
        .or_else(|_| std::env::var("MONGODB_URL"))
        .or_else(|_| std::env::var("MONGO_URL"))
        .ok()?;
    if !url.starts_with("mongodb://") && !url.starts_with("mongodb+srv://") {
        return None;
    }
    let db_name = common::mongo_test_database_name();
    let allow_standalone = std::env::var("MONGO_ALLOW_NON_TRANSACTIONAL_STANDALONE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let mut client_options = mongodb::options::ClientOptions::parse(&url).await.ok()?;
    client_options.connect_timeout = Some(Duration::from_secs(3));
    client_options.server_selection_timeout = Some(Duration::from_secs(3));
    let client = mongodb::Client::with_options(client_options).ok()?;
    let db = client.database(&db_name);
    db.run_command(mongodb::bson::doc! { "ping": 1 })
        .await
        .ok()?;

    let hello_doc = db
        .run_command(mongodb::bson::doc! { "hello": 1 })
        .await
        .ok()?;
    let is_replica_set = hello_doc.contains_key("setName")
        || hello_doc
            .get_str("msg")
            .map(|m| m == "isdbgrid")
            .unwrap_or(false);

    metal_auth::db::mongo::indexes::ensure_indexes(&db)
        .await
        .expect("Failed to create mongo indexes for store contract test");

    let store =
        metal_auth::MongoStore::new(client.clone(), &db_name, is_replica_set, allow_standalone);
    let guard = common::MongoTestGuard::new(client, db_name);
    Some(common::MongoTestFixture::new(store, guard))
}

#[cfg(feature = "mongodb")]
mod mongo_contract_tests {
    use super::*;

    #[tokio::test]
    async fn test_mongo_users_lifecycle() {
        let Some(fixture) = get_mongo_store().await else {
            eprintln!("skipping test_mongo_users_lifecycle: MONGODB_URI not set");
            return;
        };
        assert_users_lifecycle(&fixture.store).await;
        fixture.teardown().await;
    }

    #[tokio::test]
    async fn test_mongo_sessions_lifecycle() {
        let Some(fixture) = get_mongo_store().await else {
            eprintln!("skipping test_mongo_sessions_lifecycle: MONGODB_URI not set");
            return;
        };
        assert_sessions_lifecycle(&fixture.store).await;
        fixture.teardown().await;
    }

    #[tokio::test]
    async fn test_mongo_tokens_lifecycle() {
        let Some(fixture) = get_mongo_store().await else {
            eprintln!("skipping test_mongo_tokens_lifecycle: MONGODB_URI not set");
            return;
        };
        assert_tokens_lifecycle(&fixture.store).await;
        fixture.teardown().await;
    }

    #[tokio::test]
    async fn test_mongo_two_factor_token_round_trip() {
        let Some(fixture) = get_mongo_store().await else {
            eprintln!("skipping test_mongo_two_factor_token_round_trip: MONGODB_URI not set");
            return;
        };
        assert_two_factor_token_round_trip(&fixture.store).await;
        fixture.teardown().await;
    }

    #[tokio::test]
    async fn test_mongo_outbox_lifecycle() {
        let Some(fixture) = get_mongo_store().await else {
            eprintln!("skipping test_mongo_outbox_lifecycle: MONGODB_URI not set");
            return;
        };
        assert_outbox_lifecycle(&fixture.store).await;
        fixture.teardown().await;
    }

    #[tokio::test]
    async fn test_mongo_transaction_commit_and_rollback() {
        let Some(fixture) = get_mongo_store().await else {
            eprintln!("skipping test_mongo_transaction_commit_and_rollback: MONGODB_URI not set");
            return;
        };
        assert_transaction_commit_and_rollback(&fixture.store).await;
        fixture.teardown().await;
    }

    #[tokio::test]
    async fn test_mongo_oauth_round_trip() {
        let Some(fixture) = get_mongo_store().await else {
            eprintln!("skipping test_mongo_oauth_round_trip: MONGODB_URI not set");
            return;
        };
        assert_oauth_round_trip(&fixture.store).await;
        fixture.teardown().await;
    }

    #[tokio::test]
    async fn test_mongo_totp_upsert_enabled_row_rejected() {
        let Some(fixture) = get_mongo_store().await else {
            eprintln!("skipping test_mongo_totp_upsert_enabled_row_rejected: MONGODB_URI not set");
            return;
        };
        assert_totp_upsert_enabled_row_rejected(&fixture.store).await;
        fixture.teardown().await;
    }

    #[tokio::test]
    async fn test_mongo_get_user_by_email_case_insensitive() {
        let Some(fixture) = get_mongo_store().await else {
            eprintln!(
                "skipping test_mongo_get_user_by_email_case_insensitive: MONGODB_URI not set"
            );
            return;
        };
        assert_get_user_by_email_case_insensitive(&fixture.store).await;
        fixture.teardown().await;
    }
}
