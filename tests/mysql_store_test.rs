#![cfg(feature = "mysql")]

use std::time::Duration;

use chrono::Utc;
use metal_auth::{
    Config, DatabaseBackend, DatabaseStore, DbError, MySqlStore,
    db::{DbPoolOptions, init_mysql_pool_with_options},
};
use sqlx::MySqlPool;
use uuid::Uuid;

async fn get_test_mysql_pool() -> Option<MySqlPool> {
    dotenvy::dotenv().ok();
    let url = std::env::var("MYSQL_DATABASE_URL")
        .or_else(|_| std::env::var("MYSQL_URL"))
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()?;
    if !url.starts_with("mysql://") {
        return None;
    }
    let opts = DbPoolOptions {
        max_connections: 10,
        min_connections: 1,
        acquire_timeout: Duration::from_secs(3),
        max_retries: 1,
        ..Default::default()
    };
    init_mysql_pool_with_options(&url, opts).await.ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tier 1: Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_mysql_pool_options_conversion() {
    let cfg = Config {
        database_url: "mysql://root:secret@localhost:3306/metal_auth".into(),
        backend: DatabaseBackend::Mysql,
        mongo: None,
        port: 3000,
        allowed_origins: vec![],
        allowed_methods: vec![],
        allowed_headers: vec![],
        max_connections: 30,
        min_connections: 5,
        base_url: "https://example.com".into(),
        email_dispatch_timeout: Duration::from_secs(5),
        async_email_dispatch: true,
        outbox_poll_interval: Duration::from_millis(50),
        outbox_batch_size: 50,
        outbox_max_retries: 5,
        outbox_initial_backoff: Duration::from_secs(1),
        outbox_max_backoff: Duration::from_secs(300),
        outbox_sent_retention: Duration::from_secs(86400),
        session: metal_auth::SessionConfig::default(),
        rate_limit: metal_auth::RateLimitConfig::default(),
        oauth: metal_auth::OAuthConfig::default(),
        totp: metal_auth::TotpConfig::default(),
    };
    let opts = DbPoolOptions::from(&cfg);
    assert_eq!(opts.max_connections, 30);
    assert_eq!(opts.min_connections, 5);
}

#[tokio::test]
async fn test_mysql_db_pool_options_validation() {
    let options = DbPoolOptions {
        max_connections: 0,
        ..Default::default()
    };
    let err = init_mysql_pool_with_options("mysql://localhost/test", options)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        metal_auth::AppError::Config(metal_auth::ConfigError::InvalidValue {
            field: "max_connections",
            ..
        })
    ));
}

#[test]
fn test_mysql_backend_kind() {
    assert_eq!(DatabaseBackend::Mysql.to_string(), "mysql");
    let parsed = DatabaseBackend::from_scheme("mysql").expect("parse mysql scheme");
    assert_eq!(parsed, DatabaseBackend::Mysql);
}

#[test]
fn test_mysql_db_error_wrapping() {
    let err = DbError::new("MySQL query failed");
    assert_eq!(err.message, "MySQL query failed");
}

// ─────────────────────────────────────────────────────────────────────────────
// Tier 2: Integration Tests (Conditional on Live MySQL)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_mysql_users_lifecycle() {
    let Some(pool) = get_test_mysql_pool().await else {
        eprintln!("skipping test_mysql_users_lifecycle: MYSQL_URL not set");
        return;
    };
    let store = MySqlStore::new(pool);
    assert_eq!(store.backend(), DatabaseBackend::Mysql);
    assert!(store.ping().await.is_ok());

    let email = format!("mysql_user_{}@example.com", Uuid::new_v4());
    let password_hash = "$argon2id$v=19$m=19456,t=2,p=1$fake_hash_value";

    // 1. Create
    let user = store
        .users()
        .create_user(&email, password_hash)
        .await
        .expect("create user via mysql store");
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
}

#[tokio::test]
async fn test_mysql_users_duplicate_email_error() {
    let Some(pool) = get_test_mysql_pool().await else {
        eprintln!("skipping test_mysql_users_duplicate_email_error: MYSQL_URL not set");
        return;
    };
    let store = MySqlStore::new(pool);
    let email = format!("dup_{}@example.com", Uuid::new_v4());

    store
        .users()
        .create_user(&email, "hash1")
        .await
        .expect("first create succeeds");

    let err = store
        .users()
        .create_user(&email, "hash2")
        .await
        .unwrap_err();

    assert!(
        matches!(err, metal_auth::AppError::EmailAlreadyExists),
        "expected EmailAlreadyExists from MySQL 1062, got {:?}",
        err
    );
}

#[tokio::test]
async fn test_mysql_sessions_lifecycle() {
    let Some(pool) = get_test_mysql_pool().await else {
        eprintln!("skipping test_mysql_sessions_lifecycle: MYSQL_URL not set");
        return;
    };
    let store = MySqlStore::new(pool);
    let email = format!("sess_{}@example.com", Uuid::new_v4());
    let user = store
        .users()
        .create_user(&email, "hash")
        .await
        .expect("create user");

    let token_hash = format!("token_hash_{}", Uuid::new_v4());
    let expires = Utc::now() + chrono::Duration::hours(2);

    let session = store
        .sessions()
        .create_session(
            user.id,
            &token_hash,
            "cookie",
            Some("csrf_token_123"),
            expires,
        )
        .await
        .expect("create session");
    assert_eq!(session.user_id, user.id);

    let fetched = store
        .sessions()
        .get_session_by_token_hash(&token_hash)
        .await
        .expect("fetch session")
        .expect("session present");
    assert_eq!(fetched.id, session.id);

    store
        .sessions()
        .touch_session(session.id, Utc::now())
        .await
        .expect("touch session");

    let new_token_hash = format!("token_hash_rotated_{}", Uuid::new_v4());
    store
        .sessions()
        .rotate_session(
            session.id,
            &new_token_hash,
            Some("new_csrf_token"),
            Utc::now(),
        )
        .await
        .expect("rotate session");

    assert!(
        store
            .sessions()
            .get_session_by_token_hash(&token_hash)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .sessions()
            .get_session_by_token_hash(&new_token_hash)
            .await
            .unwrap()
            .is_some()
    );

    let list = store
        .sessions()
        .list_user_sessions(user.id)
        .await
        .expect("list user sessions");
    assert_eq!(list.len(), 1);

    store
        .sessions()
        .delete_session(session.id)
        .await
        .expect("delete session");
}

#[tokio::test]
async fn test_mysql_tokens_lifecycle() {
    let Some(pool) = get_test_mysql_pool().await else {
        eprintln!("skipping test_mysql_tokens_lifecycle: MYSQL_URL not set");
        return;
    };
    let store = MySqlStore::new(pool);
    let email = format!("tok_{}@example.com", Uuid::new_v4());
    let user = store
        .users()
        .create_user(&email, "hash")
        .await
        .expect("create user");

    let v_hash = [33u8; 32];
    let expires = Utc::now() + chrono::Duration::hours(1);

    store
        .tokens()
        .create_verification_token(user.id, &v_hash, expires)
        .await
        .expect("create vtoken");

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

    let r_hash = [55u8; 32];
    store
        .tokens()
        .create_password_reset_token(user.id, &r_hash, expires)
        .await
        .expect("create rtoken");

    let deleted_rtokens = store
        .tokens()
        .delete_user_password_reset_tokens(user.id)
        .await
        .expect("delete rtokens");
    assert_eq!(deleted_rtokens, 1);
}

#[tokio::test]
async fn test_mysql_outbox_lifecycle() {
    let Some(pool) = get_test_mysql_pool().await else {
        eprintln!("skipping test_mysql_outbox_lifecycle: MYSQL_URL not set");
        return;
    };
    let store = MySqlStore::new(pool);
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
        .claim_pending_outbox(10, Duration::from_secs(60))
        .await
        .expect("claim outbox");
    assert!(claimed.iter().any(|o| o.id == outbox.id));

    store
        .outbox()
        .mark_outbox_sent(outbox.id)
        .await
        .expect("mark outbox sent");
}

#[tokio::test]
async fn test_mysql_oauth_lifecycle() {
    let Some(pool) = get_test_mysql_pool().await else {
        eprintln!("skipping test_mysql_oauth_lifecycle: MYSQL_URL not set");
        return;
    };
    let store = MySqlStore::new(pool);
    let email = format!("oauth_{}@example.com", Uuid::new_v4());
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

    let fetched = store
        .oauth()
        .get_account("google", &p_uid)
        .await
        .expect("get account")
        .expect("account exists");
    assert_eq!(fetched.id, account.id);

    let unlinked = store
        .oauth()
        .unlink_account(user.id, "google")
        .await
        .expect("unlink account");
    assert!(unlinked);
}

#[tokio::test]
async fn test_mysql_totp_lifecycle() {
    let Some(pool) = get_test_mysql_pool().await else {
        eprintln!("skipping test_mysql_totp_lifecycle: MYSQL_URL not set");
        return;
    };
    let store = MySqlStore::new(pool);
    let email = format!("totp_{}@example.com", Uuid::new_v4());
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
    assert!(matches!(
        already_enabled_err,
        metal_auth::AppError::TotpAlreadyEnabled
    ));

    let code_hash = [11u8; 32];
    let recorded = store
        .totp()
        .record_used_code(user.id, &code_hash)
        .await
        .expect("record code");
    assert!(recorded);

    let replay_err = store
        .totp()
        .record_used_code(user.id, &code_hash)
        .await
        .unwrap_err();
    assert!(matches!(replay_err, metal_auth::AppError::TotpCodeReplayed));

    assert!(
        store
            .totp()
            .is_code_used(user.id, &code_hash)
            .await
            .unwrap()
    );

    let c_hash = [22u8; 32];
    let c_tok = store
        .totp()
        .create_two_factor_token(
            user.id,
            &c_hash,
            "cred_hash",
            Utc::now() + chrono::Duration::minutes(5),
        )
        .await
        .expect("create 2fa token");
    assert_eq!(c_tok.user_id, user.id);

    let consumed_2fa = store
        .totp()
        .consume_two_factor_token(&c_hash)
        .await
        .expect("consume 2fa token")
        .expect("token present");
    assert_eq!(consumed_2fa.user_id, user.id);
}

#[tokio::test]
async fn test_mysql_case_insensitive_email() {
    let Some(pool) = get_test_mysql_pool().await else {
        eprintln!("skipping test_mysql_case_insensitive_email: MYSQL_URL not set");
        return;
    };
    let store = MySqlStore::new(pool);
    let lower_email = format!("ci_{}@example.com", Uuid::new_v4());
    let user = store
        .users()
        .create_user(&lower_email, "hash")
        .await
        .expect("create user");

    let upper_email = lower_email.to_uppercase();
    let fetched = store
        .users()
        .get_user_by_email(&upper_email)
        .await
        .expect("fetch by uppercase email")
        .expect("user found via case-insensitive lookup");
    assert_eq!(fetched.id, user.id);
}

#[tokio::test]
async fn test_mysql_cascade_delete() {
    let Some(pool) = get_test_mysql_pool().await else {
        eprintln!("skipping test_mysql_cascade_delete: MYSQL_URL not set");
        return;
    };
    let store = MySqlStore::new(pool);
    let email = format!("cascade_{}@example.com", Uuid::new_v4());
    let user = store
        .users()
        .create_user(&email, "hash")
        .await
        .expect("create user");

    // Seed child records across all 7 entities
    let token_hash = format!("sess_{}", Uuid::new_v4());
    let _session = store
        .sessions()
        .create_session(
            user.id,
            &token_hash,
            "cookie",
            Some("csrf"),
            Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .expect("create session");

    let v_hash = [101u8; 32];
    store
        .tokens()
        .create_verification_token(user.id, &v_hash, Utc::now() + chrono::Duration::hours(1))
        .await
        .expect("create vtoken");

    let r_hash = [102u8; 32];
    store
        .tokens()
        .create_password_reset_token(user.id, &r_hash, Utc::now() + chrono::Duration::hours(1))
        .await
        .expect("create rtoken");

    let p_uid = format!("gh_{}", Uuid::new_v4());
    store
        .oauth()
        .link_account(user.id, "github", &p_uid, &email)
        .await
        .expect("link oauth");

    store
        .totp()
        .upsert_secret(user.id, &[1, 2, 3], serde_json::json!(["bc1"]))
        .await
        .expect("upsert totp secret");

    let used_hash = [103u8; 32];
    store
        .totp()
        .record_used_code(user.id, &used_hash)
        .await
        .expect("record used code");

    let c_hash = [104u8; 32];
    store
        .totp()
        .create_two_factor_token(
            user.id,
            &c_hash,
            "cred_hash",
            Utc::now() + chrono::Duration::minutes(5),
        )
        .await
        .expect("create 2fa token");

    // Perform cascade delete of the parent user
    let deleted = store
        .users()
        .delete_user(user.id)
        .await
        .expect("delete user cascades");
    assert!(deleted);

    // Verify all 7 child entities were cascaded
    assert!(
        store
            .users()
            .get_user_by_id(user.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .sessions()
            .get_session_by_token_hash(&token_hash)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .sessions()
            .list_user_sessions(user.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .tokens()
            .consume_verification_token(&v_hash)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .tokens()
            .consume_password_reset_token(&r_hash)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .oauth()
            .get_account("github", &p_uid)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.totp().get_secret(user.id).await.unwrap().is_none());
    assert!(
        !store
            .totp()
            .is_code_used(user.id, &used_hash)
            .await
            .unwrap()
    );
    assert!(
        store
            .totp()
            .consume_two_factor_token(&c_hash)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_mysql_transaction_atomicity() {
    let Some(pool) = get_test_mysql_pool().await else {
        eprintln!("skipping test_mysql_transaction_atomicity: MYSQL_URL not set");
        return;
    };
    let store = MySqlStore::new(pool);

    // 1. Rollback atomicity
    let mut tx_rollback = store.begin().await.expect("begin tx");
    let rb_email = format!("tx_rb_{}@example.com", Uuid::new_v4());
    let rb_user = tx_rollback
        .users()
        .create_user(&rb_email, "hash")
        .await
        .expect("create user in tx");
    tx_rollback.rollback().await.expect("rollback tx");
    assert!(
        store
            .users()
            .get_user_by_id(rb_user.id)
            .await
            .unwrap()
            .is_none()
    );

    // 2. Commit atomicity
    let mut tx_commit = store.begin().await.expect("begin tx");
    let cm_email = format!("tx_cm_{}@example.com", Uuid::new_v4());
    let cm_user = tx_commit
        .users()
        .create_user(&cm_email, "hash")
        .await
        .expect("create user in tx");
    tx_commit.commit().await.expect("commit tx");
    assert!(
        store
            .users()
            .get_user_by_id(cm_user.id)
            .await
            .unwrap()
            .is_some()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tier 3: E2E Lifecycle Flow Test
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_mysql_e2e_user_journey() {
    let Some(pool) = get_test_mysql_pool().await else {
        eprintln!("skipping test_mysql_e2e_user_journey: MYSQL_URL not set");
        return;
    };
    let store = MySqlStore::new(pool);
    let email = format!("e2e_{}@example.com", Uuid::new_v4());
    let password_hash = "$argon2id$v=19$m=19456,t=2,p=1$fake_hash_value";

    // 1. Signup
    let user = store
        .users()
        .create_user(&email, password_hash)
        .await
        .expect("signup");

    // 2. Queue and claim verification email
    store
        .outbox()
        .insert_outbox(
            &email,
            "verification",
            serde_json::json!({"action": "verify"}),
        )
        .await
        .expect("insert outbox");

    let v_hash = [88u8; 32];
    store
        .tokens()
        .create_verification_token(user.id, &v_hash, Utc::now() + chrono::Duration::hours(24))
        .await
        .expect("create vtoken");

    // 3. Consume verification token & verify account
    let token = store
        .tokens()
        .consume_verification_token(&v_hash)
        .await
        .expect("consume token")
        .expect("token exists");
    store
        .users()
        .set_email_verified(token.user_id, true)
        .await
        .expect("set verified");

    let verified_user = store
        .users()
        .get_user_by_id(user.id)
        .await
        .unwrap()
        .unwrap();
    assert!(verified_user.email_verified);

    // 4. Login and Session Rotation
    let token_hash = format!("sess_{}", Uuid::new_v4());
    let session = store
        .sessions()
        .create_session(
            user.id,
            &token_hash,
            "cookie",
            Some("csrf1"),
            Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .expect("login session");

    let rotated_hash = format!("sess_rot_{}", Uuid::new_v4());
    store
        .sessions()
        .rotate_session(session.id, &rotated_hash, Some("csrf2"), Utc::now())
        .await
        .expect("rotate session");

    store
        .sessions()
        .delete_session(session.id)
        .await
        .expect("logout");
}

// ─────────────────────────────────────────────────────────────────────────────
// Tier 4: Negative & Concurrency Tests
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_mysql_concurrency_gap_lock_totp_enrollment() {
    let Some(pool) = get_test_mysql_pool().await else {
        eprintln!("skipping test_mysql_concurrency_gap_lock_totp_enrollment: MYSQL_URL not set");
        return;
    };
    let store = MySqlStore::new(pool);
    let email = format!("gaplock_{}@example.com", Uuid::new_v4());
    let user = store
        .users()
        .create_user(&email, "hash")
        .await
        .expect("create user");

    // Spawn 10 concurrent tasks attempting TOTP enrollment for the same user concurrently.
    // Parent user row lock prevents InnoDB gap-lock deadlocks.
    let mut handles = Vec::new();
    for _ in 0..10 {
        let store_clone = store.clone();
        let user_id = user.id;
        handles.push(tokio::spawn(async move {
            store_clone
                .totp()
                .upsert_secret(user_id, &[1, 2, 3], serde_json::json!(["bc1"]))
                .await
        }));
    }

    let mut successes = 0;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(_) => successes += 1,
            Err(metal_auth::AppError::TotpAlreadyEnabled) => {}
            Err(other) => panic!("unexpected error during concurrent enrollment: {:?}", other),
        }
    }

    assert_eq!(
        successes, 10,
        "all un-enabled secret upserts should succeed without deadlocks"
    );
}

#[tokio::test]
async fn test_mysql_concurrency_single_use_token_race() {
    let Some(pool) = get_test_mysql_pool().await else {
        eprintln!("skipping test_mysql_concurrency_single_use_token_race: MYSQL_URL not set");
        return;
    };
    let store = MySqlStore::new(pool);
    let email = format!("tokrace_{}@example.com", Uuid::new_v4());
    let user = store
        .users()
        .create_user(&email, "hash")
        .await
        .expect("create user");

    let token_hash = [99u8; 32];
    store
        .tokens()
        .create_verification_token(
            user.id,
            &token_hash,
            Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .expect("create token");

    let store1 = store.clone();
    let store2 = store.clone();

    let (res1, res2) = tokio::join!(
        tokio::spawn(async move {
            store1
                .tokens()
                .consume_verification_token(&token_hash)
                .await
        }),
        tokio::spawn(async move {
            store2
                .tokens()
                .consume_verification_token(&token_hash)
                .await
        })
    );

    let opt1 = res1.unwrap().expect("query 1 succeeded");
    let opt2 = res2.unwrap().expect("query 2 succeeded");

    let count = usize::from(opt1.is_some()) + usize::from(opt2.is_some());
    assert_eq!(
        count, 1,
        "exactly one concurrent consumer must acquire the token"
    );
}
