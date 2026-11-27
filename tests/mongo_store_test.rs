#![cfg(feature = "mongodb")]

use std::time::Duration;

use chrono::Utc;
use metal_auth::{
    AppError, Config, ConfigError, DatabaseBackend, DatabaseStore, MongoConfig, MongoStore,
    config::redact_url,
    db::{
        models::{
            OUTBOX_STATUS_FAILED, OUTBOX_STATUS_PENDING, OUTBOX_STATUS_PROCESSING,
            OUTBOX_STATUS_SENT,
        },
        mongo::{
            indexes::{EMAIL_OUTBOX_COLLECTION, ensure_indexes},
            models::{
                EmailOutboxDoc, OAuthAccountDoc, PasswordResetTokenDoc, SessionDoc, TotpSecretDoc,
                TotpUsedCodeDoc, TwoFactorTokenDoc, UserDoc, VerificationTokenDoc,
            },
        },
    },
    error::DbError,
};
use mongodb::{
    Client,
    bson::{self, doc},
};
use uuid::Uuid;

async fn get_test_mongo_store() -> Option<MongoStore> {
    dotenvy::dotenv().ok();
    let url = std::env::var("MONGODB_URI")
        .or_else(|_| std::env::var("MONGODB_URL"))
        .or_else(|_| std::env::var("MONGO_URL"))
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()?;
    if !url.starts_with("mongodb://") && !url.starts_with("mongodb+srv://") {
        return None;
    }
    let db_name = std::env::var("MONGO_DATABASE").unwrap_or_else(|_| "metal_auth_test".to_string());
    let allow_standalone = std::env::var("MONGO_ALLOW_NON_TRANSACTIONAL_STANDALONE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true);

    let mut client_options = mongodb::options::ClientOptions::parse(&url).await.ok()?;
    client_options.connect_timeout = Some(Duration::from_secs(3));
    client_options.server_selection_timeout = Some(Duration::from_secs(3));
    let client = Client::with_options(client_options).ok()?;
    let db = client.database(&db_name);
    db.run_command(doc! { "ping": 1 }).await.ok()?;

    let hello_cmd = doc! { "hello": 1 };
    let is_replica_set = db
        .run_command(hello_cmd)
        .await
        .map(|doc| doc.get_str("setName").is_ok())
        .unwrap_or(false);

    ensure_indexes(&db)
        .await
        .expect("Failed to create mongo indexes for test store");

    let store = MongoStore::new(client, &db_name, is_replica_set, allow_standalone);
    Some(store)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tier 1: Unit Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_mongodb_backend_kind() {
    assert_eq!(DatabaseBackend::Mongodb.to_string(), "mongodb");
    let parsed = DatabaseBackend::from_scheme("mongodb").expect("parse mongodb scheme");
    assert_eq!(parsed, DatabaseBackend::Mongodb);
    let parsed_srv = DatabaseBackend::from_scheme("mongodb+srv").expect("parse mongodb+srv scheme");
    assert_eq!(parsed_srv, DatabaseBackend::Mongodb);
}

#[test]
fn test_mongo_config_standalone_flag() {
    let cfg = MongoConfig {
        database_name: "metal_auth".into(),
        allow_non_transactional_standalone: true,
    };
    assert!(cfg.allow_non_transactional_standalone);
}

#[test]
fn test_mongo_config_validation_requires_database() {
    let cfg = Config {
        database_url: "mongodb://127.0.0.1:27017".into(),
        backend: DatabaseBackend::Mongodb,
        mongo: Some(MongoConfig {
            database_name: "   ".into(),
            allow_non_transactional_standalone: false,
        }),
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
    let err = cfg.validate().unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidValue {
            field: "mongo.database_name",
            ..
        }
    ));
}

#[test]
fn test_mongo_url_redaction() {
    let standard = "mongodb://admin:secret123@localhost:27017/metal_auth";
    let redacted = redact_url(standard);
    assert!(!redacted.contains("secret123"));
    assert!(!redacted.contains("admin"));
    assert!(redacted.contains("[REDACTED]:[REDACTED]@localhost:27017"));

    let srv = "mongodb+srv://root:top_secret_pass@cluster0.abcde.mongodb.net/prod_db";
    let redacted_srv = redact_url(srv);
    assert!(!redacted_srv.contains("top_secret_pass"));
    assert!(!redacted_srv.contains("root"));
    assert!(redacted_srv.contains("[REDACTED]:[REDACTED]@cluster0.abcde.mongodb.net"));
}

#[test]
fn test_mongo_models_bson_roundtrip() {
    let now = Utc::now();
    let user_id = Uuid::new_v4();

    // UserDoc
    let user_doc = UserDoc {
        id: bson::Uuid::from_uuid_1(user_id),
        email: "alice@example.com".to_string(),
        password_hash: "$argon2id$...".to_string(),
        email_verified: false,
        created_at: bson::DateTime::from_chrono(now),
        updated_at: bson::DateTime::from_chrono(now),
    };
    let user_bson = bson::to_document(&user_doc).expect("serialize UserDoc");
    assert_eq!(user_bson.get_str("email").unwrap(), "alice@example.com");
    let user_roundtrip: UserDoc = bson::from_document(user_bson).expect("deserialize UserDoc");
    assert_eq!(user_roundtrip.email, user_doc.email);

    // SessionDoc
    let session_id = Uuid::new_v4();
    let session_doc = SessionDoc {
        id: bson::Uuid::from_uuid_1(session_id),
        user_id: bson::Uuid::from_uuid_1(user_id),
        token_hash: "hash_string".to_string(),
        session_type: "web".to_string(),
        csrf_token: Some("csrf_token_secret".to_string()),
        created_at: bson::DateTime::from_chrono(now),
        last_active_at: bson::DateTime::from_chrono(now),
        absolute_expires_at: bson::DateTime::from_chrono(now),
    };
    let session_bson = bson::to_document(&session_doc).expect("serialize SessionDoc");
    let session_roundtrip: SessionDoc =
        bson::from_document(session_bson).expect("deserialize SessionDoc");
    assert_eq!(session_roundtrip.session_type, "web");

    // VerificationTokenDoc
    let token_doc = VerificationTokenDoc {
        id: bson::Uuid::from_uuid_1(Uuid::new_v4()),
        user_id: bson::Uuid::from_uuid_1(user_id),
        token_hash: bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: vec![5, 6, 7],
        },
        expires_at: bson::DateTime::from_chrono(now),
        created_at: bson::DateTime::from_chrono(now),
    };
    let token_bson = bson::to_document(&token_doc).expect("serialize VerificationTokenDoc");
    let token_roundtrip: VerificationTokenDoc =
        bson::from_document(token_bson).expect("deserialize VerificationTokenDoc");
    assert_eq!(token_roundtrip.user_id, token_doc.user_id);

    // PasswordResetTokenDoc
    let reset_doc = PasswordResetTokenDoc {
        id: bson::Uuid::from_uuid_1(Uuid::new_v4()),
        user_id: bson::Uuid::from_uuid_1(user_id),
        token_hash: bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: vec![8, 9, 10],
        },
        expires_at: bson::DateTime::from_chrono(now),
        created_at: bson::DateTime::from_chrono(now),
    };
    let reset_bson = bson::to_document(&reset_doc).expect("serialize PasswordResetTokenDoc");
    let reset_roundtrip: PasswordResetTokenDoc =
        bson::from_document(reset_bson).expect("deserialize PasswordResetTokenDoc");
    assert_eq!(reset_roundtrip.user_id, reset_doc.user_id);

    // EmailOutboxDoc
    let outbox_doc = EmailOutboxDoc {
        id: bson::Uuid::from_uuid_1(Uuid::new_v4()),
        recipient: "bob@example.com".to_string(),
        email_type: "verification".to_string(),
        payload: serde_json::json!({"action": "test"}),
        status: "pending".to_string(),
        retry_count: 0,
        next_retry_at: bson::DateTime::from_chrono(now),
        error_log: None,
        created_at: bson::DateTime::from_chrono(now),
        sent_at: None,
    };
    let outbox_bson = bson::to_document(&outbox_doc).expect("serialize EmailOutboxDoc");
    let outbox_roundtrip: EmailOutboxDoc =
        bson::from_document(outbox_bson).expect("deserialize EmailOutboxDoc");
    assert_eq!(outbox_roundtrip.recipient, "bob@example.com");

    // OAuthAccountDoc
    let oauth_doc = OAuthAccountDoc {
        id: bson::Uuid::from_uuid_1(Uuid::new_v4()),
        user_id: bson::Uuid::from_uuid_1(user_id),
        provider_id: "google".to_string(),
        provider_user_id: "google_12345".to_string(),
        email: "alice@gmail.com".to_string(),
        created_at: bson::DateTime::from_chrono(now),
        updated_at: bson::DateTime::from_chrono(now),
    };
    let oauth_bson = bson::to_document(&oauth_doc).expect("serialize OAuthAccountDoc");
    let oauth_roundtrip: OAuthAccountDoc =
        bson::from_document(oauth_bson).expect("deserialize OAuthAccountDoc");
    assert_eq!(oauth_roundtrip.provider_id, "google");

    // TotpSecretDoc
    let totp_doc = TotpSecretDoc {
        id: bson::Uuid::from_uuid_1(Uuid::new_v4()),
        user_id: bson::Uuid::from_uuid_1(user_id),
        encrypted_secret: bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: vec![11, 12, 13],
        },
        enabled: true,
        backup_codes: serde_json::json!(["code1", "code2"]),
        created_at: bson::DateTime::from_chrono(now),
        updated_at: bson::DateTime::from_chrono(now),
    };
    let totp_bson = bson::to_document(&totp_doc).expect("serialize TotpSecretDoc");
    let totp_roundtrip: TotpSecretDoc =
        bson::from_document(totp_bson).expect("deserialize TotpSecretDoc");
    assert_eq!(totp_roundtrip.user_id, totp_doc.user_id);

    // TotpUsedCodeDoc
    let used_doc = TotpUsedCodeDoc {
        id: bson::Uuid::from_uuid_1(Uuid::new_v4()),
        user_id: bson::Uuid::from_uuid_1(user_id),
        code_hash: bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: vec![20, 21, 22],
        },
        used_at: bson::DateTime::from_chrono(now),
    };
    let used_bson = bson::to_document(&used_doc).expect("serialize TotpUsedCodeDoc");
    let used_roundtrip: TotpUsedCodeDoc =
        bson::from_document(used_bson).expect("deserialize TotpUsedCodeDoc");
    assert_eq!(used_roundtrip.user_id, used_doc.user_id);

    // TwoFactorTokenDoc
    let two_fa_doc = TwoFactorTokenDoc {
        id: bson::Uuid::from_uuid_1(Uuid::new_v4()),
        user_id: bson::Uuid::from_uuid_1(user_id),
        token_hash: bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: vec![14, 15],
        },
        credential_hash: Some("cred_hash".to_string()),
        expires_at: bson::DateTime::from_chrono(now),
    };
    let two_fa_bson = bson::to_document(&two_fa_doc).expect("serialize TwoFactorTokenDoc");
    let two_fa_roundtrip: TwoFactorTokenDoc =
        bson::from_document(two_fa_bson).expect("deserialize TwoFactorTokenDoc");
    assert_eq!(
        two_fa_roundtrip.credential_hash.as_deref(),
        Some("cred_hash")
    );
}

#[test]
fn test_mongo_models_debug_redaction() {
    let now = Utc::now();
    let uid = bson::Uuid::from_uuid_1(Uuid::new_v4());

    let user = UserDoc {
        id: uid,
        email: "test@example.com".to_string(),
        password_hash: "super_secret_argon_hash".to_string(),
        email_verified: false,
        created_at: bson::DateTime::from_chrono(now),
        updated_at: bson::DateTime::from_chrono(now),
    };
    let debug = format!("{user:?}");
    assert!(!debug.contains("super_secret_argon_hash"));
    assert!(debug.contains("[redacted]"));

    let session = SessionDoc {
        id: uid,
        user_id: uid,
        token_hash: "secret_token_string".to_string(),
        session_type: "web".to_string(),
        csrf_token: Some("secret_csrf".to_string()),
        created_at: bson::DateTime::from_chrono(now),
        last_active_at: bson::DateTime::from_chrono(now),
        absolute_expires_at: bson::DateTime::from_chrono(now),
    };
    let debug = format!("{session:?}");
    assert!(!debug.contains("secret_token_string"));
    assert!(!debug.contains("secret_csrf"));

    let outbox = EmailOutboxDoc {
        id: uid,
        recipient: "user@example.com".to_string(),
        email_type: "verification".to_string(),
        payload: serde_json::json!({"token": "sensitive_recovery_url"}),
        status: "pending".to_string(),
        retry_count: 0,
        next_retry_at: bson::DateTime::from_chrono(now),
        error_log: None,
        created_at: bson::DateTime::from_chrono(now),
        sent_at: None,
    };
    let debug = format!("{outbox:?}");
    assert!(!debug.contains("sensitive_recovery_url"));

    let totp = TotpSecretDoc {
        id: uid,
        user_id: uid,
        encrypted_secret: bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: b"aes_encrypted_key".to_vec(),
        },
        enabled: true,
        backup_codes: serde_json::json!(["backup_code_1"]),
        created_at: bson::DateTime::from_chrono(now),
        updated_at: bson::DateTime::from_chrono(now),
    };
    let debug = format!("{totp:?}");
    assert!(!debug.contains("aes_encrypted_key"));
    assert!(!debug.contains("backup_code_1"));
}

#[tokio::test]
async fn test_mongo_standalone_fail_closed_logic() {
    let client = Client::with_uri_str("mongodb://127.0.0.1:27017")
        .await
        .unwrap();
    let store = MongoStore::new(client, "metal_auth_test", false, false);
    assert!(!store.is_replica_set());
    assert!(!store.allow_non_transactional_standalone());

    let begin_res = store.begin().await;
    assert!(matches!(begin_res, Err(AppError::TransactionNotSupported)));
}

#[tokio::test]
async fn test_mongo_standalone_opt_in_allows_pseudo_transaction() {
    let client = Client::with_uri_str("mongodb://127.0.0.1:27017")
        .await
        .unwrap();
    let store = MongoStore::new(client, "metal_auth_test", false, true);
    assert!(!store.is_replica_set());
    assert!(store.allow_non_transactional_standalone());

    let begin_res = store.begin().await;
    assert!(begin_res.is_ok());
    let tx = begin_res.unwrap();
    assert!(tx.commit().await.is_ok());
}

#[test]
fn test_nosql_operator_injection_resilience() {
    let malicious_email = "{\"$ne\": null}";
    let query_doc = doc! {
        "email": malicious_email,
    };
    assert_eq!(query_doc.get_str("email").unwrap(), "{\"$ne\": null}");
    assert!(query_doc.get_document("email").is_err());
}

#[test]
fn test_mongo_db_error_wrapping() {
    let err = DbError::new("MongoDB query timed out");
    assert_eq!(err.message, "MongoDB query timed out");
}

// ─────────────────────────────────────────────────────────────────────────────
// Tier 2: Integration Tests (Conditional on Live MongoDB)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_mongo_users_lifecycle() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_users_lifecycle: MONGO_URL not set");
        return;
    };
    assert_eq!(store.backend(), DatabaseBackend::Mongodb);
    assert!(store.ping().await.is_ok());

    let email = format!("mongo_user_{}@example.com", Uuid::new_v4());
    let password_hash = "$argon2id$v=19$m=19456,t=2,p=1$fake_hash_value";

    // 1. Create
    let user = store
        .users()
        .create_user(&email, password_hash)
        .await
        .expect("create user via mongo store");
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

    // 3. Case-insensitive email fetch
    let upper_email = email.to_uppercase();
    let by_upper = store
        .users()
        .get_user_by_email(&upper_email)
        .await
        .expect("fetch by uppercase email")
        .expect("user exists");
    assert_eq!(by_upper.id, user.id);

    // 4. Set email verified
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

    // 5. Update password hash
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

    // 6. Delete user
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
async fn test_mongo_users_duplicate_email_error() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_users_duplicate_email_error: MONGO_URL not set");
        return;
    };
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
    assert!(matches!(err, AppError::EmailAlreadyExists));

    // Cleanup
    let user = store.users().get_user_by_email(&email).await.unwrap();
    if let Some(u) = user {
        let _ = store.users().delete_user(u.id).await;
    }
}

#[tokio::test]
async fn test_mongo_tokens_lifecycle() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_tokens_lifecycle: MONGO_URL not set");
        return;
    };

    let user = store
        .users()
        .create_user(&format!("token_{}@example.com", Uuid::new_v4()), "hash")
        .await
        .expect("create user");

    let v_token_hash = [33u8; 32];
    let r_token_hash = [55u8; 32];
    let expires_at = Utc::now() + chrono::Duration::hours(1);

    // Create verification token
    store
        .tokens()
        .create_verification_token(user.id, &v_token_hash, expires_at)
        .await
        .expect("create v token");

    // Consume verification token (single use)
    let token = store
        .tokens()
        .consume_verification_token(&v_token_hash)
        .await
        .expect("consume v token")
        .expect("token exists");
    assert_eq!(token.user_id, user.id);

    // Second consumption must return None
    let replayed = store
        .tokens()
        .consume_verification_token(&v_token_hash)
        .await
        .expect("consume replayed v token");
    assert!(replayed.is_none());

    // Create password reset token
    store
        .tokens()
        .create_password_reset_token(user.id, &r_token_hash, expires_at)
        .await
        .expect("create r token");

    // Consume password reset token (single use)
    let r_token = store
        .tokens()
        .consume_password_reset_token(&r_token_hash)
        .await
        .expect("consume r token")
        .expect("token exists");
    assert_eq!(r_token.user_id, user.id);

    // Second consumption must return None
    let r_replayed = store
        .tokens()
        .consume_password_reset_token(&r_token_hash)
        .await
        .expect("consume replayed r token");
    assert!(r_replayed.is_none());

    // Expired verification token test (pure storage contract returns token metadata without premature expiry check)
    let expired_hash = [77u8; 32];
    let past_expiry = Utc::now() - chrono::Duration::hours(1);
    store
        .tokens()
        .create_verification_token(user.id, &expired_hash, past_expiry)
        .await
        .expect("create expired token");

    let exp_token = store
        .tokens()
        .consume_verification_token(&expired_hash)
        .await
        .expect("consume expired verification token")
        .expect("token exists");
    assert_eq!(exp_token.user_id, user.id);
    assert!(exp_token.expires_at <= Utc::now());

    let exp_replayed = store
        .tokens()
        .consume_verification_token(&expired_hash)
        .await
        .expect("consume replayed expired verification token");
    assert!(exp_replayed.is_none());

    // Expired password reset token test
    let expired_reset_hash = [78u8; 32];
    store
        .tokens()
        .create_password_reset_token(user.id, &expired_reset_hash, past_expiry)
        .await
        .expect("create expired reset token");

    let exp_reset_token = store
        .tokens()
        .consume_password_reset_token(&expired_reset_hash)
        .await
        .expect("consume expired reset token")
        .expect("token exists");
    assert_eq!(exp_reset_token.user_id, user.id);
    assert!(exp_reset_token.expires_at <= Utc::now());

    let exp_reset_replayed = store
        .tokens()
        .consume_password_reset_token(&expired_reset_hash)
        .await
        .expect("consume replayed expired reset token");
    assert!(exp_reset_replayed.is_none());

    // Cleanup
    let _ = store.users().delete_user(user.id).await;
}

#[tokio::test]
async fn test_mongo_sessions_lifecycle() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_sessions_lifecycle: MONGO_URL not set");
        return;
    };

    let user = store
        .users()
        .create_user(&format!("sess_{}@example.com", Uuid::new_v4()), "hash")
        .await
        .expect("create user");

    let token_hash = format!("sess_hash_{}", Uuid::new_v4());
    let expires_at = Utc::now() + chrono::Duration::days(7);

    // 1. Create session
    let session = store
        .sessions()
        .create_session(
            user.id,
            &token_hash,
            "cookie",
            Some("csrf_initial"),
            expires_at,
        )
        .await
        .expect("create session");
    assert_eq!(session.user_id, user.id);
    assert_eq!(session.session_type, "cookie");
    assert_eq!(session.csrf_token.as_deref(), Some("csrf_initial"));

    // 2. Fetch session
    let fetched = store
        .sessions()
        .get_session_by_token_hash(&token_hash)
        .await
        .expect("fetch session")
        .expect("session exists");
    assert_eq!(fetched.id, session.id);

    // 3. Touch session
    let touched_at = Utc::now();
    store
        .sessions()
        .touch_session(session.id, touched_at)
        .await
        .expect("touch session");

    // 4. Rotate session token
    let new_token_hash = format!("sess_new_hash_{}", Uuid::new_v4());
    store
        .sessions()
        .rotate_session(
            session.id,
            &new_token_hash,
            Some("csrf_rotated"),
            Utc::now(),
        )
        .await
        .expect("rotate session token");

    let rotated = store
        .sessions()
        .get_session_by_token_hash(&new_token_hash)
        .await
        .expect("fetch rotated session")
        .expect("session present");
    assert_eq!(rotated.token_hash, new_token_hash);
    assert_eq!(rotated.csrf_token.as_deref(), Some("csrf_rotated"));

    // 5. List sessions
    let sessions = store
        .sessions()
        .list_user_sessions(user.id)
        .await
        .expect("list sessions");
    assert_eq!(sessions.len(), 1);

    // 6. Delete session
    store
        .sessions()
        .delete_session(session.id)
        .await
        .expect("delete session");

    let after_delete = store
        .sessions()
        .get_session_by_token_hash(&new_token_hash)
        .await
        .expect("fetch deleted session");
    assert!(after_delete.is_none());

    // 7. Expired session retrieval parity (storage layer returns existing session without premature expiry filtering)
    let expired_token_hash = format!("sess_expired_hash_{}", Uuid::new_v4());
    let past_expiry = Utc::now() - chrono::Duration::hours(1);
    let expired_session = store
        .sessions()
        .create_session(
            user.id,
            &expired_token_hash,
            "cookie",
            Some("csrf_expired"),
            past_expiry,
        )
        .await
        .expect("create expired session");

    let fetched_expired = store
        .sessions()
        .get_session_by_token_hash(&expired_token_hash)
        .await
        .expect("fetch expired session")
        .expect("expired session exists in storage");
    assert_eq!(fetched_expired.id, expired_session.id);
    assert_eq!(fetched_expired.user_id, user.id);
    assert!(fetched_expired.absolute_expires_at <= Utc::now());

    store
        .sessions()
        .delete_session(expired_session.id)
        .await
        .expect("delete expired session");

    // Cleanup
    let _ = store.users().delete_user(user.id).await;
}

#[tokio::test]
async fn test_mongo_outbox_lifecycle() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_outbox_lifecycle: MONGO_URL not set");
        return;
    };

    let recipient = format!("outbox_{}@example.com", Uuid::new_v4());
    let payload = serde_json::json!({ "key": "test_value" });

    // Enqueue
    let outbox = store
        .outbox()
        .insert_outbox(&recipient, "verification", payload)
        .await
        .expect("insert outbox email");
    assert_eq!(outbox.recipient, recipient);
    assert_eq!(outbox.status, "pending");

    // Claim pending outbox batch
    let claimed = store
        .outbox()
        .claim_pending_outbox(10, Duration::from_secs(60))
        .await
        .expect("claim outbox batch");
    assert!(claimed.iter().any(|item| item.id == outbox.id));

    // Update status to Sent
    store
        .outbox()
        .mark_outbox_sent(outbox.id)
        .await
        .expect("mark outbox sent");

    // Clean up sent
    let cleaned = store
        .outbox()
        .cleanup_sent_outbox(Duration::from_secs(0))
        .await
        .expect("clean sent outbox");
    assert!(cleaned >= 1);
}

#[tokio::test]
async fn test_mongo_outbox_concurrent_claims() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_outbox_concurrent_claims: MONGO_URL not set");
        return;
    };

    let count = 20;
    let mut seeded_ids = Vec::with_capacity(count);
    for _ in 0..count {
        let recipient = format!("concurrent_outbox_{}@example.com", Uuid::new_v4());
        let payload = serde_json::json!({ "worker_test": true });
        let outbox = store
            .outbox()
            .insert_outbox(&recipient, "verification", payload)
            .await
            .expect("insert outbox record");
        seeded_ids.push(outbox.id);
    }

    let seeded_set: std::collections::HashSet<Uuid> = seeded_ids.iter().copied().collect();

    // Spawn 4 concurrent worker tasks claiming batches
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let worker_store = store.clone();
        let task = tokio::spawn(async move {
            let mut worker_claimed = Vec::new();
            for _ in 0..10 {
                let batch = worker_store
                    .outbox()
                    .claim_pending_outbox(5, Duration::from_secs(60))
                    .await
                    .expect("claim outbox batch");
                if batch.is_empty() {
                    break;
                }
                for item in batch {
                    worker_claimed.push(item.id);
                }
            }
            worker_claimed
        });
        tasks.push(task);
    }

    let mut all_claimed = Vec::new();
    for task in tasks {
        let worker_claimed = task.await.expect("join worker task");
        all_claimed.extend(worker_claimed);
    }

    let test_claimed: Vec<Uuid> = all_claimed
        .into_iter()
        .filter(|id| seeded_set.contains(id))
        .collect();

    // Verify mutual exclusion: exactly count records claimed, zero duplicates
    assert_eq!(
        test_claimed.len(),
        count,
        "every seeded record must be claimed exactly once"
    );
    let mut seen = std::collections::HashSet::new();
    for id in &test_claimed {
        assert!(
            seen.insert(*id),
            "duplicate claim detected for outbox record {id}"
        );
    }

    // Cleanup
    for id in seeded_ids {
        let _ = store.outbox().mark_outbox_sent(id).await;
    }
    let _ = store
        .outbox()
        .cleanup_sent_outbox(Duration::from_secs(0))
        .await;
}

#[tokio::test]
async fn test_mongo_outbox_stale_lease_recovery() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_outbox_stale_lease_recovery: MONGO_URL not set");
        return;
    };

    let recipient = format!("stale_outbox_{}@example.com", Uuid::new_v4());
    let payload = serde_json::json!({ "stale_test": true });

    let outbox = store
        .outbox()
        .insert_outbox(&recipient, "password_reset", payload)
        .await
        .expect("insert outbox email");

    // Worker A claims with 1-second lease
    let claimed = store
        .outbox()
        .claim_pending_outbox(10, Duration::from_secs(1))
        .await
        .expect("initial claim");
    assert!(claimed.iter().any(|item| item.id == outbox.id));

    // Wait 1.1s for lease to expire (1.1s > 1s lease, but < 2s double lease)
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Worker B should immediately recover and reclaim the record without waiting 2x lease
    let reclaimed = store
        .outbox()
        .claim_pending_outbox(10, Duration::from_secs(60))
        .await
        .expect("reclaim stale record");
    assert!(
        reclaimed.iter().any(|item| item.id == outbox.id),
        "stale processing record must be reclaimable as soon as next_retry_at <= now"
    );

    // Cleanup
    let _ = store.outbox().mark_outbox_sent(outbox.id).await;
    let _ = store
        .outbox()
        .cleanup_sent_outbox(Duration::from_secs(0))
        .await;
}

#[tokio::test]
async fn test_mongo_outbox_recover_stale_processing() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_outbox_recover_stale_processing: MONGO_URL not set");
        return;
    };

    let recipient = format!("recover_stale_outbox_{}@example.com", Uuid::new_v4());
    let payload = serde_json::json!({ "recover_test": true });

    let outbox = store
        .outbox()
        .insert_outbox(&recipient, "password_reset", payload)
        .await
        .expect("insert outbox email");

    // Worker A claims with 60-second lease
    let claimed = store
        .outbox()
        .claim_pending_outbox(10, Duration::from_secs(60))
        .await
        .expect("initial claim");
    assert!(claimed.iter().any(|item| item.id == outbox.id));

    // Active lease should NOT be claimable while lease is unexpired
    let premature_claim = store
        .outbox()
        .claim_pending_outbox(10, Duration::from_secs(60))
        .await
        .expect("premature claim check");
    assert!(!premature_claim.iter().any(|item| item.id == outbox.id));

    // Update the record's next_retry_at directly in MongoDB to a past timestamp
    let coll = store.db().collection::<bson::Document>("outbox");
    let past_time = Utc::now() - chrono::Duration::seconds(10);
    coll.update_one(
        doc! { "_id": bson::Uuid::from(outbox.id) },
        doc! { "$set": { "next_retry_at": bson::DateTime::from_chrono(past_time) } },
    )
    .await
    .expect("update next_retry_at to past");

    // recover_stale_processing with large stale_duration (e.g. 60s).
    // In pre-fix code, this checked next_retry_at <= now - 60s, failing to recover the expired lease.
    // In post-fix code, next_retry_at <= now recovers it immediately to pending.
    let recovered = store
        .outbox()
        .recover_stale_processing(Duration::from_secs(60))
        .await
        .expect("recover stale processing");
    assert!(
        recovered >= 1,
        "expected at least 1 recovered record, got {recovered}"
    );

    // Verify specific document transitioned to "pending"
    let doc = coll
        .find_one(doc! { "_id": bson::Uuid::from(outbox.id) })
        .await
        .expect("find outbox doc")
        .expect("outbox doc exists");
    assert_eq!(doc.get_str("status").unwrap(), "pending");

    // Verify record has reverted to pending and can be claimed by Worker B
    let reclaimed = store
        .outbox()
        .claim_pending_outbox(10, Duration::from_secs(60))
        .await
        .expect("reclaim recovered record");
    assert!(
        reclaimed.iter().any(|item| item.id == outbox.id),
        "recovered record must be in pending status and claimable"
    );

    // Cleanup
    let _ = store.outbox().mark_outbox_sent(outbox.id).await;
    let _ = store
        .outbox()
        .cleanup_sent_outbox(Duration::from_secs(0))
        .await;
}

#[tokio::test]
async fn test_mongo_outbox_status_guards() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_outbox_status_guards: MONGO_URL not set");
        return;
    };

    let coll = store
        .db()
        .collection::<EmailOutboxDoc>(EMAIL_OUTBOX_COLLECTION);

    let recipient = format!("guard_{}@example.com", Uuid::new_v4());
    let payload = serde_json::json!({ "guard_test": true });

    // 1. Insert record (initial status = pending)
    let outbox = store
        .outbox()
        .insert_outbox(&recipient, "verification", payload)
        .await
        .expect("insert outbox email");
    assert_eq!(outbox.status, OUTBOX_STATUS_PENDING);

    let doc = coll
        .find_one(doc! { "_id": bson::Uuid::from(outbox.id) })
        .await
        .expect("find doc")
        .expect("doc exists");
    assert_eq!(doc.status, OUTBOX_STATUS_PENDING);
    assert!(doc.sent_at.is_none());
    assert!(doc.error_log.is_none());

    // 2. Calling mark_outbox_sent while pending must NOT change status or sent_at
    store
        .outbox()
        .mark_outbox_sent(outbox.id)
        .await
        .expect("mark_outbox_sent returns Ok even if unmatched");

    let doc = coll
        .find_one(doc! { "_id": bson::Uuid::from(outbox.id) })
        .await
        .expect("find doc")
        .expect("doc exists");
    assert_eq!(doc.status, OUTBOX_STATUS_PENDING);
    assert!(doc.sent_at.is_none());

    // 3. Calling record_outbox_retry while pending must NOT change status, error_log, or retry_count
    let next_retry = Utc::now() - chrono::Duration::seconds(10);
    store
        .outbox()
        .record_outbox_retry(outbox.id, 1, next_retry, "premature retry")
        .await
        .expect("record_outbox_retry returns Ok even if unmatched");

    let doc = coll
        .find_one(doc! { "_id": bson::Uuid::from(outbox.id) })
        .await
        .expect("find doc")
        .expect("doc exists");
    assert_eq!(doc.status, OUTBOX_STATUS_PENDING);
    assert_eq!(doc.retry_count, 0);
    assert!(doc.error_log.is_none());

    // 4. Calling mark_outbox_failed while pending must NOT change status or error_log
    store
        .outbox()
        .mark_outbox_failed(outbox.id, "premature fail")
        .await
        .expect("mark_outbox_failed returns Ok even if unmatched");

    let doc = coll
        .find_one(doc! { "_id": bson::Uuid::from(outbox.id) })
        .await
        .expect("find doc")
        .expect("doc exists");
    assert_eq!(doc.status, OUTBOX_STATUS_PENDING);
    assert!(doc.error_log.is_none());

    // 5. Claim record -> transitions to processing
    let claimed = store
        .outbox()
        .claim_pending_outbox(10, Duration::from_secs(60))
        .await
        .expect("claim outbox batch");
    assert!(claimed.iter().any(|item| item.id == outbox.id));

    let doc = coll
        .find_one(doc! { "_id": bson::Uuid::from(outbox.id) })
        .await
        .expect("find doc")
        .expect("doc exists");
    assert_eq!(doc.status, OUTBOX_STATUS_PROCESSING);

    // 6. While processing, record_outbox_retry succeeds and transitions to pending with error_log
    store
        .outbox()
        .record_outbox_retry(outbox.id, 1, next_retry, "transient error")
        .await
        .expect("record_outbox_retry while processing");

    let doc = coll
        .find_one(doc! { "_id": bson::Uuid::from(outbox.id) })
        .await
        .expect("find doc")
        .expect("doc exists");
    assert_eq!(doc.status, OUTBOX_STATUS_PENDING);
    assert_eq!(doc.retry_count, 1);
    assert_eq!(doc.error_log.as_deref(), Some("transient error"));

    // 7. Re-claim record back to processing (since next_retry was in the past)
    let reclaimed = store
        .outbox()
        .claim_pending_outbox(10, Duration::from_secs(60))
        .await
        .expect("reclaim outbox batch");
    assert!(reclaimed.iter().any(|item| item.id == outbox.id));

    // 8. While processing, mark_outbox_sent succeeds, sets sent_at, and CLEARS error_log to None
    store
        .outbox()
        .mark_outbox_sent(outbox.id)
        .await
        .expect("mark_outbox_sent while processing");

    let doc = coll
        .find_one(doc! { "_id": bson::Uuid::from(outbox.id) })
        .await
        .expect("find doc")
        .expect("doc exists");
    assert_eq!(doc.status, OUTBOX_STATUS_SENT);
    assert!(doc.sent_at.is_some());
    assert_eq!(
        doc.error_log, None,
        "mark_outbox_sent must clear error_log to None"
    );

    // 9. Stale worker operations on sent record must NOT mutate the document
    store
        .outbox()
        .record_outbox_retry(outbox.id, 2, next_retry, "stale worker error")
        .await
        .expect("stale record_outbox_retry on sent");

    let doc = coll
        .find_one(doc! { "_id": bson::Uuid::from(outbox.id) })
        .await
        .expect("find doc")
        .expect("doc exists");
    assert_eq!(doc.status, OUTBOX_STATUS_SENT);
    assert_eq!(doc.error_log, None);
    assert_eq!(doc.retry_count, 1);

    store
        .outbox()
        .mark_outbox_failed(outbox.id, "stale worker fatal")
        .await
        .expect("stale mark_outbox_failed on sent");

    let doc = coll
        .find_one(doc! { "_id": bson::Uuid::from(outbox.id) })
        .await
        .expect("find doc")
        .expect("doc exists");
    assert_eq!(doc.status, OUTBOX_STATUS_SENT);
    assert_eq!(doc.error_log, None);

    // 10. Verify mark_outbox_failed on processing status
    let recipient_failed = format!("guard_failed_{}@example.com", Uuid::new_v4());
    let outbox_failed = store
        .outbox()
        .insert_outbox(&recipient_failed, "password_reset", serde_json::json!({}))
        .await
        .expect("insert outbox email");

    let claimed_failed = store
        .outbox()
        .claim_pending_outbox(10, Duration::from_secs(60))
        .await
        .expect("claim outbox email");
    assert!(
        claimed_failed
            .iter()
            .any(|item| item.id == outbox_failed.id)
    );

    store
        .outbox()
        .mark_outbox_failed(outbox_failed.id, "fatal error")
        .await
        .expect("mark_outbox_failed on processing");

    let doc = coll
        .find_one(doc! { "_id": bson::Uuid::from(outbox_failed.id) })
        .await
        .expect("find doc")
        .expect("doc exists");
    assert_eq!(doc.status, OUTBOX_STATUS_FAILED);
    assert_eq!(doc.error_log.as_deref(), Some("fatal error"));

    // Stale sent attempt on failed status must be a no-op
    store
        .outbox()
        .mark_outbox_sent(outbox_failed.id)
        .await
        .expect("stale mark_outbox_sent on failed");

    let doc = coll
        .find_one(doc! { "_id": bson::Uuid::from(outbox_failed.id) })
        .await
        .expect("find doc")
        .expect("doc exists");
    assert_eq!(doc.status, OUTBOX_STATUS_FAILED);

    // Cleanup
    let _ = store
        .outbox()
        .cleanup_sent_outbox(Duration::from_secs(0))
        .await;
    let _ = coll
        .delete_one(doc! { "_id": bson::Uuid::from(outbox_failed.id) })
        .await;
}

#[tokio::test]
async fn test_mongo_oauth_lifecycle() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_oauth_lifecycle: MONGO_URL not set");
        return;
    };

    let user = store
        .users()
        .create_user(&format!("oauth_{}@example.com", Uuid::new_v4()), "hash")
        .await
        .expect("create user");

    let provider = "github";
    let provider_uid = format!("gh_uid_{}", Uuid::new_v4());

    // Link account
    let account = store
        .oauth()
        .link_account(user.id, provider, &provider_uid, &user.email)
        .await
        .expect("link oauth account");
    assert_eq!(account.user_id, user.id);
    assert_eq!(account.provider_id, provider);

    // Fetch by provider
    let by_prov = store
        .oauth()
        .get_account(provider, &provider_uid)
        .await
        .expect("fetch by provider")
        .expect("account found");
    assert_eq!(by_prov.id, account.id);

    // List accounts for user
    let accounts = store
        .oauth()
        .list_accounts_for_user(user.id)
        .await
        .expect("list accounts");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].id, account.id);

    // Duplicate link conflict
    let conflict = store
        .oauth()
        .link_account(user.id, provider, &provider_uid, "another@example.com")
        .await;
    assert!(matches!(conflict, Err(AppError::OAuthAccountLinkConflict)));

    // Unlink
    let unlinked = store
        .oauth()
        .unlink_account(user.id, provider)
        .await
        .expect("unlink account");
    assert!(unlinked);

    let accounts_after = store
        .oauth()
        .list_accounts_for_user(user.id)
        .await
        .expect("list accounts after unlink");
    assert!(accounts_after.is_empty());

    // Cleanup
    let _ = store.users().delete_user(user.id).await;
}

#[tokio::test]
async fn test_mongo_oauth_list_accounts_sort_order() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_oauth_list_accounts_sort_order: MONGO_URL not set");
        return;
    };

    let user = store
        .users()
        .create_user(
            &format!("oauth_sort_{}@example.com", Uuid::new_v4()),
            "hash",
        )
        .await
        .expect("create user");

    // 0 accounts returns empty vec
    let empty = store
        .oauth()
        .list_accounts_for_user(user.id)
        .await
        .expect("list empty accounts");
    assert!(empty.is_empty());

    let now = Utc::now();
    let t1 = now - chrono::Duration::hours(3);
    let t2 = now - chrono::Duration::hours(2);
    let t3 = now - chrono::Duration::hours(1);

    // Insert out of chronological order: t2 (google), t3 (discord), t1 (github)
    let coll = store.db().collection::<bson::Document>("oauth_accounts");
    let docs = vec![
        doc! {
            "_id": bson::Uuid::from(Uuid::new_v4()),
            "user_id": bson::Uuid::from(user.id),
            "provider_id": "google",
            "provider_user_id": format!("google_{}", Uuid::new_v4()),
            "email": "user@google.com",
            "created_at": bson::DateTime::from_chrono(t2),
            "updated_at": bson::DateTime::from_chrono(t2),
        },
        doc! {
            "_id": bson::Uuid::from(Uuid::new_v4()),
            "user_id": bson::Uuid::from(user.id),
            "provider_id": "discord",
            "provider_user_id": format!("discord_{}", Uuid::new_v4()),
            "email": "user@discord.com",
            "created_at": bson::DateTime::from_chrono(t3),
            "updated_at": bson::DateTime::from_chrono(t3),
        },
        doc! {
            "_id": bson::Uuid::from(Uuid::new_v4()),
            "user_id": bson::Uuid::from(user.id),
            "provider_id": "github",
            "provider_user_id": format!("github_{}", Uuid::new_v4()),
            "email": "user@github.com",
            "created_at": bson::DateTime::from_chrono(t1),
            "updated_at": bson::DateTime::from_chrono(t1),
        },
    ];

    coll.insert_many(docs)
        .await
        .expect("insert out-of-order oauth accounts");

    let accounts = store
        .oauth()
        .list_accounts_for_user(user.id)
        .await
        .expect("list accounts sorted");

    assert_eq!(accounts.len(), 3);
    assert_eq!(accounts[0].provider_id, "github");
    assert_eq!(accounts[1].provider_id, "google");
    assert_eq!(accounts[2].provider_id, "discord");
    assert!(accounts[0].created_at < accounts[1].created_at);
    assert!(accounts[1].created_at < accounts[2].created_at);

    // Cleanup
    let _ = store.users().delete_user(user.id).await;
}

#[tokio::test]
async fn test_mongo_totp_lifecycle() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_totp_lifecycle: MONGO_URL not set");
        return;
    };

    let user = store
        .users()
        .create_user(&format!("totp_{}@example.com", Uuid::new_v4()), "hash")
        .await
        .expect("create user");

    let secret = b"my_super_secret_totp_bytes";
    let backup_codes = serde_json::json!(["bc1", "bc2"]);

    // 1. Upsert secret
    store
        .totp()
        .upsert_secret(user.id, secret, backup_codes.clone())
        .await
        .expect("upsert totp secret");

    let fetched = store
        .totp()
        .get_secret(user.id)
        .await
        .expect("get totp secret")
        .expect("secret exists");
    assert_eq!(fetched.user_id, user.id);
    assert!(!fetched.enabled);

    // 2. Enable TOTP
    store
        .totp()
        .enable_totp(user.id)
        .await
        .expect("enable totp");

    let enabled = store
        .totp()
        .get_secret(user.id)
        .await
        .expect("get totp secret")
        .expect("secret exists");
    assert!(enabled.enabled);

    // 3. Record used code
    let code_hash = [42u8; 32];
    let recorded = store
        .totp()
        .record_used_code(user.id, &code_hash)
        .await
        .expect("record used code");
    assert!(recorded);

    // Replay should fail with TotpCodeReplayed
    let replay = store.totp().record_used_code(user.id, &code_hash).await;
    assert!(matches!(replay, Err(AppError::TotpCodeReplayed)));

    // Check is_code_used
    assert!(
        store
            .totp()
            .is_code_used(user.id, &code_hash)
            .await
            .unwrap()
    );

    // 4. 2FA challenge tokens
    let token_hash = [88u8; 32];
    let expires = Utc::now() + chrono::Duration::minutes(5);
    let challenge = store
        .totp()
        .create_two_factor_token(user.id, &token_hash, "cred_hash_test", expires)
        .await
        .expect("create 2fa token");
    assert_eq!(challenge.user_id, user.id);

    let redeemed = store
        .totp()
        .consume_two_factor_token(&token_hash)
        .await
        .expect("consume 2fa token")
        .expect("token exists");
    assert_eq!(redeemed.user_id, user.id);

    // Second redemption must fail
    let re_redeemed = store
        .totp()
        .consume_two_factor_token(&token_hash)
        .await
        .expect("re-consume 2fa token");
    assert!(re_redeemed.is_none());

    // Expired 2FA challenge token test
    let exp_token_hash = [89u8; 32];
    let past_expiry = Utc::now() - chrono::Duration::hours(1);
    store
        .totp()
        .create_two_factor_token(user.id, &exp_token_hash, "cred_hash_exp", past_expiry)
        .await
        .expect("create expired 2fa token");

    let exp_redeemed = store
        .totp()
        .consume_two_factor_token(&exp_token_hash)
        .await
        .expect("consume expired 2fa token")
        .expect("token exists");
    assert_eq!(exp_redeemed.user_id, user.id);
    assert!(exp_redeemed.expires_at <= Utc::now());

    let exp_re_redeemed = store
        .totp()
        .consume_two_factor_token(&exp_token_hash)
        .await
        .expect("re-consume expired 2fa token");
    assert!(exp_re_redeemed.is_none());

    // Cleanup
    let _ = store.users().delete_user(user.id).await;
}

#[tokio::test]
async fn test_mongo_totp_upsert_already_enabled() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_totp_upsert_already_enabled: MONGO_URL not set");
        return;
    };

    let user = store
        .users()
        .create_user(&format!("totp_en_{}@example.com", Uuid::new_v4()), "hash")
        .await
        .expect("create user");

    let secret = b"initial_totp_secret_bytes";
    let backup_codes = serde_json::json!(["bc1"]);

    store
        .totp()
        .upsert_secret(user.id, secret, backup_codes.clone())
        .await
        .expect("initial upsert succeeds");

    store
        .totp()
        .enable_totp(user.id)
        .await
        .expect("enable totp succeeds");

    // Upserting on an enabled TOTP secret must fail with TotpAlreadyEnabled
    let res = store
        .totp()
        .upsert_secret(user.id, b"new_secret_bytes", serde_json::json!(["bc2"]))
        .await;

    assert!(matches!(res, Err(AppError::TotpAlreadyEnabled)));

    // Verify original secret is intact and still enabled
    let current = store
        .totp()
        .get_secret(user.id)
        .await
        .expect("get secret")
        .expect("secret exists");
    assert!(current.enabled);
    assert_eq!(current.encrypted_secret, secret);

    let _ = store.users().delete_user(user.id).await;
}

#[tokio::test]
async fn test_mongo_totp_concurrent_upsert() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_totp_concurrent_upsert: MONGO_URL not set");
        return;
    };

    let user = store
        .users()
        .create_user(&format!("totp_cr_{}@example.com", Uuid::new_v4()), "hash")
        .await
        .expect("create user");

    let (res_a, res_b) = tokio::join!(
        store
            .totp()
            .upsert_secret(user.id, b"secret_a_bytes", serde_json::json!(["a1"])),
        store
            .totp()
            .upsert_secret(user.id, b"secret_b_bytes", serde_json::json!(["b1"]))
    );

    // Neither request should fail with a raw database duplicate key error (HTTP 500)
    assert!(res_a.is_ok(), "res_a error: {:?}", res_a.err());
    assert!(res_b.is_ok(), "res_b error: {:?}", res_b.err());

    let final_secret = store
        .totp()
        .get_secret(user.id)
        .await
        .expect("get secret")
        .expect("secret exists");
    assert!(!final_secret.enabled);

    let _ = store.users().delete_user(user.id).await;
}

#[tokio::test]
async fn test_mongo_totp_disable_parity() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_totp_disable_parity: MONGO_URL not set");
        return;
    };

    let non_existent_user_id = Uuid::new_v4();

    // 1. Disabling non-existent user returns Ok(false)
    let res = store
        .totp()
        .disable_totp(non_existent_user_id)
        .await
        .expect("disable non-existent user succeeds");
    assert!(!res);

    let user = store
        .users()
        .create_user(&format!("totp_dis_{}@example.com", Uuid::new_v4()), "hash")
        .await
        .expect("create user");

    let secret = b"super_secret_disable_parity_bytes";
    let backup_codes = serde_json::json!(["code1", "code2"]);

    // 2. Disabling unconfirmed secret (enabled: false) returns Ok(false) and leaves secret intact
    store
        .totp()
        .upsert_secret(user.id, secret, backup_codes.clone())
        .await
        .expect("upsert secret");

    let res = store
        .totp()
        .disable_totp(user.id)
        .await
        .expect("disable unconfirmed secret succeeds");
    assert!(!res);

    let pending_secret = store
        .totp()
        .get_secret(user.id)
        .await
        .expect("get secret")
        .expect("secret still exists");
    assert!(!pending_secret.enabled);
    assert_eq!(pending_secret.encrypted_secret, secret);
    assert_eq!(pending_secret.backup_codes, backup_codes);

    // 3. Confirm/enable TOTP and record a used code
    store
        .totp()
        .enable_totp(user.id)
        .await
        .expect("enable totp");

    let code_hash = [77u8; 32];
    let recorded = store
        .totp()
        .record_used_code(user.id, &code_hash)
        .await
        .expect("record used code");
    assert!(recorded);

    // 4. Disabling enabled secret returns Ok(true) and secret still exists with enabled: false
    let res = store
        .totp()
        .disable_totp(user.id)
        .await
        .expect("disable enabled secret succeeds");
    assert!(res);

    let disabled_secret = store
        .totp()
        .get_secret(user.id)
        .await
        .expect("get secret")
        .expect("secret still exists");
    assert!(!disabled_secret.enabled);
    assert_eq!(disabled_secret.encrypted_secret, secret);
    assert_eq!(disabled_secret.backup_codes, backup_codes);

    // 5. Calling disable again returns Ok(false)
    let repeat_res = store
        .totp()
        .disable_totp(user.id)
        .await
        .expect("disable already disabled secret succeeds");
    assert!(!repeat_res);

    // 6. Used codes are preserved
    let is_used = store
        .totp()
        .is_code_used(user.id, &code_hash)
        .await
        .expect("check is_code_used");
    assert!(is_used, "used code must be preserved after disable_totp");

    // Cleanup
    let _ = store.users().delete_user(user.id).await;
}

#[tokio::test]
async fn test_mongo_totp_used_codes_ttl_index() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_totp_used_codes_ttl_index: MONGO_URL not set");
        return;
    };

    let coll = store.db().collection::<bson::Document>("totp_used_codes");
    let mut cursor = coll.list_indexes().await.expect("list indexes");
    let mut found_ttl = false;
    while cursor.advance().await.expect("advance cursor") {
        let model = cursor
            .deserialize_current()
            .expect("deserialize index model");
        if let Some(opts) = model
            .options
            .as_ref()
            .filter(|o| o.name.as_deref() == Some("idx_totp_used_codes_used_at"))
        {
            assert_eq!(opts.expire_after, Some(Duration::from_secs(300)));
            found_ttl = true;
        }
    }
    assert!(
        found_ttl,
        "idx_totp_used_codes_used_at with expire_after=300s must exist"
    );
}

#[tokio::test]
async fn test_mongo_sessions_compound_index() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_sessions_compound_index: MONGO_URL not set");
        return;
    };

    let coll = store.db().collection::<bson::Document>("sessions");
    let mut cursor = coll.list_indexes().await.expect("list indexes");
    let mut found_index = false;
    while cursor.advance().await.expect("advance cursor") {
        let model = cursor
            .deserialize_current()
            .expect("deserialize index model");
        if let Some(_opts) = model
            .options
            .as_ref()
            .filter(|o| o.name.as_deref() == Some("idx_sessions_user_id_active"))
        {
            let keys: Vec<(&String, &bson::Bson)> = model.keys.iter().collect();
            assert_eq!(keys.len(), 2);
            assert_eq!(keys[0].0, "user_id");
            assert_eq!(keys[0].1, &bson::Bson::Int32(1));
            assert_eq!(keys[1].0, "last_active_at");
            assert_eq!(keys[1].1, &bson::Bson::Int32(-1));
            found_index = true;
        }
    }
    assert!(
        found_index,
        "idx_sessions_user_id_active with keys {{ user_id: 1, last_active_at: -1 }} must exist"
    );
}

#[tokio::test]
async fn test_mongo_cascade_delete() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_cascade_delete: MONGO_URL not set");
        return;
    };
    let email = format!("mongo_cascade_{}@example.com", Uuid::new_v4());
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

    let v_hash = [111u8; 32];
    store
        .tokens()
        .create_verification_token(user.id, &v_hash, Utc::now() + chrono::Duration::hours(1))
        .await
        .expect("create vtoken");

    let r_hash = [112u8; 32];
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

    let used_hash = [113u8; 32];
    store
        .totp()
        .record_used_code(user.id, &used_hash)
        .await
        .expect("record used code");

    let c_hash = [114u8; 32];
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

    // Perform cascade delete of the parent user (7-collection cascade)
    let deleted = store
        .users()
        .delete_user(user.id)
        .await
        .expect("delete user cascades in mongodb");
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
async fn test_mongo_transaction_atomicity() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_transaction_atomicity: MONGO_URL not set");
        return;
    };

    // If standalone and transactions not supported without replica set, verify fail-closed
    let tx_res = store.begin().await;
    match tx_res {
        Ok(mut tx) => {
            let email = format!("mongo_tx_{}@example.com", Uuid::new_v4());
            let user = tx
                .users()
                .create_user(&email, "hash")
                .await
                .expect("create user in mongo tx");
            tx.commit().await.expect("commit mongo tx");
            assert!(
                store
                    .users()
                    .get_user_by_id(user.id)
                    .await
                    .unwrap()
                    .is_some()
            );
            let _ = store.users().delete_user(user.id).await;
        }
        Err(AppError::TransactionNotSupported) => {
            // Standalone without replica set correctly fails closed
        }
        Err(e) => panic!("unexpected error beginning mongo tx: {:?}", e),
    }
}

#[tokio::test]
async fn test_mongo_delete_user_non_existent() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_delete_user_non_existent: MONGO_URL not set");
        return;
    };
    let random_id = Uuid::new_v4();
    let res = store.users().delete_user(random_id).await;
    assert!(!res.unwrap());
}

#[tokio::test]
async fn test_mongo_tx_delete_user_rollback() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_tx_delete_user_rollback: MONGO_URL not set");
        return;
    };

    if !store.is_replica_set() {
        eprintln!("Skipping test_mongo_tx_delete_user_rollback: not running on a replica set");
        return;
    }

    let tx_res = store.begin().await;
    let mut tx = match tx_res {
        Ok(tx) => tx,
        Err(AppError::TransactionNotSupported) => {
            eprintln!(
                "skipping test_mongo_tx_delete_user_rollback: transactions not supported on standalone"
            );
            return;
        }
        Err(e) => panic!("unexpected error beginning mongo tx: {:?}", e),
    };

    let email = format!("mongo_rollback_{}@example.com", Uuid::new_v4());
    let user = store
        .users()
        .create_user(&email, "hash")
        .await
        .expect("create user");

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

    let deleted = tx
        .users()
        .delete_user(user.id)
        .await
        .expect("delete_user inside tx");
    assert!(deleted);

    tx.rollback().await.expect("rollback mongo tx");

    // After rollback, user and session must still exist
    assert!(
        store
            .users()
            .get_user_by_id(user.id)
            .await
            .unwrap()
            .is_some()
    );
    let sessions = store.sessions().list_user_sessions(user.id).await.unwrap();
    assert_eq!(sessions.len(), 1);

    // Cleanup
    let _ = store.users().delete_user(user.id).await;
}

#[tokio::test]
async fn test_mongo_tx_drop_aborts_transaction() {
    let Some(store) = get_test_mongo_store().await else {
        eprintln!("skipping test_mongo_tx_drop_aborts_transaction: MONGO_URL not set");
        return;
    };

    if !store.is_replica_set() {
        eprintln!(
            "skipping test_mongo_tx_drop_aborts_transaction: transactions not supported on standalone"
        );
        return;
    }

    let tx_res = store.begin().await;
    let (user_id, email) = {
        let mut tx = match tx_res {
            Ok(tx) => tx,
            Err(AppError::TransactionNotSupported) => {
                eprintln!(
                    "skipping test_mongo_tx_drop_aborts_transaction: transactions not supported on standalone"
                );
                return;
            }
            Err(e) => panic!("unexpected error beginning mongo tx: {:?}", e),
        };

        let email = format!("mongo_drop_{}@example.com", Uuid::new_v4());
        let user = tx
            .users()
            .create_user(&email, "hash")
            .await
            .expect("create user in mongo tx");
        (user.id, email)
        // tx is intentionally dropped here without commit() or rollback()
    };

    // Yield briefly to allow the background abort task spawned in Drop to complete
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Assert that the uncommitted mutation was aborted and user does not exist
    let fetched = store.users().get_user_by_id(user_id).await.unwrap();
    assert!(
        fetched.is_none(),
        "uncommitted user must not exist after MongoTx drop"
    );

    // Verify subsequent operations on the collection succeed with the identical email,
    // proving the aborted transaction released unique constraints without duplicate key error.
    let mut user_after = None;
    for _ in 0..20 {
        match store.users().create_user(&email, "hash").await {
            Ok(u) => {
                user_after = Some(u);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    let user_after =
        user_after.expect("create user with identical email after drop abort must succeed");
    assert_eq!(user_after.email, email);
    let _ = store.users().delete_user(user_after.id).await;
}
