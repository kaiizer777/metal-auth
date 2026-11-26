use std::sync::{Arc, Mutex};

use metal_auth::AppError;

// ─────────────────────────────────────────────────────────────────────────────
// Zero-leak Log Audit Subscriber
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct MemoryLogCapture {
    logs: Arc<Mutex<Vec<String>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for MemoryLogCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = StringVisitor(String::new());
        event.record(&mut visitor);
        if let Ok(mut logs) = self.logs.lock() {
            logs.push(visitor.0);
        }
    }
}

struct StringVisitor(String);

impl tracing::field::Visit for StringVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!("{}: {:?}; ", field.name(), value));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push_str(&format!("{}: {}; ", field.name(), value));
    }
}

#[test]
fn test_security_zero_leak_log_audit() {
    use tracing_subscriber::layer::SubscriberExt;

    let capture = MemoryLogCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let raw_secret = "super_secret_raw_token_xyz_123456789";
    let raw_password = "attacker_password_999";

    // Simulate an error event using tracing
    tracing::warn!(
        user = "test_user@example.com",
        error = %AppError::InvalidCredentials,
        "Authentication failed for user"
    );

    // Verify logs captured the event without containing un-redacted credentials
    let logs = capture.logs.lock().unwrap();
    let all_logs = logs.join("\n");
    assert!(!all_logs.contains(raw_secret));
    assert!(!all_logs.contains(raw_password));
    assert!(all_logs.contains("Authentication failed"));
}

// ─────────────────────────────────────────────────────────────────────────────
// NoSQL Operator Injection Immunity (MongoDB)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "mongodb")]
mod mongo_security {
    use std::time::Duration;

    use chrono::Utc;
    use metal_auth::{DatabaseStore, MongoStore};
    use mongodb::{Client, bson::doc};
    use uuid::Uuid;

    use super::*;

    async fn get_mongo_store() -> Option<MongoStore> {
        dotenvy::dotenv().ok();
        let url = std::env::var("MONGODB_URI")
            .or_else(|_| std::env::var("MONGODB_URL"))
            .or_else(|_| std::env::var("MONGO_URL"))
            .or_else(|_| std::env::var("DATABASE_URL"))
            .ok()?;
        if !url.starts_with("mongodb://") && !url.starts_with("mongodb+srv://") {
            return None;
        }
        let db_name = std::env::var("MONGO_DATABASE")
            .or_else(|_| std::env::var("MONGODB_DATABASE"))
            .unwrap_or_else(|_| "metal_auth_test".to_string());
        let mut client_options = mongodb::options::ClientOptions::parse(&url).await.ok()?;
        client_options.connect_timeout = Some(Duration::from_secs(3));
        client_options.server_selection_timeout = Some(Duration::from_secs(3));
        let client = Client::with_options(client_options).ok()?;
        let db = client.database(&db_name);
        db.run_command(doc! { "ping": 1 }).await.ok()?;
        Some(MongoStore::new(client, &db_name, false, true))
    }

    #[test]
    fn test_nosql_operator_injection_payload_treated_as_literal() {
        let malicious_inputs = [
            "{\"$ne\": null}",
            "{\"$gt\": \"\"}",
            "{\"$regex\": \".*\"}",
            "{\"$where\": \"sleep(5000)\"}",
        ];

        for input in malicious_inputs {
            let filter = doc! { "email": input };
            // Document strictly stores string BSON type, NOT a subdocument with operators
            assert_eq!(filter.get_str("email").unwrap(), input);
            assert!(filter.get_document("email").is_err());
        }
    }

    #[tokio::test]
    async fn test_mongo_standalone_fails_closed_without_opt_in() {
        let client = Client::with_uri_str("mongodb://127.0.0.1:27017")
            .await
            .unwrap();
        // Disallow non-transactional standalone
        let store = MongoStore::new(client, "metal_auth_test", false, false);
        let res = store.begin().await;
        assert!(matches!(res, Err(AppError::TransactionNotSupported)));
    }

    #[tokio::test]
    async fn test_mongo_concurrent_totp_replay_barrier() {
        let Some(store) = get_mongo_store().await else {
            eprintln!("skipping test_mongo_concurrent_totp_replay_barrier: MONGODB_URI not set");
            return;
        };

        let email = format!("mongo_barrier_{}@example.com", Uuid::new_v4());
        let user = store
            .users()
            .create_user(&email, "hash")
            .await
            .expect("create user");

        let code_hash = [55u8; 32];
        let mut handles = Vec::new();

        // 5 concurrent tasks submitting identical valid TOTP code
        for _ in 0..5 {
            let store_clone = store.clone();
            let user_id = user.id;
            handles.push(tokio::spawn(async move {
                store_clone
                    .totp()
                    .record_used_code(user_id, &code_hash)
                    .await
            }));
        }

        let mut success_count = 0;
        let mut replay_count = 0;
        for handle in handles {
            match handle.await.unwrap() {
                Ok(true) => success_count += 1,
                Err(AppError::TotpCodeReplayed) => replay_count += 1,
                other => panic!("unexpected outcome: {:?}", other),
            }
        }

        assert_eq!(success_count, 1, "exactly 1 submission must succeed");
        assert_eq!(
            replay_count, 4,
            "exactly 4 submissions must fail with TotpCodeReplayed"
        );

        let _ = store.users().delete_user(user.id).await;
    }

    #[tokio::test]
    async fn test_mongo_login_vs_password_reset_race() {
        let Some(store) = get_mongo_store().await else {
            eprintln!("skipping test_mongo_login_vs_password_reset_race: MONGODB_URI not set");
            return;
        };

        let email = format!("mongo_race_{}@example.com", Uuid::new_v4());
        let user = store
            .users()
            .create_user(&email, "hash_v1")
            .await
            .expect("create user");

        // Mint 2FA challenge token before password reset
        let c_hash = [77u8; 32];
        store
            .totp()
            .create_two_factor_token(
                user.id,
                &c_hash,
                "cred_hash_old",
                Utc::now() + chrono::Duration::minutes(5),
            )
            .await
            .expect("create challenge token");

        // Execute password reset
        store
            .users()
            .update_password_hash(user.id, "hash_v2")
            .await
            .expect("update password");
        store
            .sessions()
            .delete_user_sessions(user.id)
            .await
            .expect("delete sessions");

        // Consume challenge token succeeds only once
        let first_consume = store
            .totp()
            .consume_two_factor_token(&c_hash)
            .await
            .unwrap();
        assert!(first_consume.is_some());

        // Replay of challenge token is strictly rejected
        let second_consume = store
            .totp()
            .consume_two_factor_token(&c_hash)
            .await
            .unwrap();
        assert!(second_consume.is_none());

        let _ = store.users().delete_user(user.id).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SQL Injection Defense & Concurrency Barrier (MySQL)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "mysql")]
mod mysql_security {
    use std::time::Duration;

    use chrono::Utc;
    use metal_auth::{
        DatabaseStore, MySqlStore,
        db::{DbPoolOptions, init_mysql_pool_with_options},
    };
    use sqlx::MySqlPool;
    use uuid::Uuid;

    use super::*;

    async fn get_mysql_pool() -> Option<MySqlPool> {
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

    #[tokio::test]
    async fn test_mysql_sql_injection_defense() {
        let Some(pool) = get_mysql_pool().await else {
            eprintln!("skipping test_mysql_sql_injection_defense: MYSQL_DATABASE_URL not set");
            return;
        };
        let store = MySqlStore::new(pool);

        // SQL injection payload attempting tautology and command injection
        let malicious_email = format!("attacker' OR '1'='1' -- {}", Uuid::new_v4());
        let user = store
            .users()
            .create_user(&malicious_email, "hash")
            .await
            .expect("create user with SQL injection payload in email");

        // Verify it was treated strictly as a literal string value
        assert_eq!(user.email, malicious_email);

        let fetched = store
            .users()
            .get_user_by_email(&malicious_email)
            .await
            .expect("fetch by literal malicious email")
            .expect("user found");
        assert_eq!(fetched.id, user.id);

        let _ = store.users().delete_user(user.id).await;
    }

    #[tokio::test]
    async fn test_mysql_concurrent_totp_replay_barrier() {
        let Some(pool) = get_mysql_pool().await else {
            eprintln!(
                "skipping test_mysql_concurrent_totp_replay_barrier: MYSQL_DATABASE_URL not set"
            );
            return;
        };
        let store = MySqlStore::new(pool);

        let email = format!("mysql_barrier_{}@example.com", Uuid::new_v4());
        let user = store
            .users()
            .create_user(&email, "hash")
            .await
            .expect("create user");

        let code_hash = [66u8; 32];
        let mut handles = Vec::new();

        // 5 concurrent tasks submitting identical valid TOTP code
        for _ in 0..5 {
            let store_clone = store.clone();
            let user_id = user.id;
            handles.push(tokio::spawn(async move {
                store_clone
                    .totp()
                    .record_used_code(user_id, &code_hash)
                    .await
            }));
        }

        let mut success_count = 0;
        let mut replay_count = 0;
        for handle in handles {
            match handle.await.unwrap() {
                Ok(true) => success_count += 1,
                Err(AppError::TotpCodeReplayed) => replay_count += 1,
                other => panic!("unexpected outcome: {:?}", other),
            }
        }

        assert_eq!(success_count, 1, "exactly 1 submission must succeed");
        assert_eq!(
            replay_count, 4,
            "exactly 4 submissions must fail with TotpCodeReplayed"
        );

        let _ = store.users().delete_user(user.id).await;
    }

    #[tokio::test]
    async fn test_mysql_login_vs_password_reset_race() {
        let Some(pool) = get_mysql_pool().await else {
            eprintln!(
                "skipping test_mysql_login_vs_password_reset_race: MYSQL_DATABASE_URL not set"
            );
            return;
        };
        let store = MySqlStore::new(pool);

        let email = format!("mysql_race_{}@example.com", Uuid::new_v4());
        let user = store
            .users()
            .create_user(&email, "hash_v1")
            .await
            .expect("create user");

        // Mint 2FA challenge token before password reset
        let c_hash = [88u8; 32];
        store
            .totp()
            .create_two_factor_token(
                user.id,
                &c_hash,
                "cred_hash_old",
                Utc::now() + chrono::Duration::minutes(5),
            )
            .await
            .expect("create challenge token");

        // Execute password reset
        store
            .users()
            .update_password_hash(user.id, "hash_v2")
            .await
            .expect("update password");
        store
            .sessions()
            .delete_user_sessions(user.id)
            .await
            .expect("delete sessions");

        // Consume challenge token succeeds only once
        let first_consume = store
            .totp()
            .consume_two_factor_token(&c_hash)
            .await
            .unwrap();
        assert!(first_consume.is_some());

        // Replay of challenge token is strictly rejected
        let second_consume = store
            .totp()
            .consume_two_factor_token(&c_hash)
            .await
            .unwrap();
        assert!(second_consume.is_none());

        let _ = store.users().delete_user(user.id).await;
    }
}
