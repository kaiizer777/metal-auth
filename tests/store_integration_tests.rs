mod common;

use chrono::Utc;
use sha2::Digest;
use std::time::Duration;
use uuid::Uuid;

use common::setup_test_app;
use metal_auth::DatabaseBackend;

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
    let store = app.state.store();
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
}

#[tokio::test]
async fn test_store_sessions_lifecycle() {
    let app = setup_test_app().await.expect("test app initialization");
    let store = app.state.store();
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
}

#[tokio::test]
async fn test_store_tokens_lifecycle() {
    let app = setup_test_app().await.expect("test app initialization");
    let store = app.state.store();
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
}

#[tokio::test]
async fn test_store_outbox_lifecycle() {
    let app = setup_test_app().await.expect("test app initialization");
    let store = app.state.store();
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

#[tokio::test]
async fn test_store_transaction_commit_and_rollback() {
    let app = setup_test_app().await.expect("test app initialization");
    let store = app.state.store();

    // 1. Rollback test
    let email_aborted = format!("tx_abort_{}@example.com", Uuid::new_v4());
    let mut tx = store.begin().await.expect("begin tx");
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
    tx.users()
        .create_user(&email_committed, "hash")
        .await
        .expect("create user in tx");
    tx.commit().await.expect("commit tx");

    let committed_user = store
        .users()
        .get_user_by_email(&email_committed)
        .await
        .expect("fetch committed user");
    assert!(
        committed_user.is_some(),
        "committed user must exist in storage"
    );
}
