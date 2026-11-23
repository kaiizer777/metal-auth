//! Issue #64: the `users`-row lock on the session-mint path must be
//! `FOR NO KEY UPDATE`.
//!
//! `FOR UPDATE` also conflicts with the `FOR KEY SHARE` that every insert into a
//! `users`-referencing child table takes on the parent row, so any concurrent child
//! insert waited for the whole mint. `FOR NO KEY UPDATE` keeps the conflict with an
//! `UPDATE users` writer — the edge the mint's invariants actually rest on — and
//! drops only the foreign-key edge.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use sqlx::PgPool;
use uuid::Uuid;

async fn seed_user(pool: &PgPool) -> Uuid {
    let user_id = Uuid::new_v4();
    let email = format!("lock64_{user_id}@example.com");
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(&email)
    .bind("$argon2id$v=19$m=19456,t=2,p=1$lock64placeholder")
    .execute(pool)
    .await
    .expect("insert test user");
    user_id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_mint_does_not_wait_on_a_foreign_key_key_share_holder() {
    let Some(app) = common::setup_test_app().await else {
        eprintln!("SKIP: DB-backed tests need DATABASE_URL");
        return;
    };
    let pool = &app.pool;
    let user_id = seed_user(pool).await;
    let sessions = Arc::clone(&app.state.session_service);

    // Exactly the lock a child-table INSERT takes on its parent row.
    let mut guard_tx = pool.begin().await.expect("guard tx begins");
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR KEY SHARE")
        .bind(user_id)
        .execute(&mut *guard_tx)
        .await
        .expect("key-share guard acquired");

    // The guard stays open for the whole wait, so the mint can only finish here if
    // it never requested a lock that conflicts with FOR KEY SHARE.
    let (session, raw_token) = tokio::time::timeout(
        Duration::from_secs(10),
        sessions.create_session(user_id, "bearer", None, None),
    )
    .await
    .expect("session mint must not wait on a FOR KEY SHARE holder")
    .expect("session mints while the key-share guard is open");
    assert_eq!(session.user_id, user_id);
    assert!(!raw_token.is_empty(), "a raw session token is returned");

    // Guard still holds the row: the mint did not slip past a released lock.
    sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
        .fetch_one(&mut *guard_tx)
        .await
        .expect("guard tx still open after the mint");
    guard_tx.rollback().await.expect("guard tx rolls back");

    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("session count readable");
    assert_eq!(live, 1, "exactly one session minted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_mint_still_serializes_with_a_user_row_writer() {
    let Some(app) = common::setup_test_app().await else {
        eprintln!("SKIP: DB-backed tests need DATABASE_URL");
        return;
    };
    let pool = &app.pool;
    let user_id = seed_user(pool).await;
    let sessions = Arc::clone(&app.state.session_service);

    // The mode `UPDATE users SET ...` takes, i.e. what a committing password reset holds.
    let mut guard_tx = pool.begin().await.expect("guard tx begins");
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR NO KEY UPDATE")
        .bind(user_id)
        .execute(&mut *guard_tx)
        .await
        .expect("writer-mode guard acquired");
    let guard_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *guard_tx)
        .await
        .expect("guard backend pid readable");

    let mint =
        tokio::spawn(async move { sessions.create_session(user_id, "bearer", None, None).await });

    // Blocking is asserted by the blocker relationship, not the statement text, so
    // this pin also holds for any mode that regresses to a dropped lock.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND $1 = ANY (pg_blocking_pids(pid))",
        )
        .bind(guard_pid)
        .fetch_one(pool)
        .await
        .expect("pg_stat_activity must be readable");
        if waiting > 0 {
            break;
        }
        if Instant::now() > deadline {
            panic!("session mint no longer serializes with a users-row writer");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    guard_tx.commit().await.expect("guard tx commits");
    let (_, raw_token) = mint
        .await
        .expect("mint task joins")
        .expect("mint completes once the writer commits");
    assert!(!raw_token.is_empty(), "a raw session token is returned");

    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("session count readable");
    assert_eq!(live, 1, "exactly one session minted");
}
