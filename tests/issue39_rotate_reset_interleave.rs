//! Regression tests for issue #39: rotate_session mints a live session after a
//! concurrent reset.
//!
//! The service-level tests drive the real `rotate_session` against the real
//! `reset_password`: the race test asserts zero live sessions in every
//! interleaving outcome, the serialization test proves rotate holds the
//! user-row lock across its tx (it must block while a concurrent tx holds it),
//! and the sequential test pins the reset-won fail-closed outcome by
//! construction (reset commits first, rotate fails closed, nothing survives).

mod common;

use std::time::{Duration, Instant};

use chrono::Utc;
use common::{dynamic_email, dynamic_password};
use metal_auth::{AppError, crypto::token::generate_token};
use sqlx::Row;
use uuid::Uuid;

async fn seed_user_with_session_and_reset_token(
    app: &common::TestApp,
) -> (Uuid, String, String, String) {
    let pool = &app.pool;
    let state = &app.state;
    let email = dynamic_email();
    let old_pw = dynamic_password();
    let new_pw = dynamic_password();
    state
        .auth_service
        .signup(&email, &old_pw)
        .await
        .expect("signup commits");
    let user_id: Uuid = sqlx::query("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(pool)
        .await
        .expect("user row exists")
        .get("id");
    sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("verify user");

    let (_session, old_raw) = state
        .session_service
        .create_session(user_id, "cookie", None, None)
        .await
        .expect("seed session mints");

    let (raw_token, token_hash) = generate_token();
    sqlx::query(
        "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(token_hash.as_slice())
    .bind(user_id)
    .bind(Utc::now() + chrono::Duration::hours(1))
    .execute(pool)
    .await
    .expect("seed reset token");

    (user_id, old_raw, raw_token, new_pw)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotate_concurrent_with_reset_leaves_zero_live_sessions() {
    let Some(app) = common::setup_test_app().await else {
        eprintln!("SKIP: DB-backed tests need DATABASE_URL");
        return;
    };
    let pool = &app.pool;
    let state = &app.state;

    let (user_id, old_raw, raw_token, new_pw) = seed_user_with_session_and_reset_token(&app).await;

    let rotate_state = state.clone();
    let rotate_handle = tokio::spawn(async move {
        rotate_state
            .session_service
            .rotate_session(&old_raw, None, None)
            .await
    });
    let reset_state = state.clone();
    let reset_handle = tokio::spawn(async move {
        reset_state
            .auth_service
            .reset_password(&raw_token, &new_pw)
            .await
    });

    let rotate_res = rotate_handle.await.expect("rotate task joins");
    reset_handle
        .await
        .expect("reset task joins")
        .expect("reset commits");

    // Either outcome is correct as long as nothing survives the reset:
    // rotate-first means reset's purge removes the minted row; reset-first
    // means rotate finds its old row already purged and fails closed.
    match rotate_res {
        Ok(_) => {}
        Err(e) => assert!(
            matches!(e, AppError::SessionNotFound | AppError::SessionInvalid),
            "ISSUE39: rotate lost the race but failed open with {e:?}"
        ),
    }

    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("session count readable");
    assert_eq!(
        live, 0,
        "ISSUE39: live session survived a committed password reset"
    );
}

/// Characterization: pins closed behavior post-reset (SessionNotFound, zero
/// live sessions). NOT a guard-branch regression pin — red/green ownership
/// belongs to the serialization interleave test, whose pg_stat_activity gate
/// matches a `SELECT ... FOR UPDATE` the pre-fix code never emits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotate_after_committed_reset_stays_closed() {
    let Some(app) = common::setup_test_app().await else {
        eprintln!("SKIP: DB-backed tests need DATABASE_URL");
        return;
    };
    let pool = &app.pool;
    let state = &app.state;

    let (user_id, old_raw, raw_token, new_pw) = seed_user_with_session_and_reset_token(&app).await;

    // Reset commits first, so rotate's pre-tx lookup misses the purged row and
    // fails closed by construction (no scheduler luck).
    state
        .auth_service
        .reset_password(&raw_token, &new_pw)
        .await
        .expect("reset commits");
    let err = state
        .session_service
        .rotate_session(&old_raw, None, None)
        .await
        .expect_err("rotate after a committed purge must fail");
    assert!(
        matches!(err, AppError::SessionNotFound),
        "ISSUE39: rotate after reset failed open with {err:?}"
    );

    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("session count readable");
    assert_eq!(
        live, 0,
        "ISSUE39: session survived a committed password reset"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotate_waits_on_user_row_before_delete() {
    let Some(app) = common::setup_test_app().await else {
        eprintln!("SKIP: DB-backed tests need DATABASE_URL");
        return;
    };
    let pool = &app.pool;
    let state = &app.state;

    let (user_id, old_raw, _, _) = seed_user_with_session_and_reset_token(&app).await;

    // A concurrent reset tx holds the user row from its UPDATE users until it
    // purges. Rotate must wait on that same row BEFORE deleting anything:
    // pre-fix rotate deletes first and only stalls later at the INSERT's FK
    // key-share check, which is exactly the hole the reset purge slips through.
    let mut guard_tx = pool.begin().await.expect("guard tx begins");
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *guard_tx)
        .await
        .expect("guard lock acquired");

    // Gate on the guard backend: the worker runs rotate on a pooled
    // connection whose pid the test cannot observe, but the guard tx
    // connection is held by this test, so its pid is a stable blocker id.
    let guard_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *guard_tx)
        .await
        .expect("guard backend pid readable");
    let rotate_state = state.clone();
    let rotate_handle = tokio::spawn(async move {
        rotate_state
            .session_service
            .rotate_session(&old_raw, None, None)
            .await
    });

    // The in-flight rotate backend must show up blocked inside its explicit
    // SELECT ... FOR UPDATE. Pre-fix rotate never issues that statement, so
    // the deadline expires and the test fails instead of passing by accident.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_stat_activity WHERE query LIKE 'SELECT id FROM users%FOR UPDATE' AND datname = current_database() AND wait_event_type = 'Lock' AND $1 = ANY (pg_blocking_pids(pid))",
        )
        .bind(guard_pid)
        .fetch_one(pool)
        .await
        .expect("pg_stat_activity must be readable");
        if waiting > 0 {
            break;
        }
        if Instant::now() > deadline {
            panic!("ISSUE39: rotate never waited on the user-row lock before deleting");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    guard_tx.commit().await.expect("guard tx commits");
    rotate_handle
        .await
        .expect("rotate task joins")
        .expect("rotate succeeds once the user-row lock releases");
}

/// Guard-branch pin: rotate blocks on the user-row lock, the sessions vanish
/// underneath it while it waits, and it must fail closed (SessionNotFound)
/// with zero live sessions once the guard releases. Pre-fix rotate never
/// emits SELECT ... FOR UPDATE, so the wait-gate deadline expires and this
/// test fails instead of passing by accident.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotate_blocked_by_guard_then_purged_fails_closed() {
    let Some(app) = common::setup_test_app().await else {
        eprintln!("SKIP: DB-backed tests need DATABASE_URL");
        return;
    };
    let pool = &app.pool;
    let state = &app.state;

    let (user_id, old_raw, _, _) = seed_user_with_session_and_reset_token(&app).await;

    let mut guard_tx = pool.begin().await.expect("guard tx begins");
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *guard_tx)
        .await
        .expect("guard lock acquired");

    let guard_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *guard_tx)
        .await
        .expect("guard backend pid readable");
    let rotate_state = state.clone();
    let rotate_handle = tokio::spawn(async move {
        rotate_state
            .session_service
            .rotate_session(&old_raw, None, None)
            .await
    });

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_stat_activity WHERE query LIKE 'SELECT id FROM users%FOR UPDATE' AND datname = current_database() AND wait_event_type = 'Lock' AND $1 = ANY (pg_blocking_pids(pid))",
        )
        .bind(guard_pid)
        .fetch_one(pool)
        .await
        .expect("pg_stat_activity must be readable");
        if waiting > 0 {
            break;
        }
        if Instant::now() > deadline {
            panic!("ISSUE39: rotate never waited on the user-row lock before deleting");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Purge the sessions inside the guard while rotate is still blocked, then
    // release it: rotate must observe the missing row and fail closed.
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *guard_tx)
        .await
        .expect("guard purges sessions");
    guard_tx.commit().await.expect("guard tx commits");

    let err = rotate_handle
        .await
        .expect("rotate task joins")
        .expect_err("rotate blocked behind a purge must fail closed");
    assert!(
        matches!(err, AppError::SessionNotFound),
        "ISSUE39: rotate after guard purge failed open with {err:?}"
    );

    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("session count readable");
    assert_eq!(live, 0, "ISSUE39: live session survived the guard purge");
}
