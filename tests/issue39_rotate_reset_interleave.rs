//! Regression tests for issue #39: rotate_session mints a live session after a
//! concurrent reset.
//!
//! The replay test mirrors rotate's exact in-tx statement order from
//! src/session/service.rs (user-row FOR UPDATE, DELETE old, INSERT new) around
//! the real reset_password purge (src/auth/service.rs), then asserts the
//! post-reset invariant. Pre-fix (no user-row lock) the final assertion fails
//! deterministically: one live row survives.
//!
//! The service-level tests drive the real `rotate_session` against the real
//! `reset_password`: the race test asserts zero live sessions in every
//! interleaving outcome, and the serialization test proves rotate holds the
//! user-row lock across its tx (it must block while a concurrent tx holds it).

mod common;

use std::time::{Duration, Instant};

use chrono::Utc;
use common::{dynamic_email, dynamic_password};
use metal_auth::{AppError, SessionService, crypto::token::generate_token};
use rand_core::{OsRng, RngCore};
use sqlx::Row;
use uuid::Uuid;

// Reset blocks on a lock held by the open rotate tx — pre-fix on the old
// session row at its `DELETE FROM sessions WHERE user_id` purge, post-fix
// earlier at its `UPDATE users` (rotate now holds the user row first).
// Observing that blocked backend proves the killer interleave is established
// before rotate commits (no timing guesswork).
async fn wait_until_reset_blocks(pool: &sqlx::PgPool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let blocked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_stat_activity WHERE (query LIKE 'DELETE FROM sessions WHERE user_id%' OR query LIKE 'UPDATE users SET%') AND wait_event_type = 'Lock'",
        )
        .fetch_one(pool)
        .await
        .expect("pg_stat_activity must be readable");
        if blocked > 0 {
            return;
        }
        if Instant::now() > deadline {
            panic!("ISSUE39-ISOLATION: reset never blocked on rotate tx");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotate_mints_live_session_after_concurrent_reset() {
    let Some(app) = common::setup_test_app().await else {
        panic!("DATABASE_URL must be set: issue-39 MRE needs a live DB");
    };
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

    let (old_session, old_raw) = state
        .session_service
        .create_session(user_id, "cookie", None, None)
        .await
        .expect("seed session mints");
    let old_hash = SessionService::hash_raw_id(&old_raw);

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

    // Rotate tx opens; user-row lock then DELETE old inside tx, mirroring
    // rotate_session's in-tx statement order (service.rs verbatim).
    let mut rotate_tx = pool.begin().await.expect("rotate tx begins");
    sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *rotate_tx)
        .await
        .expect("rotate user-row lock runs");
    let deleted = sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(&old_hash)
        .execute(&mut *rotate_tx)
        .await
        .expect("rotate delete runs")
        .rows_affected();
    assert_eq!(deleted, 1, "rotate must delete exactly the old session");

    // Concurrent reset commits while rotate tx still holds the delete (auth/service.rs:434-469).
    let reset_state = state.clone();
    let reset_handle = tokio::spawn(async move {
        reset_state
            .auth_service
            .reset_password(&raw_token, &new_pw)
            .await
    });
    wait_until_reset_blocks(pool).await;

    // Rotate INSERTs the new session and commits; reset's purge unblocks after
    // and sees this row (service.rs INSERT-then-commit order verbatim).
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let new_raw = hex::encode(bytes);
    let new_hash = SessionService::hash_raw_id(&new_raw);
    let now = Utc::now();
    let idle_expires_at =
        now + chrono::Duration::seconds(state.config.session.idle_timeout_secs as i64);
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, idle_expires_at, last_active_at, absolute_expires_at, session_type, csrf_token) VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $3, $4, $6, $7)",
    )
    .bind(user_id)
    .bind(&new_hash)
    .bind(now)
    .bind(old_session.absolute_expires_at)
    .bind(idle_expires_at)
    .bind(old_session.session_type.clone())
    .bind(Option::<String>::None)
    .execute(&mut *rotate_tx)
    .await
    .expect("rotate insert runs");
    rotate_tx.commit().await.expect("rotate tx commits");
    reset_handle
        .await
        .expect("reset task joins")
        .expect("reset commits");

    // Post-reset invariant: no session may survive a password reset.
    // (The old row was deleted by the committed rotate tx, so any row left
    // here is the post-purge mint: hashes would equal [new_hash].)
    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("session count readable");
    assert_eq!(
        live, 0,
        "ISSUE39: rotate minted a live session after password reset purge"
    );
}

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
        panic!("DATABASE_URL must be set: issue-39 regression test needs a live DB");
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotate_waits_on_user_row_before_delete() {
    let Some(app) = common::setup_test_app().await else {
        panic!("DATABASE_URL must be set: issue-39 regression test needs a live DB");
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
            "SELECT COUNT(*) FROM pg_stat_activity WHERE query LIKE 'SELECT id FROM users%FOR UPDATE' AND wait_event_type = 'Lock'",
        )
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
