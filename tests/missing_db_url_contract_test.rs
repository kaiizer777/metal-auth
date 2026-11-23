//! Contract test for issue #84: DB-backed setup helpers must fail loudly when
//! `DATABASE_URL` is unset instead of skipping silently via early return.

mod common;

use common::*;

fn try_setup_without_db_url() -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build test runtime")
            .block_on(setup_test_app())
    }))
    .is_err()
}

#[test]
fn missing_database_url_fails_without_silent_skip() {
    let saved_db = std::env::var("DATABASE_URL").ok();
    let saved_ci = std::env::var("CI").ok();
    // SAFETY: dedicated test binary with a single test; no thread mutates env.
    unsafe {
        std::env::remove_var("DATABASE_URL");
        std::env::remove_var("CI");
    }
    assert!(
        try_setup_without_db_url(),
        "setup_test_app must fail (not skip) without DATABASE_URL"
    );
    // SAFETY: same single-threaded binary; restore below.
    unsafe {
        std::env::set_var("CI", "true");
    }
    assert!(
        try_setup_without_db_url(),
        "setup_test_app must fail without DATABASE_URL even under CI"
    );

    // SAFETY: restore the pre-test environment before returning.
    unsafe {
        match saved_db {
            Some(v) => std::env::set_var("DATABASE_URL", v),
            None => std::env::remove_var("DATABASE_URL"),
        }
        match saved_ci {
            Some(v) => std::env::set_var("CI", v),
            None => std::env::remove_var("CI"),
        }
    }
}
