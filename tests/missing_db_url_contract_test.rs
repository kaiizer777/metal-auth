//! Contract test for issue #84: DB-backed setup helpers must fail loudly when
//! `DATABASE_URL` is unset instead of skipping silently via early return.

mod common;

use common::*;

/// Subprocess test target invoked in environment isolation by `missing_database_url_fails_without_silent_skip`.
#[test]
#[ignore = "invoked as isolated child process by missing_database_url_fails_without_silent_skip"]
fn child_case_missing_db_url() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build test runtime")
        .block_on(setup_test_app());
}

struct TempDirGuard(std::path::PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_isolated_missing_db_contract(ci_val: Option<&str>) -> std::process::Output {
    let current_exe = std::env::current_exe().expect("test binary path");
    let isolated_dir =
        std::env::temp_dir().join(format!("metal_auth_contract_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&isolated_dir).expect("create isolated temp dir");
    let _guard = TempDirGuard(isolated_dir.clone());

    let mut cmd = std::process::Command::new(current_exe);
    cmd.args([
        "child_case_missing_db_url",
        "--exact",
        "--ignored",
        "--nocapture",
    ])
    .current_dir(&isolated_dir)
    .env_remove("DATABASE_URL")
    .env("TEST_SKIP_DOTENV", "1");

    match ci_val {
        Some(ci) => {
            cmd.env("CI", ci);
        }
        None => {
            cmd.env_remove("CI");
        }
    }

    cmd.output()
        .expect("execute isolated contract child process")
}

#[test]
fn missing_database_url_fails_without_silent_skip() {
    let expected_panic = "DATABASE_URL must be set: DB-backed tests require a live database";

    // 1. Without CI set
    let output = run_isolated_missing_db_contract(None);
    assert!(
        !output.status.success(),
        "setup_test_app must fail (not skip or pass) without DATABASE_URL"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stderr.contains(expected_panic) || stdout.contains(expected_panic),
        "expected panic message about missing DATABASE_URL, got stderr: {stderr}\nstdout: {stdout}"
    );

    // 2. With CI set
    let output_ci = run_isolated_missing_db_contract(Some("true"));
    assert!(
        !output_ci.status.success(),
        "setup_test_app must fail without DATABASE_URL even under CI"
    );
    let stderr_ci = String::from_utf8_lossy(&output_ci.stderr);
    let stdout_ci = String::from_utf8_lossy(&output_ci.stdout);
    assert!(
        stderr_ci.contains(expected_panic) || stdout_ci.contains(expected_panic),
        "expected panic message about missing DATABASE_URL under CI, got stderr: {stderr_ci}\nstdout: {stdout_ci}"
    );
}
