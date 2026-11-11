use metal_auth::{AppError, Auth, Config};

#[tokio::test]
async fn test_auth_new_fails_on_invalid_auth_env_config() {
    // SAFETY: Dedicated test binary process with no concurrent test threads mutating env
    unsafe {
        std::env::set_var("ARGON2_M_COST", "100");
    }

    let cfg = Config {
        database_url: "postgres://localhost/test".into(),
        port: 3000,
        allowed_origins: vec![],
        allowed_methods: vec![],
        allowed_headers: vec![],
        max_connections: 2,
        min_connections: 1,
        base_url: "https://example.com".into(),
        email_dispatch_timeout: std::time::Duration::from_secs(10),
        async_email_dispatch: true,
    };

    let res = Auth::new(cfg).await;

    // SAFETY: Restore environment
    unsafe {
        std::env::remove_var("ARGON2_M_COST");
    }

    assert!(matches!(res, Err(AppError::Config(_))));
}
