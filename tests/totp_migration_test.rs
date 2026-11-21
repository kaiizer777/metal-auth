//! Migration 0008 against a throwaway schema.
//!
//! The up script must create every Phase 7 table, index, and unique constraint, and must stay
//! applied on an isolated schema so nothing else in the test database is touched.

use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;

const PHASE7_TABLES: [&str; 3] = ["totp_secrets", "totp_used_codes", "two_factor_tokens"];

const PHASE7_INDEXES: [&str; 4] = [
    "idx_totp_secrets_user_id",
    "idx_totp_used_codes_user_used",
    "idx_two_factor_tokens_user_id",
    "idx_two_factor_tokens_expires",
];

const PHASE7_UNIQUE_CONSTRAINTS: [&str; 3] = [
    "uq_totp_secrets_user_id",
    "uq_totp_used_codes",
    "uq_two_factor_tokens_hash",
];

#[tokio::test]
async fn migration_0008_creates_every_phase7_object() {
    in_isolated_schema(|pool, schema| async move {
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| format!("migrations must apply cleanly: {e}"))?;
        assert_phase7_present(&pool, &schema).await
    })
    .await;
}

async fn assert_phase7_present(pool: &PgPool, schema: &str) -> Result<(), String> {
    let tables = object_names(
        pool,
        "SELECT table_name FROM information_schema.tables WHERE table_schema = $1 \
         AND table_name = ANY($2)",
        schema,
        &PHASE7_TABLES,
    )
    .await?;
    if tables.len() != PHASE7_TABLES.len() {
        return Err(format!(
            "missing phase 7 tables in {schema}: found {tables:?}"
        ));
    }

    let indexes = object_names(
        pool,
        "SELECT indexname FROM pg_indexes WHERE schemaname = $1 AND indexname = ANY($2)",
        schema,
        &PHASE7_INDEXES,
    )
    .await?;
    if indexes.len() != PHASE7_INDEXES.len() {
        return Err(format!(
            "missing phase 7 indexes in {schema}: found {indexes:?}"
        ));
    }

    let constraints = object_names(
        pool,
        "SELECT constraint_name FROM information_schema.table_constraints \
         WHERE constraint_type = 'UNIQUE' AND table_schema = $1 AND constraint_name = ANY($2)",
        schema,
        &PHASE7_UNIQUE_CONSTRAINTS,
    )
    .await?;
    if constraints.len() != PHASE7_UNIQUE_CONSTRAINTS.len() {
        return Err(format!(
            "missing phase 7 unique constraints in {schema}: found {constraints:?}"
        ));
    }

    Ok(())
}

async fn object_names(
    pool: &PgPool,
    query: &'static str,
    schema: &str,
    names: &'static [&'static str],
) -> Result<Vec<String>, String> {
    sqlx::query_scalar(query)
        .bind(schema)
        .bind(names.to_vec())
        .fetch_all(pool)
        .await
        .map_err(|e| format!("inspect schema {schema}: {e}"))
}

/// Runs `body` against a freshly created schema and always drops it afterwards.
async fn in_isolated_schema<F, Fut>(body: F)
where
    F: FnOnce(PgPool, String) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), String>> + Send,
{
    dotenvy::dotenv().ok();
    let url = match std::env::var("DATABASE_URL") {
        Ok(val) => val,
        Err(std::env::VarError::NotPresent) => {
            assert!(
                std::env::var_os("CI").is_none(),
                "DATABASE_URL must be set in CI: migration tests must never skip silently"
            );
            eprintln!("SKIP: migration round trip needs DATABASE_URL");
            return;
        }
        Err(e) => panic!("invalid DATABASE_URL environment variable: {e}"),
    };

    let base_pool = PgPool::connect(&url)
        .await
        .expect("connect to base database");
    let schema_name = format!("test_schema_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE SCHEMA \"{schema_name}\""
    )))
    .execute(&base_pool)
    .await
    .expect("create isolated test schema");

    let search_path = schema_name.clone();
    let schema_pool = PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |conn, _meta| {
            let search_path = search_path.clone();
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(format!(
                    "SET search_path TO \"{search_path}\", public"
                )))
                .execute(conn)
                .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("connect to isolated test schema pool");

    // Teardown must survive an assertion failure, so the body runs in its own task.
    let task_pool = schema_pool.clone();
    let task_schema = schema_name.clone();
    let task = tokio::spawn(async move { body(task_pool, task_schema).await });

    let result = task.await;
    schema_pool.close().await;
    let cleanup = sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema_name}\" CASCADE"
    )))
    .execute(&base_pool)
    .await;

    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err}"),
        Err(join_err) => match join_err.try_into_panic() {
            Ok(payload) => std::panic::resume_unwind(payload),
            Err(e) => panic!("test task cancelled or failed: {e}"),
        },
    }

    cleanup.expect("drop isolated test schema");
}
