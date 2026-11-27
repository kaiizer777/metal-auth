//! Idempotent index initialization for MongoDB collections.
//!
//! Enforces uniqueness constraints (including case-insensitive collation for emails),
//! TTL background reaper indexes, and fast lookup compound indexes across all 9 collections.

use std::time::Duration;

use bson::doc;
use mongodb::{
    Database, IndexModel,
    options::{Collation, CollationStrength, IndexOptions},
};

use crate::error::AppError;

pub const USERS_COLLECTION: &str = "users";
pub const SESSIONS_COLLECTION: &str = "sessions";
pub const VERIFICATION_TOKENS_COLLECTION: &str = "verification_tokens";
pub const PASSWORD_RESET_TOKENS_COLLECTION: &str = "password_reset_tokens";
pub const EMAIL_OUTBOX_COLLECTION: &str = "email_outbox";
pub const OAUTH_ACCOUNTS_COLLECTION: &str = "oauth_accounts";
pub const TOTP_SECRETS_COLLECTION: &str = "totp_secrets";
pub const TOTP_USED_CODES_COLLECTION: &str = "totp_used_codes";
pub const TWO_FACTOR_TOKENS_COLLECTION: &str = "two_factor_tokens";

/// Ensures all necessary indexes across all 9 collections exist idempotently.
pub async fn ensure_indexes(db: &Database) -> Result<(), AppError> {
    // 1. users: unique email with case-insensitive secondary collation
    let email_collation = Collation::builder()
        .locale("en")
        .strength(CollationStrength::Secondary)
        .build();
    let user_indexes = vec![
        IndexModel::builder()
            .keys(doc! { "email": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_users_email_unique".to_string())
                    .unique(true)
                    .collation(email_collation)
                    .build(),
            )
            .build(),
    ];
    db.collection::<bson::Document>(USERS_COLLECTION)
        .create_indexes(user_indexes)
        .await
        .map_err(AppError::from)?;

    // 2. sessions: unique token_hash, user_id index, and TTL index on absolute_expires_at
    let session_indexes = vec![
        IndexModel::builder()
            .keys(doc! { "token_hash": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_sessions_token_hash_unique".to_string())
                    .unique(true)
                    .build(),
            )
            .build(),
        IndexModel::builder()
            .keys(doc! { "user_id": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_sessions_user_id".to_string())
                    .build(),
            )
            .build(),
        IndexModel::builder()
            .keys(doc! { "user_id": 1, "last_active_at": -1 })
            .options(
                IndexOptions::builder()
                    .name("idx_sessions_user_id_active".to_string())
                    .build(),
            )
            .build(),
        IndexModel::builder()
            .keys(doc! { "absolute_expires_at": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_sessions_ttl".to_string())
                    .expire_after(Duration::ZERO)
                    .build(),
            )
            .build(),
    ];
    db.collection::<bson::Document>(SESSIONS_COLLECTION)
        .create_indexes(session_indexes)
        .await
        .map_err(AppError::from)?;

    // 3. verification_tokens: unique token_hash, user_id index, and TTL index
    let verification_indexes = vec![
        IndexModel::builder()
            .keys(doc! { "token_hash": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_verification_tokens_token_hash_unique".to_string())
                    .unique(true)
                    .build(),
            )
            .build(),
        IndexModel::builder()
            .keys(doc! { "user_id": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_verification_tokens_user_id".to_string())
                    .build(),
            )
            .build(),
        IndexModel::builder()
            .keys(doc! { "expires_at": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_verification_tokens_ttl".to_string())
                    .expire_after(Duration::ZERO)
                    .build(),
            )
            .build(),
    ];
    db.collection::<bson::Document>(VERIFICATION_TOKENS_COLLECTION)
        .create_indexes(verification_indexes)
        .await
        .map_err(AppError::from)?;

    // 4. password_reset_tokens: unique token_hash, user_id index, and TTL index
    let reset_indexes = vec![
        IndexModel::builder()
            .keys(doc! { "token_hash": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_password_reset_tokens_token_hash_unique".to_string())
                    .unique(true)
                    .build(),
            )
            .build(),
        IndexModel::builder()
            .keys(doc! { "user_id": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_password_reset_tokens_user_id".to_string())
                    .build(),
            )
            .build(),
        IndexModel::builder()
            .keys(doc! { "expires_at": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_password_reset_tokens_ttl".to_string())
                    .expire_after(Duration::ZERO)
                    .build(),
            )
            .build(),
    ];
    db.collection::<bson::Document>(PASSWORD_RESET_TOKENS_COLLECTION)
        .create_indexes(reset_indexes)
        .await
        .map_err(AppError::from)?;

    // 5. email_outbox: status + next_retry_at compound index, recipient index
    let outbox_indexes = vec![
        IndexModel::builder()
            .keys(doc! { "status": 1, "next_retry_at": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_outbox_status_next_retry".to_string())
                    .build(),
            )
            .build(),
        IndexModel::builder()
            .keys(doc! { "recipient": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_outbox_recipient".to_string())
                    .build(),
            )
            .build(),
    ];
    db.collection::<bson::Document>(EMAIL_OUTBOX_COLLECTION)
        .create_indexes(outbox_indexes)
        .await
        .map_err(AppError::from)?;

    // 6. oauth_accounts: unique (provider_id, provider_user_id) and unique (user_id, provider_id)
    let oauth_indexes = vec![
        IndexModel::builder()
            .keys(doc! { "provider_id": 1, "provider_user_id": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_oauth_provider_user_unique".to_string())
                    .unique(true)
                    .build(),
            )
            .build(),
        IndexModel::builder()
            .keys(doc! { "user_id": 1, "provider_id": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_oauth_user_provider_unique".to_string())
                    .unique(true)
                    .build(),
            )
            .build(),
        IndexModel::builder()
            .keys(doc! { "user_id": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_oauth_user_id".to_string())
                    .build(),
            )
            .build(),
    ];
    db.collection::<bson::Document>(OAUTH_ACCOUNTS_COLLECTION)
        .create_indexes(oauth_indexes)
        .await
        .map_err(AppError::from)?;

    // 7. totp_secrets: unique user_id
    let totp_secret_indexes = vec![
        IndexModel::builder()
            .keys(doc! { "user_id": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_totp_secrets_user_id_unique".to_string())
                    .unique(true)
                    .build(),
            )
            .build(),
    ];
    db.collection::<bson::Document>(TOTP_SECRETS_COLLECTION)
        .create_indexes(totp_secret_indexes)
        .await
        .map_err(AppError::from)?;

    // 8. totp_used_codes: unique (user_id, code_hash) replay protection
    let totp_used_indexes = vec![
        IndexModel::builder()
            .keys(doc! { "user_id": 1, "code_hash": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_totp_used_codes_user_code_unique".to_string())
                    .unique(true)
                    .build(),
            )
            .build(),
        IndexModel::builder()
            .keys(doc! { "used_at": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_totp_used_codes_used_at".to_string())
                    .expire_after(Duration::from_secs(300))
                    .build(),
            )
            .build(),
    ];
    db.collection::<bson::Document>(TOTP_USED_CODES_COLLECTION)
        .create_indexes(totp_used_indexes)
        .await
        .map_err(AppError::from)?;

    // 9. two_factor_tokens: unique token_hash, user_id index, and TTL index
    let two_factor_indexes = vec![
        IndexModel::builder()
            .keys(doc! { "token_hash": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_two_factor_tokens_token_hash_unique".to_string())
                    .unique(true)
                    .build(),
            )
            .build(),
        IndexModel::builder()
            .keys(doc! { "user_id": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_two_factor_tokens_user_id".to_string())
                    .build(),
            )
            .build(),
        IndexModel::builder()
            .keys(doc! { "expires_at": 1 })
            .options(
                IndexOptions::builder()
                    .name("idx_two_factor_tokens_ttl".to_string())
                    .expire_after(Duration::ZERO)
                    .build(),
            )
            .build(),
    ];
    db.collection::<bson::Document>(TWO_FACTOR_TOKENS_COLLECTION)
        .create_indexes(two_factor_indexes)
        .await
        .map_err(AppError::from)?;

    Ok(())
}
