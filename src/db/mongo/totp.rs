//! MongoDB implementation of [`TotpStore`].

use std::time::Duration;

use bson::{Binary, DateTime as BsonDateTime, doc};
use chrono::Utc;
use mongodb::{ClientSession, Database};
use uuid::Uuid;

use crate::{
    db::{
        models::{TotpSecret, TwoFactorToken},
        mongo::{
            indexes::{
                TOTP_SECRETS_COLLECTION, TOTP_USED_CODES_COLLECTION, TWO_FACTOR_TOKENS_COLLECTION,
                USERS_COLLECTION,
            },
            is_duplicate_key_error,
            models::{TotpSecretDoc, TotpUsedCodeDoc, TwoFactorTokenDoc, UserDoc},
        },
    },
    error::AppError,
};

pub async fn get_secret(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
) -> Result<Option<TotpSecret>, AppError> {
    let filter = doc! { "user_id": bson::Uuid::from(user_id) };
    let coll = db.collection::<TotpSecretDoc>(TOTP_SECRETS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.find_one(filter).session(s).await,
        None => coll.find_one(filter).await,
    };

    let doc = res.map_err(AppError::from)?;
    Ok(doc.map(TotpSecret::from))
}

pub async fn upsert_secret(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
    encrypted_secret: &[u8],
    backup_codes: serde_json::Value,
) -> Result<TotpSecret, AppError> {
    // 1. Verify user exists
    let user_coll = db.collection::<UserDoc>(USERS_COLLECTION);
    let user_filter = doc! { "_id": bson::Uuid::from(user_id) };
    let user_exists = match session.as_deref_mut() {
        Some(s) => user_coll.find_one(user_filter).session(s).await,
        None => user_coll.find_one(user_filter).await,
    }
    .map_err(AppError::from)?;

    if user_exists.is_none() {
        return Err(AppError::NotFound);
    }

    // 2. Insert or fenced update secret
    let totp_coll = db.collection::<TotpSecretDoc>(TOTP_SECRETS_COLLECTION);
    let now = Utc::now();

    for _ in 0..2 {
        let secret_filter = doc! { "user_id": bson::Uuid::from(user_id) };
        let existing = match session.as_deref_mut() {
            Some(s) => totp_coll.find_one(secret_filter).session(s).await,
            None => totp_coll.find_one(secret_filter).await,
        }
        .map_err(AppError::from)?;

        match existing {
            Some(secret) => {
                if secret.enabled {
                    return Err(AppError::TotpAlreadyEnabled);
                }
                let update_filter = doc! {
                    "user_id": bson::Uuid::from(user_id),
                    "enabled": false,
                };
                let update = doc! {
                    "$set": {
                        "encrypted_secret": Binary {
                            subtype: bson::spec::BinarySubtype::Generic,
                            bytes: encrypted_secret.to_vec(),
                        },
                        "backup_codes": bson::to_bson(&backup_codes).map_err(|e| AppError::Database(crate::error::DbError::from(e)))?,
                        "updated_at": BsonDateTime::from_chrono(now),
                    }
                };
                let res = match session.as_deref_mut() {
                    Some(s) => totp_coll.update_one(update_filter, update).session(s).await,
                    None => totp_coll.update_one(update_filter, update).await,
                }
                .map_err(AppError::from)?;

                if res.matched_count == 0 {
                    return Err(AppError::TotpAlreadyEnabled);
                }

                return Ok(TotpSecret {
                    id: secret.id.into(),
                    user_id,
                    encrypted_secret: encrypted_secret.to_vec(),
                    backup_codes,
                    enabled: false,
                    created_at: secret.created_at.to_chrono(),
                    updated_at: now,
                });
            }
            None => {
                let id = Uuid::new_v4();
                let doc = TotpSecretDoc {
                    id: bson::Uuid::from(id),
                    user_id: bson::Uuid::from(user_id),
                    encrypted_secret: Binary {
                        subtype: bson::spec::BinarySubtype::Generic,
                        bytes: encrypted_secret.to_vec(),
                    },
                    backup_codes: backup_codes.clone(),
                    enabled: false,
                    created_at: BsonDateTime::from_chrono(now),
                    updated_at: BsonDateTime::from_chrono(now),
                };
                let res = match session.as_deref_mut() {
                    Some(s) => totp_coll.insert_one(&doc).session(s).await,
                    None => totp_coll.insert_one(&doc).await,
                };

                match res {
                    Ok(_) => return Ok(TotpSecret::from(doc)),
                    Err(e) if is_duplicate_key_error(&e) => {
                        // Concurrent insert collision; retry via find_one and fenced update.
                        continue;
                    }
                    Err(e) => return Err(AppError::from(e)),
                }
            }
        }
    }

    Err(AppError::TotpAlreadyEnabled)
}

pub async fn enable_totp(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
) -> Result<bool, AppError> {
    let filter = doc! {
        "user_id": bson::Uuid::from(user_id),
        "enabled": false,
    };
    let update = doc! {
        "$set": {
            "enabled": true,
            "updated_at": BsonDateTime::from_chrono(Utc::now()),
        }
    };
    let coll = db.collection::<TotpSecretDoc>(TOTP_SECRETS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.update_one(filter, update).session(s).await,
        None => coll.update_one(filter, update).await,
    }
    .map_err(AppError::from)?;

    Ok(res.modified_count > 0)
}

pub async fn disable_totp(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
) -> Result<bool, AppError> {
    let user_uuid = bson::Uuid::from(user_id);
    let filter = doc! { "user_id": user_uuid };

    let coll = db.collection::<TotpSecretDoc>(TOTP_SECRETS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.delete_one(filter.clone()).session(s).await,
        None => coll.delete_one(filter.clone()).await,
    }
    .map_err(AppError::from)?;

    // Also purge used codes for this user
    let used_coll = db.collection::<TotpUsedCodeDoc>(TOTP_USED_CODES_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => used_coll.delete_many(filter).session(s).await,
        None => used_coll.delete_many(filter).await,
    }
    .map_err(AppError::from)?;

    Ok(res.deleted_count > 0)
}

pub async fn record_used_code(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
    code_hash: &[u8],
) -> Result<bool, AppError> {
    let doc = TotpUsedCodeDoc {
        id: bson::Uuid::new(),
        user_id: bson::Uuid::from(user_id),
        code_hash: Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: code_hash.to_vec(),
        },
        used_at: BsonDateTime::from_chrono(Utc::now()),
    };

    let coll = db.collection::<TotpUsedCodeDoc>(TOTP_USED_CODES_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.insert_one(&doc).session(s).await,
        None => coll.insert_one(&doc).await,
    };

    match res {
        Ok(_) => Ok(true),
        Err(e) if is_duplicate_key_error(&e) => Err(AppError::TotpCodeReplayed),
        Err(e) => Err(AppError::from(e)),
    }
}

pub async fn is_code_used(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
    code_hash: &[u8],
) -> Result<bool, AppError> {
    let filter = doc! {
        "user_id": bson::Uuid::from(user_id),
        "code_hash": Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: code_hash.to_vec(),
        },
    };
    let coll = db.collection::<TotpUsedCodeDoc>(TOTP_USED_CODES_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.find_one(filter).session(s).await,
        None => coll.find_one(filter).await,
    };

    let doc = res.map_err(AppError::from)?;
    Ok(doc.is_some())
}

pub async fn create_two_factor_token(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
    token_hash: &[u8],
    credential_hash: &str,
    expires_at: chrono::DateTime<Utc>,
) -> Result<TwoFactorToken, AppError> {
    let id = Uuid::new_v4();
    let doc = TwoFactorTokenDoc {
        id: bson::Uuid::from(id),
        user_id: bson::Uuid::from(user_id),
        token_hash: Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: token_hash.to_vec(),
        },
        credential_hash: Some(credential_hash.to_string()),
        expires_at: BsonDateTime::from_chrono(expires_at),
    };

    let coll = db.collection::<TwoFactorTokenDoc>(TWO_FACTOR_TOKENS_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => coll.insert_one(&doc).session(s).await,
        None => coll.insert_one(&doc).await,
    }
    .map_err(AppError::from)?;

    Ok(TwoFactorToken::from(doc))
}

pub async fn consume_two_factor_token(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    token_hash: &[u8],
) -> Result<Option<TwoFactorToken>, AppError> {
    let bin = Binary {
        subtype: bson::spec::BinarySubtype::Generic,
        bytes: token_hash.to_vec(),
    };
    let filter = doc! { "token_hash": bin };
    let coll = db.collection::<TwoFactorTokenDoc>(TWO_FACTOR_TOKENS_COLLECTION);

    let doc = match session.as_deref_mut() {
        Some(s) => coll.find_one_and_delete(filter).session(s).await,
        None => coll.find_one_and_delete(filter).await,
    }
    .map_err(AppError::from)?;

    Ok(doc.map(TwoFactorToken::from))
}

pub async fn delete_two_factor_tokens_for_user(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
) -> Result<u64, AppError> {
    let filter = doc! { "user_id": bson::Uuid::from(user_id) };
    let coll = db.collection::<TwoFactorTokenDoc>(TWO_FACTOR_TOKENS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.delete_many(filter).session(s).await,
        None => coll.delete_many(filter).await,
    }
    .map_err(AppError::from)?;

    Ok(res.deleted_count)
}

pub async fn prune_expired_two_factor_tokens(
    db: &Database,
    mut session: Option<&mut ClientSession>,
) -> Result<u64, AppError> {
    let filter = doc! {
        "expires_at": { "$lte": BsonDateTime::from_chrono(Utc::now()) }
    };
    let coll = db.collection::<TwoFactorTokenDoc>(TWO_FACTOR_TOKENS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.delete_many(filter).session(s).await,
        None => coll.delete_many(filter).await,
    }
    .map_err(AppError::from)?;

    Ok(res.deleted_count)
}

pub async fn prune_used_codes(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    max_age: Duration,
) -> Result<u64, AppError> {
    let max_age_chrono = chrono::Duration::from_std(max_age).unwrap_or(chrono::Duration::days(1));
    let cutoff = Utc::now() - max_age_chrono;

    let filter = doc! {
        "used_at": { "$lte": BsonDateTime::from_chrono(cutoff) }
    };
    let coll = db.collection::<TotpUsedCodeDoc>(TOTP_USED_CODES_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.delete_many(filter).session(s).await,
        None => coll.delete_many(filter).await,
    }
    .map_err(AppError::from)?;

    Ok(res.deleted_count)
}
