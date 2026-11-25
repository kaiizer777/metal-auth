//! MongoDB implementation of [`UserStore`] and [`TokenStore`].

use bson::{Binary, DateTime as BsonDateTime, doc};
use chrono::{DateTime, Utc};
use mongodb::{ClientSession, Database};
use uuid::Uuid;

use crate::{
    db::{
        models::{PasswordResetToken, User, VerificationToken},
        mongo::{
            indexes::{
                OAUTH_ACCOUNTS_COLLECTION, PASSWORD_RESET_TOKENS_COLLECTION, SESSIONS_COLLECTION,
                TOTP_SECRETS_COLLECTION, TOTP_USED_CODES_COLLECTION, TWO_FACTOR_TOKENS_COLLECTION,
                USERS_COLLECTION, VERIFICATION_TOKENS_COLLECTION,
            },
            is_duplicate_key_error,
            models::{PasswordResetTokenDoc, UserDoc, VerificationTokenDoc},
        },
    },
    error::AppError,
};

// ─── UserStore operations ───────────────────────────────────────────────────

pub async fn create_user(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    email: &str,
    password_hash: &str,
) -> Result<User, AppError> {
    let now = Utc::now();
    let id = Uuid::new_v4();
    let normalized_email = email.to_lowercase();

    let doc = UserDoc {
        id: bson::Uuid::from(id),
        email: normalized_email,
        password_hash: password_hash.to_string(),
        email_verified: false,
        created_at: BsonDateTime::from_chrono(now),
        updated_at: BsonDateTime::from_chrono(now),
    };

    let coll = db.collection::<UserDoc>(USERS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.insert_one(&doc).session(s).await,
        None => coll.insert_one(&doc).await,
    };

    match res {
        Ok(_) => Ok(User::from(doc)),
        Err(e) if is_duplicate_key_error(&e) => Err(AppError::EmailAlreadyExists),
        Err(e) => Err(AppError::from(e)),
    }
}

pub async fn get_user_by_id(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    id: Uuid,
) -> Result<Option<User>, AppError> {
    let filter = doc! { "_id": bson::Uuid::from(id) };
    let coll = db.collection::<UserDoc>(USERS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.find_one(filter).session(s).await,
        None => coll.find_one(filter).await,
    };

    let doc = res.map_err(AppError::from)?;
    Ok(doc.map(User::from))
}

pub async fn get_user_by_email(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    email: &str,
) -> Result<Option<User>, AppError> {
    let normalized = email.to_lowercase();
    let filter = doc! { "email": normalized };
    let coll = db.collection::<UserDoc>(USERS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.find_one(filter).session(s).await,
        None => coll.find_one(filter).await,
    };

    let doc = res.map_err(AppError::from)?;
    Ok(doc.map(User::from))
}

pub async fn set_email_verified(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
    verified: bool,
) -> Result<(), AppError> {
    let filter = doc! { "_id": bson::Uuid::from(user_id) };
    let update = doc! {
        "$set": {
            "email_verified": verified,
            "updated_at": BsonDateTime::from_chrono(Utc::now()),
        }
    };
    let coll = db.collection::<UserDoc>(USERS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.update_one(filter, update).session(s).await,
        None => coll.update_one(filter, update).await,
    };

    res.map_err(AppError::from)?;
    Ok(())
}

pub async fn update_password_hash(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
    new_hash: &str,
) -> Result<(), AppError> {
    let filter = doc! { "_id": bson::Uuid::from(user_id) };
    let update = doc! {
        "$set": {
            "password_hash": new_hash,
            "updated_at": BsonDateTime::from_chrono(Utc::now()),
        }
    };
    let coll = db.collection::<UserDoc>(USERS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.update_one(filter, update).session(s).await,
        None => coll.update_one(filter, update).await,
    };

    res.map_err(AppError::from)?;
    Ok(())
}

/// Cascades deletion across all 7 child collections before removing the user record.
pub async fn delete_user(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
) -> Result<bool, AppError> {
    let user_uuid = bson::Uuid::from(user_id);
    let user_filter = doc! { "user_id": user_uuid };

    // 1. sessions
    let sessions_coll = db.collection::<bson::Document>(SESSIONS_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => {
            sessions_coll
                .delete_many(user_filter.clone())
                .session(s)
                .await
        }
        None => sessions_coll.delete_many(user_filter.clone()).await,
    }
    .map_err(AppError::from)?;

    // 2. verification_tokens
    let verif_coll = db.collection::<bson::Document>(VERIFICATION_TOKENS_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => verif_coll.delete_many(user_filter.clone()).session(s).await,
        None => verif_coll.delete_many(user_filter.clone()).await,
    }
    .map_err(AppError::from)?;

    // 3. password_reset_tokens
    let reset_coll = db.collection::<bson::Document>(PASSWORD_RESET_TOKENS_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => reset_coll.delete_many(user_filter.clone()).session(s).await,
        None => reset_coll.delete_many(user_filter.clone()).await,
    }
    .map_err(AppError::from)?;

    // 4. oauth_accounts
    let oauth_coll = db.collection::<bson::Document>(OAUTH_ACCOUNTS_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => oauth_coll.delete_many(user_filter.clone()).session(s).await,
        None => oauth_coll.delete_many(user_filter.clone()).await,
    }
    .map_err(AppError::from)?;

    // 5. totp_secrets
    let totp_sec_coll = db.collection::<bson::Document>(TOTP_SECRETS_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => {
            totp_sec_coll
                .delete_many(user_filter.clone())
                .session(s)
                .await
        }
        None => totp_sec_coll.delete_many(user_filter.clone()).await,
    }
    .map_err(AppError::from)?;

    // 6. totp_used_codes
    let totp_code_coll = db.collection::<bson::Document>(TOTP_USED_CODES_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => {
            totp_code_coll
                .delete_many(user_filter.clone())
                .session(s)
                .await
        }
        None => totp_code_coll.delete_many(user_filter.clone()).await,
    }
    .map_err(AppError::from)?;

    // 7. two_factor_tokens
    let two_factor_coll = db.collection::<bson::Document>(TWO_FACTOR_TOKENS_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => two_factor_coll.delete_many(user_filter).session(s).await,
        None => two_factor_coll.delete_many(user_filter).await,
    }
    .map_err(AppError::from)?;

    // 8. delete user
    let user_coll = db.collection::<UserDoc>(USERS_COLLECTION);
    let user_id_filter = doc! { "_id": user_uuid };
    let del_res = match session.as_deref_mut() {
        Some(s) => user_coll.delete_one(user_id_filter).session(s).await,
        None => user_coll.delete_one(user_id_filter).await,
    }
    .map_err(AppError::from)?;

    Ok(del_res.deleted_count > 0)
}

// ─── TokenStore operations ──────────────────────────────────────────────────

pub async fn create_verification_token(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
    token_hash: &[u8],
    expires_at: DateTime<Utc>,
) -> Result<VerificationToken, AppError> {
    let now = Utc::now();
    let doc = VerificationTokenDoc {
        id: bson::Uuid::new(),
        token_hash: Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: token_hash.to_vec(),
        },
        user_id: bson::Uuid::from(user_id),
        expires_at: BsonDateTime::from_chrono(expires_at),
        created_at: BsonDateTime::from_chrono(now),
    };

    let coll = db.collection::<VerificationTokenDoc>(VERIFICATION_TOKENS_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => coll.insert_one(&doc).session(s).await,
        None => coll.insert_one(&doc).await,
    }
    .map_err(AppError::from)?;

    Ok(VerificationToken::from(doc))
}

pub async fn consume_verification_token(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    token_hash: &[u8],
) -> Result<Option<VerificationToken>, AppError> {
    let bin = Binary {
        subtype: bson::spec::BinarySubtype::Generic,
        bytes: token_hash.to_vec(),
    };
    let filter = doc! { "token_hash": bin };
    let coll = db.collection::<VerificationTokenDoc>(VERIFICATION_TOKENS_COLLECTION);

    let doc = match session.as_deref_mut() {
        Some(s) => coll.find_one_and_delete(filter).session(s).await,
        None => coll.find_one_and_delete(filter).await,
    }
    .map_err(AppError::from)?;

    match doc {
        Some(doc) => {
            let token = VerificationToken::from(doc);
            if token.expires_at <= Utc::now() {
                Err(AppError::TokenExpired)
            } else {
                Ok(Some(token))
            }
        }
        None => Ok(None),
    }
}

pub async fn create_password_reset_token(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
    token_hash: &[u8],
    expires_at: DateTime<Utc>,
) -> Result<PasswordResetToken, AppError> {
    let now = Utc::now();
    let doc = PasswordResetTokenDoc {
        id: bson::Uuid::new(),
        token_hash: Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: token_hash.to_vec(),
        },
        user_id: bson::Uuid::from(user_id),
        expires_at: BsonDateTime::from_chrono(expires_at),
        created_at: BsonDateTime::from_chrono(now),
    };

    let coll = db.collection::<PasswordResetTokenDoc>(PASSWORD_RESET_TOKENS_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => coll.insert_one(&doc).session(s).await,
        None => coll.insert_one(&doc).await,
    }
    .map_err(AppError::from)?;

    Ok(PasswordResetToken::from(doc))
}

pub async fn consume_password_reset_token(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    token_hash: &[u8],
) -> Result<Option<PasswordResetToken>, AppError> {
    let bin = Binary {
        subtype: bson::spec::BinarySubtype::Generic,
        bytes: token_hash.to_vec(),
    };
    let filter = doc! { "token_hash": bin };
    let coll = db.collection::<PasswordResetTokenDoc>(PASSWORD_RESET_TOKENS_COLLECTION);

    let doc = match session.as_deref_mut() {
        Some(s) => coll.find_one_and_delete(filter).session(s).await,
        None => coll.find_one_and_delete(filter).await,
    }
    .map_err(AppError::from)?;

    match doc {
        Some(doc) => {
            let token = PasswordResetToken::from(doc);
            if token.expires_at <= Utc::now() {
                Err(AppError::TokenExpired)
            } else {
                Ok(Some(token))
            }
        }
        None => Ok(None),
    }
}

pub async fn delete_user_password_reset_tokens(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
) -> Result<u64, AppError> {
    let filter = doc! { "user_id": bson::Uuid::from(user_id) };
    let coll = db.collection::<bson::Document>(PASSWORD_RESET_TOKENS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.delete_many(filter).session(s).await,
        None => coll.delete_many(filter).await,
    }
    .map_err(AppError::from)?;

    Ok(res.deleted_count)
}

pub async fn delete_verification_tokens_for_user(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
) -> Result<u64, AppError> {
    let filter = doc! { "user_id": bson::Uuid::from(user_id) };
    let coll = db.collection::<bson::Document>(VERIFICATION_TOKENS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.delete_many(filter).session(s).await,
        None => coll.delete_many(filter).await,
    }
    .map_err(AppError::from)?;

    Ok(res.deleted_count)
}
