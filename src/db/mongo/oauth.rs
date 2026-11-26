//! MongoDB implementation of [`OAuthStore`].

use bson::{DateTime as BsonDateTime, doc};
use chrono::Utc;
use mongodb::{ClientSession, Database};
use uuid::Uuid;

use crate::{
    db::{
        models::OAuthAccount,
        mongo::{
            indexes::OAUTH_ACCOUNTS_COLLECTION, is_duplicate_key_error, models::OAuthAccountDoc,
        },
    },
    error::AppError,
};

pub async fn get_account(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    provider_id: &str,
    provider_user_id: &str,
) -> Result<Option<OAuthAccount>, AppError> {
    let filter = doc! {
        "provider_id": provider_id,
        "provider_user_id": provider_user_id,
    };
    let coll = db.collection::<OAuthAccountDoc>(OAUTH_ACCOUNTS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.find_one(filter).session(s).await,
        None => coll.find_one(filter).await,
    };

    let doc = res.map_err(AppError::from)?;
    Ok(doc.map(OAuthAccount::from))
}

pub async fn list_accounts_for_user(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
) -> Result<Vec<OAuthAccount>, AppError> {
    let filter = doc! { "user_id": bson::Uuid::from(user_id) };
    let coll = db.collection::<OAuthAccountDoc>(OAUTH_ACCOUNTS_COLLECTION);
    let mut accounts = Vec::new();
    match session.as_deref_mut() {
        Some(s) => {
            let mut cursor = coll
                .find(filter)
                .session(&mut *s)
                .await
                .map_err(AppError::from)?;
            while cursor.advance(&mut *s).await.map_err(AppError::from)? {
                let doc = cursor.deserialize_current().map_err(AppError::from)?;
                accounts.push(OAuthAccount::from(doc));
            }
        }
        None => {
            let mut cursor = coll.find(filter).await.map_err(AppError::from)?;
            while cursor.advance().await.map_err(AppError::from)? {
                let doc = cursor.deserialize_current().map_err(AppError::from)?;
                accounts.push(OAuthAccount::from(doc));
            }
        }
    }

    Ok(accounts)
}

pub async fn link_account(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
    provider_id: &str,
    provider_user_id: &str,
    email: &str,
) -> Result<OAuthAccount, AppError> {
    let now = Utc::now();
    let id = Uuid::new_v4();

    let doc = OAuthAccountDoc {
        id: bson::Uuid::from(id),
        user_id: bson::Uuid::from(user_id),
        provider_id: provider_id.to_string(),
        provider_user_id: provider_user_id.to_string(),
        email: email.to_string(),
        created_at: BsonDateTime::from_chrono(now),
        updated_at: BsonDateTime::from_chrono(now),
    };

    let coll = db.collection::<OAuthAccountDoc>(OAUTH_ACCOUNTS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.insert_one(&doc).session(s).await,
        None => coll.insert_one(&doc).await,
    };

    match res {
        Ok(_) => Ok(OAuthAccount::from(doc)),
        Err(e) if is_duplicate_key_error(&e) => Err(AppError::OAuthAccountLinkConflict),
        Err(e) => Err(AppError::from(e)),
    }
}

pub async fn unlink_account(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
    provider_id: &str,
) -> Result<bool, AppError> {
    let filter = doc! {
        "user_id": bson::Uuid::from(user_id),
        "provider_id": provider_id,
    };
    let coll = db.collection::<OAuthAccountDoc>(OAUTH_ACCOUNTS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.delete_one(filter).session(s).await,
        None => coll.delete_one(filter).await,
    }
    .map_err(AppError::from)?;

    Ok(res.deleted_count > 0)
}
