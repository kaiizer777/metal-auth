//! MongoDB implementation of [`SessionStore`].

use bson::{DateTime as BsonDateTime, doc};
use chrono::{DateTime, Utc};
use mongodb::{ClientSession, Database};
use uuid::Uuid;

use crate::{
    db::{
        models::Session,
        mongo::{indexes::SESSIONS_COLLECTION, models::SessionDoc},
    },
    error::AppError,
};

pub async fn create_session(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
    token_hash: &str,
    session_type: &str,
    csrf_token: Option<&str>,
    absolute_expires_at: DateTime<Utc>,
) -> Result<Session, AppError> {
    let now = Utc::now();
    let id = Uuid::new_v4();

    let doc = SessionDoc {
        id: bson::Uuid::from(id),
        user_id: bson::Uuid::from(user_id),
        token_hash: token_hash.to_string(),
        created_at: BsonDateTime::from_chrono(now),
        last_active_at: BsonDateTime::from_chrono(now),
        absolute_expires_at: BsonDateTime::from_chrono(absolute_expires_at),
        session_type: session_type.to_string(),
        csrf_token: csrf_token.map(ToString::to_string),
    };

    let coll = db.collection::<SessionDoc>(SESSIONS_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => coll.insert_one(&doc).session(s).await,
        None => coll.insert_one(&doc).await,
    }
    .map_err(AppError::from)?;

    Ok(Session::from(doc))
}

pub async fn get_session_by_token_hash(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    token_hash: &str,
) -> Result<Option<Session>, AppError> {
    let filter = doc! { "token_hash": token_hash };
    let coll = db.collection::<SessionDoc>(SESSIONS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.find_one(filter).session(s).await,
        None => coll.find_one(filter).await,
    };

    let doc = res.map_err(AppError::from)?;
    Ok(doc.map(Session::from))
}

pub async fn touch_session(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    session_id: Uuid,
    last_active_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let filter = doc! { "_id": bson::Uuid::from(session_id) };
    let update = doc! {
        "$set": {
            "last_active_at": BsonDateTime::from_chrono(last_active_at),
        }
    };
    let coll = db.collection::<SessionDoc>(SESSIONS_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => coll.update_one(filter, update).session(s).await,
        None => coll.update_one(filter, update).await,
    }
    .map_err(AppError::from)?;

    Ok(())
}

pub async fn rotate_session(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    session_id: Uuid,
    new_token_hash: &str,
    new_csrf_token: Option<&str>,
    last_active_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let filter = doc! { "_id": bson::Uuid::from(session_id) };
    let mut set_doc = doc! {
        "token_hash": new_token_hash,
        "last_active_at": BsonDateTime::from_chrono(last_active_at),
    };
    if let Some(csrf) = new_csrf_token {
        set_doc.insert("csrf_token", csrf);
    } else {
        set_doc.insert("csrf_token", bson::Bson::Null);
    }

    let update = doc! { "$set": set_doc };
    let coll = db.collection::<SessionDoc>(SESSIONS_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => coll.update_one(filter, update).session(s).await,
        None => coll.update_one(filter, update).await,
    }
    .map_err(AppError::from)?;

    Ok(())
}

pub async fn delete_session(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    session_id: Uuid,
) -> Result<(), AppError> {
    let filter = doc! { "_id": bson::Uuid::from(session_id) };
    let coll = db.collection::<SessionDoc>(SESSIONS_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => coll.delete_one(filter).session(s).await,
        None => coll.delete_one(filter).await,
    }
    .map_err(AppError::from)?;

    Ok(())
}

pub async fn delete_by_token_hash(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    token_hash: &str,
) -> Result<bool, AppError> {
    let filter = doc! { "token_hash": token_hash };
    let coll = db.collection::<SessionDoc>(SESSIONS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.delete_one(filter).session(s).await,
        None => coll.delete_one(filter).await,
    }
    .map_err(AppError::from)?;

    Ok(res.deleted_count > 0)
}

pub async fn delete_user_sessions(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
) -> Result<u64, AppError> {
    let filter = doc! { "user_id": bson::Uuid::from(user_id) };
    let coll = db.collection::<SessionDoc>(SESSIONS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.delete_many(filter).session(s).await,
        None => coll.delete_many(filter).await,
    }
    .map_err(AppError::from)?;

    Ok(res.deleted_count)
}

pub async fn list_user_sessions(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    user_id: Uuid,
) -> Result<Vec<Session>, AppError> {
    use mongodb::options::FindOptions;
    let filter = doc! { "user_id": bson::Uuid::from(user_id) };
    let options = FindOptions::builder()
        .sort(doc! { "last_active_at": -1 })
        .build();

    let coll = db.collection::<SessionDoc>(SESSIONS_COLLECTION);
    let mut sessions = Vec::new();
    let now = Utc::now();

    match session.as_deref_mut() {
        Some(s) => {
            let mut cursor = coll
                .find(filter)
                .with_options(options)
                .session(&mut *s)
                .await
                .map_err(AppError::from)?;
            while cursor.advance(&mut *s).await.map_err(AppError::from)? {
                let doc = cursor.deserialize_current().map_err(AppError::from)?;
                let s = Session::from(doc);
                if s.absolute_expires_at > now {
                    sessions.push(s);
                }
            }
        }
        None => {
            let mut cursor = coll
                .find(filter)
                .with_options(options)
                .await
                .map_err(AppError::from)?;
            while cursor.advance().await.map_err(AppError::from)? {
                let doc = cursor.deserialize_current().map_err(AppError::from)?;
                let s = Session::from(doc);
                if s.absolute_expires_at > now {
                    sessions.push(s);
                }
            }
        }
    }

    Ok(sessions)
}

pub async fn delete_expired_sessions(
    db: &Database,
    mut session: Option<&mut ClientSession>,
) -> Result<u64, AppError> {
    let filter = doc! {
        "absolute_expires_at": { "$lte": BsonDateTime::from_chrono(Utc::now()) }
    };
    let coll = db.collection::<SessionDoc>(SESSIONS_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.delete_many(filter).session(s).await,
        None => coll.delete_many(filter).await,
    }
    .map_err(AppError::from)?;

    Ok(res.deleted_count)
}
