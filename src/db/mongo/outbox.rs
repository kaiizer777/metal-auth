//! MongoDB implementation of [`OutboxStore`].

use std::time::Duration;

use bson::{DateTime as BsonDateTime, doc};
use chrono::{DateTime, Utc};
use mongodb::{ClientSession, Database, options::FindOptions};
use uuid::Uuid;

use crate::{
    db::{
        models::{
            EmailOutbox, OUTBOX_STATUS_FAILED, OUTBOX_STATUS_PENDING, OUTBOX_STATUS_PROCESSING,
            OUTBOX_STATUS_SENT,
        },
        mongo::{indexes::EMAIL_OUTBOX_COLLECTION, models::EmailOutboxDoc},
    },
    error::AppError,
};

pub async fn insert_outbox(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    recipient: &str,
    email_type: &str,
    payload: serde_json::Value,
) -> Result<EmailOutbox, AppError> {
    let now = Utc::now();
    let id = Uuid::new_v4();

    let doc = EmailOutboxDoc {
        id: bson::Uuid::from(id),
        recipient: recipient.to_string(),
        email_type: email_type.to_string(),
        payload,
        status: OUTBOX_STATUS_PENDING.to_string(),
        retry_count: 0,
        next_retry_at: BsonDateTime::from_chrono(now),
        created_at: BsonDateTime::from_chrono(now),
        sent_at: None,
        error_log: None,
    };

    let coll = db.collection::<EmailOutboxDoc>(EMAIL_OUTBOX_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => coll.insert_one(&doc).session(s).await,
        None => coll.insert_one(&doc).await,
    }
    .map_err(AppError::from)?;

    Ok(EmailOutbox::from(doc))
}

/// Claims pending outbox records using a 2-step atomic batch lease pattern.
pub async fn claim_pending_outbox(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    batch_size: u32,
    lock_duration: Duration,
) -> Result<Vec<EmailOutbox>, AppError> {
    let now = Utc::now();
    let lock_chrono =
        chrono::Duration::from_std(lock_duration).unwrap_or(chrono::Duration::seconds(60));
    let stale_boundary = now - lock_chrono;
    let next_retry = now + lock_chrono;

    let candidate_filter = doc! {
        "$or": [
            {
                "status": OUTBOX_STATUS_PENDING,
                "next_retry_at": { "$lte": BsonDateTime::from_chrono(now) }
            },
            {
                "status": OUTBOX_STATUS_PROCESSING,
                "next_retry_at": { "$lte": BsonDateTime::from_chrono(stale_boundary) }
            }
        ]
    };

    let options = FindOptions::builder()
        .sort(doc! { "next_retry_at": 1, "_id": 1 })
        .limit(batch_size as i64)
        .build();

    let coll = db.collection::<EmailOutboxDoc>(EMAIL_OUTBOX_COLLECTION);
    let mut candidate_ids = Vec::new();

    match session.as_deref_mut() {
        Some(s) => {
            let mut cursor = coll
                .find(candidate_filter.clone())
                .with_options(options)
                .session(&mut *s)
                .await
                .map_err(AppError::from)?;
            while cursor.advance(&mut *s).await.map_err(AppError::from)? {
                let doc = cursor.deserialize_current().map_err(AppError::from)?;
                candidate_ids.push(doc.id);
            }
        }
        None => {
            let mut cursor = coll
                .find(candidate_filter.clone())
                .with_options(options)
                .await
                .map_err(AppError::from)?;
            while cursor.advance().await.map_err(AppError::from)? {
                let doc = cursor.deserialize_current().map_err(AppError::from)?;
                candidate_ids.push(doc.id);
            }
        }
    }

    if candidate_ids.is_empty() {
        return Ok(Vec::new());
    }

    // Atomic update claiming candidates
    let claim_filter = doc! {
        "_id": { "$in": &candidate_ids },
        "$or": [
            { "status": OUTBOX_STATUS_PENDING },
            {
                "status": OUTBOX_STATUS_PROCESSING,
                "next_retry_at": { "$lte": BsonDateTime::from_chrono(stale_boundary) }
            }
        ]
    };

    let claim_update = doc! {
        "$set": {
            "status": OUTBOX_STATUS_PROCESSING,
            "next_retry_at": BsonDateTime::from_chrono(next_retry),
        }
    };

    let update_res = match session.as_deref_mut() {
        Some(s) => {
            coll.update_many(claim_filter, claim_update)
                .session(s)
                .await
        }
        None => coll.update_many(claim_filter, claim_update).await,
    }
    .map_err(AppError::from)?;

    if update_res.modified_count == 0 {
        return Ok(Vec::new());
    }

    // Fetch successfully claimed records
    let claimed_filter = doc! {
        "_id": { "$in": candidate_ids },
        "status": OUTBOX_STATUS_PROCESSING,
    };

    let mut outbox_items = Vec::new();
    match session.as_deref_mut() {
        Some(s) => {
            let mut claimed_cursor = coll
                .find(claimed_filter)
                .session(&mut *s)
                .await
                .map_err(AppError::from)?;
            while claimed_cursor
                .advance(&mut *s)
                .await
                .map_err(AppError::from)?
            {
                let doc = claimed_cursor
                    .deserialize_current()
                    .map_err(AppError::from)?;
                outbox_items.push(EmailOutbox::from(doc));
            }
        }
        None => {
            let mut claimed_cursor = coll.find(claimed_filter).await.map_err(AppError::from)?;
            while claimed_cursor.advance().await.map_err(AppError::from)? {
                let doc = claimed_cursor
                    .deserialize_current()
                    .map_err(AppError::from)?;
                outbox_items.push(EmailOutbox::from(doc));
            }
        }
    }

    Ok(outbox_items)
}

pub async fn mark_outbox_sent(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    id: Uuid,
) -> Result<(), AppError> {
    let filter = doc! { "_id": bson::Uuid::from(id) };
    let update = doc! {
        "$set": {
            "status": OUTBOX_STATUS_SENT,
            "sent_at": BsonDateTime::from_chrono(Utc::now()),
        }
    };
    let coll = db.collection::<EmailOutboxDoc>(EMAIL_OUTBOX_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => coll.update_one(filter, update).session(s).await,
        None => coll.update_one(filter, update).await,
    }
    .map_err(AppError::from)?;

    Ok(())
}

pub async fn record_outbox_retry(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    id: Uuid,
    retry_count: i32,
    next_retry_at: DateTime<Utc>,
    error_log: &str,
) -> Result<(), AppError> {
    let filter = doc! { "_id": bson::Uuid::from(id) };
    let update = doc! {
        "$set": {
            "status": OUTBOX_STATUS_PENDING,
            "retry_count": retry_count,
            "next_retry_at": BsonDateTime::from_chrono(next_retry_at),
            "error_log": error_log,
        }
    };
    let coll = db.collection::<EmailOutboxDoc>(EMAIL_OUTBOX_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => coll.update_one(filter, update).session(s).await,
        None => coll.update_one(filter, update).await,
    }
    .map_err(AppError::from)?;

    Ok(())
}

pub async fn mark_outbox_failed(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    id: Uuid,
    error_log: &str,
) -> Result<(), AppError> {
    let filter = doc! { "_id": bson::Uuid::from(id) };
    let update = doc! {
        "$set": {
            "status": OUTBOX_STATUS_FAILED,
            "error_log": error_log,
        }
    };
    let coll = db.collection::<EmailOutboxDoc>(EMAIL_OUTBOX_COLLECTION);
    match session.as_deref_mut() {
        Some(s) => coll.update_one(filter, update).session(s).await,
        None => coll.update_one(filter, update).await,
    }
    .map_err(AppError::from)?;

    Ok(())
}

pub async fn cleanup_sent_outbox(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    retention_duration: Duration,
) -> Result<u64, AppError> {
    let retention_chrono =
        chrono::Duration::from_std(retention_duration).unwrap_or(chrono::Duration::days(7));
    let cutoff = Utc::now() - retention_chrono;

    let filter = doc! {
        "status": OUTBOX_STATUS_SENT,
        "sent_at": { "$lte": BsonDateTime::from_chrono(cutoff) }
    };
    let coll = db.collection::<EmailOutboxDoc>(EMAIL_OUTBOX_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.delete_many(filter).session(s).await,
        None => coll.delete_many(filter).await,
    }
    .map_err(AppError::from)?;

    Ok(res.deleted_count)
}

pub async fn recover_stale_processing(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    stale_duration: Duration,
) -> Result<u64, AppError> {
    let stale_chrono =
        chrono::Duration::from_std(stale_duration).unwrap_or(chrono::Duration::minutes(5));
    let cutoff = Utc::now() - stale_chrono;

    let filter = doc! {
        "status": OUTBOX_STATUS_PROCESSING,
        "next_retry_at": { "$lte": BsonDateTime::from_chrono(cutoff) }
    };
    let update = doc! {
        "$set": {
            "status": OUTBOX_STATUS_PENDING,
        }
    };
    let coll = db.collection::<EmailOutboxDoc>(EMAIL_OUTBOX_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.update_many(filter, update).session(s).await,
        None => coll.update_many(filter, update).await,
    }
    .map_err(AppError::from)?;

    Ok(res.modified_count)
}
