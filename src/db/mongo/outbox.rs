//! MongoDB implementation of [`OutboxStore`].

use std::time::Duration;

use bson::{DateTime as BsonDateTime, doc};
use chrono::{DateTime, Utc};
use mongodb::{
    ClientSession, Database,
    options::{FindOneAndUpdateOptions, ReturnDocument},
};
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

/// Atomically claims up to `batch_size` pending or expired outbox records.
pub async fn claim_pending_outbox(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    batch_size: u32,
    lock_duration: Duration,
) -> Result<Vec<EmailOutbox>, AppError> {
    if batch_size == 0 {
        return Ok(Vec::new());
    }

    let lock_chrono =
        chrono::Duration::from_std(lock_duration).unwrap_or(chrono::Duration::seconds(60));

    let coll = db.collection::<EmailOutboxDoc>(EMAIL_OUTBOX_COLLECTION);
    let options = FindOneAndUpdateOptions::builder()
        .sort(doc! { "next_retry_at": 1, "_id": 1 })
        .return_document(ReturnDocument::After)
        .build();

    let mut claimed_ids = Vec::with_capacity(batch_size as usize);
    let mut claimed_items = Vec::with_capacity(batch_size as usize);

    for _ in 0..batch_size {
        let now = Utc::now();
        let next_retry = now + lock_chrono;

        let mut claim_filter = doc! {
            "$or": [
                {
                    "status": OUTBOX_STATUS_PENDING,
                    "next_retry_at": { "$lte": BsonDateTime::from_chrono(now) },
                },
                {
                    "status": OUTBOX_STATUS_PROCESSING,
                    "next_retry_at": { "$lte": BsonDateTime::from_chrono(now) },
                },
            ],
        };

        if !claimed_ids.is_empty() {
            claim_filter.insert("_id", doc! { "$nin": &claimed_ids });
        }

        let claim_update = doc! {
            "$set": {
                "status": OUTBOX_STATUS_PROCESSING,
                "next_retry_at": BsonDateTime::from_chrono(next_retry),
            },
        };

        let result = match session.as_deref_mut() {
            Some(s) => {
                coll.find_one_and_update(claim_filter, claim_update)
                    .with_options(options.clone())
                    .session(&mut *s)
                    .await
            }
            None => {
                coll.find_one_and_update(claim_filter, claim_update)
                    .with_options(options.clone())
                    .await
            }
        }
        .map_err(AppError::from)?;

        match result {
            Some(doc) => {
                claimed_ids.push(doc.id);
                claimed_items.push(EmailOutbox::from(doc));
            }
            None => break,
        }
    }

    Ok(claimed_items)
}

pub async fn mark_outbox_sent(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    id: Uuid,
) -> Result<(), AppError> {
    let filter = doc! {
        "_id": bson::Uuid::from(id),
        "status": OUTBOX_STATUS_PROCESSING,
    };
    let update = doc! {
        "$set": {
            "status": OUTBOX_STATUS_SENT,
            "sent_at": BsonDateTime::from_chrono(Utc::now()),
            "error_log": bson::Bson::Null,
        }
    };
    let coll = db.collection::<EmailOutboxDoc>(EMAIL_OUTBOX_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.update_one(filter, update).session(s).await,
        None => coll.update_one(filter, update).await,
    }
    .map_err(AppError::from)?;

    if res.matched_count == 0 {
        tracing::warn!(outbox_id = %id, "mark_outbox_sent: lease expired or row missing");
    }

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
    let filter = doc! {
        "_id": bson::Uuid::from(id),
        "status": OUTBOX_STATUS_PROCESSING,
    };
    let update = doc! {
        "$set": {
            "status": OUTBOX_STATUS_PENDING,
            "retry_count": retry_count,
            "next_retry_at": BsonDateTime::from_chrono(next_retry_at),
            "error_log": error_log,
        }
    };
    let coll = db.collection::<EmailOutboxDoc>(EMAIL_OUTBOX_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.update_one(filter, update).session(s).await,
        None => coll.update_one(filter, update).await,
    }
    .map_err(AppError::from)?;

    if res.matched_count == 0 {
        tracing::warn!(outbox_id = %id, "record_outbox_retry: lease expired or row missing");
    }

    Ok(())
}

pub async fn mark_outbox_failed(
    db: &Database,
    mut session: Option<&mut ClientSession>,
    id: Uuid,
    error_log: &str,
) -> Result<(), AppError> {
    let filter = doc! {
        "_id": bson::Uuid::from(id),
        "status": OUTBOX_STATUS_PROCESSING,
    };
    let update = doc! {
        "$set": {
            "status": OUTBOX_STATUS_FAILED,
            "error_log": error_log,
        }
    };
    let coll = db.collection::<EmailOutboxDoc>(EMAIL_OUTBOX_COLLECTION);
    let res = match session.as_deref_mut() {
        Some(s) => coll.update_one(filter, update).session(s).await,
        None => coll.update_one(filter, update).await,
    }
    .map_err(AppError::from)?;

    if res.matched_count == 0 {
        tracing::warn!(outbox_id = %id, "mark_outbox_failed: lease expired or row missing");
    }

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
    _stale_duration: Duration,
) -> Result<u64, AppError> {
    let now = Utc::now();

    let filter = doc! {
        "status": OUTBOX_STATUS_PROCESSING,
        "next_retry_at": { "$lte": BsonDateTime::from_chrono(now) }
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
