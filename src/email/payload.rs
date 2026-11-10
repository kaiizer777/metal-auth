use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationEmailPayload {
    pub user_id: Uuid,
    pub to: String,
    pub token: String,
    pub url: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordResetEmailPayload {
    pub user_id: Uuid,
    pub to: String,
    pub token: String,
    pub url: String,
    pub expires_at: DateTime<Utc>,
}
