//! Native BSON document models for MongoDB storage.
//!
//! Maps domain models to MongoDB BSON representations with explicit `_id` renaming,
//! binary wrappers for token/code hashes and ciphertexts, and strict `Debug` secret masking.

use serde::{Deserialize, Serialize};

use crate::db::models::{
    EmailOutbox, OAuthAccount, PasswordResetToken, Session, TotpSecret, TotpUsedCode,
    TwoFactorToken, User, VerificationToken,
};

/// BSON representation of [`User`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserDoc {
    #[serde(rename = "_id")]
    pub id: bson::Uuid,
    pub email: String,
    pub password_hash: String,
    pub email_verified: bool,
    pub created_at: bson::DateTime,
    pub updated_at: bson::DateTime,
}

impl std::fmt::Debug for UserDoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserDoc")
            .field("id", &self.id)
            .field("email", &self.email)
            .field("password_hash", &"[redacted]")
            .field("email_verified", &self.email_verified)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl From<UserDoc> for User {
    fn from(doc: UserDoc) -> Self {
        Self {
            id: doc.id.into(),
            email: doc.email,
            password_hash: doc.password_hash,
            email_verified: doc.email_verified,
            created_at: doc.created_at.to_chrono(),
            updated_at: doc.updated_at.to_chrono(),
        }
    }
}

impl From<&User> for UserDoc {
    fn from(u: &User) -> Self {
        Self {
            id: bson::Uuid::from(u.id),
            email: u.email.clone(),
            password_hash: u.password_hash.clone(),
            email_verified: u.email_verified,
            created_at: bson::DateTime::from_chrono(u.created_at),
            updated_at: bson::DateTime::from_chrono(u.updated_at),
        }
    }
}

impl From<User> for UserDoc {
    fn from(u: User) -> Self {
        Self::from(&u)
    }
}

/// BSON representation of [`Session`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDoc {
    #[serde(rename = "_id")]
    pub id: bson::Uuid,
    pub user_id: bson::Uuid,
    pub token_hash: String,
    pub created_at: bson::DateTime,
    pub last_active_at: bson::DateTime,
    pub absolute_expires_at: bson::DateTime,
    pub session_type: String,
    pub csrf_token: Option<String>,
}

impl std::fmt::Debug for SessionDoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionDoc")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("token_hash", &"[redacted]")
            .field("created_at", &self.created_at)
            .field("last_active_at", &self.last_active_at)
            .field("absolute_expires_at", &self.absolute_expires_at)
            .field("session_type", &self.session_type)
            .field(
                "csrf_token",
                &self.csrf_token.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl From<SessionDoc> for Session {
    fn from(doc: SessionDoc) -> Self {
        Self {
            id: doc.id.into(),
            user_id: doc.user_id.into(),
            token_hash: doc.token_hash,
            created_at: doc.created_at.to_chrono(),
            last_active_at: doc.last_active_at.to_chrono(),
            absolute_expires_at: doc.absolute_expires_at.to_chrono(),
            session_type: doc.session_type,
            csrf_token: doc.csrf_token,
        }
    }
}

impl From<&Session> for SessionDoc {
    fn from(s: &Session) -> Self {
        Self {
            id: bson::Uuid::from(s.id),
            user_id: bson::Uuid::from(s.user_id),
            token_hash: s.token_hash.clone(),
            created_at: bson::DateTime::from_chrono(s.created_at),
            last_active_at: bson::DateTime::from_chrono(s.last_active_at),
            absolute_expires_at: bson::DateTime::from_chrono(s.absolute_expires_at),
            session_type: s.session_type.clone(),
            csrf_token: s.csrf_token.clone(),
        }
    }
}

impl From<Session> for SessionDoc {
    fn from(s: Session) -> Self {
        Self::from(&s)
    }
}

/// BSON representation of [`VerificationToken`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationTokenDoc {
    #[serde(rename = "_id", default = "bson::Uuid::new")]
    pub id: bson::Uuid,
    pub token_hash: bson::Binary,
    pub user_id: bson::Uuid,
    pub expires_at: bson::DateTime,
    pub created_at: bson::DateTime,
}

impl std::fmt::Debug for VerificationTokenDoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerificationTokenDoc")
            .field("id", &self.id)
            .field("token_hash", &"[redacted]")
            .field("user_id", &self.user_id)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl From<VerificationTokenDoc> for VerificationToken {
    fn from(doc: VerificationTokenDoc) -> Self {
        Self {
            token_hash: doc.token_hash.bytes,
            user_id: doc.user_id.into(),
            expires_at: doc.expires_at.to_chrono(),
            created_at: doc.created_at.to_chrono(),
        }
    }
}

impl From<&VerificationToken> for VerificationTokenDoc {
    fn from(v: &VerificationToken) -> Self {
        Self {
            id: bson::Uuid::new(),
            token_hash: bson::Binary {
                subtype: bson::spec::BinarySubtype::Generic,
                bytes: v.token_hash.clone(),
            },
            user_id: bson::Uuid::from(v.user_id),
            expires_at: bson::DateTime::from_chrono(v.expires_at),
            created_at: bson::DateTime::from_chrono(v.created_at),
        }
    }
}

impl From<VerificationToken> for VerificationTokenDoc {
    fn from(v: VerificationToken) -> Self {
        Self::from(&v)
    }
}

/// BSON representation of [`PasswordResetToken`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordResetTokenDoc {
    #[serde(rename = "_id", default = "bson::Uuid::new")]
    pub id: bson::Uuid,
    pub token_hash: bson::Binary,
    pub user_id: bson::Uuid,
    pub expires_at: bson::DateTime,
    pub created_at: bson::DateTime,
}

impl std::fmt::Debug for PasswordResetTokenDoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordResetTokenDoc")
            .field("id", &self.id)
            .field("token_hash", &"[redacted]")
            .field("user_id", &self.user_id)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl From<PasswordResetTokenDoc> for PasswordResetToken {
    fn from(doc: PasswordResetTokenDoc) -> Self {
        Self {
            token_hash: doc.token_hash.bytes,
            user_id: doc.user_id.into(),
            expires_at: doc.expires_at.to_chrono(),
            created_at: doc.created_at.to_chrono(),
        }
    }
}

impl From<&PasswordResetToken> for PasswordResetTokenDoc {
    fn from(p: &PasswordResetToken) -> Self {
        Self {
            id: bson::Uuid::new(),
            token_hash: bson::Binary {
                subtype: bson::spec::BinarySubtype::Generic,
                bytes: p.token_hash.clone(),
            },
            user_id: bson::Uuid::from(p.user_id),
            expires_at: bson::DateTime::from_chrono(p.expires_at),
            created_at: bson::DateTime::from_chrono(p.created_at),
        }
    }
}

impl From<PasswordResetToken> for PasswordResetTokenDoc {
    fn from(p: PasswordResetToken) -> Self {
        Self::from(&p)
    }
}

/// BSON representation of [`EmailOutbox`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailOutboxDoc {
    #[serde(rename = "_id")]
    pub id: bson::Uuid,
    pub recipient: String,
    pub email_type: String,
    pub payload: serde_json::Value,
    pub status: String,
    pub retry_count: i32,
    pub next_retry_at: bson::DateTime,
    pub created_at: bson::DateTime,
    pub sent_at: Option<bson::DateTime>,
    pub error_log: Option<String>,
}

impl std::fmt::Debug for EmailOutboxDoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailOutboxDoc")
            .field("id", &self.id)
            .field("recipient", &self.recipient)
            .field("email_type", &self.email_type)
            .field("payload", &"[redacted]")
            .field("status", &self.status)
            .field("retry_count", &self.retry_count)
            .field("next_retry_at", &self.next_retry_at)
            .field("created_at", &self.created_at)
            .field("sent_at", &self.sent_at)
            .field("error_log", &self.error_log)
            .finish()
    }
}

impl From<EmailOutboxDoc> for EmailOutbox {
    fn from(doc: EmailOutboxDoc) -> Self {
        Self {
            id: doc.id.into(),
            recipient: doc.recipient,
            email_type: doc.email_type,
            payload: doc.payload,
            status: doc.status,
            retry_count: doc.retry_count,
            next_retry_at: doc.next_retry_at.to_chrono(),
            created_at: doc.created_at.to_chrono(),
            sent_at: doc.sent_at.map(|dt| dt.to_chrono()),
            error_log: doc.error_log,
        }
    }
}

impl From<&EmailOutbox> for EmailOutboxDoc {
    fn from(o: &EmailOutbox) -> Self {
        Self {
            id: bson::Uuid::from(o.id),
            recipient: o.recipient.clone(),
            email_type: o.email_type.clone(),
            payload: o.payload.clone(),
            status: o.status.clone(),
            retry_count: o.retry_count,
            next_retry_at: bson::DateTime::from_chrono(o.next_retry_at),
            created_at: bson::DateTime::from_chrono(o.created_at),
            sent_at: o.sent_at.map(bson::DateTime::from_chrono),
            error_log: o.error_log.clone(),
        }
    }
}

impl From<EmailOutbox> for EmailOutboxDoc {
    fn from(o: EmailOutbox) -> Self {
        Self::from(&o)
    }
}

/// BSON representation of [`OAuthAccount`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthAccountDoc {
    #[serde(rename = "_id")]
    pub id: bson::Uuid,
    pub user_id: bson::Uuid,
    pub provider_id: String,
    pub provider_user_id: String,
    pub email: String,
    pub created_at: bson::DateTime,
    pub updated_at: bson::DateTime,
}

impl From<OAuthAccountDoc> for OAuthAccount {
    fn from(doc: OAuthAccountDoc) -> Self {
        Self {
            id: doc.id.into(),
            user_id: doc.user_id.into(),
            provider_id: doc.provider_id,
            provider_user_id: doc.provider_user_id,
            email: doc.email,
            created_at: doc.created_at.to_chrono(),
            updated_at: doc.updated_at.to_chrono(),
        }
    }
}

impl From<&OAuthAccount> for OAuthAccountDoc {
    fn from(oa: &OAuthAccount) -> Self {
        Self {
            id: bson::Uuid::from(oa.id),
            user_id: bson::Uuid::from(oa.user_id),
            provider_id: oa.provider_id.clone(),
            provider_user_id: oa.provider_user_id.clone(),
            email: oa.email.clone(),
            created_at: bson::DateTime::from_chrono(oa.created_at),
            updated_at: bson::DateTime::from_chrono(oa.updated_at),
        }
    }
}

impl From<OAuthAccount> for OAuthAccountDoc {
    fn from(oa: OAuthAccount) -> Self {
        Self::from(&oa)
    }
}

/// BSON representation of [`TotpSecret`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpSecretDoc {
    #[serde(rename = "_id")]
    pub id: bson::Uuid,
    pub user_id: bson::Uuid,
    pub encrypted_secret: bson::Binary,
    pub backup_codes: serde_json::Value,
    pub enabled: bool,
    pub created_at: bson::DateTime,
    pub updated_at: bson::DateTime,
}

impl std::fmt::Debug for TotpSecretDoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpSecretDoc")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("encrypted_secret", &"[redacted]")
            .field("backup_codes", &"[redacted]")
            .field("enabled", &self.enabled)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl From<TotpSecretDoc> for TotpSecret {
    fn from(doc: TotpSecretDoc) -> Self {
        Self {
            id: doc.id.into(),
            user_id: doc.user_id.into(),
            encrypted_secret: doc.encrypted_secret.bytes,
            backup_codes: doc.backup_codes,
            enabled: doc.enabled,
            created_at: doc.created_at.to_chrono(),
            updated_at: doc.updated_at.to_chrono(),
        }
    }
}

impl From<&TotpSecret> for TotpSecretDoc {
    fn from(t: &TotpSecret) -> Self {
        Self {
            id: bson::Uuid::from(t.id),
            user_id: bson::Uuid::from(t.user_id),
            encrypted_secret: bson::Binary {
                subtype: bson::spec::BinarySubtype::Generic,
                bytes: t.encrypted_secret.clone(),
            },
            backup_codes: t.backup_codes.clone(),
            enabled: t.enabled,
            created_at: bson::DateTime::from_chrono(t.created_at),
            updated_at: bson::DateTime::from_chrono(t.updated_at),
        }
    }
}

impl From<TotpSecret> for TotpSecretDoc {
    fn from(t: TotpSecret) -> Self {
        Self::from(&t)
    }
}

/// BSON representation of [`TotpUsedCode`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpUsedCodeDoc {
    #[serde(rename = "_id")]
    pub id: bson::Uuid,
    pub user_id: bson::Uuid,
    pub code_hash: bson::Binary,
    pub used_at: bson::DateTime,
}

impl std::fmt::Debug for TotpUsedCodeDoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpUsedCodeDoc")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("code_hash", &"[redacted]")
            .field("used_at", &self.used_at)
            .finish()
    }
}

impl From<TotpUsedCodeDoc> for TotpUsedCode {
    fn from(doc: TotpUsedCodeDoc) -> Self {
        Self {
            id: doc.id.into(),
            user_id: doc.user_id.into(),
            code_hash: doc.code_hash.bytes,
            used_at: doc.used_at.to_chrono(),
        }
    }
}

impl From<&TotpUsedCode> for TotpUsedCodeDoc {
    fn from(t: &TotpUsedCode) -> Self {
        Self {
            id: bson::Uuid::from(t.id),
            user_id: bson::Uuid::from(t.user_id),
            code_hash: bson::Binary {
                subtype: bson::spec::BinarySubtype::Generic,
                bytes: t.code_hash.clone(),
            },
            used_at: bson::DateTime::from_chrono(t.used_at),
        }
    }
}

impl From<TotpUsedCode> for TotpUsedCodeDoc {
    fn from(t: TotpUsedCode) -> Self {
        Self::from(&t)
    }
}

/// BSON representation of [`TwoFactorToken`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoFactorTokenDoc {
    #[serde(rename = "_id")]
    pub id: bson::Uuid,
    pub user_id: bson::Uuid,
    pub token_hash: bson::Binary,
    pub credential_hash: Option<String>,
    pub expires_at: bson::DateTime,
}

impl std::fmt::Debug for TwoFactorTokenDoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoFactorTokenDoc")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("token_hash", &"[redacted]")
            .field("credential_hash", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl From<TwoFactorTokenDoc> for TwoFactorToken {
    fn from(doc: TwoFactorTokenDoc) -> Self {
        Self {
            id: doc.id.into(),
            user_id: doc.user_id.into(),
            token_hash: doc.token_hash.bytes,
            expires_at: doc.expires_at.to_chrono(),
        }
    }
}

impl From<&TwoFactorToken> for TwoFactorTokenDoc {
    fn from(t: &TwoFactorToken) -> Self {
        Self {
            id: bson::Uuid::from(t.id),
            user_id: bson::Uuid::from(t.user_id),
            token_hash: bson::Binary {
                subtype: bson::spec::BinarySubtype::Generic,
                bytes: t.token_hash.clone(),
            },
            credential_hash: None,
            expires_at: bson::DateTime::from_chrono(t.expires_at),
        }
    }
}

impl From<TwoFactorToken> for TwoFactorTokenDoc {
    fn from(t: TwoFactorToken) -> Self {
        Self::from(&t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_models_debug_redaction() {
        let now = Utc::now();
        let user_id = Uuid::new_v4();

        let user_doc = UserDoc {
            id: bson::Uuid::from(user_id),
            email: "alice@example.com".into(),
            password_hash: "argon2id$supersecret".into(),
            email_verified: true,
            created_at: bson::DateTime::from_chrono(now),
            updated_at: bson::DateTime::from_chrono(now),
        };
        let user_dbg = format!("{user_doc:?}");
        assert!(!user_dbg.contains("supersecret"));
        assert!(user_dbg.contains("[redacted]"));

        let session_doc = SessionDoc {
            id: bson::Uuid::new(),
            user_id: bson::Uuid::from(user_id),
            token_hash: "a".repeat(64),
            created_at: bson::DateTime::from_chrono(now),
            last_active_at: bson::DateTime::from_chrono(now),
            absolute_expires_at: bson::DateTime::from_chrono(now),
            session_type: "cookie".into(),
            csrf_token: Some("csrfsecret123".into()),
        };
        let session_dbg = format!("{session_doc:?}");
        assert!(!session_dbg.contains("csrfsecret123"));
        assert!(!session_dbg.contains(&"a".repeat(64)));
        assert!(session_dbg.contains("[redacted]"));

        let outbox_doc = EmailOutboxDoc {
            id: bson::Uuid::new(),
            recipient: "bob@example.com".into(),
            email_type: "verification".into(),
            payload: serde_json::json!({ "token": "sensitive_token_value" }),
            status: "pending".into(),
            retry_count: 0,
            next_retry_at: bson::DateTime::from_chrono(now),
            created_at: bson::DateTime::from_chrono(now),
            sent_at: None,
            error_log: None,
        };
        let outbox_dbg = format!("{outbox_doc:?}");
        assert!(!outbox_dbg.contains("sensitive_token_value"));
        assert!(outbox_dbg.contains("[redacted]"));

        let totp_doc = TotpSecretDoc {
            id: bson::Uuid::new(),
            user_id: bson::Uuid::from(user_id),
            encrypted_secret: bson::Binary {
                subtype: bson::spec::BinarySubtype::Generic,
                bytes: vec![1, 2, 3, 4],
            },
            backup_codes: serde_json::json!(["code1", "code2"]),
            enabled: true,
            created_at: bson::DateTime::from_chrono(now),
            updated_at: bson::DateTime::from_chrono(now),
        };
        let totp_dbg = format!("{totp_doc:?}");
        assert!(!totp_dbg.contains("code1"));
        assert!(totp_dbg.contains("[redacted]"));
    }

    #[test]
    fn test_models_bson_roundtrip() {
        let now = Utc::now();
        let user_id = Uuid::new_v4();

        let user = User {
            id: user_id,
            email: "bob@example.com".into(),
            password_hash: "hash123".into(),
            email_verified: true,
            created_at: now,
            updated_at: now,
        };
        let doc = UserDoc::from(&user);
        let bson_doc = bson::to_document(&doc).expect("serialize UserDoc to bson");
        assert!(bson_doc.contains_key("_id"));
        let roundtrip_doc: UserDoc = bson::from_document(bson_doc).expect("deserialize UserDoc");
        let roundtrip_user = User::from(roundtrip_doc);
        assert_eq!(roundtrip_user.id, user.id);
        assert_eq!(roundtrip_user.email, user.email);
        assert_eq!(roundtrip_user.password_hash, user.password_hash);
        assert_eq!(roundtrip_user.email_verified, user.email_verified);
    }
}
