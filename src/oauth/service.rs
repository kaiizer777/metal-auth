use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::config::Config;
use crate::db::models::{
    OAUTH_UNUSABLE_PASSWORD_HASH, OAuthAccount, Session, User, is_unusable_password_hash,
};
use crate::error::AppError;
use crate::oauth::pkce::generate_pkce;
use crate::oauth::provider::{
    OAuthProvider, SUPPORTED_PROVIDERS, UserInfo, build_oauth_http_client, create_provider,
};
use crate::oauth::state::{OAuthStateManager, OAuthStatePayload};
use crate::session::SessionService;
use crate::totp::service::TotpService;

const SELECT_USER_BY_ID: &str = "SELECT id, email, password_hash, email_verified, created_at, updated_at FROM users WHERE id = $1";
const SELECT_USER_BY_EMAIL_LOWER: &str = "SELECT id, email, password_hash, email_verified, created_at, updated_at FROM users WHERE LOWER(email) = LOWER($1)";
const INSERT_USER: &str = "INSERT INTO users (id, email, password_hash, email_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)";
const SELECT_LINK_BY_PROVIDER_UID: &str = "SELECT id, user_id, provider_id, provider_user_id, email, created_at, updated_at FROM oauth_accounts WHERE provider_id = $1 AND provider_user_id = $2";
const INSERT_OAUTH_ACCOUNT: &str = "INSERT INTO oauth_accounts (id, user_id, provider_id, provider_user_id, email, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)";
const SELECT_ACCOUNTS_BY_USER: &str = "SELECT id, user_id, provider_id, provider_user_id, email, created_at, updated_at FROM oauth_accounts WHERE user_id = $1 ORDER BY created_at ASC";
const SELECT_PROVIDER_IDS_BY_USER: &str =
    "SELECT provider_id FROM oauth_accounts WHERE user_id = $1";
const SELECT_LINK_ID_BY_USER_PROVIDER: &str =
    "SELECT id FROM oauth_accounts WHERE user_id = $1 AND provider_id = $2";
const DELETE_USER_LINKS: &str =
    "DELETE FROM oauth_accounts WHERE user_id = $1 AND provider_id = $2";
const SELECT_USER_PASSWORD_HASH_FOR_UPDATE: &str =
    "SELECT password_hash FROM users WHERE id = $1 FOR UPDATE";
const SELECT_SESSION_BY_HASH_FOR_UPDATE: &str = "SELECT id, user_id, token_hash, created_at, last_active_at, absolute_expires_at, session_type, csrf_token FROM sessions WHERE token_hash = $1 AND user_id = $2 FOR UPDATE";

/// Result envelope returned by [`OAuthService::handle_callback_extended`].
#[derive(Clone)]
pub struct OAuthCallbackResult {
    pub session: Session,
    pub raw_token: String,
    pub user: User,
    pub redirect_url: String,
    pub clear_cookie_header: String,
    pub is_linked: bool,
    pub is_created: bool,
}

// Manual `Debug`: `raw_token` is a live session bearer token.
impl std::fmt::Debug for OAuthCallbackResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthCallbackResult")
            .field("session", &self.session)
            .field("raw_token", &"[REDACTED]")
            .field("user", &self.user)
            .field("redirect_url", &self.redirect_url)
            .field("clear_cookie_header", &self.clear_cookie_header)
            .field("is_linked", &self.is_linked)
            .field("is_created", &self.is_created)
            .finish()
    }
}

/// Outcome of processing an OAuth callback, distinguishing between standard login and account linking.
///
/// Non-exhaustive: embedders consume this from their own HTTP layer, so a new outcome
/// (the second-factor challenge, for one) must not break an exhaustive `match`.
#[non_exhaustive]
#[derive(Clone)]
pub enum OAuthCallbackOutcome {
    Login(OAuthCallbackResult),
    /// Second factor outstanding: no session was issued. The challenge token is the same
    /// intermediate token the password path mints and `/auth/totp/*` redeems.
    TwoFactorRequired {
        challenge_token: String,
        clear_cookie_header: String,
    },
    Linked {
        user: User,
        account: OAuthAccount,
        redirect_url: String,
        clear_cookie_header: String,
    },
}

// Manual `Debug`: `challenge_token` is a live half-authenticated credential that a session
// can be minted from, so it must never reach a log line or a panic message.
impl std::fmt::Debug for OAuthCallbackOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Login(result) => f.debug_tuple("Login").field(result).finish(),
            Self::TwoFactorRequired {
                clear_cookie_header,
                ..
            } => f
                .debug_struct("TwoFactorRequired")
                .field("challenge_token", &"[REDACTED]")
                .field("clear_cookie_header", clear_cookie_header)
                .finish(),
            Self::Linked {
                user,
                account,
                redirect_url,
                clear_cookie_header,
            } => f
                .debug_struct("Linked")
                .field("user", user)
                .field("account", account)
                .field("redirect_url", redirect_url)
                .field("clear_cookie_header", clear_cookie_header)
                .finish(),
        }
    }
}

/// Per-request transport metadata for a callback.
struct CallbackContext<'a> {
    provider_id: &'a str,
    session_type: &'a str,
    ip: Option<&'a str>,
    user_agent: Option<&'a str>,
}

/// Outcome of the transactional link write: a fresh row, a pre-existing row
/// owned by the same user, or a unique race requiring a post-rollback read.
#[derive(Debug)]
enum LinkWrite {
    Created { user: User, account: OAuthAccount },
    Existing { user: User, account: OAuthAccount },
    UniqueRace,
}

/// Converged identity: the local user plus its linked provider account.
struct LinkResult {
    user: User,
    account: OAuthAccount,
    is_linked: bool,
    is_created: bool,
}

fn oauth_account_row(
    user_id: Uuid,
    provider_id: &str,
    provider_user_id: &str,
    email: &str,
    now: DateTime<Utc>,
) -> OAuthAccount {
    OAuthAccount {
        id: Uuid::new_v4(),
        user_id,
        provider_id: provider_id.to_string(),
        provider_user_id: provider_user_id.to_string(),
        email: email.to_string(),
        created_at: now,
        updated_at: now,
    }
}

/// Service managing OAuth identity delegation, account linking, and pre-hijacking defense.
#[derive(Clone)]
pub struct OAuthService {
    db: PgPool,
    providers: HashMap<String, Arc<dyn OAuthProvider>>,
    state_mgr: OAuthStateManager,
    session_service: Arc<SessionService>,
    totp_service: Arc<TotpService>,
    config: Arc<Config>,
}

impl std::fmt::Debug for OAuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthService")
            .field("providers", &self.providers.keys().collect::<Vec<_>>())
            .field("state_mgr", &self.state_mgr)
            .field("config", &self.config)
            .finish()
    }
}

/// Transaction boundary: each write helper commits only after all of its
/// fallible reads, so it never reports an `Err` for a change it already
/// committed.
///
/// Login is deliberately not atomic across session issuance: `handle_login`
/// commits the user and identity rows via `converge_link` before issuing
/// a session, so a failed session creation leaves a verified user and its link
/// behind without a session. The state token is already consumed, so recovery is
/// a fresh authorize round-trip, which converges on the existing identity.
impl OAuthService {
    /// Constructs a new OAuth service instance with active providers instantiated
    /// from application configuration.
    ///
    /// `totp_service` is required: the login path gates session issuance on an enabled
    /// second factor, so a service built without it could not enforce that gate.
    /// Callers upgrading from a three-argument form must pass one built from the same
    /// pool and [`Config`].
    pub fn new(
        db: PgPool,
        config: Arc<Config>,
        session_service: Arc<SessionService>,
        totp_service: Arc<TotpService>,
    ) -> Result<Self, AppError> {
        let mut http_client: Option<reqwest::Client> = None;
        let mut providers: HashMap<String, Arc<dyn OAuthProvider>> = HashMap::new();

        for id in SUPPORTED_PROVIDERS {
            if let Some(cfg) = config.oauth.providers.get(*id)
                && cfg.enabled
            {
                let client = match &http_client {
                    Some(c) => c.clone(),
                    None => {
                        let c = build_oauth_http_client()?;
                        http_client = Some(c.clone());
                        c
                    }
                };
                let provider = create_provider(id, cfg, client)?;
                providers.insert((*id).to_string(), provider);
            }
        }

        let state_mgr = OAuthStateManager::new(&config.oauth, config.session.cookie_secure);

        Ok(Self {
            db,
            providers,
            state_mgr,
            session_service,
            totp_service,
            config,
        })
    }

    /// Constructs a service with custom/mock providers for testing.
    ///
    /// Takes the same required `totp_service` as [`Self::new`].
    pub fn with_providers(
        db: PgPool,
        config: Arc<Config>,
        session_service: Arc<SessionService>,
        totp_service: Arc<TotpService>,
        providers: HashMap<String, Arc<dyn OAuthProvider>>,
    ) -> Self {
        let state_mgr = OAuthStateManager::new(&config.oauth, config.session.cookie_secure);
        Self {
            db,
            providers,
            state_mgr,
            session_service,
            totp_service,
            config,
        }
    }

    /// Constructs a service with explicit state manager.
    ///
    /// Takes the same required `totp_service` as [`Self::new`].
    pub fn new_with_manager(
        db: PgPool,
        providers: HashMap<String, Arc<dyn OAuthProvider>>,
        state_mgr: OAuthStateManager,
        session_service: Arc<SessionService>,
        totp_service: Arc<TotpService>,
        config: Arc<Config>,
    ) -> Self {
        Self {
            db,
            providers,
            state_mgr,
            session_service,
            totp_service,
            config,
        }
    }

    /// Retrieves an active OAuth provider by canonical identifier.
    pub fn provider(&self, provider_id: &str) -> Result<Arc<dyn OAuthProvider>, AppError> {
        if !SUPPORTED_PROVIDERS.contains(&provider_id) {
            return Err(AppError::OAuthProviderNotFound);
        }
        self.providers
            .get(provider_id)
            .cloned()
            .ok_or(AppError::OAuthProviderNotFound)
    }

    /// Generates PKCE challenge and signed state cookie, returning `(auth_url, set_cookie_header)`.
    pub fn get_authorization_url(
        &self,
        provider_id: &str,
        redirect_url: Option<String>,
    ) -> Result<(String, String), AppError> {
        let provider = self.provider(provider_id)?;
        let pkce = generate_pkce()?;
        let (state_token, set_cookie_str) =
            self.state_mgr
                .create_state(provider_id, &pkce.verifier, redirect_url)?;
        let auth_url = provider.auth_url(&state_token, &pkce.challenge);

        tracing::info!(event = "oauth_initiate", provider = provider_id,);

        Ok((auth_url, set_cookie_str))
    }

    /// Alias for [`get_authorization_url`].
    pub fn initiate_flow(
        &self,
        provider_id: &str,
        redirect_url: Option<String>,
    ) -> Result<(String, String), AppError> {
        self.get_authorization_url(provider_id, redirect_url)
    }

    /// Initiates an authenticated account linking flow, embedding user_id in the signed state.
    pub fn initiate_link_flow(
        &self,
        provider_id: &str,
        user_id: Uuid,
        redirect_url: Option<String>,
        session_hash: Option<String>,
    ) -> Result<(String, String), AppError> {
        let provider = self.provider(provider_id)?;
        let pkce = generate_pkce()?;
        let (state_token, set_cookie_str) = self.state_mgr.create_state_with_user(
            provider_id,
            &pkce.verifier,
            redirect_url,
            Some(user_id),
            session_hash,
        )?;
        let auth_url = provider.auth_url(&state_token, &pkce.challenge);

        tracing::info!(
            event = "oauth_initiate_link",
            provider = provider_id,
            user_id = %user_id,
        );

        Ok((auth_url, set_cookie_str))
    }

    /// Returns a `Set-Cookie` header value to clear the OAuth state cookie (`Max-Age=0`).
    #[must_use]
    pub fn clear_state_cookie(&self) -> String {
        self.state_mgr.build_clear_cookie()
    }

    /// Returns a `Set-Cookie` header value to clear the OAuth state cookie for a specific provider.
    #[must_use]
    pub fn clear_state_cookie_for_provider(&self, provider_id: &str) -> String {
        self.state_mgr.build_clear_cookie_for_provider(provider_id)
    }

    /// Exposes a reference to the internal [`OAuthStateManager`].
    #[must_use]
    pub fn state_mgr(&self) -> &OAuthStateManager {
        &self.state_mgr
    }

    /// Handles an incoming OAuth callback returning the full [`OAuthCallbackOutcome`].
    ///
    /// The seven-argument signature is a frozen cross-module contract with
    /// `handler/oauth.rs`; the body itself is split into focused steps.
    #[allow(clippy::too_many_arguments)]
    pub async fn handle_callback_extended(
        &self,
        provider_id: &str,
        code: &str,
        state_param: &str,
        cookie_header: Option<&str>,
        session_type: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<OAuthCallbackOutcome, AppError> {
        let ctx = CallbackContext {
            provider_id,
            session_type,
            ip,
            user_agent,
        };
        let clear_cookie_header = self.state_mgr.build_clear_cookie_for_provider(provider_id);

        let payload = self.validate_callback_state(&ctx, code, state_param, cookie_header)?;
        let user_info = self
            .exchange_and_fetch(&ctx, code, &payload.code_verifier)
            .await?;
        let user_info = self.verified_email_gate(&ctx, user_info)?;

        if let Some(link_user_id) = payload.user_id {
            return self
                .handle_link_intent(&ctx, link_user_id, payload, &user_info, clear_cookie_header)
                .await;
        }
        self.handle_login(&ctx, payload, &user_info, clear_cookie_header)
            .await
    }

    /// Validates the signed state against its cookie and rejects empty codes.
    fn validate_callback_state(
        &self,
        ctx: &CallbackContext<'_>,
        code: &str,
        state_param: &str,
        cookie_header: Option<&str>,
    ) -> Result<OAuthStatePayload, AppError> {
        let cookie_header = match cookie_header {
            Some(header) if !header.trim().is_empty() => header,
            _ => {
                self.log_callback_failure(ctx.provider_id, "state_missing");
                return Err(AppError::OAuthStateInvalid);
            }
        };

        let payload = match self
            .state_mgr
            .validate(cookie_header, state_param, ctx.provider_id)
        {
            Ok(payload) => payload,
            Err(e) => {
                self.log_callback_failure(ctx.provider_id, "state_invalid");
                return Err(e);
            }
        };

        if code.trim().is_empty() {
            self.log_callback_failure(ctx.provider_id, "code_invalid");
            return Err(AppError::OAuthCodeInvalid);
        }

        Ok(payload)
    }

    /// Exchanges the authorization code and fetches the provider profile.
    async fn exchange_and_fetch(
        &self,
        ctx: &CallbackContext<'_>,
        code: &str,
        code_verifier: &str,
    ) -> Result<UserInfo, AppError> {
        let provider = match self.provider(ctx.provider_id) {
            Ok(provider) => provider,
            Err(e) => {
                self.log_callback_failure(ctx.provider_id, "provider_not_found");
                return Err(e);
            }
        };

        let tokens = match provider.exchange_code(code, code_verifier).await {
            Ok(tokens) => tokens,
            Err(e) => {
                self.log_callback_failure(ctx.provider_id, "exchange_failed");
                return Err(e);
            }
        };

        match provider.get_user_info(&tokens).await {
            Ok(user_info) => Ok(user_info),
            Err(e) => {
                self.log_callback_failure(ctx.provider_id, "userinfo_failed");
                Err(e)
            }
        }
    }

    /// PRE-HIJACKING GUARD 1 (OWASP ASVS 5.0 L1): the provider must have
    /// verified the email before any database read, and the normalized address
    /// must be non-empty.
    fn verified_email_gate(
        &self,
        ctx: &CallbackContext<'_>,
        mut user_info: UserInfo,
    ) -> Result<UserInfo, AppError> {
        if !user_info.email_verified {
            self.log_callback_failure(ctx.provider_id, "email_unverified");
            return Err(AppError::OAuthEmailUnverified);
        }

        user_info.email = user_info.email.trim().to_lowercase();

        if user_info.email.is_empty() {
            self.log_callback_failure(ctx.provider_id, "email_empty");
            return Err(AppError::OAuthProviderError);
        }

        Ok(user_info)
    }

    /// Applies a link intent: the session check and the identity insert share
    /// one transaction holding the session row lock, so a revocation commits
    /// either before the check (link rejected) or after the insert (link
    /// stands). All reads stay pre-commit: no `Err` after write.
    async fn handle_link_intent(
        &self,
        ctx: &CallbackContext<'_>,
        link_user_id: Uuid,
        payload: OAuthStatePayload,
        user_info: &UserInfo,
        clear_cookie_header: String,
    ) -> Result<OAuthCallbackOutcome, AppError> {
        let provider_id = ctx.provider_id;
        let mut tx = self.db.begin().await.map_err(AppError::Database)?;

        // The initiating session must still be live. A logout, revoke-all, or
        // account deletion in flight blocks the link; the row lock serializes
        // this check with revocation. Fail closed pre-commit.
        let session_live = self
            .session_is_live(&mut tx, link_user_id, payload.session_hash.as_deref())
            .await?;
        if !session_live {
            rollback_quietly(tx).await;
            self.log_callback_failure(provider_id, "link_session_revoked");
            return Err(AppError::OAuthStateInvalid);
        }

        // The session gate above covers a deleted account (sessions cascade), so
        // this is the same contract error rather than a server fault.
        let user = fetch_user_by_id(&mut *tx, link_user_id)
            .await?
            .ok_or(AppError::OAuthStateInvalid)?;

        let redirect_url = payload.redirect_url.unwrap_or_else(|| "/".to_string());

        let write = match Self::link_identity_in_tx(
            &mut tx,
            link_user_id,
            provider_id,
            &user_info.email,
            &user_info.provider_user_id,
        )
        .await
        {
            Ok(write) => write,
            Err(e) => {
                rollback_quietly(tx).await;
                return Err(e);
            }
        };

        let account = match write {
            LinkWrite::Created { account, .. } | LinkWrite::Existing { account, .. } => account,
            LinkWrite::UniqueRace => {
                rollback_quietly(tx).await;
                return self
                    .resolve_link_race(link_user_id, provider_id, &user_info.provider_user_id)
                    .await
                    .map(|account| OAuthCallbackOutcome::Linked {
                        user,
                        account,
                        redirect_url,
                        clear_cookie_header,
                    });
            }
        };

        tx.commit().await.map_err(AppError::Database)?;

        Ok(OAuthCallbackOutcome::Linked {
            user,
            account,
            redirect_url,
            clear_cookie_header,
        })
    }

    /// Resolves or provisions the local user for a login callback and issues a session.
    async fn handle_login(
        &self,
        ctx: &CallbackContext<'_>,
        payload: OAuthStatePayload,
        user_info: &UserInfo,
        clear_cookie_header: String,
    ) -> Result<OAuthCallbackOutcome, AppError> {
        let link = self
            .converge_link(
                None,
                ctx.provider_id,
                &user_info.email,
                &user_info.provider_user_id,
            )
            .await?;
        let user = link.user;

        if link.is_linked {
            tracing::info!(
                event = "oauth_account_linked",
                provider = ctx.provider_id,
                user_id = %user.id,
            );
        }
        if link.is_created {
            tracing::info!(
                event = "oauth_user_created",
                provider = ctx.provider_id,
                user_id = %user.id,
                email = %user.email,
            );
        }

        // Second factor gate: an enabled factor blocks session issuance on every login
        // path, not only the password one. The gate read and the session insert share one
        // transaction, so an activation that lands after the read waits for this commit
        // instead of slipping between the decision and the insert. This is the same shape
        // as `handler::auth::issue_session_after_gate`. Fail closed — a gate read error
        // aborts the login.
        let mut transaction = self.db.begin().await.map_err(AppError::Database)?;
        let enabled = match self
            .totp_service
            .is_totp_enabled_locked(&mut transaction, user.id)
            .await
        {
            Ok(enabled) => enabled,
            Err(error) => {
                rollback_quietly(transaction).await;
                return Err(error);
            }
        };

        if enabled {
            rollback_quietly(transaction).await;
            let challenge_token = self.totp_service.generate_two_factor_token(user.id).await?;
            tracing::info!(
                target: "security_event",
                event = "two_factor_challenge_issued",
                provider = ctx.provider_id,
                user_id = %user.id,
                ip = ?ctx.ip,
            );
            return Ok(OAuthCallbackOutcome::TwoFactorRequired {
                challenge_token,
                clear_cookie_header,
            });
        }

        let (session, raw_token) = match self
            .session_service
            .create_session_in(&mut transaction, user.id, None, ctx.session_type)
            .await
        {
            Ok(created) => created,
            Err(error) => {
                rollback_quietly(transaction).await;
                return Err(error);
            }
        };
        transaction.commit().await.map_err(AppError::Database)?;

        // `create_session_in` leaves logging to its caller; keep the standalone path's
        // `session_created` event on this one.
        tracing::info!(
            event = "session_created",
            user_id = %user.id,
            session_type = ctx.session_type,
            ip = ctx.ip.unwrap_or("unknown"),
            user_agent = ctx.user_agent.unwrap_or("unknown"),
        );

        // `session_id_hash` is a SHA-256 of a 256-bit token, never the token: a correlator,
        // not a credential. Every authentication event carries it; lifecycle events do not.
        tracing::info!(
            event = "oauth_callback_success",
            provider = ctx.provider_id,
            user_id = %user.id,
            session_id_hash = %session.token_hash,
        );

        let redirect_url = payload.redirect_url.unwrap_or_else(|| "/".to_string());

        Ok(OAuthCallbackOutcome::Login(OAuthCallbackResult {
            session,
            raw_token,
            user,
            redirect_url,
            clear_cookie_header,
            is_linked: link.is_linked,
            is_created: link.is_created,
        }))
    }

    fn log_callback_failure(&self, provider_id: &str, reason: &str) {
        tracing::info!(
            event = "oauth_callback_failure",
            provider = provider_id,
            reason = reason,
        );
    }

    /// Converges an external identity with a local account.
    ///
    /// `user_id = Some` is a link intent: the authenticated user must exist,
    /// be verified, and own the identity — another owner is a conflict.
    /// `user_id = None` is the login path, which resolves or provisions the
    /// user by email and trusts the unique-constraint winner. That asymmetry
    /// is deliberate: a login must never turn into a link conflict.
    async fn converge_link(
        &self,
        user_id: Option<Uuid>,
        provider_id: &str,
        email: &str,
        provider_user_id: &str,
    ) -> Result<LinkResult, AppError> {
        match user_id {
            Some(user_id) => {
                self.converge_authenticated_link(user_id, provider_id, email, provider_user_id)
                    .await
            }
            None => {
                self.converge_login(provider_id, email, provider_user_id)
                    .await
            }
        }
    }

    /// Links an identity to a known authenticated user under the cross-user check.
    async fn converge_authenticated_link(
        &self,
        user_id: Uuid,
        provider_id: &str,
        email: &str,
        provider_user_id: &str,
    ) -> Result<LinkResult, AppError> {
        let mut tx = self.db.begin().await.map_err(AppError::Database)?;

        let write =
            match Self::link_identity_in_tx(&mut tx, user_id, provider_id, email, provider_user_id)
                .await
            {
                Ok(write) => write,
                Err(e) => {
                    rollback_quietly(tx).await;
                    return Err(e);
                }
            };

        match write {
            LinkWrite::Created { user, account } => {
                tx.commit().await.map_err(AppError::Database)?;

                tracing::info!(
                    event = "oauth_account_linked",
                    provider = provider_id,
                    user_id = %user_id,
                );

                Ok(LinkResult {
                    user,
                    account,
                    is_linked: true,
                    is_created: false,
                })
            }
            LinkWrite::Existing { user, account } => {
                // Read-only fast path: nothing was written.
                rollback_quietly(tx).await;
                Ok(LinkResult {
                    user,
                    account,
                    is_linked: false,
                    is_created: false,
                })
            }
            LinkWrite::UniqueRace => {
                rollback_quietly(tx).await;
                let account = self
                    .resolve_link_race(user_id, provider_id, provider_user_id)
                    .await?;
                let user = fetch_user_by_id(&self.db, user_id)
                    .await?
                    .ok_or(AppError::NotFound)?;
                Ok(LinkResult {
                    user,
                    account,
                    is_linked: true,
                    is_created: false,
                })
            }
        }
    }

    /// Resolves the login path: existing identity, verified local user, or provisioning.
    async fn converge_login(
        &self,
        provider_id: &str,
        email: &str,
        provider_user_id: &str,
    ) -> Result<LinkResult, AppError> {
        let email = email.trim().to_lowercase();

        // Case A: identity already linked to a user.
        if let Some(link) =
            fetch_link_by_provider_uid(&self.db, provider_id, provider_user_id).await?
        {
            let user = fetch_user_by_id(&self.db, link.user_id)
                .await?
                .ok_or(AppError::NotFound)?;
            return Ok(LinkResult {
                user,
                account: link,
                is_linked: false,
                is_created: false,
            });
        }

        // Case B: a local account with the normalized email already exists.
        if let Some(user) = fetch_user_by_email(&self.db, &email).await? {
            return self
                .attach_link(user, provider_id, &email, provider_user_id)
                .await;
        }

        // Case C: provision a verified user and its first link atomically.
        self.provision_user_with_link(provider_id, &email, provider_user_id)
            .await
    }

    /// Inserts a link for a resolved user and converges on a unique race.
    async fn attach_link(
        &self,
        user: User,
        provider_id: &str,
        email: &str,
        provider_user_id: &str,
    ) -> Result<LinkResult, AppError> {
        // PRE-HIJACKING COLLISION GUARD 2 (OWASP ASVS 5.0 L1):
        // Never link a federated identity onto an unverified local account.
        if !user.email_verified {
            tracing::warn!(
                event = "oauth_pre_hijack_prevented",
                email = %email,
                provider = provider_id,
                "rejected linking to unverified local account"
            );
            return Err(AppError::OAuthAccountLinkConflict);
        }

        let account = oauth_account_row(user.id, provider_id, provider_user_id, email, Utc::now());

        match insert_oauth_account(&self.db, &account).await {
            Ok(()) => Ok(LinkResult {
                user,
                account,
                is_linked: true,
                is_created: false,
            }),
            Err(e) if is_unique_violation(&e) => {
                let winner = self.relink_winner(provider_id, provider_user_id).await?;
                if winner.user.id != user.id {
                    tracing::warn!(
                        event = "oauth_login_identity_adopted",
                        provider = provider_id,
                        provider_user_id = provider_user_id,
                        resolved_user_id = %user.id,
                        winner_user_id = %winner.user.id,
                        "login adopted an identity already owned by another account"
                    );
                }
                Ok(winner)
            }
            Err(e) => Err(AppError::Database(e)),
        }
    }

    /// Reads the identity row that won a concurrent insert. The login path
    /// trusts the winner regardless of owner (see [`Self::converge_link`]).
    async fn relink_winner(
        &self,
        provider_id: &str,
        provider_user_id: &str,
    ) -> Result<LinkResult, AppError> {
        let link = fetch_link_by_provider_uid(&self.db, provider_id, provider_user_id)
            .await?
            .ok_or(AppError::NotFound)?;
        let user = fetch_user_by_id(&self.db, link.user_id)
            .await?
            .ok_or(AppError::NotFound)?;

        Ok(LinkResult {
            user,
            account: link,
            is_linked: false,
            is_created: false,
        })
    }

    /// Provisions a verified OAuth user and its first identity in one transaction.
    async fn provision_user_with_link(
        &self,
        provider_id: &str,
        email: &str,
        provider_user_id: &str,
    ) -> Result<LinkResult, AppError> {
        let mut tx = self.db.begin().await.map_err(AppError::Database)?;
        let now = Utc::now();
        let user_id = Uuid::new_v4();
        let user = User {
            id: user_id,
            email: email.to_string(),
            password_hash: OAUTH_UNUSABLE_PASSWORD_HASH.to_string(),
            email_verified: true,
            created_at: now,
            updated_at: now,
        };
        let account = oauth_account_row(user_id, provider_id, provider_user_id, email, now);

        if let Err(e) = insert_user(&mut *tx, &user).await {
            rollback_quietly(tx).await;
            if is_unique_violation(&e) {
                return self
                    .attach_link_to_raced_user(provider_id, email, provider_user_id)
                    .await;
            }
            return Err(AppError::Database(e));
        }

        if let Err(e) = insert_oauth_account(&mut *tx, &account).await {
            rollback_quietly(tx).await;
            if is_unique_violation(&e) {
                return self.relink_winner(provider_id, provider_user_id).await;
            }
            return Err(AppError::Database(e));
        }

        tx.commit().await.map_err(AppError::Database)?;

        Ok(LinkResult {
            user,
            account,
            is_linked: true,
            is_created: true,
        })
    }

    /// Converges after losing a concurrent user creation race.
    async fn attach_link_to_raced_user(
        &self,
        provider_id: &str,
        email: &str,
        provider_user_id: &str,
    ) -> Result<LinkResult, AppError> {
        let user = fetch_user_by_email(&self.db, email)
            .await?
            .ok_or(AppError::NotFound)?;
        self.attach_link(user, provider_id, email, provider_user_id)
            .await
    }

    /// Attaches an external identity to an existing local user.
    pub async fn link_identity_to_user(
        &self,
        user_id: Uuid,
        provider_id: &str,
        user_info: &UserInfo,
    ) -> Result<OAuthAccount, AppError> {
        if !user_info.email_verified {
            return Err(AppError::OAuthEmailUnverified);
        }

        let email = user_info.email.trim().to_lowercase();
        if email.is_empty() {
            return Err(AppError::OAuthProviderError);
        }

        let link = self
            .converge_link(
                Some(user_id),
                provider_id,
                &email,
                &user_info.provider_user_id,
            )
            .await?;

        Ok(link.account)
    }

    /// Runs the link read-check-insert sequence inside the caller's transaction.
    /// On `UniqueRace` the caller's transaction is aborted: roll it back and
    /// resolve via [`Self::resolve_link_race`].
    async fn link_identity_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
        provider_id: &str,
        email: &str,
        provider_user_id: &str,
    ) -> Result<LinkWrite, AppError> {
        let user = fetch_user_by_id(&mut **tx, user_id)
            .await?
            .ok_or(AppError::NotFound)?;
        if !user.email_verified {
            return Err(AppError::OAuthAccountLinkConflict);
        }

        if let Some(link) =
            fetch_link_by_provider_uid(&mut **tx, provider_id, provider_user_id).await?
        {
            if link.user_id != user_id {
                return Err(AppError::OAuthAccountLinkConflict);
            }
            return Ok(LinkWrite::Existing {
                user,
                account: link,
            });
        }

        let account = oauth_account_row(user_id, provider_id, provider_user_id, email, Utc::now());

        match insert_oauth_account(&mut **tx, &account).await {
            Ok(()) => Ok(LinkWrite::Created { user, account }),
            Err(e) if is_unique_violation(&e) => Ok(LinkWrite::UniqueRace),
            Err(e) => Err(AppError::Database(e)),
        }
    }

    /// Post-rollback read for a link lost to a concurrent unique insert: the
    /// winner's row decides, same-user wins, cross-user conflicts.
    async fn resolve_link_race(
        &self,
        user_id: Uuid,
        provider_id: &str,
        provider_user_id: &str,
    ) -> Result<OAuthAccount, AppError> {
        let link = fetch_link_by_provider_uid(&self.db, provider_id, provider_user_id).await?;

        if let Some(link) = link
            && link.user_id == user_id
        {
            return Ok(link);
        }
        Err(AppError::OAuthAccountLinkConflict)
    }

    /// Links an additional OAuth identity and returns the created or existing [`OAuthAccount`].
    pub async fn link_account_identity(
        &self,
        user_id: Uuid,
        provider_id: &str,
        code: &str,
        state_param: &str,
        cookie_header: Option<&str>,
    ) -> Result<OAuthAccount, AppError> {
        let cookie_header = cookie_header.ok_or(AppError::OAuthStateInvalid)?;
        let payload = self
            .state_mgr
            .validate(cookie_header, state_param, provider_id)?;

        if let Some(state_uid) = payload.user_id
            && state_uid != user_id
        {
            return Err(AppError::OAuthStateInvalid);
        }

        if code.trim().is_empty() {
            return Err(AppError::OAuthCodeInvalid);
        }

        let provider = self.provider(provider_id)?;
        let tokens = provider.exchange_code(code, &payload.code_verifier).await?;
        let user_info = provider.get_user_info(&tokens).await?;

        self.link_identity_to_user(user_id, provider_id, &user_info)
            .await
    }

    /// Unlinks an external provider, preventing account lockout if no usable password remains.
    pub async fn unlink_account(&self, user_id: Uuid, provider_id: &str) -> Result<(), AppError> {
        let mut tx = self.db.begin().await.map_err(AppError::Database)?;

        // Acquire exclusive row lock on user record to serialize concurrent unlinking.
        let user = sqlx::query_as::<_, (String,)>(SELECT_USER_PASSWORD_HASH_FOR_UPDATE)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::Database)?
            .ok_or(AppError::NotFound)?;

        let target_link: Option<(Uuid,)> = sqlx::query_as(SELECT_LINK_ID_BY_USER_PROVIDER)
            .bind(user_id)
            .bind(provider_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::Database)?;

        if target_link.is_none() {
            return Err(AppError::NotFound);
        }

        if self
            .remaining_auth_methods(&mut tx, user_id, provider_id, &user.0)
            .await?
            == 0
        {
            return Err(AppError::ValidationError(
                "Cannot unlink the only authentication method".to_string(),
            ));
        }

        sqlx::query(DELETE_USER_LINKS)
            .bind(user_id)
            .bind(provider_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;

        tx.commit().await.map_err(AppError::Database)?;

        tracing::info!(
            event = "oauth_account_unlinked",
            provider = provider_id,
            user_id = %user_id,
        );

        Ok(())
    }

    /// Counts the auth methods left after removing `provider_id`: a usable
    /// password plus other linked providers that are still enabled.
    async fn remaining_auth_methods(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
        provider_id: &str,
        password_hash: &str,
    ) -> Result<usize, AppError> {
        let linked_accounts: Vec<(String,)> = sqlx::query_as(SELECT_PROVIDER_IDS_BY_USER)
            .bind(user_id)
            .fetch_all(&mut **tx)
            .await
            .map_err(AppError::Database)?;

        let has_usable_password = !is_unusable_password_hash(password_hash);
        let remaining_enabled_oauth_accounts = linked_accounts
            .into_iter()
            .filter(|(p,)| p != provider_id && self.providers.contains_key(p))
            .count();

        Ok(has_usable_password as usize + remaining_enabled_oauth_accounts)
    }

    /// Lists all external identities linked to the given user.
    pub async fn list_linked_accounts(&self, user_id: Uuid) -> Result<Vec<OAuthAccount>, AppError> {
        let accounts = sqlx::query_as::<_, OAuthAccount>(SELECT_ACCOUNTS_BY_USER)
            .bind(user_id)
            .fetch_all(&self.db)
            .await
            .map_err(AppError::Database)?;

        Ok(accounts)
    }

    /// Whether the initiating session is still live, under a row lock.
    async fn session_is_live(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
        session_hash: Option<&str>,
    ) -> Result<bool, AppError> {
        let Some(hash) = session_hash.filter(|hash| !hash.is_empty()) else {
            return Ok(false);
        };

        let row: Option<Session> = sqlx::query_as::<_, Session>(SELECT_SESSION_BY_HASH_FOR_UPDATE)
            .bind(hash)
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::Database)?;

        let Some(session) = row else {
            return Ok(false);
        };

        let idle = chrono::Duration::from_std(self.config.session.idle_timeout())
            .map_err(|_| AppError::Internal)?;
        let now = Utc::now();
        Ok(now <= session.absolute_expires_at && now <= session.last_active_at + idle)
    }
}

async fn fetch_user_by_id<'c, E>(executor: E, user_id: Uuid) -> Result<Option<User>, AppError>
where
    E: sqlx::Executor<'c, Database = Postgres>,
{
    sqlx::query_as::<_, User>(SELECT_USER_BY_ID)
        .bind(user_id)
        .fetch_optional(executor)
        .await
        .map_err(AppError::Database)
}

async fn fetch_user_by_email<'c, E>(executor: E, email: &str) -> Result<Option<User>, AppError>
where
    E: sqlx::Executor<'c, Database = Postgres>,
{
    sqlx::query_as::<_, User>(SELECT_USER_BY_EMAIL_LOWER)
        .bind(email)
        .fetch_optional(executor)
        .await
        .map_err(AppError::Database)
}

async fn fetch_link_by_provider_uid<'c, E>(
    executor: E,
    provider_id: &str,
    provider_user_id: &str,
) -> Result<Option<OAuthAccount>, AppError>
where
    E: sqlx::Executor<'c, Database = Postgres>,
{
    sqlx::query_as::<_, OAuthAccount>(SELECT_LINK_BY_PROVIDER_UID)
        .bind(provider_id)
        .bind(provider_user_id)
        .fetch_optional(executor)
        .await
        .map_err(AppError::Database)
}

async fn insert_user<'c, E>(executor: E, user: &User) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'c, Database = Postgres>,
{
    sqlx::query(INSERT_USER)
        .bind(user.id)
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(user.email_verified)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(executor)
        .await?;
    Ok(())
}

async fn insert_oauth_account<'c, E>(executor: E, row: &OAuthAccount) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'c, Database = Postgres>,
{
    sqlx::query(INSERT_OAUTH_ACCOUNT)
        .bind(row.id)
        .bind(row.user_id)
        .bind(&row.provider_id)
        .bind(&row.provider_user_id)
        .bind(&row.email)
        .bind(row.created_at)
        .bind(row.updated_at)
        .execute(executor)
        .await?;
    Ok(())
}

/// Rolls back without masking the original error.
async fn rollback_quietly(tx: Transaction<'_, Postgres>) {
    if let Err(err) = tx.rollback().await {
        tracing::debug!(err = %err, "oauth transaction rollback failed");
    }
}

/// Detects PostgreSQL unique constraint violation (SQLSTATE 23505).
fn is_unique_violation(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db_err) => db_err.code().as_deref() == Some("23505"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use sqlx::postgres::PgPoolOptions;

    #[derive(Debug)]
    struct MockProvider {
        id: &'static str,
        user_info: UserInfo,
        exchange_fail: bool,
    }

    #[async_trait]
    impl OAuthProvider for MockProvider {
        fn id(&self) -> &'static str {
            self.id
        }

        fn auth_url(&self, state: &str, code_challenge: &str) -> String {
            format!("https://mock.provider/auth?state={state}&code_challenge={code_challenge}")
        }

        async fn exchange_code(
            &self,
            code: &str,
            _code_verifier: &str,
        ) -> Result<crate::oauth::provider::TokenResponse, AppError> {
            if self.exchange_fail || code == "bad_code" {
                return Err(AppError::OAuthProviderError);
            }
            Ok(crate::oauth::provider::TokenResponse {
                access_token: "mock_access_token".to_string(),
                token_type: "Bearer".to_string(),
                refresh_token: None,
                expires_in: Some(3600),
                id_token: None,
                raw: HashMap::new(),
            })
        }

        async fn fetch_user_info(
            &self,
            _tokens: &crate::oauth::provider::TokenResponse,
        ) -> Result<UserInfo, AppError> {
            Ok(self.user_info.clone())
        }
    }

    fn test_service_with_mock(user_info: UserInfo, exchange_fail: bool) -> OAuthService {
        let mut cfg = Config {
            database_url: "postgres://postgres:postgres@127.0.0.1:1/postgres".to_string(),
            ..Default::default()
        };
        cfg.oauth.state_secret = "01234567890123456789012345678901".to_string();
        let cfg_arc = Arc::new(cfg);
        let pool = PgPoolOptions::new()
            .connect_lazy(&cfg_arc.database_url)
            .expect("lazy pool");
        let session_service = Arc::new(SessionService::new(pool.clone(), Arc::clone(&cfg_arc)));
        let totp_service = Arc::new(crate::totp::service::TotpService::new(
            pool.clone(),
            Arc::clone(&cfg_arc),
            Arc::new(crate::config::AppConfig::default()),
        ));

        let mut providers: HashMap<String, Arc<dyn OAuthProvider>> = HashMap::new();
        providers.insert(
            "google".to_string(),
            Arc::new(MockProvider {
                id: "google",
                user_info,
                exchange_fail,
            }),
        );

        OAuthService::with_providers(pool, cfg_arc, session_service, totp_service, providers)
    }

    fn alice_user_info() -> UserInfo {
        UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog_123".to_string(),
            email: "alice@example.com".to_string(),
            email_verified: true,
            name: Some("Alice".to_string()),
            avatar_url: None,
        }
    }

    #[tokio::test]
    async fn test_provider_lookup_and_not_found() {
        let svc = test_service_with_mock(alice_user_info(), false);

        assert!(svc.provider("google").is_ok());
        assert!(matches!(
            svc.provider("github"),
            Err(AppError::OAuthProviderNotFound)
        ));
        assert!(matches!(
            svc.provider("discord"),
            Err(AppError::OAuthProviderNotFound)
        ));
    }

    #[tokio::test]
    async fn test_get_authorization_url_sets_cookie_and_params() {
        let svc = test_service_with_mock(alice_user_info(), false);

        let (auth_url, set_cookie) = svc
            .get_authorization_url("google", Some("/dashboard".to_string()))
            .expect("auth url");

        assert!(auth_url.contains("https://mock.provider/auth?state="));
        assert!(auth_url.contains("code_challenge="));
        assert!(set_cookie.contains("oauth_state="));
        assert!(set_cookie.contains("Path=/"));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Lax"));
    }

    #[tokio::test]
    async fn test_handle_callback_invalid_state_rejection() {
        let svc = test_service_with_mock(alice_user_info(), false);

        // Missing cookie
        let res = svc
            .handle_callback_extended("google", "code123", "state123", None, "cookie", None, None)
            .await;
        assert!(matches!(res, Err(AppError::OAuthStateInvalid)));

        // Tampered cookie
        let res = svc
            .handle_callback_extended(
                "google",
                "code123",
                "state123",
                Some("oauth_state=invalid.signature"),
                "cookie",
                None,
                None,
            )
            .await;
        assert!(matches!(res, Err(AppError::OAuthStateInvalid)));
    }

    #[tokio::test]
    async fn test_handle_callback_empty_code_rejection() {
        let svc = test_service_with_mock(alice_user_info(), false);

        let (auth_url, set_cookie) = svc
            .get_authorization_url("google", None)
            .expect("init flow");
        let state_token = auth_url
            .split("state=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        let res = svc
            .handle_callback_extended(
                "google",
                "",
                state_token,
                Some(&set_cookie),
                "cookie",
                None,
                None,
            )
            .await;
        assert!(matches!(res, Err(AppError::OAuthCodeInvalid)));
    }

    #[tokio::test]
    async fn test_handle_callback_pre_hijacking_guard_rejects_unverified_provider_email() {
        let unverified_user_info = UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog_unverified".to_string(),
            email: "victim@example.com".to_string(),
            email_verified: false,
            name: None,
            avatar_url: None,
        };
        let svc = test_service_with_mock(unverified_user_info, false);

        let (auth_url, set_cookie) = svc
            .get_authorization_url("google", None)
            .expect("init flow");
        let state_token = auth_url
            .split("state=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        // Must reject with 400 OAuthEmailUnverified BEFORE any database queries
        let res = svc
            .handle_callback_extended(
                "google",
                "valid_code",
                state_token,
                Some(&set_cookie),
                "cookie",
                None,
                None,
            )
            .await;
        assert!(matches!(res, Err(AppError::OAuthEmailUnverified)));
    }

    #[tokio::test]
    async fn test_handle_callback_rejects_empty_verified_email() {
        let empty_email_user_info = UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog_empty".to_string(),
            email: "   ".to_string(),
            email_verified: true,
            name: None,
            avatar_url: None,
        };
        let svc = test_service_with_mock(empty_email_user_info, false);

        let (auth_url, set_cookie) = svc
            .get_authorization_url("google", None)
            .expect("init flow");
        let state_token = auth_url
            .split("state=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        let res = svc
            .handle_callback_extended(
                "google",
                "valid_code",
                state_token,
                Some(&set_cookie),
                "cookie",
                None,
                None,
            )
            .await;
        assert!(matches!(res, Err(AppError::OAuthProviderError)));
    }

    #[tokio::test]
    async fn test_clear_state_cookie_and_state_mgr_accessors() {
        let svc = test_service_with_mock(alice_user_info(), false);
        let clear_cookie = svc.clear_state_cookie();
        assert!(clear_cookie.contains("Max-Age=0"));
        assert!(clear_cookie.contains("oauth_state="));
        assert_eq!(svc.state_mgr().cookie_name, "oauth_state");
    }

    #[test]
    fn test_callback_result_debug_redacts_raw_token() {
        let now = Utc::now();
        let result = OAuthCallbackResult {
            session: Session {
                id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                token_hash: "session-hash".to_string(),
                created_at: now,
                last_active_at: now,
                absolute_expires_at: now,
                session_type: "cookie".to_string(),
                csrf_token: None,
            },
            raw_token: "live-bearer-token".to_string(),
            user: User {
                id: Uuid::new_v4(),
                email: "alice@example.com".to_string(),
                password_hash: OAUTH_UNUSABLE_PASSWORD_HASH.to_string(),
                email_verified: true,
                created_at: now,
                updated_at: now,
            },
            redirect_url: "/".to_string(),
            clear_cookie_header: "oauth_state=; Max-Age=0".to_string(),
            is_linked: false,
            is_created: false,
        };

        let debug = format!("{result:?}");
        assert!(!debug.contains("live-bearer-token"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn callback_outcome_debug_redacts_the_challenge_token() {
        let outcome = OAuthCallbackOutcome::TwoFactorRequired {
            challenge_token: "live-challenge-token".to_string(),
            clear_cookie_header: "oauth_state=; Max-Age=0".to_string(),
        };

        let debug = format!("{outcome:?}");
        assert!(!debug.contains("live-challenge-token"));
        assert!(debug.contains("[REDACTED]"));
        // Not secret: the same header is printed for a completed login.
        assert!(debug.contains("oauth_state=; Max-Age=0"));
    }
}
