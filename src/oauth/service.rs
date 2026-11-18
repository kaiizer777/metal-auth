use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;
use crate::db::models::{OAuthAccount, Session, User};
use crate::error::AppError;
use crate::oauth::pkce::generate_pkce;
use crate::oauth::provider::{
    OAuthProvider, SUPPORTED_PROVIDERS, UserInfo, build_oauth_http_client, create_provider,
};
use crate::oauth::state::OAuthStateManager;
use crate::session::SessionService;

/// Result envelope returned by [`OAuthService::handle_callback_extended`].
#[derive(Debug, Clone)]
pub struct OAuthCallbackResult {
    pub session: Session,
    pub raw_token: String,
    pub user: User,
    pub redirect_url: String,
    pub clear_cookie_header: String,
    pub is_linked: bool,
    pub is_created: bool,
}

/// Service managing OAuth identity delegation, account linking, and pre-hijacking defense.
#[derive(Clone)]
pub struct OAuthService {
    db: PgPool,
    providers: HashMap<String, Arc<dyn OAuthProvider>>,
    state_mgr: OAuthStateManager,
    session_service: Arc<SessionService>,
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

impl OAuthService {
    /// Constructs a new OAuth service instance with active providers instantiated
    /// from application configuration.
    pub fn new(
        db: PgPool,
        config: Arc<Config>,
        session_service: Arc<SessionService>,
    ) -> Result<Self, AppError> {
        let http_client = build_oauth_http_client()?;
        let mut providers: HashMap<String, Arc<dyn OAuthProvider>> = HashMap::new();

        for id in SUPPORTED_PROVIDERS {
            if let Some(cfg) = config.oauth.providers.get(*id)
                && cfg.enabled
            {
                let provider = create_provider(id, cfg, http_client.clone())?;
                providers.insert((*id).to_string(), provider);
            }
        }

        let state_mgr = OAuthStateManager::new(&config.oauth, config.session.cookie_secure);

        Ok(Self {
            db,
            providers,
            state_mgr,
            session_service,
            config,
        })
    }

    /// Constructs a service with custom/mock providers for testing.
    pub fn with_providers(
        db: PgPool,
        config: Arc<Config>,
        session_service: Arc<SessionService>,
        providers: HashMap<String, Arc<dyn OAuthProvider>>,
    ) -> Self {
        let state_mgr = OAuthStateManager::new(&config.oauth, config.session.cookie_secure);
        Self {
            db,
            providers,
            state_mgr,
            session_service,
            config,
        }
    }

    /// Constructs a service with explicit state manager.
    pub fn new_with_manager(
        db: PgPool,
        providers: HashMap<String, Arc<dyn OAuthProvider>>,
        state_mgr: OAuthStateManager,
        session_service: Arc<SessionService>,
        config: Arc<Config>,
    ) -> Self {
        Self {
            db,
            providers,
            state_mgr,
            session_service,
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

        tracing::info!(
            event = "oauth_initiate",
            provider = provider_id,
        );

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

    /// Handles an incoming OAuth callback, returning `(Session, User, clear_cookie_header)`.
    pub async fn handle_callback(
        &self,
        provider_id: &str,
        code: &str,
        state_param: &str,
        cookie_header: Option<&str>,
    ) -> Result<(Session, User, String), AppError> {
        let result = self
            .handle_callback_extended(
                provider_id,
                code,
                state_param,
                cookie_header,
                "cookie",
                None,
                None,
            )
            .await?;
        Ok((result.session, result.user, result.clear_cookie_header))
    }

    /// Handles an incoming OAuth callback returning the full [`OAuthCallbackResult`].
    pub async fn handle_callback_extended(
        &self,
        provider_id: &str,
        code: &str,
        state_param: &str,
        cookie_header: Option<&str>,
        session_type: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<OAuthCallbackResult, AppError> {
        let clear_cookie_str = self.state_mgr.build_clear_cookie();

        // 1. Validate state parameter against signed cookie
        let cookie_header = match cookie_header {
            Some(h) if !h.trim().is_empty() => h,
            _ => {
                tracing::info!(
                    event = "oauth_callback_failure",
                    provider = provider_id,
                    reason = "state_missing",
                );
                return Err(AppError::OAuthStateInvalid);
            }
        };

        let payload = match self.state_mgr.validate(cookie_header, state_param, provider_id) {
            Ok(p) => p,
            Err(e) => {
                tracing::info!(
                    event = "oauth_callback_failure",
                    provider = provider_id,
                    reason = "state_invalid",
                );
                return Err(e);
            }
        };

        // 2. Validate authorization code
        if code.trim().is_empty() {
            tracing::info!(
                event = "oauth_callback_failure",
                provider = provider_id,
                reason = "code_invalid",
            );
            return Err(AppError::OAuthCodeInvalid);
        }

        // 3. Obtain provider and exchange code for tokens
        let provider = match self.provider(provider_id) {
            Ok(p) => p,
            Err(e) => {
                tracing::info!(
                    event = "oauth_callback_failure",
                    provider = provider_id,
                    reason = "provider_not_found",
                );
                return Err(e);
            }
        };

        let tokens = match provider.exchange_code(code, &payload.code_verifier).await {
            Ok(t) => t,
            Err(e) => {
                tracing::info!(
                    event = "oauth_callback_failure",
                    provider = provider_id,
                    reason = "exchange_failed",
                );
                return Err(e);
            }
        };

        // 4. Fetch user profile from provider
        let user_info = match provider.get_user_info(&tokens).await {
            Ok(u) => u,
            Err(e) => {
                tracing::info!(
                    event = "oauth_callback_failure",
                    provider = provider_id,
                    reason = "userinfo_failed",
                );
                return Err(e);
            }
        };

        // 5. PRE-HIJACKING GUARD 1 (OWASP ASVS 5.0 L1):
        // Email must be explicitly verified by identity provider before touching database.
        if !user_info.email_verified {
            tracing::info!(
                event = "oauth_callback_failure",
                provider = provider_id,
                reason = "email_unverified",
            );
            return Err(AppError::OAuthEmailUnverified);
        }

        if user_info.email.trim().is_empty() {
            tracing::info!(
                event = "oauth_callback_failure",
                provider = provider_id,
                reason = "email_empty",
            );
            return Err(AppError::OAuthProviderError);
        }

        // 6. Database linking / user provisioning
        let (user, is_linked, is_created) = self.link_or_create(provider_id, &user_info).await?;

        // 7. Issue session via SessionService
        let (session, raw_token) = self
            .session_service
            .create_session(user.id, session_type, ip, user_agent)
            .await?;

        tracing::info!(
            event = "oauth_callback_success",
            provider = provider_id,
            user_id = %user.id,
            session_id_hash = %session.token_hash,
        );
        if is_linked {
            tracing::info!(
                event = "oauth_account_linked",
                provider = provider_id,
                user_id = %user.id,
            );
        }
        if is_created {
            tracing::info!(
                event = "oauth_user_created",
                provider = provider_id,
                user_id = %user.id,
                email = %user.email,
            );
        }

        let redirect_url = payload.redirect_url.unwrap_or_else(|| "/".to_string());

        Ok(OAuthCallbackResult {
            session,
            raw_token,
            user,
            redirect_url,
            clear_cookie_header: clear_cookie_str,
            is_linked,
            is_created,
        })
    }

    /// Links an identity or creates a new user, returning `(User, is_linked, is_created)`.
    async fn link_or_create(
        &self,
        provider_id: &str,
        user_info: &UserInfo,
    ) -> Result<(User, bool, bool), AppError> {
        // Case A: Identity already linked to a user
        let existing_link: Option<OAuthAccount> = sqlx::query_as::<_, OAuthAccount>(
            "SELECT id, user_id, provider_id, provider_user_id, email, created_at, updated_at FROM oauth_accounts WHERE provider_id = $1 AND provider_user_id = $2"
        )
        .bind(provider_id)
        .bind(&user_info.provider_user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(AppError::Database)?;

        if let Some(link) = existing_link {
            let user: User = sqlx::query_as::<_, User>(
                "SELECT id, email, password_hash, email_verified, created_at, updated_at FROM users WHERE id = $1"
            )
            .bind(link.user_id)
            .fetch_optional(&self.db)
            .await
            .map_err(AppError::Database)?
            .ok_or(AppError::NotFound)?;

            return Ok((user, false, false));
        }

        // Case B: No existing link found; check local account by normalized email
        let existing_user: Option<User> = sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, email_verified, created_at, updated_at FROM users WHERE LOWER(email) = LOWER($1)"
        )
        .bind(&user_info.email)
        .fetch_optional(&self.db)
        .await
        .map_err(AppError::Database)?;

        // Subcase B1: Existing user matches email
        if let Some(existing) = existing_user {
            // PRE-HIJACKING COLLISION GUARD 2:
            // Never link federated identity onto an unverified local account.
            if !existing.email_verified {
                tracing::warn!(
                    event = "oauth_pre_hijack_prevented",
                    email = %user_info.email,
                    provider = provider_id,
                    "rejected linking to unverified local account"
                );
                return Err(AppError::OAuthAccountLinkConflict);
            }

            let link_id = Uuid::new_v4();
            let now = Utc::now();
            let insert_res = sqlx::query(
                "INSERT INTO oauth_accounts (id, user_id, provider_id, provider_user_id, email, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)"
            )
            .bind(link_id)
            .bind(existing.id)
            .bind(provider_id)
            .bind(&user_info.provider_user_id)
            .bind(&user_info.email)
            .bind(now)
            .bind(now)
            .execute(&self.db)
            .await;

            match insert_res {
                Ok(_) => return Ok((existing, true, false)),
                Err(e) if is_unique_violation(&e) => {
                    return self
                        .relink_existing(provider_id, &user_info.provider_user_id)
                        .await;
                }
                Err(e) => return Err(AppError::Database(e)),
            }
        }

        // Subcase B2: No existing user; atomically create verified user and link row
        let mut tx = self.db.begin().await.map_err(AppError::Database)?;
        let user_id = Uuid::new_v4();
        let link_id = Uuid::new_v4();
        let now = Utc::now();
        let unusable_hash = "$unusable$oauth$";

        let user_res = sqlx::query(
            "INSERT INTO users (id, email, password_hash, email_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)"
        )
        .bind(user_id)
        .bind(&user_info.email)
        .bind(unusable_hash)
        .bind(true)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await;

        if let Err(e) = user_res {
            let _ = tx.rollback().await;
            if is_unique_violation(&e) {
                return self.link_raced_user(provider_id, user_info).await;
            }
            return Err(AppError::Database(e));
        }

        let link_res = sqlx::query(
            "INSERT INTO oauth_accounts (id, user_id, provider_id, provider_user_id, email, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(link_id)
        .bind(user_id)
        .bind(provider_id)
        .bind(&user_info.provider_user_id)
        .bind(&user_info.email)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await;

        if let Err(e) = link_res {
            let _ = tx.rollback().await;
            if is_unique_violation(&e) {
                return self
                    .relink_existing(provider_id, &user_info.provider_user_id)
                    .await;
            }
            return Err(AppError::Database(e));
        }

        tx.commit().await.map_err(AppError::Database)?;

        let new_user = User {
            id: user_id,
            email: user_info.email.clone(),
            password_hash: unusable_hash.to_string(),
            email_verified: true,
            created_at: now,
            updated_at: now,
        };

        Ok((new_user, true, true))
    }

    /// Relinks an identity row that won a concurrent insert race.
    async fn relink_existing(
        &self,
        provider_id: &str,
        provider_user_id: &str,
    ) -> Result<(User, bool, bool), AppError> {
        let link: OAuthAccount = sqlx::query_as::<_, OAuthAccount>(
            "SELECT id, user_id, provider_id, provider_user_id, email, created_at, updated_at FROM oauth_accounts WHERE provider_id = $1 AND provider_user_id = $2"
        )
        .bind(provider_id)
        .bind(provider_user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(AppError::Database)?
        .ok_or(AppError::NotFound)?;

        let user: User = sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, email_verified, created_at, updated_at FROM users WHERE id = $1"
        )
        .bind(link.user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(AppError::Database)?
        .ok_or(AppError::NotFound)?;

        Ok((user, false, false))
    }

    /// Converges after losing a concurrent user creation race.
    async fn link_raced_user(
        &self,
        provider_id: &str,
        user_info: &UserInfo,
    ) -> Result<(User, bool, bool), AppError> {
        let existing: User = sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, email_verified, created_at, updated_at FROM users WHERE LOWER(email) = LOWER($1)"
        )
        .bind(&user_info.email)
        .fetch_optional(&self.db)
        .await
        .map_err(AppError::Database)?
        .ok_or(AppError::NotFound)?;

        if !existing.email_verified {
            return Err(AppError::OAuthAccountLinkConflict);
        }

        let link_id = Uuid::new_v4();
        let now = Utc::now();
        let insert_res = sqlx::query(
            "INSERT INTO oauth_accounts (id, user_id, provider_id, provider_user_id, email, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(link_id)
        .bind(existing.id)
        .bind(provider_id)
        .bind(&user_info.provider_user_id)
        .bind(&user_info.email)
        .bind(now)
        .bind(now)
        .execute(&self.db)
        .await;

        match insert_res {
            Ok(_) => Ok((existing, true, false)),
            Err(e) if is_unique_violation(&e) => {
                self.relink_existing(provider_id, &user_info.provider_user_id)
                    .await
            }
            Err(e) => Err(AppError::Database(e)),
        }
    }

    /// Links an additional OAuth identity to an authenticated user.
    pub async fn link_account(
        &self,
        user_id: Uuid,
        provider_id: &str,
        code: &str,
        state_param: &str,
        cookie_header: Option<&str>,
    ) -> Result<(), AppError> {
        self.link_account_identity(user_id, provider_id, code, state_param, cookie_header)
            .await?;
        Ok(())
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

        if code.trim().is_empty() {
            return Err(AppError::OAuthCodeInvalid);
        }

        let provider = self.provider(provider_id)?;
        let tokens = provider.exchange_code(code, &payload.code_verifier).await?;
        let user_info = provider.get_user_info(&tokens).await?;

        // 1. Provider email must be verified
        if !user_info.email_verified {
            return Err(AppError::OAuthEmailUnverified);
        }

        // 2. User must exist and have verified status
        let user: Option<User> = sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, email_verified, created_at, updated_at FROM users WHERE id = $1"
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(AppError::Database)?;

        let user = user.ok_or(AppError::NotFound)?;
        if !user.email_verified {
            return Err(AppError::OAuthAccountLinkConflict);
        }

        // 3. Ensure identity is not linked to another user
        let existing_link: Option<OAuthAccount> = sqlx::query_as::<_, OAuthAccount>(
            "SELECT id, user_id, provider_id, provider_user_id, email, created_at, updated_at FROM oauth_accounts WHERE provider_id = $1 AND provider_user_id = $2"
        )
        .bind(provider_id)
        .bind(&user_info.provider_user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(AppError::Database)?;

        if let Some(link) = existing_link {
            if link.user_id != user_id {
                return Err(AppError::OAuthAccountLinkConflict);
            }
            return Ok(link);
        }

        let link_id = Uuid::new_v4();
        let now = Utc::now();
        let row = OAuthAccount {
            id: link_id,
            user_id,
            provider_id: provider_id.to_string(),
            provider_user_id: user_info.provider_user_id,
            email: user_info.email,
            created_at: now,
            updated_at: now,
        };

        sqlx::query(
            "INSERT INTO oauth_accounts (id, user_id, provider_id, provider_user_id, email, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(row.id)
        .bind(row.user_id)
        .bind(&row.provider_id)
        .bind(&row.provider_user_id)
        .bind(&row.email)
        .bind(row.created_at)
        .bind(row.updated_at)
        .execute(&self.db)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                AppError::OAuthAccountLinkConflict
            } else {
                AppError::Database(e)
            }
        })?;

        tracing::info!(
            event = "oauth_account_linked",
            provider = provider_id,
            user_id = %user_id,
        );

        Ok(row)
    }

    /// Unlinks an external provider, preventing account lockout if no usable password remains.
    pub async fn unlink_account(&self, user_id: Uuid, provider_id: &str) -> Result<(), AppError> {
        let user = sqlx::query_as::<_, (String,)>(
            "SELECT password_hash FROM users WHERE id = $1"
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(AppError::Database)?
        .ok_or(AppError::NotFound)?;

        let target_link: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM oauth_accounts WHERE user_id = $1 AND provider_id = $2"
        )
        .bind(user_id)
        .bind(provider_id)
        .fetch_optional(&self.db)
        .await
        .map_err(AppError::Database)?;

        if target_link.is_none() {
            return Err(AppError::NotFound);
        }

        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM oauth_accounts WHERE user_id = $1"
        )
        .bind(user_id)
        .fetch_one(&self.db)
        .await
        .map_err(AppError::Database)?;

        let password_hash = &user.0;
        let has_usable_password =
            !password_hash.is_empty() && !password_hash.starts_with("$unusable$");

        // Lockout prevention: user must retain a usable password or at least 1 other linked provider
        if !has_usable_password && count.0 <= 1 {
            return Err(AppError::ValidationError(
                "Cannot unlink the only login method".to_string(),
            ));
        }

        sqlx::query("DELETE FROM oauth_accounts WHERE user_id = $1 AND provider_id = $2")
            .bind(user_id)
            .bind(provider_id)
            .execute(&self.db)
            .await
            .map_err(AppError::Database)?;

        tracing::info!(
            event = "oauth_account_unlinked",
            provider = provider_id,
            user_id = %user_id,
        );

        Ok(())
    }

    /// Lists all external identities linked to the given user.
    pub async fn list_linked_accounts(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<OAuthAccount>, AppError> {
        let accounts = sqlx::query_as::<_, OAuthAccount>(
            "SELECT id, user_id, provider_id, provider_user_id, email, created_at, updated_at FROM oauth_accounts WHERE user_id = $1 ORDER BY created_at ASC"
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(AppError::Database)?;

        Ok(accounts)
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
            format!(
                "https://mock.provider/auth?state={state}&code_challenge={code_challenge}"
            )
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

        let mut providers: HashMap<String, Arc<dyn OAuthProvider>> = HashMap::new();
        providers.insert(
            "google".to_string(),
            Arc::new(MockProvider {
                id: "google",
                user_info,
                exchange_fail,
            }),
        );

        OAuthService::with_providers(pool, cfg_arc, session_service, providers)
    }

    #[tokio::test]
    async fn test_provider_lookup_and_not_found() {
        let user_info = UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog_123".to_string(),
            email: "alice@example.com".to_string(),
            email_verified: true,
            name: Some("Alice".to_string()),
            avatar_url: None,
        };
        let svc = test_service_with_mock(user_info, false);

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
        let user_info = UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog_123".to_string(),
            email: "alice@example.com".to_string(),
            email_verified: true,
            name: Some("Alice".to_string()),
            avatar_url: None,
        };
        let svc = test_service_with_mock(user_info, false);

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
        let user_info = UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog_123".to_string(),
            email: "alice@example.com".to_string(),
            email_verified: true,
            name: None,
            avatar_url: None,
        };
        let svc = test_service_with_mock(user_info, false);

        // Missing cookie
        let res = svc.handle_callback("google", "code123", "state123", None).await;
        assert!(matches!(res, Err(AppError::OAuthStateInvalid)));

        // Tampered cookie
        let res = svc
            .handle_callback("google", "code123", "state123", Some("oauth_state=invalid.signature"))
            .await;
        assert!(matches!(res, Err(AppError::OAuthStateInvalid)));
    }

    #[tokio::test]
    async fn test_handle_callback_empty_code_rejection() {
        let user_info = UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog_123".to_string(),
            email: "alice@example.com".to_string(),
            email_verified: true,
            name: None,
            avatar_url: None,
        };
        let svc = test_service_with_mock(user_info, false);

        let (auth_url, set_cookie) = svc
            .get_authorization_url("google", None)
            .expect("init flow");
        let state_token = auth_url.split("state=").nth(1).unwrap().split('&').next().unwrap();

        let res = svc
            .handle_callback("google", "", state_token, Some(&set_cookie))
            .await;
        assert!(matches!(res, Err(AppError::OAuthCodeInvalid)));
    }

    #[tokio::test]
    async fn test_handle_callback_pre_hijacking_guard_rejects_unverified_provider_email() {
        let unverified_user_info = UserInfo {
            provider_id: "google".to_string(),
            provider_user_id: "goog_unverified".to_string(),
            email: "victim@example.com".to_string(),
            email_verified: false, // Provider reports unverified!
            name: None,
            avatar_url: None,
        };
        let svc = test_service_with_mock(unverified_user_info, false);

        let (auth_url, set_cookie) = svc
            .get_authorization_url("google", None)
            .expect("init flow");
        let state_token = auth_url.split("state=").nth(1).unwrap().split('&').next().unwrap();

        // Must reject with 400 OAuthEmailUnverified BEFORE any database queries
        let res = svc
            .handle_callback("google", "valid_code", state_token, Some(&set_cookie))
            .await;
        assert!(matches!(res, Err(AppError::OAuthEmailUnverified)));
    }
}
