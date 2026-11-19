use std::str::FromStr;
use std::time::Duration;

use crate::error::ConfigError;

pub const DEFAULT_PORT: u16 = 3000;
pub const DEFAULT_MAX_CONNECTIONS: u32 = 25;
pub const DEFAULT_MIN_CONNECTIONS: u32 = 2;
pub const DEFAULT_EMAIL_DISPATCH_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_OUTBOX_POLL_INTERVAL_MS: u64 = 1000;
pub const DEFAULT_OUTBOX_BATCH_SIZE: u32 = 50;
pub const DEFAULT_OUTBOX_MAX_RETRIES: u32 = 5;
pub const DEFAULT_OUTBOX_INITIAL_BACKOFF_SECS: u64 = 1;
pub const DEFAULT_OUTBOX_MAX_BACKOFF_SECS: u64 = 300;
pub const DEFAULT_OUTBOX_SENT_RETENTION_SECS: u64 = 7 * 24 * 3600; // 7 days (604,800 s)

// ─── Phase 1 — Infra Config ──────────────────────────────────────────────────

#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    pub database_url: String,
    pub port: u16,

    // CORS
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,

    // DB pool
    pub max_connections: u32,
    pub min_connections: u32,

    // Phase 2: email hook dispatch
    pub base_url: String,
    pub email_dispatch_timeout: Duration,
    /// Whether email dispatch blocks the caller until delivery completes.
    ///
    /// Inert: delivery is always detached, so this flag cannot change request latency.
    /// [`Config::validate`] rejects `false` so a deployment still setting it fails at boot
    /// instead of silently keeping a dead knob.
    pub async_email_dispatch: bool,

    // Outbox worker configuration
    pub outbox_poll_interval: Duration,
    pub outbox_batch_size: u32,
    pub outbox_max_retries: u32,
    pub outbox_initial_backoff: Duration,
    pub outbox_max_backoff: Duration,
    pub outbox_sent_retention: Duration,

    // Phase 4: Session & Rate Limit
    pub session: SessionConfig,
    pub rate_limit: RateLimitConfig,

    // Phase 6: OAuth
    pub oauth: OAuthConfig,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &"[REDACTED]")
            .field("port", &self.port)
            .field("allowed_origins", &self.allowed_origins)
            .field("allowed_methods", &self.allowed_methods)
            .field("allowed_headers", &self.allowed_headers)
            .field("max_connections", &self.max_connections)
            .field("min_connections", &self.min_connections)
            .field("base_url", &"[REDACTED]")
            .field("email_dispatch_timeout", &self.email_dispatch_timeout)
            .field("async_email_dispatch", &self.async_email_dispatch)
            .field("outbox_poll_interval", &self.outbox_poll_interval)
            .field("outbox_batch_size", &self.outbox_batch_size)
            .field("outbox_max_retries", &self.outbox_max_retries)
            .field("outbox_initial_backoff", &self.outbox_initial_backoff)
            .field("outbox_max_backoff", &self.outbox_max_backoff)
            .field("outbox_sent_retention", &self.outbox_sent_retention)
            .field("session", &self.session)
            .field("rate_limit", &self.rate_limit)
            .field("oauth", &self.oauth)
            .finish()
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.database_url.trim().is_empty() {
            return Err(ConfigError::InvalidValue {
                field: "database_url",
                reason: "must not be empty",
            });
        }
        if self.max_connections == 0 {
            return Err(ConfigError::InvalidValue {
                field: "max_connections",
                reason: "must be greater than 0",
            });
        }
        if self.min_connections > self.max_connections {
            return Err(ConfigError::InvalidValue {
                field: "min_connections",
                reason: "must not exceed max_connections",
            });
        }
        if self.base_url.trim().is_empty() {
            return Err(ConfigError::MissingEnvVar("BASE_URL"));
        }
        let uri = self
            .base_url
            .parse::<axum::http::Uri>()
            .map_err(|_| ConfigError::InvalidEnvVar("BASE_URL"))?;
        // Fragments would survive into email-link construction; `#` can only
        // start a fragment here since it must be percent-encoded elsewhere.
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || uri.authority().is_none()
            || uri.query().is_some()
            || self.base_url.contains('#')
            || uri.authority().is_some_and(|a| a.as_str().contains('@'))
        {
            return Err(ConfigError::InvalidEnvVar("BASE_URL"));
        }
        if self.email_dispatch_timeout == Duration::ZERO {
            return Err(ConfigError::InvalidEnvVar("EMAIL_DISPATCH_TIMEOUT_SECS"));
        }
        if !self.async_email_dispatch {
            return Err(ConfigError::InvalidValue {
                field: "ASYNC_EMAIL_DISPATCH",
                reason: "must be true: the inline dispatch path no longer exists, unset ASYNC_EMAIL_DISPATCH or set it to true",
            });
        }
        if self.outbox_poll_interval == Duration::ZERO {
            return Err(ConfigError::InvalidValue {
                field: "outbox_poll_interval",
                reason: "must be greater than 0",
            });
        }
        if self.outbox_batch_size == 0 {
            return Err(ConfigError::InvalidValue {
                field: "outbox_batch_size",
                reason: "must be greater than 0",
            });
        }
        if self.outbox_max_retries == 0 {
            return Err(ConfigError::InvalidValue {
                field: "outbox_max_retries",
                reason: "must be at least 1",
            });
        }
        if self.outbox_initial_backoff == Duration::ZERO {
            return Err(ConfigError::InvalidValue {
                field: "outbox_initial_backoff",
                reason: "must be greater than 0",
            });
        }
        if self.outbox_max_backoff < self.outbox_initial_backoff {
            return Err(ConfigError::InvalidValue {
                field: "outbox_max_backoff",
                reason: "must be greater than or equal to outbox_initial_backoff",
            });
        }
        if self.outbox_sent_retention == Duration::ZERO {
            return Err(ConfigError::InvalidValue {
                field: "outbox_sent_retention",
                reason: "must be greater than 0",
            });
        }
        for origin in &self.allowed_origins {
            let trimmed = origin.trim();
            if trimmed.ends_with('/') {
                return Err(ConfigError::InvalidValue {
                    field: "allowed_origins",
                    reason: "must not contain trailing slash",
                });
            }
            if trimmed != "*" {
                axum::http::HeaderValue::from_str(trimmed).map_err(|source| {
                    ConfigError::InvalidOrigin {
                        value: trimmed.to_string(),
                        source,
                    }
                })?;
            }
        }
        for method in &self.allowed_methods {
            let trimmed = method.trim();
            axum::http::Method::from_str(trimmed).map_err(|source| ConfigError::InvalidMethod {
                value: trimmed.to_string(),
                source,
            })?;
        }
        for header in &self.allowed_headers {
            let trimmed = header.trim();
            axum::http::header::HeaderName::from_str(trimmed).map_err(|source| {
                ConfigError::InvalidHeader {
                    value: trimmed.to_string(),
                    source,
                }
            })?;
        }
        self.session.validate()?;
        self.rate_limit.validate()?;
        self.oauth.validate()?;
        Ok(())
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();
        Self::from_lookup(|k| std::env::var(k))
    }

    pub fn from_lookup<F>(lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Result<String, std::env::VarError>,
    {
        let database_url = match lookup("DATABASE_URL") {
            Ok(val) => val,
            Err(std::env::VarError::NotPresent) => {
                return Err(ConfigError::MissingEnvVar("DATABASE_URL"));
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("DATABASE_URL"));
            }
        };
        let port = match lookup("PORT") {
            Ok(val) => val.parse::<u16>().map_err(ConfigError::InvalidPort)?,
            Err(std::env::VarError::NotPresent) => DEFAULT_PORT,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("PORT"));
            }
        };

        let allowed_origins = match lookup("ALLOWED_ORIGINS") {
            Ok(val) => parse_allowed_origins_str(&val),
            Err(std::env::VarError::NotPresent) => Vec::new(),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("ALLOWED_ORIGINS"));
            }
        };

        let allowed_headers = match lookup("ALLOWED_HEADERS") {
            Ok(val) => parse_allowed_headers_str(&val),
            Err(std::env::VarError::NotPresent) => default_allowed_headers(),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("ALLOWED_HEADERS"));
            }
        };

        let base_url = match lookup("BASE_URL") {
            Ok(val) => val,
            Err(std::env::VarError::NotPresent) => {
                return Err(ConfigError::MissingEnvVar("BASE_URL"));
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("BASE_URL"));
            }
        };

        let email_dispatch_timeout = match lookup("EMAIL_DISPATCH_TIMEOUT_SECS") {
            Ok(val) => {
                let secs: u64 = val
                    .parse()
                    .map_err(|_| ConfigError::InvalidEnvVar("EMAIL_DISPATCH_TIMEOUT_SECS"))?;
                if secs == 0 {
                    return Err(ConfigError::InvalidEnvVar("EMAIL_DISPATCH_TIMEOUT_SECS"));
                }
                Duration::from_secs(secs)
            }
            Err(std::env::VarError::NotPresent) => {
                Duration::from_secs(DEFAULT_EMAIL_DISPATCH_TIMEOUT_SECS)
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("EMAIL_DISPATCH_TIMEOUT_SECS"));
            }
        };

        let async_email_dispatch = match lookup("ASYNC_EMAIL_DISPATCH") {
            Ok(val) => val
                .parse::<bool>()
                .map_err(|_| ConfigError::InvalidEnvVar("ASYNC_EMAIL_DISPATCH"))?,
            Err(std::env::VarError::NotPresent) => true,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("ASYNC_EMAIL_DISPATCH"));
            }
        };

        let outbox_poll_interval = match lookup("OUTBOX_POLL_INTERVAL_MS") {
            Ok(val) => {
                let ms: u64 = val
                    .parse()
                    .map_err(|_| ConfigError::InvalidEnvVar("OUTBOX_POLL_INTERVAL_MS"))?;
                if ms == 0 {
                    return Err(ConfigError::InvalidEnvVar("OUTBOX_POLL_INTERVAL_MS"));
                }
                Duration::from_millis(ms)
            }
            Err(std::env::VarError::NotPresent) => {
                Duration::from_millis(DEFAULT_OUTBOX_POLL_INTERVAL_MS)
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("OUTBOX_POLL_INTERVAL_MS"));
            }
        };

        let outbox_batch_size = match lookup("OUTBOX_BATCH_SIZE") {
            Ok(val) => {
                let size: u32 = val
                    .parse()
                    .map_err(|_| ConfigError::InvalidEnvVar("OUTBOX_BATCH_SIZE"))?;
                if size == 0 {
                    return Err(ConfigError::InvalidEnvVar("OUTBOX_BATCH_SIZE"));
                }
                size
            }
            Err(std::env::VarError::NotPresent) => DEFAULT_OUTBOX_BATCH_SIZE,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("OUTBOX_BATCH_SIZE"));
            }
        };

        let outbox_max_retries = match lookup("OUTBOX_MAX_RETRIES") {
            Ok(val) => {
                let retries: u32 = val
                    .parse()
                    .map_err(|_| ConfigError::InvalidEnvVar("OUTBOX_MAX_RETRIES"))?;
                if retries == 0 {
                    return Err(ConfigError::InvalidEnvVar("OUTBOX_MAX_RETRIES"));
                }
                retries
            }
            Err(std::env::VarError::NotPresent) => DEFAULT_OUTBOX_MAX_RETRIES,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("OUTBOX_MAX_RETRIES"));
            }
        };

        let outbox_initial_backoff = match lookup("OUTBOX_INITIAL_BACKOFF_SECS") {
            Ok(val) => {
                let secs: u64 = val
                    .parse()
                    .map_err(|_| ConfigError::InvalidEnvVar("OUTBOX_INITIAL_BACKOFF_SECS"))?;
                if secs == 0 {
                    return Err(ConfigError::InvalidEnvVar("OUTBOX_INITIAL_BACKOFF_SECS"));
                }
                Duration::from_secs(secs)
            }
            Err(std::env::VarError::NotPresent) => {
                Duration::from_secs(DEFAULT_OUTBOX_INITIAL_BACKOFF_SECS)
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("OUTBOX_INITIAL_BACKOFF_SECS"));
            }
        };

        let outbox_max_backoff = match lookup("OUTBOX_MAX_BACKOFF_SECS") {
            Ok(val) => {
                let secs: u64 = val
                    .parse()
                    .map_err(|_| ConfigError::InvalidEnvVar("OUTBOX_MAX_BACKOFF_SECS"))?;
                if secs == 0 {
                    return Err(ConfigError::InvalidEnvVar("OUTBOX_MAX_BACKOFF_SECS"));
                }
                Duration::from_secs(secs)
            }
            Err(std::env::VarError::NotPresent) => {
                Duration::from_secs(DEFAULT_OUTBOX_MAX_BACKOFF_SECS)
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("OUTBOX_MAX_BACKOFF_SECS"));
            }
        };

        let outbox_sent_retention = match lookup("OUTBOX_SENT_RETENTION_SECS") {
            Ok(val) => {
                let secs: u64 = val
                    .parse()
                    .map_err(|_| ConfigError::InvalidEnvVar("OUTBOX_SENT_RETENTION_SECS"))?;
                if secs == 0 {
                    return Err(ConfigError::InvalidEnvVar("OUTBOX_SENT_RETENTION_SECS"));
                }
                Duration::from_secs(secs)
            }
            Err(std::env::VarError::NotPresent) => {
                Duration::from_secs(DEFAULT_OUTBOX_SENT_RETENTION_SECS)
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("OUTBOX_SENT_RETENTION_SECS"));
            }
        };

        let cookie_name = match lookup("SESSION_COOKIE_NAME") {
            Ok(val) => val,
            Err(std::env::VarError::NotPresent) => default_cookie_name(),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("SESSION_COOKIE_NAME"));
            }
        };
        let cookie_domain = match lookup("SESSION_COOKIE_DOMAIN") {
            Ok(val) => {
                let trimmed = val.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("SESSION_COOKIE_DOMAIN"));
            }
        };
        let cookie_path = match lookup("SESSION_COOKIE_PATH") {
            Ok(val) => {
                let trimmed = val.trim();
                if trimmed.is_empty() {
                    default_cookie_path()
                } else {
                    trimmed.to_string()
                }
            }
            Err(std::env::VarError::NotPresent) => default_cookie_path(),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("SESSION_COOKIE_PATH"));
            }
        };
        let cookie_same_site = match lookup("SESSION_COOKIE_SAME_SITE") {
            Ok(val) => val,
            Err(std::env::VarError::NotPresent) => default_cookie_same_site(),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("SESSION_COOKIE_SAME_SITE"));
            }
        };
        let cookie_secure =
            parse_env_bool(&lookup, "SESSION_COOKIE_SECURE", default_cookie_secure())?;
        let idle_timeout_secs = parse_env_from_str(
            &lookup,
            "SESSION_IDLE_TIMEOUT_SECS",
            default_idle_timeout_secs(),
        )?;
        // Legacy alias: SESSION_ABSOLUTE_LIFETIME_SECS wins when both are set;
        // SESSION_ABSOLUTE_TIMEOUT_SECS is only read as a fallback and an
        // invalid fallback value is rejected rather than ignored.
        let absolute_lifetime_secs = match lookup("SESSION_ABSOLUTE_LIFETIME_SECS") {
            Ok(val) => val.parse::<u64>().map_err(|_| ConfigError::InvalidValue {
                field: "absolute_lifetime_secs",
                reason: "must be a valid integer",
            })?,
            Err(std::env::VarError::NotPresent) => match lookup("SESSION_ABSOLUTE_TIMEOUT_SECS") {
                Ok(val) => val.parse::<u64>().map_err(|_| ConfigError::InvalidValue {
                    field: "absolute_lifetime_secs",
                    reason: "must be a valid integer",
                })?,
                Err(std::env::VarError::NotPresent) => default_absolute_lifetime_secs(),
                Err(std::env::VarError::NotUnicode(_)) => {
                    return Err(ConfigError::NonUnicodeEnvVar(
                        "SESSION_ABSOLUTE_TIMEOUT_SECS",
                    ));
                }
            },
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar(
                    "SESSION_ABSOLUTE_LIFETIME_SECS",
                ));
            }
        };
        let max_active_sessions_per_user = match lookup("SESSION_MAX_ACTIVE_PER_USER") {
            Ok(val) => val
                .parse::<usize>()
                .map_err(|_| ConfigError::InvalidValue {
                    field: "max_active_sessions_per_user",
                    reason: "must be a valid integer",
                })?,
            Err(std::env::VarError::NotPresent) => default_max_active_sessions_per_user(),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("SESSION_MAX_ACTIVE_PER_USER"));
            }
        };
        let session = SessionConfig {
            cookie_name,
            cookie_domain,
            cookie_path,
            cookie_same_site,
            cookie_secure,
            idle_timeout_secs,
            absolute_lifetime_secs,
            max_active_sessions_per_user,
        };

        let rate_limit_enabled =
            parse_env_bool(&lookup, "RATE_LIMIT_ENABLED", default_rate_limit_enabled())?;
        let max_attempts = match lookup("RATE_LIMIT_MAX_ATTEMPTS") {
            Ok(val) => val.parse::<u32>().map_err(|_| ConfigError::InvalidValue {
                field: "max_attempts",
                reason: "must be a valid integer",
            })?,
            Err(std::env::VarError::NotPresent) => default_max_attempts(),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::NonUnicodeEnvVar("RATE_LIMIT_MAX_ATTEMPTS"));
            }
        };
        let window_secs =
            parse_env_from_str(&lookup, "RATE_LIMIT_WINDOW_SECS", default_window_secs())?;
        let login_cooldown_secs = parse_env_from_str(
            &lookup,
            "RATE_LIMIT_LOGIN_COOLDOWN_SECS",
            default_login_cooldown_secs(),
        )?;

        let rate_limit = RateLimitConfig {
            enabled: rate_limit_enabled,
            max_attempts,
            window_secs,
            login_cooldown_secs,
        };

        let oauth_state_secret = lookup_env_or_default(&lookup, "OAUTH_STATE_SECRET", "")?;
        let oauth_state_cookie_name = lookup_env_or_default(
            &lookup,
            "OAUTH_STATE_COOKIE_NAME",
            DEFAULT_OAUTH_STATE_COOKIE_NAME,
        )?;
        let oauth_state_cookie_path = lookup_env_or_default(
            &lookup,
            "OAUTH_STATE_COOKIE_PATH",
            DEFAULT_OAUTH_STATE_COOKIE_PATH,
        )?;
        let oauth_state_ttl_secs = lookup_env_or_default(&lookup, "OAUTH_STATE_TTL_SECS", "600")?
            .parse::<u64>()
            .map_err(|_| ConfigError::InvalidEnvVar("OAUTH_STATE_TTL_SECS"))?;
        let oauth_callback_base_url =
            lookup_env_or_default(&lookup, "OAUTH_CALLBACK_BASE_URL", "")?;

        let mut providers: std::collections::HashMap<String, ProviderConfig> =
            std::collections::HashMap::new();
        for name in SUPPORTED_PROVIDERS {
            let (enabled_key, client_id_key, client_secret_key, redirect_uri_key): (
                &'static str,
                &'static str,
                &'static str,
                &'static str,
            ) = match *name {
                "google" => (
                    "OAUTH_GOOGLE_ENABLED",
                    "OAUTH_GOOGLE_CLIENT_ID",
                    "OAUTH_GOOGLE_CLIENT_SECRET",
                    "OAUTH_GOOGLE_REDIRECT_URI",
                ),
                "github" => (
                    "OAUTH_GITHUB_ENABLED",
                    "OAUTH_GITHUB_CLIENT_ID",
                    "OAUTH_GITHUB_CLIENT_SECRET",
                    "OAUTH_GITHUB_REDIRECT_URI",
                ),
                "apple" => (
                    "OAUTH_APPLE_ENABLED",
                    "OAUTH_APPLE_CLIENT_ID",
                    "OAUTH_APPLE_CLIENT_SECRET",
                    "OAUTH_APPLE_REDIRECT_URI",
                ),
                _ => continue,
            };
            let enabled = lookup_env_or_default(&lookup, enabled_key, "false")?
                .parse::<bool>()
                .map_err(|_| ConfigError::InvalidEnvVar(enabled_key))?;
            let client_id = lookup_env_or_default(&lookup, client_id_key, "")?;
            let client_secret = lookup_env_or_default(&lookup, client_secret_key, "")?;
            let redirect_uri = lookup_env_or_default(&lookup, redirect_uri_key, "")?;
            let (team_id, key_id, private_key) = if *name == "apple" {
                let team_id = lookup_env_or_default(&lookup, "OAUTH_APPLE_TEAM_ID", "")?;
                let key_id = lookup_env_or_default(&lookup, "OAUTH_APPLE_KEY_ID", "")?;
                let private_key = lookup_env_or_default(&lookup, "OAUTH_APPLE_PRIVATE_KEY", "")?;
                (
                    (!team_id.is_empty()).then_some(team_id),
                    (!key_id.is_empty()).then_some(key_id),
                    (!private_key.is_empty()).then_some(private_key),
                )
            } else {
                (None, None, None)
            };
            providers.insert(
                (*name).to_string(),
                ProviderConfig {
                    redirect_uri,
                    client_id,
                    client_secret,
                    scopes: Vec::new(),
                    enabled,
                    team_id,
                    key_id,
                    private_key,
                },
            );
        }

        let oauth = OAuthConfig {
            providers,
            state_cookie_name: oauth_state_cookie_name,
            state_cookie_path: oauth_state_cookie_path,
            state_ttl: Duration::from_secs(oauth_state_ttl_secs),
            state_secret: oauth_state_secret,
            callback_base_url: oauth_callback_base_url,
        };

        let cfg = Self {
            database_url,
            port,
            allowed_origins,
            allowed_methods: vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"]
                .into_iter()
                .map(String::from)
                .collect(),
            allowed_headers,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            min_connections: DEFAULT_MIN_CONNECTIONS,
            base_url,
            email_dispatch_timeout,
            async_email_dispatch,
            outbox_poll_interval,
            outbox_batch_size,
            outbox_max_retries,
            outbox_initial_backoff,
            outbox_max_backoff,
            outbox_sent_retention,
            session,
            rate_limit,
            oauth,
        };

        cfg.validate()?;
        Ok(cfg)
    }
}

/// Canonical origin rule: origins are stored normalized (trimmed, no trailing
/// `/`). The env loader normalizes via this helper; [`Config::validate`]
/// rejects unnormalized programmatic values instead of silently fixing them.
fn parse_allowed_origins_str(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().trim_end_matches('/'))
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

pub(crate) fn default_allowed_headers() -> Vec<String> {
    vec![
        "Authorization".to_string(),
        "Content-Type".to_string(),
        "X-CSRF-Token".to_string(),
    ]
}

fn lookup_env_or_default<F>(
    lookup: &F,
    key: &'static str,
    default: &str,
) -> Result<String, ConfigError>
where
    F: Fn(&str) -> Result<String, std::env::VarError>,
{
    match lookup(key) {
        Ok(val) => Ok(val),
        Err(std::env::VarError::NotPresent) => Ok(default.to_string()),
        Err(std::env::VarError::NotUnicode(_)) => Err(ConfigError::NonUnicodeEnvVar(key)),
    }
}

pub(crate) fn parse_allowed_headers_str(raw: &str) -> Vec<String> {
    if raw.trim().is_empty() {
        return default_allowed_headers();
    }

    let mut headers: Vec<String> = raw
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    if headers.is_empty() {
        return default_allowed_headers();
    }

    if !headers
        .iter()
        .any(|h| h.eq_ignore_ascii_case("x-csrf-token"))
    {
        headers.push("X-CSRF-Token".to_string());
    }

    headers
}

// ─── Phase 3 — Auth-specific configuration ───────────────────────────────────

/// Auth-specific runtime configuration validated at construction time.
///
/// # Validation rules (enforced in `AppConfig::new`, bypassed in `AppConfig::default`)
/// - `argon2_m_cost >= 19456`
/// - `argon2_t_cost >= 2`
/// - `argon2_p_cost >= 1`
/// - `8 <= password_min_len <= password_max_len <= 128`
/// - `900 <= verification_token_ttl_secs <= 3600`
/// - `900 <= reset_token_ttl_secs <= 3600`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppConfig {
    /// Argon2id memory cost in KiB. Default: 65536 (64 MiB — RFC 9106 §4 second option).
    pub argon2_m_cost: u32,
    /// Argon2id time cost (iterations). Default: 3.
    pub argon2_t_cost: u32,
    /// Argon2id parallelism lanes. Default: 4.
    pub argon2_p_cost: u32,
    /// Password minimum length in Unicode code points. Must be >= 8. Default: 8.
    pub password_min_len: usize,
    /// Password maximum length in Unicode code points. Must be <= 128. Default: 128.
    pub password_max_len: usize,
    /// Email verification token TTL in seconds. Range: 900–3600. Default: 1800 (30 min).
    pub verification_token_ttl_secs: u64,
    /// Password reset token TTL in seconds. Range: 900–3600. Default: 900 (15 min).
    pub reset_token_ttl_secs: u64,
    /// Controls whether login is blocked for unverified email addresses. Default: true.
    pub require_email_verification: bool,
}

impl AppConfig {
    /// Validates all configuration bounds per OWASP ASVS 5.0 L1 minimums.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.argon2_m_cost < 19456 {
            return Err(ConfigError::InvalidValue {
                field: "argon2_m_cost",
                reason: "must be at least 19456 KiB",
            });
        }
        if self.argon2_t_cost < 2 {
            return Err(ConfigError::InvalidValue {
                field: "argon2_t_cost",
                reason: "must be at least 2 iterations",
            });
        }
        if self.argon2_p_cost < 1 {
            return Err(ConfigError::InvalidValue {
                field: "argon2_p_cost",
                reason: "must be at least 1 lane",
            });
        }
        if self.password_min_len < 8 {
            return Err(ConfigError::InvalidValue {
                field: "password_min_len",
                reason: "must be at least 8 characters",
            });
        }
        if self.password_max_len > 128 {
            return Err(ConfigError::InvalidValue {
                field: "password_max_len",
                reason: "must not exceed 128 characters",
            });
        }
        if self.password_min_len > self.password_max_len {
            return Err(ConfigError::InvalidValue {
                field: "password_min_len",
                reason: "must not exceed password_max_len",
            });
        }
        if !(900..=3600).contains(&self.verification_token_ttl_secs) {
            return Err(ConfigError::InvalidValue {
                field: "verification_token_ttl_secs",
                reason: "must be between 900 and 3600 seconds",
            });
        }
        if !(900..=3600).contains(&self.reset_token_ttl_secs) {
            return Err(ConfigError::InvalidValue {
                field: "reset_token_ttl_secs",
                reason: "must be between 900 and 3600 seconds",
            });
        }
        Ok(())
    }

    /// Fallible constructor — validates all fields per OWASP ASVS 5.0 L1 minimums.
    ///
    /// Returns typed `ConfigError::InvalidValue` on any out-of-range value.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        argon2_m_cost: u32,
        argon2_t_cost: u32,
        argon2_p_cost: u32,
        password_min_len: usize,
        password_max_len: usize,
        verification_token_ttl_secs: u64,
        reset_token_ttl_secs: u64,
        require_email_verification: bool,
    ) -> Result<Self, ConfigError> {
        let config = Self {
            argon2_m_cost,
            argon2_t_cost,
            argon2_p_cost,
            password_min_len,
            password_max_len,
            verification_token_ttl_secs,
            reset_token_ttl_secs,
            require_email_verification,
        };
        config.validate()?;
        Ok(config)
    }

    /// Load `AppConfig` from a custom key-value lookup function.
    pub fn from_lookup<F>(lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Result<String, std::env::VarError>,
    {
        let defaults = Self::default();

        let argon2_m_cost = parse_env_from_str(&lookup, "ARGON2_M_COST", defaults.argon2_m_cost)?;
        let argon2_t_cost = parse_env_from_str(&lookup, "ARGON2_T_COST", defaults.argon2_t_cost)?;
        let argon2_p_cost = parse_env_from_str(&lookup, "ARGON2_P_COST", defaults.argon2_p_cost)?;
        let password_min_len =
            parse_env_from_str(&lookup, "PASSWORD_MIN_LEN", defaults.password_min_len)?;
        let password_max_len =
            parse_env_from_str(&lookup, "PASSWORD_MAX_LEN", defaults.password_max_len)?;
        let verification_token_ttl_secs = parse_env_from_str(
            &lookup,
            "VERIFICATION_TOKEN_TTL_SECS",
            defaults.verification_token_ttl_secs,
        )?;
        let reset_token_ttl_secs = parse_env_from_str(
            &lookup,
            "RESET_TOKEN_TTL_SECS",
            defaults.reset_token_ttl_secs,
        )?;
        let require_email_verification = parse_env_bool(
            &lookup,
            "REQUIRE_EMAIL_VERIFICATION",
            defaults.require_email_verification,
        )?;

        Self::new(
            argon2_m_cost,
            argon2_t_cost,
            argon2_p_cost,
            password_min_len,
            password_max_len,
            verification_token_ttl_secs,
            reset_token_ttl_secs,
            require_email_verification,
        )
    }

    /// Load `AppConfig` from environment variables, falling back to defaults.
    pub fn from_env() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();
        Self::from_lookup(|k| std::env::var(k))
    }
}

fn parse_env_from_str<T>(
    lookup: &impl Fn(&str) -> Result<String, std::env::VarError>,
    key: &'static str,
    default: T,
) -> Result<T, ConfigError>
where
    T: FromStr,
{
    match lookup(key) {
        Ok(val) => val.parse::<T>().map_err(|_| ConfigError::InvalidValue {
            field: key,
            reason: "must be a valid integer",
        }),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(ConfigError::NonUnicodeEnvVar(key)),
    }
}

fn parse_env_bool(
    lookup: &impl Fn(&str) -> Result<String, std::env::VarError>,
    key: &'static str,
    default: bool,
) -> Result<bool, ConfigError> {
    match lookup(key) {
        Ok(val) => match val.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            _ => Err(ConfigError::InvalidValue {
                field: key,
                reason: "must be a boolean (true/false/1/0)",
            }),
        },
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(ConfigError::NonUnicodeEnvVar(key)),
    }
}

// ─── Phase 4 — Session & Rate Limiting Configuration ──────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct SessionConfig {
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    /// Cookie domain for session and CSRF cookies.
    ///
    /// In split-host or cross-subdomain architectures (e.g. frontend on `app.example.com` calling
    /// an API on `api.example.com`), configure `SESSION_COOKIE_DOMAIN` (e.g. `.example.com`) so that
    /// client-side JavaScript can read the `csrf_token` cookie for Double Submit Cookie verification.
    ///
    /// The `csrf_token` cookie uses `SESSION_COOKIE_PATH`. Browsers expose it to frontend JavaScript
    /// only when the frontend document path matches that cookie path. Keep `SESSION_COOKIE_PATH` at
    /// `/` (the default) for this setup.
    #[serde(default)]
    pub cookie_domain: Option<String>,
    /// Cookie path for session and CSRF cookies. Must match the frontend document root (typically `/`)
    /// so CSRF double-submit cookies are accessible to the browser client.
    #[serde(default = "default_cookie_path")]
    pub cookie_path: String,
    #[serde(default = "default_cookie_same_site")]
    pub cookie_same_site: String,
    #[serde(default = "default_cookie_secure")]
    pub cookie_secure: bool,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_absolute_lifetime_secs")]
    pub absolute_lifetime_secs: u64,
    #[serde(default = "default_max_active_sessions_per_user")]
    pub max_active_sessions_per_user: usize,
}

pub fn default_cookie_name() -> String {
    "sid".into()
}

pub fn default_cookie_domain() -> Option<String> {
    None
}

pub fn default_cookie_path() -> String {
    "/".into()
}

pub fn default_cookie_same_site() -> String {
    "Lax".into()
}

pub fn default_cookie_secure() -> bool {
    true
}

pub fn default_idle_timeout_secs() -> u64 {
    1800
}

pub fn default_absolute_lifetime_secs() -> u64 {
    86400
}

pub fn default_max_active_sessions_per_user() -> usize {
    5
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookie_name: default_cookie_name(),
            cookie_domain: default_cookie_domain(),
            cookie_path: default_cookie_path(),
            cookie_same_site: default_cookie_same_site(),
            cookie_secure: default_cookie_secure(),
            idle_timeout_secs: default_idle_timeout_secs(),
            absolute_lifetime_secs: default_absolute_lifetime_secs(),
            max_active_sessions_per_user: default_max_active_sessions_per_user(),
        }
    }
}

impl SessionConfig {
    pub fn default_cookie_name() -> String {
        default_cookie_name()
    }
    pub fn default_cookie_domain() -> Option<String> {
        default_cookie_domain()
    }
    pub fn default_cookie_path() -> String {
        default_cookie_path()
    }
    pub fn default_cookie_same_site() -> String {
        default_cookie_same_site()
    }
    pub fn default_cookie_secure() -> bool {
        default_cookie_secure()
    }
    pub fn default_idle_timeout_secs() -> u64 {
        default_idle_timeout_secs()
    }
    pub fn default_absolute_lifetime_secs() -> u64 {
        default_absolute_lifetime_secs()
    }
    pub fn default_max_active_sessions_per_user() -> usize {
        default_max_active_sessions_per_user()
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let is_valid_cookie_ascii = |s: &str| -> bool {
            s.chars().all(|c| {
                c.is_ascii() && !c.is_ascii_control() && c != ';' && c != '\r' && c != '\n'
            })
        };
        if self.cookie_name.trim().is_empty() {
            return Err(ConfigError::InvalidValue {
                field: "cookie_name",
                reason: "must not be empty",
            });
        }
        if !is_valid_cookie_ascii(&self.cookie_name) {
            return Err(ConfigError::InvalidValue {
                field: "cookie_name",
                reason: "must contain only valid non-control ASCII characters without semicolons",
            });
        }
        if self.cookie_path.trim().is_empty() {
            return Err(ConfigError::InvalidValue {
                field: "cookie_path",
                reason: "must not be empty",
            });
        }
        if !is_valid_cookie_ascii(&self.cookie_path) {
            return Err(ConfigError::InvalidValue {
                field: "cookie_path",
                reason: "must contain only valid non-control ASCII characters without semicolons",
            });
        }
        if let Some(ref domain) = self.cookie_domain {
            if domain.trim().is_empty() {
                return Err(ConfigError::InvalidValue {
                    field: "cookie_domain",
                    reason: "must not be empty when provided",
                });
            }
            if !is_valid_cookie_ascii(domain) {
                return Err(ConfigError::InvalidValue {
                    field: "cookie_domain",
                    reason: "must contain only valid non-control ASCII characters without semicolons",
                });
            }
        }
        if self.idle_timeout_secs < 60 {
            return Err(ConfigError::InvalidValue {
                field: "idle_timeout_secs",
                reason: "must be at least 60 seconds",
            });
        }
        if self.idle_timeout_secs > self.absolute_lifetime_secs {
            return Err(ConfigError::InvalidValue {
                field: "idle_timeout_secs",
                reason: "must be less than or equal to absolute_lifetime_secs",
            });
        }
        if self.absolute_lifetime_secs > 2_592_000 {
            return Err(ConfigError::InvalidValue {
                field: "absolute_lifetime_secs",
                reason: "must not exceed 2592000 seconds (30 days)",
            });
        }
        let same_site_lower = self.cookie_same_site.trim().to_ascii_lowercase();
        if !matches!(same_site_lower.as_str(), "lax" | "strict" | "none") {
            return Err(ConfigError::InvalidValue {
                field: "cookie_same_site",
                reason: "must be Lax, Strict, or None",
            });
        }
        if same_site_lower == "none" && !self.cookie_secure {
            return Err(ConfigError::InvalidValue {
                field: "cookie_secure",
                reason: "SameSite=None requires cookie_secure=true",
            });
        }
        if self.max_active_sessions_per_user == 0 {
            return Err(ConfigError::InvalidValue {
                field: "max_active_sessions_per_user",
                reason: "must be at least 1",
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }

    #[must_use]
    pub fn absolute_lifetime(&self) -> Duration {
        Duration::from_secs(self.absolute_lifetime_secs)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_login_cooldown_secs")]
    pub login_cooldown_secs: u64,
}

pub fn default_rate_limit_enabled() -> bool {
    true
}

pub fn default_max_attempts() -> u32 {
    10
}

pub fn default_window_secs() -> u64 {
    900
}

pub fn default_login_cooldown_secs() -> u64 {
    900
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_rate_limit_enabled(),
            max_attempts: default_max_attempts(),
            window_secs: default_window_secs(),
            login_cooldown_secs: default_login_cooldown_secs(),
        }
    }
}

impl RateLimitConfig {
    pub fn default_max_attempts() -> u32 {
        default_max_attempts()
    }
    pub fn default_window_secs() -> u64 {
        default_window_secs()
    }
    pub fn default_login_cooldown_secs() -> u64 {
        default_login_cooldown_secs()
    }
    pub fn default_rate_limit_enabled() -> bool {
        default_rate_limit_enabled()
    }

    /// Bounds are enforced only while enabled. A disabled config may hold
    /// degenerate zeros; re-validate after flipping `enabled` back on.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled {
            if self.max_attempts == 0 {
                return Err(ConfigError::InvalidValue {
                    field: "max_attempts",
                    reason: "must be at least 1",
                });
            }
            if self.window_secs < 60 {
                return Err(ConfigError::InvalidValue {
                    field: "window_secs",
                    reason: "must be at least 60 seconds",
                });
            }
            if self.login_cooldown_secs == 0 {
                return Err(ConfigError::InvalidValue {
                    field: "login_cooldown_secs",
                    reason: "must be at least 1",
                });
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn window(&self) -> Duration {
        Duration::from_secs(self.window_secs)
    }

    #[must_use]
    pub fn cooldown(&self) -> Duration {
        Duration::from_secs(self.login_cooldown_secs)
    }
}

// ─── Phase 6 — OAuth Config ──────────────────────────────────────────────────

pub const SUPPORTED_PROVIDERS: &[&str] = &["google", "github", "apple"];
pub const DEFAULT_OAUTH_STATE_COOKIE_NAME: &str = "oauth_state";
pub const DEFAULT_OAUTH_STATE_COOKIE_PATH: &str = "/";
pub const DEFAULT_OAUTH_STATE_TTL_SECS: u64 = 600; // 10 minutes

#[derive(Clone, PartialEq, Eq)]
pub struct ProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub enabled: bool,

    // Apple-specific credentials for dynamic ES256 client_secret JWT signing
    pub team_id: Option<String>,
    pub key_id: Option<String>,
    pub private_key: Option<String>,
}

impl ProviderConfig {
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        scopes: Vec<String>,
        enabled: bool,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            scopes,
            enabled,
            team_id: None,
            key_id: None,
            private_key: None,
        }
    }
}

impl std::fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .field("enabled", &self.enabled)
            .field("team_id", &self.team_id)
            .field("key_id", &self.key_id)
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct OAuthConfig {
    pub providers: std::collections::HashMap<String, ProviderConfig>,
    pub state_cookie_name: String,
    pub state_cookie_path: String,
    pub state_ttl: Duration,
    pub state_secret: String,
    pub callback_base_url: String,
}

impl std::fmt::Debug for OAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthConfig")
            .field("providers", &self.providers)
            .field("state_cookie_name", &self.state_cookie_name)
            .field("state_cookie_path", &self.state_cookie_path)
            .field("state_ttl", &self.state_ttl)
            .field("state_secret", &"[REDACTED]")
            .field("callback_base_url", &self.callback_base_url)
            .finish()
    }
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            providers: std::collections::HashMap::new(),
            state_cookie_name: DEFAULT_OAUTH_STATE_COOKIE_NAME.to_string(),
            state_cookie_path: DEFAULT_OAUTH_STATE_COOKIE_PATH.to_string(),
            state_ttl: Duration::from_secs(DEFAULT_OAUTH_STATE_TTL_SECS),
            state_secret: String::new(),
            callback_base_url: String::new(),
        }
    }
}

// RFC 6265 cookie-name token characters; spaces/separators break Set-Cookie.
fn is_valid_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            matches!(
                b,
                b'0'..=b'9'
                    | b'A'..=b'Z'
                    | b'a'..=b'z'
                    | b'!'
                    | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
        })
}

// RFC 6265 path-value minus whitespace: browsers trim it, breaking lookup.
fn is_valid_cookie_path(path: &str) -> bool {
    !path.is_empty() && path.bytes().all(|b| b >= 0x21 && b != 0x7f && b != b';')
}

impl OAuthConfig {
    #[must_use]
    pub fn state_ttl_secs(&self) -> u64 {
        self.state_ttl.as_secs()
    }

    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.state_ttl
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !is_valid_cookie_name(&self.state_cookie_name) {
            return Err(ConfigError::InvalidValue {
                field: "oauth.state_cookie_name",
                reason: "must be a valid cookie name (RFC 6265 token characters)",
            });
        }
        if !is_valid_cookie_path(&self.state_cookie_path) {
            return Err(ConfigError::InvalidValue {
                field: "oauth.state_cookie_path",
                reason: "must be a valid cookie path (no whitespace, controls, or ';')",
            });
        }
        let ttl_secs = self.ttl().as_secs();
        if !(60..=3600).contains(&ttl_secs) {
            return Err(ConfigError::InvalidValue {
                field: "oauth.state_ttl",
                reason: "must be between 60 and 3600 seconds",
            });
        }

        let any_enabled = self.providers.values().any(|p| p.enabled);
        if any_enabled && self.state_secret.len() < 32 {
            return Err(ConfigError::InvalidValue {
                field: "oauth.state_secret",
                reason: "must be at least 32 bytes when oauth providers are enabled",
            });
        }

        for (name, provider) in &self.providers {
            if !SUPPORTED_PROVIDERS.contains(&name.as_str()) {
                return Err(ConfigError::InvalidValue {
                    field: "oauth.providers",
                    reason: "unsupported provider key; supported providers are google, github, apple",
                });
            }

            if provider.enabled {
                if provider.client_id.trim().is_empty() {
                    return Err(ConfigError::InvalidValue {
                        field: "oauth.provider.client_id",
                        reason: "must not be empty for enabled provider",
                    });
                }
                if provider.redirect_uri.trim().is_empty() {
                    return Err(ConfigError::InvalidValue {
                        field: "oauth.provider.redirect_uri",
                        reason: "must not be empty for enabled provider",
                    });
                }

                if name == "google" || name == "github" {
                    if provider.client_secret.trim().is_empty() {
                        return Err(ConfigError::InvalidValue {
                            field: "oauth.provider.client_secret",
                            reason: "must not be empty for google/github provider",
                        });
                    }
                } else if name == "apple" {
                    let has_secret = !provider.client_secret.trim().is_empty();
                    let has_p8 = provider
                        .team_id
                        .as_deref()
                        .is_some_and(|s| !s.trim().is_empty())
                        && provider
                            .key_id
                            .as_deref()
                            .is_some_and(|s| !s.trim().is_empty())
                        && provider
                            .private_key
                            .as_deref()
                            .is_some_and(|s| !s.trim().is_empty());

                    if !has_secret && !has_p8 {
                        return Err(ConfigError::InvalidValue {
                            field: "oauth.provider.apple",
                            reason: "must configure either client_secret or team_id, key_id, and private_key",
                        });
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        let cfg = Self {
            database_url: "postgres://localhost/test".into(),
            port: DEFAULT_PORT,
            allowed_origins: vec!["https://app.example.com".into()],
            allowed_methods: vec![
                "GET".into(),
                "POST".into(),
                "PUT".into(),
                "DELETE".into(),
                "OPTIONS".into(),
            ],
            allowed_headers: default_allowed_headers(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            min_connections: DEFAULT_MIN_CONNECTIONS,
            base_url: "https://app.example.com".into(),
            email_dispatch_timeout: Duration::from_secs(DEFAULT_EMAIL_DISPATCH_TIMEOUT_SECS),
            async_email_dispatch: true,
            outbox_poll_interval: Duration::from_millis(DEFAULT_OUTBOX_POLL_INTERVAL_MS),
            outbox_batch_size: DEFAULT_OUTBOX_BATCH_SIZE,
            outbox_max_retries: DEFAULT_OUTBOX_MAX_RETRIES,
            outbox_initial_backoff: Duration::from_secs(DEFAULT_OUTBOX_INITIAL_BACKOFF_SECS),
            outbox_max_backoff: Duration::from_secs(DEFAULT_OUTBOX_MAX_BACKOFF_SECS),
            outbox_sent_retention: Duration::from_secs(DEFAULT_OUTBOX_SENT_RETENTION_SECS),
            session: SessionConfig::default(),
            rate_limit: RateLimitConfig::default(),
            oauth: OAuthConfig::default(),
        };
        // Compiled-in defaults must stay deployable: fail fast in debug/test
        // if a future default edit stops validating.
        debug_assert!(cfg.validate().is_ok());
        cfg
    }
}

impl Default for AppConfig {
    /// Skips validation — for tests only.
    ///
    /// Default parameters meet RFC 9106 §4 second option and OWASP ASVS 5.0 L1 minimums:
    /// m=65536 KiB (64 MiB), t=3, p=4.
    fn default() -> Self {
        let cfg = Self {
            argon2_m_cost: 65536,
            argon2_t_cost: 3,
            argon2_p_cost: 4,
            password_min_len: 8,
            password_max_len: 128,
            verification_token_ttl_secs: 1800,
            reset_token_ttl_secs: 900,
            require_email_verification: true,
        };
        debug_assert!(cfg.validate().is_ok());
        cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Phase 1 Config tests ──────────────────────────────────────────────────

    #[test]
    fn test_config_defaults() {
        let cfg = Config {
            database_url: "postgres://user:pass@localhost:5432/metal_auth".into(),
            ..test_infra_config()
        };
        assert_eq!(cfg.port, 3000);
        assert_eq!(cfg.max_connections, 25);
        assert_eq!(cfg.min_connections, 2);
        assert_eq!(cfg.outbox_batch_size, 50);
        assert_eq!(cfg.outbox_max_retries, 5);
    }

    fn test_infra_config() -> Config {
        Config {
            database_url: "postgres://localhost/test".into(),
            port: 3000,
            allowed_origins: vec!["https://app.example.com".into()],
            allowed_methods: vec!["GET".into(), "POST".into()],
            allowed_headers: default_allowed_headers(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            min_connections: DEFAULT_MIN_CONNECTIONS,
            base_url: "https://app.example.com".into(),
            email_dispatch_timeout: Duration::from_secs(10),
            async_email_dispatch: true,
            outbox_poll_interval: Duration::from_millis(DEFAULT_OUTBOX_POLL_INTERVAL_MS),
            outbox_batch_size: DEFAULT_OUTBOX_BATCH_SIZE,
            outbox_max_retries: DEFAULT_OUTBOX_MAX_RETRIES,
            outbox_initial_backoff: Duration::from_secs(DEFAULT_OUTBOX_INITIAL_BACKOFF_SECS),
            outbox_max_backoff: Duration::from_secs(DEFAULT_OUTBOX_MAX_BACKOFF_SECS),
            outbox_sent_retention: Duration::from_secs(DEFAULT_OUTBOX_SENT_RETENTION_SECS),
            session: SessionConfig::default(),
            rate_limit: RateLimitConfig::default(),
            oauth: OAuthConfig::default(),
        }
    }

    #[test]
    fn test_config_debug_redacts_database_url() {
        let cfg = Config {
            database_url: "postgres://secret_user:super_secret_password@localhost:5432/db".into(),
            base_url: "https://example.com".into(),
            ..test_infra_config()
        };
        let debug_output = format!("{cfg:?}");
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("super_secret_password"));
        assert!(!debug_output.contains("secret_user"));
        assert!(!debug_output.contains("https://example.com"));
    }

    #[test]
    fn test_parse_allowed_origins_str() {
        assert!(parse_allowed_origins_str("").is_empty());
        assert!(parse_allowed_origins_str("   ,   , ").is_empty());
        assert!(parse_allowed_origins_str("   ,   /   , ///, ").is_empty());

        let parsed =
            parse_allowed_origins_str("https://app1.com/, https://app2.com , https://app3.com///");
        assert_eq!(
            parsed,
            vec![
                "https://app1.com".to_string(),
                "https://app2.com".to_string(),
                "https://app3.com".to_string(),
            ]
        );
    }

    #[test]
    fn test_config_validate_success() {
        let cfg = Config {
            allowed_origins: vec!["https://app.example.com".into(), "*".into()],
            ..test_infra_config()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_config_validate_rejects_malformed_origin() {
        let cfg = Config {
            allowed_origins: vec!["bad\norigin".into()],
            ..test_infra_config()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidOrigin { ref value, .. }) if value == "bad\norigin"
        ));
    }

    #[test]
    fn test_config_validate_rejects_malformed_method() {
        let cfg = Config {
            allowed_methods: vec!["BAD METHOD".into()],
            ..test_infra_config()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidMethod { ref value, .. }) if value == "BAD METHOD"
        ));
    }

    #[test]
    fn test_config_validate_rejects_malformed_header() {
        let cfg = Config {
            allowed_headers: vec!["Bad Header".into()],
            ..test_infra_config()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidHeader { ref value, .. }) if value == "Bad Header"
        ));
    }

    #[test]
    fn test_config_validate_rejects_empty_database_url() {
        let cfg = Config {
            database_url: "".into(),
            ..test_infra_config()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidValue {
                field: "database_url",
                reason: "must not be empty",
            })
        ));
    }

    #[test]
    fn test_config_validate_rejects_whitespace_database_url() {
        let cfg = Config {
            database_url: "   \t\n  ".into(),
            ..test_infra_config()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidValue {
                field: "database_url",
                reason: "must not be empty",
            })
        ));
    }

    #[test]
    fn test_config_validate_rejects_zero_max_connections() {
        let cfg = Config {
            max_connections: 0,
            ..test_infra_config()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidValue {
                field: "max_connections",
                reason: "must be greater than 0",
            })
        ));
    }

    #[test]
    fn test_config_validate_rejects_min_connections_greater_than_max() {
        let cfg = Config {
            max_connections: 5,
            min_connections: 6,
            ..test_infra_config()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidValue {
                field: "min_connections",
                reason: "must not exceed max_connections",
            })
        ));
    }

    #[test]
    fn test_config_validate_accepts_equal_min_and_max_connections() {
        let cfg = Config {
            max_connections: 5,
            min_connections: 5,
            ..test_infra_config()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_validate_rejects_sync_email_dispatch() {
        let cfg = Config {
            async_email_dispatch: false,
            ..test_infra_config()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidValue {
                field: "ASYNC_EMAIL_DISPATCH",
                ..
            })
        ));
    }

    #[test]
    fn test_config_validate_rejects_origin_with_trailing_slash() {
        let cfg = Config {
            allowed_origins: vec!["https://app.example.com/".into()],
            ..test_infra_config()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidValue {
                field: "allowed_origins",
                reason: "must not contain trailing slash",
            })
        ));
    }

    #[test]
    fn test_config_validate_outbox_params() {
        let cfg_zero_interval = Config {
            outbox_poll_interval: Duration::ZERO,
            ..test_infra_config()
        };
        assert!(matches!(
            cfg_zero_interval.validate(),
            Err(ConfigError::InvalidValue {
                field: "outbox_poll_interval",
                ..
            })
        ));

        let cfg_zero_batch = Config {
            outbox_batch_size: 0,
            ..test_infra_config()
        };
        assert!(matches!(
            cfg_zero_batch.validate(),
            Err(ConfigError::InvalidValue {
                field: "outbox_batch_size",
                ..
            })
        ));

        let cfg_zero_retries = Config {
            outbox_max_retries: 0,
            ..test_infra_config()
        };
        assert!(matches!(
            cfg_zero_retries.validate(),
            Err(ConfigError::InvalidValue {
                field: "outbox_max_retries",
                ..
            })
        ));

        let cfg_zero_initial_backoff = Config {
            outbox_initial_backoff: Duration::ZERO,
            ..test_infra_config()
        };
        assert!(matches!(
            cfg_zero_initial_backoff.validate(),
            Err(ConfigError::InvalidValue {
                field: "outbox_initial_backoff",
                ..
            })
        ));

        let cfg_bad_max_backoff = Config {
            outbox_initial_backoff: Duration::from_secs(10),
            outbox_max_backoff: Duration::from_secs(5),
            ..test_infra_config()
        };
        assert!(matches!(
            cfg_bad_max_backoff.validate(),
            Err(ConfigError::InvalidValue {
                field: "outbox_max_backoff",
                ..
            })
        ));
    }

    #[test]
    fn outbox_sent_retention_defaults_to_7_days() {
        let lookup = |k: &str| match k {
            "DATABASE_URL" => Ok("postgres://localhost/test".into()),
            "BASE_URL" => Ok("https://example.com".into()),
            _ => Err(std::env::VarError::NotPresent),
        };
        let cfg = Config::from_lookup(lookup).expect("load default config");
        assert_eq!(
            cfg.outbox_sent_retention,
            Duration::from_secs(DEFAULT_OUTBOX_SENT_RETENTION_SECS)
        );
        assert_eq!(
            cfg.outbox_sent_retention,
            Duration::from_secs(7 * 24 * 3600)
        );
    }

    #[test]
    fn outbox_sent_retention_override_from_lookup() {
        let lookup = |k: &str| match k {
            "DATABASE_URL" => Ok("postgres://localhost/test".into()),
            "BASE_URL" => Ok("https://example.com".into()),
            "OUTBOX_SENT_RETENTION_SECS" => Ok("86400".into()),
            _ => Err(std::env::VarError::NotPresent),
        };
        let cfg = Config::from_lookup(lookup).expect("load overridden retention");
        assert_eq!(cfg.outbox_sent_retention, Duration::from_secs(86400));
    }

    #[test]
    fn outbox_sent_retention_rejects_zero() {
        let cfg_zero = Config {
            outbox_sent_retention: Duration::ZERO,
            ..test_infra_config()
        };
        assert!(matches!(
            cfg_zero.validate(),
            Err(ConfigError::InvalidValue {
                field: "outbox_sent_retention",
                ..
            })
        ));

        let lookup_zero = |k: &str| match k {
            "DATABASE_URL" => Ok("postgres://localhost/test".into()),
            "BASE_URL" => Ok("https://example.com".into()),
            "OUTBOX_SENT_RETENTION_SECS" => Ok("0".into()),
            _ => Err(std::env::VarError::NotPresent),
        };
        assert!(matches!(
            Config::from_lookup(lookup_zero),
            Err(ConfigError::InvalidEnvVar("OUTBOX_SENT_RETENTION_SECS"))
        ));
    }

    #[test]
    fn outbox_config_env_var_overrides_from_lookup() {
        let lookup = |k: &str| match k {
            "DATABASE_URL" => Ok("postgres://localhost/test".into()),
            "BASE_URL" => Ok("https://example.com".into()),
            "OUTBOX_POLL_INTERVAL_MS" => Ok("250".into()),
            "OUTBOX_BATCH_SIZE" => Ok("100".into()),
            "OUTBOX_MAX_RETRIES" => Ok("10".into()),
            "OUTBOX_INITIAL_BACKOFF_SECS" => Ok("3".into()),
            "OUTBOX_MAX_BACKOFF_SECS" => Ok("60".into()),
            "OUTBOX_SENT_RETENTION_SECS" => Ok("86400".into()),
            _ => Err(std::env::VarError::NotPresent),
        };
        let cfg = Config::from_lookup(lookup).expect("load outbox overrides");
        assert_eq!(cfg.outbox_poll_interval, Duration::from_millis(250));
        assert_eq!(cfg.outbox_batch_size, 100);
        assert_eq!(cfg.outbox_max_retries, 10);
        assert_eq!(cfg.outbox_initial_backoff, Duration::from_secs(3));
        assert_eq!(cfg.outbox_max_backoff, Duration::from_secs(60));
        assert_eq!(cfg.outbox_sent_retention, Duration::from_secs(86400));
    }

    #[test]
    fn outbox_config_rejects_invalid_and_zero_env_vars() {
        let vars = [
            "OUTBOX_POLL_INTERVAL_MS",
            "OUTBOX_BATCH_SIZE",
            "OUTBOX_MAX_RETRIES",
            "OUTBOX_INITIAL_BACKOFF_SECS",
            "OUTBOX_MAX_BACKOFF_SECS",
            "OUTBOX_SENT_RETENTION_SECS",
        ];

        for var in vars {
            // Non-numeric
            let lookup_invalid = |k: &str| {
                if k == var {
                    Ok("invalid_number".into())
                } else if k == "DATABASE_URL" {
                    Ok("postgres://localhost/test".into())
                } else if k == "BASE_URL" {
                    Ok("https://example.com".into())
                } else {
                    Err(std::env::VarError::NotPresent)
                }
            };
            assert!(
                matches!(
                    Config::from_lookup(lookup_invalid),
                    Err(ConfigError::InvalidEnvVar(v)) if v == var
                ),
                "expected InvalidEnvVar for {var} on non-numeric value"
            );

            // Zero
            let lookup_zero = |k: &str| {
                if k == var {
                    Ok("0".into())
                } else if k == "DATABASE_URL" {
                    Ok("postgres://localhost/test".into())
                } else if k == "BASE_URL" {
                    Ok("https://example.com".into())
                } else {
                    Err(std::env::VarError::NotPresent)
                }
            };
            assert!(
                matches!(
                    Config::from_lookup(lookup_zero),
                    Err(ConfigError::InvalidEnvVar(v)) if v == var
                ),
                "expected InvalidEnvVar for {var} on zero value"
            );

            // Non-unicode
            let lookup_non_unicode = |k: &str| {
                if k == var {
                    Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
                        "bad",
                    )))
                } else if k == "DATABASE_URL" {
                    Ok("postgres://localhost/test".into())
                } else if k == "BASE_URL" {
                    Ok("https://example.com".into())
                } else {
                    Err(std::env::VarError::NotPresent)
                }
            };
            assert!(
                matches!(
                    Config::from_lookup(lookup_non_unicode),
                    Err(ConfigError::NonUnicodeEnvVar(v)) if v == var
                ),
                "expected NonUnicodeEnvVar for {var}"
            );
        }
    }

    // ── Phase 3 AppConfig tests ───────────────────────────────────────────────

    /// OWASP ASVS 5.0 L1 doc-check: default params meet or exceed minimums.
    /// RFC 9106 §4 second option: m=65536, t=3, p=4.
    #[test]
    fn default_argon2_params_meet_asvs_l1_minimums() {
        let cfg = AppConfig::default();
        assert!(
            cfg.argon2_m_cost >= 19456,
            "m_cost must be >= 19456 KiB (ASVS L1)"
        );
        assert!(cfg.argon2_t_cost >= 2, "t_cost must be >= 2 (ASVS L1)");
        assert!(cfg.argon2_p_cost >= 1, "p_cost must be >= 1");
        assert_eq!(cfg.argon2_m_cost, 65536, "RFC 9106 §4 second option");
        assert_eq!(cfg.argon2_t_cost, 3, "RFC 9106 §4 second option");
        assert_eq!(cfg.argon2_p_cost, 4, "RFC 9106 §4 second option");
        assert_eq!(cfg.reset_token_ttl_secs, 900);
        assert!(cfg.require_email_verification);
    }

    #[test]
    fn app_config_new_accepts_valid_config() {
        assert!(AppConfig::new(65536, 3, 4, 8, 128, 1800, 900, true).is_ok());
    }

    #[test]
    fn app_config_new_rejects_m_cost_below_minimum() {
        assert!(matches!(
            AppConfig::new(19455, 2, 1, 8, 128, 900, 900, false),
            Err(ConfigError::InvalidValue {
                field: "argon2_m_cost",
                ..
            })
        ));
    }

    #[test]
    fn app_config_new_rejects_t_cost_below_2() {
        assert!(matches!(
            AppConfig::new(65536, 1, 4, 8, 128, 1800, 900, false),
            Err(ConfigError::InvalidValue {
                field: "argon2_t_cost",
                ..
            })
        ));
    }

    #[test]
    fn app_config_new_accepts_t_cost_exactly_2() {
        assert!(AppConfig::new(65536, 2, 4, 8, 128, 1800, 900, false).is_ok());
    }

    #[test]
    fn app_config_new_rejects_p_cost_below_1() {
        assert!(matches!(
            AppConfig::new(65536, 2, 0, 8, 128, 1800, 900, false),
            Err(ConfigError::InvalidValue {
                field: "argon2_p_cost",
                ..
            })
        ));
    }

    #[test]
    fn app_config_new_rejects_password_min_below_8() {
        assert!(matches!(
            AppConfig::new(65536, 3, 4, 7, 128, 1800, 900, false),
            Err(ConfigError::InvalidValue {
                field: "password_min_len",
                ..
            })
        ));
    }

    #[test]
    fn app_config_new_rejects_password_max_above_128() {
        assert!(matches!(
            AppConfig::new(65536, 3, 4, 8, 129, 1800, 900, false),
            Err(ConfigError::InvalidValue {
                field: "password_max_len",
                ..
            })
        ));
    }

    #[test]
    fn app_config_new_rejects_min_greater_than_max() {
        assert!(matches!(
            AppConfig::new(65536, 3, 4, 20, 10, 1800, 900, false),
            Err(ConfigError::InvalidValue {
                field: "password_min_len",
                ..
            })
        ));
    }

    #[test]
    fn app_config_new_rejects_verification_ttl_out_of_range() {
        assert!(matches!(
            AppConfig::new(65536, 3, 4, 8, 128, 899, 900, false),
            Err(ConfigError::InvalidValue {
                field: "verification_token_ttl_secs",
                ..
            })
        ));
        assert!(matches!(
            AppConfig::new(65536, 3, 4, 8, 128, 3601, 900, false),
            Err(ConfigError::InvalidValue {
                field: "verification_token_ttl_secs",
                ..
            })
        ));
    }

    #[test]
    fn app_config_new_rejects_reset_ttl_out_of_range() {
        assert!(matches!(
            AppConfig::new(65536, 3, 4, 8, 128, 1800, 899, false),
            Err(ConfigError::InvalidValue {
                field: "reset_token_ttl_secs",
                ..
            })
        ));
        assert!(matches!(
            AppConfig::new(65536, 3, 4, 8, 128, 1800, 3601, false),
            Err(ConfigError::InvalidValue {
                field: "reset_token_ttl_secs",
                ..
            })
        ));
    }

    #[test]
    fn app_config_new_accepts_boundary_ttl_values() {
        assert!(AppConfig::new(65536, 3, 4, 8, 128, 900, 3600, false).is_ok());
        assert!(AppConfig::new(65536, 3, 4, 8, 128, 3600, 900, false).is_ok());
    }

    #[test]
    fn app_config_from_env_defaults() {
        let cfg = AppConfig::from_lookup(|_| Err(std::env::VarError::NotPresent))
            .expect("load default env config");
        let expected = AppConfig::default();
        assert_eq!(cfg, expected);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn app_config_from_lookup_overrides() {
        let lookup = |key: &str| match key {
            "ARGON2_M_COST" => Ok("32768".to_string()),
            "ARGON2_T_COST" => Ok("4".to_string()),
            "ARGON2_P_COST" => Ok("2".to_string()),
            "PASSWORD_MIN_LEN" => Ok("10".to_string()),
            "PASSWORD_MAX_LEN" => Ok("64".to_string()),
            "VERIFICATION_TOKEN_TTL_SECS" => Ok("1200".to_string()),
            "RESET_TOKEN_TTL_SECS" => Ok("1000".to_string()),
            "REQUIRE_EMAIL_VERIFICATION" => Ok("false".to_string()),
            _ => Err(std::env::VarError::NotPresent),
        };

        let cfg = AppConfig::from_lookup(lookup).expect("load overridden config");
        assert_eq!(cfg.argon2_m_cost, 32768);
        assert_eq!(cfg.argon2_t_cost, 4);
        assert_eq!(cfg.argon2_p_cost, 2);
        assert_eq!(cfg.password_min_len, 10);
        assert_eq!(cfg.password_max_len, 64);
        assert_eq!(cfg.verification_token_ttl_secs, 1200);
        assert_eq!(cfg.reset_token_ttl_secs, 1000);
        assert!(!cfg.require_email_verification);
    }

    // ── Config::validate base_url rejection tests ─────────────────────────────

    fn valid_config_base() -> Config {
        test_infra_config()
    }

    #[test]
    fn config_validate_rejects_base_url_with_query_string() {
        let cfg = Config {
            base_url: "https://app.example.com?foo=bar".into(),
            ..valid_config_base()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidEnvVar("BASE_URL"))
        ));
    }

    #[test]
    fn config_validate_rejects_base_url_with_userinfo() {
        let cfg = Config {
            base_url: "https://user:pass@app.example.com".into(),
            ..valid_config_base()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidEnvVar("BASE_URL"))
        ));
    }

    #[test]
    fn config_validate_rejects_base_url_non_http_scheme() {
        let cfg = Config {
            base_url: "ftp://app.example.com".into(),
            ..valid_config_base()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidEnvVar("BASE_URL"))
        ));
    }

    #[test]
    fn config_validate_rejects_zero_email_dispatch_timeout() {
        let cfg = Config {
            email_dispatch_timeout: Duration::ZERO,
            ..valid_config_base()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidEnvVar("EMAIL_DISPATCH_TIMEOUT_SECS"))
        ));
    }

    // ── AppConfig::from_lookup parse error tests ──────────────────────────────

    #[test]
    fn from_lookup_rejects_non_numeric_u32() {
        let cfg = AppConfig::from_lookup(|key| match key {
            "ARGON2_M_COST" => Ok("not_a_number".into()),
            _ => Err(std::env::VarError::NotPresent),
        });
        assert!(matches!(
            cfg,
            Err(ConfigError::InvalidValue {
                field: "ARGON2_M_COST",
                ..
            })
        ));
    }

    #[test]
    fn from_lookup_rejects_non_unicode_env_var() {
        let cfg = AppConfig::from_lookup(|key| match key {
            "ARGON2_M_COST" => Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
                "bad",
            ))),
            _ => Err(std::env::VarError::NotPresent),
        });
        assert!(matches!(
            cfg,
            Err(ConfigError::NonUnicodeEnvVar("ARGON2_M_COST"))
        ));
    }

    #[test]
    fn from_lookup_rejects_invalid_bool_string() {
        let cfg = AppConfig::from_lookup(|key| match key {
            "REQUIRE_EMAIL_VERIFICATION" => Ok("maybe".into()),
            _ => Err(std::env::VarError::NotPresent),
        });
        assert!(matches!(
            cfg,
            Err(ConfigError::InvalidValue {
                field: "REQUIRE_EMAIL_VERIFICATION",
                ..
            })
        ));
    }

    #[test]
    fn app_config_validate_rejects_invalid_bounds() {
        let cfg = AppConfig {
            argon2_m_cost: 1000,
            ..Default::default()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidValue {
                field: "argon2_m_cost",
                ..
            })
        ));

        let cfg = AppConfig {
            password_min_len: 5,
            ..Default::default()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidValue {
                field: "password_min_len",
                ..
            })
        ));
    }

    // ── Phase 4 Session & RateLimit tests ─────────────────────────────────────

    #[test]
    fn test_session_config_defaults() {
        let sc = SessionConfig::default();
        assert_eq!(sc.cookie_name, "sid");
        assert_eq!(sc.cookie_domain, None);
        assert_eq!(sc.cookie_path, "/");
        assert_eq!(sc.cookie_same_site, "Lax");
        assert!(sc.cookie_secure);
        assert_eq!(sc.idle_timeout_secs, 1800);
        assert_eq!(sc.absolute_lifetime_secs, 86400);
        assert_eq!(sc.max_active_sessions_per_user, 5);
        assert_eq!(sc.idle_timeout(), Duration::from_secs(1800));
        assert_eq!(sc.absolute_lifetime(), Duration::from_secs(86400));
        assert!(sc.validate().is_ok());
    }

    #[test]
    fn test_rate_limit_config_defaults() {
        let rlc = RateLimitConfig::default();
        assert!(rlc.enabled);
        assert_eq!(rlc.max_attempts, 10);
        assert_eq!(rlc.window_secs, 900);
        assert_eq!(rlc.login_cooldown_secs, 900);
        assert_eq!(rlc.window(), Duration::from_secs(900));
        assert_eq!(rlc.cooldown(), Duration::from_secs(900));
        assert!(rlc.validate().is_ok());
    }

    #[test]
    fn test_session_config_validation_custom_valid() {
        let sc = SessionConfig {
            cookie_name: "custom_sid".into(),
            cookie_domain: Some("app.example.com".into()),
            cookie_path: "/auth".into(),
            cookie_same_site: "Strict".into(),
            cookie_secure: true,
            idle_timeout_secs: 600,
            absolute_lifetime_secs: 3600,
            max_active_sessions_per_user: 10,
        };
        assert!(sc.validate().is_ok());
    }

    #[test]
    fn test_session_config_validation_failures() {
        let empty_name = SessionConfig {
            cookie_name: "   ".into(),
            ..SessionConfig::default()
        };
        assert!(matches!(
            empty_name.validate(),
            Err(ConfigError::InvalidValue {
                field: "cookie_name",
                ..
            })
        ));

        let empty_path = SessionConfig {
            cookie_path: "   ".into(),
            ..SessionConfig::default()
        };
        assert!(matches!(
            empty_path.validate(),
            Err(ConfigError::InvalidValue {
                field: "cookie_path",
                ..
            })
        ));

        let lt_60_idle = SessionConfig {
            idle_timeout_secs: 59,
            ..SessionConfig::default()
        };
        assert!(matches!(
            lt_60_idle.validate(),
            Err(ConfigError::InvalidValue {
                field: "idle_timeout_secs",
                ..
            })
        ));

        let bad_abs = SessionConfig {
            idle_timeout_secs: 1800,
            absolute_lifetime_secs: 900,
            ..SessionConfig::default()
        };
        assert!(matches!(
            bad_abs.validate(),
            Err(ConfigError::InvalidValue {
                field: "idle_timeout_secs",
                ..
            })
        ));

        let zero_max = SessionConfig {
            max_active_sessions_per_user: 0,
            ..SessionConfig::default()
        };
        assert!(matches!(
            zero_max.validate(),
            Err(ConfigError::InvalidValue {
                field: "max_active_sessions_per_user",
                ..
            })
        ));
    }

    #[test]
    fn test_rate_limit_config_validation_failures() {
        let zero_attempts = RateLimitConfig {
            max_attempts: 0,
            ..RateLimitConfig::default()
        };
        assert!(matches!(
            zero_attempts.validate(),
            Err(ConfigError::InvalidValue {
                field: "max_attempts",
                ..
            })
        ));

        let lt_60_window = RateLimitConfig {
            window_secs: 30,
            ..RateLimitConfig::default()
        };
        assert!(matches!(
            lt_60_window.validate(),
            Err(ConfigError::InvalidValue {
                field: "window_secs",
                ..
            })
        ));

        let zero_cooldown = RateLimitConfig {
            login_cooldown_secs: 0,
            ..RateLimitConfig::default()
        };
        assert!(matches!(
            zero_cooldown.validate(),
            Err(ConfigError::InvalidValue {
                field: "login_cooldown_secs",
                ..
            })
        ));
    }

    #[test]
    fn test_config_validate_with_invalid_session_and_rate_limit() {
        let cfg_bad_session = Config {
            session: SessionConfig {
                cookie_name: "".into(),
                ..SessionConfig::default()
            },
            ..test_infra_config()
        };
        assert!(matches!(
            cfg_bad_session.validate(),
            Err(ConfigError::InvalidValue {
                field: "cookie_name",
                ..
            })
        ));

        let cfg_bad_rate = Config {
            rate_limit: RateLimitConfig {
                max_attempts: 0,
                ..RateLimitConfig::default()
            },
            ..test_infra_config()
        };
        assert!(matches!(
            cfg_bad_rate.validate(),
            Err(ConfigError::InvalidValue {
                field: "max_attempts",
                ..
            })
        ));
    }

    #[test]
    fn test_config_from_lookup_with_session_and_rate_limit_env() {
        let cfg = Config::from_lookup(|key| match key {
            "DATABASE_URL" => Ok("postgres://localhost/test".into()),
            "BASE_URL" => Ok("https://app.example.com".into()),
            "SESSION_COOKIE_NAME" => Ok("my_session".into()),
            "SESSION_COOKIE_DOMAIN" => Ok("example.com".into()),
            "SESSION_COOKIE_PATH" => Ok("/app".into()),
            "SESSION_COOKIE_SAME_SITE" => Ok("Strict".into()),
            "SESSION_COOKIE_SECURE" => Ok("true".into()),
            "SESSION_IDLE_TIMEOUT_SECS" => Ok("900".into()),
            "SESSION_ABSOLUTE_LIFETIME_SECS" => Ok("7200".into()),
            "SESSION_MAX_ACTIVE_PER_USER" => Ok("3".into()),
            "RATE_LIMIT_ENABLED" => Ok("false".into()),
            "RATE_LIMIT_MAX_ATTEMPTS" => Ok("20".into()),
            "RATE_LIMIT_WINDOW_SECS" => Ok("600".into()),
            "RATE_LIMIT_LOGIN_COOLDOWN_SECS" => Ok("300".into()),
            _ => Err(std::env::VarError::NotPresent),
        })
        .expect("from_lookup with phase 4 env vars should succeed");

        assert_eq!(cfg.session.cookie_name, "my_session");
        assert_eq!(cfg.session.cookie_domain, Some("example.com".into()));
        assert_eq!(cfg.session.cookie_path, "/app");
        assert_eq!(cfg.session.cookie_same_site, "Strict");
        assert!(cfg.session.cookie_secure);
        assert_eq!(cfg.session.idle_timeout_secs, 900);
        assert_eq!(cfg.session.absolute_lifetime_secs, 7200);
        assert_eq!(cfg.session.max_active_sessions_per_user, 3);

        assert!(!cfg.rate_limit.enabled);
        assert_eq!(cfg.rate_limit.max_attempts, 20);
        assert_eq!(cfg.rate_limit.window_secs, 600);
        assert_eq!(cfg.rate_limit.login_cooldown_secs, 300);
    }

    #[test]
    fn config_session_defaults_are_valid() {
        let sc = SessionConfig::default();
        assert_eq!(sc.cookie_name, "sid");
        assert_eq!(sc.cookie_domain, None);
        assert_eq!(sc.cookie_path, "/");
        assert_eq!(sc.cookie_same_site, "Lax");
        assert!(sc.cookie_secure);
        assert_eq!(sc.idle_timeout_secs, 1800);
        assert_eq!(sc.absolute_lifetime_secs, 86400);
        assert_eq!(sc.max_active_sessions_per_user, 5);
        assert!(sc.validate().is_ok());
    }

    #[test]
    fn config_rate_limit_defaults_are_valid() {
        let rlc = RateLimitConfig::default();
        assert!(rlc.enabled);
        assert_eq!(rlc.max_attempts, 10);
        assert_eq!(rlc.window_secs, 900);
        assert_eq!(rlc.login_cooldown_secs, 900);
        assert!(rlc.validate().is_ok());
    }

    #[test]
    fn config_validate_rejects_idle_gt_absolute() {
        let cfg = Config {
            session: SessionConfig {
                idle_timeout_secs: 7200,
                absolute_lifetime_secs: 3600,
                ..SessionConfig::default()
            },
            ..test_infra_config()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_samesite_none_without_secure() {
        let cfg = Config {
            session: SessionConfig {
                cookie_same_site: "None".into(),
                cookie_secure: false,
                ..SessionConfig::default()
            },
            ..test_infra_config()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_window_secs_lt_60() {
        let cfg = Config {
            rate_limit: RateLimitConfig {
                window_secs: 30,
                ..RateLimitConfig::default()
            },
            ..test_infra_config()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn session_config_idle_timeout_returns_duration() {
        let cfg = test_infra_config();
        assert_eq!(cfg.session.idle_timeout(), Duration::from_secs(1800));
    }

    #[test]
    fn session_config_absolute_lifetime_returns_duration() {
        let cfg = test_infra_config();
        assert_eq!(cfg.session.absolute_lifetime(), Duration::from_secs(86400));
    }

    #[test]
    fn config_validate_accepts_idle_eq_absolute() {
        let cfg = Config {
            session: SessionConfig {
                idle_timeout_secs: 3600,
                absolute_lifetime_secs: 3600,
                ..SessionConfig::default()
            },
            ..test_infra_config()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_validate_rejects_idle_lt_60() {
        let cfg = Config {
            session: SessionConfig {
                idle_timeout_secs: 59,
                ..SessionConfig::default()
            },
            ..test_infra_config()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_absolute_lifetime_gt_30_days() {
        let cfg = Config {
            session: SessionConfig {
                absolute_lifetime_secs: 2_592_001,
                ..SessionConfig::default()
            },
            ..test_infra_config()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_accepts_absolute_lifetime_boundary_30_days() {
        let cfg = Config {
            session: SessionConfig {
                absolute_lifetime_secs: 2_592_000,
                ..SessionConfig::default()
            },
            ..test_infra_config()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_validate_rejects_invalid_samesite() {
        let cfg = Config {
            session: SessionConfig {
                cookie_same_site: "invalid_policy".into(),
                ..SessionConfig::default()
            },
            ..test_infra_config()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_accepts_case_insensitive_samesite() {
        for site in ["lax", "strict", "none", "LAX", "Strict", "None"] {
            let sc = SessionConfig {
                cookie_same_site: site.into(),
                cookie_secure: true,
                ..SessionConfig::default()
            };
            assert!(sc.validate().is_ok());
        }
    }

    #[test]
    fn config_validate_rejects_max_active_sessions_zero() {
        let cfg = Config {
            session: SessionConfig {
                max_active_sessions_per_user: 0,
                ..SessionConfig::default()
            },
            ..test_infra_config()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_empty_cookie_name() {
        let sc = SessionConfig {
            cookie_name: "  ".into(),
            ..SessionConfig::default()
        };
        assert!(sc.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_invalid_ascii_cookie_name() {
        let sc = SessionConfig {
            cookie_name: "sid;evil=1".into(),
            ..SessionConfig::default()
        };
        assert!(sc.validate().is_err());

        let sc_nl = SessionConfig {
            cookie_name: "sid\r\nSet-Cookie: pwn=1".into(),
            ..SessionConfig::default()
        };
        assert!(sc_nl.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_empty_cookie_path() {
        let sc = SessionConfig {
            cookie_path: "".into(),
            ..SessionConfig::default()
        };
        assert!(sc.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_invalid_ascii_cookie_path() {
        let sc = SessionConfig {
            cookie_path: "/;Secure".into(),
            ..SessionConfig::default()
        };
        assert!(sc.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_invalid_ascii_cookie_domain() {
        let sc = SessionConfig {
            cookie_domain: Some("example.com;evil".into()),
            ..SessionConfig::default()
        };
        assert!(sc.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_rate_limit_max_attempts_zero() {
        let cfg = Config {
            rate_limit: RateLimitConfig {
                max_attempts: 0,
                ..RateLimitConfig::default()
            },
            ..test_infra_config()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_rate_limit_login_cooldown_zero() {
        let cfg = Config {
            rate_limit: RateLimitConfig {
                login_cooldown_secs: 0,
                ..RateLimitConfig::default()
            },
            ..test_infra_config()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_disabled_rate_limit_skips_bounds_validation() {
        let cfg = Config {
            rate_limit: RateLimitConfig {
                enabled: false,
                max_attempts: 0,
                window_secs: 10,
                login_cooldown_secs: 0,
            },
            ..test_infra_config()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rate_limit_config_window_and_cooldown_return_durations() {
        let rlc = RateLimitConfig {
            window_secs: 600,
            login_cooldown_secs: 300,
            ..RateLimitConfig::default()
        };
        assert_eq!(rlc.window(), Duration::from_secs(600));
        assert_eq!(rlc.cooldown(), Duration::from_secs(300));
    }

    #[test]
    fn defaults_pass_validation() {
        assert!(Config::default().validate().is_ok());
        assert!(AppConfig::default().validate().is_ok());
        assert!(SessionConfig::default().validate().is_ok());
        assert!(RateLimitConfig::default().validate().is_ok());
    }

    #[test]
    fn config_validate_rejects_base_url_with_fragment() {
        let cfg = Config {
            base_url: "https://app.example.com/callback#section".into(),
            ..test_infra_config()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::InvalidEnvVar("BASE_URL"))
        ));
    }

    #[test]
    fn config_validate_accepts_uppercase_scheme_base_url() {
        let cfg = Config {
            base_url: "HTTPS://app.example.com".into(),
            ..test_infra_config()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn from_lookup_normalizes_trailing_slash_origins() {
        let cfg = Config::from_lookup(|key| match key {
            "DATABASE_URL" => Ok("postgres://localhost/test".into()),
            "BASE_URL" => Ok("https://app.example.com".into()),
            "ALLOWED_ORIGINS" => Ok("https://a.example.com/, https://b.example.com".into()),
            _ => Err(std::env::VarError::NotPresent),
        })
        .expect("load config with trailing-slash origin");
        assert_eq!(
            cfg.allowed_origins,
            vec![
                "https://a.example.com".to_string(),
                "https://b.example.com".to_string(),
            ]
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn session_absolute_lifetime_prefers_canonical_over_legacy_alias() {
        let cfg = Config::from_lookup(|key| match key {
            "DATABASE_URL" => Ok("postgres://localhost/test".into()),
            "BASE_URL" => Ok("https://app.example.com".into()),
            "SESSION_ABSOLUTE_LIFETIME_SECS" => Ok("7200".into()),
            "SESSION_ABSOLUTE_TIMEOUT_SECS" => Ok("3600".into()),
            _ => Err(std::env::VarError::NotPresent),
        })
        .expect("load config with both lifetime vars");
        assert_eq!(cfg.session.absolute_lifetime_secs, 7200);
    }

    #[test]
    fn session_absolute_lifetime_falls_back_to_legacy_alias() {
        let cfg = Config::from_lookup(|key| match key {
            "DATABASE_URL" => Ok("postgres://localhost/test".into()),
            "BASE_URL" => Ok("https://app.example.com".into()),
            "SESSION_ABSOLUTE_TIMEOUT_SECS" => Ok("3600".into()),
            _ => Err(std::env::VarError::NotPresent),
        })
        .expect("load config with legacy timeout only");
        assert_eq!(cfg.session.absolute_lifetime_secs, 3600);
    }

    #[test]
    fn session_absolute_lifetime_rejects_invalid_legacy_alias() {
        let cfg = Config::from_lookup(|key| match key {
            "DATABASE_URL" => Ok("postgres://localhost/test".into()),
            "BASE_URL" => Ok("https://app.example.com".into()),
            "SESSION_ABSOLUTE_TIMEOUT_SECS" => Ok("not_a_number".into()),
            _ => Err(std::env::VarError::NotPresent),
        });
        assert!(matches!(
            cfg,
            Err(ConfigError::InvalidValue {
                field: "absolute_lifetime_secs",
                ..
            })
        ));
    }

    #[test]
    fn disabled_rate_limit_reenabled_without_validation_stays_invalid() {
        let degenerate = RateLimitConfig {
            enabled: false,
            max_attempts: 0,
            window_secs: 0,
            login_cooldown_secs: 0,
        };
        assert!(degenerate.validate().is_ok());
        let reenabled = RateLimitConfig {
            enabled: true,
            ..degenerate
        };
        assert!(reenabled.validate().is_err());
    }

    #[test]
    fn default_allowed_headers_includes_csrf_token() {
        let headers = default_allowed_headers();
        assert!(
            headers
                .iter()
                .any(|h| h.eq_ignore_ascii_case("x-csrf-token"))
        );
    }

    #[test]
    fn parse_allowed_headers_appends_csrf_token_if_missing() {
        let headers = parse_allowed_headers_str("Authorization, Content-Type, X-Custom");
        assert_eq!(
            headers,
            vec!["Authorization", "Content-Type", "X-Custom", "X-CSRF-Token"]
        );
    }

    #[test]
    fn parse_allowed_headers_preserves_csrf_token_if_already_present() {
        let headers = parse_allowed_headers_str("Authorization, X-CSRF-Token, Content-Type");
        assert_eq!(
            headers,
            vec!["Authorization", "X-CSRF-Token", "Content-Type"]
        );
    }

    #[test]
    fn parse_allowed_headers_empty_or_whitespace_falls_back_to_defaults() {
        for empty_val in ["", "   ", " \t\n ", ", ,  ,"] {
            let headers = parse_allowed_headers_str(empty_val);
            assert_eq!(
                headers,
                default_allowed_headers(),
                "expected default allowed headers for input '{empty_val}'"
            );
        }
    }

    #[test]
    fn allowed_headers_empty_env_lookup_falls_back_to_defaults() {
        let cfg = Config::from_lookup(|key| match key {
            "DATABASE_URL" => Ok("postgres://localhost/test".into()),
            "BASE_URL" => Ok("https://app.example.com".into()),
            "ALLOWED_HEADERS" => Ok("   ".into()),
            _ => Err(std::env::VarError::NotPresent),
        })
        .expect("load config with whitespace allowed headers");
        assert_eq!(cfg.allowed_headers, default_allowed_headers());
    }

    #[test]
    fn allowed_headers_loaded_from_env_lookup() {
        let cfg = Config::from_lookup(|key| match key {
            "DATABASE_URL" => Ok("postgres://localhost/test".into()),
            "BASE_URL" => Ok("https://app.example.com".into()),
            "ALLOWED_HEADERS" => Ok("Authorization, X-Custom-Header".into()),
            _ => Err(std::env::VarError::NotPresent),
        })
        .expect("load config with custom allowed headers");
        assert_eq!(
            cfg.allowed_headers,
            vec!["Authorization", "X-Custom-Header", "X-CSRF-Token"]
        );
    }

    #[test]
    fn test_oauth_config_defaults() {
        let oauth = OAuthConfig::default();
        assert_eq!(oauth.state_cookie_name, "oauth_state");
        assert_eq!(oauth.state_cookie_path, "/");
        assert_eq!(oauth.ttl(), Duration::from_secs(600));
        assert!(oauth.providers.is_empty());
        assert!(oauth.validate().is_ok());
    }

    #[test]
    fn test_oauth_config_validation_ttl_bounds() {
        let mut oauth = OAuthConfig {
            state_ttl: Duration::from_secs(59),
            ..Default::default()
        };
        assert!(oauth.validate().is_err());

        oauth.state_ttl = Duration::from_secs(3601);
        assert!(oauth.validate().is_err());

        oauth.state_ttl = Duration::from_secs(600);
        assert!(oauth.validate().is_ok());
        assert_eq!(oauth.state_ttl_secs(), 600);
    }

    #[test]
    fn test_oauth_config_validation_secret_length() {
        let mut oauth = OAuthConfig::default();
        oauth.providers.insert(
            "google".into(),
            ProviderConfig::new("cid", "sec", "https://app.com/callback", vec![], true),
        );
        // Empty secret with enabled provider fails
        assert!(oauth.validate().is_err());

        // Short secret (< 32 bytes) fails
        oauth.state_secret = "short_secret_under_32_bytes!!".into();
        assert!(oauth.validate().is_err());

        // Valid secret >= 32 bytes succeeds
        oauth.state_secret = "01234567890123456789012345678901".into();
        assert!(oauth.validate().is_ok());
    }

    #[test]
    fn rejects_invalid_state_cookie_name() {
        let mut oauth = OAuthConfig {
            state_secret: "01234567890123456789012345678901".into(),
            ..Default::default()
        };

        oauth.state_cookie_name = " oauth_state".into();
        assert!(oauth.validate().is_err());

        oauth.state_cookie_name = "bad;name".into();
        assert!(oauth.validate().is_err());

        oauth.state_cookie_name = "bad=name".into();
        assert!(oauth.validate().is_err());

        oauth.state_cookie_name = "my_oauth_state".into();
        assert!(oauth.validate().is_ok());
    }

    #[test]
    fn rejects_invalid_state_cookie_path() {
        let mut oauth = OAuthConfig {
            state_secret: "01234567890123456789012345678901".into(),
            ..Default::default()
        };

        oauth.state_cookie_path = "/bad path".into();
        assert!(oauth.validate().is_err());

        oauth.state_cookie_path = "/bad;path".into();
        assert!(oauth.validate().is_err());

        oauth.state_cookie_path = "/".into();
        assert!(oauth.validate().is_ok());
    }

    #[test]
    fn test_oauth_config_validation_provider_keys() {
        let mut oauth = OAuthConfig {
            state_secret: "01234567890123456789012345678901".into(),
            ..Default::default()
        };
        oauth.providers.insert(
            "discord".into(),
            ProviderConfig::new("cid", "sec", "https://app.com/callback", vec![], false),
        );
        assert!(oauth.validate().is_err());
    }

    #[test]
    fn test_oauth_config_validation_provider_required_fields() {
        let mut oauth = OAuthConfig {
            state_secret: "01234567890123456789012345678901".into(),
            ..Default::default()
        };

        // Missing client_secret on enabled Google provider
        oauth.providers.insert(
            "google".into(),
            ProviderConfig::new("cid", "", "https://app.com/callback", vec![], true),
        );
        assert!(oauth.validate().is_err());

        // Missing client_id
        oauth.providers.insert(
            "google".into(),
            ProviderConfig::new("", "sec", "https://app.com/callback", vec![], true),
        );
        assert!(oauth.validate().is_err());

        // Missing redirect_uri
        oauth.providers.insert(
            "google".into(),
            ProviderConfig::new("cid", "sec", "", vec![], true),
        );
        assert!(oauth.validate().is_err());
    }

    #[test]
    fn test_oauth_config_debug_redacts_secrets() {
        let provider = ProviderConfig {
            client_id: "client-id-123".into(),
            client_secret: "super-secret-key".into(),
            redirect_uri: "https://example.com/callback".into(),
            scopes: vec!["email".into()],
            enabled: true,
            team_id: Some("team1".into()),
            key_id: Some("key1".into()),
            private_key: Some("private-key-secret".into()),
        };

        let rendered = format!("{provider:?}");
        assert!(!rendered.contains("super-secret-key"));
        assert!(!rendered.contains("private-key-secret"));
        assert!(rendered.contains("[REDACTED]"));

        let oauth = OAuthConfig {
            state_secret: "super-secret-oauth-state-key-32b".into(),
            ..Default::default()
        };
        let rendered_oauth = format!("{oauth:?}");
        assert!(!rendered_oauth.contains("super-secret-oauth-state-key-32b"));
        assert!(rendered_oauth.contains("[REDACTED]"));
    }

    #[test]
    fn oauth_env_populates_providers_and_state() {
        let cfg = Config::from_lookup(|key| match key {
            "DATABASE_URL" => Ok("postgres://localhost/test".into()),
            "BASE_URL" => Ok("https://app.example.com".into()),
            "OAUTH_STATE_SECRET" => Ok("01234567890123456789012345678901".into()),
            "OAUTH_STATE_COOKIE_NAME" => Ok("my_oauth_state".into()),
            "OAUTH_STATE_TTL_SECS" => Ok("900".into()),
            "OAUTH_CALLBACK_BASE_URL" => Ok("https://app.example.com".into()),
            "OAUTH_GOOGLE_ENABLED" => Ok("true".into()),
            "OAUTH_GOOGLE_CLIENT_ID" => Ok("google-id".into()),
            "OAUTH_GOOGLE_CLIENT_SECRET" => Ok("google-secret".into()),
            "OAUTH_GOOGLE_REDIRECT_URI" => Ok("https://app.example.com/cb".into()),
            _ => Err(std::env::VarError::NotPresent),
        })
        .expect("load oauth env vars");

        assert_eq!(cfg.oauth.state_secret, "01234567890123456789012345678901");
        assert_eq!(cfg.oauth.state_cookie_name, "my_oauth_state");
        assert_eq!(cfg.oauth.state_cookie_path, DEFAULT_OAUTH_STATE_COOKIE_PATH);
        assert_eq!(cfg.oauth.state_ttl, Duration::from_secs(900));
        assert_eq!(cfg.oauth.callback_base_url, "https://app.example.com");
        let google = &cfg.oauth.providers["google"];
        assert!(google.enabled);
        assert_eq!(google.client_id, "google-id");
        assert_eq!(google.client_secret, "google-secret");
        assert_eq!(google.redirect_uri, "https://app.example.com/cb");
        assert!(!cfg.oauth.providers["github"].enabled);
    }

    #[test]
    fn oauth_env_rejects_invalid_values() {
        let bad_ttl = |key: &str| match key {
            "DATABASE_URL" => Ok("postgres://localhost/test".into()),
            "BASE_URL" => Ok("https://app.example.com".into()),
            "OAUTH_STATE_TTL_SECS" => Ok("not-a-number".into()),
            _ => Err(std::env::VarError::NotPresent),
        };
        assert!(matches!(
            Config::from_lookup(bad_ttl),
            Err(ConfigError::InvalidEnvVar("OAUTH_STATE_TTL_SECS"))
        ));

        let bad_bool = |key: &str| match key {
            "DATABASE_URL" => Ok("postgres://localhost/test".into()),
            "BASE_URL" => Ok("https://app.example.com".into()),
            "OAUTH_GOOGLE_ENABLED" => Ok("yes".into()),
            _ => Err(std::env::VarError::NotPresent),
        };
        assert!(matches!(
            Config::from_lookup(bad_bool),
            Err(ConfigError::InvalidEnvVar("OAUTH_GOOGLE_ENABLED"))
        ));
    }

    #[test]
    fn oauth_env_enabled_without_secret_fails_validation() {
        let cfg = Config {
            oauth: OAuthConfig {
                state_secret: "01234567890123456789012345678901".into(),
                providers: [(
                    "google".to_string(),
                    ProviderConfig::new(
                        "google-id",
                        "",
                        "https://app.example.com/cb",
                        vec![],
                        true,
                    ),
                )]
                .into_iter()
                .collect(),
                ..Default::default()
            },
            ..test_infra_config()
        };
        assert!(cfg.validate().is_err());

        let lookup = |key: &str| match key {
            "DATABASE_URL" => Ok("postgres://localhost/test".into()),
            "BASE_URL" => Ok("https://app.example.com".into()),
            "OAUTH_GOOGLE_ENABLED" => Ok("true".into()),
            "OAUTH_GOOGLE_CLIENT_ID" => Ok("google-id".into()),
            "OAUTH_GOOGLE_REDIRECT_URI" => Ok("https://app.example.com/cb".into()),
            _ => Err(std::env::VarError::NotPresent),
        };
        assert!(Config::from_lookup(lookup).is_err());
    }
}
