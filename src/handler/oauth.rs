use axum::{
    Form, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    db::models::OAuthAccount,
    error::AppError,
    handler::untrusted_client_ip,
    middleware::{AuthUser, csrf_middleware, require_auth},
    oauth::{OAUTH_BODY_LIMIT, OAuthCallbackOutcome, SUPPORTED_PROVIDERS},
    ratelimit::rate_limit_key,
    session::cookie::{set_csrf_cookie, set_session_cookie},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct InitiateQuery {
    pub redirect_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    #[serde(rename = "type")]
    pub session_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AppleCallbackForm {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub user: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LinkRequest {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Serialize)]
pub struct OAuthSuccessResponse {
    pub user_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf_token: Option<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: &'static str,
}

/// Sanitizes redirect targets to prevent open redirect vulnerabilities (CWE-601).
///
/// Rejects scheme-relative URLs ("//"), backslashes ("/\"), whitespace, and control chars.
#[must_use]
pub fn safe_oauth_redirect(target: &str) -> &str {
    if target.is_empty() || !target.starts_with('/') {
        return "/";
    }
    if target.len() > 1 && (target.as_bytes()[1] == b'/' || target.as_bytes()[1] == b'\\') {
        return "/";
    }
    if target
        .chars()
        .any(|c| c == '\\' || c == ' ' || c.is_control())
    {
        return "/";
    }
    target
}

/// Attaches a Set-Cookie header clearing the `oauth_state` cookie on error.
fn oauth_error_response(state: &AppState, err: AppError) -> Response {
    let mut resp = err.into_response();
    let clear_cookie = state.oauth_service.clear_state_cookie();
    if let Ok(hv) = header::HeaderValue::from_str(&clear_cookie) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
    resp
}

fn check_oauth_rate_limit(
    state: &AppState,
    headers: &HeaderMap,
    provider: &str,
) -> Result<(), AppError> {
    if !state.config.rate_limit.enabled {
        return Ok(());
    }
    let ip = untrusted_client_ip(headers).unwrap_or("127.0.0.1");
    let key = rate_limit_key(&format!("oauth:{provider}"), ip);
    state.rate_limiter.check_rate_limit(&key)
}

fn wants_oauth_bearer(headers: &HeaderMap, query_type: Option<&str>) -> bool {
    if let Some(h) = headers.get("x-auth-type")
        && let Ok(s) = h.to_str()
        && s.eq_ignore_ascii_case("bearer")
    {
        return true;
    }
    if let Some(t) = query_type
        && t.eq_ignore_ascii_case("bearer")
    {
        return true;
    }
    false
}

fn wants_oauth_json(headers: &HeaderMap, query_type: Option<&str>) -> bool {
    if wants_oauth_bearer(headers, query_type) {
        return true;
    }
    if let Some(accept) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) {
        return accept.to_ascii_lowercase().contains("application/json");
    }
    false
}

/// GET /auth/oauth/{provider} (and /api/auth/oauth/{provider})
///
/// Initiates the OAuth authorization flow, generating a signed state cookie and
/// returning a 302 redirect to the provider's authorization endpoint.
pub async fn oauth_initiate(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Query(query): Query<InitiateQuery>,
) -> Response {
    if !SUPPORTED_PROVIDERS.contains(&provider.as_str()) {
        return oauth_error_response(&state, AppError::OAuthProviderNotFound);
    }

    if let Err(e) = check_oauth_rate_limit(&state, &headers, &provider) {
        return oauth_error_response(&state, e);
    }

    let (auth_url, set_cookie_str) = match state
        .oauth_service
        .initiate_flow(&provider, query.redirect_url)
    {
        Ok(v) => v,
        Err(e) => return oauth_error_response(&state, e),
    };

    let mut resp = (StatusCode::FOUND, [(header::LOCATION, auth_url)]).into_response();
    if let Ok(hv) = header::HeaderValue::from_str(&set_cookie_str) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

/// GET /auth/oauth/{provider}/link (and /api/auth/oauth/{provider}/link)
///
/// Initiates an authenticated account linking flow, embedding user_id in the signed state.
pub async fn oauth_link_initiate(
    State(state): State<AppState>,
    AuthUser { user_id, .. }: AuthUser,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Query(query): Query<InitiateQuery>,
) -> Response {
    if !SUPPORTED_PROVIDERS.contains(&provider.as_str()) {
        return oauth_error_response(&state, AppError::OAuthProviderNotFound);
    }

    if let Err(e) = check_oauth_rate_limit(&state, &headers, &provider) {
        return oauth_error_response(&state, e);
    }

    let (auth_url, set_cookie_str) =
        match state
            .oauth_service
            .initiate_link_flow(&provider, user_id, query.redirect_url)
        {
            Ok(v) => v,
            Err(e) => return oauth_error_response(&state, e),
        };

    let mut resp = (StatusCode::FOUND, [(header::LOCATION, auth_url)]).into_response();
    if let Ok(hv) = header::HeaderValue::from_str(&set_cookie_str) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

/// GET /auth/oauth/{provider}/callback (and /api/auth/oauth/{provider}/callback)
pub async fn oauth_callback(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    handle_callback_internal(
        &state,
        &provider,
        &headers,
        query.code.as_deref(),
        query.state.as_deref(),
        query.error.as_deref(),
        query.session_type.as_deref(),
    )
    .await
}

/// POST /auth/oauth/{provider}/callback (and /api/auth/oauth/{provider}/callback)
///
/// Handles Apple `form_post` responses. Exempt from local CSRF middleware.
pub async fn oauth_callback_post(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Form(form): Form<AppleCallbackForm>,
) -> Response {
    handle_callback_internal(
        &state,
        &provider,
        &headers,
        form.code.as_deref(),
        form.state.as_deref(),
        form.error.as_deref(),
        None,
    )
    .await
}

async fn handle_callback_internal(
    state: &AppState,
    provider: &str,
    headers: &HeaderMap,
    code: Option<&str>,
    state_param: Option<&str>,
    error_param: Option<&str>,
    query_session_type: Option<&str>,
) -> Response {
    if !SUPPORTED_PROVIDERS.contains(&provider) {
        return oauth_error_response(state, AppError::OAuthProviderNotFound);
    }

    if let Err(e) = check_oauth_rate_limit(state, headers, provider) {
        return oauth_error_response(state, e);
    }

    let client_ip = untrusted_client_ip(headers);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());

    if let Some(err) = error_param {
        tracing::info!(
            event = "oauth_callback_failure",
            provider = provider,
            reason = "provider_error",
            error = err,
            ip = ?client_ip,
            user_agent = ?user_agent,
        );
        return oauth_error_response(state, AppError::OAuthProviderError);
    }

    let code = match code {
        Some(c) if !c.trim().is_empty() => c,
        _ => {
            tracing::info!(
                event = "oauth_callback_failure",
                provider = provider,
                reason = "code_invalid",
                ip = ?client_ip,
                user_agent = ?user_agent,
            );
            return oauth_error_response(state, AppError::OAuthCodeInvalid);
        }
    };

    let state_param = match state_param {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            tracing::info!(
                event = "oauth_callback_failure",
                provider = provider,
                reason = "state_invalid",
                ip = ?client_ip,
                user_agent = ?user_agent,
            );
            return oauth_error_response(state, AppError::OAuthStateInvalid);
        }
    };

    let wants_bearer = wants_oauth_bearer(headers, query_session_type);
    let session_type = if wants_bearer { "bearer" } else { "cookie" };

    let cookie_header = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());

    let result = match state
        .oauth_service
        .handle_callback_extended(
            provider,
            code,
            state_param,
            cookie_header,
            session_type,
            client_ip,
            user_agent,
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return oauth_error_response(state, e),
    };

    match result {
        OAuthCallbackOutcome::Login(result) => {
            if wants_bearer {
                let mut resp = (
                    StatusCode::OK,
                    Json(OAuthSuccessResponse {
                        user_id: result.user.id,
                        token: Some(result.raw_token),
                        csrf_token: None,
                        expires_at: result.session.absolute_expires_at,
                        redirect_url: None,
                    }),
                )
                    .into_response();
                if let Ok(hv) = header::HeaderValue::from_str(&result.clear_cookie_header) {
                    resp.headers_mut().append(header::SET_COOKIE, hv);
                }
                return resp;
            }

            let wants_json = wants_oauth_json(headers, query_session_type);
            let sanitized_redirect = safe_oauth_redirect(&result.redirect_url);

            let mut resp = if wants_json {
                (
                    StatusCode::OK,
                    Json(OAuthSuccessResponse {
                        user_id: result.user.id,
                        token: None,
                        csrf_token: result.session.csrf_token.clone(),
                        expires_at: result.session.absolute_expires_at,
                        redirect_url: Some(sanitized_redirect.to_string()),
                    }),
                )
                    .into_response()
            } else {
                (StatusCode::FOUND, [(header::LOCATION, sanitized_redirect)]).into_response()
            };

            match set_session_cookie(&state.config, &result.raw_token) {
                Ok(hv) => {
                    resp.headers_mut().append(header::SET_COOKIE, hv);
                }
                Err(e) => return oauth_error_response(state, e),
            }

            if let Some(ref csrf) = result.session.csrf_token {
                match set_csrf_cookie(&state.config, csrf) {
                    Ok(hv) => {
                        resp.headers_mut().append(header::SET_COOKIE, hv);
                    }
                    Err(e) => return oauth_error_response(state, e),
                }
            }

            if let Ok(hv) = header::HeaderValue::from_str(&result.clear_cookie_header) {
                resp.headers_mut().append(header::SET_COOKIE, hv);
            }

            resp
        }
        OAuthCallbackOutcome::Linked {
            user: _,
            account,
            redirect_url,
            clear_cookie_header,
        } => {
            let wants_json = wants_oauth_json(headers, query_session_type);
            let sanitized_redirect = safe_oauth_redirect(&redirect_url);

            let mut resp = if wants_json {
                (StatusCode::OK, Json(account)).into_response()
            } else {
                (StatusCode::FOUND, [(header::LOCATION, sanitized_redirect)]).into_response()
            };

            if let Ok(hv) = header::HeaderValue::from_str(&clear_cookie_header) {
                resp.headers_mut().append(header::SET_COOKIE, hv);
            }

            resp
        }
    }
}

/// GET /auth/oauth/accounts (and /api/auth/oauth/accounts)
///
/// Lists all external identities linked to the authenticated user.
pub async fn list_accounts(
    State(state): State<AppState>,
    AuthUser { user_id, .. }: AuthUser,
) -> Result<Json<Vec<OAuthAccount>>, AppError> {
    let accounts = state.oauth_service.list_linked_accounts(user_id).await?;
    Ok(Json(accounts))
}

/// POST /auth/oauth/{provider}/link (and /api/auth/oauth/{provider}/link)
///
/// Links a new external identity to the authenticated user.
pub async fn link_account(
    State(state): State<AppState>,
    AuthUser { user_id, .. }: AuthUser,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Json(req): Json<LinkRequest>,
) -> Result<Response, AppError> {
    if !SUPPORTED_PROVIDERS.contains(&provider.as_str()) {
        return Err(AppError::OAuthProviderNotFound);
    }
    check_oauth_rate_limit(&state, &headers, &provider)?;
    let cookie_header = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());
    let account = match state
        .oauth_service
        .link_account_identity(user_id, &provider, &req.code, &req.state, cookie_header)
        .await
    {
        Ok(acc) => acc,
        Err(e) => return Ok(oauth_error_response(&state, e)),
    };
    let clear_cookie = state.oauth_service.clear_state_cookie();
    let mut resp = Json(account).into_response();
    if let Ok(hv) = header::HeaderValue::from_str(&clear_cookie) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
    Ok(resp)
}

/// POST /auth/oauth/{provider}/unlink (and /api/auth/oauth/{provider}/unlink)
///
/// Unlinks an external identity, preventing lockout if no password remains.
pub async fn unlink_account(
    State(state): State<AppState>,
    AuthUser { user_id, .. }: AuthUser,
    Path(provider): Path<String>,
) -> Result<Json<MessageResponse>, AppError> {
    if !SUPPORTED_PROVIDERS.contains(&provider.as_str()) {
        return Err(AppError::OAuthProviderNotFound);
    }
    state
        .oauth_service
        .unlink_account(user_id, &provider)
        .await?;
    Ok(Json(MessageResponse {
        message: "account unlinked",
    }))
}

/// Constructs the OAuth sub-router.
pub fn routes(state: AppState) -> Router {
    let authenticated_csrf_routes = Router::new()
        .route("/oauth/{provider}/link", axum::routing::post(link_account))
        .route(
            "/oauth/{provider}/unlink",
            axum::routing::post(unlink_account),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            csrf_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ));

    let authenticated_read_routes = Router::new()
        .route("/oauth/accounts", axum::routing::get(list_accounts))
        .route(
            "/oauth/{provider}/link",
            axum::routing::get(oauth_link_initiate),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ));

    let public_oauth_routes = Router::new()
        .route("/oauth/{provider}", axum::routing::get(oauth_initiate))
        .route(
            "/oauth/{provider}/callback",
            axum::routing::get(oauth_callback)
                .post(oauth_callback_post)
                .layer(axum::extract::DefaultBodyLimit::max(OAUTH_BODY_LIMIT)),
        );

    public_oauth_routes
        .merge(authenticated_read_routes)
        .merge(authenticated_csrf_routes)
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_oauth_redirect_sanitizes_correctly() {
        assert_eq!(safe_oauth_redirect("/dashboard"), "/dashboard");
        assert_eq!(safe_oauth_redirect("/app/home?tab=1"), "/app/home?tab=1");
        assert_eq!(safe_oauth_redirect("https://evil.com"), "/");
        assert_eq!(safe_oauth_redirect("//evil.com"), "/");
        assert_eq!(safe_oauth_redirect("/\\evil.com"), "/");
        assert_eq!(safe_oauth_redirect(""), "/");
        assert_eq!(safe_oauth_redirect("relative/path"), "/");
        assert_eq!(safe_oauth_redirect("/with space"), "/");
        assert_eq!(safe_oauth_redirect("/with\ttab"), "/");
        assert_eq!(safe_oauth_redirect("/with\rnewline"), "/");
        assert_eq!(safe_oauth_redirect("/with\nnewline"), "/");
        assert_eq!(safe_oauth_redirect("/back\\slash"), "/");
        assert_eq!(safe_oauth_redirect("/\0evil"), "/");
        assert_eq!(safe_oauth_redirect("/\u{7}bell"), "/");
        assert_eq!(safe_oauth_redirect("/\u{7f}del"), "/");
    }

    #[tokio::test]
    async fn test_link_account_enforces_oauth_rate_limit() {
        use crate::config::{AppConfig, Config};
        use sqlx::PgPool;
        use std::sync::Arc;

        let mut cfg = Config::default();
        cfg.rate_limit.enabled = true;
        cfg.rate_limit.max_attempts = 1;
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let state = AppState::with_configs_and_dispatcher(
            pool,
            cfg,
            Arc::new(AppConfig::default()),
            None,
        )
        .unwrap();

        let ip = "203.0.113.7";
        state
            .rate_limiter
            .check_rate_limit(&rate_limit_key("oauth:google", ip))
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            header::HeaderValue::from_static("203.0.113.7"),
        );
        let result = link_account(
            State(state),
            AuthUser {
                user_id: Uuid::new_v4(),
                session_hash: "hash".to_string(),
                session_type: "cookie".to_string(),
            },
            Path("google".to_string()),
            headers,
            Json(LinkRequest {
                code: "code".to_string(),
                state: "state".to_string(),
            }),
        )
        .await;
        assert!(matches!(result, Err(AppError::RateLimitExceeded)));
    }
}
