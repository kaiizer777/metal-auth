use axum::{
    Form, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::models::LoginResponse,
    db::models::OAuthAccount,
    error::{AppError, truncate_for_log},
    handler::untrusted_client_ip,
    middleware::{AuthUser, csrf_middleware, require_auth},
    oauth::{OAUTH_BODY_LIMIT, OAuthCallbackOutcome, SUPPORTED_PROVIDERS},
    ratelimit::rate_limit_key,
    session::cookie::{set_csrf_cookie, set_session_cookie},
    state::AppState,
};

/// Upper bound on `redirect_url`; the value is signed into the state cookie and
/// re-emitted as `Location`, so an unbounded value blows past header limits.
const MAX_REDIRECT_URL_LEN: usize = 2048;

/// Fragment key handing a pending second-factor challenge to the destination app.
///
/// A fragment is never sent to a server, so the half-authenticated token stays out of
/// `Referer`, proxy logs, and this service's own request logging.
const TOTP_CHALLENGE_FRAGMENT_KEY: &str = "totp_challenge";

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

/// Builds the browser handoff for a pending second factor.
///
/// The destination is sanitized here rather than trusted from the service, exactly like the
/// `Login` and `Linked` arms. A destination that already carries a fragment cannot also carry
/// the challenge, so that fragment is dropped instead of emitting two `#`.
fn totp_challenge_location(destination: &str, challenge_token: &str) -> String {
    let destination = safe_oauth_redirect(destination);
    let destination = destination.split('#').next().unwrap_or("/");
    format!("{destination}#{TOTP_CHALLENGE_FRAGMENT_KEY}={challenge_token}")
}

/// Attaches a `Set-Cookie` header clearing the provider-scoped OAuth state cookie.
fn oauth_error_response(state: &AppState, provider: &str, err: AppError) -> Response {
    let mut resp = err.into_response();
    clear_state_cookie(&mut resp, state, provider);
    resp
}

/// Appends a `Set-Cookie` header, logging when the value cannot be encoded.
///
/// Cookie strings are usually built from config values vetted by
/// `OAuthConfig::validate`, but that guarantee is bypassable, so a
/// `HeaderValue::from_str` rejection drops the header and emits an error log
/// (cookie name only, never the value) instead of failing silently. Callers
/// keep their status/`Location` semantics; the missing `Set-Cookie` is now
/// traceable. Valid input takes the identical append path as before.
fn append_set_cookie(resp: &mut Response, cookie: &str) {
    match header::HeaderValue::from_str(cookie) {
        Ok(hv) => {
            resp.headers_mut().append(header::SET_COOKIE, hv);
        }
        Err(_) => {
            let name = cookie.split(['=', ';']).next().unwrap_or("");
            tracing::error!(
                event = "cookie_build_failed",
                kind = "oauth_state",
                cookie = %truncate_for_log(name),
                "oauth state cookie attach failed",
            );
        }
    }
}

fn clear_state_cookie(resp: &mut Response, state: &AppState, provider: &str) {
    append_set_cookie(
        resp,
        &state
            .oauth_service
            .clear_state_cookie_for_provider(provider),
    );
}

fn check_redirect_url(redirect_url: Option<String>) -> Result<Option<String>, AppError> {
    match redirect_url {
        Some(url) if url.len() > MAX_REDIRECT_URL_LEN => Err(AppError::ValidationError(format!(
            "redirect_url exceeds {MAX_REDIRECT_URL_LEN} bytes"
        ))),
        other => Ok(other),
    }
}

fn check_oauth_rate_limit(
    state: &AppState,
    headers: &HeaderMap,
    provider: &str,
    op: &str,
) -> Result<(), AppError> {
    if !state.config.rate_limit.enabled {
        return Ok(());
    }
    let ip = untrusted_client_ip(headers).unwrap_or("127.0.0.1");
    let key = rate_limit_key(&format!("oauth:{op}:{provider}"), ip);
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
    let Some(accept) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    accept.split(',').any(|media_range| {
        media_range
            .split(';')
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
    })
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
        return oauth_error_response(&state, &provider, AppError::OAuthProviderNotFound);
    }

    if let Err(e) = check_oauth_rate_limit(&state, &headers, &provider, "initiate") {
        return oauth_error_response(&state, &provider, e);
    }

    let redirect_url = match check_redirect_url(query.redirect_url) {
        Ok(url) => url,
        Err(e) => return oauth_error_response(&state, &provider, e),
    };

    let (auth_url, set_cookie_str) =
        match state.oauth_service.initiate_flow(&provider, redirect_url) {
            Ok(v) => v,
            Err(e) => return oauth_error_response(&state, &provider, e),
        };

    let mut resp = (StatusCode::FOUND, [(header::LOCATION, auth_url)]).into_response();
    append_set_cookie(&mut resp, &set_cookie_str);
    resp
}

/// GET /auth/oauth/{provider}/link (and /api/auth/oauth/{provider}/link)
///
/// Initiates an authenticated account linking flow, embedding user_id in the signed state.
pub async fn oauth_link_initiate(
    State(state): State<AppState>,
    AuthUser {
        user_id,
        session_hash,
        ..
    }: AuthUser,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Query(query): Query<InitiateQuery>,
) -> Response {
    if !SUPPORTED_PROVIDERS.contains(&provider.as_str()) {
        return oauth_error_response(&state, &provider, AppError::OAuthProviderNotFound);
    }

    if let Err(e) = check_oauth_rate_limit(&state, &headers, &provider, "initiate") {
        return oauth_error_response(&state, &provider, e);
    }

    let redirect_url = match check_redirect_url(query.redirect_url) {
        Ok(url) => url,
        Err(e) => return oauth_error_response(&state, &provider, e),
    };

    let (auth_url, set_cookie_str) = match state.oauth_service.initiate_link_flow(
        &provider,
        user_id,
        redirect_url,
        Some(session_hash),
    ) {
        Ok(v) => v,
        Err(e) => return oauth_error_response(&state, &provider, e),
    };

    let mut resp = (StatusCode::FOUND, [(header::LOCATION, auth_url)]).into_response();
    append_set_cookie(&mut resp, &set_cookie_str);
    resp
}

/// GET /auth/oauth/{provider}/callback (and /api/auth/oauth/{provider}/callback)
pub async fn oauth_callback(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let params = CallbackParams {
        provider: &provider,
        code: query.code.as_deref(),
        state: query.state.as_deref(),
        error: query.error.as_deref(),
        session_type: query.session_type.as_deref(),
    };
    handle_callback_internal(&state, &headers, params).await
}

/// POST /auth/oauth/{provider}/callback (and /api/auth/oauth/{provider}/callback)
///
/// Handles Apple `form_post` responses. The route is CSRF-exempt by construction:
/// `public_oauth_routes` is never wrapped in `csrf_middleware`, and the signed
/// `state` parameter supplies the cross-site request binding instead.
pub async fn oauth_callback_post(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Form(form): Form<AppleCallbackForm>,
) -> Response {
    let params = CallbackParams {
        provider: &provider,
        code: form.code.as_deref(),
        state: form.state.as_deref(),
        error: form.error.as_deref(),
        session_type: None,
    };
    handle_callback_internal(&state, &headers, params).await
}

struct CallbackParams<'a> {
    provider: &'a str,
    code: Option<&'a str>,
    state: Option<&'a str>,
    error: Option<&'a str>,
    session_type: Option<&'a str>,
}

fn log_callback_failure(
    provider: &str,
    reason: &str,
    ip: Option<&str>,
    user_agent: Option<&str>,
    error: Option<&str>,
) {
    tracing::info!(
        event = "oauth_callback_failure",
        provider = provider,
        reason = reason,
        error = error.map(truncate_for_log),
        ip = ?ip,
        user_agent = user_agent.map(truncate_for_log),
    );
}

async fn handle_callback_internal(
    state: &AppState,
    headers: &HeaderMap,
    params: CallbackParams<'_>,
) -> Response {
    let provider = params.provider;
    if !SUPPORTED_PROVIDERS.contains(&provider) {
        return oauth_error_response(state, provider, AppError::OAuthProviderNotFound);
    }

    if let Err(e) = check_oauth_rate_limit(state, headers, provider, "callback") {
        return oauth_error_response(state, provider, e);
    }

    let client_ip = untrusted_client_ip(headers);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());

    if let Some(err) = params.error {
        log_callback_failure(provider, "provider_error", client_ip, user_agent, Some(err));
        return oauth_error_response(state, provider, AppError::OAuthProviderError);
    }

    let Some(code) = params.code.filter(|c| !c.trim().is_empty()) else {
        log_callback_failure(provider, "code_invalid", client_ip, user_agent, None);
        return oauth_error_response(state, provider, AppError::OAuthCodeInvalid);
    };

    let Some(state_param) = params.state.filter(|s| !s.trim().is_empty()) else {
        log_callback_failure(provider, "state_invalid", client_ip, user_agent, None);
        return oauth_error_response(state, provider, AppError::OAuthStateInvalid);
    };

    let wants_bearer = wants_oauth_bearer(headers, params.session_type);
    let wants_json = wants_oauth_json(headers, params.session_type);
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
        Err(e) => return oauth_error_response(state, provider, e),
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
                append_set_cookie(&mut resp, &result.clear_cookie_header);
                return resp;
            }

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
                Err(e) => return oauth_error_response(state, provider, e),
            }

            if let Some(ref csrf) = result.session.csrf_token {
                match set_csrf_cookie(&state.config, csrf) {
                    Ok(hv) => {
                        resp.headers_mut().append(header::SET_COOKIE, hv);
                    }
                    Err(e) => return oauth_error_response(state, provider, e),
                }
            }

            append_set_cookie(&mut resp, &result.clear_cookie_header);
            resp
        }
        OAuthCallbackOutcome::TwoFactorRequired {
            challenge_token,
            redirect_url,
            clear_cookie_header,
        } => {
            let mut resp = if wants_json {
                (
                    StatusCode::OK,
                    Json(LoginResponse::two_factor_required(challenge_token)),
                )
                    .into_response()
            } else {
                let location = totp_challenge_location(&redirect_url, &challenge_token);
                match header::HeaderValue::from_str(&location) {
                    Ok(value) => (StatusCode::FOUND, [(header::LOCATION, value)]).into_response(),
                    // Unreachable: `safe_oauth_redirect` rejects control characters and the
                    // minted challenge is hex. Fail loudly rather than emit a broken header.
                    Err(_) => return oauth_error_response(state, provider, AppError::Internal),
                }
            };
            append_set_cookie(&mut resp, &clear_cookie_header);
            resp
        }
        OAuthCallbackOutcome::Linked {
            user: _,
            account,
            redirect_url,
            clear_cookie_header,
        } => {
            let mut resp = if wants_json {
                (StatusCode::OK, Json(account)).into_response()
            } else {
                let sanitized_redirect = safe_oauth_redirect(&redirect_url);
                (StatusCode::FOUND, [(header::LOCATION, sanitized_redirect)]).into_response()
            };

            append_set_cookie(&mut resp, &clear_cookie_header);
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
) -> Response {
    if !SUPPORTED_PROVIDERS.contains(&provider.as_str()) {
        return oauth_error_response(&state, &provider, AppError::OAuthProviderNotFound);
    }
    if let Err(e) = check_oauth_rate_limit(&state, &headers, &provider, "link") {
        return oauth_error_response(&state, &provider, e);
    }
    let cookie_header = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());
    let account = match state
        .oauth_service
        .link_account_identity(user_id, &provider, &req.code, &req.state, cookie_header)
        .await
    {
        Ok(acc) => acc,
        Err(e) => return oauth_error_response(&state, &provider, e),
    };
    let mut resp = Json(account).into_response();
    clear_state_cookie(&mut resp, &state, &provider);
    resp
}

/// POST /auth/oauth/{provider}/unlink (and /api/auth/oauth/{provider}/unlink)
///
/// Unlinks an external identity, preventing lockout if no password remains.
pub async fn unlink_account(
    State(state): State<AppState>,
    AuthUser { user_id, .. }: AuthUser,
    Path(provider): Path<String>,
) -> Response {
    if !SUPPORTED_PROVIDERS.contains(&provider.as_str()) {
        return oauth_error_response(&state, &provider, AppError::OAuthProviderNotFound);
    }
    if let Err(e) = state.oauth_service.unlink_account(user_id, &provider).await {
        return oauth_error_response(&state, &provider, e);
    }
    Json(MessageResponse {
        message: "account unlinked",
    })
    .into_response()
}

/// Constructs the OAuth sub-router.
pub fn routes(state: AppState) -> Router {
    let authenticated_csrf_routes = Router::new()
        .route(
            "/oauth/{provider}/link",
            axum::routing::post(link_account)
                .layer(axum::extract::DefaultBodyLimit::max(OAUTH_BODY_LIMIT)),
        )
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

    #[test]
    fn test_safe_oauth_redirect_rejects_percent_encoded_and_all_c0_controls() {
        // Percent-encoded separators are not decoded here; they stay inert path text.
        assert_eq!(safe_oauth_redirect("/%2F%2Fevil.com"), "/%2F%2Fevil.com");
        assert_eq!(safe_oauth_redirect("/%5Cevil.com"), "/%5Cevil.com");
        assert_eq!(
            safe_oauth_redirect("/%252F%252Fevil.com"),
            "/%252F%252Fevil.com"
        );

        for control in 0u8..=0x1f {
            let target = format!("/x{}y", char::from(control));
            assert_eq!(
                safe_oauth_redirect(&target),
                "/",
                "C0 control {control:#04x} must be rejected"
            );
        }
    }

    #[test]
    fn test_totp_challenge_location_appends_fragment_to_a_sanitized_destination() {
        let token = "a".repeat(64);
        assert_eq!(
            totp_challenge_location("/app/settings", &token),
            format!("/app/settings#totp_challenge={token}")
        );
        // An existing query survives: the fragment separator is not a query separator.
        assert_eq!(
            totp_challenge_location("/app/home?tab=1", &token),
            format!("/app/home?tab=1#totp_challenge={token}")
        );
        // A destination that already carries a fragment cannot carry the challenge too.
        assert_eq!(
            totp_challenge_location("/app/home#section", &token),
            format!("/app/home#totp_challenge={token}")
        );
        for rejected in ["https://evil.com", "//evil.com", "/with\rnewline", ""] {
            assert_eq!(
                totp_challenge_location(rejected, &token),
                format!("/#totp_challenge={token}")
            );
        }
    }

    #[test]
    fn test_header_value_rejects_unencodable_cookie_bytes() {
        // Probe result: `HeaderValue::from_str` rejects C0 controls and DEL
        // but accepts obs-text (>= 0x80), which `is_valid_cookie_path` also
        // permits. A boot-validated config therefore rarely trips the `Err`
        // arm; the reachable surface is validate-bypass construction and any
        // future input, and the defect is the silent drop itself.
        assert!(header::HeaderValue::from_str("oauth_state=abc; Path=/\n").is_err());
        assert!(header::HeaderValue::from_str("oauth_state=abc; Path=/\u{7f}").is_err());
        assert!(header::HeaderValue::from_str("oauth_state=abc; Path=/\u{80}").is_ok());
    }

    #[test]
    fn test_append_set_cookie_attaches_valid_value() {
        let mut resp = StatusCode::FOUND.into_response();
        let cookie = "oauth_state=abc; Path=/; Max-Age=600; HttpOnly; SameSite=Lax";
        append_set_cookie(&mut resp, cookie);
        let attached = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>();
        assert_eq!(attached, [cookie]);
    }

    #[test]
    fn test_append_set_cookie_drops_unencodable_value() {
        let mut resp = StatusCode::FOUND.into_response();
        append_set_cookie(&mut resp, "oauth_state=abc; Path=/\n");
        assert!(
            resp.headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .next()
                .is_none()
        );
    }

    #[test]
    fn test_append_set_cookie_logs_unencodable_value() {
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct Sink(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let sink = Sink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer({
                let sink = sink.clone();
                move || sink.clone()
            })
            .finish();
        let logged = || String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();

        tracing::subscriber::with_default(subscriber, || {
            let mut resp = StatusCode::FOUND.into_response();
            append_set_cookie(&mut resp, "oauth_state=abc; Path=/; Max-Age=600");
            assert!(logged().is_empty());

            let mut resp = StatusCode::FOUND.into_response();
            append_set_cookie(&mut resp, "oauth_state=secretvalue9zqx; Path=/\n");
            let out = logged();
            assert!(out.contains("cookie_build_failed"), "missing event: {out}");
            assert!(out.contains("oauth_state"), "missing kind: {out}");
            assert!(!out.contains("secretvalue9zqx"), "value leaked: {out}");
        });
    }

    #[test]
    fn test_check_redirect_url_caps_length() {
        assert!(check_redirect_url(None).unwrap().is_none());

        let at_limit = format!("/{}", "a".repeat(MAX_REDIRECT_URL_LEN - 1));
        assert_eq!(at_limit.len(), MAX_REDIRECT_URL_LEN);
        assert!(check_redirect_url(Some(at_limit)).is_ok());

        let over_limit = format!("/{}", "a".repeat(MAX_REDIRECT_URL_LEN));
        assert!(matches!(
            check_redirect_url(Some(over_limit)),
            Err(AppError::ValidationError(_))
        ));
    }

    #[test]
    fn test_wants_oauth_json_matches_exact_media_type() {
        let with_accept = |value: &'static str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT, header::HeaderValue::from_static(value));
            headers
        };

        assert!(wants_oauth_json(&with_accept("application/json"), None));
        assert!(wants_oauth_json(
            &with_accept("text/html, application/json; q=0.9"),
            None
        ));
        assert!(wants_oauth_json(&with_accept("APPLICATION/JSON"), None));
        assert!(!wants_oauth_json(&with_accept("application/jsonx"), None));
        assert!(!wants_oauth_json(
            &with_accept("text/plain;note=application/json"),
            None
        ));
        assert!(!wants_oauth_json(&HeaderMap::new(), None));
        assert!(wants_oauth_json(&HeaderMap::new(), Some("bearer")));
    }

    #[tokio::test]
    async fn test_oauth_initiate_then_callback_pass_single_attempt_budget() {
        use crate::config::{AppConfig, Config};
        use sqlx::PgPool;
        use std::sync::Arc;

        let mut cfg = Config::default();
        cfg.rate_limit.enabled = true;
        cfg.rate_limit.max_attempts = 1;
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let state =
            AppState::with_configs_and_dispatcher(pool, cfg, Arc::new(AppConfig::default()), None)
                .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            header::HeaderValue::from_static("203.0.113.9"),
        );
        check_oauth_rate_limit(&state, &headers, "google", "initiate").unwrap();
        check_oauth_rate_limit(&state, &headers, "google", "callback").unwrap();
        assert!(matches!(
            check_oauth_rate_limit(&state, &headers, "google", "initiate"),
            Err(AppError::RateLimitExceeded)
        ));
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
        let state =
            AppState::with_configs_and_dispatcher(pool, cfg, Arc::new(AppConfig::default()), None)
                .unwrap();

        let ip = "203.0.113.7";
        state
            .rate_limiter
            .check_rate_limit(&rate_limit_key("oauth:link:google", ip))
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            header::HeaderValue::from_static("203.0.113.7"),
        );
        let resp = link_account(
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
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
