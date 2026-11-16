use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    db::models::Session,
    error::AppError,
    handler::untrusted_client_ip,
    middleware::{
        auth::{AuthUser, require_auth},
        csrf_middleware,
    },
    session::{
        bearer::read_bearer_token,
        cookie::{clear_session_cookie, read_session_cookie, set_csrf_cookie, set_session_cookie},
    },
    state::AppState,
};

/// Wire response for session metadata.
///
/// `session_id` is the SHA-256 hash (`token_hash`) — 64-character lowercase hex.
/// The raw 32-character session ID token is never exposed in response bodies.
/// `csrf_token` is strictly omitted from the response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionInfoResponse {
    pub session_id: String,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
    #[serde(rename = "expires_at")]
    pub absolute_expires_at: DateTime<Utc>,
    pub session_type: String,
}

/// GET /auth/session (and /auth/session/me)
///
/// Returns metadata for the current authenticated session.
///
/// Takes the row `require_auth` already validated (and touched) from request
/// extensions — no second SELECT per request.
pub async fn get_session(session: Session) -> Json<SessionInfoResponse> {
    Json(SessionInfoResponse {
        session_id: session.token_hash,
        created_at: session.created_at,
        last_active_at: session.last_active_at,
        absolute_expires_at: session.absolute_expires_at,
        session_type: session.session_type,
    })
}

/// DELETE /auth/session (and POST /auth/session/revoke)
///
/// Revokes the current session and clears the session cookie.
///
/// # Errors
///
/// Returns `AppError` when the session is missing, the database fails, or the
/// clear cookie cannot be encoded.
pub async fn delete_session(
    State(state): State<AppState>,
    auth_user: AuthUser,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let raw_id = read_session_cookie(&headers, &state.config.session.cookie_name)
        .or_else(|| read_bearer_token(&headers))
        .ok_or(AppError::SessionNotFound)?;

    // Server-side invalidation happens first — server state is authoritative.
    state.session_service.invalidate_session(&raw_id).await?;

    tracing::info!(
        event = "logout",
        user_id = %auth_user.user_id,
    );

    let mut response = StatusCode::OK.into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, clear_session_cookie(&state.config)?);
    Ok(response)
}

/// GET /auth/sessions
///
/// Lists all active (non-expired) sessions for the authenticated user.
pub async fn list_sessions(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<Vec<SessionInfoResponse>>, AppError> {
    let sessions = state
        .session_service
        .list_user_sessions(auth_user.user_id)
        .await?;

    let response: Vec<SessionInfoResponse> = sessions
        .into_iter()
        .map(|s| SessionInfoResponse {
            session_id: s.token_hash,
            created_at: s.created_at,
            last_active_at: s.last_active_at,
            absolute_expires_at: s.absolute_expires_at,
            session_type: s.session_type,
        })
        .collect();

    Ok(Json(response))
}

/// DELETE /auth/sessions (and POST /auth/session/revoke-all)
///
/// Revokes all active sessions for the authenticated user and clears the session cookie.
///
/// # Errors
///
/// Returns `AppError` when the database fails or the clear cookie cannot be encoded.
pub async fn delete_all_sessions(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Response, AppError> {
    state
        .session_service
        .invalidate_all_user_sessions(auth_user.user_id)
        .await?;

    tracing::info!(
        event = "all_sessions_invalidated",
        user_id = %auth_user.user_id,
        triggered_by = "user_request",
    );

    let mut response = StatusCode::OK.into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, clear_session_cookie(&state.config)?);
    Ok(response)
}

/// POST /auth/session/refresh
///
/// Rotates the active session: revokes the old token and issues a fresh token.
///
/// # Errors
///
/// Returns `AppError` when the session is missing/expired, the database fails,
/// or the rotated cookies cannot be encoded.
pub async fn refresh_session(
    State(state): State<AppState>,
    auth_user: AuthUser,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let raw_id = read_session_cookie(&headers, &state.config.session.cookie_name)
        .or_else(|| read_bearer_token(&headers))
        .ok_or(AppError::SessionNotFound)?;

    // Spoofable unless a trusted proxy strips these headers; audit use only.
    let ip = untrusted_client_ip(&headers);

    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());

    let (session, new_raw_id) = state
        .session_service
        .rotate_session(&raw_id, ip, user_agent)
        .await?;

    tracing::info!(
        event = "session_refreshed",
        user_id = %auth_user.user_id,
        session_type = %session.session_type,
    );

    if session.session_type == "bearer" {
        Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "token": new_raw_id,
                "user_id": session.user_id,
            })),
        )
            .into_response())
    } else {
        let mut response = StatusCode::OK.into_response();
        response.headers_mut().insert(
            header::SET_COOKIE,
            set_session_cookie(&state.config, new_raw_id.as_str())?,
        );
        if let Some(ref csrf) = session.csrf_token {
            response.headers_mut().append(
                header::SET_COOKIE,
                set_csrf_cookie(&state.config, csrf.as_str())?,
            );
        }
        Ok(response)
    }
}

/// Router builder for session endpoints protected by `require_auth` middleware.
pub fn routes(state: AppState) -> Router {
    Router::new()
        .route(
            "/session",
            axum::routing::get(get_session).delete(delete_session),
        )
        .route("/session/me", axum::routing::get(get_session))
        .route("/session/refresh", axum::routing::post(refresh_session))
        .route("/session/revoke", axum::routing::post(delete_session))
        .route(
            "/session/revoke-all",
            axum::routing::post(delete_all_sessions),
        )
        .route(
            "/sessions",
            axum::routing::get(list_sessions).delete(delete_all_sessions),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            csrf_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn get_session_serves_extension_row_without_refetch() {
        let now = Utc::now();
        let csrf = "f".repeat(64);
        let session = Session {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            token_hash: "e".repeat(64),
            created_at: now,
            last_active_at: now,
            absolute_expires_at: now,
            session_type: "cookie".to_string(),
            csrf_token: Some(csrf.clone()),
        };
        // Handler takes the validated row from extensions; no DB read involved.
        let body = get_session(session.clone()).await.0;
        assert_eq!(body.session_id, session.token_hash);
        assert_eq!(body.created_at, session.created_at);
        assert_eq!(body.last_active_at, session.last_active_at);
        assert_eq!(body.absolute_expires_at, session.absolute_expires_at);
        assert_eq!(body.session_type, session.session_type);
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(!serialized.contains(&csrf));
    }

    #[test]
    fn get_session_response_session_id_is_64_chars() {
        let hash = "a".repeat(64);
        let resp = SessionInfoResponse {
            session_id: hash.clone(),
            created_at: Utc::now(),
            last_active_at: Utc::now(),
            absolute_expires_at: Utc::now(),
            session_type: "cookie".to_string(),
        };
        assert_eq!(resp.session_id.len(), 64);
        let serialized = serde_json::to_string(&resp).unwrap();
        assert!(serialized.contains(&hash));
    }

    #[test]
    fn get_session_response_does_not_contain_csrf_token() {
        let resp = SessionInfoResponse {
            session_id: "b".repeat(64),
            created_at: Utc::now(),
            last_active_at: Utc::now(),
            absolute_expires_at: Utc::now(),
            session_type: "cookie".to_string(),
        };
        let serialized = serde_json::to_string(&resp).unwrap();
        assert!(!serialized.contains("csrf"));
        assert!(serialized.contains("expires_at"));
    }

    #[test]
    fn list_sessions_returns_array() {
        let list = vec![SessionInfoResponse {
            session_id: "c".repeat(64),
            created_at: Utc::now(),
            last_active_at: Utc::now(),
            absolute_expires_at: Utc::now(),
            session_type: "bearer".to_string(),
        }];
        let val = serde_json::to_value(&list).unwrap();
        assert!(val.is_array());
        assert_eq!(val.as_array().unwrap().len(), 1);
    }
}
