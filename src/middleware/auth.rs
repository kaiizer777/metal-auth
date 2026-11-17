//! Authentication middleware and user extractor.

use axum::{
    body::Body,
    extract::{FromRequestParts, State},
    http::{Request, Response, request::Parts},
    middleware::Next,
};
use uuid::Uuid;

use crate::{
    db::models::Session,
    error::{AppError, ErrorCode},
    session::{bearer::read_bearer_token, cookie::read_session_cookie},
    state::AppState,
};

/// Authenticated user credentials and session context injected into request extensions.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
    /// SHA-256 hash of the raw session token (NEVER the raw token).
    pub session_hash: String,
    pub session_type: String,
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or_else(|| AppError::from_code(ErrorCode::SessionNotFound))
    }
}

impl<S> FromRequestParts<S> for Session
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or_else(|| AppError::from_code(ErrorCode::SessionNotFound))
    }
}

/// Axum middleware enforcing session authentication via cookie or bearer token.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, AppError> {
    let raw_id = read_session_cookie(req.headers(), &state.config.session.cookie_name)
        .or_else(|| read_bearer_token(req.headers()))
        .ok_or_else(|| AppError::from_code(ErrorCode::SessionNotFound))?;

    let session = state.session_service.get_session(&raw_id).await?;

    let auth_user = AuthUser {
        user_id: session.user_id,
        session_hash: session.token_hash.clone(),
        session_type: session.session_type.clone(),
    };

    // Share the validated row with handlers (e.g. GET /auth/session) so they
    // don't re-SELECT the same session `require_auth` just checked and touched.
    req.extensions_mut().insert(auth_user);
    req.extensions_mut().insert(session);
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, http::StatusCode, middleware::from_fn_with_state, routing::get};
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use crate::config::Config;

    fn test_app_state() -> AppState {
        let cfg = Config {
            database_url: "postgres://postgres:postgres@127.0.0.1:1/postgres".to_string(),
            ..Default::default()
        };
        let pool = PgPoolOptions::new()
            .connect_lazy(&cfg.database_url)
            .expect("lazy pool");
        AppState::new(pool, cfg).expect("AppState::new")
    }

    #[tokio::test]
    async fn test_auth_user_extractor_missing_extension() {
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let (mut parts, _) = req.into_parts();
        let result = AuthUser::from_request_parts(&mut parts, &()).await;
        assert!(matches!(result, Err(AppError::SessionNotFound)));
    }

    #[tokio::test]
    async fn test_auth_user_extractor_present_extension() {
        let user_id = Uuid::new_v4();
        let expected = AuthUser {
            user_id,
            session_hash: "hash123".to_string(),
            session_type: "cookie".to_string(),
        };

        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        req.extensions_mut().insert(expected.clone());

        let (mut parts, _) = req.into_parts();
        let result = AuthUser::from_request_parts(&mut parts, &()).await.unwrap();
        assert_eq!(result.user_id, user_id);
        assert_eq!(result.session_hash, "hash123");
        assert_eq!(result.session_type, "cookie");
    }

    #[tokio::test]
    async fn test_session_extractor_missing_extension() {
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let (mut parts, _) = req.into_parts();
        let result = Session::from_request_parts(&mut parts, &()).await;
        let err = match result {
            Err(err) => err,
            Ok(_) => panic!("missing Session extension must be rejected"),
        };
        assert!(matches!(err, AppError::SessionNotFound));
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_session_extractor_present_extension() {
        let now = chrono::Utc::now();
        let expected = Session {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            token_hash: "d".repeat(64),
            created_at: now,
            last_active_at: now,
            absolute_expires_at: now,
            session_type: "cookie".to_string(),
            csrf_token: None,
        };

        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        req.extensions_mut().insert(expected.clone());

        let (mut parts, _) = req.into_parts();
        let session = Session::from_request_parts(&mut parts, &()).await.unwrap();
        assert_eq!(session, expected);
    }

    #[tokio::test]
    async fn test_require_auth_missing_credentials_returns_401() {
        let state = test_app_state();
        let app = Router::new()
            .route(
                "/protected",
                get(|user: AuthUser| async move { format!("hello {}", user.user_id) }),
            )
            .layer(from_fn_with_state(state.clone(), require_auth))
            .with_state(state);

        let req = Request::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
