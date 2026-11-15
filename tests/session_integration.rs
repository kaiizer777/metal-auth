mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::{HeaderMap, Method, StatusCode, header};
use common::*;
use metal_auth::{ErrorCode, SessionService};
use serde_json::json;

fn extract_cookie_val(headers: &HeaderMap, name: &str) -> Option<String> {
    for val in headers.get_all(header::SET_COOKIE) {
        if let Ok(s) = val.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some((k, v)) = part.split_once('=')
                    && k.trim() == name
                {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

fn extract_cookie_header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    for val in headers.get_all(header::SET_COOKIE) {
        if let Ok(s) = val.to_str()
            && s.starts_with(&format!("{name}="))
        {
            return Some(s.to_string());
        }
    }
    None
}

async fn create_and_verify_user(app: &TestApp) -> (String, String) {
    let email = dynamic_email();
    let password = dynamic_password();

    let signup_resp = app
        .post_json(
            "/auth/signup",
            json!({
                "email": email,
                "password": password
            }),
        )
        .await;
    assert_eq!(signup_resp.status(), StatusCode::OK);

    if let Some(token) = app.email_sender.verification_token_for(&email) {
        let verify_resp = app
            .post_json(
                "/auth/verify",
                json!({
                    "token": token
                }),
            )
            .await;
        assert_eq!(verify_resp.status(), StatusCode::OK);
    }

    sqlx::query("UPDATE users SET email_verified = true WHERE email = $1")
        .bind(&email)
        .execute(&app.pool)
        .await
        .expect("ensure email verified");

    (email, password)
}

// ─── 1. Unit & Handler Tests (1–10) ──────────────────────────────────────────

#[tokio::test]
async fn test_login_response_sets_session_cookie_with_httponly() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let cookie_header =
        extract_cookie_header_string(&resp.headers, &app.state.config.session.cookie_name)
            .expect("session cookie in Set-Cookie header");

    assert!(cookie_header.contains("HttpOnly"));
    assert!(cookie_header.contains("SameSite=Lax"));
    assert!(cookie_header.contains("Path=/"));
}

#[tokio::test]
async fn test_login_response_cookie_session_also_sets_csrf_cookie() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let sid_cookie = extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name);
    let csrf_cookie = extract_cookie_val(&resp.headers, "csrf_token");

    assert!(sid_cookie.is_some());
    assert!(csrf_cookie.is_some());

    let csrf_header = extract_cookie_header_string(&resp.headers, "csrf_token")
        .expect("csrf_token in Set-Cookie");
    assert!(!csrf_header.contains("HttpOnly"));
    assert!(csrf_header.contains("SameSite=Strict"));
}

#[tokio::test]
async fn test_login_bearer_response_returns_token_in_json() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let mut headers = HeaderMap::new();
    headers.insert("x-auth-type", "bearer".parse().unwrap());

    let req = json_request_with_headers(
        Method::POST,
        "/auth/login",
        json!({ "email": email, "password": password }),
        headers,
    );
    let resp = app.dispatch(req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let token = resp.json["token"]
        .as_str()
        .expect("bearer token string in json");
    assert_eq!(token.len(), 32, "raw session ID must be 32-character hex");
    assert!(resp.json["user_id"].is_string());
}

#[tokio::test]
async fn test_bearer_session_no_cookie_set() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let mut headers = HeaderMap::new();
    headers.insert("x-auth-type", "bearer".parse().unwrap());

    let req = json_request_with_headers(
        Method::POST,
        "/auth/login",
        json!({ "email": email, "password": password }),
        headers,
    );
    let resp = app.dispatch(req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!resp.headers.contains_key(header::SET_COOKIE));
}

#[tokio::test]
async fn test_logout_clears_session_cookie() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let login_resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;

    let sid =
        extract_cookie_val(&login_resp.headers, &app.state.config.session.cookie_name).unwrap();
    let csrf = extract_cookie_val(&login_resp.headers, "csrf_token").unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}={}; csrf_token={}",
            app.state.config.session.cookie_name, sid, csrf
        )
        .parse()
        .unwrap(),
    );
    headers.insert("x-csrf-token", csrf.parse().unwrap());

    let req = empty_request_with_headers(Method::DELETE, "/auth/session", headers);
    let resp = app.dispatch(req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let clear_header =
        extract_cookie_header_string(&resp.headers, &app.state.config.session.cookie_name)
            .expect("clearing Set-Cookie header");
    assert!(clear_header.contains("Max-Age=0"));
    assert!(clear_header.contains("Expires=Thu, 01 Jan 1970"));
}

#[tokio::test]
async fn test_get_session_response_session_id_is_64_chars() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let login_resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;

    let sid =
        extract_cookie_val(&login_resp.headers, &app.state.config.session.cookie_name).unwrap();
    let csrf = extract_cookie_val(&login_resp.headers, "csrf_token").unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}={}; csrf_token={}",
            app.state.config.session.cookie_name, sid, csrf
        )
        .parse()
        .unwrap(),
    );
    headers.insert("x-csrf-token", csrf.parse().unwrap());

    let req = empty_request_with_headers(Method::GET, "/auth/session", headers);
    let resp = app.dispatch(req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let session_id = resp.json["session_id"].as_str().expect("session_id string");
    assert_eq!(
        session_id.len(),
        64,
        "session_id in json response must be 64-character SHA-256 hash"
    );
    assert_ne!(
        session_id, sid,
        "raw session ID must never be exposed as session_id"
    );
}

#[tokio::test]
async fn test_get_session_response_does_not_contain_csrf_token() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let login_resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;

    let sid =
        extract_cookie_val(&login_resp.headers, &app.state.config.session.cookie_name).unwrap();
    let csrf = extract_cookie_val(&login_resp.headers, "csrf_token").unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}={}; csrf_token={}",
            app.state.config.session.cookie_name, sid, csrf
        )
        .parse()
        .unwrap(),
    );
    headers.insert("x-csrf-token", csrf.parse().unwrap());

    let req = empty_request_with_headers(Method::GET, "/auth/session", headers);
    let resp = app.dispatch(req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.json.get("csrf_token").is_none());
    assert!(resp.json.get("csrf").is_none());
}

#[tokio::test]
async fn test_list_sessions_returns_array() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let login_resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;

    let sid =
        extract_cookie_val(&login_resp.headers, &app.state.config.session.cookie_name).unwrap();
    let csrf = extract_cookie_val(&login_resp.headers, "csrf_token").unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}={}; csrf_token={}",
            app.state.config.session.cookie_name, sid, csrf
        )
        .parse()
        .unwrap(),
    );
    headers.insert("x-csrf-token", csrf.parse().unwrap());

    let req = empty_request_with_headers(Method::GET, "/auth/sessions", headers);
    let resp = app.dispatch(req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let arr = resp.json.as_array().expect("array of sessions");
    assert!(!arr.is_empty());
}

#[tokio::test]
async fn test_delete_all_sessions_clears_cookie() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let login_resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;

    let sid =
        extract_cookie_val(&login_resp.headers, &app.state.config.session.cookie_name).unwrap();
    let csrf = extract_cookie_val(&login_resp.headers, "csrf_token").unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}={}; csrf_token={}",
            app.state.config.session.cookie_name, sid, csrf
        )
        .parse()
        .unwrap(),
    );
    headers.insert("x-csrf-token", csrf.parse().unwrap());

    let req = empty_request_with_headers(Method::DELETE, "/auth/sessions", headers);
    let resp = app.dispatch(req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let clear_header =
        extract_cookie_header_string(&resp.headers, &app.state.config.session.cookie_name)
            .expect("clear cookie header");
    assert!(clear_header.contains("Max-Age=0"));
}

#[tokio::test]
async fn test_login_rate_limited_after_max_attempts() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let max = app.state.config.rate_limit.max_attempts;

    for _ in 0..max {
        let _ = app
            .post_json(
                "/auth/login",
                json!({ "email": email, "password": "WrongPassword123!" }),
            )
            .await;
    }

    let blocked_resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;

    assert_eq!(blocked_resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        blocked_resp.error_code(),
        Some(ErrorCode::RateLimitExceeded)
    );
    assert!(blocked_resp.headers.contains_key(header::RETRY_AFTER));
}

// ─── 2. Integration Tests with Real PostgreSQL (11–17) ───────────────────────

#[tokio::test]
async fn test_login_cookie_session_lifecycle() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;

    // 1. Login
    let login_resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(login_resp.status(), StatusCode::OK);
    let sid =
        extract_cookie_val(&login_resp.headers, &app.state.config.session.cookie_name).unwrap();

    // 2. GET /auth/session
    let mut get_headers = HeaderMap::new();
    get_headers.insert(
        header::COOKIE,
        format!("{}={}", app.state.config.session.cookie_name, sid)
            .parse()
            .unwrap(),
    );
    let get_resp = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            get_headers.clone(),
        ))
        .await;
    assert_eq!(get_resp.status(), StatusCode::OK);
    assert_eq!(get_resp.json["session_id"].as_str().unwrap().len(), 64);

    // 3. DELETE /auth/session
    let del_resp = app
        .dispatch(empty_request_with_headers(
            Method::DELETE,
            "/auth/session",
            get_headers.clone(),
        ))
        .await;
    assert_eq!(del_resp.status(), StatusCode::OK);

    // 4. Re-verify GET /auth/session returns 401
    let re_get_resp = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            get_headers,
        ))
        .await;
    assert_eq!(re_get_resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_login_bearer_session_lifecycle() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;

    // 1. Login with X-Auth-Type: bearer
    let mut login_headers = HeaderMap::new();
    login_headers.insert("x-auth-type", "bearer".parse().unwrap());
    let login_req = json_request_with_headers(
        Method::POST,
        "/auth/login",
        json!({ "email": email, "password": password }),
        login_headers,
    );
    let login_resp = app.dispatch(login_req).await;
    assert_eq!(login_resp.status(), StatusCode::OK);
    let token = login_resp.json["token"].as_str().unwrap().to_string();

    // 2. GET /auth/session with Bearer header
    let mut bearer_headers = HeaderMap::new();
    bearer_headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    let get_resp = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            bearer_headers.clone(),
        ))
        .await;
    assert_eq!(get_resp.status(), StatusCode::OK);
    assert_eq!(get_resp.json["session_type"], "bearer");

    // 3. DELETE /auth/session
    let del_resp = app
        .dispatch(empty_request_with_headers(
            Method::DELETE,
            "/auth/session",
            bearer_headers.clone(),
        ))
        .await;
    assert_eq!(del_resp.status(), StatusCode::OK);

    // 4. Re-verify GET /auth/session returns 401
    let re_get_resp = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            bearer_headers,
        ))
        .await;
    assert_eq!(re_get_resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_session_fixation() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;

    // Login 1
    let resp1 = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    let sid1 = extract_cookie_val(&resp1.headers, &app.state.config.session.cookie_name).unwrap();

    // Login 2 (new ID every login)
    let resp2 = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    let sid2 = extract_cookie_val(&resp2.headers, &app.state.config.session.cookie_name).unwrap();

    assert_ne!(
        sid1, sid2,
        "subsequent logins must issue distinct session tokens"
    );

    // Rotate session sid1
    let old_session = app.state.session_service.get_session(&sid1).await.unwrap();
    let (new_session, sid3) = app
        .state
        .session_service
        .rotate_session(&sid1, None, None)
        .await
        .expect("session rotation");

    assert_ne!(sid1, sid3);
    assert_eq!(new_session.session_type, "cookie");
    assert_eq!(new_session.absolute_expires_at, old_session.absolute_expires_at);

    // Replay rotation of sid1 must fail with SessionNotFound
    let replay_err = app
        .state
        .session_service
        .rotate_session(&sid1, None, None)
        .await
        .unwrap_err();
    assert!(matches!(replay_err, metal_auth::AppError::SessionNotFound));

    // sid1 is invalidated
    let old_check = app.state.session_service.get_session(&sid1).await;
    assert!(old_check.is_err());

    // sid3 is valid
    let new_check = app.state.session_service.get_session(&sid3).await;
    assert!(new_check.is_ok());
}

#[tokio::test]
async fn test_idle_expiry_integration() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let sid = extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name)
        .expect("session cookie present in login response");
    let hash = SessionService::hash_raw_id(&sid);

    // Fast-forward last_active_at past idle timeout (idle_timeout_secs + 10s)
    let idle_secs = app.state.config.session.idle_timeout_secs as i64 + 10;
    sqlx::query("UPDATE sessions SET last_active_at = NOW() - make_interval(secs => $1) WHERE token_hash = $2")
        .bind(idle_secs as f64)
        .bind(&hash)
        .execute(&app.pool)
        .await
        .unwrap();

    // Request with idle-expired session
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("{}={}", app.state.config.session.cookie_name, sid)
            .parse()
            .unwrap(),
    );
    let get_resp = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            headers,
        ))
        .await;

    assert_eq!(get_resp.status(), StatusCode::UNAUTHORIZED);

    // Verify row was eagerly purged from database
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE token_hash = $1")
        .bind(&hash)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "idle expired session must be eagerly deleted");
}

#[tokio::test]
async fn test_absolute_expiry_integration() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let sid = extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name)
        .expect("session cookie present in login response");
    let hash = SessionService::hash_raw_id(&sid);

    // Fast-forward absolute_expires_at into the past
    sqlx::query("UPDATE sessions SET absolute_expires_at = NOW() - INTERVAL '10 seconds' WHERE token_hash = $1")
        .bind(&hash)
        .execute(&app.pool)
        .await
        .unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("{}={}", app.state.config.session.cookie_name, sid)
            .parse()
            .unwrap(),
    );
    let get_resp = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            headers,
        ))
        .await;

    assert_eq!(get_resp.status(), StatusCode::UNAUTHORIZED);

    // Verify eager deletion
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE token_hash = $1")
        .bind(&hash)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "absolute expired session must be eagerly deleted");
}

#[tokio::test]
async fn test_invalidate_all_sessions() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;

    // Login from 3 different "devices"
    let mut sids = Vec::new();
    let mut csrf_opt = None;
    for _ in 0..3 {
        let resp = app
            .post_json(
                "/auth/login",
                json!({ "email": email, "password": password }),
            )
            .await;
        let sid = extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name).unwrap();
        if csrf_opt.is_none() {
            csrf_opt = extract_cookie_val(&resp.headers, "csrf_token");
        }
        sids.push(sid);
    }
    let csrf = csrf_opt.expect("csrf_token in login response");

    // Invalidate all sessions using the 1st session
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}={}; csrf_token={}",
            app.state.config.session.cookie_name, sids[0], csrf
        )
        .parse()
        .unwrap(),
    );
    headers.insert("x-csrf-token", csrf.parse().unwrap());
    let del_resp = app
        .dispatch(empty_request_with_headers(
            Method::DELETE,
            "/auth/sessions",
            headers,
        ))
        .await;
    assert_eq!(del_resp.status(), StatusCode::OK);

    // All 3 sessions must now return 401
    for sid in &sids {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            format!("{}={}", app.state.config.session.cookie_name, sid)
                .parse()
                .unwrap(),
        );
        let check_resp = app
            .dispatch(empty_request_with_headers(Method::GET, "/auth/session", h))
            .await;
        assert_eq!(check_resp.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn test_password_change_invalidates_sessions() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;

    // Login from 2 devices
    let mut sids = Vec::new();
    for _ in 0..2 {
        let resp = app
            .post_json(
                "/auth/login",
                json!({ "email": email, "password": password }),
            )
            .await;
        let sid = extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name).unwrap();
        sids.push(sid);
    }

    // Request password reset
    let _ = app
        .post_json("/auth/password/reset-request", json!({ "email": email }))
        .await;

    let reset_token = app
        .email_sender
        .reset_token_for(&email)
        .or_else(|| {
            app.email_sender
                .reset_calls()
                .into_iter()
                .rfind(|c| c.to == email)
                .map(|c| c.token)
        })
        .expect("password reset email dispatched for recipient");
    let new_password = dynamic_password();

    // Confirm password reset
    let reset_resp = app
        .post_json(
            "/auth/password/reset",
            json!({ "token": reset_token, "new_password": new_password }),
        )
        .await;
    assert_eq!(reset_resp.status(), StatusCode::OK);

    // Both previous sessions must now return 401
    for sid in &sids {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            format!("{}={}", app.state.config.session.cookie_name, sid)
                .parse()
                .unwrap(),
        );
        let check_resp = app
            .dispatch(empty_request_with_headers(Method::GET, "/auth/session", h))
            .await;
        assert_eq!(check_resp.status(), StatusCode::UNAUTHORIZED);
    }
}

// ─── 3. ASVS L1 Negative & Security Tests (18–30) ───────────────────────────

#[tokio::test]
async fn test_replay_deleted_session() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let sid = extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name)
        .expect("session cookie present in login response");
    let csrf = extract_cookie_val(&resp.headers, "csrf_token").unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}={}; csrf_token={}",
            app.state.config.session.cookie_name, sid, csrf
        )
        .parse()
        .unwrap(),
    );
    headers.insert("x-csrf-token", csrf.parse().unwrap());

    // Delete session
    let _ = app
        .dispatch(empty_request_with_headers(
            Method::DELETE,
            "/auth/session",
            headers.clone(),
        ))
        .await;

    // Replay deleted session
    let replay_resp = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            headers,
        ))
        .await;
    assert_eq!(replay_resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(replay_resp.error_code(), Some(ErrorCode::SessionNotFound));
}

#[tokio::test]
async fn test_expired_session_rejected() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let sid = extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name)
        .expect("session cookie present in login response");
    let hash = SessionService::hash_raw_id(&sid);

    sqlx::query(
        "UPDATE sessions SET absolute_expires_at = NOW() - INTERVAL '1 hour' WHERE token_hash = $1",
    )
    .bind(&hash)
    .execute(&app.pool)
    .await
    .unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("{}={}", app.state.config.session.cookie_name, sid)
            .parse()
            .unwrap(),
    );

    let get_resp = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            headers,
        ))
        .await;
    assert_eq!(get_resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_csrf_missing_on_post() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let sid = extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name)
        .expect("session cookie present in login response");
    let csrf = extract_cookie_val(&resp.headers, "csrf_token").unwrap();

    // Mutating POST request with cookie but WITHOUT X-CSRF-Token header
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}={}; csrf_token={}",
            app.state.config.session.cookie_name, sid, csrf
        )
        .parse()
        .unwrap(),
    );

    let req = empty_request_with_headers(Method::POST, "/auth/session/refresh", headers);
    let resp = app.dispatch(req).await;

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.error_code(), Some(ErrorCode::CsrfTokenMissing));
}

#[tokio::test]
async fn test_csrf_mismatch_on_post() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let sid = extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name)
        .expect("session cookie present in login response");
    let csrf = extract_cookie_val(&resp.headers, "csrf_token").unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}={}; csrf_token={}",
            app.state.config.session.cookie_name, sid, csrf
        )
        .parse()
        .unwrap(),
    );
    headers.insert("x-csrf-token", "invalid_mismatched_token".parse().unwrap());

    let req = empty_request_with_headers(Method::POST, "/auth/session/refresh", headers);
    let resp = app.dispatch(req).await;

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.error_code(), Some(ErrorCode::CsrfTokenInvalid));
}

#[tokio::test]
async fn test_csrf_missing_on_delete_session_and_revoke_all() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let sid = extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name)
        .expect("session cookie present in login response");
    let csrf = extract_cookie_val(&resp.headers, "csrf_token").unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}={}; csrf_token={}",
            app.state.config.session.cookie_name, sid, csrf
        )
        .parse()
        .unwrap(),
    );

    let req = empty_request_with_headers(Method::DELETE, "/auth/session", headers.clone());
    let resp = app.dispatch(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.error_code(), Some(ErrorCode::CsrfTokenMissing));

    let req2 = empty_request_with_headers(Method::POST, "/auth/session/revoke-all", headers);
    let resp2 = app.dispatch(req2).await;
    assert_eq!(resp2.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp2.error_code(), Some(ErrorCode::CsrfTokenMissing));
}

#[tokio::test]
async fn test_csrf_bypass_via_bearer() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;

    let mut login_headers = HeaderMap::new();
    login_headers.insert("x-auth-type", "bearer".parse().unwrap());
    let login_req = json_request_with_headers(
        Method::POST,
        "/auth/login",
        json!({ "email": email, "password": password }),
        login_headers,
    );
    let login_resp = app.dispatch(login_req).await;
    let token = login_resp.json["token"].as_str().unwrap();

    // Mutating POST with Bearer authentication and NO CSRF header succeeds
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );

    let req = empty_request_with_headers(Method::POST, "/auth/session/refresh", headers);
    let resp = app.dispatch(req).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.json["token"].is_string());
}

#[tokio::test]
async fn test_rate_limit_trigger() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let max = app.state.config.rate_limit.max_attempts;

    for _ in 0..max {
        let _ = app
            .post_json(
                "/auth/login",
                json!({ "email": email, "password": "WrongPassword123!" }),
            )
            .await;
    }

    let limit_resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;

    assert_eq!(limit_resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(limit_resp.headers.contains_key(header::RETRY_AFTER));
}

#[tokio::test]
async fn test_rate_limit_reset_on_success() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let max = app.state.config.rate_limit.max_attempts;

    // Fail max - 1 times
    for _ in 0..(max - 1) {
        let _ = app
            .post_json(
                "/auth/login",
                json!({ "email": email, "password": "WrongPassword123!" }),
            )
            .await;
    }

    // Successful login resets the counter
    let ok_resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(ok_resp.status(), StatusCode::OK);

    // Subsequent failure starts from 1, does NOT trigger 429
    let fail_resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": "WrongPassword123!" }),
        )
        .await;
    assert_eq!(fail_resp.status(), StatusCode::UNAUTHORIZED);
}

#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuffer {
    type Writer = SharedBuffer;
    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn test_session_hash_not_logged() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let log_buf = SharedBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(log_buf.clone())
        .with_ansi(false)
        .finish();
    let _log_guard = tracing::subscriber::set_default(subscriber);

    let (email, password) = create_and_verify_user(&app).await;

    let resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    let sid = extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name).unwrap();
    let csrf = extract_cookie_val(&resp.headers, "csrf_token").unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}={}; csrf_token={}",
            app.state.config.session.cookie_name, sid, csrf
        )
        .parse()
        .unwrap(),
    );
    headers.insert("x-csrf-token", csrf.parse().unwrap());
    let _ = app
        .dispatch(empty_request_with_headers(
            Method::DELETE,
            "/auth/session",
            headers,
        ))
        .await;

    let logs = String::from_utf8(log_buf.0.lock().unwrap().clone()).unwrap();
    let hash = SessionService::hash_raw_id(&sid);

    assert!(
        !logs.contains(&sid),
        "raw session token must never appear in logs"
    );
    assert!(
        !logs.contains(&hash),
        "token hash must never appear in logs"
    );
    assert!(
        !logs.contains(&csrf),
        "csrf token value must never appear in logs"
    );
}

#[tokio::test]
async fn test_session_id_not_in_response() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let sid = extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name)
        .expect("session cookie present in login response");
    let csrf = extract_cookie_val(&resp.headers, "csrf_token").unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}={}; csrf_token={}",
            app.state.config.session.cookie_name, sid, csrf
        )
        .parse()
        .unwrap(),
    );
    headers.insert("x-csrf-token", csrf.parse().unwrap());

    let get_resp = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            headers,
        ))
        .await;

    assert_eq!(get_resp.status(), StatusCode::OK);
    assert!(
        !get_resp.body_str.contains(&sid),
        "raw session token must never be present in response body"
    );
}

#[tokio::test]
async fn test_logout_server_side() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let sid = extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name)
        .expect("session cookie present in login response");
    let csrf = extract_cookie_val(&resp.headers, "csrf_token").unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}={}; csrf_token={}",
            app.state.config.session.cookie_name, sid, csrf
        )
        .parse()
        .unwrap(),
    );
    headers.insert("x-csrf-token", csrf.parse().unwrap());

    // Logout
    let logout_resp = app
        .dispatch(empty_request_with_headers(
            Method::DELETE,
            "/auth/session",
            headers.clone(),
        ))
        .await;
    assert_eq!(logout_resp.status(), StatusCode::OK);

    // Replay cookie — server must reject with 401
    let replay_resp = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            headers,
        ))
        .await;
    assert_eq!(replay_resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_cookie_httponly_flag() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;

    let cookie_header =
        extract_cookie_header_string(&resp.headers, &app.state.config.session.cookie_name)
            .expect("cookie header exists");
    assert!(cookie_header.contains("HttpOnly"));
}

#[tokio::test]
async fn test_session_refresh_rotates_token() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let resp = app
        .post_json(
            "/auth/login",
            json!({ "email": email, "password": password }),
        )
        .await;

    let sid1 = extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name).unwrap();
    let csrf1 = extract_cookie_val(&resp.headers, "csrf_token").unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}={}; csrf_token={}",
            app.state.config.session.cookie_name, sid1, csrf1
        )
        .parse()
        .unwrap(),
    );
    headers.insert("x-csrf-token", csrf1.parse().unwrap());

    // Refresh session
    let refresh_resp = app
        .dispatch(empty_request_with_headers(
            Method::POST,
            "/auth/session/refresh",
            headers.clone(),
        ))
        .await;
    assert_eq!(refresh_resp.status(), StatusCode::OK);

    let sid2 = extract_cookie_val(&refresh_resp.headers, &app.state.config.session.cookie_name)
        .expect("fresh session cookie");
    assert_ne!(
        sid1, sid2,
        "refreshed session token must differ from old token"
    );

    // Old token sid1 must now return 401
    let old_resp = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            headers,
        ))
        .await;
    assert_eq!(old_resp.status(), StatusCode::UNAUTHORIZED);

    // New token sid2 must succeed
    let mut new_headers = HeaderMap::new();
    new_headers.insert(
        header::COOKIE,
        format!("{}={}", app.state.config.session.cookie_name, sid2)
            .parse()
            .unwrap(),
    );
    let new_resp = app
        .dispatch(empty_request_with_headers(
            Method::GET,
            "/auth/session",
            new_headers,
        ))
        .await;
    assert_eq!(new_resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_device_and_session_limits_eviction() {
    let _guard = DB_LOCK.lock().await;
    let Some(app) = setup_test_app().await else {
        return;
    };

    let (email, password) = create_and_verify_user(&app).await;
    let limit = app.state.config.session.max_active_sessions_per_user;

    if limit > 0 {
        let mut sids = Vec::new();
        for _ in 0..limit {
            let resp = app
                .post_json(
                    "/auth/login",
                    json!({ "email": email, "password": password }),
                )
                .await;
            let sid =
                extract_cookie_val(&resp.headers, &app.state.config.session.cookie_name).unwrap();
            sids.push(sid);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Login one more time -> exceeds limit, evicts oldest (sids[0])
        let resp_extra = app
            .post_json(
                "/auth/login",
                json!({ "email": email, "password": password }),
            )
            .await;
        let sid_extra =
            extract_cookie_val(&resp_extra.headers, &app.state.config.session.cookie_name).unwrap();

        // Oldest session sids[0] must now return 401
        let mut old_headers = HeaderMap::new();
        old_headers.insert(
            header::COOKIE,
            format!("{}={}", app.state.config.session.cookie_name, sids[0])
                .parse()
                .unwrap(),
        );
        let check_old = app
            .dispatch(empty_request_with_headers(
                Method::GET,
                "/auth/session",
                old_headers,
            ))
            .await;
        assert_eq!(check_old.status(), StatusCode::UNAUTHORIZED);

        // Extra session must be valid
        let mut extra_headers = HeaderMap::new();
        extra_headers.insert(
            header::COOKIE,
            format!("{}={}", app.state.config.session.cookie_name, sid_extra)
                .parse()
                .unwrap(),
        );
        let check_extra = app
            .dispatch(empty_request_with_headers(
                Method::GET,
                "/auth/session",
                extra_headers,
            ))
            .await;
        assert_eq!(check_extra.status(), StatusCode::OK);
    }
}
