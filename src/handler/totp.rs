//! TOTP two-factor HTTP handlers.
//!
//! `enroll`, `confirm`, and `DELETE /auth/totp` are authenticated cookie
//! mutations and sit behind `require_auth` + CSRF. `verify` and `backup`
//! authenticate with a body-borne challenge token instead of the session
//! cookie, so they are mounted outside the CSRF layer on purpose.

use serde::Deserialize;

use axum::{
    Json, Router,
    extract::{State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::{
    auth::models::{LoginResponse, MessageResponse},
    error::AppError,
    handler::auth::{
        attach_login_cookies, extract_client_ip, json_rejection_response, method_not_allowed,
        service_error_response,
    },
    middleware::{
        auth::{AuthUser, require_auth},
        csrf_middleware,
    },
    ratelimit::RateLimitRejection,
    state::AppState,
    totp::service::FreshAuthProof,
};

/// Log prefix for rejections from the verification budgets (`totp:*`).
const TOTP_KEY_PREFIX: &str = "totp";
/// Log prefix for rejections from the enrollment budgets (`totp:enroll:*`).
const ENROLL_KEY_PREFIX: &str = "totp:enroll";
/// Log prefix for rejections from the confirmation budgets (`totp:confirm:*`).
const CONFIRM_KEY_PREFIX: &str = "totp:confirm";

/// `POST /auth/totp/confirm` body.
#[derive(Deserialize)]
pub struct ConfirmTotpRequest {
    pub code: String,
}

// Manual `Debug`: the one-time code must never reach a log or error trace.
impl std::fmt::Debug for ConfirmTotpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfirmTotpRequest")
            .field("code", &"[redacted]")
            .finish()
    }
}

/// `POST /auth/totp/verify` and `POST /auth/totp/backup` body.
#[derive(Deserialize)]
pub struct TwoFactorChallengeRequest {
    pub challenge_token: String,
    pub code: String,
}

// Manual `Debug`: challenge token and code are live credentials.
impl std::fmt::Debug for TwoFactorChallengeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoFactorChallengeRequest")
            .field("challenge_token", &"[redacted]")
            .field("code", &"[redacted]")
            .finish()
    }
}

/// `DELETE /auth/totp` body: exactly one fresh-auth proof.
#[derive(Deserialize)]
pub struct DisableTotpRequest {
    pub password: Option<String>,
    pub totp_code: Option<String>,
}

// Manual `Debug`: both fields carry a live credential.
impl std::fmt::Debug for DisableTotpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DisableTotpRequest")
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .field("totp_code", &self.totp_code.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

impl DisableTotpRequest {
    /// Reject an absent, blank, or ambiguous proof before any rate-limit budget is spent.
    fn into_proof(self) -> Result<FreshAuthProof, AppError> {
        match (self.password, self.totp_code) {
            (Some(password), None) if !password.is_empty() => {
                Ok(FreshAuthProof::Password(password))
            }
            (None, Some(code)) if !code.is_empty() => Ok(FreshAuthProof::TotpCode(code)),
            _ => Err(AppError::ValidationError(
                "provide exactly one of password or totp_code".into(),
            )),
        }
    }
}

/// `POST /auth/totp/enroll`
///
/// Rotates the pending secret and returns the QR URI plus the backup codes once.
/// Refuses unverified emails and an already enabled secret. Rate-limited like every other
/// TOTP route: enrollment spends ten Argon2id hashes on the shared blocking pool, so an
/// unthrottled reroll loop is a CPU-exhaustion vector for the whole instance. Its own
/// `totp:enroll:*` keys keep that throttle off the budget code verification needs.
pub async fn totp_enroll(
    State(state): State<AppState>,
    auth_user: AuthUser,
    headers: HeaderMap,
) -> Response {
    let client_ip = extract_client_ip(&headers);
    let user_agent = user_agent(&headers);

    if let Err(rejection) = state
        .rate_limiter
        .check_totp_enroll_ip_limit(&client_ip, &state.config.totp)
    {
        return totp_rate_limit_exceeded(&client_ip, ENROLL_KEY_PREFIX, "ip", rejection);
    }
    if let Err(rejection) = state
        .rate_limiter
        .check_totp_enroll_user_limit(auth_user.user_id, &state.config.totp)
    {
        return totp_rate_limit_exceeded(&client_ip, ENROLL_KEY_PREFIX, "user", rejection);
    }

    match state.totp_service.enroll_totp(auth_user.user_id).await {
        Ok(enrollment) => {
            tracing::info!(
                target: "security_event",
                event = "totp_enrolled",
                user_id = %auth_user.user_id,
                ip = %client_ip,
                user_agent = %user_agent,
            );
            (StatusCode::OK, Json(enrollment)).into_response()
        }
        Err(error) => service_error_response(error),
    }
}

/// `POST /auth/totp/confirm`
///
/// Verifies the first code against the pending secret and enables 2FA. One code check, unlike
/// enrollment's ten Argon2id hashes, so it charges its own `totp:confirm:*` budget: neither
/// step can exhaust the other's attempts.
pub async fn totp_confirm(
    State(state): State<AppState>,
    auth_user: AuthUser,
    headers: HeaderMap,
    body: Result<Json<ConfirmTotpRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match body {
        Ok(body) => body,
        Err(rejection) => return json_rejection_response(rejection),
    };

    let client_ip = extract_client_ip(&headers);

    if let Err(rejection) = state
        .rate_limiter
        .check_totp_confirm_ip_limit(&client_ip, &state.config.totp)
    {
        return totp_rate_limit_exceeded(&client_ip, CONFIRM_KEY_PREFIX, "ip", rejection);
    }
    if let Err(rejection) = state
        .rate_limiter
        .check_totp_confirm_user_limit(auth_user.user_id, &state.config.totp)
    {
        return totp_rate_limit_exceeded(&client_ip, CONFIRM_KEY_PREFIX, "user", rejection);
    }

    match state
        .totp_service
        .confirm_enrollment(auth_user.user_id, &request.code, &client_ip)
        .await
    {
        Ok(()) => {
            tracing::info!(
                target: "security_event",
                event = "totp_confirmed",
                user_id = %auth_user.user_id,
                ip = %client_ip,
                user_agent = %user_agent(&headers),
            );
            (StatusCode::OK, Json(MessageResponse::new("totp confirmed"))).into_response()
        }
        Err(error) => service_error_response(error),
    }
}

/// `POST /auth/totp/backup`
///
/// Same lifecycle as [`totp_verify`] with a single-use backup code as the factor. The
/// Argon2id match runs before the transaction; only its removal is transactional.
pub async fn totp_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<TwoFactorChallengeRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match body {
        Ok(body) => body,
        Err(rejection) => return json_rejection_response(rejection),
    };

    let client_ip = extract_client_ip(&headers);
    let user_id = match challenge_user_id(&state, &client_ip, &request.challenge_token).await {
        Ok(user_id) => user_id,
        Err(rejection) => return rejection.into_response(&client_ip),
    };

    let matched_hash = match state
        .totp_service
        .match_backup_code(user_id, &request.code)
        .await
    {
        Ok(matched_hash) => matched_hash,
        Err(error) => return service_error_response(error),
    };

    redeem_challenge(
        &state,
        &headers,
        &client_ip,
        user_id,
        &request.challenge_token,
        PresentedFactor::BackupCode(matched_hash),
        VerifiedFactor::BackupCode,
    )
    .await
}

/// `DELETE /auth/totp`
///
/// Requires a fresh-auth proof: the current password or a live TOTP code. A missing,
/// blank, or ambiguous proof is a 400 `VALIDATION_ERROR` before any budget is spent.
/// A rejected proof keeps the status of the check that rejected it: a wrong password
/// fails a credential comparison, so 401 `INVALID_CREDENTIALS`; a wrong TOTP code is
/// reported by the shared code check as 400 `TOTP_CODE_INVALID`, same as every other
/// code verification. An absent session is rejected by `require_auth` before this runs.
pub async fn totp_disable(
    State(state): State<AppState>,
    auth_user: AuthUser,
    headers: HeaderMap,
    body: Result<Json<DisableTotpRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match body {
        Ok(body) => body,
        Err(rejection) => return json_rejection_response(rejection),
    };

    let proof = match request.into_proof() {
        Ok(proof) => proof,
        Err(error) => return service_error_response(error),
    };
    let proof_method = match &proof {
        FreshAuthProof::Password(_) => "password",
        FreshAuthProof::TotpCode(_) => "totp_code",
    };

    let client_ip = extract_client_ip(&headers);

    if let Err(rejection) = state
        .rate_limiter
        .check_totp_ip_limit(&client_ip, &state.config.totp)
    {
        return totp_rate_limit_exceeded(&client_ip, TOTP_KEY_PREFIX, "ip", rejection);
    }
    if let Err(rejection) = state
        .rate_limiter
        .check_totp_user_limit(auth_user.user_id, &state.config.totp)
    {
        return totp_rate_limit_exceeded(&client_ip, TOTP_KEY_PREFIX, "user", rejection);
    }

    match state
        .totp_service
        .disable_totp(auth_user.user_id, proof, &client_ip)
        .await
    {
        Ok(()) => {
            tracing::info!(
                target: "security_event",
                event = "totp_disabled",
                user_id = %auth_user.user_id,
                ip = %client_ip,
                user_agent = %user_agent(&headers),
                method = proof_method,
            );
            (
                StatusCode::OK,
                Json(MessageResponse::new("two-factor authentication disabled")),
            )
                .into_response()
        }
        Err(error) => service_error_response(error),
    }
}

/// 429 for either TOTP dimension.
///
/// `Retry-After` comes from the rejection value itself, so the header always describes the
/// decision that produced it rather than whatever the key holds by the time the response is
/// built. A window rejection carries the remaining time of the attempt that tripped it;
/// capacity exhaustion carries none, so that response omits the header instead of
/// inventing a duration (RFC 6585 §4 permits either).
fn totp_rate_limit_exceeded(
    client_ip: &str,
    key_prefix: &'static str,
    dimension: &'static str,
    rejection: RateLimitRejection,
) -> Response {
    let retry_after_secs = rejection.retry_after();

    tracing::warn!(
        event = "rate_limit_exceeded",
        ip = %client_ip,
        key_prefix,
        dimension,
        retry_after_secs = ?retry_after_secs,
    );

    let mut response = service_error_response(AppError::TotpRateLimitExceeded);
    if let Some(secs) = retry_after_secs {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, header::HeaderValue::from(secs));
    }
    response
}

/// Why [`challenge_user_id`] refused a challenge.
///
/// `Response` exceeds the 128-byte `Err` size Clippy allows, so the response is built at the
/// handler boundary instead of being carried here.
enum ChallengeRejection {
    /// A verification budget is exhausted; `dimension` records which one.
    RateLimited {
        dimension: &'static str,
        rejection: RateLimitRejection,
    },
    /// The challenge token failed validation.
    Service(AppError),
}

impl ChallengeRejection {
    fn into_response(self, client_ip: &str) -> Response {
        match self {
            Self::RateLimited {
                dimension,
                rejection,
            } => totp_rate_limit_exceeded(client_ip, TOTP_KEY_PREFIX, dimension, rejection),
            Self::Service(error) => service_error_response(error),
        }
    }
}

/// Charge the IP budget, resolve the challenge token without consuming it, then charge the
/// user budget. Token validation sits between the dimensions so an unparsable token costs
/// the IP budget only.
async fn challenge_user_id(
    state: &AppState,
    client_ip: &str,
    challenge_token: &str,
) -> Result<Uuid, ChallengeRejection> {
    if let Err(rejection) = state
        .rate_limiter
        .check_totp_ip_limit(client_ip, &state.config.totp)
    {
        return Err(ChallengeRejection::RateLimited {
            dimension: "ip",
            rejection,
        });
    }

    let user_id = state
        .totp_service
        .validate_two_factor_token(challenge_token)
        .await
        .map_err(ChallengeRejection::Service)?;

    if let Err(rejection) = state
        .rate_limiter
        .check_totp_user_limit(user_id, &state.config.totp)
    {
        return Err(ChallengeRejection::RateLimited {
            dimension: "user",
            rejection,
        });
    }

    Ok(user_id)
}

/// `POST /auth/totp/verify`
///
/// Order is load-bearing: IP budget, then non-destructive token validation, then the
/// user budget, then the code check. The code check, token consumption, and session insert
/// commit as one unit — see [`redeem_challenge`].
pub async fn totp_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<TwoFactorChallengeRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match body {
        Ok(body) => body,
        Err(rejection) => return json_rejection_response(rejection),
    };

    let client_ip = extract_client_ip(&headers);
    let user_id = match challenge_user_id(&state, &client_ip, &request.challenge_token).await {
        Ok(user_id) => user_id,
        Err(rejection) => return rejection.into_response(&client_ip),
    };

    redeem_challenge(
        &state,
        &headers,
        &client_ip,
        user_id,
        &request.challenge_token,
        PresentedFactor::TotpCode(&request.code),
        VerifiedFactor::Totp,
    )
    .await
}

/// Which factor redeems the challenge.
enum PresentedFactor<'a> {
    /// Verified inside the redemption transaction, so its counter derives from the same
    /// clock reference as the replay-row prune.
    TotpCode(&'a str),
    /// Matched against the stored hashes before the transaction: Argon2id must never hold
    /// a connection. The matched hash is what the transaction removes.
    BackupCode(String),
}

/// Redeem a challenge as one unit of work.
///
/// Ordering, and what commits when:
/// 1. the factor use — the replay-row insert for a TOTP code, the hash removal for a
///    backup code. This is the single-use arbiter, so it takes the code's row lock first;
/// 2. the challenge-token delete — the single-winner check on the challenge;
/// 3. the session insert — last, because it locks the user row for the credential check.
///
/// Committing only after step 3 means a failure anywhere leaves the code unspent and the
/// challenge intact, so the client can retry the same code, and no session can be minted
/// from a code that was not spent. The lock order above is the same for every redemption,
/// so two of them cannot deadlock.
async fn redeem_challenge(
    state: &AppState,
    headers: &HeaderMap,
    client_ip: &str,
    user_id: Uuid,
    challenge_token: &str,
    factor: PresentedFactor<'_>,
    verified: VerifiedFactor,
) -> Response {
    let user_agent = user_agent(headers);
    let is_bearer = headers
        .get("x-auth-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("bearer"));
    let session_type = if is_bearer { "bearer" } else { "cookie" };

    // `create_session_in` re-reads this column under the user row lock and rejects a
    // mismatch, so a reset racing *this request* cannot mint a session. A reset that
    // committed before this read yields the same value at both reads and is not detected:
    // the challenge token carries no credential material. Follow-up: bind the credential
    // state to the challenge token.
    let credential_hash = match state.session_service.current_credential_hash(user_id).await {
        Ok(hash) => hash,
        Err(error) => return service_error_response(error),
    };

    let mut transaction = match state.pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => {
            tracing::error!(error = %error, "failed to begin challenge redemption");
            return service_error_response(AppError::Database(error));
        }
    };

    let factor_use = match factor {
        PresentedFactor::TotpCode(code) => {
            state
                .totp_service
                .verify_and_record_totp(&mut transaction, user_id, code)
                .await
        }
        PresentedFactor::BackupCode(matched_hash) => {
            state
                .totp_service
                .consume_backup_code(&mut transaction, user_id, &matched_hash)
                .await
        }
    };
    if let Err(error) = factor_use {
        let _ = transaction.rollback().await;
        return service_error_response(error);
    }

    if let Err(error) = state
        .totp_service
        .consume_two_factor_token_in(&mut transaction, challenge_token)
        .await
    {
        let _ = transaction.rollback().await;
        return service_error_response(error);
    }

    let (session, raw_id) = match state
        .session_service
        .create_session_in(
            &mut transaction,
            user_id,
            Some(&credential_hash),
            session_type,
        )
        .await
    {
        Ok(session) => session,
        Err(error) => {
            let _ = transaction.rollback().await;
            return service_error_response(error);
        }
    };

    if let Err(error) = transaction.commit().await {
        tracing::error!(error = %error, "failed to commit challenge redemption");
        return service_error_response(AppError::Database(error));
    }

    tracing::info!(
        target: "security_event",
        event = "session_created",
        user_id = %user_id,
        session_type,
        ip = %client_ip,
        user_agent = %user_agent,
    );
    // `session_id_hash` is a SHA-256 of a 256-bit token, never the token: a correlator,
    // not a credential. Every authentication event carries it; lifecycle events do not.
    tracing::info!(
        target: "security_event",
        event = verified.event(),
        user_id = %user_id,
        ip = %client_ip,
        user_agent = %user_agent,
        session_id_hash = %session.token_hash,
    );

    if is_bearer {
        (
            StatusCode::OK,
            Json(LoginResponse::with_token(user_id, raw_id)),
        )
            .into_response()
    } else {
        let response = (StatusCode::OK, Json(LoginResponse::new(user_id))).into_response();
        match attach_login_cookies(
            response,
            &state.config,
            raw_id.as_str(),
            session.csrf_token.as_deref(),
        ) {
            Ok(response) => response,
            Err(error) => service_error_response(error),
        }
    }
}

/// Which factor redeemed the challenge, and therefore which audit event fires.
#[derive(Clone, Copy)]
enum VerifiedFactor {
    Totp,
    BackupCode,
}

impl VerifiedFactor {
    fn event(self) -> &'static str {
        match self {
            Self::Totp => "totp_verified",
            Self::BackupCode => "backup_code_used",
        }
    }
}

/// Best-effort user agent for audit events, `"unknown"` when absent (login convention).
fn user_agent(headers: &HeaderMap) -> &str {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown")
}

/// Router for the TOTP endpoints, merged under `/auth` by [`crate::handler::create_router`].
///
/// Fails at startup when the TOTP encryption key is absent or unusable: verification decrypts
/// the stored secret, so a keyless config would answer every challenge with a 503.
///
/// CSRF split is deliberate. `enroll`, `confirm`, and `DELETE /totp` mutate state on an
/// ambient session cookie and sit behind `require_auth` + CSRF (guard outermost, so an
/// anonymous request gets 401 before CSRF can answer 403). `verify` and `backup`
/// authenticate with a body-borne `challenge_token` and carry no ambient authority;
/// inside the CSRF layer a browser holding any unrelated `sid` cookie would be rejected
/// before the challenge is read, while cookie-less clients would still pass.
pub fn routes(state: AppState) -> Result<Router, AppError> {
    super::require_totp_key(Some(&state.config))?;

    let protected = Router::new()
        .route(
            "/totp/enroll",
            axum::routing::post(totp_enroll).fallback(method_not_allowed),
        )
        .route(
            "/totp/confirm",
            axum::routing::post(totp_confirm).fallback(method_not_allowed),
        )
        // No JSON 405 fallback here: the shared helper advertises POST only.
        .route("/totp", axum::routing::delete(totp_disable))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            csrf_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ))
        .with_state(state.clone());

    // CSRF-exempt by design: see the type-level note above.
    let public = Router::new()
        .route(
            "/totp/verify",
            axum::routing::post(totp_verify).fallback(method_not_allowed),
        )
        .route(
            "/totp/backup",
            axum::routing::post(totp_backup).fallback(method_not_allowed),
        )
        .with_state(state);

    Ok(protected.merge(public))
}
