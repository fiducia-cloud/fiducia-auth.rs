//! Least-privilege administrative surface for Fiducia token revocation.
//!
//! This binary is intentionally separate from the customer auth server. Write
//! and read operations use different secrets, no browser CORS is enabled, and
//! every mutation requires an actor plus an idempotency key.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use fiducia_auth::revocation::{
    CheckRequest, LiftRequest, MutationIdentity, RevocationError, RevocationStore, RevokeRequest,
};
use serde_json::{json, Value};
use tower_http::{
    catch_panic::CatchPanicLayer, limit::RequestBodyLimitLayer, timeout::TimeoutLayer,
    trace::TraceLayer,
};

const SERVICE: &str = "fiducia-revocation-admin";
const DEFAULT_PORT: u16 = 8098;
const REQUEST_TIMEOUT_SECS: u64 = 10;
const MAX_BODY_BYTES: usize = 32 * 1024;
const MIN_SECRET_BYTES: usize = 32;
const ADMIN_AUTH_HEADER: &str = "x-revocation-admin-auth";
const READER_AUTH_HEADER: &str = "x-revocation-reader-auth";
const ACTOR_HEADER: &str = "x-fiducia-actor";

struct AppState {
    revocations: RevocationStore,
    admin_secret: String,
    reader_secret: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _telemetry = fiducia_telemetry::init(SERVICE);
    let admin_secret = required_secret("FIDUCIA_REVOCATION_ADMIN_SECRET")?;
    let reader_secret = required_secret("FIDUCIA_REVOCATION_READER_SECRET")?;
    if constant_time_eq(admin_secret.as_bytes(), reader_secret.as_bytes()) {
        return Err(
            std::io::Error::other("revocation admin and reader secrets must be distinct").into(),
        );
    }
    let revocations = RevocationStore::from_env().map_err(std::io::Error::other)?;
    let state = Arc::new(AppState {
        revocations,
        admin_secret,
        reader_secret,
    });

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/revocations/revoke", post(revoke))
        .route("/v1/revocations/lift", post(lift))
        .route("/v1/revocations/check", post(check))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(REQUEST_TIMEOUT_SECS)))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(CatchPanicLayer::new());

    let port = port_from_env()?;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!(%addr, "{SERVICE} listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "service": SERVICE }))
}

async fn revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<RevokeRequest>,
) -> Response {
    if !authorized(&headers, ADMIN_AUTH_HEADER, &state.admin_secret) {
        return unauthorized();
    }
    let actor = match required_actor(&headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let idempotency_key = match required_idempotency_key(&headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match state
        .revocations
        .revoke(
            request,
            MutationIdentity::new(&actor, &idempotency_key),
            now_secs(),
        )
        .await
    {
        Ok(snapshot) => no_store(json!({ "revocation": snapshot })),
        Err(error) => revocation_error(error),
    }
}

async fn lift(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<LiftRequest>,
) -> Response {
    if !authorized(&headers, ADMIN_AUTH_HEADER, &state.admin_secret) {
        return unauthorized();
    }
    let actor = match required_actor(&headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let idempotency_key = match required_idempotency_key(&headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match state
        .revocations
        .lift(
            request,
            MutationIdentity::new(&actor, &idempotency_key),
            now_secs(),
        )
        .await
    {
        Ok(snapshot) => no_store(json!({ "revocation": snapshot })),
        Err(error) => revocation_error(error),
    }
}

async fn check(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CheckRequest>,
) -> Response {
    if !authorized(&headers, READER_AUTH_HEADER, &state.reader_secret) {
        return unauthorized();
    }
    match state.revocations.check(&request.claims, now_secs()).await {
        Ok(decision) => no_store(json!({ "decision": decision })),
        Err(error) => revocation_error(error),
    }
}

fn authorized(headers: &HeaderMap, name: &'static str, expected: &str) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::as_bytes)
        .map(|provided| constant_time_eq(provided, expected.as_bytes()))
        .unwrap_or(false)
}

fn required_actor(headers: &HeaderMap) -> Result<String, Response> {
    let Some(actor) = headers
        .get(ACTOR_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    else {
        return Err(bad_request("actor_required"));
    };
    if actor.is_empty() || actor.len() > 128 || actor.chars().any(char::is_control) {
        return Err(bad_request("invalid_actor"));
    }
    Ok(actor.to_string())
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<String, Response> {
    let Some(key) = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    else {
        return Err(bad_request("idempotency_key_required"));
    };
    if key.is_empty()
        || key.len() > 128
        || key
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(bad_request("invalid_idempotency_key"));
    }
    Ok(key.to_string())
}

fn no_store(value: Value) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Json(value)).into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "unauthorized" })),
    )
        .into_response()
}

fn bad_request(code: &'static str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": code }))).into_response()
}

fn revocation_error(error: RevocationError) -> Response {
    let (status, code, log_error) = match &error {
        RevocationError::InvalidMutation(_)
        | RevocationError::InvalidClaims
        | RevocationError::Contract(_) => {
            (StatusCode::BAD_REQUEST, "invalid_revocation_request", false)
        }
        RevocationError::IdempotencyConflict => {
            (StatusCode::CONFLICT, "idempotency_conflict", false)
        }
        RevocationError::NotFound => (StatusCode::NOT_FOUND, "revocation_not_found", false),
        RevocationError::NotActive => (StatusCode::CONFLICT, "revocation_not_active", false),
        RevocationError::TransitionLimit => {
            (StatusCode::CONFLICT, "revocation_transition_limit", false)
        }
        RevocationError::Store(_)
        | RevocationError::InvalidLedger
        | RevocationError::CasRetriesExhausted => {
            (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", true)
        }
    };
    if log_error {
        tracing::error!(error = %error, "revocation operation failed");
    }
    (status, Json(json!({ "error": code }))).into_response()
}

fn required_secret(name: &str) -> Result<String, std::io::Error> {
    let value = std::env::var(name)
        .map_err(|_| std::io::Error::other(format!("{name} must be configured")))?;
    validate_secret(name, value)
}

fn validate_secret(name: &str, value: String) -> Result<String, std::io::Error> {
    if value.len() < MIN_SECRET_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(std::io::Error::other(format!(
            "{name} must contain at least {MIN_SECRET_BYTES} non-whitespace bytes"
        )));
    }
    Ok(value)
}

fn port_from_env() -> Result<u16, std::io::Error> {
    let value = match std::env::var("FIDUCIA_REVOCATION_PORT") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(DEFAULT_PORT),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(std::io::Error::other(
                "FIDUCIA_REVOCATION_PORT must be valid UTF-8",
            ));
        }
    };
    let port = value.trim().parse::<u16>().map_err(|_| {
        std::io::Error::other("FIDUCIA_REVOCATION_PORT must be a valid non-zero TCP port")
    })?;
    if port == 0 {
        return Err(std::io::Error::other(
            "FIDUCIA_REVOCATION_PORT must be a valid non-zero TCP port",
        ));
    }
    Ok(port)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_contract_fails_closed() {
        assert!(validate_secret("TEST", "x".repeat(MIN_SECRET_BYTES)).is_ok());
        assert!(validate_secret("TEST", "short".to_string()).is_err());
        assert!(validate_secret("TEST", "x".repeat(MIN_SECRET_BYTES) + " ").is_err());
    }

    #[test]
    fn constant_time_comparison_requires_exact_equality() {
        assert!(constant_time_eq(b"reader-secret", b"reader-secret"));
        assert!(!constant_time_eq(b"reader-secret", b"writer-secret"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }
}
