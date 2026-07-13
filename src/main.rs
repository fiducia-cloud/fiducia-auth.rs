//! fiducia-auth — the auth server.
//!
//! Two planes and two credentials. Human JWT verification avoids Supabase on
//! the normal path; API-key introspection reads authoritative Fiducia KV so
//! rotations and revocations are visible across auth replicas:
//!
//!   * **Dashboard (humans):** Supabase Auth issues a session JWT. We verify it
//!     **offline** with Supabase's cached JWKS (only the dashboard/control plane;
//!     see `supabase.rs`). Used to create/list/revoke API keys.
//!   * **API clients (machines):** a static API key (`fdc_live_<id>.<secret>`).
//!     The edge/LB validates it via `POST /v1/introspect` and **caches** the
//!     result (short TTL), so steady state makes no auth call. Optionally the key
//!     is exchanged once for a short-lived JWT verified offline (see `token.rs`).
//!
//! Routing, Supabase JWT verification, API-key crypto/hashing, JWT signing, and
//! fiducia-KV-backed API-key persistence are implemented.

mod keys;
mod model;
mod store;
mod supabase;
mod sync;
mod token;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::time::Duration;
use tower_http::{
    catch_panic::CatchPanicLayer, limit::RequestBodyLimitLayer, timeout::TimeoutLayer,
    trace::TraceLayer,
};

use keys::KeyStore;
use model::{CreateKeyBody, IntrospectBody, TokenBody, UserCtx};

const SERVICE: &str = "fiducia-auth";
/// Default positive-introspection cache bound used by the current edge/LB.
/// Deployments that raise a consumer cache TTL must raise
/// `FIDUCIA_ROTATION_OVERLAP_SECONDS` to the same maximum.
const DEFAULT_ROTATION_OVERLAP_SECONDS: u64 = 60;
const ALLOWED_API_KEY_SCOPES: &[&str] = &[
    "requests:read",
    "requests:write",
    "locks:read",
    "locks:write",
    "kv:read",
    "kv:write",
    "services:read",
    "services:write",
    "elections:read",
    "elections:write",
    "cron:read",
    "cron:write",
    "rate-limit:read",
    "rate-limit:write",
];

/// Reject any request whose handler runs longer than this (slow-loris / hung
/// upstream protection). Auth work is sub-millisecond.
const REQUEST_TIMEOUT_SECS: u64 = 15;
/// Cap request bodies; auth payloads are tiny JSON.
const MAX_BODY_BYTES: usize = 64 * 1024;

struct AppState {
    keys: KeyStore,
    orgs: Arc<sync::OrgCache>,
    introspect_secret: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    fiducia_telemetry::init(SERVICE);

    token::validate_config().map_err(std::io::Error::other)?;
    let introspect_secret = required_env("FIDUCIA_INTROSPECT_SECRET")?;
    let keys = KeyStore::from_env().map_err(std::io::Error::other)?;

    // Supabase is the durable system of record; complete one initial sync before
    // accepting traffic so an empty cache cannot impersonate real org state.
    let orgs = Arc::new(sync::OrgCache::default());
    sync::start(orgs.clone())
        .await
        .map_err(std::io::Error::other)?;

    let state = Arc::new(AppState {
        keys,
        orgs,
        introspect_secret,
    });

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/.well-known/jwks.json", get(jwks))
        // Dashboard plane (requires a Supabase session JWT).
        .route("/v1/me", get(me))
        .route("/v1/keys", post(create_key).get(list_keys))
        .route("/v1/keys/:key_id", axum::routing::delete(revoke_key))
        .route("/v1/keys/:key_id/rotate", post(rotate_key))
        .route("/v1/orgs/:org_id", get(get_org))
        // Data plane (called by the edge/LB; should be internal-only / mTLS).
        .route("/v1/introspect", post(introspect))
        .route("/v1/token", post(exchange_token))
        .with_state(state)
        // Hardening stack (outermost last): catch handler panics → 500 instead
        // of dropping the connection, bound request time, and cap body size.
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(REQUEST_TIMEOUT_SECS)))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(CatchPanicLayer::new());

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8097);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("{SERVICE} listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "service": SERVICE }))
}

async fn jwks() -> Json<Value> {
    Json(token::jwks())
}

/// Require a valid Supabase session; 401 otherwise.
async fn require_user(headers: &HeaderMap) -> Result<UserCtx, Response> {
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    match bearer {
        Some(jwt) => supabase::verify_session(jwt)
            .await
            .ok_or_else(|| unauthorized("invalid or expired session")),
        None => Err(unauthorized("missing bearer token")),
    }
}

fn unauthorized(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "unauthorized", "detail": msg })),
    )
        .into_response()
}

#[derive(Debug, Default, serde::Deserialize)]
struct OrgQuery {
    #[serde(default)]
    org_id: Option<String>,
}

#[allow(clippy::result_large_err)]
fn select_user_org(user: &UserCtx, requested: Option<&str>) -> Result<String, Response> {
    if let Some(org_id) = requested.map(str::trim).filter(|value| !value.is_empty()) {
        if user.orgs.iter().any(|allowed| allowed == org_id) {
            return Ok(org_id.to_string());
        }
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "forbidden_org", "org_id": org_id })),
        )
            .into_response());
    }

    match user.orgs.as_slice() {
        [] => Err((StatusCode::FORBIDDEN, Json(json!({ "error": "no_org" }))).into_response()),
        [org_id] => Ok(org_id.clone()),
        _ => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "org_id_required" })),
        )
            .into_response()),
    }
}

struct KeyCreateInput {
    name: String,
    scopes: Vec<String>,
    env: String,
    require_idempotency: bool,
}

fn validated_key_create_input(body: CreateKeyBody) -> Result<KeyCreateInput, &'static str> {
    let name = body.name.trim().to_string();
    if name.is_empty() {
        return Err("name_required");
    }

    let env = body
        .env
        .unwrap_or_else(|| "live".to_string())
        .trim()
        .to_string();
    if !matches!(env.as_str(), "live" | "test") {
        return Err("invalid_environment");
    }

    let mut scopes = Vec::new();
    for scope in body.scopes {
        let scope = scope.trim().to_string();
        if scope.is_empty() {
            continue;
        }
        if !ALLOWED_API_KEY_SCOPES.contains(&scope.as_str()) {
            return Err("invalid_scope");
        }
        if !scopes.iter().any(|existing| existing == &scope) {
            scopes.push(scope);
        }
    }
    if scopes.is_empty() {
        scopes.push("requests:write".to_string());
    }

    Ok(KeyCreateInput {
        name,
        scopes,
        env,
        require_idempotency: body.require_idempotency,
    })
}

fn bad_key_request(error: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))).into_response()
}

fn storage_unavailable(error: &dyn std::fmt::Display) -> Response {
    tracing::error!(error = %error, "auth storage operation failed");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": "storage_unavailable" })),
    )
        .into_response()
}

fn required_env(name: &str) -> Result<String, std::io::Error> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| std::io::Error::other(format!("{name} must be configured")))
}

// --- dashboard handlers ---

/// `GET /v1/me` — return the Supabase-authenticated dashboard identity.
async fn me(headers: HeaderMap) -> Response {
    match require_user(&headers).await {
        Ok(user) => Json(json!({ "user": user })).into_response(),
        Err(e) => e,
    }
}

/// `GET /v1/orgs/:org_id` — read org metadata from the in-cluster cache synced
/// from Supabase (the system of record). Never a live Supabase call.
async fn get_org(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
) -> Response {
    let user = match require_user(&headers).await {
        Ok(u) => u,
        Err(e) => return e,
    };
    if !user.orgs.iter().any(|o| o == &org_id) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(json!({ "error": "forbidden_org", "org_id": org_id })),
        )
            .into_response();
    }
    match s.orgs.get(&org_id).await {
        Some(org) => {
            Json(json!({ "org_id": org_id, "org": org, "source": "synced-cache" })).into_response()
        }
        None => (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({ "error": "not_found", "org_id": org_id })),
        )
            .into_response(),
    }
}

/// `POST /v1/keys` — create an API key for one of the caller's orgs. The raw key
/// is returned **once**.
async fn create_key(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateKeyBody>,
) -> Response {
    let user = match require_user(&headers).await {
        Ok(u) => u,
        Err(e) => return e,
    };
    let org = match select_user_org(&user, body.org_id.as_deref()) {
        Ok(org) => org,
        Err(response) => return response,
    };
    let input = match validated_key_create_input(body) {
        Ok(input) => input,
        Err(error) => return bad_key_request(error),
    };
    let (raw, meta) = match s
        .keys
        .create(
            org,
            input.name,
            input.scopes,
            input.env,
            input.require_idempotency,
        )
        .await
    {
        Ok(created) => created,
        Err(error) => return storage_unavailable(&error),
    };
    // This raw value is returned only in the response that minted it.
    Json(json!({ "api_key": raw, "key": meta })).into_response()
}

/// `POST /v1/keys/{key_id}/rotate` — replace the authoritative secret and return
/// the raw replacement only once. The response reports the configured bound for
/// already-cached positive introspection decisions at edge/LB consumers.
async fn rotate_key(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key_id): Path<String>,
    Query(query): Query<OrgQuery>,
) -> Response {
    let user = match require_user(&headers).await {
        Ok(u) => u,
        Err(e) => return e,
    };
    let org = match select_user_org(&user, query.org_id.as_deref()) {
        Ok(org) => org,
        Err(response) => return response,
    };
    match s.keys.rotate(&org, &key_id).await {
        Ok(Some((raw, meta))) => Json(json!({
            "ok": true,
            "api_key": raw,
            "key": meta,
            "secret_once": true,
            "overlap_seconds": rotation_overlap_seconds(),
        }))
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error": "key_not_found" })),
        )
            .into_response(),
        Err(error) => storage_unavailable(&error),
    }
}

fn rotation_overlap_seconds() -> u64 {
    std::env::var("FIDUCIA_ROTATION_OVERLAP_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_ROTATION_OVERLAP_SECONDS)
}

/// `GET /v1/keys` — list the caller org's keys (masked).
async fn list_keys(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<OrgQuery>,
) -> Response {
    let user = match require_user(&headers).await {
        Ok(u) => u,
        Err(e) => return e,
    };
    let org = match select_user_org(&user, query.org_id.as_deref()) {
        Ok(org) => org,
        Err(response) => return response,
    };
    match s.keys.list(&org).await {
        Ok(keys) => Json(json!({ "keys": keys })).into_response(),
        Err(error) => storage_unavailable(&error),
    }
}

/// `DELETE /v1/keys/{key_id}` — revoke a key the caller's org owns.
async fn revoke_key(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key_id): Path<String>,
    Query(query): Query<OrgQuery>,
) -> Response {
    let user = match require_user(&headers).await {
        Ok(u) => u,
        Err(e) => return e,
    };
    let org = match select_user_org(&user, query.org_id.as_deref()) {
        Ok(org) => org,
        Err(response) => return response,
    };
    match s.keys.revoke(&org, &key_id).await {
        Ok(revoked) => Json(json!({ "revoked": revoked })).into_response(),
        Err(error) => storage_unavailable(&error),
    }
}

// --- data-plane handlers (edge/LB) ---

/// `POST /v1/introspect` — validate an API key → org + scopes. The edge/LB caches
/// this. `FIDUCIA_INTROSPECT_SECRET` is required at startup and supplied via
/// `x-server-auth` on this internal endpoint.
async fn introspect(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<IntrospectBody>,
) -> Response {
    if !internal_secret_authorized(&headers, &s.introspect_secret) {
        return unauthorized("missing or invalid internal auth");
    }
    match s.keys.introspect(&body.api_key).await {
        Ok(result) => Json(json!(result)).into_response(),
        Err(error) => storage_unavailable(&error),
    }
}

/// `POST /v1/token` — exchange an API key for a short-lived JWT (offline-verifiable).
async fn exchange_token(State(s): State<Arc<AppState>>, Json(body): Json<TokenBody>) -> Response {
    let intro = match s.keys.introspect(&body.api_key).await {
        Ok(result) => result,
        Err(error) => return storage_unavailable(&error),
    };
    if !intro.valid {
        return unauthorized("invalid api key");
    }
    let org = intro.org_id.unwrap_or_default();
    let jwt = token::mint_token(&org, &intro.scopes, 900);
    Json(json!({ "token": jwt, "token_type": "Bearer", "expires_in": 900 })).into_response()
}

fn internal_secret_authorized(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get("x-server-auth")
        .and_then(|value| value.to_str().ok())
        .map(|provided| constant_time_eq(provided.as_bytes(), expected.as_bytes()))
        .unwrap_or(false)
}

/// Compare two byte strings in time independent of how many leading bytes match,
/// so an attacker probing `x-server-auth` can't recover the shared introspection
/// secret one byte at a time. (The API-key path already does this in `keys.rs`;
/// this closes the same gap on the internal server-to-server secret.) The length
/// short-circuit leaks only the secret's length, not its contents.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod constant_time_tests {
    use super::constant_time_eq;

    #[test]
    fn matches_only_on_exact_equality() {
        assert!(constant_time_eq(b"s3cret-value", b"s3cret-value"));
        assert!(!constant_time_eq(b"s3cret-value", b"s3cret-walue"));
        assert!(!constant_time_eq(b"s3cret", b"s3cret-value")); // length mismatch
        assert!(constant_time_eq(b"", b""));
    }
}

#[cfg(test)]
mod interface_contract_tests {
    use super::{validated_key_create_input, CreateKeyBody};
    use fiducia_interfaces::{LockAcquireManyRequest, ProposeErrorReason};

    #[test]
    fn generated_interfaces_are_importable() {
        let request = LockAcquireManyRequest {
            keys: vec!["orders/42".to_string(), "inventory/sku-7".to_string()],
            holder: Some("worker-a".to_string()),
            ttl_ms: Some(30_000),
            wait: Some(false),
        };

        assert_eq!(request.keys.len(), 2);
        assert!(matches!(
            ProposeErrorReason::NotLeader,
            ProposeErrorReason::NotLeader
        ));
    }

    #[test]
    fn key_creation_defaults_and_dedupes_scopes() {
        let input = validated_key_create_input(CreateKeyBody {
            name: " production ".to_string(),
            org_id: None,
            scopes: vec![
                " kv:read ".to_string(),
                "kv:read".to_string(),
                "".to_string(),
            ],
            env: None,
            require_idempotency: true,
        })
        .expect("valid input");

        assert_eq!(input.name, "production");
        assert_eq!(input.env, "live");
        assert_eq!(input.scopes, vec!["kv:read".to_string()]);
        assert!(input.require_idempotency);

        let defaulted = validated_key_create_input(CreateKeyBody {
            name: "worker".to_string(),
            org_id: None,
            scopes: vec![],
            env: Some("test".to_string()),
            require_idempotency: false,
        })
        .expect("valid input");
        assert_eq!(defaulted.scopes, vec!["requests:write".to_string()]);
        assert_eq!(defaulted.env, "test");
        assert!(!defaulted.require_idempotency);
    }

    #[test]
    fn key_creation_rejects_bad_name_env_and_scope() {
        assert!(validated_key_create_input(CreateKeyBody {
            name: " ".to_string(),
            org_id: None,
            scopes: vec!["kv:read".to_string()],
            env: None,
            require_idempotency: true,
        })
        .is_err());
        assert!(validated_key_create_input(CreateKeyBody {
            name: "worker".to_string(),
            org_id: None,
            scopes: vec!["kv:read".to_string()],
            env: Some("prod".to_string()),
            require_idempotency: true,
        })
        .is_err());
        assert!(validated_key_create_input(CreateKeyBody {
            name: "worker".to_string(),
            org_id: None,
            scopes: vec!["*".to_string()],
            env: None,
            require_idempotency: true,
        })
        .is_err());
    }

    #[test]
    fn key_request_defaults_idempotency_to_true() {
        let body: CreateKeyBody = serde_json::from_value(serde_json::json!({
            "name": "worker",
            "org_id": "org_1",
            "scopes": ["requests:write"],
            "env": "live"
        }))
        .unwrap();
        assert!(body.require_idempotency);
    }
}
