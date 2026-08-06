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
mod supabase_policy;
mod sync;
mod token;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::time::Duration;
use tower_http::{
    catch_panic::CatchPanicLayer, cors::CorsLayer, limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer, trace::TraceLayer,
};

use keys::{KeyStore, MutationIdentity};
use model::{CreateKeyBody, IntrospectBody, TokenBody, UserCtx};
use store::StoreError;

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
/// Shared server-to-server credentials must have meaningful entropy and must
/// never be syntactically ambiguous when an intermediary coalesces headers.
const MIN_INTROSPECT_SECRET_BYTES: usize = 32;

struct AppState {
    keys: KeyStore,
    orgs: Arc<sync::OrgCache>,
    introspect_secret: String,
    rotation_overlap_seconds: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Hold the guard for the whole of `main`: v0.2.1's `init` returns a
    // `#[must_use]` TelemetryGuard that flushes and shuts down the OTLP trace +
    // metric exporters on drop, so `let _ =` (or a bare statement) would tear
    // telemetry down immediately. `_telemetry` keeps it alive until main exits.
    let _telemetry = fiducia_telemetry::init(SERVICE);

    token::validate_config().map_err(std::io::Error::other)?;
    supabase::validate_config().map_err(std::io::Error::other)?;
    let introspect_secret = introspect_secret_from_env()?;
    let rotation_overlap_seconds = rotation_overlap_seconds_from_env()?;
    let keys = KeyStore::from_env().map_err(std::io::Error::other)?;
    let customer_origin = customer_origin_from_env()?;

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
        rotation_overlap_seconds,
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
        // Data plane. `introspect` is a server-to-server oracle (answers "is this
        // arbitrary key valid?" for keys the caller does not hold), so it is
        // internal-only and gated by the `x-server-auth` shared secret. `token`
        // is a customer-facing exchange: the caller proves possession of a valid
        // API key and receives a JWT scoped to that key's own org — it is
        // self-authenticated by the key and intentionally NOT secret-gated.
        .route("/v1/introspect", post(introspect))
        .route("/v1/token", post(exchange_token))
        .with_state(state)
        // Hardening stack (outermost last): catch handler panics → 500 instead
        // of dropping the connection, bound request time, and cap body size.
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(REQUEST_TIMEOUT_SECS)))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(CatchPanicLayer::new())
        // The customer portal is independently hosted. Permit only its exact
        // configured origin to call browser-facing auth routes; this is never a
        // wildcard and does not enable credentialed cookies.
        .layer(customer_cors_layer(customer_origin));

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
    let bearer = single_header_str(headers, "authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty());
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

fn key_store_error(error: StoreError) -> Response {
    if matches!(error, StoreError::IdempotencyConflict) {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "idempotency_conflict" })),
        )
            .into_response();
    }
    storage_unavailable(&error)
}

#[allow(clippy::result_large_err)]
fn require_idempotency_key(headers: &HeaderMap) -> Result<String, Response> {
    let Some(value) = single_header_str(headers, "idempotency-key") else {
        return Err(bad_key_request("idempotency_key_required"));
    };
    if value.is_empty()
        || value.len() > 128
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(bad_key_request("invalid_idempotency_key"));
    }
    Ok(value.to_string())
}

fn introspect_secret_from_env() -> Result<String, std::io::Error> {
    match std::env::var("FIDUCIA_INTROSPECT_SECRET") {
        Ok(value) => introspect_secret_from(Some(&value)),
        Err(std::env::VarError::NotPresent) => introspect_secret_from(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(std::io::Error::other(
            "FIDUCIA_INTROSPECT_SECRET must be valid UTF-8",
        )),
    }
}

fn introspect_secret_from(value: Option<&str>) -> Result<String, std::io::Error> {
    let Some(secret) = value.filter(|value| !value.is_empty()) else {
        return Err(std::io::Error::other(
            "FIDUCIA_INTROSPECT_SECRET must be configured",
        ));
    };
    if secret.trim() != secret
        || secret.len() < MIN_INTROSPECT_SECRET_BYTES
        || secret.chars().any(|character| {
            character.is_control() || character.is_whitespace() || character == ','
        })
    {
        return Err(std::io::Error::other(
            "FIDUCIA_INTROSPECT_SECRET must be at least 32 bytes and contain no whitespace, control characters, or commas",
        ));
    }
    Ok(secret.to_string())
}

/// Return one canonical header value or fail closed. `HeaderMap::get` alone is
/// not enough for an identity boundary: it selects one value when duplicates
/// exist, while a proxy may select another or coalesce them with commas.
fn single_header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?.trim();
    if value.is_empty() || value.contains(',') || values.next().is_some() {
        return None;
    }
    Some(value)
}

fn customer_origin_from_env() -> Result<HeaderValue, std::io::Error> {
    customer_origin_from(std::env::var("FIDUCIA_CUSTOMER_ORIGIN").ok().as_deref())
}

fn customer_origin_from(value: Option<&str>) -> Result<HeaderValue, std::io::Error> {
    let configured = value.unwrap_or("https://app.fiducia.cloud").trim();
    let parsed = reqwest::Url::parse(configured).map_err(|_| {
        std::io::Error::other("FIDUCIA_CUSTOMER_ORIGIN must be an absolute HTTP(S) origin")
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(std::io::Error::other(
            "FIDUCIA_CUSTOMER_ORIGIN must contain only an HTTP(S) scheme, host, and optional port",
        ));
    }
    let origin = parsed.origin().ascii_serialization();
    HeaderValue::from_str(&origin).map_err(|_| {
        std::io::Error::other("FIDUCIA_CUSTOMER_ORIGIN is not a valid HTTP Origin header")
    })
}

fn customer_cors_layer(origin: HeaderValue) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(origin)
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("idempotency-key"),
            HeaderName::from_static("x-fiducia-org-id"),
        ])
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
    let idempotency_key = match require_idempotency_key(&headers) {
        Ok(value) => value,
        Err(response) => return response,
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
            MutationIdentity::new(&user.user_id, &idempotency_key),
            org,
            input.name,
            input.scopes,
            input.env,
            input.require_idempotency,
        )
        .await
    {
        Ok(created) => created,
        Err(error) => return key_store_error(error),
    };
    // This raw value is returned only in the response that minted it.
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "api_key": raw, "key": meta })),
    )
        .into_response()
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
    let idempotency_key = match require_idempotency_key(&headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let org = match select_user_org(&user, query.org_id.as_deref()) {
        Ok(org) => org,
        Err(response) => return response,
    };
    match s
        .keys
        .rotate(&user.user_id, &idempotency_key, &org, &key_id)
        .await
    {
        Ok(Some((raw, meta))) => (
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({
                "ok": true,
                "api_key": raw,
                "key": meta,
                "secret_once": true,
                "overlap_seconds": s.rotation_overlap_seconds,
            })),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error": "key_not_found" })),
        )
            .into_response(),
        Err(error) => key_store_error(error),
    }
}

fn rotation_overlap_seconds_from_env() -> Result<u64, std::io::Error> {
    match std::env::var("FIDUCIA_ROTATION_OVERLAP_SECONDS") {
        Ok(value) => rotation_overlap_seconds_from(Some(&value)),
        Err(std::env::VarError::NotPresent) => rotation_overlap_seconds_from(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(std::io::Error::other(
            "FIDUCIA_ROTATION_OVERLAP_SECONDS must be valid UTF-8",
        )),
    }
}

fn rotation_overlap_seconds_from(value: Option<&str>) -> Result<u64, std::io::Error> {
    let Some(value) = value else {
        return Ok(DEFAULT_ROTATION_OVERLAP_SECONDS);
    };
    let seconds = value.trim().parse::<u64>().map_err(|_| {
        std::io::Error::other("FIDUCIA_ROTATION_OVERLAP_SECONDS must be a positive integer")
    })?;
    if seconds == 0 {
        return Err(std::io::Error::other(
            "FIDUCIA_ROTATION_OVERLAP_SECONDS must be greater than zero",
        ));
    }
    Ok(seconds)
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
///
/// Public / customer-facing: unlike `introspect`, this endpoint is deliberately
/// NOT gated by the `x-server-auth` internal secret. It is self-authenticated by
/// the API key itself — the caller must present a valid `fdc_…` key (verified by
/// the constant-time secret-hash check in `keys.rs`), an invalid key yields 401,
/// and a valid one only ever mints a JWT scoped to *that key's own* org/scopes.
/// A caller without a valid key learns nothing, so there is no introspection
/// oracle to protect here. The customers who exchange keys for JWTs do not (and
/// must not) hold the internal server secret, so gating this would break the
/// exchange while adding no security. Do not add an `internal_secret_authorized`
/// check here — see `introspect` for the endpoint that genuinely needs it.
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
    single_header_str(headers, "x-server-auth")
        .is_some_and(|provided| constant_time_eq(provided.as_bytes(), expected.as_bytes()))
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
    use super::{
        constant_time_eq, internal_secret_authorized, introspect_secret_from, single_header_str,
    };
    use axum::http::HeaderMap;

    #[test]
    fn matches_only_on_exact_equality() {
        assert!(constant_time_eq(b"s3cret-value", b"s3cret-value"));
        assert!(!constant_time_eq(b"s3cret-value", b"s3cret-walue"));
        assert!(!constant_time_eq(b"s3cret", b"s3cret-value")); // length mismatch
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn identity_headers_require_exactly_one_unambiguous_value() {
        let mut headers = HeaderMap::new();
        headers.append("authorization", "Bearer valid.jwt.value".parse().unwrap());
        assert_eq!(
            single_header_str(&headers, "authorization"),
            Some("Bearer valid.jwt.value")
        );

        headers.append(
            "authorization",
            "Bearer attacker.jwt.value".parse().unwrap(),
        );
        assert_eq!(single_header_str(&headers, "authorization"), None);

        let mut coalesced = HeaderMap::new();
        coalesced.insert(
            "authorization",
            "Bearer valid.jwt.value, Bearer attacker.jwt.value"
                .parse()
                .unwrap(),
        );
        assert_eq!(single_header_str(&coalesced, "authorization"), None);
    }

    #[test]
    fn introspection_rejects_duplicate_values_in_both_orders() {
        let secret = "0123456789abcdef0123456789abcdef";
        let mut correct_first = HeaderMap::new();
        correct_first.append("x-server-auth", secret.parse().unwrap());
        correct_first.append("x-server-auth", "attacker".parse().unwrap());
        assert!(!internal_secret_authorized(&correct_first, secret));

        let mut correct_last = HeaderMap::new();
        correct_last.append("x-server-auth", "attacker".parse().unwrap());
        correct_last.append("x-server-auth", secret.parse().unwrap());
        assert!(!internal_secret_authorized(&correct_last, secret));

        let mut exact = HeaderMap::new();
        exact.insert("x-server-auth", secret.parse().unwrap());
        assert!(internal_secret_authorized(&exact, secret));
    }

    #[test]
    fn introspection_secret_configuration_is_strong_and_unambiguous() {
        assert!(introspect_secret_from(None).is_err());
        assert!(introspect_secret_from(Some("short")).is_err());
        let padded = format!(" {}", "x".repeat(32));
        assert!(introspect_secret_from(Some(&padded)).is_err());
        assert!(introspect_secret_from(Some(&"x".repeat(32))).is_ok());
        assert!(introspect_secret_from(Some(&("x".repeat(32) + ",suffix"))).is_err());
        assert!(introspect_secret_from(Some(&("x".repeat(32) + " suffix"))).is_err());
    }
}

#[cfg(test)]
mod cors_tests {
    use super::{customer_cors_layer, customer_origin_from};
    use axum::{
        body::Body,
        http::{header, Method, Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new()
            .route("/v1/me", get(|| async { StatusCode::OK }))
            .layer(customer_cors_layer(
                customer_origin_from(Some("https://app.fiducia.cloud")).unwrap(),
            ))
    }

    #[tokio::test]
    async fn customer_origin_preflight_is_allowed_exactly() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/v1/me")
                    .header(header::ORIGIN, "https://app.fiducia.cloud")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&"https://app.fiducia.cloud".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn sibling_origin_never_receives_itself_as_an_allowed_origin() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v1/me")
                    .header(header::ORIGIN, "https://admin.fiducia.cloud")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let allowed = response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap();
        assert_eq!(allowed, "https://app.fiducia.cloud");
        assert_ne!(allowed, "https://admin.fiducia.cloud");
    }
}

#[cfg(test)]
mod interface_contract_tests {
    use super::{
        customer_origin_from, rotation_overlap_seconds_from, select_user_org,
        validated_key_create_input, CreateKeyBody, UserCtx,
    };
    use crate::model::AssuranceLevel;
    use fiducia_interfaces::{LockAcquireManyRequest, ProposeErrorReason};

    #[test]
    fn generated_interfaces_are_importable() {
        let request = LockAcquireManyRequest {
            keys: vec!["orders/42".to_string(), "inventory/sku-7".to_string()],
            holder: "worker-a".to_string(),
            request_id: Some("interface-contract-attempt".to_string()),
            ttl_ms: Some(30_000),
            wait: Some(true),
            wait_timeout_ms: Some(5_000),
        };

        assert_eq!(request.keys.len(), 2);
        assert_eq!(request.holder, "worker-a");
        assert_eq!(
            request.request_id.as_deref(),
            Some("interface-contract-attempt")
        );
        assert_eq!(request.wait_timeout_ms, Some(5_000));
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

    fn user(orgs: &[&str]) -> UserCtx {
        UserCtx {
            user_id: "user_1".to_string(),
            email: None,
            orgs: orgs.iter().map(|value| (*value).to_string()).collect(),
            roles: Vec::new(),
            aal: AssuranceLevel::Aal2,
            project_surfaces: None,
        }
    }

    #[test]
    fn multi_org_key_operations_require_an_explicit_authorized_org() {
        let multi = user(&["org_a", "org_b"]);
        assert!(select_user_org(&multi, None).is_err());
        assert_eq!(select_user_org(&multi, Some("org_b")).unwrap(), "org_b");
        assert!(select_user_org(&multi, Some("org_c")).is_err());

        let single = user(&["org_a"]);
        assert_eq!(select_user_org(&single, None).unwrap(), "org_a");
    }

    #[test]
    fn customer_key_creation_rejects_admin_scopes() {
        for scope in ["admin:read", "admin:write", "admin:*"] {
            assert!(validated_key_create_input(CreateKeyBody {
                name: "worker".to_string(),
                org_id: Some("org_a".to_string()),
                scopes: vec![scope.to_string()],
                env: None,
                require_idempotency: true,
            })
            .is_err());
        }
    }

    #[test]
    fn rotation_overlap_configuration_fails_closed_when_invalid() {
        assert_eq!(rotation_overlap_seconds_from(None).unwrap(), 60);
        assert_eq!(rotation_overlap_seconds_from(Some("120")).unwrap(), 120);
        assert!(rotation_overlap_seconds_from(Some("0")).is_err());
        assert!(rotation_overlap_seconds_from(Some("not-a-number")).is_err());
    }

    #[test]
    fn customer_cors_origin_is_exact_and_normalized() {
        assert_eq!(
            customer_origin_from(None).unwrap().to_str().unwrap(),
            "https://app.fiducia.cloud"
        );
        assert_eq!(
            customer_origin_from(Some("http://127.0.0.1:4173/"))
                .unwrap()
                .to_str()
                .unwrap(),
            "http://127.0.0.1:4173"
        );
        for invalid in [
            "*",
            "null",
            "ftp://app.fiducia.cloud",
            "https://app.fiducia.cloud/path",
            "https://app.fiducia.cloud?query=1",
        ] {
            assert!(
                customer_origin_from(Some(invalid)).is_err(),
                "accepted {invalid}"
            );
        }
    }
}
