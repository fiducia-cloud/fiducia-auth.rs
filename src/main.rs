//! fiducia-auth — the auth server.
//!
//! Two planes, two credentials, and **neither hits Supabase (or the DB) on the
//! hot path**:
//!
//!   * **Dashboard (humans):** Supabase Auth issues a session JWT. We verify it
//!     **offline** with Supabase's cached JWKS (only the dashboard/control plane;
//!     see `supabase.rs`). Used to create/list/revoke API keys.
//!   * **API clients (machines):** a static API key (`fdc_live_<id>.<secret>`).
//!     The edge/LB validates it via `POST /v1/introspect` and **caches** the
//!     result (short TTL), so steady state makes no auth call. Optionally the key
//!     is exchanged once for a short-lived JWT verified offline (see `token.rs`).
//!
//! This is a **skeleton**: routing + the key store are real (in-memory);
//! Supabase JWT verification, real crypto/hashing, JWT signing, and Postgres are
//! stubbed with `TODO`s.

mod keys;
mod model;
mod supabase;
mod token;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::HeaderMap,
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

/// Reject any request whose handler runs longer than this (slow-loris / hung
/// upstream protection). Auth work is sub-millisecond.
const REQUEST_TIMEOUT_SECS: u64 = 15;
/// Cap request bodies; auth payloads are tiny JSON.
const MAX_BODY_BYTES: usize = 64 * 1024;

struct AppState {
    keys: KeyStore,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    fiducia_telemetry::init(SERVICE);

    let state = Arc::new(AppState {
        keys: KeyStore::new(),
    });

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/.well-known/jwks.json", get(jwks))
        // Dashboard plane (requires a Supabase session JWT).
        .route("/v1/me", get(me))
        .route("/v1/keys", post(create_key).get(list_keys))
        .route("/v1/keys/:key_id", axum::routing::delete(revoke_key))
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
        axum::http::StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "unauthorized", "detail": msg })),
    )
        .into_response()
}

// --- dashboard handlers ---

/// `GET /v1/me` — return the Supabase-authenticated dashboard identity.
async fn me(headers: HeaderMap) -> Response {
    match require_user(&headers).await {
        Ok(user) => Json(json!({ "user": user })).into_response(),
        Err(e) => e,
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
    // TODO: take org from request + check `user.orgs` contains it. Skeleton uses
    // the user's first org.
    let Some(org) = user.orgs.first().cloned() else {
        return (
            axum::http::StatusCode::FORBIDDEN,
            Json(json!({ "error": "no_org" })),
        )
            .into_response();
    };
    let env = body.env.unwrap_or_else(|| "live".to_string());
    let (raw, meta) = s.keys.create(org, body.name, body.scopes, env);
    // The only time the raw key is ever returned.
    Json(json!({ "api_key": raw, "key": meta })).into_response()
}

/// `GET /v1/keys` — list the caller org's keys (masked).
async fn list_keys(State(s): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let user = match require_user(&headers).await {
        Ok(u) => u,
        Err(e) => return e,
    };
    let org = user.orgs.first().cloned().unwrap_or_default();
    Json(json!({ "keys": s.keys.list(&org) })).into_response()
}

/// `DELETE /v1/keys/{key_id}` — revoke a key the caller's org owns.
async fn revoke_key(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key_id): Path<String>,
) -> Response {
    let user = match require_user(&headers).await {
        Ok(u) => u,
        Err(e) => return e,
    };
    let org = user.orgs.first().cloned().unwrap_or_default();
    Json(json!({ "revoked": s.keys.revoke(&org, &key_id) })).into_response()
}

// --- data-plane handlers (edge/LB) ---

/// `POST /v1/introspect` — validate an API key → org + scopes. The edge/LB caches
/// this. TODO: protect this endpoint (mTLS / shared secret); it's internal-only.
async fn introspect(
    State(s): State<Arc<AppState>>,
    Json(body): Json<IntrospectBody>,
) -> Json<Value> {
    Json(json!(s.keys.introspect(&body.api_key)))
}

/// `POST /v1/token` — exchange an API key for a short-lived JWT (offline-verifiable).
async fn exchange_token(State(s): State<Arc<AppState>>, Json(body): Json<TokenBody>) -> Response {
    let intro = s.keys.introspect(&body.api_key);
    if !intro.valid {
        return unauthorized("invalid api key");
    }
    let org = intro.org_id.unwrap_or_default();
    let jwt = token::mint_token(&org, &intro.scopes, 900); // 15 min
    Json(json!({ "token": jwt, "token_type": "Bearer", "expires_in": 900 })).into_response()
}

#[cfg(test)]
mod interface_contract_tests {
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
}
