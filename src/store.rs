//! Durable API-key storage in fiducia's OWN KV (dogfooding the coordination
//! cluster) — so the end-user data plane never touches Supabase. The auth server
//! talks to a node's KV over HTTP (`FIDUCIA_KV_URL`, in-cluster); records live
//! under the reserved `__auth/` keyspace. An in-memory hot cache (see `keys.rs`)
//! fronts this so the steady-state introspect is a local map lookup, not a round
//! trip.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

use crate::model::{ApiKeyRecord, OrgId};

pub fn key_path(key_id: &str) -> String {
    format!("__auth/keys/{key_id}")
}

pub fn org_index_path(org_id: &str) -> String {
    format!("__auth/orgs/{org_id}/keys")
}

/// The durable form of a key. Unlike [`ApiKeyRecord`] (whose `secret_hash` is
/// `#[serde(skip)]` so it never leaks over the API), this serializes the hash —
/// it IS the persisted record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKey {
    pub key_id: String,
    pub org_id: OrgId,
    pub name: String,
    pub secret_hash: String,
    pub scopes: Vec<String>,
    pub created_ms: u64,
    pub last_used_ms: Option<u64>,
    pub revoked: bool,
    pub env: String,
    /// When true, the edge/LB rejects keyless mutating calls. `#[serde(default)]`
    /// so records persisted before this field parse as `false` (opt-in control).
    #[serde(default)]
    pub require_idempotency: bool,
}

impl From<&ApiKeyRecord> for StoredKey {
    fn from(r: &ApiKeyRecord) -> Self {
        StoredKey {
            key_id: r.key_id.clone(),
            org_id: r.org_id.clone(),
            name: r.name.clone(),
            secret_hash: r.secret_hash.clone(),
            scopes: r.scopes.clone(),
            created_ms: r.created_ms,
            last_used_ms: r.last_used_ms,
            revoked: r.revoked,
            env: r.env.clone(),
            require_idempotency: r.require_idempotency,
        }
    }
}

impl From<&StoredKey> for ApiKeyRecord {
    fn from(s: &StoredKey) -> Self {
        ApiKeyRecord {
            key_id: s.key_id.clone(),
            org_id: s.org_id.clone(),
            name: s.name.clone(),
            secret_hash: s.secret_hash.clone(),
            scopes: s.scopes.clone(),
            created_ms: s.created_ms,
            last_used_ms: s.last_used_ms,
            revoked: s.revoked,
            env: s.env.clone(),
            require_idempotency: s.require_idempotency,
        }
    }
}

/// Thin HTTP client for fiducia KV. Values are opaque strings on the wire, so we
/// store each record as a JSON string.
pub struct KvClient {
    base: String,
    http: reqwest::Client,
}

#[derive(Debug)]
pub enum KvError {
    Http(reqwest::Error),
    Protocol(String),
    Json(serde_json::Error),
}

impl fmt::Display for KvError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(error) => write!(formatter, "fiducia KV HTTP error: {error}"),
            Self::Protocol(error) => write!(formatter, "fiducia KV protocol error: {error}"),
            Self::Json(error) => write!(formatter, "fiducia KV JSON error: {error}"),
        }
    }
}

impl std::error::Error for KvError {}

impl From<reqwest::Error> for KvError {
    fn from(error: reqwest::Error) -> Self {
        Self::Http(error)
    }
}

impl From<serde_json::Error> for KvError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl KvClient {
    /// Build from `FIDUCIA_KV_URL` (e.g. http://fiducia-node.fiducia.svc:8090).
    /// Production auth requires an authoritative KV endpoint. Tests construct an
    /// in-memory store directly and never call this initializer.
    pub fn from_env() -> Result<Self, String> {
        let base = std::env::var("FIDUCIA_KV_URL")
            .ok()
            .filter(|u| !u.trim().is_empty())
            .ok_or_else(|| "FIDUCIA_KV_URL must be configured".to_string())?;
        Ok(KvClient {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        })
    }

    /// GET /v1/kv?key=… → the stored value parsed back from its JSON string.
    pub async fn get(&self, key: &str) -> Result<Option<Value>, KvError> {
        let resp = self
            .http
            .get(format!("{}/v1/kv", self.base))
            .query(&[("key", key)])
            .send()
            .await?
            .error_for_status()?;
        let body: Value = resp.json().await?;
        match body.get("found").and_then(Value::as_bool) {
            Some(false) => return Ok(None),
            Some(true) => {}
            None => {
                return Err(KvError::Protocol(
                    "response omitted found boolean".to_string(),
                ))
            }
        }
        let raw = body
            .get("entry")
            .and_then(|entry| entry.get("value"))
            .and_then(Value::as_str)
            .ok_or_else(|| KvError::Protocol("found response omitted entry.value".to_string()))?;
        Ok(Some(serde_json::from_str(raw)?))
    }

    /// PUT /v1/kv?key=… with the value as a JSON string. Success means the node
    /// accepted the write; any transport or status failure is returned to the
    /// caller so credentials cannot be issued before persistence.
    pub async fn put(&self, key: &str, value: &Value) -> Result<(), KvError> {
        let body = serde_json::json!({ "value": value.to_string() });
        self.http
            .put(format!("{}/v1/kv", self.base))
            .query(&[("key", key)])
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}
