//! Durable API-key storage in fiducia's OWN KV (dogfooding the coordination
//! cluster) — so the end-user data plane never touches Supabase. The auth server
//! talks to a node's KV over HTTP (`FIDUCIA_KV_URL`, in-cluster); records live
//! under the reserved `__auth/` keyspace. An in-memory hot cache (see `keys.rs`)
//! fronts this so the steady-state introspect is a local map lookup, not a round
//! trip.

use serde::{Deserialize, Serialize};
use serde_json::Value;

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
        }
    }
}

/// Thin HTTP client for fiducia KV. Values are opaque strings on the wire, so we
/// store each record as a JSON string.
pub struct KvClient {
    base: String,
    http: reqwest::Client,
}

impl KvClient {
    /// Build from `FIDUCIA_KV_URL` (e.g. http://fiducia-node.fiducia.svc:8090).
    /// Absent → `None` (auth runs in-memory only; dev / tests).
    pub fn from_env() -> Option<Self> {
        let base = std::env::var("FIDUCIA_KV_URL")
            .ok()
            .filter(|u| !u.trim().is_empty())?;
        Some(KvClient {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        })
    }

    /// GET /v1/kv?key=… → the stored value parsed back from its JSON string.
    pub async fn get(&self, key: &str) -> Option<Value> {
        let resp = self
            .http
            .get(format!("{}/v1/kv", self.base))
            .query(&[("key", key)])
            .send()
            .await
            .ok()?;
        let body: Value = resp.json().await.ok()?;
        if body.get("found").and_then(Value::as_bool) != Some(true) {
            return None;
        }
        let raw = body.get("entry")?.get("value")?.as_str()?;
        serde_json::from_str(raw).ok()
    }

    /// PUT /v1/kv?key=… with the value as a JSON string. Returns commit success.
    pub async fn put(&self, key: &str, value: &Value) -> bool {
        let body = serde_json::json!({ "value": value.to_string() });
        match self
            .http
            .put(format!("{}/v1/kv", self.base))
            .query(&[("key", key)])
            .json(&body)
            .send()
            .await
        {
            Ok(r) => {
                let ok = r.status().is_success();
                if !ok {
                    tracing::warn!(key, status = %r.status(), "fiducia KV put failed");
                }
                ok
            }
            Err(e) => {
                tracing::warn!(key, error = %e, "fiducia KV put error");
                false
            }
        }
    }
}
