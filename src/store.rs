//! Durable API-key storage in fiducia's OWN KV (dogfooding the coordination
//! cluster) — so the end-user data plane never touches Supabase. The auth server
//! talks to a node's KV over HTTP (`FIDUCIA_KV_URL`, in-cluster); records live
//! under the reserved `__auth/` keyspace. Production introspection reads these
//! authoritative records so rotations and revocations cross replica boundaries.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

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
    /// Monotonic customer-visible record version. Records written before this
    /// field was introduced deserialize at version 0; their next mutation
    /// advances them to 1.
    #[serde(default)]
    pub version: u64,
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
            version: r.version,
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
            version: s.version,
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

/// One decoded KV value together with the revision needed for compare-and-set.
pub struct VersionedValue {
    pub value: Value,
    pub mod_revision: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasOutcome {
    Applied,
    Mismatch,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("FIDUCIA_KV_URL must be set")]
    MissingUrl,
    #[error("fiducia KV request failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("fiducia KV returned HTTP {0}")]
    Http(reqwest::StatusCode),
    #[error("fiducia KV returned an invalid stored value")]
    InvalidValue,
    #[error("fiducia KV compare-and-set retries exhausted")]
    CasRetriesExhausted,
    #[error("API-key record version overflow")]
    VersionOverflow,
}

impl KvClient {
    /// Build from `FIDUCIA_KV_URL` (e.g. http://fiducia-node.fiducia.svc:8090).
    /// Production requires a durable Fiducia KV endpoint.
    pub fn from_env() -> Result<Self, StoreError> {
        let base = std::env::var("FIDUCIA_KV_URL")
            .ok()
            .filter(|u| !u.trim().is_empty())
            .ok_or(StoreError::MissingUrl)?;
        Ok(KvClient {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        })
    }

    /// GET /v1/kv?key=… → the stored value and its CAS revision.
    pub async fn get_versioned(&self, key: &str) -> Result<Option<VersionedValue>, StoreError> {
        let resp = self
            .http
            .get(format!("{}/v1/kv", self.base))
            .query(&[("key", key)])
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(StoreError::Http(resp.status()));
        }
        let body: Value = resp.json().await?;
        match body.get("found").and_then(Value::as_bool) {
            Some(false) => return Ok(None),
            Some(true) => {}
            None => return Err(StoreError::InvalidValue),
        }
        let entry = body.get("entry").ok_or(StoreError::InvalidValue)?;
        let raw = entry
            .get("value")
            .and_then(Value::as_str)
            .ok_or(StoreError::InvalidValue)?;
        let mod_revision = entry
            .get("mod_revision")
            .and_then(Value::as_u64)
            .ok_or(StoreError::InvalidValue)?;
        Ok(Some(VersionedValue {
            value: serde_json::from_str(raw).map_err(|_| StoreError::InvalidValue)?,
            mod_revision,
        }))
    }

    /// GET a decoded value when its revision is not needed.
    pub async fn get(&self, key: &str) -> Result<Option<Value>, StoreError> {
        Ok(self.get_versioned(key).await?.map(|entry| entry.value))
    }

    /// Unconditional PUT. Still validates the complete mutation envelope and
    /// fails closed unless the command both committed and reported `ok: true`.
    pub async fn put(&self, key: &str, value: &Value) -> Result<(), StoreError> {
        match self.put_inner(key, value, None).await? {
            CasOutcome::Applied => Ok(()),
            CasOutcome::Mismatch => Err(StoreError::InvalidValue),
        }
    }

    /// Compare-and-set PUT. A `prev_revision` of 0 means the key must not exist.
    pub async fn put_if_revision(
        &self,
        key: &str,
        value: &Value,
        prev_revision: u64,
    ) -> Result<CasOutcome, StoreError> {
        self.put_inner(key, value, Some(prev_revision)).await
    }

    async fn put_inner(
        &self,
        key: &str,
        value: &Value,
        prev_revision: Option<u64>,
    ) -> Result<CasOutcome, StoreError> {
        let body = serde_json::json!({
            "value": value.to_string(),
            "prev_revision": prev_revision,
        });
        let response = self
            .http
            .put(format!("{}/v1/kv", self.base))
            .query(&[("key", key)])
            .json(&body)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(StoreError::Http(response.status()));
        }
        let response: Value = response.json().await?;
        parse_put_response(&response)
    }

    #[cfg(test)]
    pub(crate) fn for_test(base: String) -> Self {
        Self {
            base,
            http: reqwest::Client::new(),
        }
    }
}

fn parse_put_response(response: &Value) -> Result<CasOutcome, StoreError> {
    if response.get("committed").and_then(Value::as_bool) != Some(true) {
        return Err(StoreError::InvalidValue);
    }
    let output = response
        .get("result")
        .and_then(|result| result.get("output"))
        .ok_or(StoreError::InvalidValue)?;
    match output.get("ok").and_then(Value::as_bool) {
        Some(true) => {
            output
                .get("revision")
                .and_then(Value::as_u64)
                .ok_or(StoreError::InvalidValue)?;
            Ok(CasOutcome::Applied)
        }
        Some(false)
            if output.get("reason").and_then(Value::as_str) == Some("cas_mismatch")
                && output
                    .get("current_revision")
                    .and_then(Value::as_u64)
                    .is_some() =>
        {
            Ok(CasOutcome::Mismatch)
        }
        _ => Err(StoreError::InvalidValue),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn old_stored_keys_default_version_and_idempotency_to_zero_and_false() {
        let stored: StoredKey = serde_json::from_value(json!({
            "key_id": "k1",
            "org_id": "org_1",
            "name": "legacy",
            "secret_hash": "sha256:x",
            "scopes": [],
            "created_ms": 1,
            "last_used_ms": null,
            "revoked": false,
            "env": "live"
        }))
        .unwrap();

        assert_eq!(stored.version, 0);
        assert!(!stored.require_idempotency);
    }

    #[test]
    fn put_response_requires_committed_success_envelope() {
        let applied = json!({
            "committed": true,
            "result": { "output": { "ok": true, "revision": 9 } }
        });
        assert_eq!(parse_put_response(&applied).unwrap(), CasOutcome::Applied);

        let mismatch = json!({
            "committed": true,
            "result": { "output": {
                "ok": false,
                "reason": "cas_mismatch",
                "current_revision": 8,
                "revision": 9
            } }
        });
        assert_eq!(parse_put_response(&mismatch).unwrap(), CasOutcome::Mismatch);

        for invalid in [
            json!({ "committed": false, "result": { "output": { "ok": true, "revision": 1 } } }),
            json!({ "committed": true, "result": { "output": { "ok": true } } }),
            json!({ "committed": true, "result": { "output": { "ok": false, "reason": "cas_mismatch" } } }),
            json!({ "committed": true, "result": { "output": { "ok": false, "reason": "unknown" } } }),
        ] {
            assert!(parse_put_response(&invalid).is_err());
        }
    }
}
