//! API keys + introspection - the **data** plane.
//!
//! B2B *machines* authenticate to the coordination API with a static API key
//! (`Authorization: Bearer fdc_live_<id>.<secret>`). We store only a **hash** of
//! the secret; a raw key is shown to the user only in the creation or rotation
//! response that minted it.
//!
//! Durable records live in fiducia's own KV (see `store.rs`). Production
//! introspection reads that authority on every request so rotation/revocation is
//! immediately visible across auth replicas; test-only in-memory stores use the
//! local map.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::model::{ApiKeyMeta, ApiKeyRecord, Introspection, OrgId};
use crate::store::{
    key_path, org_index_path, CasOutcome, KvClient, StoreError, StoredKey, VersionedValue,
};

/// Retrying a CAS is safe because every attempt re-reads and merges the latest
/// authoritative value. Bound it so sustained contention fails closed instead
/// of hanging a request indefinitely.
const MAX_CAS_RETRIES: usize = 8;
#[cfg(test)]
const TEST_API_KEY_PEPPER: &[u8] = b"fiducia-auth-test-api-key-pepper";

struct CacheEntry {
    record: ApiKeyRecord,
}

impl CacheEntry {
    fn now(record: ApiKeyRecord) -> Self {
        CacheEntry { record }
    }
}

/// Durable KV is the production introspection authority. The local map supports
/// lifecycle response caching and the in-memory test store, but never bypasses
/// a production KV read during credential verification.
pub struct KeyStore {
    cache: Mutex<HashMap<String, CacheEntry>>,
    kv: Option<KvClient>,
    idempotency_secret: Vec<u8>,
    api_key_pepper: Vec<u8>,
    allow_legacy_sha256: bool,
}

#[derive(Clone, Copy)]
pub struct MutationIdentity<'a> {
    pub actor_id: &'a str,
    pub idempotency_key: &'a str,
}

impl<'a> MutationIdentity<'a> {
    pub fn new(actor_id: &'a str, idempotency_key: &'a str) -> Self {
        Self {
            actor_id,
            idempotency_key,
        }
    }
}

impl KeyStore {
    /// In-memory only (no durable KV) - tests.
    #[cfg(test)]
    pub fn new() -> Self {
        KeyStore {
            cache: Mutex::new(HashMap::new()),
            kv: None,
            idempotency_secret: b"fiducia-auth-test-idempotency-secret".to_vec(),
            api_key_pepper: TEST_API_KEY_PEPPER.to_vec(),
            allow_legacy_sha256: false,
        }
    }

    /// Construct the production store. Durable KV is mandatory.
    pub fn from_env() -> Result<Self, StoreError> {
        let idempotency_secret = validated_idempotency_secret(
            std::env::var("FIDUCIA_KEY_IDEMPOTENCY_SECRET")
                .ok()
                .as_deref(),
        )?;
        let api_key_pepper =
            validated_api_key_pepper(std::env::var("CUSTOMER_API_KEY_PEPPER").ok().as_deref())?;
        let hash_algorithm = std::env::var("CUSTOMER_API_KEY_HASH_ALGORITHM")
            .unwrap_or_else(|_| "hmac-sha256".to_string());
        if hash_algorithm.trim() != "hmac-sha256" {
            return Err(StoreError::UnsupportedApiKeyHashAlgorithm);
        }
        let allow_legacy_sha256 = matches!(
            std::env::var("CUSTOMER_API_KEY_ACCEPT_LEGACY_SHA256")
                .ok()
                .as_deref()
                .map(str::trim),
            Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
        );
        Ok(KeyStore {
            cache: Mutex::new(HashMap::new()),
            kv: Some(KvClient::from_env()?),
            idempotency_secret,
            api_key_pepper,
            allow_legacy_sha256,
        })
    }

    /// Create a key for an org. Returns the raw key to the original request and
    /// exact idempotent retries, without persisting the raw value.
    pub async fn create(
        &self,
        mutation: MutationIdentity<'_>,
        org_id: OrgId,
        name: String,
        scopes: Vec<String>,
        env: String,
        require_idempotency: bool,
    ) -> Result<(String, ApiKeyMeta), StoreError> {
        let MutationIdentity {
            actor_id,
            idempotency_key,
        } = mutation;
        let create_idempotency_hash =
            self.derive_idempotency("create-marker", &[actor_id, &org_id, idempotency_key]);
        let key_id = self
            .derive_idempotency("create-key-id", &[actor_id, &org_id, idempotency_key])[..16]
            .to_string();
        let secret =
            self.derive_idempotency("create-secret", &[actor_id, &org_id, idempotency_key]);
        let raw = format!("fdc_{env}_{key_id}.{secret}");
        let rec = ApiKeyRecord {
            key_id: key_id.clone(),
            org_id: org_id.clone(),
            name,
            secret_hash: hash_secret(&secret, &self.api_key_pepper),
            create_idempotency_hash,
            last_rotation_idempotency_hash: None,
            scopes,
            created_ms: now_ms(),
            last_used_ms: None,
            revoked: false,
            version: 1,
            env,
            require_idempotency,
        };
        if let Some(kv) = &self.kv {
            let stored: StoredKey = (&rec).into();
            let value = serde_json::to_value(&stored).map_err(|_| StoreError::InvalidValue)?;
            if kv.put_if_revision(&key_path(&key_id), &value, 0).await? == CasOutcome::Mismatch {
                let Some(existing) = self.load(kv, &key_id).await? else {
                    return Err(StoreError::KeyIdCollision);
                };
                if !same_create_request(&existing, &rec) {
                    return Err(StoreError::IdempotencyConflict);
                }
                self.index_add(kv, &org_id, &key_id).await?;
                let meta: ApiKeyMeta = (&existing).into();
                self.cache
                    .lock()
                    .unwrap()
                    .insert(key_id, CacheEntry::now(existing));
                return Ok((raw, meta));
            }
            // The org index is part of the credential's committed identity.
            // Introspection requires this membership, so a failure here leaves
            // the just-written record unusable. Retrying the same idempotency
            // key repairs the index and replays the same one-time secret.
            self.index_add(kv, &org_id, &key_id).await?;
        } else {
            let cache = self.cache.lock().unwrap();
            if let Some(existing) = cache.get(&key_id).map(|entry| &entry.record) {
                if !same_create_request(existing, &rec) {
                    return Err(StoreError::IdempotencyConflict);
                }
                return Ok((raw, existing.into()));
            }
        }
        let meta: ApiKeyMeta = (&rec).into();
        self.cache
            .lock()
            .unwrap()
            .insert(key_id, CacheEntry::now(rec));
        Ok((raw, meta))
    }

    /// List an org's keys (masked - never returns secrets).
    pub async fn list(&self, org_id: &str) -> Result<Vec<ApiKeyMeta>, StoreError> {
        if let Some(kv) = &self.kv {
            let mut out = Vec::new();
            for id in self.index_get(kv, org_id).await? {
                if let Some(rec) = self.load(kv, &id).await? {
                    if rec.org_id == org_id {
                        out.push((&rec).into());
                    }
                }
            }
            return Ok(out);
        }
        Ok(self
            .cache
            .lock()
            .unwrap()
            .values()
            .map(|e| &e.record)
            .filter(|r| r.org_id == org_id)
            .map(ApiKeyMeta::from)
            .collect())
    }

    /// Revoke a key (must belong to the caller's org). Returns whether it matched.
    pub async fn revoke(&self, org_id: &str, key_id: &str) -> Result<bool, StoreError> {
        if let Some(kv) = &self.kv {
            for _ in 0..MAX_CAS_RETRIES {
                let Some((mut rec, mod_revision)) = self.load_versioned(kv, key_id).await? else {
                    return Ok(false);
                };
                if rec.org_id != org_id {
                    return Ok(false);
                }
                if rec.revoked {
                    self.cache
                        .lock()
                        .unwrap()
                        .insert(key_id.to_string(), CacheEntry::now(rec));
                    return Ok(true);
                }
                rec.revoked = true;
                rec.version = next_version(rec.version)?;
                let stored: StoredKey = (&rec).into();
                let value = serde_json::to_value(&stored).map_err(|_| StoreError::InvalidValue)?;
                match kv
                    .put_if_revision(&key_path(key_id), &value, mod_revision)
                    .await?
                {
                    CasOutcome::Applied => {
                        self.cache
                            .lock()
                            .unwrap()
                            .insert(key_id.to_string(), CacheEntry::now(rec));
                        return Ok(true);
                    }
                    CasOutcome::Mismatch => continue,
                }
            }
            return Err(StoreError::CasRetriesExhausted);
        }
        let mut cache = self.cache.lock().unwrap();
        match cache.get_mut(key_id) {
            Some(e) if e.record.org_id == org_id => {
                if !e.record.revoked {
                    e.record.revoked = true;
                    e.record.version = next_version(e.record.version)?;
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Replace a key's secret without any overlap. Returns the raw replacement
    /// exactly once plus the updated public metadata.
    pub async fn rotate(
        &self,
        actor_id: &str,
        idempotency_key: &str,
        org_id: &str,
        key_id: &str,
    ) -> Result<Option<(String, ApiKeyMeta)>, StoreError> {
        let rotation_idempotency_hash = self.derive_idempotency(
            "rotate-marker",
            &[actor_id, org_id, key_id, idempotency_key],
        );
        let secret = self.derive_idempotency(
            "rotate-secret",
            &[actor_id, org_id, key_id, idempotency_key],
        );
        let secret_hash = hash_secret(&secret, &self.api_key_pepper);
        if let Some(kv) = &self.kv {
            for _ in 0..MAX_CAS_RETRIES {
                let Some((mut rec, mod_revision)) = self.load_versioned(kv, key_id).await? else {
                    return Ok(None);
                };
                if rec.org_id != org_id {
                    return Ok(None);
                }
                if rec.last_rotation_idempotency_hash.as_deref()
                    == Some(rotation_idempotency_hash.as_str())
                {
                    if rec.secret_hash != secret_hash {
                        return Err(StoreError::InvalidValue);
                    }
                    let raw = format!("fdc_{}_{}.{secret}", rec.env, rec.key_id);
                    return Ok(Some((raw, (&rec).into())));
                }
                if rec.revoked {
                    return Ok(None);
                }
                rec.secret_hash = secret_hash.clone();
                rec.last_rotation_idempotency_hash = Some(rotation_idempotency_hash.clone());
                rec.version = next_version(rec.version)?;
                let raw = format!("fdc_{}_{}.{secret}", rec.env, rec.key_id);
                let meta: ApiKeyMeta = (&rec).into();
                let stored: StoredKey = (&rec).into();
                let value = serde_json::to_value(&stored).map_err(|_| StoreError::InvalidValue)?;
                match kv
                    .put_if_revision(&key_path(key_id), &value, mod_revision)
                    .await?
                {
                    CasOutcome::Applied => {
                        self.cache
                            .lock()
                            .unwrap()
                            .insert(key_id.to_string(), CacheEntry::now(rec));
                        return Ok(Some((raw, meta)));
                    }
                    CasOutcome::Mismatch => continue,
                }
            }
            return Err(StoreError::CasRetriesExhausted);
        }

        let mut cache = self.cache.lock().unwrap();
        let Some(entry) = cache
            .get_mut(key_id)
            .filter(|entry| entry.record.org_id == org_id)
        else {
            return Ok(None);
        };
        if entry.record.last_rotation_idempotency_hash.as_deref()
            == Some(rotation_idempotency_hash.as_str())
        {
            if entry.record.secret_hash != secret_hash {
                return Err(StoreError::InvalidValue);
            }
            let raw = format!("fdc_{}_{}.{secret}", entry.record.env, entry.record.key_id);
            return Ok(Some((raw, (&entry.record).into())));
        }
        if entry.record.revoked {
            return Ok(None);
        }
        entry.record.secret_hash = secret_hash;
        entry.record.last_rotation_idempotency_hash = Some(rotation_idempotency_hash);
        entry.record.version = next_version(entry.record.version)?;
        let raw = format!("fdc_{}_{}.{secret}", entry.record.env, entry.record.key_id);
        Ok(Some((raw, (&entry.record).into())))
    }

    /// Validate a raw API key -> org + scopes. Production reads authoritative KV
    /// on every call so another auth replica's rotation/revocation is visible.
    pub async fn introspect(&self, raw: &str) -> Result<Introspection, StoreError> {
        let Some((env, key_id, secret)) = parse_raw_key(raw) else {
            return Ok(Introspection::invalid());
        };

        // Production never accepts a local cache hit without checking durable
        // state. This prevents per-replica stale acceptance after rotation.
        if let Some(kv) = &self.kv {
            if let Some(rec) = self.load(kv, key_id).await? {
                // Fail closed if create persisted the record but could not
                // commit its org index. This prevents a valid-but-unlisted
                // credential after a partial multi-key KV write.
                let indexed = self
                    .index_get(kv, &rec.org_id)
                    .await?
                    .iter()
                    .any(|indexed_id| indexed_id == key_id);
                let intro = if indexed {
                    verify(
                        &rec,
                        env,
                        secret,
                        &self.api_key_pepper,
                        self.allow_legacy_sha256,
                    )
                } else {
                    Introspection::invalid()
                };
                self.cache
                    .lock()
                    .unwrap()
                    .insert(key_id.to_string(), CacheEntry::now(rec));
                return Ok(intro);
            }
            return Ok(Introspection::invalid());
        }
        // Test-only stores have no KV and use their local map as the source.
        Ok(self
            .cache
            .lock()
            .unwrap()
            .get(key_id)
            .map(|e| {
                verify(
                    &e.record,
                    env,
                    secret,
                    &self.api_key_pepper,
                    self.allow_legacy_sha256,
                )
            })
            .unwrap_or_else(Introspection::invalid))
    }

    async fn load(&self, kv: &KvClient, key_id: &str) -> Result<Option<ApiKeyRecord>, StoreError> {
        let Some(value) = kv.get(&key_path(key_id)).await? else {
            return Ok(None);
        };
        let stored: StoredKey =
            serde_json::from_value(value).map_err(|_| StoreError::InvalidValue)?;
        if stored.key_id != key_id {
            return Err(StoreError::InvalidValue);
        }
        Ok(Some((&stored).into()))
    }

    async fn load_versioned(
        &self,
        kv: &KvClient,
        key_id: &str,
    ) -> Result<Option<(ApiKeyRecord, u64)>, StoreError> {
        let Some(VersionedValue {
            value,
            mod_revision,
        }) = kv.get_versioned(&key_path(key_id)).await?
        else {
            return Ok(None);
        };
        let stored: StoredKey =
            serde_json::from_value(value).map_err(|_| StoreError::InvalidValue)?;
        if stored.key_id != key_id {
            return Err(StoreError::InvalidValue);
        }
        Ok(Some(((&stored).into(), mod_revision)))
    }

    async fn index_get(&self, kv: &KvClient, org_id: &str) -> Result<Vec<String>, StoreError> {
        match kv.get(&org_index_path(org_id)).await? {
            Some(value) => serde_json::from_value(value).map_err(|_| StoreError::InvalidValue),
            None => Ok(Vec::new()),
        }
    }

    async fn index_add(&self, kv: &KvClient, org_id: &str, key_id: &str) -> Result<(), StoreError> {
        let path = org_index_path(org_id);
        for _ in 0..MAX_CAS_RETRIES {
            let (mut ids, mod_revision) = match kv.get_versioned(&path).await? {
                Some(entry) => (
                    serde_json::from_value(entry.value).map_err(|_| StoreError::InvalidValue)?,
                    entry.mod_revision,
                ),
                None => (Vec::<String>::new(), 0),
            };
            if ids.iter().any(|id| id == key_id) {
                return Ok(());
            }
            ids.push(key_id.to_string());
            match kv.put_if_revision(&path, &json!(ids), mod_revision).await? {
                CasOutcome::Applied => return Ok(()),
                CasOutcome::Mismatch => continue,
            }
        }
        Err(StoreError::CasRetriesExhausted)
    }

    fn derive_idempotency(&self, purpose: &str, parts: &[&str]) -> String {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&self.idempotency_secret)
            .expect("HMAC accepts keys of any length");
        mac.update(purpose.as_bytes());
        for part in parts {
            mac.update(&[0]);
            mac.update(part.as_bytes());
        }
        to_hex(&mac.finalize().into_bytes())
    }
}

fn validated_idempotency_secret(value: Option<&str>) -> Result<Vec<u8>, StoreError> {
    let value = value
        .filter(|candidate| !candidate.is_empty())
        .ok_or(StoreError::MissingIdempotencySecret)?;
    if value.len() < 32 || value.chars().any(char::is_whitespace) {
        return Err(StoreError::WeakIdempotencySecret);
    }
    Ok(value.as_bytes().to_vec())
}

fn validated_api_key_pepper(value: Option<&str>) -> Result<Vec<u8>, StoreError> {
    let value = value
        .filter(|candidate| !candidate.is_empty())
        .ok_or(StoreError::MissingApiKeyPepper)?;
    if value.len() < 32 || value.chars().any(char::is_whitespace) {
        return Err(StoreError::WeakApiKeyPepper);
    }
    Ok(value.as_bytes().to_vec())
}

fn same_create_request(existing: &ApiKeyRecord, requested: &ApiKeyRecord) -> bool {
    existing.create_idempotency_hash == requested.create_idempotency_hash
        && existing.key_id == requested.key_id
        && existing.org_id == requested.org_id
        && existing.name == requested.name
        && existing.scopes == requested.scopes
        && existing.env == requested.env
        && existing.require_idempotency == requested.require_idempotency
        && existing.secret_hash == requested.secret_hash
}

fn next_version(version: u64) -> Result<u64, StoreError> {
    version.checked_add(1).ok_or(StoreError::VersionOverflow)
}

/// Parse the only accepted API-key wire shape without touching durable storage
/// for malformed attacker input.
fn parse_raw_key(raw: &str) -> Option<(&str, &str, &str)> {
    let (left, secret) = raw.split_once('.')?;
    if secret.len() != 64 || !secret.bytes().all(is_lower_hex) {
        return None;
    }
    let rest = left.strip_prefix("fdc_")?;
    let (env, key_id) = rest.split_once('_')?;
    if !matches!(env, "live" | "test") || key_id.len() != 16 || !key_id.bytes().all(is_lower_hex) {
        return None;
    }
    Some((env, key_id, secret))
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

/// Read-only check of a record against a presented secret (constant-time).
fn verify(
    rec: &ApiKeyRecord,
    env: &str,
    secret: &str,
    pepper: &[u8],
    allow_legacy_sha256: bool,
) -> Introspection {
    if !rec.revoked
        && rec.env == env
        && verify_secret_hash(&rec.secret_hash, secret, pepper, allow_legacy_sha256)
    {
        Introspection {
            valid: true,
            org_id: Some(rec.org_id.clone()),
            key_id: Some(rec.key_id.clone()),
            // Defense in depth for durable records minted before customer/admin
            // separation: an API key must never surface operator authority.
            scopes: rec
                .scopes
                .iter()
                .filter(|scope| !is_admin_scope(scope))
                .cloned()
                .collect(),
            require_idempotency: rec.require_idempotency,
        }
    } else {
        Introspection::invalid()
    }
}

fn is_admin_scope(scope: &str) -> bool {
    scope == "admin" || scope.starts_with("admin:")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// `n` cryptographically-random bytes from the OS CSPRNG, lower-hex encoded.
#[cfg(test)]
fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    getrandom::getrandom(&mut buf).expect("OS CSPRNG unavailable");
    to_hex(&buf)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Public, non-secret key identifier (64 random bits -> 16 hex chars).
#[cfg(test)]
fn gen_id() -> String {
    random_hex(8)
}

/// The secret half of an API key: 256 bits of CSPRNG entropy.
#[cfg(test)]
fn gen_secret() -> String {
    random_hex(32)
}

/// Pepper-keyed HMAC of the secret half. The raw secret is never stored.
fn hash_secret(secret: &str, pepper: &[u8]) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(pepper).expect("HMAC accepts keys of any length");
    mac.update(secret.as_bytes());
    format!("hmac-sha256:{}", to_hex(&mac.finalize().into_bytes()))
}

/// Verify both current peppered records and legacy SHA-256 records during the
/// rotation window. Every newly created or rotated key uses HMAC.
fn verify_secret_hash(
    stored: &str,
    secret: &str,
    pepper: &[u8],
    allow_legacy_sha256: bool,
) -> bool {
    let expected = if stored.starts_with("hmac-sha256:") {
        hash_secret(secret, pepper)
    } else if allow_legacy_sha256 && stored.starts_with("sha256:") {
        let digest = Sha256::digest(secret.as_bytes());
        format!("sha256:{}", to_hex(&digest))
    } else {
        return false;
    };
    constant_time_eq(stored, &expected)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::{Query, State},
        http::StatusCode,
        routing::get,
        Json, Router,
    };
    use serde_json::Value;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[derive(Clone, Default)]
    struct IndexCasState {
        reads: Arc<AtomicUsize>,
        writes: Arc<Mutex<Vec<Value>>>,
    }

    async fn mock_index_get(State(state): State<IndexCasState>) -> Json<Value> {
        let read = state.reads.fetch_add(1, Ordering::SeqCst);
        let (ids, mod_revision) = if read == 0 {
            (json!(["existing"]), 7)
        } else {
            (json!(["existing", "concurrent"]), 8)
        };
        Json(json!({
            "found": true,
            "entry": {
                "value": ids.to_string(),
                "mod_revision": mod_revision,
                "expires_at_ms": null
            }
        }))
    }

    async fn mock_index_put(
        State(state): State<IndexCasState>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let attempt = {
            let mut writes = state.writes.lock().unwrap();
            writes.push(body);
            writes.len()
        };
        if attempt == 1 {
            Json(json!({
                "committed": true,
                "result": { "output": {
                    "ok": false,
                    "reason": "cas_mismatch",
                    "current_revision": 8,
                    "revision": 8
                } }
            }))
        } else {
            Json(json!({
                "committed": true,
                "result": { "output": { "ok": true, "revision": 9 } }
            }))
        }
    }

    async fn mock_storage_failure() -> StatusCode {
        StatusCode::SERVICE_UNAVAILABLE
    }

    async fn mock_unindexed_key(
        State(stored): State<StoredKey>,
        Query(query): Query<HashMap<String, String>>,
    ) -> Json<Value> {
        if query.get("key") == Some(&key_path(&stored.key_id)) {
            return Json(json!({
                "found": true,
                "entry": {
                    "value": serde_json::to_string(&stored).unwrap(),
                    "mod_revision": 1,
                    "expires_at_ms": null
                }
            }));
        }
        Json(json!({ "found": false }))
    }

    fn store() -> KeyStore {
        KeyStore::new()
    }

    #[test]
    fn credential_derivation_secret_is_strong_and_unambiguous() {
        assert!(matches!(
            validated_idempotency_secret(None),
            Err(StoreError::MissingIdempotencySecret)
        ));
        assert!(matches!(
            validated_idempotency_secret(Some("too-short")),
            Err(StoreError::WeakIdempotencySecret)
        ));
        assert!(matches!(
            validated_idempotency_secret(Some("0123456789abcdef0123456789abcde ")),
            Err(StoreError::WeakIdempotencySecret)
        ));
        assert_eq!(
            validated_idempotency_secret(Some("0123456789abcdef0123456789abcdef")).unwrap(),
            b"0123456789abcdef0123456789abcdef"
        );
        assert!(matches!(
            validated_api_key_pepper(None),
            Err(StoreError::MissingApiKeyPepper)
        ));
        assert!(matches!(
            validated_api_key_pepper(Some("too-short")),
            Err(StoreError::WeakApiKeyPepper)
        ));
        assert_eq!(
            validated_api_key_pepper(Some("0123456789abcdef0123456789abcdef")).unwrap(),
            b"0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn secrets_are_high_entropy_and_unique() {
        let s = gen_secret();
        assert_eq!(s.len(), 64, "secret must be 32 random bytes");
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(gen_id().len(), 16);

        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(gen_secret()), "duplicate secret from CSPRNG");
        }
    }

    #[test]
    fn hash_is_pepper_keyed_and_legacy_records_remain_verifiable() {
        let h = hash_secret("super-secret", TEST_API_KEY_PEPPER);
        assert!(h.starts_with("hmac-sha256:"));
        assert!(!h.contains("super-secret"));
        assert_eq!(h, hash_secret("super-secret", TEST_API_KEY_PEPPER));
        assert_ne!(h, hash_secret("super-secreu", TEST_API_KEY_PEPPER));
        assert_ne!(
            h,
            hash_secret("super-secret", b"another-valid-test-pepper-0123456789")
        );
        let legacy = format!("sha256:{}", to_hex(&Sha256::digest(b"super-secret")));
        assert!(verify_secret_hash(
            &legacy,
            "super-secret",
            TEST_API_KEY_PEPPER,
            true,
        ));
        assert!(!verify_secret_hash(
            &legacy,
            "wrong-secret",
            TEST_API_KEY_PEPPER,
            true,
        ));
        assert!(!verify_secret_hash(
            &legacy,
            "super-secret",
            TEST_API_KEY_PEPPER,
            false,
        ));
    }

    #[test]
    fn raw_key_parser_accepts_only_the_minted_wire_shape() {
        let key_id = "0123456789abcdef";
        let secret = "a".repeat(64);
        assert_eq!(
            parse_raw_key(&format!("fdc_live_{key_id}.{secret}")),
            Some(("live", key_id, secret.as_str()))
        );
        for invalid in [
            format!("other_live_{key_id}.{secret}"),
            format!("fdc_prod_{key_id}.{secret}"),
            format!("fdc_live_short.{secret}"),
            format!("fdc_live_{key_id}.short"),
            format!("fdc_live_{key_id}.{}", "z".repeat(64)),
            format!("fdc_live_{}.{}", key_id.to_ascii_uppercase(), secret),
            format!("fdc_live_{key_id}.{}", secret.to_ascii_uppercase()),
        ] {
            assert!(parse_raw_key(&invalid).is_none(), "accepted {invalid}");
        }
    }

    #[tokio::test]
    async fn introspect_round_trips_a_created_key() {
        let s = store();
        let (raw, meta) = s
            .create(
                MutationIdentity::new("user_1", "create-1"),
                "org_1".into(),
                "ci".into(),
                vec!["kv:read".into()],
                "live".into(),
                true,
            )
            .await
            .unwrap();
        assert!(raw.starts_with("fdc_live_"));

        let intro = s.introspect(&raw).await.unwrap();
        assert!(intro.valid);
        assert_eq!(intro.org_id.as_deref(), Some("org_1"));
        assert_eq!(intro.key_id.as_deref(), Some(meta.key_id.as_str()));
        assert_eq!(intro.scopes, vec!["kv:read".to_string()]);
        assert!(intro.require_idempotency);
        assert_eq!(meta.version, 1);
        assert!(meta.require_idempotency);
        let wrong_env = raw.replacen("fdc_live_", "fdc_test_", 1);
        assert!(!s.introspect(&wrong_env).await.unwrap().valid);
    }

    #[tokio::test]
    async fn create_replays_the_same_one_time_secret_for_the_same_idempotency_key() {
        let s = store();
        let first = s
            .create(
                MutationIdentity::new("user_1", "create-retry"),
                "org_1".into(),
                "worker".into(),
                vec!["kv:read".into()],
                "live".into(),
                true,
            )
            .await
            .unwrap();
        let replay = s
            .create(
                MutationIdentity::new("user_1", "create-retry"),
                "org_1".into(),
                "worker".into(),
                vec!["kv:read".into()],
                "live".into(),
                true,
            )
            .await
            .unwrap();

        assert_eq!(replay.0, first.0);
        assert_eq!(replay.1.key_id, first.1.key_id);
        assert_eq!(replay.1.version, 1);

        let conflict = s
            .create(
                MutationIdentity::new("user_1", "create-retry"),
                "org_1".into(),
                "changed".into(),
                vec!["kv:read".into()],
                "live".into(),
                true,
            )
            .await;
        assert!(matches!(conflict, Err(StoreError::IdempotencyConflict)));
    }

    #[tokio::test]
    async fn introspection_is_wire_compatible_with_the_shared_interface() {
        let s = store();
        let (raw, _) = s
            .create(
                MutationIdentity::new("user_1", "create-1"),
                "org_1".into(),
                "ci".into(),
                vec!["kv:read".into()],
                "live".into(),
                true,
            )
            .await
            .unwrap();

        for intro in [s.introspect(&raw).await.unwrap(), Introspection::invalid()] {
            let json = serde_json::to_value(&intro).unwrap();
            let shared: fiducia_interfaces::Introspection = serde_json::from_value(json).unwrap();
            assert_eq!(shared.valid, intro.valid);
            assert_eq!(shared.org_id, intro.org_id);
            assert_eq!(shared.key_id, intro.key_id);
            assert_eq!(shared.scopes, intro.scopes);
        }
    }

    #[tokio::test]
    async fn legacy_customer_keys_never_surface_admin_scopes() {
        let s = store();
        let (raw, _) = s
            .create(
                MutationIdentity::new("user_1", "create-1"),
                "org_1".into(),
                "legacy".into(),
                vec!["admin:read".into(), "kv:read".into()],
                "live".into(),
                true,
            )
            .await
            .unwrap();

        let intro = s.introspect(&raw).await.unwrap();
        assert!(intro.valid);
        assert_eq!(intro.scopes, vec!["kv:read"]);
    }

    #[tokio::test]
    async fn introspect_rejects_tampered_secret_and_revoked_keys() {
        let s = store();
        let (raw, meta) = s
            .create(
                MutationIdentity::new("user_1", "create-1"),
                "org_1".into(),
                "ci".into(),
                vec![],
                "live".into(),
                true,
            )
            .await
            .unwrap();

        let mut bad = raw.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'a' { 'b' } else { 'a' });
        assert!(
            !s.introspect(&bad).await.unwrap().valid,
            "tampered secret must be invalid"
        );

        assert!(!s.introspect("not-a-key").await.unwrap().valid);
        assert!(!s.introspect("fdc_live_deadbeef").await.unwrap().valid); // no '.secret'

        assert!(s.revoke("org_1", &meta.key_id).await.unwrap());
        assert!(
            !s.introspect(&raw).await.unwrap().valid,
            "revoked key must be invalid"
        );
    }

    #[tokio::test]
    async fn production_introspection_never_falls_back_to_a_stale_local_record() {
        let app = Router::new().route("/v1/kv", get(mock_storage_failure));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let key_id = "0123456789abcdef";
        let secret = "a".repeat(64);
        let rec = ApiKeyRecord {
            key_id: key_id.to_string(),
            org_id: "org_1".to_string(),
            name: "cached".to_string(),
            secret_hash: hash_secret(&secret, TEST_API_KEY_PEPPER),
            create_idempotency_hash: "test-create".to_string(),
            last_rotation_idempotency_hash: None,
            scopes: vec!["kv:read".to_string()],
            created_ms: 1,
            last_used_ms: None,
            revoked: false,
            version: 1,
            env: "live".to_string(),
            require_idempotency: true,
        };
        let store = KeyStore {
            cache: Mutex::new(HashMap::from([(key_id.to_string(), CacheEntry::now(rec))])),
            kv: Some(KvClient::for_test(format!("http://{address}"))),
            idempotency_secret: b"fiducia-auth-test-idempotency-secret".to_vec(),
            api_key_pepper: TEST_API_KEY_PEPPER.to_vec(),
            allow_legacy_sha256: false,
        };

        let result = store
            .introspect(&format!("fdc_live_{key_id}.{secret}"))
            .await;
        assert!(
            matches!(result, Err(StoreError::Http(status)) if status == StatusCode::SERVICE_UNAVAILABLE)
        );
        server.abort();
    }

    #[tokio::test]
    async fn production_introspection_rejects_a_record_missing_from_its_org_index() {
        let key_id = "0123456789abcdef";
        let secret = "a".repeat(64);
        let stored = StoredKey {
            key_id: key_id.to_string(),
            org_id: "org_1".to_string(),
            name: "unindexed".to_string(),
            secret_hash: hash_secret(&secret, TEST_API_KEY_PEPPER),
            create_idempotency_hash: "create-marker".to_string(),
            last_rotation_idempotency_hash: None,
            scopes: vec!["kv:read".to_string()],
            created_ms: 1,
            last_used_ms: None,
            revoked: false,
            version: 1,
            env: "live".to_string(),
            require_idempotency: true,
        };
        let app = Router::new()
            .route("/v1/kv", get(mock_unindexed_key))
            .with_state(stored);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let store = KeyStore {
            cache: Mutex::new(HashMap::new()),
            kv: Some(KvClient::for_test(format!("http://{address}"))),
            idempotency_secret: b"fiducia-auth-test-idempotency-secret".to_vec(),
            api_key_pepper: TEST_API_KEY_PEPPER.to_vec(),
            allow_legacy_sha256: false,
        };

        let intro = store
            .introspect(&format!("fdc_live_{key_id}.{secret}"))
            .await
            .unwrap();
        assert!(!intro.valid);
        server.abort();
    }

    #[tokio::test]
    async fn revoke_is_scoped_to_the_owning_org() {
        let s = store();
        let (_raw, meta) = s
            .create(
                MutationIdentity::new("user_1", "create-1"),
                "org_1".into(),
                "k".into(),
                vec![],
                "live".into(),
                true,
            )
            .await
            .unwrap();
        assert!(!s.revoke("org_2", &meta.key_id).await.unwrap());
    }

    #[tokio::test]
    async fn rotate_replaces_secret_increments_version_and_preserves_policy() {
        let s = store();
        let (old_raw, created) = s
            .create(
                MutationIdentity::new("user_1", "create-1"),
                "org_1".into(),
                "worker".into(),
                vec!["requests:write".into()],
                "test".into(),
                true,
            )
            .await
            .unwrap();

        let (new_raw, rotated) = s
            .rotate("user_1", "rotate-1", "org_1", &created.key_id)
            .await
            .unwrap()
            .expect("owning org can rotate");

        assert_ne!(new_raw, old_raw);
        assert!(new_raw.starts_with("fdc_test_"));
        assert!(!s.introspect(&old_raw).await.unwrap().valid);
        assert!(s.introspect(&new_raw).await.unwrap().valid);
        assert_eq!(rotated.version, created.version + 1);
        assert!(rotated.require_idempotency);
        assert!(!rotated.revoked);

        let (replayed_raw, replayed) = s
            .rotate("user_1", "rotate-1", "org_1", &created.key_id)
            .await
            .unwrap()
            .expect("the same rotation request replays");
        assert_eq!(replayed_raw, new_raw);
        assert_eq!(replayed.version, rotated.version);

        let (next_raw, next) = s
            .rotate("user_1", "rotate-2", "org_1", &created.key_id)
            .await
            .unwrap()
            .expect("a new idempotency key performs a new rotation");
        assert_ne!(next_raw, new_raw);
        assert_eq!(next.version, rotated.version + 1);
    }

    #[tokio::test]
    async fn revoke_versions_only_the_first_state_transition() {
        let s = store();
        let (_raw, created) = s
            .create(
                MutationIdentity::new("user_1", "create-1"),
                "org_1".into(),
                "worker".into(),
                vec![],
                "live".into(),
                false,
            )
            .await
            .unwrap();

        assert!(s.revoke("org_1", &created.key_id).await.unwrap());
        let once = s.list("org_1").await.unwrap().pop().unwrap();
        assert_eq!(once.version, created.version + 1);
        assert!(once.revoked);
        assert!(!once.require_idempotency);

        assert!(s.revoke("org_1", &created.key_id).await.unwrap());
        let twice = s.list("org_1").await.unwrap().pop().unwrap();
        assert_eq!(twice.version, once.version);
    }

    #[tokio::test]
    async fn rotate_is_scoped_to_the_owning_org() {
        let s = store();
        let (_raw, created) = s
            .create(
                MutationIdentity::new("user_1", "create-1"),
                "org_1".into(),
                "worker".into(),
                vec![],
                "live".into(),
                true,
            )
            .await
            .unwrap();
        assert!(s
            .rotate("user_1", "rotate-1", "org_2", &created.key_id)
            .await
            .unwrap()
            .is_none());
        let unchanged = s.list("org_1").await.unwrap().pop().unwrap();
        assert_eq!(unchanged.version, created.version);
    }

    #[tokio::test]
    async fn revoked_key_cannot_be_rotated() {
        let s = store();
        let (_raw, created) = s
            .create(
                MutationIdentity::new("user_1", "create-1"),
                "org_1".into(),
                "worker".into(),
                vec![],
                "live".into(),
                true,
            )
            .await
            .unwrap();
        assert!(s.revoke("org_1", &created.key_id).await.unwrap());
        assert!(s
            .rotate("user_1", "rotate-1", "org_1", &created.key_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn org_index_cas_retries_and_merges_a_concurrent_insert() {
        let state = IndexCasState::default();
        let app = Router::new()
            .route("/v1/kv", get(mock_index_get).put(mock_index_put))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let kv = KvClient::for_test(format!("http://{address}"));

        store()
            .index_add(&kv, "org_1", "ours")
            .await
            .expect("retry should merge the concurrent index entry");

        let writes = state.writes.lock().unwrap();
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0]["prev_revision"], json!(7));
        assert_eq!(writes[1]["prev_revision"], json!(8));
        let merged: Vec<String> =
            serde_json::from_str(writes[1]["value"].as_str().unwrap()).unwrap();
        assert_eq!(merged, vec!["existing", "concurrent", "ours"]);
        server.abort();
    }
}
