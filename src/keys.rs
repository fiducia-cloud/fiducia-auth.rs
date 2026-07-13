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
}

impl KeyStore {
    /// In-memory only (no durable KV) - tests.
    #[cfg(test)]
    pub fn new() -> Self {
        KeyStore {
            cache: Mutex::new(HashMap::new()),
            kv: None,
        }
    }

    /// Construct the production store. Durable KV is mandatory.
    pub fn from_env() -> Result<Self, StoreError> {
        Ok(KeyStore {
            cache: Mutex::new(HashMap::new()),
            kv: Some(KvClient::from_env()?),
        })
    }

    /// Create a key for an org. Returns the **raw key (shown once)** + its meta.
    pub async fn create(
        &self,
        org_id: OrgId,
        name: String,
        scopes: Vec<String>,
        env: String,
        require_idempotency: bool,
    ) -> Result<(String, ApiKeyMeta), StoreError> {
        let key_id = gen_id();
        let secret = gen_secret();
        let raw = format!("fdc_{env}_{key_id}.{secret}");
        let rec = ApiKeyRecord {
            key_id: key_id.clone(),
            org_id: org_id.clone(),
            name,
            secret_hash: hash_secret(&secret),
            scopes,
            created_ms: now_ms(),
            last_used_ms: None,
            revoked: false,
            version: 1,
            env,
            require_idempotency,
        };
        let meta: ApiKeyMeta = (&rec).into();
        if let Some(kv) = &self.kv {
            let stored: StoredKey = (&rec).into();
            kv.put(
                &key_path(&key_id),
                &serde_json::to_value(&stored).map_err(|_| StoreError::InvalidValue)?,
            )
            .await?;
            self.index_add(kv, &org_id, &key_id).await?;
        }
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
        org_id: &str,
        key_id: &str,
    ) -> Result<Option<(String, ApiKeyMeta)>, StoreError> {
        if let Some(kv) = &self.kv {
            for _ in 0..MAX_CAS_RETRIES {
                let Some((mut rec, mod_revision)) = self.load_versioned(kv, key_id).await? else {
                    return Ok(None);
                };
                if rec.org_id != org_id {
                    return Ok(None);
                }
                if rec.revoked {
                    return Ok(None);
                }
                let secret = gen_secret();
                rec.secret_hash = hash_secret(&secret);
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
            .filter(|entry| entry.record.org_id == org_id && !entry.record.revoked)
        else {
            return Ok(None);
        };
        let secret = gen_secret();
        entry.record.secret_hash = hash_secret(&secret);
        entry.record.version = next_version(entry.record.version)?;
        let raw = format!("fdc_{}_{}.{secret}", entry.record.env, entry.record.key_id);
        Ok(Some((raw, (&entry.record).into())))
    }

    /// Validate a raw API key -> org + scopes. Production reads authoritative KV
    /// on every call so another auth replica's rotation/revocation is visible.
    pub async fn introspect(&self, raw: &str) -> Result<Introspection, StoreError> {
        // Parse `fdc_<env>_<key_id>.<secret>`.
        let Some((left, secret)) = raw.split_once('.') else {
            return Ok(Introspection::invalid());
        };
        let Some(key_id) = left.rsplit('_').next() else {
            return Ok(Introspection::invalid());
        };

        // Production never accepts a local cache hit without checking durable
        // state. This prevents per-replica stale acceptance after rotation.
        if let Some(kv) = &self.kv {
            if let Some(rec) = self.load(kv, key_id).await? {
                let intro = verify(&rec, secret);
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
            .map(|e| verify(&e.record, secret))
            .unwrap_or_else(Introspection::invalid))
    }

    async fn load(&self, kv: &KvClient, key_id: &str) -> Result<Option<ApiKeyRecord>, StoreError> {
        let Some(value) = kv.get(&key_path(key_id)).await? else {
            return Ok(None);
        };
        let stored: StoredKey =
            serde_json::from_value(value).map_err(|_| StoreError::InvalidValue)?;
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
}

fn next_version(version: u64) -> Result<u64, StoreError> {
    version.checked_add(1).ok_or(StoreError::VersionOverflow)
}

/// Read-only check of a record against a presented secret (constant-time).
fn verify(rec: &ApiKeyRecord, secret: &str) -> Introspection {
    if !rec.revoked && constant_time_eq(&rec.secret_hash, &hash_secret(secret)) {
        Introspection {
            valid: true,
            org_id: Some(rec.org_id.clone()),
            key_id: Some(rec.key_id.clone()),
            scopes: rec.scopes.clone(),
            require_idempotency: rec.require_idempotency,
        }
    } else {
        Introspection::invalid()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// `n` cryptographically-random bytes from the OS CSPRNG, lower-hex encoded.
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
fn gen_id() -> String {
    random_hex(8)
}

/// The secret half of an API key: 256 bits of CSPRNG entropy.
fn gen_secret() -> String {
    random_hex(32)
}

/// SHA-256 of the secret half (hex). The raw secret is never stored.
fn hash_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    format!("sha256:{}", to_hex(&digest))
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
    use axum::{extract::State, routing::get, Json, Router};
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

    fn store() -> KeyStore {
        KeyStore::new()
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
    fn hash_is_sha256_and_hides_the_secret() {
        let h = hash_secret("super-secret");
        assert!(h.starts_with("sha256:"));
        assert!(!h.contains("super-secret"));
        assert_eq!(h, hash_secret("super-secret"));
        assert_ne!(h, hash_secret("super-secreu"));
    }

    #[tokio::test]
    async fn introspect_round_trips_a_created_key() {
        let s = store();
        let (raw, meta) = s
            .create(
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
        assert_eq!(meta.version, 1);
        assert!(meta.require_idempotency);
    }

    #[tokio::test]
    async fn introspection_is_wire_compatible_with_the_shared_interface() {
        let s = store();
        let (raw, _) = s
            .create(
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
    async fn introspect_rejects_tampered_secret_and_revoked_keys() {
        let s = store();
        let (raw, meta) = s
            .create("org_1".into(), "ci".into(), vec![], "live".into(), true)
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
    async fn revoke_is_scoped_to_the_owning_org() {
        let s = store();
        let (_raw, meta) = s
            .create("org_1".into(), "k".into(), vec![], "live".into(), true)
            .await
            .unwrap();
        assert!(!s.revoke("org_2", &meta.key_id).await.unwrap());
    }

    #[tokio::test]
    async fn rotate_replaces_secret_increments_version_and_preserves_policy() {
        let s = store();
        let (old_raw, created) = s
            .create(
                "org_1".into(),
                "worker".into(),
                vec!["requests:write".into()],
                "test".into(),
                true,
            )
            .await
            .unwrap();

        let (new_raw, rotated) = s
            .rotate("org_1", &created.key_id)
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
    }

    #[tokio::test]
    async fn revoke_versions_only_the_first_state_transition() {
        let s = store();
        let (_raw, created) = s
            .create(
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
            .create("org_1".into(), "worker".into(), vec![], "live".into(), true)
            .await
            .unwrap();

        assert!(s.rotate("org_2", &created.key_id).await.unwrap().is_none());
        let unchanged = s.list("org_1").await.unwrap().pop().unwrap();
        assert_eq!(unchanged.version, created.version);
    }

    #[tokio::test]
    async fn revoked_key_cannot_be_rotated() {
        let s = store();
        let (_raw, created) = s
            .create("org_1".into(), "worker".into(), vec![], "live".into(), true)
            .await
            .unwrap();
        assert!(s.revoke("org_1", &created.key_id).await.unwrap());
        assert!(s.rotate("org_1", &created.key_id).await.unwrap().is_none());
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
