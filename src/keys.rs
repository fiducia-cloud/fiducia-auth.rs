//! API keys + introspection - the **data** plane.
//!
//! B2B *machines* authenticate to the coordination API with a static API key
//! (`Authorization: Bearer fdc_live_<id>.<secret>`). We store only a **hash** of
//! the secret; the raw key is shown to the user exactly once, at creation.
//!
//! Storage is **cache-aside**: durable records live in fiducia's own KV (see
//! `store.rs`) and an in-memory hot cache fronts it, so the steady-state
//! [`introspect`](KeyStore::introspect) - the call the edge/LB make (and cache
//! again, with a short TTL) - is a local map lookup, never a round trip, and
//! never Supabase.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;
use sha2::{Digest, Sha256};

use crate::model::{ApiKeyMeta, ApiKeyRecord, Introspection, OrgId};
use crate::store::{key_path, org_index_path, KvClient, StoredKey};

/// Cache-aside key store: an in-memory hot cache fronts durable fiducia KV. With
/// no `FIDUCIA_KV_URL` configured it is purely in-memory (dev / tests).
pub struct KeyStore {
    cache: Mutex<HashMap<String, ApiKeyRecord>>, // key_id -> record
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

    /// Durable when `FIDUCIA_KV_URL` is set, else in-memory.
    pub fn from_env() -> Self {
        KeyStore {
            cache: Mutex::new(HashMap::new()),
            kv: KvClient::from_env(),
        }
    }

    /// Create a key for an org. Returns the **raw key (shown once)** + its meta.
    pub async fn create(
        &self,
        org_id: OrgId,
        name: String,
        scopes: Vec<String>,
        env: String,
    ) -> (String, ApiKeyMeta) {
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
            env,
        };
        let meta: ApiKeyMeta = (&rec).into();
        if let Some(kv) = &self.kv {
            let stored: StoredKey = (&rec).into();
            kv.put(
                &key_path(&key_id),
                &serde_json::to_value(&stored).unwrap_or_default(),
            )
            .await;
            self.index_add(kv, &org_id, &key_id).await;
        }
        self.cache.lock().unwrap().insert(key_id, rec);
        (raw, meta)
    }

    /// List an org's keys (masked - never returns secrets).
    pub async fn list(&self, org_id: &str) -> Vec<ApiKeyMeta> {
        if let Some(kv) = &self.kv {
            let mut out = Vec::new();
            for id in self.index_get(kv, org_id).await {
                if let Some(rec) = self.load(kv, &id).await {
                    if rec.org_id == org_id {
                        out.push((&rec).into());
                    }
                }
            }
            return out;
        }
        self.cache
            .lock()
            .unwrap()
            .values()
            .filter(|r| r.org_id == org_id)
            .map(ApiKeyMeta::from)
            .collect()
    }

    /// Revoke a key (must belong to the caller's org). Returns whether it matched.
    pub async fn revoke(&self, org_id: &str, key_id: &str) -> bool {
        if let Some(kv) = &self.kv {
            if let Some(mut rec) = self.load(kv, key_id).await {
                if rec.org_id == org_id {
                    rec.revoked = true;
                    let stored: StoredKey = (&rec).into();
                    kv.put(
                        &key_path(key_id),
                        &serde_json::to_value(&stored).unwrap_or_default(),
                    )
                    .await;
                    self.cache.lock().unwrap().insert(key_id.to_string(), rec);
                    return true;
                }
            }
            return false;
        }
        let mut cache = self.cache.lock().unwrap();
        match cache.get_mut(key_id) {
            Some(r) if r.org_id == org_id => {
                r.revoked = true;
                true
            }
            _ => false,
        }
    }

    /// Validate a raw API key -> org + scopes. Called by the edge/LB (and cached).
    /// Hot path: an in-memory cache hit avoids any KV round trip.
    pub async fn introspect(&self, raw: &str) -> Introspection {
        // Parse `fdc_<env>_<key_id>.<secret>`.
        let Some((left, secret)) = raw.split_once('.') else {
            return Introspection::invalid();
        };
        let Some(key_id) = left.rsplit('_').next() else {
            return Introspection::invalid();
        };

        if let Some(intro) = self.introspect_cached(key_id, secret) {
            return intro;
        }
        if let Some(kv) = &self.kv {
            if let Some(rec) = self.load(kv, key_id).await {
                let intro = verify(&rec, secret);
                self.cache.lock().unwrap().insert(key_id.to_string(), rec);
                return intro;
            }
        }
        Introspection::invalid()
    }

    fn introspect_cached(&self, key_id: &str, secret: &str) -> Option<Introspection> {
        self.cache
            .lock()
            .unwrap()
            .get(key_id)
            .map(|rec| verify(rec, secret))
    }

    async fn load(&self, kv: &KvClient, key_id: &str) -> Option<ApiKeyRecord> {
        let stored: StoredKey = serde_json::from_value(kv.get(&key_path(key_id)).await?).ok()?;
        Some((&stored).into())
    }

    async fn index_get(&self, kv: &KvClient, org_id: &str) -> Vec<String> {
        kv.get(&org_index_path(org_id))
            .await
            .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
            .unwrap_or_default()
    }

    async fn index_add(&self, kv: &KvClient, org_id: &str, key_id: &str) {
        let mut ids = self.index_get(kv, org_id).await;
        if !ids.iter().any(|id| id == key_id) {
            ids.push(key_id.to_string());
            kv.put(&org_index_path(org_id), &json!(ids)).await;
        }
    }
}

/// Read-only check of a record against a presented secret (constant-time).
fn verify(rec: &ApiKeyRecord, secret: &str) -> Introspection {
    if !rec.revoked && constant_time_eq(&rec.secret_hash, &hash_secret(secret)) {
        Introspection {
            valid: true,
            org_id: Some(rec.org_id.clone()),
            key_id: Some(rec.key_id.clone()),
            scopes: rec.scopes.clone(),
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
            )
            .await;
        assert!(raw.starts_with("fdc_live_"));

        let intro = s.introspect(&raw).await;
        assert!(intro.valid);
        assert_eq!(intro.org_id.as_deref(), Some("org_1"));
        assert_eq!(intro.key_id.as_deref(), Some(meta.key_id.as_str()));
        assert_eq!(intro.scopes, vec!["kv:read".to_string()]);
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
            )
            .await;

        for intro in [s.introspect(&raw).await, Introspection::invalid()] {
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
            .create("org_1".into(), "ci".into(), vec![], "live".into())
            .await;

        let mut bad = raw.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'a' { 'b' } else { 'a' });
        assert!(
            !s.introspect(&bad).await.valid,
            "tampered secret must be invalid"
        );

        assert!(!s.introspect("not-a-key").await.valid);
        assert!(!s.introspect("fdc_live_deadbeef").await.valid); // no '.secret'

        assert!(s.revoke("org_1", &meta.key_id).await);
        assert!(
            !s.introspect(&raw).await.valid,
            "revoked key must be invalid"
        );
    }

    #[tokio::test]
    async fn revoke_is_scoped_to_the_owning_org() {
        let s = store();
        let (_raw, meta) = s
            .create("org_1".into(), "k".into(), vec![], "live".into())
            .await;
        assert!(!s.revoke("org_2", &meta.key_id).await);
    }
}
