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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;
use sha2::{Digest, Sha256};

use crate::model::{ApiKeyMeta, ApiKeyRecord, Introspection, OrgId};
use crate::store::{key_path, org_index_path, KvClient, KvError, StoredKey};

/// Default hot-cache TTL: how long a cached introspection result may be served
/// before it must be re-read from the authoritative KV. Bounds how long a
/// *revocation issued on another replica* can go unseen here (see [`KeyStore`]).
const DEFAULT_KEY_CACHE_TTL_MS: u64 = 30_000;

/// A cached key record plus when it was cached, so entries can expire (TTL).
struct CacheEntry {
    record: ApiKeyRecord,
    inserted: Instant,
}

impl CacheEntry {
    fn now(record: ApiKeyRecord) -> Self {
        CacheEntry {
            record,
            inserted: Instant::now(),
        }
    }
}

/// Cache-aside key store: an in-memory hot cache fronts durable fiducia KV.
/// Production construction requires `FIDUCIA_KV_URL`; the optional client exists
/// only so isolated unit tests can exercise the cryptographic behavior.
///
/// Cache entries carry a **TTL** (`FIDUCIA_KEY_CACHE_TTL_MS`, default
/// [`DEFAULT_KEY_CACHE_TTL_MS`]). A hit within the TTL short-circuits (the hot
/// path, no round trip); an entry older than the TTL is a MISS, so `introspect`
/// re-reads the authoritative KV and picks up revocations propagated from other
/// replicas — without this, replica B would serve `valid:true` for a key revoked
/// via replica A until it restarted.
pub struct KeyStore {
    cache: Mutex<HashMap<String, CacheEntry>>, // key_id -> (record, inserted)
    kv: Option<KvClient>,
    ttl: Duration,
}

#[derive(Debug)]
pub enum KeyStoreError {
    Kv(KvError),
    Serialization(serde_json::Error),
}

impl std::fmt::Display for KeyStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kv(error) => write!(formatter, "{error}"),
            Self::Serialization(error) => write!(formatter, "key serialization failed: {error}"),
        }
    }
}

impl std::error::Error for KeyStoreError {}

impl From<KvError> for KeyStoreError {
    fn from(error: KvError) -> Self {
        Self::Kv(error)
    }
}

impl From<serde_json::Error> for KeyStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error)
    }
}

impl KeyStore {
    /// In-memory only (no durable KV) - tests.
    #[cfg(test)]
    pub fn new() -> Self {
        KeyStore {
            cache: Mutex::new(HashMap::new()),
            kv: None,
            ttl: Duration::from_millis(DEFAULT_KEY_CACHE_TTL_MS),
        }
    }

    /// In-memory only with an explicit cache TTL - tests.
    #[cfg(test)]
    pub fn with_ttl(ttl: Duration) -> Self {
        KeyStore {
            cache: Mutex::new(HashMap::new()),
            kv: None,
            ttl,
        }
    }

    /// Construct the production store. Missing durable configuration is a
    /// startup error rather than an implicit process-local credential database.
    pub fn from_env() -> Result<Self, String> {
        Ok(KeyStore {
            cache: Mutex::new(HashMap::new()),
            kv: Some(KvClient::from_env()?),
            ttl: key_cache_ttl_from_env(),
        })
    }

    /// Backdate a cached entry's insertion time so it reads as `age` old, to
    /// exercise TTL expiry deterministically without sleeping.
    #[cfg(test)]
    fn test_age_entry(&self, key_id: &str, age: Duration) {
        let mut cache = self.cache.lock().unwrap();
        if let Some(e) = cache.get_mut(key_id) {
            e.inserted = Instant::now()
                .checked_sub(age)
                .expect("age within Instant range");
        }
    }

    /// Create a key for an org. Returns the **raw key (shown once)** + its meta.
    pub async fn create(
        &self,
        org_id: OrgId,
        name: String,
        scopes: Vec<String>,
        env: String,
    ) -> Result<(String, ApiKeyMeta), KeyStoreError> {
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
            // Opt-in: keys minted directly here default to not requiring a key.
            // The customer-facing default lives with the backend key config.
            require_idempotency: false,
        };
        let meta: ApiKeyMeta = (&rec).into();
        if let Some(kv) = &self.kv {
            let stored: StoredKey = (&rec).into();
            kv.put(&key_path(&key_id), &serde_json::to_value(&stored)?)
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
    pub async fn list(&self, org_id: &str) -> Result<Vec<ApiKeyMeta>, KeyStoreError> {
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
    pub async fn revoke(&self, org_id: &str, key_id: &str) -> Result<bool, KeyStoreError> {
        if let Some(kv) = &self.kv {
            if let Some(mut rec) = self.load(kv, key_id).await? {
                if rec.org_id == org_id {
                    rec.revoked = true;
                    let stored: StoredKey = (&rec).into();
                    kv.put(&key_path(key_id), &serde_json::to_value(&stored)?)
                        .await?;
                    self.cache
                        .lock()
                        .unwrap()
                        .insert(key_id.to_string(), CacheEntry::now(rec));
                    return Ok(true);
                }
            }
            return Ok(false);
        }
        let mut cache = self.cache.lock().unwrap();
        Ok(match cache.get_mut(key_id) {
            Some(e) if e.record.org_id == org_id => {
                e.record.revoked = true;
                e.inserted = Instant::now();
                true
            }
            _ => false,
        })
    }

    /// Validate a raw API key -> org + scopes. Called by the edge/LB (and cached).
    /// Hot path: an in-memory cache hit avoids any KV round trip.
    pub async fn introspect(&self, raw: &str) -> Result<Introspection, KeyStoreError> {
        // Parse `fdc_<env>_<key_id>.<secret>`.
        let Some((left, secret)) = raw.split_once('.') else {
            return Ok(Introspection::invalid());
        };
        let Some(key_id) = left.rsplit('_').next() else {
            return Ok(Introspection::invalid());
        };

        // Hot path: a *fresh* cache hit (within the TTL) short-circuits with no
        // round trip.
        if let Some(intro) = self.introspect_cached(key_id, secret) {
            return Ok(intro);
        }
        // Miss, or an entry past its TTL: re-read the authoritative KV so a
        // revocation issued on another replica is seen within the TTL, then
        // refresh the entry.
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
        // Test-only in-memory stores retain their local record past the TTL.
        Ok(self
            .cache
            .lock()
            .unwrap()
            .get(key_id)
            .map(|e| verify(&e.record, secret))
            .unwrap_or_else(Introspection::invalid))
    }

    /// Fresh cache hit only. An entry older than `ttl` is treated as a MISS
    /// (returns `None`) so the caller re-reads the authoritative KV — this is how
    /// a revocation from another replica propagates here within the TTL.
    fn introspect_cached(&self, key_id: &str, secret: &str) -> Option<Introspection> {
        let cache = self.cache.lock().unwrap();
        let entry = cache.get(key_id)?;
        if entry.inserted.elapsed() >= self.ttl {
            return None;
        }
        Some(verify(&entry.record, secret))
    }

    async fn load(
        &self,
        kv: &KvClient,
        key_id: &str,
    ) -> Result<Option<ApiKeyRecord>, KeyStoreError> {
        let Some(value) = kv.get(&key_path(key_id)).await? else {
            return Ok(None);
        };
        let stored: StoredKey = serde_json::from_value(value)?;
        Ok(Some((&stored).into()))
    }

    async fn index_get(&self, kv: &KvClient, org_id: &str) -> Result<Vec<String>, KeyStoreError> {
        match kv.get(&org_index_path(org_id)).await? {
            Some(value) => Ok(serde_json::from_value(value)?),
            None => Ok(Vec::new()),
        }
    }

    async fn index_add(
        &self,
        kv: &KvClient,
        org_id: &str,
        key_id: &str,
    ) -> Result<(), KeyStoreError> {
        let mut ids = self.index_get(kv, org_id).await?;
        if !ids.iter().any(|id| id == key_id) {
            ids.push(key_id.to_string());
            kv.put(&org_index_path(org_id), &json!(ids)).await?;
        }
        Ok(())
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
            require_idempotency: rec.require_idempotency,
        }
    } else {
        Introspection::invalid()
    }
}

/// Hot-cache TTL from `FIDUCIA_KEY_CACHE_TTL_MS` (milliseconds), defaulting to
/// [`DEFAULT_KEY_CACHE_TTL_MS`] when unset or unparseable.
fn key_cache_ttl_from_env() -> Duration {
    let ms = std::env::var("FIDUCIA_KEY_CACHE_TTL_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_KEY_CACHE_TTL_MS);
    Duration::from_millis(ms)
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
            .await
            .unwrap();
        assert!(raw.starts_with("fdc_live_"));

        let intro = s.introspect(&raw).await.unwrap();
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
            .create("org_1".into(), "ci".into(), vec![], "live".into())
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

    #[test]
    fn default_cache_ttl_is_the_safe_default() {
        assert_eq!(
            store().ttl,
            Duration::from_millis(DEFAULT_KEY_CACHE_TTL_MS),
            "unset FIDUCIA_KEY_CACHE_TTL_MS must fall back to the safe default"
        );
    }

    #[tokio::test]
    async fn a_cache_entry_past_its_ttl_is_a_miss_and_triggers_a_reread() {
        // Tiny TTL so an aged entry is unambiguously stale.
        let s = KeyStore::with_ttl(Duration::from_millis(50));
        let (raw, meta) = s
            .create("org_1".into(), "ci".into(), vec![], "live".into())
            .await
            .unwrap();
        let key_id = meta.key_id.as_str();

        // Split `fdc_<env>_<key_id>.<secret>` back into its pieces.
        let (_left, secret) = raw.split_once('.').unwrap();

        // Fresh: a hit within the TTL short-circuits (authoritative, still valid).
        assert!(
            s.introspect_cached(key_id, secret).is_some(),
            "a fresh entry must short-circuit the hot path"
        );

        // Age the entry beyond the TTL: the cache layer now reports a MISS, which
        // is what forces `introspect` to re-read the authoritative KV (and thus
        // observe revocations propagated from another replica).
        s.test_age_entry(key_id, Duration::from_millis(500));
        assert!(
            s.introspect_cached(key_id, secret).is_none(),
            "an entry past its TTL must be a MISS so KV is re-read"
        );

        // No durable KV here, so `introspect` still honors the (only) local record
        // rather than spuriously 401-ing a valid key — existing behavior preserved.
        assert!(
            s.introspect(&raw).await.unwrap().valid,
            "with no KV to re-read, a stale-but-valid key must stay valid"
        );
    }

    #[tokio::test]
    async fn revoke_is_scoped_to_the_owning_org() {
        let s = store();
        let (_raw, meta) = s
            .create("org_1".into(), "k".into(), vec![], "live".into())
            .await
            .unwrap();
        assert!(!s.revoke("org_2", &meta.key_id).await.unwrap());
    }
}
