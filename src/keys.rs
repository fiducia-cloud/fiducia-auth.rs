//! API keys + introspection — the **data** plane.
//!
//! B2B *machines* authenticate to the coordination API with a static API key
//! (`Authorization: Bearer fdc_live_<id>.<secret>`). We store only a **hash** of
//! the secret; the raw key is shown to the user exactly once, at creation.
//!
//! [`introspect`](KeyStore::introspect) is the endpoint the edge/LB calls and
//! **caches** (short TTL) so the steady-state hot path makes no auth/DB call.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::{ApiKeyMeta, ApiKeyRecord, Introspection, OrgId};

/// File-backed API key store, keyed by `key_id`.
pub struct KeyStore {
    keys: Mutex<HashMap<String, ApiKeyRecord>>, // key_id -> record
    path: Option<PathBuf>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self::from_path(default_store_path()).expect("failed to initialize fiducia-auth key store")
    }

    pub fn ephemeral() -> Self {
        KeyStore {
            keys: Mutex::new(HashMap::new()),
            path: None,
        }
    }

    pub fn from_path(path: Option<PathBuf>) -> std::io::Result<Self> {
        let keys = match path.as_deref() {
            Some(path) => load_records(path)?,
            None => HashMap::new(),
        };
        Ok(KeyStore {
            keys: Mutex::new(keys),
            path,
        })
    }

    /// Create a key for an org. Returns the **raw key (shown once)** + its meta.
    pub fn create(
        &self,
        org_id: OrgId,
        name: String,
        scopes: Vec<String>,
        env: String,
    ) -> std::io::Result<(String, ApiKeyMeta)> {
        let key_id = gen_id();
        let secret = gen_secret();
        let raw = format!("fdc_{env}_{key_id}.{secret}");
        let rec = ApiKeyRecord {
            key_id: key_id.clone(),
            org_id,
            name,
            secret_hash: hash_secret(&secret),
            scopes,
            created_ms: now_ms(),
            last_used_ms: None,
            revoked: false,
            env,
        };
        let meta: ApiKeyMeta = (&rec).into();
        let mut keys = self.keys.lock().unwrap();
        keys.insert(key_id, rec);
        if let Err(err) = self.persist_locked(&keys) {
            keys.remove(&meta.key_id);
            return Err(err);
        }
        Ok((raw, meta))
    }

    /// List an org's keys (masked — never returns secrets).
    pub fn list(&self, org_id: &str) -> Vec<ApiKeyMeta> {
        self.keys
            .lock()
            .unwrap()
            .values()
            .filter(|r| r.org_id == org_id)
            .map(ApiKeyMeta::from)
            .collect()
    }

    /// Revoke a key (must belong to the caller's org). Returns whether it matched.
    pub fn revoke(&self, org_id: &str, key_id: &str) -> std::io::Result<bool> {
        let mut keys = self.keys.lock().unwrap();
        let Some(previous) = keys.get_mut(key_id).and_then(|r| {
            if r.org_id == org_id {
                let previous = r.revoked;
                r.revoked = true;
                Some(previous)
            } else {
                None
            }
        }) else {
            return Ok(false);
        };
        if let Err(err) = self.persist_locked(&keys) {
            if let Some(record) = keys.get_mut(key_id) {
                record.revoked = previous;
            }
            return Err(err);
        }
        Ok(true)
    }

    /// Validate a raw API key → org + scopes. Called by the edge/LB (and cached).
    pub fn introspect(&self, raw: &str) -> Introspection {
        // Parse `fdc_<env>_<key_id>.<secret>`.
        let Some((left, secret)) = raw.split_once('.') else {
            return Introspection::invalid();
        };
        let Some(key_id) = left.rsplit('_').next() else {
            return Introspection::invalid();
        };

        let mut keys = self.keys.lock().unwrap();
        match keys.get_mut(key_id) {
            Some(r) if !r.revoked && constant_time_eq(&r.secret_hash, &hash_secret(secret)) => {
                r.last_used_ms = Some(now_ms());
                let intro = Introspection {
                    valid: true,
                    org_id: Some(r.org_id.clone()),
                    key_id: Some(r.key_id.clone()),
                    scopes: r.scopes.clone(),
                };
                if let Err(err) = self.persist_locked(&keys) {
                    tracing::warn!(?err, "failed to persist API key last_used timestamp");
                }
                intro
            }
            _ => Introspection::invalid(),
        }
    }

    fn persist_locked(&self, keys: &HashMap<String, ApiKeyRecord>) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        persist_records(path, keys)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedKeyRecord {
    key_id: String,
    org_id: OrgId,
    name: String,
    secret_hash: String,
    scopes: Vec<String>,
    created_ms: u64,
    last_used_ms: Option<u64>,
    revoked: bool,
    env: String,
}

impl From<PersistedKeyRecord> for ApiKeyRecord {
    fn from(record: PersistedKeyRecord) -> Self {
        ApiKeyRecord {
            key_id: record.key_id,
            org_id: record.org_id,
            name: record.name,
            secret_hash: record.secret_hash,
            scopes: record.scopes,
            created_ms: record.created_ms,
            last_used_ms: record.last_used_ms,
            revoked: record.revoked,
            env: record.env,
        }
    }
}

impl From<&ApiKeyRecord> for PersistedKeyRecord {
    fn from(record: &ApiKeyRecord) -> Self {
        PersistedKeyRecord {
            key_id: record.key_id.clone(),
            org_id: record.org_id.clone(),
            name: record.name.clone(),
            secret_hash: record.secret_hash.clone(),
            scopes: record.scopes.clone(),
            created_ms: record.created_ms,
            last_used_ms: record.last_used_ms,
            revoked: record.revoked,
            env: record.env.clone(),
        }
    }
}

fn default_store_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("FIDUCIA_AUTH_STORE_PATH") {
        let path = PathBuf::from(path);
        return (!path.as_os_str().is_empty()).then_some(path);
    }
    if let Some(dir) = std::env::var_os("FIDUCIA_AUTH_STORE_DIR") {
        let dir = PathBuf::from(dir);
        if !dir.as_os_str().is_empty() {
            return Some(dir.join("keys.json"));
        }
    }
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
        let dir = PathBuf::from(dir);
        if !dir.as_os_str().is_empty() {
            return Some(dir.join("fiducia-auth").join("keys.json"));
        }
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| {
            home.join(".local")
                .join("share")
                .join("fiducia-auth")
                .join("keys.json")
        })
        .or_else(|| Some(PathBuf::from("fiducia-auth-keys.json")))
}

fn load_records(path: &Path) -> std::io::Result<HashMap<String, ApiKeyRecord>> {
    match std::fs::read_to_string(path) {
        Ok(raw) if raw.trim().is_empty() => Ok(HashMap::new()),
        Ok(raw) => {
            let records: Vec<PersistedKeyRecord> = serde_json::from_str(&raw).map_err(|err| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
            })?;
            Ok(records
                .into_iter()
                .map(|record| (record.key_id.clone(), ApiKeyRecord::from(record)))
                .collect())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(err) => Err(err),
    }
}

fn persist_records(path: &Path, keys: &HashMap<String, ApiKeyRecord>) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut records: Vec<PersistedKeyRecord> =
        keys.values().map(PersistedKeyRecord::from).collect();
    records.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    let raw = serde_json::to_vec_pretty(&records)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?;
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, raw)?;
    std::fs::rename(tmp_path, path)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// `n` cryptographically-random bytes from the OS CSPRNG, lower-hex encoded.
/// Panics only if the OS has no entropy source — a fatal, fail-closed condition
/// (we must never hand out a guessable secret).
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

/// Public, non-secret key identifier (64 random bits → 16 hex chars). Used to
/// look the record up before the constant-time secret check.
fn gen_id() -> String {
    random_hex(8)
}

/// The secret half of an API key: 256 bits of CSPRNG entropy.
fn gen_secret() -> String {
    random_hex(32)
}

/// SHA-256 of the secret half (hex). High-entropy random secrets make a slow
/// password KDF unnecessary; introspection still compares hashes in constant
/// time. The raw secret is never stored.
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
        KeyStore::ephemeral()
    }

    #[test]
    fn secrets_are_high_entropy_and_unique() {
        // 256-bit secret → 64 hex chars; 64-bit id → 16 hex chars.
        let s = gen_secret();
        assert_eq!(s.len(), 64, "secret must be 32 random bytes");
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(gen_id().len(), 16);

        // No timestamp determinism: a batch of secrets must all differ.
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
        // Deterministic for a fixed input (so introspect can re-derive + compare).
        assert_eq!(h, hash_secret("super-secret"));
        assert_ne!(h, hash_secret("super-secreu"));
    }

    #[test]
    fn introspect_round_trips_a_created_key() {
        let s = store();
        let (raw, meta) = s
            .create(
                "org_1".into(),
                "ci".into(),
                vec!["kv:read".into()],
                "live".into(),
            )
            .unwrap();
        assert!(raw.starts_with("fdc_live_"));

        let intro = s.introspect(&raw);
        assert!(intro.valid);
        assert_eq!(intro.org_id.as_deref(), Some("org_1"));
        assert_eq!(intro.key_id.as_deref(), Some(meta.key_id.as_str()));
        assert_eq!(intro.scopes, vec!["kv:read".to_string()]);
    }

    #[test]
    fn introspection_is_wire_compatible_with_the_shared_interface() {
        // The edge/LB cache the introspection result as
        // `fiducia_interfaces::Introspection`. Pin that auth emits exactly that
        // shape, for both a valid key and the invalid sentinel.
        let s = store();
        let (raw, _) = s
            .create(
                "org_1".into(),
                "ci".into(),
                vec!["kv:read".into()],
                "live".into(),
            )
            .unwrap();

        for intro in [s.introspect(&raw), Introspection::invalid()] {
            let json = serde_json::to_value(&intro).unwrap();
            let shared: fiducia_interfaces::Introspection = serde_json::from_value(json).unwrap();
            assert_eq!(shared.valid, intro.valid);
            assert_eq!(shared.org_id, intro.org_id);
            assert_eq!(shared.key_id, intro.key_id);
            assert_eq!(shared.scopes, intro.scopes);
        }
    }

    #[test]
    fn introspect_rejects_tampered_secret_and_revoked_keys() {
        let s = store();
        let (raw, meta) = s
            .create("org_1".into(), "ci".into(), vec![], "live".into())
            .unwrap();

        // Flip the last char of the secret → must be rejected.
        let mut bad = raw.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'a' { 'b' } else { 'a' });
        assert!(!s.introspect(&bad).valid, "tampered secret must be invalid");

        // Garbage / malformed inputs never panic and are invalid.
        assert!(!s.introspect("not-a-key").valid);
        assert!(!s.introspect("fdc_live_deadbeef").valid); // no '.secret'

        // Revoked keys stop introspecting.
        assert!(s.revoke("org_1", &meta.key_id).unwrap());
        assert!(!s.introspect(&raw).valid, "revoked key must be invalid");
    }

    #[test]
    fn revoke_is_scoped_to_the_owning_org() {
        let s = store();
        let (_raw, meta) = s
            .create("org_1".into(), "k".into(), vec![], "live".into())
            .unwrap();
        // A different org cannot revoke it.
        assert!(!s.revoke("org_2", &meta.key_id).unwrap());
    }

    #[test]
    fn file_store_survives_restart_and_revoke() {
        let path = std::env::temp_dir().join(format!("fiducia-auth-keys-{}.json", gen_id()));
        let (raw, key_id) = {
            let s = KeyStore::from_path(Some(path.clone())).unwrap();
            let (raw, meta) = s
                .create(
                    "org_1".into(),
                    "ci".into(),
                    vec!["kv:read".into()],
                    "live".into(),
                )
                .unwrap();
            (raw, meta.key_id)
        };

        {
            let s = KeyStore::from_path(Some(path.clone())).unwrap();
            assert!(s.introspect(&raw).valid);
            assert_eq!(s.list("org_1").len(), 1);
            assert!(s.revoke("org_1", &key_id).unwrap());
        }

        {
            let s = KeyStore::from_path(Some(path.clone())).unwrap();
            assert!(!s.introspect(&raw).valid);
            assert!(s.list("org_1")[0].revoked);
        }

        let _ = std::fs::remove_file(path);
    }
}
