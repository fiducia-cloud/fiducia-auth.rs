//! API keys + introspection (skeleton) — the **data** plane.
//!
//! B2B *machines* authenticate to the coordination API with a static API key
//! (`Authorization: Bearer fdc_live_<id>.<secret>`). We store only a **hash** of
//! the secret; the raw key is shown to the user exactly once, at creation.
//!
//! [`introspect`](KeyStore::introspect) is the endpoint the edge/LB calls and
//! **caches** (short TTL) so the steady-state hot path makes no auth/DB call.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::model::{ApiKeyMeta, ApiKeyRecord, Introspection, OrgId};

/// In-memory key store. TODO: back with Supabase Postgres (`sqlx`), keyed by
/// `key_id`, with the org-membership join.
pub struct KeyStore {
    keys: Mutex<HashMap<String, ApiKeyRecord>>, // key_id -> record
}

impl KeyStore {
    pub fn new() -> Self {
        KeyStore {
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// Create a key for an org. Returns the **raw key (shown once)** + its meta.
    pub fn create(
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
        self.keys.lock().unwrap().insert(key_id, rec);
        (raw, meta)
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
    pub fn revoke(&self, org_id: &str, key_id: &str) -> bool {
        let mut keys = self.keys.lock().unwrap();
        match keys.get_mut(key_id) {
            Some(r) if r.org_id == org_id => {
                r.revoked = true;
                true
            }
            _ => false,
        }
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
                Introspection {
                    valid: true,
                    org_id: Some(r.org_id.clone()),
                    key_id: Some(r.key_id.clone()),
                    scopes: r.scopes.clone(),
                }
            }
            _ => Introspection::invalid(),
        }
    }
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
        KeyStore::new()
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
        let (raw, meta) = s.create(
            "org_1".into(),
            "ci".into(),
            vec!["kv:read".into()],
            "live".into(),
        );
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
        let (raw, _) = s.create("org_1".into(), "ci".into(), vec!["kv:read".into()], "live".into());

        for intro in [s.introspect(&raw), Introspection::invalid()] {
            let json = serde_json::to_value(&intro).unwrap();
            let shared: fiducia_interfaces::Introspection =
                serde_json::from_value(json).unwrap();
            assert_eq!(shared.valid, intro.valid);
            assert_eq!(shared.org_id, intro.org_id);
            assert_eq!(shared.key_id, intro.key_id);
            assert_eq!(shared.scopes, intro.scopes);
        }
    }

    #[test]
    fn introspect_rejects_tampered_secret_and_revoked_keys() {
        let s = store();
        let (raw, meta) = s.create("org_1".into(), "ci".into(), vec![], "live".into());

        // Flip the last char of the secret → must be rejected.
        let mut bad = raw.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'a' { 'b' } else { 'a' });
        assert!(!s.introspect(&bad).valid, "tampered secret must be invalid");

        // Garbage / malformed inputs never panic and are invalid.
        assert!(!s.introspect("not-a-key").valid);
        assert!(!s.introspect("fdc_live_deadbeef").valid); // no '.secret'

        // Revoked keys stop introspecting.
        assert!(s.revoke("org_1", &meta.key_id));
        assert!(!s.introspect(&raw).valid, "revoked key must be invalid");
    }

    #[test]
    fn revoke_is_scoped_to_the_owning_org() {
        let s = store();
        let (_raw, meta) = s.create("org_1".into(), "k".into(), vec![], "live".into());
        // A different org cannot revoke it.
        assert!(!s.revoke("org_2", &meta.key_id));
    }
}
