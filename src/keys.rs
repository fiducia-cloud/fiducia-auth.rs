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

use rand::{rngs::OsRng, RngCore};
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
        let key_id = self.gen_id();
        let secret = self.gen_secret();
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

    fn gen_id(&self) -> String {
        random_hex(12)
    }

    fn gen_secret(&self) -> String {
        random_hex(32)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn hash_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    format!("sha256:{}", hex_encode(&digest))
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    hex_encode(&buf)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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

    fn org() -> OrgId {
        "org_test".to_string()
    }

    #[test]
    fn generated_keys_are_unique_and_masked_in_metadata() {
        let store = KeyStore::new();
        let (first_raw, first_meta) = store.create(
            org(),
            "first".to_string(),
            vec!["kv:read".to_string()],
            "test".to_string(),
        );
        let (second_raw, second_meta) = store.create(
            org(),
            "second".to_string(),
            vec!["kv:write".to_string()],
            "test".to_string(),
        );

        assert_ne!(first_raw, second_raw);
        assert_ne!(first_meta.key_id, second_meta.key_id);
        assert!(first_raw.starts_with("fdc_test_"));
        assert!(!serde_json::to_string(&first_meta).unwrap().contains('.'));
    }

    #[test]
    fn introspection_accepts_only_the_original_secret() {
        let store = KeyStore::new();
        let (raw, meta) = store.create(
            org(),
            "service".to_string(),
            vec!["locks:write".to_string()],
            "live".to_string(),
        );

        let valid = store.introspect(&raw);
        assert!(valid.valid);
        assert_eq!(valid.key_id.as_deref(), Some(meta.key_id.as_str()));

        let tampered = format!("{raw}00");
        assert!(!store.introspect(&tampered).valid);
    }

    #[test]
    fn stored_secret_hash_uses_sha256_prefix() {
        let store = KeyStore::new();
        let (_raw, meta) = store.create(
            org(),
            "service".to_string(),
            vec!["locks:write".to_string()],
            "live".to_string(),
        );
        let keys = store.keys.lock().unwrap();
        let record = keys.get(&meta.key_id).expect("created record");

        assert!(record.secret_hash.starts_with("sha256:"));
        assert_eq!(record.secret_hash.len(), "sha256:".len() + 64);
    }
}
