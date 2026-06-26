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

use crate::model::{ApiKeyMeta, ApiKeyRecord, Introspection, OrgId};

/// In-memory key store. TODO: back with Supabase Postgres (`sqlx`), keyed by
/// `key_id`, with the org-membership join.
pub struct KeyStore {
    keys: Mutex<HashMap<String, ApiKeyRecord>>, // key_id -> record
    counter: Mutex<u64>,
}

impl KeyStore {
    pub fn new() -> Self {
        KeyStore { keys: Mutex::new(HashMap::new()), counter: Mutex::new(0) }
    }

    /// Create a key for an org. Returns the **raw key (shown once)** + its meta.
    pub fn create(&self, org_id: OrgId, name: String, scopes: Vec<String>, env: String) -> (String, ApiKeyMeta) {
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
        self.keys.lock().unwrap().values()
            .filter(|r| r.org_id == org_id)
            .map(ApiKeyMeta::from)
            .collect()
    }

    /// Revoke a key (must belong to the caller's org). Returns whether it matched.
    pub fn revoke(&self, org_id: &str, key_id: &str) -> bool {
        let mut keys = self.keys.lock().unwrap();
        match keys.get_mut(key_id) {
            Some(r) if r.org_id == org_id => { r.revoked = true; true }
            _ => false,
        }
    }

    /// Validate a raw API key → org + scopes. Called by the edge/LB (and cached).
    pub fn introspect(&self, raw: &str) -> Introspection {
        // Parse `fdc_<env>_<key_id>.<secret>`.
        let Some((left, secret)) = raw.split_once('.') else { return Introspection::invalid() };
        let Some(key_id) = left.rsplit('_').next() else { return Introspection::invalid() };

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

    // TODO(security): replace with a CSPRNG (getrandom/rand). These are NOT
    // suitable for production secrets.
    fn gen_id(&self) -> String {
        let mut c = self.counter.lock().unwrap();
        *c += 1;
        format!("{:012x}", now_ms().wrapping_add(*c))
    }
    fn gen_secret(&self) -> String {
        format!("{:024x}", now_ms().wrapping_mul(2654435761))
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// TODO(security): replace with argon2id (or at least SHA-256). This placeholder
/// is deterministic only so the skeleton round-trips — it is NOT secure.
fn hash_secret(secret: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in secret.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("stubhash:{h:016x}")
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
