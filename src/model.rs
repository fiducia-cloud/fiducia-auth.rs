//! Auth domain types (skeleton).

use serde::{Deserialize, Serialize};

pub type OrgId = String;
pub type UserId = String;

/// Identity proven by a Supabase session JWT (dashboard plane).
#[derive(Debug, Clone, Serialize)]
pub struct UserCtx {
    pub user_id: UserId,
    pub email: Option<String>,
    /// Orgs this user belongs to (from the org-membership table).
    pub orgs: Vec<OrgId>,
}

/// What an API key resolves to (data plane). This is what the edge/LB caches.
#[derive(Debug, Clone, Serialize)]
pub struct Introspection {
    pub valid: bool,
    pub org_id: Option<OrgId>,
    pub key_id: Option<String>,
    pub scopes: Vec<String>,
}

impl Introspection {
    pub fn invalid() -> Self {
        Introspection {
            valid: false,
            org_id: None,
            key_id: None,
            scopes: vec![],
        }
    }
}

/// Stored API key record. **Only the hash of the secret is persisted** — the raw
/// key is shown to the user exactly once, at creation.
#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyRecord {
    pub key_id: String,
    pub org_id: OrgId,
    pub name: String,
    /// `argon2`/`sha256` of the secret half. Never the raw key.
    #[serde(skip)]
    pub secret_hash: String,
    pub scopes: Vec<String>,
    pub created_ms: u64,
    pub last_used_ms: Option<u64>,
    pub revoked: bool,
    /// "live" or "test".
    pub env: String,
}

/// Public (maskable) view of a key for the dashboard list.
#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyMeta {
    pub key_id: String,
    pub org_id: OrgId,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_ms: u64,
    pub last_used_ms: Option<u64>,
    pub revoked: bool,
    pub env: String,
}

impl From<&ApiKeyRecord> for ApiKeyMeta {
    fn from(r: &ApiKeyRecord) -> Self {
        ApiKeyMeta {
            key_id: r.key_id.clone(),
            org_id: r.org_id.clone(),
            name: r.name.clone(),
            scopes: r.scopes.clone(),
            created_ms: r.created_ms,
            last_used_ms: r.last_used_ms,
            revoked: r.revoked,
            env: r.env.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateKeyBody {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub env: Option<String>, // "live" | "test"
    /// Which of the caller's orgs to create the key under. When omitted, the
    /// caller's first org is used. Must be an org the caller belongs to.
    #[serde(default)]
    pub org: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IntrospectBody {
    pub api_key: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenBody {
    pub api_key: String,
}
