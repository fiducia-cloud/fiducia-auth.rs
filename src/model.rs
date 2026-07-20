//! Auth domain types.

use serde::{Deserialize, Serialize};

pub type OrgId = String;
pub type UserId = String;

/// The assurance level carried by a Supabase session JWT. Missing claims are
/// treated as `aal1` by the verifier for backwards compatibility with tokens
/// issued before Supabase added the claim; unknown levels are rejected.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AssuranceLevel {
    #[default]
    Aal1,
    Aal2,
}

/// Identity proven by a Supabase session JWT (dashboard plane).
#[derive(Debug, Clone, Serialize)]
pub struct UserCtx {
    pub user_id: UserId,
    pub email: Option<String>,
    /// Orgs this user belongs to (from the org-membership table).
    pub orgs: Vec<OrgId>,
    /// Application roles copied only from Supabase `app_metadata`, which is
    /// controlled by trusted server-side administration. Browser-writable user
    /// metadata is never an authorization source. Customer callers normally
    /// have no roles; admin apps additionally require a recognized operator role.
    pub roles: Vec<String>,
    /// Verified session assurance. Customer-facing consumers use this together
    /// with the live factor list to reject a stale `aal1` session for an account
    /// that has an enrolled MFA factor.
    pub aal: AssuranceLevel,
}

/// What an API key resolves to (data plane). This is what the edge/LB caches.
#[derive(Debug, Clone, Serialize)]
pub struct Introspection {
    pub valid: bool,
    pub org_id: Option<OrgId>,
    pub key_id: Option<String>,
    pub scopes: Vec<String>,
    /// When true, the edge/LB must reject mutating calls made with this key that
    /// omit an `Idempotency-Key` header. Defaults false so the control is opt-in.
    pub require_idempotency: bool,
}

impl Introspection {
    pub fn invalid() -> Self {
        Introspection {
            valid: false,
            org_id: None,
            key_id: None,
            scopes: vec![],
            require_idempotency: false,
        }
    }
}

/// Stored API key record. **Only the hash of the secret is persisted** — a raw
/// key is shown to the user only in the creation or rotation response that
/// minted it.
#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyRecord {
    pub key_id: String,
    pub org_id: OrgId,
    pub name: String,
    /// `argon2`/`sha256` of the secret half. Never the raw key.
    #[serde(skip)]
    pub secret_hash: String,
    /// Server-only HMAC of the create request's idempotency identity. It lets a
    /// retry recover the original one-time secret without persisting that secret.
    #[serde(skip)]
    pub create_idempotency_hash: String,
    /// Server-only HMAC of the most recently applied rotation request.
    #[serde(skip)]
    pub last_rotation_idempotency_hash: Option<String>,
    pub scopes: Vec<String>,
    pub created_ms: u64,
    pub last_used_ms: Option<u64>,
    pub revoked: bool,
    /// Durable per-key version. Starts at 1 and advances on each secret rotation
    /// and on the first transition to revoked.
    pub version: u64,
    /// "live" or "test".
    pub env: String,
    /// When true, mutating calls with this key must carry an `Idempotency-Key`.
    pub require_idempotency: bool,
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
    pub version: u64,
    pub env: String,
    pub require_idempotency: bool,
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
            version: r.version,
            env: r.env.clone(),
            require_idempotency: r.require_idempotency,
        }
    }
}

fn default_require_idempotency() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct CreateKeyBody {
    pub name: String,
    #[serde(default)]
    pub org_id: Option<OrgId>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub env: Option<String>, // "live" | "test"
    /// Customer-facing creates require mutation idempotency unless explicitly
    /// disabled. This request default is intentionally stricter than the
    /// backward-compatible default for old durable records.
    #[serde(default = "default_require_idempotency")]
    pub require_idempotency: bool,
}

#[derive(Debug, Deserialize)]
pub struct IntrospectBody {
    pub api_key: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenBody {
    pub api_key: String,
}
