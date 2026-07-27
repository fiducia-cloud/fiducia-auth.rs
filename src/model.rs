//! Auth domain types.

use serde::{
    ser::{SerializeStruct, Serializer},
    Deserialize, Serialize,
};

pub type OrgId = String;
pub type UserId = String;

pub const AUTHORIZATION_CONTEXT_VERSION: u16 = 1;
pub const ADMIN_SURFACE_AUDIENCE: &str = "fiducia-admin";
pub const CUSTOMER_SURFACE_AUDIENCE: &str = "fiducia-customer";

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

/// Versioned authorization decision emitted by `fiducia-auth` after it verifies
/// the Supabase token and reads roles exclusively from trusted `app_metadata`.
/// Browser headers and user-editable metadata never populate this structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationContext {
    pub version: u16,
    pub surface_audiences: Vec<&'static str>,
    pub roles: Vec<&'static str>,
    pub capabilities: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustedRole {
    Admin,
    Operator,
    Customer,
}

impl TrustedRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Customer => "customer",
        }
    }
}

/// Identity proven by a Supabase session JWT (dashboard plane).
#[derive(Debug, Clone)]
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

impl UserCtx {
    /// Normalize the trusted role vocabulary and derive explicit receiving
    /// surfaces. The compatibility rule is intentionally narrow: an empty role
    /// list is a legacy customer session. A non-empty list containing only
    /// unknown roles receives no audience and therefore fails closed everywhere.
    pub fn authorization_context(&self) -> AuthorizationContext {
        let trusted_roles = normalized_trusted_roles(&self.roles);
        let has_admin = trusted_roles
            .iter()
            .any(|role| matches!(role, TrustedRole::Admin));
        let has_operator = trusted_roles
            .iter()
            .any(|role| matches!(role, TrustedRole::Operator));
        let has_customer = trusted_roles
            .iter()
            .any(|role| matches!(role, TrustedRole::Customer));

        let mut surface_audiences = Vec::new();
        if has_admin || has_operator {
            surface_audiences.push(ADMIN_SURFACE_AUDIENCE);
        }
        if has_customer || self.roles.is_empty() {
            surface_audiences.push(CUSTOMER_SURFACE_AUDIENCE);
        }

        let mut capabilities = Vec::new();
        if has_admin {
            capabilities.extend(["admin:read", "admin:operate", "admin:write"]);
        } else if has_operator {
            capabilities.extend(["admin:read", "admin:operate"]);
        }
        if has_customer || self.roles.is_empty() {
            capabilities.push("customer:self-service");
        }

        AuthorizationContext {
            version: AUTHORIZATION_CONTEXT_VERSION,
            surface_audiences,
            roles: trusted_roles.into_iter().map(TrustedRole::as_str).collect(),
            capabilities,
        }
    }
}

/// Preserve the existing `/v1/me` user shape while adding one versioned trusted
/// authorization object. Consumers must authorize from `authorization`, not from
/// raw client headers or arbitrary role strings.
impl Serialize for UserCtx {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let authorization = self.authorization_context();
        let mut state = serializer.serialize_struct("UserCtx", 6)?;
        state.serialize_field("user_id", &self.user_id)?;
        state.serialize_field("email", &self.email)?;
        state.serialize_field("orgs", &self.orgs)?;
        state.serialize_field("roles", &self.roles)?;
        state.serialize_field("aal", &self.aal)?;
        state.serialize_field("authorization", &authorization)?;
        state.end()
    }
}

fn normalized_trusted_roles(roles: &[String]) -> Vec<TrustedRole> {
    let mut normalized = Vec::new();
    for role in roles {
        let role = match role.trim().to_ascii_lowercase().as_str() {
            "admin" => Some(TrustedRole::Admin),
            "operator" => Some(TrustedRole::Operator),
            "customer" => Some(TrustedRole::Customer),
            _ => None,
        };
        if let Some(role) = role {
            if !normalized.contains(&role) {
                normalized.push(role);
            }
        }
    }
    normalized
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
    fn from(record: &ApiKeyRecord) -> Self {
        ApiKeyMeta {
            key_id: record.key_id.clone(),
            org_id: record.org_id.clone(),
            name: record.name.clone(),
            scopes: record.scopes.clone(),
            created_ms: record.created_ms,
            last_used_ms: record.last_used_ms,
            revoked: record.revoked,
            version: record.version,
            env: record.env.clone(),
            require_idempotency: record.require_idempotency,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn user(roles: &[&str]) -> UserCtx {
        UserCtx {
            user_id: "user_1".to_string(),
            email: Some("user@example.com".to_string()),
            orgs: vec!["org_1".to_string()],
            roles: roles.iter().map(|role| (*role).to_string()).collect(),
            aal: AssuranceLevel::Aal2,
        }
    }

    #[test]
    fn legacy_empty_roles_receive_only_the_customer_surface() {
        let authorization = user(&[]).authorization_context();
        assert_eq!(authorization.version, AUTHORIZATION_CONTEXT_VERSION);
        assert_eq!(
            authorization.surface_audiences,
            vec![CUSTOMER_SURFACE_AUDIENCE]
        );
        assert!(authorization.roles.is_empty());
        assert_eq!(authorization.capabilities, vec!["customer:self-service"]);
    }

    #[test]
    fn admin_and_operator_roles_receive_only_the_admin_surface() {
        let admin = user(&["ADMIN", "admin"]).authorization_context();
        assert_eq!(admin.surface_audiences, vec![ADMIN_SURFACE_AUDIENCE]);
        assert_eq!(admin.roles, vec!["admin"]);
        assert_eq!(
            admin.capabilities,
            vec!["admin:read", "admin:operate", "admin:write"]
        );

        let operator = user(&["operator"]).authorization_context();
        assert_eq!(operator.surface_audiences, vec![ADMIN_SURFACE_AUDIENCE]);
        assert_eq!(operator.roles, vec!["operator"]);
        assert_eq!(operator.capabilities, vec!["admin:read", "admin:operate"]);
    }

    #[test]
    fn dual_surface_access_must_be_explicit() {
        let authorization = user(&["operator", "customer"]).authorization_context();
        assert_eq!(
            authorization.surface_audiences,
            vec![ADMIN_SURFACE_AUDIENCE, CUSTOMER_SURFACE_AUDIENCE]
        );
        assert_eq!(authorization.roles, vec!["operator", "customer"]);
        assert_eq!(
            authorization.capabilities,
            vec!["admin:read", "admin:operate", "customer:self-service"]
        );
    }

    #[test]
    fn unknown_nonempty_roles_fail_closed_on_every_surface() {
        let authorization = user(&["authenticated", "owner-from-browser"]).authorization_context();
        assert!(authorization.surface_audiences.is_empty());
        assert!(authorization.roles.is_empty());
        assert!(authorization.capabilities.is_empty());
    }

    #[test]
    fn serialized_user_carries_the_versioned_trusted_authorization_context() {
        let value = serde_json::to_value(user(&["admin"])).unwrap();
        assert_eq!(value["user_id"], "user_1");
        assert_eq!(value["roles"], json!(["admin"]));
        assert_eq!(value["authorization"]["version"], 1);
        assert_eq!(
            value["authorization"]["surface_audiences"],
            json!(["fiducia-admin"])
        );
        assert_eq!(
            value["authorization"]["capabilities"],
            json!(["admin:read", "admin:operate", "admin:write"])
        );
    }
}
