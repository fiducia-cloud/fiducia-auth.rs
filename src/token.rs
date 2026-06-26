//! Short-lived JWT minting + JWKS (skeleton).
//!
//! The trick that keeps the hot path off the auth server: instead of validating
//! the opaque API key on every request, a client (or the edge) can **exchange**
//! it once for a short-lived **signed JWT** carrying `{org_id, scopes, exp}`.
//! Every fiducia component then verifies that JWT **offline** with our public key
//! (served at `/.well-known/jwks.json`) — no call back to auth.
//!
//! Revocation is handled by keeping `exp` short (minutes) + an optional denylist
//! for emergencies. For long-lived B2B keys, the alternative is cached
//! introspection (see `keys.rs`); both avoid per-request auth calls.

use serde_json::{json, Value};

use crate::model::OrgId;

/// Mint a short-lived JWT for an introspected key.
///
/// TODO: sign with `jsonwebtoken` using an asymmetric key (EdDSA/RS256) whose
/// public half is published via [`jwks`]. Claims: `sub`(org), `scopes`, `exp`,
/// `iat`, `iss=fiducia-auth`.
pub fn mint_token(_org_id: &OrgId, _scopes: &[String], _ttl_secs: u64) -> String {
    // Skeleton placeholder — NOT a real token.
    "stub.jwt.token".to_string()
}

/// Public keys for offline JWT verification by the edge/LB/nodes.
///
/// TODO: publish the real public JWK(s); rotate with a `kid`.
pub fn jwks() -> Value {
    json!({ "keys": [] })
}
