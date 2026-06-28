//! Short-lived JWT minting + JWKS.
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

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::{json, Value};

use crate::model::OrgId;

const DEFAULT_ISSUER: &str = "fiducia-auth";
const DEFAULT_AUDIENCE: &str = "fiducia-api";
const DEFAULT_KEY_ID: &str = "fiducia-auth-1";

/// Mint a short-lived JWT for an introspected key.
///
/// Requires asymmetric signing material in env:
///
/// - `FIDUCIA_JWT_PRIVATE_KEY_PEM`
/// - `FIDUCIA_JWT_PUBLIC_JWK`
/// - optional `FIDUCIA_JWT_ALG` (`RS256` or `ES256`)
/// - optional `FIDUCIA_JWT_KID`, `FIDUCIA_JWT_ISSUER`, `FIDUCIA_JWT_AUDIENCE`
pub fn mint_token(org_id: &OrgId, scopes: &[String], ttl_secs: u64) -> Result<String, TokenError> {
    let signer = SignerConfig::from_env()?;
    let now = unix_secs();
    let claims = FiduciaClaims {
        sub: org_id.clone(),
        org_id: org_id.clone(),
        scopes: scopes.to_vec(),
        iss: signer.issuer.clone(),
        aud: signer.audience.clone(),
        iat: now,
        exp: now.saturating_add(ttl_secs),
    };
    let mut header = Header::new(signer.algorithm);
    header.kid = Some(signer.kid);
    encode(&header, &claims, &signer.encoding_key).map_err(TokenError::Jwt)
}

/// Public keys for offline JWT verification by the edge/LB/nodes.
pub fn jwks() -> Value {
    let Some(mut jwk) = env_json("FIDUCIA_JWT_PUBLIC_JWK") else {
        return json!({ "keys": [] });
    };
    if jwk.get("kid").is_none() {
        jwk["kid"] = json!(env_value("FIDUCIA_JWT_KID").unwrap_or_else(|| DEFAULT_KEY_ID.into()));
    }
    if jwk.get("use").is_none() {
        jwk["use"] = json!("sig");
    }
    json!({ "keys": [jwk] })
}

#[derive(Debug, Serialize)]
struct FiduciaClaims {
    sub: String,
    org_id: String,
    scopes: Vec<String>,
    iss: String,
    aud: String,
    iat: u64,
    exp: u64,
}

struct SignerConfig {
    algorithm: Algorithm,
    audience: String,
    encoding_key: EncodingKey,
    issuer: String,
    kid: String,
}

impl SignerConfig {
    fn from_env() -> Result<Self, TokenError> {
        let algorithm = parse_algorithm(
            env_value("FIDUCIA_JWT_ALG")
                .unwrap_or_else(|| "RS256".to_string())
                .as_str(),
        )?;
        let pem = env_value("FIDUCIA_JWT_PRIVATE_KEY_PEM").ok_or(TokenError::MissingPrivateKey)?;
        let encoding_key = encoding_key_for(algorithm, pem.as_bytes())?;
        Ok(SignerConfig {
            algorithm,
            audience: env_value("FIDUCIA_JWT_AUDIENCE")
                .unwrap_or_else(|| DEFAULT_AUDIENCE.to_string()),
            encoding_key,
            issuer: env_value("FIDUCIA_JWT_ISSUER").unwrap_or_else(|| DEFAULT_ISSUER.to_string()),
            kid: env_value("FIDUCIA_JWT_KID").unwrap_or_else(|| DEFAULT_KEY_ID.to_string()),
        })
    }
}

#[derive(Debug)]
pub enum TokenError {
    InvalidAlgorithm(String),
    Jwt(jsonwebtoken::errors::Error),
    MissingPrivateKey,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::InvalidAlgorithm(alg) => write!(f, "unsupported jwt algorithm {alg}"),
            TokenError::Jwt(err) => write!(f, "jwt signing error: {err}"),
            TokenError::MissingPrivateKey => write!(f, "FIDUCIA_JWT_PRIVATE_KEY_PEM is required"),
        }
    }
}

impl std::error::Error for TokenError {}

fn parse_algorithm(value: &str) -> Result<Algorithm, TokenError> {
    match value {
        "RS256" => Ok(Algorithm::RS256),
        "ES256" => Ok(Algorithm::ES256),
        other => Err(TokenError::InvalidAlgorithm(other.to_string())),
    }
}

fn encoding_key_for(algorithm: Algorithm, pem: &[u8]) -> Result<EncodingKey, TokenError> {
    match algorithm {
        Algorithm::RS256 => EncodingKey::from_rsa_pem(pem).map_err(TokenError::Jwt),
        Algorithm::ES256 => EncodingKey::from_ec_pem(pem).map_err(TokenError::Jwt),
        other => Err(TokenError::InvalidAlgorithm(format!("{other:?}"))),
    }
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_json(name: &str) -> Option<Value> {
    env_value(name).and_then(|value| serde_json::from_str(&value).ok())
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_algorithm_accepts_only_supported_asymmetric_algs() {
        assert_eq!(parse_algorithm("RS256").unwrap(), Algorithm::RS256);
        assert_eq!(parse_algorithm("ES256").unwrap(), Algorithm::ES256);
        assert!(matches!(
            parse_algorithm("HS256"),
            Err(TokenError::InvalidAlgorithm(_))
        ));
        assert!(matches!(
            parse_algorithm("EdDSA"),
            Err(TokenError::InvalidAlgorithm(_))
        ));
    }

    #[test]
    fn jwks_is_empty_until_public_jwk_is_configured() {
        std::env::remove_var("FIDUCIA_JWT_PUBLIC_JWK");
        assert_eq!(jwks(), json!({ "keys": [] }));
    }
}
