//! Short-lived fiducia-issued JWTs (ES256 / P-256) + the public JWKS.
//!
//! The trick that keeps the hot path off the auth server: instead of validating
//! the opaque API key on every request, a client (or the edge) **exchanges** it
//! once for a short-lived **signed JWT** carrying `{org_id, scopes, exp}`. Every
//! fiducia component (edge, LB, nodes) then verifies that JWT **offline** with the
//! public key served at `/.well-known/jwks.json` — no call back to auth.
//!
//! Revocation is handled by keeping `exp` short (minutes) + an optional denylist
//! for emergencies. Long-lived B2B keys use cached introspection instead; both
//! avoid per-request auth calls.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use p256::SecretKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::model::OrgId;

const ISSUER: &str = "fiducia-auth";

/// Claims in a fiducia-issued access token. `sub` = org id (the tenant the token
/// acts for) so standard JWT tooling shows the org as the subject.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub org_id: String,
    pub scopes: Vec<String>,
    pub iss: String,
    pub iat: u64,
    pub exp: u64,
}

/// Process-wide ES256 signer, loaded once.
struct Signer {
    encoding: EncodingKey,
    decoding: DecodingKey,
    jwk: Value,
    kid: String,
}

static SIGNER: Lazy<Signer> = Lazy::new(Signer::load);

impl Signer {
    /// Load the signing key from `FIDUCIA_JWT_SIGNING_KEY` (PKCS#8 EC P-256 PEM,
    /// shared across replicas via a k8s secret). With no env key we generate an
    /// EPHEMERAL one — fine for a single dev pod, but multi-replica MUST share a
    /// key or each pod publishes a different JWKS and cross-pod verification fails.
    fn load() -> Self {
        let secret = match std::env::var("FIDUCIA_JWT_SIGNING_KEY") {
            Ok(pem) if !pem.trim().is_empty() => SecretKey::from_pkcs8_pem(pem.trim())
                .expect("FIDUCIA_JWT_SIGNING_KEY must be a PKCS#8 EC (P-256) private key PEM"),
            _ => {
                tracing::warn!(
                    "FIDUCIA_JWT_SIGNING_KEY not set — generating an EPHEMERAL ES256 key (OK for a single dev pod; provide a shared key for multi-replica)"
                );
                generate_secret()
            }
        };
        Self::from_secret(&secret)
    }

    fn from_secret(secret: &SecretKey) -> Self {
        let pkcs8 = secret
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode signing key to PKCS#8 PEM");
        let encoding = EncodingKey::from_ec_pem(pkcs8.as_bytes()).expect("ES256 encoding key");

        let pubkey = secret.public_key();
        let spki = pubkey
            .to_public_key_pem(LineEnding::LF)
            .expect("encode public key to SPKI PEM");
        let decoding = DecodingKey::from_ec_pem(spki.as_bytes()).expect("ES256 decoding key");

        // Public JWK (uncompressed point -> x/y) for /.well-known/jwks.json.
        let point = pubkey.to_encoded_point(false); // 0x04 || x || y
        let x = point.x().expect("P-256 x coordinate");
        let y = point.y().expect("P-256 y coordinate");
        let b64u = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let kid = {
            let mut h = Sha256::new();
            h.update(x);
            h.update(y);
            hex16(&h.finalize())
        };
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64u(x),
            "y": b64u(y),
            "use": "sig",
            "alg": "ES256",
            "kid": kid,
        });

        Signer {
            encoding,
            decoding,
            jwk,
            kid,
        }
    }
}

/// Mint a short-lived JWT for an introspected key/session.
pub fn mint_token(org_id: &OrgId, scopes: &[String], ttl_secs: u64) -> String {
    mint_with(&SIGNER, org_id, scopes, ttl_secs)
}

fn mint_with(signer: &Signer, org_id: &OrgId, scopes: &[String], ttl_secs: u64) -> String {
    let now = now_secs();
    let claims = Claims {
        sub: org_id.clone(),
        org_id: org_id.clone(),
        scopes: scopes.to_vec(),
        iss: ISSUER.to_string(),
        iat: now,
        exp: now.saturating_add(ttl_secs),
    };
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(signer.kid.clone());
    encode(&header, &claims, &signer.encoding).expect("sign fiducia JWT")
}

/// Public keys for offline JWT verification by the edge / LB / nodes.
pub fn jwks() -> Value {
    json!({ "keys": [SIGNER.jwk.clone()] })
}

/// Verify a fiducia-issued token offline (used by tests; the edge/LB carry their
/// own copy of this check, fed by the published JWKS).
pub fn verify_token(token: &str) -> Option<Claims> {
    verify_with(&SIGNER, token)
}

fn verify_with(signer: &Signer, token: &str) -> Option<Claims> {
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&[ISSUER]);
    validation.validate_exp = true;
    decode::<Claims>(token, &signer.decoding, &validation)
        .ok()
        .map(|data| data.claims)
}

fn generate_secret() -> SecretKey {
    // Use the OS CSPRNG directly (no extra rng dep); reject the negligible chance
    // of an out-of-range scalar and retry.
    loop {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("OS CSPRNG");
        if let Ok(secret) = SecretKey::from_slice(&bytes) {
            return secret;
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex16(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> Signer {
        Signer::from_secret(&generate_secret())
    }

    #[test]
    fn mint_then_verify_offline_roundtrips() {
        let s = signer();
        let scopes = vec!["locks:write".to_string(), "kv:read".to_string()];
        let token = mint_with(&s, &"org_123".to_string(), &scopes, 900);

        let claims = verify_with(&s, &token).expect("valid token verifies");
        assert_eq!(claims.org_id, "org_123");
        assert_eq!(claims.sub, "org_123");
        assert_eq!(claims.scopes, scopes);
        assert_eq!(claims.iss, ISSUER);
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn jwks_exposes_one_es256_signing_key() {
        let s = signer();
        assert_eq!(s.jwk["kty"], "EC");
        assert_eq!(s.jwk["crv"], "P-256");
        assert_eq!(s.jwk["alg"], "ES256");
        assert_eq!(s.jwk["use"], "sig");
        assert!(s.jwk["x"].as_str().is_some_and(|x| !x.is_empty()));
        assert!(s.jwk["y"].as_str().is_some_and(|y| !y.is_empty()));
        assert_eq!(s.jwk["kid"], s.kid.as_str());
    }

    #[test]
    fn a_token_from_a_different_key_is_rejected() {
        let token = mint_with(&signer(), &"org_a".to_string(), &[], 900);
        // A verifier holding a different key must reject it (signature mismatch).
        assert!(verify_with(&signer(), &token).is_none());
    }

    #[test]
    fn expired_token_is_rejected() {
        // Build a token that expired 2 min ago — beyond the verifier's default
        // 60s clock-skew leeway — and confirm it's rejected.
        let s = signer();
        let now = now_secs();
        let claims = Claims {
            sub: "org_a".to_string(),
            org_id: "org_a".to_string(),
            scopes: vec![],
            iss: ISSUER.to_string(),
            iat: now.saturating_sub(200),
            exp: now.saturating_sub(120),
        };
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(s.kid.clone());
        let token = encode(&header, &claims, &s.encoding).expect("sign");
        assert!(verify_with(&s, &token).is_none());
    }
}
