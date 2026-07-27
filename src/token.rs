//! Short-lived fiducia-issued JWTs (ES256 / P-256) + the public JWKS.
//!
//! The trick that keeps the hot path off the auth server: instead of validating
//! the opaque API key on every request, a client (or the edge) **exchanges** it
//! once for a short-lived **signed JWT** carrying `{org_id, scopes, jti, exp}`.
//! Every fiducia component (edge, LB, nodes) then verifies that JWT **offline**
//! with the public key served at `/.well-known/jwks.json` - no call back to auth.
//!
//! Emergency revocation needs an identity stronger than subject alone. Every new
//! token therefore carries a CSPRNG-backed `jti`, and this module defines the
//! versioned, issuer/audience/tenant-scoped record that distributed verifiers can
//! cache without cross-tenant collisions. The durable replicated store and
//! verifier-side cache rollout are tracked separately under DEN-252.

use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine as _;
#[cfg(test)]
use jsonwebtoken::{decode, DecodingKey, Validation};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use once_cell::sync::Lazy;
use p256::elliptic_curve::sec1::ToEncodedPoint;
#[cfg(test)]
use p256::pkcs8::EncodePublicKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use p256::SecretKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::model::OrgId;

const ISSUER: &str = "fiducia-auth";
/// The data-plane verifiers (edge and load balancer) require this audience.
/// Keep it a fixed issuer contract rather than an environment-controlled value:
/// an accidental deployment mismatch must reject the token, not broaden where a
/// credential is accepted.
const AUDIENCE: &str = "fiducia-api";

/// Existing exchanges mint 15-minute credentials. Keep this as a hard ceiling so
/// a future caller cannot accidentally turn an offline-verifiable access token
/// into a long-lived credential that outlives bounded revocation propagation.
pub const MAX_ACCESS_TOKEN_TTL_SECS: u64 = 15 * 60;
pub const REVOCATION_RECORD_VERSION: u16 = 1;
/// Subject-level emergency records are deliberately bounded. Token-ID records
/// normally expire with the token (at most 15 minutes); a subject quarantine may
/// bridge a key/session rotation but must be renewed deliberately after one day.
pub const MAX_INTERNAL_REVOCATION_TTL_SECS: u64 = 24 * 60 * 60;

/// Claims in a fiducia-issued access token. `sub` = org id (the tenant the token
/// acts for) so standard JWT tooling shows the org as the subject.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub org_id: String,
    pub scopes: Vec<String>,
    pub iss: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    /// Unique token identity used for immediate emergency revocation.
    pub jti: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MintError {
    InvalidTtl { requested: u64, maximum: u64 },
    EntropyUnavailable,
}

impl fmt::Display for MintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTtl { requested, maximum } => write!(
                formatter,
                "access-token TTL {requested}s is outside the allowed 1..={maximum}s range",
            ),
            Self::EntropyUnavailable => {
                write!(formatter, "operating-system entropy is unavailable")
            }
        }
    }
}

impl std::error::Error for MintError {}

/// The target of one versioned revocation record.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RevocationTarget {
    TokenId { jti: String },
    Subject { subject: String },
}

/// Durable replicated revocation record. It contains no raw token, API key,
/// credential hash, email, or user-editable metadata.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub version: u16,
    pub issuer: String,
    pub audience: String,
    pub tenant_id: String,
    pub target: RevocationTarget,
    pub reason: String,
    pub actor: String,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RevocationRecordError {
    UnsupportedVersion,
    WrongIssuer,
    WrongAudience,
    InvalidField(&'static str),
    InvalidWindow,
    WindowTooLong,
}

impl fmt::Display for RevocationRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => write!(formatter, "unsupported revocation record version"),
            Self::WrongIssuer => write!(formatter, "revocation issuer is outside this token class"),
            Self::WrongAudience => {
                write!(formatter, "revocation audience is outside this token class")
            }
            Self::InvalidField(field) => write!(formatter, "invalid revocation field {field}"),
            Self::InvalidWindow => write!(formatter, "invalid revocation time window"),
            Self::WindowTooLong => write!(formatter, "revocation time window exceeds policy"),
        }
    }
}

impl std::error::Error for RevocationRecordError {}

impl RevocationRecord {
    /// Revoke one exact token until its signed expiry. The caller supplies a
    /// content-free actor and reason suitable for immutable audit evidence.
    pub fn for_token(
        claims: &Claims,
        reason: &str,
        actor: &str,
        created_at: u64,
    ) -> Result<Self, RevocationRecordError> {
        if created_at < claims.iat || created_at >= claims.exp {
            return Err(RevocationRecordError::InvalidWindow);
        }
        let record = Self {
            version: REVOCATION_RECORD_VERSION,
            issuer: claims.iss.clone(),
            audience: claims.aud.clone(),
            tenant_id: claims.org_id.clone(),
            target: RevocationTarget::TokenId {
                jti: claims.jti.clone(),
            },
            reason: reason.trim().to_string(),
            actor: actor.trim().to_string(),
            created_at,
            expires_at: claims.exp,
        };
        record.validate()?;
        Ok(record)
    }

    /// Revoke every internal access token for one subject within one tenant for a
    /// bounded interval. This never crosses issuer, audience, or tenant scope.
    pub fn for_subject(
        tenant_id: &str,
        subject: &str,
        reason: &str,
        actor: &str,
        created_at: u64,
        expires_at: u64,
    ) -> Result<Self, RevocationRecordError> {
        let record = Self {
            version: REVOCATION_RECORD_VERSION,
            issuer: ISSUER.to_string(),
            audience: AUDIENCE.to_string(),
            tenant_id: tenant_id.trim().to_string(),
            target: RevocationTarget::Subject {
                subject: subject.trim().to_string(),
            },
            reason: reason.trim().to_string(),
            actor: actor.trim().to_string(),
            created_at,
            expires_at,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), RevocationRecordError> {
        if self.version != REVOCATION_RECORD_VERSION {
            return Err(RevocationRecordError::UnsupportedVersion);
        }
        if self.issuer != ISSUER {
            return Err(RevocationRecordError::WrongIssuer);
        }
        if self.audience != AUDIENCE {
            return Err(RevocationRecordError::WrongAudience);
        }
        validate_identifier("tenant_id", &self.tenant_id)?;
        validate_audit_text("reason", &self.reason, 256)?;
        validate_audit_text("actor", &self.actor, 128)?;
        match &self.target {
            RevocationTarget::TokenId { jti } => validate_identifier("jti", jti)?,
            RevocationTarget::Subject { subject } => validate_identifier("subject", subject)?,
        }
        if self.expires_at <= self.created_at {
            return Err(RevocationRecordError::InvalidWindow);
        }
        if self.expires_at - self.created_at > MAX_INTERNAL_REVOCATION_TTL_SECS {
            return Err(RevocationRecordError::WindowTooLong);
        }
        Ok(())
    }

    /// Stable opaque storage key. Length-prefixing every scope component avoids
    /// ambiguous concatenations, while hashing keeps subject/JTI values out of KV
    /// paths, logs, dashboards, and metrics.
    pub fn storage_key(&self) -> Result<String, RevocationRecordError> {
        self.validate()?;
        let (target_kind, target_value) = match &self.target {
            RevocationTarget::TokenId { jti } => ("token_id", jti.as_str()),
            RevocationTarget::Subject { subject } => ("subject", subject.as_str()),
        };
        let digest = scoped_revocation_digest(&[
            &self.issuer,
            &self.audience,
            &self.tenant_id,
            target_kind,
            target_value,
        ]);
        Ok(format!(
            "auth/revocations/v{}/{}",
            self.version,
            hex(&digest)
        ))
    }

    pub fn is_active_at(&self, now: u64) -> bool {
        self.validate().is_ok() && now >= self.created_at && now < self.expires_at
    }

    pub fn should_prune_at(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Match only the exact fixed token class and tenant. A record copied between
    /// organizations, issuers, or audiences cannot revoke an unrelated token.
    pub fn matches(&self, claims: &Claims, now: u64) -> bool {
        if !self.is_active_at(now)
            || self.issuer != claims.iss
            || self.audience != claims.aud
            || self.tenant_id != claims.org_id
        {
            return false;
        }
        match &self.target {
            RevocationTarget::TokenId { jti } => jti == &claims.jti,
            RevocationTarget::Subject { subject } => subject == &claims.sub,
        }
    }
}

/// Process-wide ES256 signer, loaded once.
struct Signer {
    encoding: EncodingKey,
    #[cfg(test)]
    decoding: DecodingKey,
    jwk: Value,
    kid: String,
}

static SIGNER: Lazy<Signer> = Lazy::new(Signer::load);

impl Signer {
    /// Load the signing key from `FIDUCIA_JWT_SIGNING_KEY` (PKCS#8 EC P-256 PEM,
    /// shared across replicas via a k8s secret). Unit tests may generate an
    /// isolated signer; production startup validates that this variable exists.
    fn load() -> Self {
        let secret = match std::env::var("FIDUCIA_JWT_SIGNING_KEY") {
            Ok(pem) if !pem.trim().is_empty() => SecretKey::from_pkcs8_pem(pem.trim())
                .expect("FIDUCIA_JWT_SIGNING_KEY must be a PKCS#8 EC (P-256) private key PEM"),
            #[cfg(test)]
            _ => generate_secret(),
            #[cfg(not(test))]
            _ => panic!("FIDUCIA_JWT_SIGNING_KEY must be configured"),
        };
        Self::from_secret(&secret)
    }

    fn from_secret(secret: &SecretKey) -> Self {
        let pkcs8 = secret
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode signing key to PKCS#8 PEM");
        let encoding = EncodingKey::from_ec_pem(pkcs8.as_bytes()).expect("ES256 encoding key");

        let pubkey = secret.public_key();
        #[cfg(test)]
        let decoding = {
            let spki = pubkey
                .to_public_key_pem(LineEnding::LF)
                .expect("encode public key to SPKI PEM");
            DecodingKey::from_ec_pem(spki.as_bytes()).expect("ES256 decoding key")
        };

        // Public JWK (uncompressed point -> x/y) for /.well-known/jwks.json.
        let point = pubkey.to_encoded_point(false); // 0x04 || x || y
        let x = point.x().expect("P-256 x coordinate");
        let y = point.y().expect("P-256 y coordinate");
        let b64u = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let kid = {
            let mut hasher = Sha256::new();
            hasher.update(x);
            hasher.update(y);
            hex16(&hasher.finalize())
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
            #[cfg(test)]
            decoding,
            jwk,
            kid,
        }
    }
}

/// Validate and initialize the production signer before binding the HTTP port.
/// This prevents a replica from starting with an identity that disappears on
/// restart or differs from its peers.
pub fn validate_config() -> Result<(), String> {
    let pem = std::env::var("FIDUCIA_JWT_SIGNING_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "FIDUCIA_JWT_SIGNING_KEY must be configured".to_string())?;
    SecretKey::from_pkcs8_pem(pem.trim())
        .map_err(|error| format!("FIDUCIA_JWT_SIGNING_KEY is invalid: {error}"))?;
    Lazy::force(&SIGNER);
    Ok(())
}

/// Mint a short-lived JWT for an introspected key/session.
///
/// This compatibility wrapper is fail-closed: a programmer request outside the
/// hard TTL policy or an entropy failure aborts the handler rather than issuing a
/// weaker credential. New call sites should prefer [`try_mint_token`].
pub fn mint_token(org_id: &OrgId, scopes: &[String], ttl_secs: u64) -> String {
    try_mint_token(org_id, scopes, ttl_secs)
        .unwrap_or_else(|error| panic!("refusing to mint fiducia access token: {error}"))
}

pub fn try_mint_token(
    org_id: &OrgId,
    scopes: &[String],
    ttl_secs: u64,
) -> Result<String, MintError> {
    mint_with(&SIGNER, org_id, scopes, ttl_secs)
}

fn mint_with(
    signer: &Signer,
    org_id: &OrgId,
    scopes: &[String],
    ttl_secs: u64,
) -> Result<String, MintError> {
    validate_ttl(ttl_secs)?;
    let now = now_secs();
    let claims = Claims {
        sub: org_id.clone(),
        org_id: org_id.clone(),
        scopes: scopes.to_vec(),
        iss: ISSUER.to_string(),
        aud: AUDIENCE.to_string(),
        iat: now,
        exp: now.saturating_add(ttl_secs),
        jti: random_jti()?,
    };
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(signer.kid.clone());
    encode(&header, &claims, &signer.encoding).map_err(|_| MintError::EntropyUnavailable)
}

fn validate_ttl(ttl_secs: u64) -> Result<(), MintError> {
    if !(1..=MAX_ACCESS_TOKEN_TTL_SECS).contains(&ttl_secs) {
        return Err(MintError::InvalidTtl {
            requested: ttl_secs,
            maximum: MAX_ACCESS_TOKEN_TTL_SECS,
        });
    }
    Ok(())
}

fn random_jti() -> Result<String, MintError> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| MintError::EntropyUnavailable)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Public keys for offline JWT verification by the edge / LB / nodes.
pub fn jwks() -> Value {
    json!({ "keys": [SIGNER.jwk.clone()] })
}

#[cfg(test)]
fn verify_with(signer: &Signer, token: &str) -> Option<Claims> {
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[AUDIENCE]);
    validation.validate_exp = true;
    decode::<Claims>(token, &signer.decoding, &validation)
        .ok()
        .map(|data| data.claims)
}

#[cfg(test)]
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

fn validate_identifier(field: &'static str, value: &str) -> Result<(), RevocationRecordError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(RevocationRecordError::InvalidField(field));
    }
    Ok(())
}

fn validate_audit_text(
    field: &'static str,
    value: &str,
    max_len: usize,
) -> Result<(), RevocationRecordError> {
    let value = value.trim();
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        return Err(RevocationRecordError::InvalidField(field));
    }
    Ok(())
}

fn scoped_revocation_digest(parts: &[&str]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.finalize().into()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn hex16(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> Signer {
        Signer::from_secret(&generate_secret())
    }

    fn claims(tenant: &str, subject: &str, jti: &str, iat: u64, exp: u64) -> Claims {
        Claims {
            sub: subject.to_string(),
            org_id: tenant.to_string(),
            scopes: vec!["locks:write".to_string()],
            iss: ISSUER.to_string(),
            aud: AUDIENCE.to_string(),
            iat,
            exp,
            jti: jti.to_string(),
        }
    }

    #[test]
    fn mint_then_verify_offline_roundtrips() {
        let signer = signer();
        let scopes = vec!["locks:write".to_string(), "kv:read".to_string()];
        let token = mint_with(&signer, &"org_123".to_string(), &scopes, 900).unwrap();

        let claims = verify_with(&signer, &token).expect("valid token verifies");
        assert_eq!(claims.org_id, "org_123");
        assert_eq!(claims.sub, "org_123");
        assert_eq!(claims.scopes, scopes);
        assert_eq!(claims.iss, ISSUER);
        assert_eq!(claims.aud, AUDIENCE);
        assert!(claims.exp > claims.iat);
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn separately_minted_tokens_have_distinct_ids() {
        let signer = signer();
        let first = mint_with(&signer, &"org_a".to_string(), &[], 900).unwrap();
        let second = mint_with(&signer, &"org_a".to_string(), &[], 900).unwrap();
        let first = verify_with(&signer, &first).unwrap();
        let second = verify_with(&signer, &second).unwrap();
        assert_ne!(first.jti, second.jti);
    }

    #[test]
    fn token_ttl_is_strictly_bounded() {
        let signer = signer();
        for ttl in [0, MAX_ACCESS_TOKEN_TTL_SECS + 1, u64::MAX] {
            assert!(matches!(
                mint_with(&signer, &"org_a".to_string(), &[], ttl),
                Err(MintError::InvalidTtl { .. })
            ));
        }
        assert!(mint_with(
            &signer,
            &"org_a".to_string(),
            &[],
            MAX_ACCESS_TOKEN_TTL_SECS,
        )
        .is_ok());
    }

    #[test]
    fn jwks_exposes_one_es256_signing_key() {
        let signer = signer();
        assert_eq!(signer.jwk["kty"], "EC");
        assert_eq!(signer.jwk["crv"], "P-256");
        assert_eq!(signer.jwk["alg"], "ES256");
        assert_eq!(signer.jwk["use"], "sig");
        assert!(signer.jwk["x"].as_str().is_some_and(|x| !x.is_empty()));
        assert!(signer.jwk["y"].as_str().is_some_and(|y| !y.is_empty()));
        assert_eq!(signer.jwk["kid"], signer.kid.as_str());
    }

    #[test]
    fn a_token_from_a_different_key_is_rejected() {
        let token = mint_with(&signer(), &"org_a".to_string(), &[], 900).unwrap();
        // A verifier holding a different key must reject it (signature mismatch).
        assert!(verify_with(&signer(), &token).is_none());
    }

    #[test]
    fn tampered_or_garbage_tokens_are_rejected() {
        let signer = signer();
        let token =
            mint_with(&signer, &"org_a".to_string(), &["kv:read".to_string()], 900).unwrap();
        assert!(
            verify_with(&signer, &token).is_some(),
            "sanity: intact verifies"
        );

        // Corrupt one signature character: offline verification must fail
        // closed rather than accept a forged/bit-flipped credential.
        let (head, signature) = token.rsplit_once('.').expect("JWT has a signature");
        let mut signature_bytes: Vec<u8> = signature.bytes().collect();
        signature_bytes[0] = if signature_bytes[0] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let tampered = format!("{head}.{}", String::from_utf8(signature_bytes).unwrap());
        assert!(
            verify_with(&signer, &tampered).is_none(),
            "tampered signature must be rejected"
        );

        // Structurally-garbage inputs never verify either.
        for garbage in ["", "not-a-jwt", "a.b", "a.b.c", &token[..token.len() - 20]] {
            assert!(
                verify_with(&signer, garbage).is_none(),
                "accepted {garbage:?}"
            );
        }
    }

    #[test]
    fn expired_token_is_rejected() {
        // Build a token that expired 2 min ago - beyond the verifier's default
        // 60s clock-skew leeway - and confirm it's rejected.
        let signer = signer();
        let now = now_secs();
        let claims = Claims {
            sub: "org_a".to_string(),
            org_id: "org_a".to_string(),
            scopes: vec![],
            iss: ISSUER.to_string(),
            aud: AUDIENCE.to_string(),
            iat: now.saturating_sub(200),
            exp: now.saturating_sub(120),
            jti: "expired-token-id".to_string(),
        };
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(signer.kid.clone());
        let token = encode(&header, &claims, &signer.encoding).expect("sign");
        assert!(verify_with(&signer, &token).is_none());
    }

    #[test]
    fn exact_token_revocation_is_scoped_and_expires() {
        let token = claims("org_a", "org_a", "token-1", 100, 1_000);
        let record = RevocationRecord::for_token(&token, "compromised", "admin:42", 500)
            .expect("valid record");

        assert!(record.matches(&token, 500));
        assert!(record.matches(&token, 999));
        assert!(!record.matches(&token, 1_000));
        assert!(record.should_prune_at(1_000));
        assert!(!record.matches(&claims("org_a", "org_a", "token-2", 100, 1_000), 500,));
        assert!(!record.matches(&claims("org_b", "org_a", "token-1", 100, 1_000), 500,));
    }

    #[test]
    fn subject_revocation_never_crosses_tenants() {
        let record =
            RevocationRecord::for_subject("org_a", "user_1", "session reset", "admin:42", 100, 200)
                .unwrap();
        assert!(record.matches(&claims("org_a", "user_1", "token-a", 50, 200), 150,));
        assert!(!record.matches(&claims("org_b", "user_1", "token-b", 50, 200), 150,));
        assert!(!record.matches(&claims("org_a", "user_2", "token-c", 50, 200), 150,));
    }

    #[test]
    fn storage_keys_are_opaque_deterministic_and_collision_scoped() {
        let first =
            RevocationRecord::for_subject("org_a", "user_1", "session reset", "admin:42", 100, 200)
                .unwrap();
        let retry = first.clone();
        let other_tenant =
            RevocationRecord::for_subject("org_b", "user_1", "session reset", "admin:42", 100, 200)
                .unwrap();

        let key = first.storage_key().unwrap();
        assert_eq!(key, retry.storage_key().unwrap());
        assert_ne!(key, other_tenant.storage_key().unwrap());
        assert!(key.starts_with("auth/revocations/v1/"));
        assert!(!key.contains("org_a"));
        assert!(!key.contains("user_1"));
    }

    #[test]
    fn records_are_versioned_serializable_and_bounded() {
        let record =
            RevocationRecord::for_subject("org_a", "user_1", "session reset", "admin:42", 100, 200)
                .unwrap();
        let encoded = serde_json::to_string(&record).unwrap();
        let decoded: RevocationRecord = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(decoded.version, REVOCATION_RECORD_VERSION);

        assert_eq!(
            RevocationRecord::for_subject(
                "org_a",
                "user_1",
                "session reset",
                "admin:42",
                100,
                100 + MAX_INTERNAL_REVOCATION_TTL_SECS + 1,
            ),
            Err(RevocationRecordError::WindowTooLong),
        );
    }
}
