//! DEN-1391 production-gate regression tests for the public revocation contract.
//!
//! These tests deliberately stay outside `src/` and use only the reusable API a
//! real verifier consumes. They are an automated source-level slice of AUTH-005:
//! issuer, audience, tenant, subject, and token identities must not share
//! revocation authority; an unavailable authority must never become an allow.
//!
//! Passing this file does not prove the production propagation SLO. Exact-release
//! multi-process cache, ingress, partition, restart, and timing evidence remains
//! required before AUTH-005 can be marked `passed` in the launch gate.

use std::future::Future;
use std::sync::{Arc, Mutex};

use fiducia_auth::cache::RevocationCache;
use fiducia_auth::gate::{
    Authorization, RevocationAuthority, RevocationGate, Unavailable, DEFAULT_REFRESH_TIMEOUT,
};
use fiducia_auth::revocation::{RevocationDecision, RevocationError};
use fiducia_auth::token::{Claims, RevocationRecord, RevocationRecordError};

const CREATED_AT: u64 = 1_100;
const EXPIRES_AT: u64 = 2_000;

fn claims(tenant: &str, subject: &str, jti: &str) -> Claims {
    Claims {
        sub: subject.to_string(),
        org_id: tenant.to_string(),
        scopes: vec!["locks:write".to_string(), "kv:read".to_string()],
        iss: "fiducia-auth".to_string(),
        aud: "fiducia-api".to_string(),
        iat: 1_000,
        exp: EXPIRES_AT,
        jti: jti.to_string(),
    }
}

#[derive(Clone, Default)]
struct RecordAuthority {
    records: Arc<Mutex<Vec<RevocationRecord>>>,
    unavailable: Arc<Mutex<bool>>,
}

impl RecordAuthority {
    fn with_records(records: Vec<RevocationRecord>) -> Self {
        Self {
            records: Arc::new(Mutex::new(records)),
            unavailable: Arc::new(Mutex::new(false)),
        }
    }

    fn unavailable() -> Self {
        Self {
            records: Arc::new(Mutex::new(Vec::new())),
            unavailable: Arc::new(Mutex::new(true)),
        }
    }
}

impl RevocationAuthority for RecordAuthority {
    fn check_revocation(
        &self,
        claims: &Claims,
        now: u64,
    ) -> impl Future<Output = Result<RevocationDecision, RevocationError>> + Send {
        let claims = claims.clone();
        let records = self.records.clone();
        let unavailable = self.unavailable.clone();
        async move {
            if *unavailable.lock().expect("unavailable lock") {
                return Err(RevocationError::CasRetriesExhausted);
            }
            let revoked = records
                .lock()
                .expect("records lock")
                .iter()
                .any(|record| record.matches(&claims, now));
            Ok(RevocationDecision {
                revoked,
                matched_target: None,
                generation: None,
                expires_at: None,
            })
        }
    }
}

#[test]
fn exact_token_record_is_bound_to_the_full_token_class_and_tenant() {
    let original = claims("tenant-a", "subject-a", "token-a");
    let record = RevocationRecord::for_token(
        &original,
        "credential compromise",
        "security-operator",
        CREATED_AT,
    )
    .expect("valid exact-token record");

    assert!(record.matches(&original, CREATED_AT));
    assert!(record.matches(&original, EXPIRES_AT - 1));
    assert!(!record.matches(&original, EXPIRES_AT));

    let mut wrong_tenant = original.clone();
    wrong_tenant.org_id = "tenant-b".to_string();
    assert!(!record.matches(&wrong_tenant, CREATED_AT));

    let mut wrong_subject = original.clone();
    wrong_subject.sub = "subject-b".to_string();
    // Exact-token records intentionally identify the token by JTI. Subject-level
    // quarantine is represented by a distinct record type below.
    assert!(record.matches(&wrong_subject, CREATED_AT));

    let mut wrong_jti = original.clone();
    wrong_jti.jti = "token-b".to_string();
    assert!(!record.matches(&wrong_jti, CREATED_AT));

    let mut wrong_issuer = original.clone();
    wrong_issuer.iss = "attacker-auth".to_string();
    assert!(!record.matches(&wrong_issuer, CREATED_AT));

    let mut wrong_audience = original;
    wrong_audience.aud = "fiducia-admin".to_string();
    assert!(!record.matches(&wrong_audience, CREATED_AT));
}

#[test]
fn subject_record_is_tenant_scoped_and_time_bounded() {
    let record = RevocationRecord::for_subject(
        "tenant-a",
        "subject-a",
        "account containment",
        "security-operator",
        CREATED_AT,
        EXPIRES_AT,
    )
    .expect("valid subject record");

    assert!(record.matches(
        &claims("tenant-a", "subject-a", "first-token"),
        CREATED_AT
    ));
    assert!(record.matches(
        &claims("tenant-a", "subject-a", "replacement-token"),
        EXPIRES_AT - 1
    ));
    assert!(!record.matches(
        &claims("tenant-b", "subject-a", "first-token"),
        CREATED_AT
    ));
    assert!(!record.matches(
        &claims("tenant-a", "subject-b", "first-token"),
        CREATED_AT
    ));
    assert!(!record.matches(
        &claims("tenant-a", "subject-a", "first-token"),
        CREATED_AT - 1
    ));
    assert!(!record.matches(
        &claims("tenant-a", "subject-a", "first-token"),
        EXPIRES_AT
    ));
}

#[test]
fn storage_keys_are_opaque_and_domain_separated() {
    let token_claims = claims("tenant-visible", "subject-visible", "jti-visible");
    let exact = RevocationRecord::for_token(
        &token_claims,
        "credential compromise",
        "security-operator",
        CREATED_AT,
    )
    .expect("valid exact-token record");
    let subject = RevocationRecord::for_subject(
        "tenant-visible",
        "subject-visible",
        "account containment",
        "security-operator",
        CREATED_AT,
        EXPIRES_AT,
    )
    .expect("valid subject record");
    let other_tenant = RevocationRecord::for_subject(
        "tenant-other",
        "subject-visible",
        "account containment",
        "security-operator",
        CREATED_AT,
        EXPIRES_AT,
    )
    .expect("valid other-tenant record");

    let exact_key = exact.storage_key().expect("exact storage key");
    let subject_key = subject.storage_key().expect("subject storage key");
    let other_tenant_key = other_tenant.storage_key().expect("other storage key");

    for key in [&exact_key, &subject_key, &other_tenant_key] {
        assert!(key.starts_with("auth/revocations/v1/"));
        assert_eq!(key.len(), "auth/revocations/v1/".len() + 64);
        assert!(!key.contains("tenant-visible"));
        assert!(!key.contains("tenant-other"));
        assert!(!key.contains("subject-visible"));
        assert!(!key.contains("jti-visible"));
    }
    assert_ne!(exact_key, subject_key, "target kind must be domain separated");
    assert_ne!(subject_key, other_tenant_key, "tenant must be domain separated");
}

#[test]
fn malformed_token_class_records_fail_validation() {
    let original = claims("tenant-a", "subject-a", "token-a");
    let mut wrong_issuer = RevocationRecord::for_token(
        &original,
        "credential compromise",
        "security-operator",
        CREATED_AT,
    )
    .expect("valid exact-token record");
    wrong_issuer.issuer = "attacker-auth".to_string();
    assert_eq!(
        wrong_issuer.validate(),
        Err(RevocationRecordError::WrongIssuer)
    );

    let mut wrong_audience = RevocationRecord::for_token(
        &original,
        "credential compromise",
        "security-operator",
        CREATED_AT,
    )
    .expect("valid exact-token record");
    wrong_audience.audience = "fiducia-admin".to_string();
    assert_eq!(
        wrong_audience.validate(),
        Err(RevocationRecordError::WrongAudience)
    );
}

#[tokio::test]
async fn revocation_gate_does_not_poison_an_equal_jti_in_another_tenant() {
    let tenant_a = claims("tenant-a", "subject-a", "shared-jti");
    let tenant_b = claims("tenant-b", "subject-b", "shared-jti");
    let record = RevocationRecord::for_token(
        &tenant_a,
        "credential compromise",
        "security-operator",
        CREATED_AT,
    )
    .expect("valid exact-token record");
    let gate = RevocationGate::new(
        RevocationCache::new(30, 128),
        RecordAuthority::with_records(vec![record]),
        DEFAULT_REFRESH_TIMEOUT,
    );

    assert_eq!(
        gate.authorize(&tenant_a, CREATED_AT).await,
        Authorization::Revoked
    );
    assert_eq!(
        gate.authorize(&tenant_b, CREATED_AT).await,
        Authorization::Allowed,
        "equal JTI in another tenant must not share revocation state"
    );
}

#[tokio::test]
async fn cold_gate_fails_closed_when_authority_is_unavailable() {
    let gate = RevocationGate::new(
        RevocationCache::new(30, 128),
        RecordAuthority::unavailable(),
        DEFAULT_REFRESH_TIMEOUT,
    );
    let decision = gate
        .authorize(&claims("tenant-a", "subject-a", "token-a"), CREATED_AT)
        .await;

    assert_eq!(
        decision,
        Authorization::Unavailable(Unavailable::RefreshFailed)
    );
    assert_ne!(decision, Authorization::Allowed);
}
