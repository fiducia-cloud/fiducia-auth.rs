use super::*;

fn mutation<'a>(key: &'a str) -> MutationIdentity<'a> {
    MutationIdentity::new("admin:test", key)
}

fn claims(tenant: &str, subject: &str, jti: &str) -> Claims {
    Claims {
        sub: subject.to_string(),
        org_id: tenant.to_string(),
        scopes: vec!["locks:write".to_string()],
        iss: INTERNAL_ISSUER.to_string(),
        aud: INTERNAL_AUDIENCE.to_string(),
        iat: 50,
        exp: 900,
        jti: jti.to_string(),
    }
}

fn token_request(reason: &str) -> RevokeRequest {
    RevokeRequest::TokenId {
        claims: Box::new(claims("org_a", "subject_a", "token_1")),
        reason: reason.to_string(),
    }
}

#[test]
fn selector_keys_match_the_canonical_record_contract() {
    let token_claims = claims("org_a", "subject_a", "token_1");
    let token = RevocationRecord::for_token(&token_claims, "incident", "admin:test", 100).unwrap();
    assert_eq!(
        RevocationSelector::TokenId {
            tenant_id: "org_a".to_string(),
            jti: "token_1".to_string(),
        }
        .storage_key()
        .unwrap(),
        token.storage_key().unwrap()
    );

    let subject = RevocationRecord::for_subject(
        "org_a",
        "subject_a",
        "incident",
        "admin:test",
        100,
        800,
    )
    .unwrap();
    assert_eq!(
        RevocationSelector::Subject {
            tenant_id: "org_a".to_string(),
            subject: "subject_a".to_string(),
        }
        .storage_key()
        .unwrap(),
        subject.storage_key().unwrap()
    );
}

#[tokio::test]
async fn exact_token_revocation_is_tenant_scoped_and_idempotent() {
    let store = RevocationStore::in_memory();
    let first = store
        .revoke(token_request("incident"), mutation("request-1"), 100)
        .await
        .unwrap();
    let replay = store
        .revoke(token_request("incident"), mutation("request-1"), 200)
        .await
        .unwrap();
    assert_eq!(first, replay);
    assert_eq!(first.generation, 1);
    assert_eq!(first.status, RevocationStatus::Active);

    assert!(
        store
            .check(&claims("org_a", "subject_a", "token_1"), 200)
            .await
            .unwrap()
            .revoked
    );
    assert!(
        !store
            .check(&claims("org_b", "subject_a", "token_1"), 200)
            .await
            .unwrap()
            .revoked
    );
    assert!(
        !store
            .check(&claims("org_a", "subject_a", "token_2"), 200)
            .await
            .unwrap()
            .revoked
    );
}

#[tokio::test]
async fn idempotency_reuse_with_different_intent_is_rejected() {
    let store = RevocationStore::in_memory();
    store
        .revoke(token_request("first"), mutation("request-1"), 100)
        .await
        .unwrap();
    let error = store
        .revoke(token_request("second"), mutation("request-1"), 100)
        .await
        .unwrap_err();
    assert!(matches!(error, RevocationError::IdempotencyConflict));
}

#[tokio::test]
async fn subject_revocation_matches_only_one_tenant_and_subject() {
    let store = RevocationStore::in_memory();
    store
        .revoke(
            RevokeRequest::Subject {
                tenant_id: "org_a".to_string(),
                subject: "subject_a".to_string(),
                expires_at: 800,
                reason: "incident".to_string(),
            },
            mutation("request-1"),
            100,
        )
        .await
        .unwrap();

    let decision = store
        .check(&claims("org_a", "subject_a", "token_9"), 200)
        .await
        .unwrap();
    assert!(decision.revoked);
    assert_eq!(decision.matched_target, Some(MatchedTarget::Subject));
    assert!(
        !store
            .check(&claims("org_a", "subject_b", "token_9"), 200)
            .await
            .unwrap()
            .revoked
    );
    assert!(
        !store
            .check(&claims("org_b", "subject_a", "token_9"), 200)
            .await
            .unwrap()
            .revoked
    );
}

#[tokio::test]
async fn lift_is_append_only_and_exact_retries_return_original_generation() {
    let store = RevocationStore::in_memory();
    store
        .revoke(token_request("incident"), mutation("revoke-1"), 100)
        .await
        .unwrap();
    let selector = token_request("unused").selector();
    let lifted = store
        .lift(
            LiftRequest {
                selector: selector.clone(),
                reason: "false positive".to_string(),
            },
            mutation("lift-1"),
            200,
        )
        .await
        .unwrap();
    assert_eq!(lifted.generation, 2);
    assert_eq!(lifted.status, RevocationStatus::Lifted);
    assert!(
        !store
            .check(&claims("org_a", "subject_a", "token_1"), 200)
            .await
            .unwrap()
            .revoked
    );

    let replay = store
        .lift(
            LiftRequest {
                selector,
                reason: "false positive".to_string(),
            },
            mutation("lift-1"),
            300,
        )
        .await
        .unwrap();
    assert_eq!(replay, lifted);
}

#[tokio::test]
async fn expired_records_do_not_revoke_and_cannot_be_lifted() {
    let store = RevocationStore::in_memory();
    store
        .revoke(token_request("incident"), mutation("revoke-1"), 100)
        .await
        .unwrap();
    assert!(
        !store
            .check(&claims("org_a", "subject_a", "token_1"), 900)
            .await
            .unwrap()
            .revoked
    );
    let error = store
        .lift(
            LiftRequest {
                selector: token_request("unused").selector(),
                reason: "too late".to_string(),
            },
            mutation("lift-1"),
            900,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, RevocationError::NotActive));
}

#[tokio::test]
async fn excessive_or_wrong_class_claims_fail_closed() {
    let store = RevocationStore::in_memory();
    let mut too_long = claims("org_a", "subject_a", "token_1");
    too_long.exp = too_long.iat + MAX_ACCESS_TOKEN_TTL_SECS + 1;
    assert!(matches!(
        store.check(&too_long, 100).await,
        Err(RevocationError::InvalidClaims)
    ));

    let mut wrong_audience = claims("org_a", "subject_a", "token_1");
    wrong_audience.aud = "other-api".to_string();
    assert!(matches!(
        store.check(&wrong_audience, 100).await,
        Err(RevocationError::InvalidClaims)
    ));
}

#[test]
fn ledger_rejects_hash_chain_tampering() {
    let request = token_request("incident");
    let selector = request.selector();
    let record = request.record("admin:test", 100).unwrap();
    let mut ledger = RevocationLedger::new(
        selector.storage_key().unwrap(),
        record,
        mutation_hash("revoke", "key", "admin:test", "request-1"),
        request.request_hash(),
    )
    .unwrap();
    let replacement = if ledger.events[0].event_hash.starts_with('0') {
        "1"
    } else {
        "0"
    };
    ledger.events[0]
        .event_hash
        .replace_range(0..1, replacement);
    assert!(matches!(
        ledger.validate(),
        Err(RevocationError::InvalidLedger)
    ));
}

#[tokio::test]
async fn transition_growth_is_bounded_without_silent_truncation() {
    let store = RevocationStore::in_memory();
    for index in 0..MAX_TRANSITIONS_PER_TARGET {
        let reason = format!("incident-{index}");
        let key = format!("request-{index}");
        store
            .revoke(token_request(&reason), mutation(&key), 100 + index as u64)
            .await
            .unwrap();
    }
    let error = store
        .revoke(
            token_request("one-too-many"),
            mutation("request-overflow"),
            200,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, RevocationError::TransitionLimit));
}
