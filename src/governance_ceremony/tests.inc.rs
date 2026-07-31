#[cfg(test)]
mod tests {
    use super::*;

    fn test_codec() -> ProtectedStateCodec {
        ProtectedStateCodec::new(
            "test-key",
            1,
            std::collections::BTreeMap::from([("test-key".to_string(), [9_u8; 32])]),
        )
        .expect("valid test protected-state codec")
    }

    fn test_config() -> GovernanceConfig {
        GovernanceConfig {
            enabled: true,
            rp_id: Some("auth.fiducia.test".to_string()),
            origin: Some("https://auth.fiducia.test".to_string()),
            allowed_tenants: BTreeSet::from(["company-123".to_string()]),
            ttl_ms: 300_000,
            ceremony_secret: Some(vec![7u8; 32]),
            verifier_secret: Some("v".repeat(32)),
            protected_state_codec: Some(test_codec()),
        }
    }

    fn binding() -> ApprovalBinding {
        ApprovalBinding {
            tenant_id: "company-123".to_string(),
            participant_id: "founder-a".to_string(),
            proposal_id: "proposal-1".to_string(),
            canonical_proposal_hash: format!("sha256:{}", "a".repeat(64)),
            policy_id: "policy-1".to_string(),
            policy_version: 1,
            policy_hash: format!("sha256:{}", "b".repeat(64)),
            continuity_state: "normal".to_string(),
            continuity_generation: 7,
            rp_id: "auth.fiducia.test".to_string(),
            origin: "https://auth.fiducia.test".to_string(),
            credential_generation: 3,
            activation_credential_id: None,
            created_at_ms: 1_000,
            expires_at_ms: 301_000,
        }
    }

    fn record() -> CeremonyRecord {
        let binding = binding();
        let binding_hash = binding.binding_hash().unwrap();
        let challenge = derive_challenge(&[7u8; 32], "gcer_test", &binding_hash).unwrap();
        CeremonyRecord {
            contract_version: CONTRACT_VERSION.to_string(),
            object_kind: OBJECT_KIND.to_string(),
            ceremony_id: "gcer_test".to_string(),
            binding,
            binding_hash,
            challenge_hash: sha256_bytes(challenge.as_bytes()),
            status: CeremonyStatus::Pending,
            claim_id: None,
            fencing_token: 0,
            claimed_at_ms: None,
            terminal: None,
        }
    }

    fn completion(record: &CeremonyRecord, claim_id: &str, token: u64) -> CompleteVerifiedRequest {
        CompleteVerifiedRequest {
            tenant_id: record.binding.tenant_id.clone(),
            participant_id: record.binding.participant_id.clone(),
            claim_id: claim_id.to_string(),
            fencing_token: token,
            binding_hash: record.binding_hash.clone(),
            challenge_hash: record.challenge_hash.clone(),
            credential_id: "credential-a".to_string(),
            credential_generation: record.binding.credential_generation,
            assertion_receipt_hash: format!("sha256:{}", "c".repeat(64)),
            user_verified: true,
        }
    }

    #[test]
    fn feature_defaults_disabled_and_ttl_is_bounded() {
        assert!(!parse_strict_bool(None).unwrap());
        assert!(!parse_strict_bool(Some("false")).unwrap());
        assert!(parse_strict_bool(Some("true")).unwrap());
        assert!(parse_strict_bool(Some("yes")).is_err());
        assert_eq!(parse_ttl_secs(None).unwrap(), DEFAULT_TTL_SECS);
        assert!(parse_ttl_secs(Some("59")).is_err());
        assert!(parse_ttl_secs(Some("901")).is_err());
    }

    #[test]
    fn protected_state_keyring_requires_one_active_32_byte_key() {
        let encoded = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let keys = serde_json::json!({ "key-1": encoded }).to_string();
        let codec = parse_protected_state_codec("key-1", "3", &keys).unwrap();
        assert_eq!(codec.active_key_id(), "key-1");
        assert_eq!(codec.keyring_version(), 3);

        assert!(parse_protected_state_codec("missing", "3", &keys).is_err());
        assert!(parse_protected_state_codec("key-1", "0", &keys).is_err());
        assert!(parse_protected_state_codec("key-1", "3", "{}").is_err());
        assert!(parse_protected_state_codec(
            "key-1",
            "3",
            &serde_json::json!({ "key-1": URL_SAFE_NO_PAD.encode([7_u8; 31]) }).to_string(),
        )
        .is_err());
    }

    #[test]
    fn governance_config_debug_output_redacts_all_secret_material() {
        let config = test_config();
        let rendered = format!("{config:?}");
        assert!(rendered.contains("test-key"));
        assert!(rendered.contains("keyring_version"));
        assert!(!rendered.contains(&"v".repeat(32)));
        assert!(!rendered.contains("[7, 7, 7"));
        assert!(!rendered.contains("[9, 9, 9"));
    }

    #[test]
    fn challenge_is_deterministic_but_bound_to_the_exact_proposal() {
        let config = test_config();
        let first = binding();
        let first_hash = first.binding_hash().unwrap();
        let first_challenge = derive_challenge(
            config.ceremony_secret().unwrap(),
            "gcer_1",
            &first_hash,
        )
        .unwrap();
        assert_eq!(
            first_challenge,
            derive_challenge(config.ceremony_secret().unwrap(), "gcer_1", &first_hash).unwrap()
        );
        let mut changed = first;
        changed.continuity_generation += 1;
        assert_ne!(
            first_challenge,
            derive_challenge(
                config.ceremony_secret().unwrap(),
                "gcer_1",
                &changed.binding_hash().unwrap(),
            )
            .unwrap()
        );
    }

    #[test]
    fn one_claim_wins_and_higher_fencing_can_take_over() {
        let original = record();
        let (claimed, replayed, taken_over) = claim_record(original, "claim-a", 11, 2_000).unwrap();
        assert!(!replayed);
        assert!(!taken_over);
        let (same, replayed, taken_over) = claim_record(claimed.clone(), "claim-a", 11, 2_001).unwrap();
        assert!(replayed);
        assert!(!taken_over);
        assert_eq!(same.claim_id.as_deref(), Some("claim-a"));
        assert!(matches!(
            claim_record(claimed.clone(), "claim-b", 11, 2_002),
            Err(CeremonyError::AlreadyClaimed)
        ));
        let (taken, replayed, taken_over) = claim_record(claimed, "claim-b", 12, 2_003).unwrap();
        assert!(!replayed);
        assert!(taken_over);
        assert_eq!(taken.claim_id.as_deref(), Some("claim-b"));
        assert_eq!(taken.fencing_token, 12);
    }

    #[test]
    fn stale_claimant_cannot_finish_after_takeover() {
        let (claimed, _, _) = claim_record(record(), "claim-a", 11, 2_000).unwrap();
        let (taken, _, _) = claim_record(claimed, "claim-b", 12, 2_001).unwrap();
        assert!(matches!(
            complete_record(taken.clone(), &completion(&taken, "claim-a", 11), 2_002),
            Err(CeremonyError::StaleFencing)
        ));
        let completed = complete_record(taken.clone(), &completion(&taken, "claim-b", 12), 2_002)
            .unwrap();
        assert_eq!(completed.status, CeremonyStatus::Completed);
        assert!(completed.terminal.is_some());
    }

    #[test]
    fn binding_mutation_and_self_activation_fail_closed() {
        let (claimed, _, _) = claim_record(record(), "claim-a", 11, 2_000).unwrap();
        let mut mutated = completion(&claimed, "claim-a", 11);
        mutated.binding_hash = format!("sha256:{}", "d".repeat(64));
        assert!(matches!(
            complete_record(claimed.clone(), &mutated, 2_001),
            Err(CeremonyError::Conflict)
        ));

        let mut self_activation = claimed;
        self_activation.binding.activation_credential_id = Some("credential-a".to_string());
        assert!(matches!(
            complete_record(
                self_activation.clone(),
                &completion(&self_activation, "claim-a", 11),
                2_001,
            ),
            Err(CeremonyError::Unauthorized)
        ));
    }

    #[test]
    fn secret_comparison_uses_fixed_length_digests() {
        assert!(constant_time_secret_matches(&"x".repeat(32), &"x".repeat(32)));
        assert!(!constant_time_secret_matches(&"x".repeat(32), &"y".repeat(32)));
    }
}
