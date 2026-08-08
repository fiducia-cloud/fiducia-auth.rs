const CEREMONY_ID_PREFIX: &str = "gcer_";
const SHA256_URN_PREFIX: &str = "sha256:";
const SHA256_HEX_BYTES: usize = 64;

fn validate_ceremony_id(value: &str) -> Result<(), CeremonyError> {
    match value.strip_prefix(CEREMONY_ID_PREFIX) {
        Some(hex) if hex.len() == SHA256_HEX_BYTES && hex.bytes().all(is_lower_hex) => Ok(()),
        _ => Err(CeremonyError::InvalidRequest("invalid_ceremony_id")),
    }
}

fn validate_canonical_sha256_urn(
    value: &str,
    _field: &'static str,
) -> Result<(), CeremonyError> {
    match value.strip_prefix(SHA256_URN_PREFIX) {
        Some(hex) if hex.len() == SHA256_HEX_BYTES && hex.bytes().all(is_lower_hex) => Ok(()),
        _ => Err(CeremonyError::InvalidRequest("invalid_sha256_urn")),
    }
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
}

fn corrupt(reason: &'static str) -> CeremonyError {
    CeremonyError::ProtectedState(reason)
}

fn stored<T>(result: Result<T, CeremonyError>, reason: &'static str) -> Result<T, CeremonyError> {
    result.map_err(|_| corrupt(reason))
}

impl CeremonyRecord {
    fn validate_integrity(&self, expected_id: &str) -> Result<(), CeremonyError> {
        stored(validate_ceremony_id(expected_id), "stored ceremony key is invalid")?;
        stored(
            validate_ceremony_id(&self.ceremony_id),
            "stored ceremony id is invalid",
        )?;
        if self.ceremony_id != expected_id {
            return Err(corrupt("stored ceremony id does not match its key"));
        }
        if self.contract_version != CONTRACT_VERSION || self.object_kind != OBJECT_KIND {
            return Err(corrupt("stored ceremony contract metadata is unsupported"));
        }

        stored(self.binding.validate(), "stored ceremony binding is invalid")?;
        for (hash, field, reason) in [
            (
                self.binding.canonical_proposal_hash.as_str(),
                "canonical_proposal_hash",
                "stored proposal hash is not canonical",
            ),
            (
                self.binding.policy_hash.as_str(),
                "policy_hash",
                "stored policy hash is not canonical",
            ),
            (
                self.binding_hash.as_str(),
                "binding_hash",
                "stored binding hash is not canonical",
            ),
            (
                self.challenge_hash.as_str(),
                "challenge_hash",
                "stored challenge hash is not canonical",
            ),
        ] {
            stored(validate_canonical_sha256_urn(hash, field), reason)?;
        }

        let ttl_ms = self
            .binding
            .expires_at_ms
            .checked_sub(self.binding.created_at_ms)
            .ok_or_else(|| corrupt("stored ceremony expiry is invalid"))?;
        if self.binding.created_at_ms == 0
            || !(MIN_TTL_SECS * 1000..=MAX_TTL_SECS * 1000).contains(&ttl_ms)
        {
            return Err(corrupt(
                "stored ceremony lifetime is outside the configured safety bounds",
            ));
        }

        let expected_binding_hash = stored(
            self.binding.binding_hash(),
            "stored ceremony binding cannot be hashed",
        )?;
        if self.binding_hash != expected_binding_hash {
            return Err(corrupt(
                "stored ceremony binding hash does not match the binding",
            ));
        }

        match self.status {
            CeremonyStatus::Pending => {
                if self.claim_id.is_some()
                    || self.fencing_token != 0
                    || self.claimed_at_ms.is_some()
                    || self.terminal.is_some()
                {
                    return Err(corrupt("pending ceremony contains mutable state"));
                }
            }
            CeremonyStatus::Claimed => {
                self.validate_claim_metadata()?;
                if self.terminal.is_some() {
                    return Err(corrupt("claimed ceremony contains terminal state"));
                }
            }
            CeremonyStatus::Completed => self.validate_completed()?,
            CeremonyStatus::Rejected | CeremonyStatus::Expired => {
                return Err(corrupt("stored ceremony uses an unsupported terminal state"));
            }
        }
        Ok(())
    }

    fn validate_claim_metadata(&self) -> Result<(), CeremonyError> {
        let claim_id = self
            .claim_id
            .as_deref()
            .ok_or_else(|| corrupt("claimed ceremony is missing claim id"))?;
        stored(
            validate_identifier(claim_id, "claim_id"),
            "stored ceremony claim id is invalid",
        )?;
        if self.fencing_token == 0 {
            return Err(corrupt("claimed ceremony has a zero fencing token"));
        }
        let claimed_at_ms = self
            .claimed_at_ms
            .ok_or_else(|| corrupt("claimed ceremony is missing claim time"))?;
        if claimed_at_ms < self.binding.created_at_ms
            || claimed_at_ms >= self.binding.expires_at_ms
        {
            return Err(corrupt("claimed ceremony timestamp is outside its lifetime"));
        }
        Ok(())
    }

    fn validate_completed(&self) -> Result<(), CeremonyError> {
        self.validate_claim_metadata()?;
        let terminal = self
            .terminal
            .as_ref()
            .ok_or_else(|| corrupt("completed ceremony is missing terminal state"))?;
        if terminal.outcome != CeremonyStatus::Completed || terminal.reason != "verified" {
            return Err(corrupt("completed ceremony has an invalid outcome"));
        }
        let receipt_hash = terminal
            .assertion_receipt_hash
            .as_deref()
            .ok_or_else(|| corrupt("completed ceremony is missing receipt evidence"))?;
        let credential_id = terminal
            .credential_id
            .as_deref()
            .ok_or_else(|| corrupt("completed ceremony is missing credential evidence"))?;
        let credential_generation = terminal
            .credential_generation
            .ok_or_else(|| corrupt("completed ceremony is missing credential generation"))?;
        stored(
            validate_identifier(credential_id, "credential_id"),
            "completed ceremony credential id is invalid",
        )?;
        stored(
            validate_canonical_sha256_urn(receipt_hash, "assertion_receipt_hash"),
            "completed ceremony receipt hash is not canonical",
        )?;
        stored(
            validate_canonical_sha256_urn(&terminal.result_hash, "result_hash"),
            "completed ceremony result hash is not canonical",
        )?;
        if self.binding.activation_credential_id.as_deref() == Some(credential_id) {
            return Err(corrupt(
                "completed ceremony used the credential being activated",
            ));
        }
        if credential_generation != self.binding.credential_generation {
            return Err(corrupt("completed ceremony credential generation changed"));
        }
        let claimed_at_ms = self
            .claimed_at_ms
            .ok_or_else(|| corrupt("completed ceremony is missing claim time"))?;
        if terminal.completed_at_ms < claimed_at_ms
            || terminal.completed_at_ms >= self.binding.expires_at_ms
        {
            return Err(corrupt(
                "completed ceremony timestamp is outside its claim lifetime",
            ));
        }
        if terminal.result_hash
            != self.completed_result_hash(
                credential_id,
                credential_generation,
                receipt_hash,
                terminal.completed_at_ms,
            )?
        {
            return Err(corrupt(
                "completed ceremony result hash does not match its evidence",
            ));
        }
        Ok(())
    }

    fn completed_result_hash(
        &self,
        credential_id: &str,
        credential_generation: u64,
        assertion_receipt_hash: &str,
        completed_at_ms: u64,
    ) -> Result<String, CeremonyError> {
        sha256_json(&json!({
            "contract_version": CONTRACT_VERSION,
            "object_kind": "verified_governance_webauthn_assertion",
            "ceremony_id": &self.ceremony_id,
            "tenant_id": &self.binding.tenant_id,
            "participant_id": &self.binding.participant_id,
            "proposal_id": &self.binding.proposal_id,
            "canonical_proposal_hash": &self.binding.canonical_proposal_hash,
            "policy_id": &self.binding.policy_id,
            "policy_version": self.binding.policy_version,
            "policy_hash": &self.binding.policy_hash,
            "continuity_generation": self.binding.continuity_generation,
            "credential_id": credential_id,
            "credential_generation": credential_generation,
            "assertion_receipt_hash": assertion_receipt_hash,
            "user_verified": true,
            "completed_at_ms": completed_at_ms
        }))
    }
}

fn validate_record_against_config(
    record: &CeremonyRecord,
    config: &GovernanceConfig,
    expected_id: &str,
) -> Result<(), CeremonyError> {
    record.validate_integrity(expected_id)?;
    let rp_id = stored(config.rp_id(), "governance RP ID is unavailable")?;
    let origin = stored(config.origin(), "governance origin is unavailable")?;
    if !config.enabled
        || !config.allowed_tenants.contains(&record.binding.tenant_id)
        || record.binding.rp_id.as_str() != rp_id
        || record.binding.origin.as_str() != origin
    {
        return Err(corrupt(
            "stored ceremony is outside the active governance configuration",
        ));
    }
    let secret = stored(
        config.ceremony_secret(),
        "governance ceremony secret is unavailable",
    )?;
    let challenge = stored(
        derive_challenge(secret, expected_id, &record.binding_hash),
        "stored ceremony challenge cannot be derived",
    )?;
    if record.challenge_hash != sha256_bytes(challenge.as_bytes()) {
        return Err(corrupt(
            "stored ceremony challenge hash does not match its binding",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod integrity_tests {
    use super::*;

    fn test_config() -> GovernanceConfig {
        GovernanceConfig {
            enabled: true,
            rp_id: Some("auth.fiducia.test".to_string()),
            origin: Some("https://auth.fiducia.test".to_string()),
            allowed_tenants: BTreeSet::from(["company-123".to_string()]),
            ttl_ms: 300_000,
            ceremony_secret: Some(vec![7_u8; 32]),
            verifier_secret: Some("v".repeat(32)),
            protected_state_codec: None,
        }
    }

    fn valid_id() -> String {
        format!("gcer_{}", "1".repeat(64))
    }

    fn record() -> CeremonyRecord {
        let config = test_config();
        let ceremony_id = valid_id();
        let binding = ApprovalBinding {
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
        };
        let binding_hash = binding.binding_hash().expect("binding hash");
        let challenge = derive_challenge(
            config.ceremony_secret().expect("ceremony secret"),
            &ceremony_id,
            &binding_hash,
        )
        .expect("challenge");
        CeremonyRecord {
            contract_version: CONTRACT_VERSION.to_string(),
            object_kind: OBJECT_KIND.to_string(),
            ceremony_id,
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

    #[test]
    fn durable_record_rejects_cross_key_binding_and_challenge_mutation() {
        let config = test_config();
        let record = record();
        validate_record_against_config(&record, &config, &record.ceremony_id)
            .expect("valid record");
        assert!(validate_record_against_config(
            &record,
            &config,
            &format!("gcer_{}", "2".repeat(64)),
        )
        .is_err());

        let mut binding_mutated = record.clone();
        binding_mutated.binding.continuity_generation += 1;
        assert!(binding_mutated
            .validate_integrity(&binding_mutated.ceremony_id)
            .is_err());

        let mut challenge_mutated = record;
        challenge_mutated.challenge_hash = format!("sha256:{}", "c".repeat(64));
        assert!(validate_record_against_config(
            &challenge_mutated,
            &config,
            &challenge_mutated.ceremony_id,
        )
        .is_err());
    }

    #[test]
    fn durable_record_rejects_incoherent_state_metadata() {
        let record = record();
        let mut pending_with_claim = record.clone();
        pending_with_claim.claim_id = Some("claim-a".to_string());
        assert!(pending_with_claim
            .validate_integrity(&pending_with_claim.ceremony_id)
            .is_err());

        let mut claimed_without_fence = record;
        claimed_without_fence.status = CeremonyStatus::Claimed;
        claimed_without_fence.claim_id = Some("claim-a".to_string());
        claimed_without_fence.claimed_at_ms = Some(2_000);
        assert!(claimed_without_fence
            .validate_integrity(&claimed_without_fence.ceremony_id)
            .is_err());
    }

    #[test]
    fn completed_receipt_is_revalidated_from_terminal_evidence() {
        let (claimed, _, _) = claim_record(record(), "claim-a", 11, 2_000).expect("claim");
        let request = CompleteVerifiedRequest {
            tenant_id: claimed.binding.tenant_id.clone(),
            participant_id: claimed.binding.participant_id.clone(),
            claim_id: "claim-a".to_string(),
            fencing_token: 11,
            binding_hash: claimed.binding_hash.clone(),
            challenge_hash: claimed.challenge_hash.clone(),
            credential_id: "credential-a".to_string(),
            credential_generation: claimed.binding.credential_generation,
            assertion_receipt_hash: format!("sha256:{}", "d".repeat(64)),
            user_verified: true,
        };
        let mut completed = complete_record(claimed, &request, 3_000).expect("complete");
        completed
            .validate_integrity(&completed.ceremony_id)
            .expect("valid completion");
        completed.terminal.as_mut().expect("terminal").credential_id =
            Some("credential-b".to_string());
        assert!(completed.validate_integrity(&completed.ceremony_id).is_err());
    }

    #[test]
    fn governance_keys_and_hashes_are_canonical_lowercase() {
        assert!(validate_ceremony_id(&valid_id()).is_ok());
        assert!(validate_ceremony_id(&format!("gcer_{}", "A".repeat(64))).is_err());
        assert!(validate_ceremony_id("gcer_../other-key").is_err());
        assert!(validate_canonical_sha256_urn(
            &format!("sha256:{}", "a".repeat(64)),
            "hash",
        )
        .is_ok());
        assert!(validate_canonical_sha256_urn(
            &format!("sha256:{}", "A".repeat(64)),
            "hash",
        )
        .is_err());
    }
}
