pub struct CeremonyStore {
    kv: Arc<KvClient>,
    config: GovernanceConfig,
}

impl CeremonyStore {
    pub fn new(kv: Arc<KvClient>, config: GovernanceConfig) -> Self {
        Self { kv, config }
    }

    pub async fn begin(
        &self,
        proposal_id: &str,
        participant_id: &str,
        tenant_id: &str,
        idempotency_key: &str,
        request: &BeginApprovalRequest,
        now_ms: u64,
    ) -> Result<BeginApprovalResponse, CeremonyError> {
        if !self.config.enabled {
            return Err(CeremonyError::Disabled);
        }
        validate_identifier(proposal_id, "proposal_id")?;
        validate_identifier(participant_id, "participant_id")?;
        validate_identifier(tenant_id, "tenant_id")?;
        validate_idempotency_key(idempotency_key)?;
        if request.org_id != tenant_id || request.participant_id != participant_id {
            return Err(CeremonyError::Unauthorized);
        }
        if !self.config.allowed_tenants.contains(tenant_id) {
            return Err(CeremonyError::Unauthorized);
        }

        let expires_at_ms = now_ms
            .checked_add(self.config.ttl_ms)
            .ok_or(CeremonyError::InvalidRequest("ceremony expiry overflow"))?;
        let binding = ApprovalBinding {
            tenant_id: tenant_id.to_string(),
            participant_id: participant_id.to_string(),
            proposal_id: proposal_id.to_string(),
            canonical_proposal_hash: request.canonical_proposal_hash.clone(),
            policy_id: request.policy_id.clone(),
            policy_version: request.policy_version,
            policy_hash: request.policy_hash.clone(),
            continuity_state: request.continuity_state.clone(),
            continuity_generation: request.continuity_generation,
            rp_id: self.config.rp_id()?.to_string(),
            origin: self.config.origin()?.to_string(),
            credential_generation: request.credential_generation,
            activation_credential_id: request.activation_credential_id.clone(),
            created_at_ms: now_ms,
            expires_at_ms,
        };
        let binding_hash = binding.binding_hash()?;
        let ceremony_id = ceremony_id(tenant_id, participant_id, proposal_id, idempotency_key);
        let challenge = derive_challenge(
            self.config.ceremony_secret()?,
            &ceremony_id,
            &binding_hash,
        )?;
        let challenge_hash = sha256_bytes(challenge.as_bytes());
        let record = CeremonyRecord {
            contract_version: CONTRACT_VERSION.to_string(),
            object_kind: OBJECT_KIND.to_string(),
            ceremony_id: ceremony_id.clone(),
            binding,
            binding_hash: binding_hash.clone(),
            challenge_hash: challenge_hash.clone(),
            status: CeremonyStatus::Pending,
            claim_id: None,
            fencing_token: 0,
            claimed_at_ms: None,
            terminal: None,
        };
        let path = ceremony_path(&ceremony_id);
        match self
            .kv
            .put_if_revision(&path, &serde_json::to_value(&record)?, 0)
            .await?
        {
            CasOutcome::Applied => Ok(BeginApprovalResponse {
                ceremony_id,
                binding_hash,
                challenge,
                challenge_hash,
                rp_id: record.binding.rp_id,
                origin: record.binding.origin,
                expires_at_ms,
                replayed: false,
            }),
            CasOutcome::Mismatch => {
                let existing = self.load(&ceremony_id).await?;
                if existing.binding_hash != record.binding_hash
                    || existing.challenge_hash != record.challenge_hash
                    || existing.binding.tenant_id != tenant_id
                    || existing.binding.participant_id != participant_id
                {
                    return Err(CeremonyError::Conflict);
                }
                if existing.binding.expires_at_ms <= now_ms {
                    return Err(CeremonyError::Expired);
                }
                if matches!(
                    existing.status,
                    CeremonyStatus::Completed | CeremonyStatus::Rejected | CeremonyStatus::Expired
                ) {
                    return Err(CeremonyError::Conflict);
                }
                Ok(BeginApprovalResponse {
                    ceremony_id,
                    binding_hash,
                    challenge,
                    challenge_hash,
                    rp_id: existing.binding.rp_id,
                    origin: existing.binding.origin,
                    expires_at_ms: existing.binding.expires_at_ms,
                    replayed: true,
                })
            }
        }
    }

    pub async fn claim(
        &self,
        ceremony_id: &str,
        request: &ClaimRequest,
        now_ms: u64,
    ) -> Result<ClaimResponse, CeremonyError> {
        validate_identifier(ceremony_id, "ceremony_id")?;
        validate_identifier(&request.claim_id, "claim_id")?;
        if request.fencing_token == 0 {
            return Err(CeremonyError::InvalidRequest("fencing_token must be positive"));
        }
        let path = ceremony_path(ceremony_id);
        for _ in 0..MAX_CAS_ATTEMPTS {
            let versioned = self
                .kv
                .get_versioned(&path)
                .await?
                .ok_or(CeremonyError::NotFound)?;
            let record: CeremonyRecord = serde_json::from_value(versioned.value)?;
            record.validate_identity(&request.tenant_id, &request.participant_id)?;
            if record.binding.expires_at_ms <= now_ms {
                return Err(CeremonyError::Expired);
            }
            if let Some(terminal) = record.terminal.as_ref() {
                return Ok(ClaimResponse {
                    ceremony_id: ceremony_id.to_string(),
                    status: terminal.outcome,
                    fencing_token: record.fencing_token,
                    replayed: true,
                    taken_over: false,
                });
            }
            let (candidate, replayed, taken_over) = claim_record(
                record,
                &request.claim_id,
                request.fencing_token,
                now_ms,
            )?;
            if replayed {
                return Ok(ClaimResponse {
                    ceremony_id: ceremony_id.to_string(),
                    status: candidate.status,
                    fencing_token: candidate.fencing_token,
                    replayed: true,
                    taken_over,
                });
            }
            match self
                .kv
                .put_if_revision(
                    &path,
                    &serde_json::to_value(&candidate)?,
                    versioned.mod_revision,
                )
                .await?
            {
                CasOutcome::Applied => {
                    return Ok(ClaimResponse {
                        ceremony_id: ceremony_id.to_string(),
                        status: candidate.status,
                        fencing_token: candidate.fencing_token,
                        replayed: false,
                        taken_over,
                    })
                }
                CasOutcome::Mismatch => continue,
            }
        }
        Err(CeremonyError::CasRetriesExhausted)
    }

    pub async fn complete_verified(
        &self,
        ceremony_id: &str,
        request: &CompleteVerifiedRequest,
        now_ms: u64,
    ) -> Result<CompleteVerifiedResponse, CeremonyError> {
        validate_identifier(ceremony_id, "ceremony_id")?;
        validate_identifier(&request.claim_id, "claim_id")?;
        validate_identifier(&request.credential_id, "credential_id")?;
        validate_sha256_urn(&request.binding_hash, "binding_hash")?;
        validate_sha256_urn(&request.challenge_hash, "challenge_hash")?;
        validate_sha256_urn(&request.assertion_receipt_hash, "assertion_receipt_hash")?;
        if !request.user_verified {
            return Err(CeremonyError::Unauthorized);
        }
        let path = ceremony_path(ceremony_id);
        for _ in 0..MAX_CAS_ATTEMPTS {
            let versioned = self
                .kv
                .get_versioned(&path)
                .await?
                .ok_or(CeremonyError::NotFound)?;
            let record: CeremonyRecord = serde_json::from_value(versioned.value)?;
            record.validate_identity(&request.tenant_id, &request.participant_id)?;
            if let Some(terminal) = record.terminal.as_ref() {
                if terminal.outcome == CeremonyStatus::Completed
                    && terminal.assertion_receipt_hash.as_deref()
                        == Some(request.assertion_receipt_hash.as_str())
                {
                    return Ok(CompleteVerifiedResponse {
                        ceremony_id: ceremony_id.to_string(),
                        status: CeremonyStatus::Completed,
                        terminal: terminal.clone(),
                        replayed: true,
                    });
                }
                return Err(CeremonyError::Conflict);
            }
            if record.binding.expires_at_ms <= now_ms {
                return Err(CeremonyError::Expired);
            }
            let candidate = complete_record(record, request, now_ms)?;
            let terminal = candidate
                .terminal
                .clone()
                .ok_or(CeremonyError::InvalidRequest("terminal result missing"))?;
            match self
                .kv
                .put_if_revision(
                    &path,
                    &serde_json::to_value(&candidate)?,
                    versioned.mod_revision,
                )
                .await?
            {
                CasOutcome::Applied => {
                    return Ok(CompleteVerifiedResponse {
                        ceremony_id: ceremony_id.to_string(),
                        status: CeremonyStatus::Completed,
                        terminal,
                        replayed: false,
                    })
                }
                CasOutcome::Mismatch => continue,
            }
        }
        Err(CeremonyError::CasRetriesExhausted)
    }

    async fn load(&self, ceremony_id: &str) -> Result<CeremonyRecord, CeremonyError> {
        let value = self
            .kv
            .get(&ceremony_path(ceremony_id))
            .await?
            .ok_or(CeremonyError::NotFound)?;
        Ok(serde_json::from_value(value)?)
    }
}

fn claim_record(
    mut record: CeremonyRecord,
    claim_id: &str,
    fencing_token: u64,
    now_ms: u64,
) -> Result<(CeremonyRecord, bool, bool), CeremonyError> {
    match record.status {
        CeremonyStatus::Pending => {
            record.status = CeremonyStatus::Claimed;
            record.claim_id = Some(claim_id.to_string());
            record.fencing_token = fencing_token;
            record.claimed_at_ms = Some(now_ms);
            Ok((record, false, false))
        }
        CeremonyStatus::Claimed => {
            if fencing_token < record.fencing_token {
                return Err(CeremonyError::StaleFencing);
            }
            if fencing_token == record.fencing_token {
                if record.claim_id.as_deref() == Some(claim_id) {
                    return Ok((record, true, false));
                }
                return Err(CeremonyError::AlreadyClaimed);
            }
            record.claim_id = Some(claim_id.to_string());
            record.fencing_token = fencing_token;
            record.claimed_at_ms = Some(now_ms);
            Ok((record, false, true))
        }
        CeremonyStatus::Completed | CeremonyStatus::Rejected | CeremonyStatus::Expired => {
            Err(CeremonyError::Conflict)
        }
    }
}

fn complete_record(
    mut record: CeremonyRecord,
    request: &CompleteVerifiedRequest,
    now_ms: u64,
) -> Result<CeremonyRecord, CeremonyError> {
    if record.status != CeremonyStatus::Claimed {
        return Err(CeremonyError::NotClaimed);
    }
    if request.fencing_token < record.fencing_token {
        return Err(CeremonyError::StaleFencing);
    }
    if request.fencing_token != record.fencing_token
        || record.claim_id.as_deref() != Some(request.claim_id.as_str())
    {
        return Err(CeremonyError::ClaimMismatch);
    }
    if record.binding_hash != request.binding_hash
        || record.challenge_hash != request.challenge_hash
        || record.binding.credential_generation != request.credential_generation
    {
        return Err(CeremonyError::Conflict);
    }
    if record.binding.activation_credential_id.as_deref() == Some(request.credential_id.as_str()) {
        return Err(CeremonyError::Unauthorized);
    }
    let unsigned = json!({
        "contract_version": CONTRACT_VERSION,
        "object_kind": "verified_governance_webauthn_assertion",
        "ceremony_id": &record.ceremony_id,
        "tenant_id": &record.binding.tenant_id,
        "participant_id": &record.binding.participant_id,
        "proposal_id": &record.binding.proposal_id,
        "canonical_proposal_hash": &record.binding.canonical_proposal_hash,
        "policy_id": &record.binding.policy_id,
        "policy_version": record.binding.policy_version,
        "policy_hash": &record.binding.policy_hash,
        "continuity_generation": record.binding.continuity_generation,
        "credential_id": &request.credential_id,
        "credential_generation": request.credential_generation,
        "assertion_receipt_hash": &request.assertion_receipt_hash,
        "user_verified": true,
        "completed_at_ms": now_ms
    });
    let result_hash = sha256_json(&unsigned)?;
    record.status = CeremonyStatus::Completed;
    record.terminal = Some(TerminalVerification {
        outcome: CeremonyStatus::Completed,
        reason: "verified".to_string(),
        assertion_receipt_hash: Some(request.assertion_receipt_hash.clone()),
        credential_id: Some(request.credential_id.clone()),
        credential_generation: Some(request.credential_generation),
        completed_at_ms: now_ms,
        result_hash,
    });
    Ok(record)
}

