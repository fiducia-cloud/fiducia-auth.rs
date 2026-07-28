#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalBinding {
    pub tenant_id: String,
    pub participant_id: String,
    pub proposal_id: String,
    pub canonical_proposal_hash: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub policy_hash: String,
    pub continuity_state: String,
    pub continuity_generation: u64,
    pub rp_id: String,
    pub origin: String,
    pub credential_generation: u64,
    pub activation_credential_id: Option<String>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

impl ApprovalBinding {
    fn validate(&self) -> Result<(), CeremonyError> {
        for (value, field) in [
            (&self.tenant_id, "tenant_id"),
            (&self.participant_id, "participant_id"),
            (&self.proposal_id, "proposal_id"),
            (&self.policy_id, "policy_id"),
            (&self.continuity_state, "continuity_state"),
            (&self.rp_id, "rp_id"),
            (&self.origin, "origin"),
        ] {
            validate_identifier(value, field)?;
        }
        validate_sha256_urn(&self.canonical_proposal_hash, "canonical_proposal_hash")?;
        validate_sha256_urn(&self.policy_hash, "policy_hash")?;
        if self.policy_version == 0 || self.credential_generation == 0 {
            return Err(CeremonyError::InvalidRequest(
                "policy_version and credential_generation must be positive",
            ));
        }
        if self.expires_at_ms <= self.created_at_ms {
            return Err(CeremonyError::InvalidRequest(
                "ceremony expiry must be after creation",
            ));
        }
        if let Some(credential_id) = self.activation_credential_id.as_deref() {
            validate_identifier(credential_id, "activation_credential_id")?;
        }
        Ok(())
    }

    pub fn binding_hash(&self) -> Result<String, CeremonyError> {
        self.validate()?;
        sha256_json(self)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyStatus {
    Pending,
    Claimed,
    Completed,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TerminalVerification {
    pub outcome: CeremonyStatus,
    pub reason: String,
    pub assertion_receipt_hash: Option<String>,
    pub credential_id: Option<String>,
    pub credential_generation: Option<u64>,
    pub completed_at_ms: u64,
    pub result_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CeremonyRecord {
    pub contract_version: String,
    pub object_kind: String,
    pub ceremony_id: String,
    pub binding: ApprovalBinding,
    pub binding_hash: String,
    pub challenge_hash: String,
    pub status: CeremonyStatus,
    pub claim_id: Option<String>,
    pub fencing_token: u64,
    pub claimed_at_ms: Option<u64>,
    pub terminal: Option<TerminalVerification>,
}

impl CeremonyRecord {
    fn validate_identity(&self, tenant_id: &str, participant_id: &str) -> Result<(), CeremonyError> {
        if self.binding.tenant_id != tenant_id || self.binding.participant_id != participant_id {
            return Err(CeremonyError::Unauthorized);
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct BeginApprovalRequest {
    pub org_id: String,
    pub participant_id: String,
    pub canonical_proposal_hash: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub policy_hash: String,
    pub continuity_state: String,
    pub continuity_generation: u64,
    pub credential_generation: u64,
    #[serde(default)]
    pub activation_credential_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BeginApprovalResponse {
    pub ceremony_id: String,
    pub binding_hash: String,
    pub challenge: String,
    pub challenge_hash: String,
    pub rp_id: String,
    pub origin: String,
    pub expires_at_ms: u64,
    pub replayed: bool,
}

#[derive(Debug, Deserialize)]
pub struct ClaimRequest {
    pub tenant_id: String,
    pub participant_id: String,
    pub claim_id: String,
    pub fencing_token: u64,
}

#[derive(Debug, Serialize)]
pub struct ClaimResponse {
    pub ceremony_id: String,
    pub status: CeremonyStatus,
    pub fencing_token: u64,
    pub replayed: bool,
    pub taken_over: bool,
}

#[derive(Debug, Deserialize)]
pub struct CompleteVerifiedRequest {
    pub tenant_id: String,
    pub participant_id: String,
    pub claim_id: String,
    pub fencing_token: u64,
    pub binding_hash: String,
    pub challenge_hash: String,
    pub credential_id: String,
    pub credential_generation: u64,
    pub assertion_receipt_hash: String,
    pub user_verified: bool,
}

#[derive(Debug, Serialize)]
pub struct CompleteVerifiedResponse {
    pub ceremony_id: String,
    pub status: CeremonyStatus,
    pub terminal: TerminalVerification,
    pub replayed: bool,
}

