//! Durable, tenant-scoped revocation state over Fiducia KV.
//!
//! Mutations are compare-and-set updates to one bounded ledger per opaque target
//! key. Every accepted transition carries a hashed idempotency identity and an
//! append-only hash chain so accidental truncation or mutation is rejected when
//! the value is read back. Verifier-side caches are intentionally outside this
//! module; callers consume the monotonic generation and enforce their own
//! documented outage policy.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::store::{CasOutcome, KvClient, StoreError};
use crate::token::{
    Claims, RevocationRecord, RevocationRecordError, MAX_ACCESS_TOKEN_TTL_SECS,
    REVOCATION_RECORD_VERSION,
};

const LEDGER_VERSION: u16 = 1;
const MAX_CAS_RETRIES: usize = 8;
const INTERNAL_ISSUER: &str = "fiducia-auth";
const INTERNAL_AUDIENCE: &str = "fiducia-api";
pub const MAX_TRANSITIONS_PER_TARGET: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RevocationSelector {
    TokenId {
        tenant_id: String,
        jti: String,
    },
    Subject {
        tenant_id: String,
        subject: String,
    },
}

impl RevocationSelector {
    pub fn tenant_id(&self) -> &str {
        match self {
            Self::TokenId { tenant_id, .. } | Self::Subject { tenant_id, .. } => tenant_id,
        }
    }

    fn target_kind(&self) -> &'static str {
        match self {
            Self::TokenId { .. } => "token_id",
            Self::Subject { .. } => "subject",
        }
    }

    fn target_value(&self) -> &str {
        match self {
            Self::TokenId { jti, .. } => jti,
            Self::Subject { subject, .. } => subject,
        }
    }

    pub fn storage_key(&self) -> Result<String, RevocationError> {
        validate_identifier("tenant_id", self.tenant_id())?;
        validate_identifier(self.target_kind(), self.target_value())?;
        let digest = digest_text_parts(&[
            INTERNAL_ISSUER,
            INTERNAL_AUDIENCE,
            self.tenant_id(),
            self.target_kind(),
            self.target_value(),
        ]);
        Ok(format!(
            "auth/revocations/v{REVOCATION_RECORD_VERSION}/{digest}"
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RevokeRequest {
    TokenId { claims: Box<Claims>, reason: String },
    Subject {
        tenant_id: String,
        subject: String,
        expires_at: u64,
        reason: String,
    },
}

impl RevokeRequest {
    pub fn selector(&self) -> RevocationSelector {
        match self {
            Self::TokenId { claims, .. } => RevocationSelector::TokenId {
                tenant_id: claims.org_id.clone(),
                jti: claims.jti.clone(),
            },
            Self::Subject {
                tenant_id,
                subject,
                ..
            } => RevocationSelector::Subject {
                tenant_id: tenant_id.clone(),
                subject: subject.clone(),
            },
        }
    }

    fn record(&self, actor: &str, now: u64) -> Result<RevocationRecord, RevocationError> {
        match self {
            Self::TokenId { claims, reason } => {
                validate_internal_claims(claims)?;
                Ok(RevocationRecord::for_token(claims, reason, actor, now)?)
            }
            Self::Subject {
                tenant_id,
                subject,
                expires_at,
                reason,
            } => Ok(RevocationRecord::for_subject(
                tenant_id,
                subject,
                reason,
                actor,
                now,
                *expires_at,
            )?),
        }
    }

    fn request_hash(&self) -> String {
        match self {
            Self::TokenId { claims, reason } => {
                let issued_at = claims.iat.to_string();
                let expires_at = claims.exp.to_string();
                digest_text_parts(&[
                    "revoke",
                    "token_id",
                    claims.iss.as_str(),
                    claims.aud.as_str(),
                    claims.org_id.as_str(),
                    claims.sub.as_str(),
                    claims.jti.as_str(),
                    issued_at.as_str(),
                    expires_at.as_str(),
                    reason.trim(),
                ])
            }
            Self::Subject {
                tenant_id,
                subject,
                expires_at,
                reason,
            } => {
                let expires_at = expires_at.to_string();
                digest_text_parts(&[
                    "revoke",
                    "subject",
                    tenant_id.as_str(),
                    subject.as_str(),
                    expires_at.as_str(),
                    reason.trim(),
                ])
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiftRequest {
    pub selector: RevocationSelector,
    pub reason: String,
}

impl LiftRequest {
    fn request_hash(&self) -> String {
        digest_text_parts(&[
            "lift",
            self.selector.target_kind(),
            self.selector.tenant_id(),
            self.selector.target_value(),
            self.reason.trim(),
        ])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckRequest {
    pub claims: Claims,
}

#[derive(Debug, Clone, Copy)]
pub struct MutationIdentity<'a> {
    pub actor: &'a str,
    pub idempotency_key: &'a str,
}

impl<'a> MutationIdentity<'a> {
    pub fn new(actor: &'a str, idempotency_key: &'a str) -> Self {
        Self {
            actor,
            idempotency_key,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum RevocationAction {
    Revoke { record: Box<RevocationRecord> },
    Lift {
        actor: String,
        reason: String,
        at: u64,
    },
}

impl RevocationAction {
    fn at(&self) -> u64 {
        match self {
            Self::Revoke { record } => record.created_at,
            Self::Lift { at, .. } => *at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RevocationEvent {
    sequence: u64,
    action: RevocationAction,
    idempotency_hash: String,
    request_hash: String,
    previous_hash: String,
    event_hash: String,
}

impl RevocationEvent {
    fn new(
        sequence: u64,
        action: RevocationAction,
        idempotency_hash: String,
        request_hash: String,
        previous_hash: String,
    ) -> Result<Self, RevocationError> {
        let event_hash = event_hash(
            sequence,
            &action,
            &idempotency_hash,
            &request_hash,
            &previous_hash,
        )?;
        Ok(Self {
            sequence,
            action,
            idempotency_hash,
            request_hash,
            previous_hash,
            event_hash,
        })
    }

    fn validate_hash(&self) -> Result<(), RevocationError> {
        if !is_sha256_hex(&self.idempotency_hash)
            || !is_sha256_hex(&self.request_hash)
            || (!self.previous_hash.is_empty() && !is_sha256_hex(&self.previous_hash))
            || !is_sha256_hex(&self.event_hash)
        {
            return Err(RevocationError::InvalidLedger);
        }
        let expected = event_hash(
            self.sequence,
            &self.action,
            &self.idempotency_hash,
            &self.request_hash,
            &self.previous_hash,
        )?;
        if expected != self.event_hash {
            return Err(RevocationError::InvalidLedger);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RevocationLedger {
    version: u16,
    storage_key: String,
    events: Vec<RevocationEvent>,
}

impl RevocationLedger {
    fn new(
        storage_key: String,
        record: RevocationRecord,
        idempotency_hash: String,
        request_hash: String,
    ) -> Result<Self, RevocationError> {
        let event = RevocationEvent::new(
            1,
            RevocationAction::Revoke {
                record: Box::new(record),
            },
            idempotency_hash,
            request_hash,
            String::new(),
        )?;
        let ledger = Self {
            version: LEDGER_VERSION,
            storage_key,
            events: vec![event],
        };
        ledger.validate()?;
        Ok(ledger)
    }

    fn generation(&self) -> u64 {
        self.events
            .last()
            .map(|event| event.sequence)
            .unwrap_or(0)
    }

    fn current_record(&self) -> Option<&RevocationRecord> {
        let mut current = None;
        for event in &self.events {
            match &event.action {
                RevocationAction::Revoke { record } => current = Some(record.as_ref()),
                RevocationAction::Lift { .. } => current = None,
            }
        }
        current
    }

    fn latest_expiry(&self) -> Option<u64> {
        self.events
            .iter()
            .rev()
            .find_map(|event| match &event.action {
                RevocationAction::Revoke { record } => Some(record.expires_at),
                RevocationAction::Lift { .. } => None,
            })
    }

    fn replay_snapshot(
        &self,
        idempotency_hash: &str,
        request_hash: &str,
    ) -> Result<Option<RevocationSnapshot>, RevocationError> {
        let mut latest_expiry = None;
        for event in &self.events {
            if let RevocationAction::Revoke { record } = &event.action {
                latest_expiry = Some(record.expires_at);
            }
            if event.idempotency_hash != idempotency_hash {
                continue;
            }
            if event.request_hash != request_hash {
                return Err(RevocationError::IdempotencyConflict);
            }
            let status = match &event.action {
                RevocationAction::Revoke { .. } => RevocationStatus::Active,
                RevocationAction::Lift { .. } => RevocationStatus::Lifted,
            };
            return Ok(Some(RevocationSnapshot {
                storage_key: self.storage_key.clone(),
                generation: event.sequence,
                status,
                expires_at: latest_expiry,
            }));
        }
        Ok(None)
    }

    fn append_revoke(
        &mut self,
        record: RevocationRecord,
        idempotency_hash: String,
        request_hash: String,
    ) -> Result<(), RevocationError> {
        self.ensure_capacity()?;
        let event = RevocationEvent::new(
            self.generation() + 1,
            RevocationAction::Revoke {
                record: Box::new(record),
            },
            idempotency_hash,
            request_hash,
            self.events
                .last()
                .map(|event| event.event_hash.clone())
                .unwrap_or_default(),
        )?;
        self.events.push(event);
        self.validate()
    }

    fn append_lift(
        &mut self,
        actor: &str,
        reason: &str,
        at: u64,
        idempotency_hash: String,
        request_hash: String,
    ) -> Result<(), RevocationError> {
        self.ensure_capacity()?;
        let Some(active) = self.current_record() else {
            return Err(RevocationError::NotActive);
        };
        if !active.is_active_at(at) {
            return Err(RevocationError::NotActive);
        }
        validate_audit_text("actor", actor, 128)?;
        validate_audit_text("reason", reason, 256)?;
        let event = RevocationEvent::new(
            self.generation() + 1,
            RevocationAction::Lift {
                actor: actor.trim().to_string(),
                reason: reason.trim().to_string(),
                at,
            },
            idempotency_hash,
            request_hash,
            self.events
                .last()
                .map(|event| event.event_hash.clone())
                .unwrap_or_default(),
        )?;
        self.events.push(event);
        self.validate()
    }

    fn ensure_capacity(&self) -> Result<(), RevocationError> {
        if self.events.len() >= MAX_TRANSITIONS_PER_TARGET {
            return Err(RevocationError::TransitionLimit);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), RevocationError> {
        if self.version != LEDGER_VERSION
            || self.events.is_empty()
            || self.events.len() > MAX_TRANSITIONS_PER_TARGET
        {
            return Err(RevocationError::InvalidLedger);
        }

        let mut expected_previous = String::new();
        let mut last_at = 0_u64;
        let mut current: Option<&RevocationRecord> = None;
        let mut idempotency_hashes = HashSet::new();
        for (index, event) in self.events.iter().enumerate() {
            if event.sequence != index as u64 + 1
                || event.previous_hash != expected_previous
                || event.action.at() < last_at
                || !idempotency_hashes.insert(event.idempotency_hash.as_str())
            {
                return Err(RevocationError::InvalidLedger);
            }
            event.validate_hash()?;
            match &event.action {
                RevocationAction::Revoke { record } => {
                    record
                        .validate()
                        .map_err(|_| RevocationError::InvalidLedger)?;
                    if record
                        .storage_key()
                        .map_err(|_| RevocationError::InvalidLedger)?
                        != self.storage_key
                    {
                        return Err(RevocationError::InvalidLedger);
                    }
                    current = Some(record.as_ref());
                }
                RevocationAction::Lift { actor, reason, at } => {
                    validate_audit_text("actor", actor, 128)
                        .map_err(|_| RevocationError::InvalidLedger)?;
                    validate_audit_text("reason", reason, 256)
                        .map_err(|_| RevocationError::InvalidLedger)?;
                    let Some(active) = current else {
                        return Err(RevocationError::InvalidLedger);
                    };
                    if *at < active.created_at || *at >= active.expires_at {
                        return Err(RevocationError::InvalidLedger);
                    }
                    current = None;
                }
            }
            expected_previous = event.event_hash.clone();
            last_at = event.action.at();
        }
        Ok(())
    }

    fn snapshot(&self, now: u64) -> RevocationSnapshot {
        let status = match self.current_record() {
            Some(record) if now < record.created_at => RevocationStatus::Pending,
            Some(record) if record.is_active_at(now) => RevocationStatus::Active,
            Some(_) => RevocationStatus::Expired,
            None => RevocationStatus::Lifted,
        };
        RevocationSnapshot {
            storage_key: self.storage_key.clone(),
            generation: self.generation(),
            status,
            expires_at: self.latest_expiry(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationStatus {
    Pending,
    Active,
    Lifted,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevocationSnapshot {
    pub storage_key: String,
    pub generation: u64,
    pub status: RevocationStatus,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchedTarget {
    TokenId,
    Subject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevocationDecision {
    pub revoked: bool,
    pub matched_target: Option<MatchedTarget>,
    pub generation: Option<u64>,
    pub expires_at: Option<u64>,
}

pub struct RevocationStore {
    kv: Option<KvClient>,
    memory: Mutex<HashMap<String, RevocationLedger>>,
}

impl RevocationStore {
    pub fn from_env() -> Result<Self, StoreError> {
        Ok(Self {
            kv: Some(KvClient::from_env()?),
            memory: Mutex::new(HashMap::new()),
        })
    }

    #[cfg(test)]
    fn in_memory() -> Self {
        Self {
            kv: None,
            memory: Mutex::new(HashMap::new()),
        }
    }

    pub async fn revoke(
        &self,
        request: RevokeRequest,
        mutation: MutationIdentity<'_>,
        now: u64,
    ) -> Result<RevocationSnapshot, RevocationError> {
        validate_mutation(mutation)?;
        let selector = request.selector();
        let storage_key = selector.storage_key()?;
        let record = request.record(mutation.actor, now)?;
        if record.storage_key()? != storage_key {
            return Err(RevocationError::InvalidMutation("target"));
        }
        let idempotency_hash = mutation_hash(
            "revoke",
            &storage_key,
            mutation.actor,
            mutation.idempotency_key,
        );
        let request_hash = request.request_hash();

        if let Some(kv) = &self.kv {
            for _ in 0..MAX_CAS_RETRIES {
                let existing = load_ledger(kv, &storage_key).await?;
                let (mut ledger, previous_revision) = match existing {
                    Some((ledger, revision)) => (Some(ledger), revision),
                    None => (None, 0),
                };
                if let Some(current) = ledger.as_ref() {
                    if let Some(snapshot) = current
                        .replay_snapshot(&idempotency_hash, &request_hash)?
                    {
                        return Ok(snapshot);
                    }
                }

                let next = match ledger.as_mut() {
                    Some(current) => {
                        current.append_revoke(
                            record.clone(),
                            idempotency_hash.clone(),
                            request_hash.clone(),
                        )?;
                        current.clone()
                    }
                    None => RevocationLedger::new(
                        storage_key.clone(),
                        record.clone(),
                        idempotency_hash.clone(),
                        request_hash.clone(),
                    )?,
                };
                let value =
                    serde_json::to_value(&next).map_err(|_| RevocationError::InvalidLedger)?;
                match kv
                    .put_if_revision(&storage_key, &value, previous_revision)
                    .await?
                {
                    CasOutcome::Applied => return Ok(next.snapshot(now)),
                    CasOutcome::Mismatch => continue,
                }
            }
            return Err(RevocationError::CasRetriesExhausted);
        }

        let mut ledgers = self.memory.lock().expect("revocation memory mutex");
        if let Some(current) = ledgers.get(&storage_key) {
            if let Some(snapshot) = current.replay_snapshot(&idempotency_hash, &request_hash)? {
                return Ok(snapshot);
            }
        }
        let next = match ledgers.get_mut(&storage_key) {
            Some(current) => {
                current.append_revoke(record, idempotency_hash, request_hash)?;
                current.clone()
            }
            None => RevocationLedger::new(
                storage_key.clone(),
                record,
                idempotency_hash,
                request_hash,
            )?,
        };
        ledgers.insert(storage_key, next.clone());
        Ok(next.snapshot(now))
    }

    pub async fn lift(
        &self,
        request: LiftRequest,
        mutation: MutationIdentity<'_>,
        now: u64,
    ) -> Result<RevocationSnapshot, RevocationError> {
        validate_mutation(mutation)?;
        validate_audit_text("reason", &request.reason, 256)?;
        let storage_key = request.selector.storage_key()?;
        let idempotency_hash = mutation_hash(
            "lift",
            &storage_key,
            mutation.actor,
            mutation.idempotency_key,
        );
        let request_hash = request.request_hash();

        if let Some(kv) = &self.kv {
            for _ in 0..MAX_CAS_RETRIES {
                let Some((mut ledger, previous_revision)) =
                    load_ledger(kv, &storage_key).await?
                else {
                    return Err(RevocationError::NotFound);
                };
                if let Some(snapshot) = ledger.replay_snapshot(&idempotency_hash, &request_hash)? {
                    return Ok(snapshot);
                }
                ledger.append_lift(
                    mutation.actor,
                    &request.reason,
                    now,
                    idempotency_hash.clone(),
                    request_hash.clone(),
                )?;
                let value =
                    serde_json::to_value(&ledger).map_err(|_| RevocationError::InvalidLedger)?;
                match kv
                    .put_if_revision(&storage_key, &value, previous_revision)
                    .await?
                {
                    CasOutcome::Applied => return Ok(ledger.snapshot(now)),
                    CasOutcome::Mismatch => continue,
                }
            }
            return Err(RevocationError::CasRetriesExhausted);
        }

        let mut ledgers = self.memory.lock().expect("revocation memory mutex");
        let ledger = ledgers
            .get_mut(&storage_key)
            .ok_or(RevocationError::NotFound)?;
        if let Some(snapshot) = ledger.replay_snapshot(&idempotency_hash, &request_hash)? {
            return Ok(snapshot);
        }
        ledger.append_lift(
            mutation.actor,
            &request.reason,
            now,
            idempotency_hash,
            request_hash,
        )?;
        Ok(ledger.snapshot(now))
    }

    pub async fn check(
        &self,
        claims: &Claims,
        now: u64,
    ) -> Result<RevocationDecision, RevocationError> {
        validate_internal_claims(claims)?;
        let selectors = [
            (
                RevocationSelector::TokenId {
                    tenant_id: claims.org_id.clone(),
                    jti: claims.jti.clone(),
                },
                MatchedTarget::TokenId,
            ),
            (
                RevocationSelector::Subject {
                    tenant_id: claims.org_id.clone(),
                    subject: claims.sub.clone(),
                },
                MatchedTarget::Subject,
            ),
        ];

        for (selector, matched_target) in selectors {
            let storage_key = selector.storage_key()?;
            let Some(ledger) = self.read_ledger(&storage_key).await? else {
                continue;
            };
            if let Some(record) = ledger.current_record() {
                if record.matches(claims, now) {
                    return Ok(RevocationDecision {
                        revoked: true,
                        matched_target: Some(matched_target),
                        generation: Some(ledger.generation()),
                        expires_at: Some(record.expires_at),
                    });
                }
            }
        }

        Ok(RevocationDecision {
            revoked: false,
            matched_target: None,
            generation: None,
            expires_at: None,
        })
    }

    async fn read_ledger(
        &self,
        storage_key: &str,
    ) -> Result<Option<RevocationLedger>, RevocationError> {
        if let Some(kv) = &self.kv {
            return Ok(load_ledger(kv, storage_key)
                .await?
                .map(|(ledger, _)| ledger));
        }
        Ok(self
            .memory
            .lock()
            .expect("revocation memory mutex")
            .get(storage_key)
            .cloned())
    }
}

async fn load_ledger(
    kv: &KvClient,
    storage_key: &str,
) -> Result<Option<(RevocationLedger, u64)>, RevocationError> {
    let Some(stored) = kv.get_versioned(storage_key).await? else {
        return Ok(None);
    };
    let ledger: RevocationLedger =
        serde_json::from_value(stored.value).map_err(|_| RevocationError::InvalidLedger)?;
    ledger.validate()?;
    if ledger.storage_key != storage_key {
        return Err(RevocationError::InvalidLedger);
    }
    Ok(Some((ledger, stored.mod_revision)))
}

fn validate_internal_claims(claims: &Claims) -> Result<(), RevocationError> {
    if claims.iss != INTERNAL_ISSUER || claims.aud != INTERNAL_AUDIENCE {
        return Err(RevocationError::InvalidClaims);
    }
    validate_identifier("tenant_id", &claims.org_id)?;
    validate_identifier("subject", &claims.sub)?;
    validate_identifier("jti", &claims.jti)?;
    if claims.exp <= claims.iat || claims.exp - claims.iat > MAX_ACCESS_TOKEN_TTL_SECS {
        return Err(RevocationError::InvalidClaims);
    }
    Ok(())
}

fn validate_mutation(mutation: MutationIdentity<'_>) -> Result<(), RevocationError> {
    validate_audit_text("actor", mutation.actor, 128)?;
    let idempotency_key = mutation.idempotency_key.trim();
    if idempotency_key.is_empty()
        || idempotency_key.len() > 128
        || idempotency_key
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(RevocationError::InvalidMutation("idempotency_key"));
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), RevocationError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(RevocationError::InvalidMutation(field));
    }
    Ok(())
}

fn validate_audit_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), RevocationError> {
    let value = value.trim();
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(RevocationError::InvalidMutation(field));
    }
    Ok(())
}

fn mutation_hash(action: &str, key: &str, actor: &str, idempotency_key: &str) -> String {
    digest_text_parts(&[action, key, actor.trim(), idempotency_key.trim()])
}

fn event_hash(
    sequence: u64,
    action: &RevocationAction,
    idempotency_hash: &str,
    request_hash: &str,
    previous_hash: &str,
) -> Result<String, RevocationError> {
    let sequence = sequence.to_be_bytes();
    let action = serde_json::to_vec(action).map_err(|_| RevocationError::InvalidLedger)?;
    Ok(digest_byte_parts(&[
        &sequence,
        &action,
        idempotency_hash.as_bytes(),
        request_hash.as_bytes(),
        previous_hash.as_bytes(),
    ]))
}

fn digest_text_parts(parts: &[&str]) -> String {
    let byte_parts = parts.iter().map(|part| part.as_bytes()).collect::<Vec<_>>();
    digest_byte_parts(&byte_parts)
}

fn digest_byte_parts(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Debug, Error)]
pub enum RevocationError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Contract(#[from] RevocationRecordError),
    #[error("invalid revocation mutation field: {0}")]
    InvalidMutation(&'static str),
    #[error("invalid internal access-token claims")]
    InvalidClaims,
    #[error("stored revocation ledger is invalid")]
    InvalidLedger,
    #[error("idempotency key was already used for a different request")]
    IdempotencyConflict,
    #[error("revocation target was not found")]
    NotFound,
    #[error("revocation target is not active")]
    NotActive,
    #[error("revocation transition limit reached")]
    TransitionLimit,
    #[error("revocation compare-and-set retries exhausted")]
    CasRetriesExhausted,
}

#[cfg(test)]
mod tests;
