# Proposal-bound WebAuthn governance prototype

Status: implementation plan for DEN-195. This is a non-production, disabled-by-default prototype boundary. It does not treat a passkey as proof of equity ownership, corporate office, death, incapacity, or legal authority.

## Library and protocol boundary

Use the stable safe API of `webauthn-rs` and pin the reviewed crate revision in `Cargo.toml` and `Cargo.lock` together. The currently reviewed upstream API exposes `WebauthnBuilder`, `start_passkey_registration`, `finish_passkey_registration`, `start_passkey_authentication`, and `finish_passkey_authentication`.

Do not enable `danger-*` features. Do not implement WebAuthn verification directly. The library verifies the authenticator response; Fiducia separately verifies governance policy, tenant identity, participant/role/credential binding, proposal hash, continuity generation, and single-use ceremony state.

## Separation from ordinary login

Supabase remains the product-session and organization-membership source of truth. A valid Supabase session, including AAL2, may open an enrollment or approval ceremony but never counts as a governance approval.

A governance approval exists only after:

1. a pre-authorized participant starts a proposal-bound ceremony;
2. the browser/authenticator completes a WebAuthn assertion;
3. `fiducia-auth` verifies the WebAuthn assertion;
4. current tenant governance state revalidates participant, role, credential, policy, proposal, and continuity generation;
5. durable ceremony state is atomically consumed;
6. the exact approval is appended once to the governance ledger.

## Disabled-by-default configuration

The prototype must refuse to expose begin/finish routes unless all required values are valid:

- `FIDUCIA_GOVERNANCE_WEBAUTHN_ENABLED=false` by default;
- exact HTTPS RP origin;
- RP ID compatible with that origin;
- dedicated governance-state namespace;
- durable atomic ceremony store;
- verified governance-ledger endpoint and service credential;
- maximum ceremony TTL;
- explicit allowed tenant list for the prototype.

Release deployments must reject HTTP origins. Local debug builds may use loopback-only HTTP through an explicit test flag.

## Proposed module layout

```text
src/governance/
  mod.rs                 feature/config and route assembly
  model.rs               typed public and internal objects
  binding.rs             canonical proposal/challenge binding
  participants.rs        current role/credential registry lookup
  ceremonies.rs          durable single-use ceremony state
  webauthn.rs             webauthn-rs adapter only
  approvals.rs            finish-time policy and ledger checks
  audit.rs                secret-free security events
```

Provider credentials, provider connectors, equity records, and continuity legal determinations do not belong in this module.

## Routes

All routes require a verified Supabase user and explicit organization selection. Begin routes additionally require recent AAL2, but AAL2 is not the governance signature.

```text
POST /v1/governance/credentials/registration/begin
POST /v1/governance/credentials/registration/finish
POST /v1/governance/proposals/{proposal_id}/approval/begin
POST /v1/governance/proposals/{proposal_id}/approval/finish
GET  /v1/governance/credentials
POST /v1/governance/credentials/{credential_id}/revoke
```

The finish routes never accept tenant, participant role, policy version, continuity generation, or proposal parameters as authoritative browser input. Those values come from the stored ceremony and current server-side governance state.

## Proposal-bound challenge

The server stores an immutable binding containing at least:

```text
tenant_id
participant_id
proposal_id
canonical_proposal_hash
policy_id
policy_version
policy_hash
continuity_state
continuity_generation
rp_id
origin
ceremony_nonce
credential_generation
created_at_ms
expires_at_ms
```

The WebAuthn challenge is derived from a domain-separated hash of the canonical binding plus high-entropy server randomness. The raw server random value and library ceremony state are stored server-side, never trusted from browser-returned JSON.

Changing any bound value requires a new ceremony and new assertion.

## Registration ceremony

1. Require a live Supabase session, explicit tenant, recent AAL2, and a pre-authorized participant record.
2. Reject self-activation: a newly recovered/replacement credential cannot approve the transaction that authorizes itself.
3. Start registration with the participant's stable opaque user handle, not email as authority.
4. Store the complete library registration state with a short TTL and single-use identifier.
5. At finish, atomically claim the ceremony before registering the credential.
6. Revalidate tenant membership, participant status, authorization transaction, RP ID/origin, expiry, and credential generation.
7. Persist only the public credential/passkey record and security metadata; no private key exists server-side.
8. Append an immutable enrollment receipt.

## Approval ceremony

1. Load the immutable proposal and current policy from governance state.
2. Verify the proposal is unexpired, unexecuted, and still references the current policy/generation required by its rules.
3. Verify the participant is active and has an eligible registered credential.
4. Start WebAuthn authentication and store the complete authentication state plus proposal binding.
5. At finish, atomically claim the ceremony.
6. Verify the assertion through `webauthn-rs` with user verification required.
7. Re-read current participant, credential, policy, proposal, and continuity state.
8. Reject revoked, suspended, replaced, expired, wrong-role, wrong-tenant, wrong-generation, or self-activation credentials.
9. Append exactly one approval for the participant and exact canonical proposal hash.

Multiple authenticators for one participant still count as one human in quorum evaluation.

## Durable ceremony semantics

Ceremony state must live in a durable store that supports compare-and-delete or claim-and-complete atomically across replicas.

Required states:

```text
pending -> claimed -> completed
                 \-> rejected
pending -> expired
```

A ceremony may be claimed once. A crash after claim never makes it reusable; recovery either completes from durable result state or expires/rejects it. Exact retries return the original terminal receipt and never append a second approval.

Do not use process memory as the production or multi-replica ceremony authority.

## Credential record

Store at minimum:

```text
tenant_id
participant_id
credential_id
public passkey record
roles allowed by current participant registry
status: active | suspended | revoked | replaced
credential_generation
created_at_ms
last_used_at_ms
revoked_at_ms
replaced_by_credential_id
backup_eligible
backup_state
last_observed_counter
```

Roles in an assertion are claims only. The current tenant-controlled participant registry remains authoritative.

## Counter and backup-state handling

Record signature-counter and backup-state changes returned by the WebAuthn library. A suspicious counter regression, unexpected backup-state transition, or credential cloning signal fails closed for protected approvals or moves the credential into explicit review according to policy. It must never silently downgrade to session-only authentication.

## Logging and telemetry

Logs, traces, metrics, and errors may contain tenant-scoped opaque IDs, result codes, and latency. They must not contain:

- raw challenges;
- WebAuthn ceremony state;
- authenticator responses;
- session JWTs;
- passkey private material;
- provider credentials;
- confidential evidence;
- full proposal parameters when sensitive.

## Required tests

1. Supabase AAL2 without WebAuthn cannot approve.
2. Wrong tenant, participant, proposal hash, policy hash/version, generation, RP ID, or origin fails.
3. Mutating proposal parameters after begin fails.
4. Revocation or replacement between begin and finish fails.
5. Wrong-role and unregistered credentials fail.
6. Ceremony replay and concurrent finish produce at most one approval.
7. Restart/failover cannot resurrect consumed ceremony state.
8. Multiple credentials for one participant count once.
9. A replacement credential cannot approve its own activation.
10. User verification is required for protected approvals.
11. Counter and backup-state anomalies follow fail-closed/review policy.
12. Expired ceremonies fail with no ledger mutation.
13. Unknown contract versions and unsupported canonicalization fail before WebAuthn or ledger mutation.
14. Logs and traces contain no challenge, assertion, JWT, or credential secret.

## Implementation sequence

1. Land reviewed canonical proposal/transition bindings and hosted CI in `fiducia-interfaces`.
2. Pin `webauthn-rs` and update the lockfile through normal dependency tooling.
3. Add configuration parsing and disabled route assembly.
4. Implement durable ceremony storage and tests before browser routes.
5. Add registration with test credentials.
6. Add proposal-bound authentication and finish-time governance revalidation.
7. Integrate the isolated Founder Control Plane service through a narrow verified-assertion interface.
8. Run only fake/sandbox flows until security review and HSM/KMS/provider-custody decisions are complete.
