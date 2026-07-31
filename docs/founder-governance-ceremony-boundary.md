# Durable founder-governance ceremony boundary

Status: non-production implementation for DEN-475, DEN-493, and DEN-799. The binary is disabled at both compile time and runtime and is not part of the production auth image.

## Compile-time isolation

The standalone ceremony service requires the explicit Cargo feature:

```bash
cargo run --locked \
  --features governance-webauthn \
  --bin fiducia-governance-ceremony
```

`governance-webauthn` enables only the reviewed high-level `webauthn-rs` passkey API and XChaCha20-Poly1305 protected-state codec. Production auth binaries compile with the empty default feature set, so WebAuthn/OpenSSL dependencies do not enter the normal production build unless the governance feature is explicitly selected.

CI verifies both boundaries:

```bash
cargo check --locked --bins
cargo clippy --locked --all-targets --features governance-webauthn -- -D warnings
cargo test --locked --all-targets --features governance-webauthn
```

## Durable ceremony baseline

`src/bin/fiducia-governance-ceremony.rs` exposes a narrow ceremony service with:

- a public AAL2-gated proposal-approval begin route;
- deterministic binding to tenant, participant, proposal, policy, continuity generation, RP ID, origin, credential generation, expiry, and idempotency identity;
- compare-and-set creation under `__auth/governance/ceremonies/`;
- exact begin retry and conflict on idempotency-key reuse for a different binding;
- an internal authenticated claim route with monotonic fencing and higher-fenced failover takeover;
- an internal authenticated completion route that records only a content-addressed verified-assertion receipt;
- exact terminal retry and stale-claimant rejection after takeover;
- explicit denial of a replacement credential approving its own activation;
- fixed-vocabulary, secret-free tracing events.

The completion route does **not** accept a browser assertion and does **not** append a governance approval. The Founder Control Plane must still re-read participant, credential, proposal, policy, and continuity state before turning a verified assertion receipt into an approval.

## WebAuthn options and opaque state are one ceremony

`src/governance_ceremony/webauthn.rs` wraps the safe passkey APIs:

- `start_passkey_registration` / `finish_passkey_registration`;
- `start_passkey_authentication` / `finish_passkey_authentication`.

A start call produces two inseparable values:

1. the browser-facing `CreationChallengeResponse` or `RequestChallengeResponse`;
2. the matching opaque `PasskeyRegistration` or `PasskeyAuthentication` state required at finish time.

DEN-799 treats those values as one retryable bundle. The browser options are converted to JSON and encrypted together with the matching opaque library state. An exact retry or higher-fenced replacement replica can therefore recover the original options instead of generating a second challenge that would invalidate the browser response.

`webauthn-rs` disables ceremony-state serialization by default because returning state to a client enables replay. Fiducia enables only `danger-allow-state-serialisation` for authenticated encrypted **server-side** custody. Client cookies, local storage, and browser-returned ceremony state remain prohibited.

## Protected-state envelope

The complete bundle is sealed with XChaCha20-Poly1305. Associated data binds:

- contract version and object kind;
- algorithm, key ID, and key-ring version;
- tenant and ceremony ID;
- immutable governance binding hash;
- registration versus authentication state kind;
- ceremony expiry.

The envelope stores only key metadata, a random nonce, ciphertext, state kind, and associated-data hash. Raw state-encryption keys are not part of the envelope. The codec supports old-key reads during rotation while writing new state with the configured active key. Wrong keys, corrupted ciphertext, changed binding, changed state kind, changed key-ring version, changed metadata, and associated-data mismatch fail closed.

The configuration object implements a redacted `Debug` representation; ceremony, verifier, and state-encryption key material is never printed through ordinary diagnostics.

## Runtime key ring

The runtime feature is off when `FIDUCIA_GOVERNANCE_WEBAUTHN_ENABLED` is absent, `false`, or `0`.

When enabled, the service requires:

```text
FIDUCIA_GOVERNANCE_WEBAUTHN_ENABLED=true
FIDUCIA_GOVERNANCE_RP_ID=auth.example.com
FIDUCIA_GOVERNANCE_ORIGIN=https://auth.example.com
FIDUCIA_GOVERNANCE_TENANTS=tenant-a,tenant-b
FIDUCIA_GOVERNANCE_CEREMONY_SECRET=<32+ byte no-whitespace secret>
FIDUCIA_GOVERNANCE_VERIFIER_SECRET=<32+ byte no-whitespace secret>
FIDUCIA_GOVERNANCE_CEREMONY_TTL_SECS=300
FIDUCIA_GOVERNANCE_STATE_ACTIVE_KEY_ID=state-key-2026-07
FIDUCIA_GOVERNANCE_STATE_KEYRING_VERSION=1
FIDUCIA_GOVERNANCE_STATE_KEYS_JSON={"state-key-2026-07":"<base64url-encoded 32-byte key>"}
FIDUCIA_GOVERNANCE_PORT=8102
```

The normal Supabase verification and Fiducia KV variables are also required. Release configuration rejects non-HTTPS origins. Debug builds permit loopback-only HTTP.

The active key ID must exist in the JSON key ring; every decoded key must be exactly 32 bytes. Key IDs and key-ring versions may appear in records and diagnostics. Raw keys must come from a secret-manager or KMS-backed deployment boundary and must not be stored in ceremony records, receipts, logs, source control, or user-visible configuration.

Service startup constructs the reviewed WebAuthn adapter and protected-state codec before becoming ready, so invalid RP/origin or key-ring configuration fails closed.

## Routes

```text
GET  /healthz
POST /v1/governance/proposals/:proposal_id/approval/begin
POST /internal/v1/governance/ceremonies/:ceremony_id/claim
POST /internal/v1/governance/ceremonies/:ceremony_id/complete-verified
```

The current public begin route remains the pre-adapter deterministic prototype. It requires a verified Supabase session, `aal2`, explicit tenant membership, exact participant binding, an idempotency key, and valid proposal/policy hashes. A later DEN-799 slice will replace its client response with the encrypted bundle's recovered WebAuthn options after passkeys are supplied by the server-side credential registry.

Internal routes require `x-fiducia-governance-verifier-auth` and never accept a product session as a substitute for verification.

## Security boundary

This implementation intentionally avoids these unsafe shortcuts:

1. A Supabase session or AAL2 event is not a governance approval.
2. A browser cannot assert that WebAuthn verification succeeded.
3. Browser options and opaque `webauthn-rs` state are encrypted together and are never client authority.
4. Raw challenge, client-data JSON, authenticator data, session JWTs, private keys, state-encryption keys, and provider credentials are not persisted in receipts or logs.
5. A terminal verified-assertion receipt is evidence for the next policy step, not authority to mutate an external provider.
6. WebAuthn and crypto dependencies remain outside production auth binaries unless the dedicated feature is explicitly enabled.

## Remaining DEN-799 / DEN-493 work

- attach the encrypted bundle to the durable Fiducia KV ceremony record;
- make create-if-absent losers and exact retries decrypt and return the winner's original options;
- preserve the same bundle through restart and higher-fenced takeover;
- define terminal ciphertext deletion while retaining immutable hashes and verification receipts;
- add browser registration and authentication begin/finish routes that call the reviewed adapter directly;
- persist public passkey records through the governance credential registry;
- revalidate live participant, role, credential, proposal, policy, continuity generation, RP ID, and origin at completion;
- implement signature-counter and backup-state anomaly policy;
- add restart, multi-replica, key-rotation, corrupt-state, and browser/test-authenticator integration tests;
- append final governance approval only in `fiducia-founder-control-plane.rs` after current policy and generation checks;
- deploy only in a disposable prototype tenant after the canonical contract gate passes.
