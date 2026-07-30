# Durable founder-governance ceremony boundary

Status: non-production implementation for DEN-475 and DEN-493. The binary is disabled at both compile time and runtime and is not part of the production auth image.

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
- deterministic HMAC-derived challenge binding to tenant, participant, proposal, policy, continuity generation, RP ID, origin, credential generation, expiry, and idempotency identity;
- no raw challenge persisted in Fiducia KV;
- compare-and-set creation under `__auth/governance/ceremonies/`;
- exact begin retry with the same challenge and conflict on idempotency-key reuse for a different binding;
- an internal authenticated claim route with monotonic fencing and higher-fenced failover takeover;
- an internal authenticated completion route that records only a content-addressed verified-assertion receipt;
- exact terminal retry and stale-claimant rejection after takeover;
- explicit denial of a replacement credential approving its own activation;
- fixed-vocabulary, secret-free tracing events.

The completion route does **not** accept a browser assertion and does **not** append a governance approval. The Founder Control Plane must still re-read participant, credential, proposal, policy, and continuity state before turning a verified assertion receipt into an approval.

## WebAuthn adapter and protected state

`src/governance_ceremony/webauthn.rs` now provides wrappers around the safe passkey APIs:

- `start_passkey_registration` / `finish_passkey_registration`;
- `start_passkey_authentication` / `finish_passkey_authentication`.

`webauthn-rs` disables ceremony-state serialization by default because returning state to a client enables replay. Fiducia enables only `danger-allow-state-serialisation` for authenticated encrypted **server-side** custody. Client cookies, local storage, and browser-returned ceremony state remain prohibited.

Opaque registration/authentication state is sealed with XChaCha20-Poly1305. Associated data binds:

- contract version and object kind;
- algorithm and key ID;
- tenant and ceremony ID;
- immutable governance binding hash;
- registration versus authentication state kind;
- ceremony expiry.

The envelope stores a key ID/version, random nonce, ciphertext, state kind, and associated-data hash. Raw state-encryption keys are not part of the envelope. The codec supports old-key reads during rotation while writing new state with the configured active key. Wrong keys, corrupted ciphertext, changed binding, changed state kind, changed metadata, and associated-data mismatch fail closed.

The codec exists and is tested, but it is not yet wired into the durable ceremony record or runtime key configuration. That is the next DEN-493 slice.

## Routes

```text
GET  /healthz
POST /v1/governance/proposals/:proposal_id/approval/begin
POST /internal/v1/governance/ceremonies/:ceremony_id/claim
POST /internal/v1/governance/ceremonies/:ceremony_id/complete-verified
```

The public begin route requires:

- governance enabled;
- a verified Supabase bearer session;
- `aal2`;
- explicit membership in the requested prototype tenant;
- exact `participant_id == Supabase sub` during this restrictive prototype phase;
- a 16–128 character `Idempotency-Key`;
- valid proposal and policy SHA-256 URNs.

Internal routes require `x-fiducia-governance-verifier-auth` and never accept a product session as a substitute for verification.

## Runtime configuration

The runtime feature is off when `FIDUCIA_GOVERNANCE_WEBAUTHN_ENABLED` is absent, `false`, or `0`.

When enabled, the current durable baseline requires:

```text
FIDUCIA_GOVERNANCE_WEBAUTHN_ENABLED=true
FIDUCIA_GOVERNANCE_RP_ID=auth.example.com
FIDUCIA_GOVERNANCE_ORIGIN=https://auth.example.com
FIDUCIA_GOVERNANCE_TENANTS=tenant-a,tenant-b
FIDUCIA_GOVERNANCE_CEREMONY_SECRET=<32+ byte no-whitespace secret>
FIDUCIA_GOVERNANCE_VERIFIER_SECRET=<32+ byte no-whitespace secret>
FIDUCIA_GOVERNANCE_CEREMONY_TTL_SECS=300   # 60..900
FIDUCIA_GOVERNANCE_PORT=8102
```

The normal Supabase verification and Fiducia KV variables are also required. Release configuration rejects non-HTTPS origins. Debug builds permit loopback-only HTTP.

The next slice will add an explicit protected-state key ring and active key ID. Those values must come from a secret manager or KMS-backed deployment boundary; raw keys must not be stored in ceremony records, receipts, logs, or checked-in configuration.

## Security boundary

This implementation intentionally avoids these unsafe shortcuts:

1. A Supabase session or AAL2 event is not a governance approval.
2. A browser cannot assert that WebAuthn verification succeeded.
3. Opaque `webauthn-rs` ceremony state is never a client authority.
4. Raw challenge, client-data JSON, authenticator data, session JWTs, private keys, state-encryption keys, and provider credentials are not persisted in receipts or logs.
5. A terminal verified-assertion receipt is evidence for the next policy step, not authority to mutate an external provider.
6. WebAuthn and crypto dependencies remain outside the production auth binaries unless the dedicated feature is explicitly enabled.

## Remaining DEN-493 / DEN-475 work

- wire the protected envelope and key ring into the durable Fiducia KV ceremony record;
- add browser registration and authentication begin/finish routes that call the reviewed adapter directly;
- persist public passkey records through the governance credential registry;
- revalidate live participant, role, credential, proposal, policy, continuity generation, RP ID, and origin at completion;
- implement signature-counter and backup-state anomaly policy;
- emit exactly one verified assertion receipt;
- add restart, multi-replica, key-rotation, corrupt-state, and browser/test-authenticator integration tests;
- append final governance approval only in `fiducia-founder-control-plane.rs` after current policy and generation checks;
- deploy only in a disposable prototype tenant after the canonical contract gate passes.
