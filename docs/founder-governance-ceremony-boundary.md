# Durable founder-governance ceremony boundary

Status: non-production implementation slice for DEN-475. The binary is disabled by default and is not part of the production deployment.

## What this slice implements

`src/bin/fiducia-governance-ceremony.rs` exposes a narrow ceremony service with:

- a public AAL2-gated proposal-approval begin route;
- deterministic HMAC-derived WebAuthn challenges bound to tenant, participant, proposal, policy, continuity generation, RP ID, origin, credential generation, expiry, and idempotency identity;
- no raw challenge persisted in Fiducia KV;
- compare-and-set creation under `__auth/governance/ceremonies/`;
- exact begin retry with the same challenge and conflict on idempotency-key reuse for a different binding;
- an internal authenticated claim route with monotonic fencing and higher-fenced failover takeover;
- an internal authenticated completion route that records only a verified-assertion receipt from a future reviewed WebAuthn adapter;
- exact terminal retry and stale-claimant rejection after takeover;
- explicit denial of a replacement credential approving its own activation;
- fixed-vocabulary, secret-free tracing events.

The completion route does **not** accept a browser assertion and does **not** append a governance approval. It accepts only a content-addressed verification receipt from the trusted future `webauthn-rs` adapter. The Founder Control Plane must still re-read participant, credential, proposal, policy, and continuity state before turning that receipt into an approval.

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

## Required configuration

The feature is off when `FIDUCIA_GOVERNANCE_WEBAUTHN_ENABLED` is absent, `false`, or `0`.

When enabled, all of the following are required:

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

The normal Supabase verification and Fiducia KV variables are also required when enabled. Release configuration rejects non-HTTPS origins. Debug builds permit loopback-only HTTP.

## Security boundary

This implementation intentionally avoids four unsafe shortcuts:

1. A Supabase session or AAL2 event is not a governance approval.
2. A browser cannot assert that WebAuthn verification succeeded.
3. Raw challenge, client-data JSON, authenticator data, session JWTs, private keys, and provider credentials are not persisted in the ceremony record.
4. A terminal verified-assertion receipt is evidence for the next policy step, not authority to mutate an external provider.

## Remaining DEN-475 work

- add the reviewed `webauthn-rs` registration and authentication adapter;
- encrypt or otherwise protect the adapter's opaque ceremony state at rest;
- add credential registration begin/finish routes;
- verify live participant/role/credential registry state at completion;
- append exactly one governance approval after current policy and generation checks;
- integrate counter and backup-state anomaly policy;
- add restart, multi-replica, and browser-level integration tests;
- deploy only in a disposable prototype tenant after the canonical contract gate passes.
