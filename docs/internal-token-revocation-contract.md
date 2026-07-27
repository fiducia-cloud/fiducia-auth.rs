# Internal token revocation contract

Linear: DEN-252

This repository mints short-lived Fiducia access tokens for the `fiducia-auth` issuer and `fiducia-api` audience. This change establishes the identity and storage-key contract required before a replicated revocation service can be enforced consistently by the edge, load balancer, nodes, and admin tooling.

## Token contract

Every newly minted token contains:

- fixed issuer `fiducia-auth`;
- fixed audience `fiducia-api`;
- tenant-scoped `sub` and `org_id`;
- a CSPRNG-backed 128-bit `jti` encoded with unpadded base64url;
- an issued-at time and expiry;
- a hard maximum lifetime of 900 seconds.

A request for a zero or longer lifetime fails closed. The existing token-exchange route already requests exactly 900 seconds, so this change does not lengthen credentials or alter their scopes.

## Revocation record v1

A record is scoped by all of the following:

- record version;
- issuer;
- audience;
- tenant ID;
- exact token ID (`jti`) or subject;
- creation and expiry times.

It also carries a content-free reason and actor for immutable audit evidence. Records contain no raw JWT, API key, credential hash, email, token signature, request body, or user-editable metadata.

The storage key is a length-prefixed SHA-256 digest of issuer, audience, tenant, target kind, and target value. This makes retries deterministic while preventing ambiguous concatenation, cross-tenant collisions, and identity leakage in KV paths or metrics.

Exact-token records expire with the signed token. Subject-level emergency records are capped at 24 hours and must be renewed deliberately. Expired records are safe to prune once every verifier has passed the documented propagation and clock-skew bound.

## Required follow-up before claiming distributed revocation

This PR deliberately does **not** claim that existing offline verifiers enforce the records yet. DEN-252 remains open for:

1. a replicated authoritative store with compare-and-set/idempotent revoke and unrevoke operations;
2. least-privilege admin authorization and immutable audit persistence;
3. bounded local caches in edge, load balancer, nodes, and any other JWT verifier;
4. explicit fail-open/fail-closed behavior for customer, admin, machine, and recovery surfaces;
5. propagation-latency telemetry, stale-cache detection, and rollback protection;
6. partition, restart, expiry-pruning, flood, replay, and cross-tenant integration tests.

Until those consumers land, short expiry remains the enforcement bound. Deploying this token-contract change is safe first: older in-flight tokens expire normally, and verifiers that ignore unknown claims continue to validate the fixed signature, issuer, audience, and expiry contract.
