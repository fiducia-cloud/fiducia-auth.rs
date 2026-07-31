# Internal access-token revocation ledger

This document describes the first deployable slice of DEN-252. It establishes authoritative revocation state and an administrative control plane. It does **not** claim that every token verifier already consumes that state.

## Authority and target identity

`fiducia-revocation-admin` stores one versioned ledger per opaque, tenant-scoped target key in the same replicated Fiducia KV authority used by API-key lifecycle state.

Targets are either:

- an exact internal token identifier: `(issuer, audience, tenant_id, token_id)`; or
- a subject quarantine: `(issuer, audience, tenant_id, subject)`.

The key derivation is byte-for-byte compatible with `RevocationRecord::storage_key`. Raw token IDs and subjects are not present in the KV path. Exact token revocations expire with the token. Subject revocations are explicitly bounded by the shared one-day maximum.

## Mutation semantics

The writer API requires all of the following:

- `FIDUCIA_REVOCATION_ADMIN_SECRET` through `x-revocation-admin-auth`;
- an explicit `x-fiducia-actor` value;
- an `Idempotency-Key` value;
- a bounded reason and a valid target record.

The read/check API uses a separate `FIDUCIA_REVOCATION_READER_SECRET` through `x-revocation-reader-auth`. The process refuses to start when either secret is missing, malformed, or identical to the other.

Accepted changes use compare-and-set against the previous KV revision. Exact idempotent retries return the original transition generation. Reusing the same actor/key identity for different intent is rejected. The raw idempotency key is never stored.

Each target ledger contains at most 32 append-only transitions. Events are linked by SHA-256 hashes and the complete chain is validated on every read or mutation. The service rejects corrupt, reordered, truncated, cross-target, or duplicate-idempotency histories instead of silently repairing them. Reaching the bound is an explicit conflict and does not truncate audit evidence.

## Endpoints

The standalone binary listens on `FIDUCIA_REVOCATION_PORT` or port 8098 by default:

- `POST /v1/revocations/revoke`
- `POST /v1/revocations/lift`
- `POST /v1/revocations/check`
- `GET /healthz`

No browser CORS policy is enabled. Bodies are limited to 32 KiB, requests time out after ten seconds, responses containing decisions use `Cache-Control: no-store`, and storage corruption or unavailability returns a generic 503 without exposing internals.

A token revocation request carries decoded internal claims rather than the raw JWT. The service rejects the wrong issuer or audience, missing tenant/subject/token identifiers, invalid lifetimes, and lifetimes above the 15-minute internal-token maximum.

## Outage and cache boundary

The authority fails closed for administrative mutations and authoritative checks: unavailable or invalid KV state returns 503. This binary is not intended to add a remote read to every application request.

Edge and load-balancer verifiers still need bounded local revocation caches, monotonic-generation refresh, convergence metrics, and a documented stale-cache policy. Until those consumers are deployed, existing already-issued JWTs are not universally and immediately blocked. This is an explicit remaining DEN-252 gate, not work completed by this ledger PR.

## Expiry, growth, and rollback

Expired records no longer match checks and cannot be lifted. Physical deletion or audit compaction is intentionally deferred because the current KV client exposes conditional put but not a conditional delete primitive. The per-target transition ceiling bounds growth without destroying evidence.

Rollback of the administration binary does not alter the existing `fiducia-auth` HTTP server or token format. Versioned ledger records remain inert until a compatible reader consumes them. A future schema change must use a new ledger and record version rather than reinterpret stored events.

## Required follow-up

DEN-252 remains open for verifier-side cache integration in edge/load-balancer services, multi-instance convergence and partition tests, clock-skew policy, metrics and alerts, deployment secrets, runbooks, safe pruning/compaction, and measured end-to-end propagation evidence.
