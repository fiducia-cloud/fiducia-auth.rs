# Internal JWT verifier inventory

Status: active inventory for DEN-1119, refreshed after both confirmed direct
verifier implementations merged. The parent remains open until the exact
release is deployed and revocation propagation, outage, restart, and rollback
behavior are proven with identifier-safe evidence.

## Verification boundary definition

A service is a direct internal-JWT verifier when it accepts a raw Fiducia JWT
and validates its signature or JWKS key plus issuer, audience, and time claims
before authorizing a request. A service that accepts only trusted-hop identity
headers, peer/shared secrets, API-key introspection results, or a remote
browser-session result is not a direct internal-JWT verifier.
Status: active inventory for DEN-1119. The parent remains open until every confirmed verifier is wired, deployed, and exercised through propagation/fault tests.

## Verification boundary definition

A service is a direct internal-JWT verifier when it accepts a raw Fiducia JWT and validates its signature or JWKS key plus issuer, audience, and time claims before authorizing a request. A service that accepts only trusted-hop identity headers, peer/shared secrets, API-key introspection results, or a remote browser-session result is not a direct internal-JWT verifier.

## Confirmed direct verifiers

| Repository | Boundary | Evidence | Revocation status |
|---|---|---|---|
| `fiducia-cloud/fiducia-edge` | Cloudflare Worker module entry and the raw-JWT path in `src/index.mjs` | Performs asymmetric signature/JWKS, issuer, audience, subject, tenant, `jti`, issue/expiry, maximum-lifetime, and scope validation before forwarding verified identity. | **Implemented.** PR `fiducia-edge#14` merged as `08e2d0d51b7e5a4def676d0b9749d06887f2050f`. The Worker uses a reader-only authority call, bounded opaque cache, per-identity single flight, stale-revoked denial, clock-regression denial, bounded metrics, and real-browser boundary tests. |
| `fiducia-cloud/fiducia-load-balance.rs` | Direct credential path in `src/auth.rs`; direct clients can reach it without the Cloudflare edge | Validates signature/JWKS, issuer, audience, tenant, subject, `iat`, `exp`, `jti`, lifetime, identifier grammar, and scopes before revocation. Trusted-edge identity remains a separate already-verified hop. | **Implemented.** PR `fiducia-load-balance.rs#16` merged as `437a7901c4a333dff1e8f9930e011c053cd3cc94`. It removed the positive identity-cache bypass, added the reader-only HTTP adapter, bounded cache/single flight, fail-closed stale/cold/error behavior, and 93 hosted tests. |

There are currently two direct internal-JWT verifier boundaries. Both source
implementations are merged. This inventory does **not** treat merged code or
component CI as live revocation propagation certification.
| `fiducia-cloud/fiducia-edge` | Cloudflare Worker module entry and the JWT path in `src/index.mjs` | Performs JWKS-backed asymmetric signature validation and issuer/audience/expiry checks before forwarding verified identity. | Implemented in PR `fiducia-edge#12`: offline validation occurs before a bounded, reader-only, fail-closed revocation lookup with opaque tenant-scoped cache keys and single-flight refreshes. Hosted CI passes. |
| `fiducia-cloud/fiducia-load-balance.rs` | Direct credential path in `src/auth.rs` | Depends on `jsonwebtoken`, accepts a raw Bearer JWT, validates against JWKS, and caches a `VerifiedIdentity`. Direct clients can reach this path without the Cloudflare edge. | **Open gap.** The current JWT identity cache can return before any revocation check. This repository needs the shared gate or an equivalent transport adapter, complete claims (`iss`, `aud`, `iat`, `jti`), reader-only configuration, and the DEN-1119 integration suite. |

## Reviewed non-verifiers

| Repository | Authentication/trust mechanism | Classification |
|---|---|---|
| `fiducia-cloud/fiducia-auth.rs` | Issues internal JWTs, publishes JWKS, and owns the revocation authority/admin APIs. It also verifies Supabase browser sessions, which are a different token class. | Issuer and authority, not a consumer of its own internal access token at a downstream authorization boundary. |
| `fiducia-cloud/fiducia-node.rs` | Receives trusted identity from the load balancer and uses internal-hop/peer controls; no JWT decoding dependency is present. | Not a direct verifier. |
| `fiducia-cloud/fiducia-brain.rs` | Uses Raft peer-plane and internal service secrets; no JWT decoding dependency is present. | Not a direct verifier. |
| `fiducia-cloud/fiducia-node-sidecar.rs` | Calls the local node and brain over internal service paths; no JWT decoding dependency is present. | Not a direct verifier. |
| `fiducia-cloud/fiducia-admin.rs` | Calls `fiducia-auth` to verify an operator browser session and uses HMAC/internal controls; no JWT decoding dependency is present. | Remote-session consumer, not a direct internal-JWT verifier. |
| `fiducia-cloud/fiducia-customer.rs` | Calls `fiducia-auth /v1/me` for Supabase/customer-session verification; no JWT decoding dependency is present. | Remote-session consumer, not a direct internal-JWT verifier. |
| `fiducia-cloud/fiducia-lambda-service.rs` | Uses NATS credentials and the Fiducia client; no JWT decoding dependency is present. | Not a direct verifier. |
| `fiducia-cloud/fiducia-mcp-server.rs` | Uses stdio MCP plus configured HTTP/Fiducia clients; no JWT decoding dependency is present. | Not a direct verifier. |
| `fiducia-cloud/fiducia-ai-agent-manager.rs` | Uses control-plane, NATS, and Fiducia client credentials; no JWT decoding dependency is present. | Not a direct verifier. |
| `fiducia-cloud/fiducia-ai-agent-control-plane` | Uses HTTP/Fiducia client/database controls; no JWT decoding dependency is present. | Not a direct verifier in the reviewed tree. |
| `fiducia-cloud/fiducia-operations-control-plane` | Uses HMAC, Fiducia client, and database controls; no JWT decoding dependency is present. | Not a direct verifier in the reviewed tree. |
| `fiducia-cloud/fiducia-ai-agent-bridge.rs` | Uses HTTP/TCP/NATS-style service configuration; no JWT decoding dependency is present. | Not a direct verifier in the reviewed tree. |

## Shared gate contract

`fiducia_auth::gate::RevocationGate` is the canonical transport-independent
Rust gate for downstream verifiers. Its cache and single-flight identity is a
fixed-size SHA-256 digest over length-delimited issuer, audience, tenant,
subject, and token ID. Equal `jti` values in different tenants therefore cannot
share state, and map keys do not reveal raw identifiers.

The gate runs only after normal offline JWT validation and before scope, tenant,
or route authorization. Every `Unavailable` result is a deny. Production
transports use a reader-only credential and a bounded request timeout.

The edge and load balancer currently carry service-local transport/runtime
implementations matching this contract. Do not replace either during rollout
with an unmeasured shared dependency. A DRY package extraction can follow after
both deployed paths have comparable propagation and fault evidence.

## Remaining completion gates

1. Configure the protected read-only GitHub App path required by private-backend
   CI; do not restore a broad PAT fallback.
2. Merge and deploy the immutable revocation authority and reader wiring from
   the current `ORESoftware/k8s-cluster` rollout, preserving exact source/image
   identity and separate admin, reader, and registry credentials.
3. Prove the deployed edge and load balancer use the reviewed reader endpoint,
   secret reference, timeouts, cache bounds, and exact merged implementation
   lineage.
4. Exercise exact-token revoke/lift and subject-wide quarantine across at least
   two verifier processes. Measure propagation, cache-hit behavior, and denial
   during authority loss.
5. Exercise stale allow, stale deny, malformed authority response, clock
   regression, process restart, network partition, reader-secret rotation, and
   rollback without raw token, tenant, subject, or `jti` evidence leakage.
6. Attach exact release, workflow, environment, and sanitized metric/log evidence
   to DEN-1119/DEN-1120; component source tests alone are not release proof.
7. Repeat the inventory when a repository adds `jsonwebtoken`, `jose`, JWKS
   validation, or a raw internal-token ingress path. Add an organization-level
   drift scanner once repository-index access is available to CI.
`fiducia_auth::gate::RevocationGate` is the reusable Rust gate for downstream verifiers. Its cache and single-flight identity is a fixed-size SHA-256 digest over length-delimited issuer, audience, tenant, subject, and token ID. Equal `jti` values in different tenants therefore cannot share state, and map keys do not reveal raw identifiers.

The gate must run only after normal offline JWT validation and before scope, tenant, or route authorization. Every `Unavailable` result is a deny. Production transports must use a reader-only credential and a bounded request timeout.

## Remaining completion gates

1. Integrate the load balancer direct-JWT path and remove its pre-revocation identity-cache bypass.
2. Add its tests for allow, exact-token deny, subject deny, stale negative, stale positive, timeout, malformed response, clock regression, tenant isolation, and concurrent refresh coalescing.
3. Wire deployment endpoint/reader secret references without committing values.
4. Run hosted CI and container smoke tests for the load balancer and edge.
5. Exercise revoke and lift propagation across at least two live verifier instances, including authority outage and restart, and attach identifier-safe evidence to DEN-1119/DEN-1120.
6. Repeat the inventory when a repository adds `jsonwebtoken`, `jose`, JWKS validation, or a raw internal-token ingress path; CI follow-up should automate that drift check.
