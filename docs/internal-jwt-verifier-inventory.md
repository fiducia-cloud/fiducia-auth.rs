# Internal JWT verifier inventory

Status: active inventory for DEN-1119. The parent remains open until every confirmed verifier is wired, deployed, and exercised through propagation/fault tests.

## Verification boundary definition

A service is a direct internal-JWT verifier when it accepts a raw Fiducia JWT and validates its signature or JWKS key plus issuer, audience, and time claims before authorizing a request. A service that accepts only trusted-hop identity headers, peer/shared secrets, API-key introspection results, or a remote browser-session result is not a direct internal-JWT verifier.

## Confirmed direct verifiers

| Repository | Boundary | Evidence | Revocation status |
|---|---|---|---|
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

`fiducia_auth::gate::RevocationGate` is the reusable Rust gate for downstream verifiers. Its cache and single-flight identity is a fixed-size SHA-256 digest over length-delimited issuer, audience, tenant, subject, and token ID. Equal `jti` values in different tenants therefore cannot share state, and map keys do not reveal raw identifiers.

The gate must run only after normal offline JWT validation and before scope, tenant, or route authorization. Every `Unavailable` result is a deny. Production transports must use a reader-only credential and a bounded request timeout.

## Remaining completion gates

1. Integrate the load balancer direct-JWT path and remove its pre-revocation identity-cache bypass.
2. Add its tests for allow, exact-token deny, subject deny, stale negative, stale positive, timeout, malformed response, clock regression, tenant isolation, and concurrent refresh coalescing.
3. Wire deployment endpoint/reader secret references without committing values.
4. Run hosted CI and container smoke tests for the load balancer and edge.
5. Exercise revoke and lift propagation across at least two live verifier instances, including authority outage and restart, and attach identifier-safe evidence to DEN-1119/DEN-1120.
6. Repeat the inventory when a repository adds `jsonwebtoken`, `jose`, JWKS validation, or a raw internal-token ingress path; CI follow-up should automate that drift check.
