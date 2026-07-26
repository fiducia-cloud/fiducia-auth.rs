# fiducia-auth

The auth server for [fiducia.cloud](https://fiducia.cloud). It authenticates two
very different callers. Human JWT verification avoids Supabase on the normal
path; API-key introspection reads authoritative Fiducia KV so rotations and
revocations are visible across auth replicas. Routing, Supabase Auth
verification, and the API-key store are real;
API-key records are durable in Fiducia KV and JWT signing is env-backed.
Supabase remains the
source of truth for human identity and org membership.

## Two planes, two credentials

| Plane | Who | Credential | Verified how |
|-------|-----|-----------|--------------|
| Dashboard | B2B humans | Supabase session **JWT** | **offline** signature check via Supabase JWKS (cached), with `/auth/v1/user` fallback for shared-secret projects |
| Data API | their machines | static **API key** `fdc_live_<id>.<secret>` | edge/LB calls `introspect` **once** and caches it (short TTL) |

```
B2B user → Supabase Auth ──(JWT)──► customer BFF → POST /v1/keys ──► raw key (no-store)
                                                         │ store HASH only
client → Authorization: Bearer fdc_live_… → edge/LB ──► POST /v1/introspect ─┐
                                              ▲  cache {key → org,scopes} TTL │
                                              └────────────────────────────────┘
```

### Why it never calls auth per request

- **Supabase JWTs are signed** → verify the signature locally with the cached
  JWKS when asymmetric signing keys are enabled. Projects still using
  shared-secret signing fall back to Supabase's Auth user endpoint.
- **API keys** → the edge/LB caches `introspect` results for a short TTL, so the
  steady state is a local decision. Revocation lag = the TTL.
- Optional: `POST /v1/token` **exchanges** a key for a short-lived JWT signed by
  `fiducia-auth`; any component verifies it **offline** via
  `/.well-known/jwks.json` — zero auth calls on the hot path; revocation via
  short `exp` (+ optional denylist).

Clients keep sending a **simple static API key** (best B2B DX); the edge does the
validation/caching and attaches a verified identity inward.

## Endpoints

| Route | Caller | Purpose |
|-------|--------|---------|
| `GET /v1/me` | customer/admin app (Supabase JWT) | return user id, email, orgs, and trusted roles; each app enforces its own surface authorization |
| `POST /v1/keys` | customer app/BFF (Supabase JWT) | create a key; requires `Idempotency-Key` (raw returned to the original request and exact retries) |
| `GET /v1/keys?org_id={org}` | customer app/BFF | list one authorized org's keys (masked) |
| `POST /v1/keys/{id}/rotate?org_id={org}` | customer app/BFF | replace the authoritative secret; requires `Idempotency-Key` and reports bounded consumer-cache overlap (raw returned to the original request and exact retries) |
| `DELETE /v1/keys/{id}?org_id={org}` | customer app/BFF | revoke |
| `POST /v1/introspect` | edge/LB (internal) | validate key → org + scopes (cache this); **requires `x-server-auth`** |
| `POST /v1/token` | any valid API-key holder (public) | exchange key → short-lived JWT; authenticated by the key itself, **no `x-server-auth`** |
| `GET /.well-known/jwks.json` | anyone | public keys for offline JWT verify |
| `GET /healthz` | — | liveness |

## Storage & secrets

- `fiducia-auth` is the sole customer API-key authority. Only a **hash** of the
  key secret is stored. Create/rotate require a client `Idempotency-Key`; a
  domain-separated HMAC derives a pseudorandom 256-bit credential so an exact
  retry can recover the same response without persisting the raw secret. Reusing
  an idempotency key with a different create payload returns `409`. Stored
  secrets use pepper-keyed HMAC-SHA-256 plus constant-time comparison. Legacy
  `sha256:` records are rejected by default and can be enabled only for an
  explicit rotation window; every new or rotated key is written as
  `hmac-sha256:`.
- Public key metadata carries a durable monotonic `version`. Rotation replaces
  the authoritative secret immediately and advances the version; the response's
  `overlap_seconds` reports how long an already-cached positive edge/LB decision
  may remain valid. Revocation advances the version only on the first
  active-to-revoked transition.
- Customer-created keys default to `require_idempotency: true`; durable records
  written before that field existed remain backward-compatible as `false`.
- Keys are scoped to an **org**; lifecycle operations require a Supabase session
  whose verified `app_metadata` includes that organization.
- API keys persist in the Fiducia KV endpoint selected by `FIDUCIA_KV_URL`.
  Every request authenticates to the node using `FIDUCIA_INTERNAL_SECRET` and a
  dedicated `FIDUCIA_KV_ORG_ID` tenant. Startup fails when those durable-storage
  credentials are not configured.
- Key records and per-org indexes form one credential identity. Introspection
  requires both, so a record written before an index failure remains unusable;
  an exact idempotent create retry repairs the index and returns the same secret.
- Source of truth: **Supabase** for human login identity and org membership,
  and Fiducia KV for API-key hashes and versions. Auth replicas read KV for
  each introspection request; edge/LB consumers may keep a bounded positive
  decision cache whose maximum TTL is reported by rotation.
- API-key introspection returns `{org, project?, scopes}` for the edge/LB to
  cache. Serious B2B deployments can require both the API key and a registered
  client certificate fingerprint.

## Layout

| File | Responsibility |
|------|----------------|
| `src/main.rs` | axum wiring, dashboard-vs-internal routes, Supabase-session guard |
| `src/supabase.rs` | verify Supabase session JWT (offline via cached JWKS) |
| `src/keys.rs` | API key create/list/rotate/revoke + **introspect** (hashed store) |
| `src/token.rs` | mint short-lived JWT + publish JWKS |
| `src/model.rs` | domain types |

## Run locally

```bash
cargo run --locked    # :8097 (override PORT)
curl localhost:8097/healthz
```

### Reproducible container and CI dependency

This crate uses generated Rust contracts from the sibling
`fiducia-interfaces` repository. CI and the Dockerfile both pin that dependency
to commit `2c5c806174e067fbe83ad48b724366323ba390a2`; neither follows a moving
branch. The Docker build checks the commit out detached and verifies that its
full `HEAD` equals `INTERFACES_SHA`, so a branch, tag, or abbreviated hash fails
closed. To upgrade the contracts, update the Dockerfile argument and the CI
checkout `ref` together, then validate with the committed Cargo lockfile.

An intentional local override must also be a full commit SHA:

```bash
docker build \
  --build-arg INTERFACES_SHA=<40-character-commit-sha> \
  -t fiducia-auth:local .
```

Organization access and application roles come only from Supabase
`app_metadata`; user-editable metadata and a synthetic default organization are
never trusted. Operator accounts carry `admin` or `operator` in
`app_metadata.fiducia_roles`, `app_metadata.roles`, or `app_metadata.role`.
`GET /v1/me` returns those trusted roles so separately deployed applications can
authorize their own surface without maintaining email-based role lists. The
admin app additionally requires its own local operator-registry entry.

## Configuration

Everything is read from the environment at startup. Startup **fails fast** if a
required secret or endpoint is missing, so a misconfigured replica never serves
traffic with a half-initialized identity.

### Core

| Var | Type | Secret? | Meaning | Default |
|-----|------|:------:|---------|---------|
| `PORT` | integer | no | HTTP listen port | `8097` |
| `FIDUCIA_JWT_SIGNING_KEY` | string (PEM) | **yes** | PKCS#8 EC P-256 private key that signs fiducia JWTs; shared across replicas via a k8s secret | — (required) |
| `FIDUCIA_KV_URL` | string (URL) | no | Durable fiducia KV endpoint backing the API-key store | — (required) |
| `FIDUCIA_KV_ORG_ID` | string | no | Dedicated node tenant for auth-owned KV records; sent as `x-fiducia-org-id` | `fiducia-auth` |
| `FIDUCIA_INTERNAL_SECRET` | string | **yes** | Node service credential sent as `x-fiducia-internal-auth` on every KV request | — (required) |
| `FIDUCIA_KEY_IDEMPOTENCY_SECRET` | string (32+ bytes, no whitespace) | **yes** | Stable HMAC root used to derive replayable create/rotate credentials; changing it breaks outstanding exact retries and requires a coordinated migration | — (required) |
| `CUSTOMER_API_KEY_PEPPER` | string (32+ bytes, no whitespace) | **yes** | Server-side HMAC key for stored API-key hashes; rotate existing keys before retiring legacy `sha256:` reads | — (required) |
| `CUSTOMER_API_KEY_HASH_ALGORITHM` | enum | no | Stored key-hash algorithm; any value other than `hmac-sha256` aborts startup | `hmac-sha256` |
| `CUSTOMER_API_KEY_ACCEPT_LEGACY_SHA256` | bool | no | Temporary migration gate for pre-pepper `sha256:` records; rotate all such keys, then disable | `false` |
| `FIDUCIA_ROTATION_OVERLAP_SECONDS` | positive integer | no | Maximum positive-introspection cache TTL across edge/LB consumers; reported to clients after rotation. Invalid or zero values abort startup. | `60` |
| `FIDUCIA_INTROSPECT_SECRET` | string | **yes** | `x-server-auth` shared secret required on the internal `POST /v1/introspect` route | — (required) |
| `FIDUCIA_CUSTOMER_ORIGIN` | HTTP(S) origin | no | Exact independently hosted customer-app origin allowed by CORS; paths, wildcards, query strings, and `null` are rejected | `https://app.fiducia.cloud` |
| `SUPABASE_URL` | string (URL) | no | Supabase project URL — the system of record for org membership | derived from project ref |
| `SUPABASE_SERVICE_ROLE_KEY` | string | **yes** | Supabase service-role key used by the required org sync | — (required) |
| `SUPABASE_SYNC_INTERVAL_SECS` | integer | no | Interval between Supabase org syncs, in seconds | `60` |

### Supabase session verification (optional overrides)

| Var | Type | Secret? | Meaning | Default |
|-----|------|:------:|---------|---------|
| `SUPABASE_PUBLISHABLE_KEY` | string | no | Publishable key for the `/auth/v1/user` fallback (shared-secret projects) | none |
| `SUPABASE_PROJECT_REF` / `SUPABASE_PROJECT_ID` | string | no | Project ref used to derive URLs when `SUPABASE_URL` is unset | none; one source is required |
| `SUPABASE_AUTH_ISSUER` | string | no | Override for `{SUPABASE_URL}/auth/v1` | derived |
| `SUPABASE_AUTH_JWKS_URL` | string | no | Override for the JWKS endpoint | `{issuer}/.well-known/jwks.json` |
| `SUPABASE_AUTH_USER_URL` | string | no | Override for the `/auth/v1/user` endpoint | `{issuer}/user` |
| `SUPABASE_AUTH_AUDIENCE` | string | no | Expected `aud` claim | `authenticated` |
| `SUPABASE_AUTH_JWKS_TTL_SECS` | integer | no | JWKS cache TTL, in seconds | `600` |
| `SUPABASE_AUTH_ALLOW_REMOTE_USERINFO` | bool | no | Allow the `/auth/v1/user` fallback for shared-secret projects (**see below**) | `true` |
| `SUPABASE_ORGS_TABLE` | string | no | Table synced for org metadata | `organizations` |
| `SUPABASE_ORGS_ID_COLUMN` | string | no | Id column in that table | `id` |

### Verification-mode flag

`SUPABASE_AUTH_ALLOW_REMOTE_USERINFO` is the one flag that changes how a session
is verified, so treat it deliberately:

- **`true` (default)** — for asymmetric (JWKS-signed) tokens, fiducia-auth still
  verifies the signature **offline** first; the remote `/auth/v1/user` endpoint is
  only a fallback. For shared-secret (HS256) projects with no public JWKS, the
  token is validated by **Supabase itself** over that endpoint. Either way the
  token is validated — this is fail-safe, not a bypass — but it adds a network
  dependency on Supabase and requires `SUPABASE_PUBLISHABLE_KEY`.
- **`false`** — offline JWKS verification only. Set this if every project uses
  asymmetric signing keys and you want zero auth-time calls to Supabase; tokens
  that aren't asymmetrically signed are rejected outright.

There is **no** flag that disables authentication, accepts unsigned tokens, or
grants a synthetic "all orgs" identity. Org access is derived solely from
admin-controlled Supabase `app_metadata`; user-writable `user_metadata` is never
trusted for org membership or operator roles. API-key scopes intentionally do
not include admin-dashboard permissions, and introspection strips any such scope
from legacy durable records. Human operator access is a verified Supabase role,
never a customer-minted key scope. The top-level Supabase JWT
`role=authenticated` proves token class but does not grant Fiducia operator
access.

## CLI flags → env (flags-2-env)

The non-secret `FIDUCIA_*` / `SUPABASE_*` variables above can be supplied as CLI
flags via the pinned
[`ORESoftware/flags-2-env`](https://github.com/ORESoftware/flags-2-env) parser
(schema in `.cli-flags.toml`, audited in CI by `.github/workflows/cli-flags.yml`):

```bash
git submodule update --init --recursive
make -B -C vendor/flags-2-env all
scripts/with-flags2env.sh \
  --port=8097 --kv-url=http://fiducia-node.fiducia.svc:8090 \
  --kv-org-id=fiducia-auth --customer-origin=https://app.fiducia.cloud \
  --supabase-url=https://<ref>.supabase.co -- cargo run --locked
```

Secrets such as `FIDUCIA_JWT_SIGNING_KEY`, `FIDUCIA_INTERNAL_SECRET`,
`FIDUCIA_INTROSPECT_SECRET`, `FIDUCIA_KEY_IDEMPOTENCY_SECRET`,
`CUSTOMER_API_KEY_PEPPER`, and `SUPABASE_SERVICE_ROLE_KEY` are intentionally
excluded from the CLI schema.
Inject them only through the environment or your secret store so they cannot
leak through shell history or process listings.

## Security

Hardening in place:

- **Constant-time** comparison of both the API-key secret hash (`keys.rs`) and the
  internal `x-server-auth` secret (`main.rs`), so neither leaks byte-by-byte under
  timing probes.
- **Two data-plane endpoints, two threat models.** `POST /v1/introspect` is a
  server-to-server oracle — it reports validity/scopes for *any* key the caller
  submits, including keys the caller does not hold — so it is internal-only and
  gated by the `x-server-auth` shared secret (`FIDUCIA_INTROSPECT_SECRET`);
  requests without it get 401. `POST /v1/token` is **intentionally public and is
  not `x-server-auth`-gated**: it is self-authenticated by the API key itself. The
  caller must present a valid `fdc_…` key (verified by the same constant-time
  secret-hash check), an invalid key yields 401, and a valid key only mints a JWT
  scoped to *that key's own* org/scopes. Customers exchanging a key for an
  offline-verifiable JWT never hold the internal secret, so gating `/v1/token`
  would break the exchange without adding protection — a caller lacking a valid
  key already learns nothing from it.
- Only a **pepper-keyed HMAC-SHA-256 hash** of a 256-bit HMAC-derived API-key
  secret is stored. A leaked key store is insufficient to test guesses without
  the separately managed pepper. Legacy unkeyed hashes are readable only when
  the explicit migration gate is enabled, while every create/rotate writes the
  current format.
  Exact `Idempotency-Key` retries deterministically recover the original raw
  response; changed-payload reuse fails with `409`. Secret-bearing responses set
  `Cache-Control: no-store`.
- **API-key lifecycle is monotonic and race-safe.** Key records and per-org
  indexes use Fiducia KV compare-and-set. Concurrent index additions are merged;
  rotate/revoke retry from the latest revision; a revoked key can never rotate
  back to active; unindexed partial records cannot introspect; and malformed or
  mismatched durable records fail closed.
- **No authoritative introspection cache in auth.** Production introspection
  reads durable KV on every request and returns `503` on storage failure rather
  than accepting a stale local value. Edge/LB positive caches remain bounded by
  `FIDUCIA_ROTATION_OVERLAP_SECONDS`.
- **Fail-fast startup**: missing `FIDUCIA_JWT_SIGNING_KEY`,
  `FIDUCIA_INTROSPECT_SECRET`, `FIDUCIA_INTERNAL_SECRET`,
  `FIDUCIA_KEY_IDEMPOTENCY_SECRET`, `FIDUCIA_KV_URL`, `SUPABASE_URL`, or
  `SUPABASE_SERVICE_ROLE_KEY` aborts boot; the org cache completes one sync
  before serving so an empty cache can't impersonate real state.
- **Offline-first** Supabase JWT verification with symmetric-JWK rejection and
  required `iss`/`aud`/`sub` claims; org membership only from admin-controlled
  `app_metadata`.
- Request hardening layers: **body-size cap** (64 KiB), **request timeout** (15 s),
  and **panic-catching** (`CatchPanicLayer`) so a handler panic becomes a 500
  rather than a dropped connection. Browser CORS uses one normalized exact
  `FIDUCIA_CUSTOMER_ORIGIN`; wildcard and credential-cookie CORS are not enabled.

`jsonwebtoken` uses the AWS-LC backend rather than its RustCrypto default, so the
active runtime dependency graph is free of the vulnerable `rsa` crate and passes
`cargo audit`. The only accepted advisory is documented in `.cargo/audit.toml`:

- **`proc-macro-error` — RUSTSEC-2024-0370** (unmaintained). Build-time proc-macro
  dependency only; never linked into the running service, so no runtime risk.

## Related

- [`fiducia-load-balance.rs`](https://github.com/fiducia-cloud/fiducia-load-balance.rs) / [`fiducia-edge`](https://github.com/fiducia-cloud/fiducia-edge) — call `introspect` (and cache) to gate the API.
- [`fiducia-node.rs`](https://github.com/fiducia-cloud/fiducia-node.rs) — the coordination API being protected.
