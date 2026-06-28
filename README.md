# fiducia-auth

The auth server for [fiducia.cloud](https://fiducia.cloud). It authenticates two
very different callers — and **neither hits Supabase (or the DB) on the hot
path**. Routing, Supabase Auth verification, and the API-key store are real
and file-backed; fiducia-issued JWT signing is env-backed. Supabase remains the
source of truth for human identity and org membership.

## Two planes, two credentials

| Plane | Who | Credential | Verified how |
|-------|-----|-----------|--------------|
| Dashboard | B2B humans | Supabase session **JWT** | **offline** signature check via Supabase JWKS (cached), with `/auth/v1/user` fallback for shared-secret projects |
| Data API | their machines | static **API key** `fdc_live_<id>.<secret>` | edge/LB calls `introspect` **once** and caches it (short TTL) |

```
B2B user → Supabase Auth ──(JWT)──► dashboard → POST /v1/keys ──► raw key (shown once)
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
| `GET /v1/me` | dashboard (Supabase JWT) | return the authenticated Supabase user context |
| `POST /v1/keys` | dashboard (Supabase JWT) | create a key (raw shown **once**) |
| `GET /v1/keys` | dashboard | list keys (masked) |
| `DELETE /v1/keys/{id}` | dashboard | revoke |
| `POST /v1/introspect` | edge/LB (internal) | validate key → org + scopes (cache this) |
| `POST /v1/token` | edge/LB (internal) | exchange key → short-lived JWT |
| `GET /.well-known/jwks.json` | anyone | public keys for offline JWT verify |
| `GET /healthz` | — | liveness |

## Storage & secrets

- Only a **hash** of the key secret is stored; the raw key is returned exactly
  once at creation. Secrets are 256-bit random values, so SHA-256 plus
  constant-time comparison is sufficient for introspection.
- Keys are scoped to an **org** and may be narrowed to a **project**; dashboard
  ops require a Supabase session whose user has the right org/project role.
- API keys persist in a JSON store selected by `FIDUCIA_AUTH_STORE_PATH` or
  `FIDUCIA_AUTH_STORE_DIR`; otherwise it defaults under the local data dir.
- Source of truth: **Supabase** for human login identity and org membership.
  `fiducia-auth` materializes the hot API-key state locally so edge/LB calls
  stay private and fast.
- API-key introspection returns `{org, project?, scopes}` for the edge/LB to
  cache. Serious B2B deployments can require both the API key and a registered
  client certificate fingerprint.

## Layout

| File | Responsibility |
|------|----------------|
| `src/main.rs` | axum wiring, dashboard-vs-internal routes, Supabase-session guard |
| `src/supabase.rs` | verify Supabase session JWT (offline via cached JWKS) |
| `src/keys.rs` | API key create/list/revoke + **introspect** (hashed store) |
| `src/token.rs` | mint short-lived JWT + publish JWKS |
| `src/model.rs` | domain types |

## Run locally

```bash
cargo run    # :8097 (override PORT)
curl localhost:8097/healthz
```

Env:

- `SUPABASE_URL` or `SUPABASE_PROJECT_REF`
- `SUPABASE_PUBLISHABLE_KEY` for the `/auth/v1/user` fallback
- `SUPABASE_AUTH_ISSUER`, optional override for `{SUPABASE_URL}/auth/v1`
- `SUPABASE_AUTH_JWKS_URL`, optional override for the JWKS endpoint
- `SUPABASE_AUTH_AUDIENCE`, defaults to `authenticated`
- `SUPABASE_AUTH_ALLOW_REMOTE_USERINFO`, defaults to `true`
- `FIDUCIA_DEFAULT_ORG_ID`, used until org membership moves into Supabase Postgres
- `FIDUCIA_AUTH_STORE_PATH` or `FIDUCIA_AUTH_STORE_DIR`, optional API-key store location
- `FIDUCIA_JWT_PRIVATE_KEY_PEM`, required for `POST /v1/token`
- `FIDUCIA_JWT_PUBLIC_JWK`, published by `/.well-known/jwks.json`
- `FIDUCIA_JWT_ALG`, one of `RS256` or `ES256` (default `RS256`)
- `FIDUCIA_JWT_KID`, `FIDUCIA_JWT_ISSUER`, `FIDUCIA_JWT_AUDIENCE`

## Related

- [`fiducia-load-balance.rs`](https://github.com/fiducia-cloud/fiducia-load-balance.rs) / [`fiducia-edge`](https://github.com/fiducia-cloud/fiducia-edge) — call `introspect` (and cache) to gate the API.
- [`fiducia-node.rs`](https://github.com/fiducia-cloud/fiducia-node.rs) — the coordination API being protected.
