# fiducia-auth

The auth server for [fiducia.cloud](https://fiducia.cloud). It authenticates two
very different callers — and **neither hits Supabase (or the DB) on the hot
path**. This repository is a **skeleton**: routing + the API-key store are real
(in-memory); Supabase JWT verification, real hashing/JWT signing, and Postgres
are stubbed with `TODO`s.

## Two planes, two credentials

| Plane | Who | Credential | Verified how |
|-------|-----|-----------|--------------|
| Dashboard | B2B humans | Supabase session **JWT** | **offline** signature check via Supabase JWKS (cached) — Supabase hit only at login/refresh |
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
  JWKS. No Supabase call per request.
- **API keys** → the edge/LB caches `introspect` results for a short TTL, so the
  steady state is a local decision. Revocation lag = the TTL.
- Optional: `POST /v1/token` **exchanges** a key for a short-lived JWT that any
  component verifies **offline** via `/.well-known/jwks.json` — zero auth calls
  on the hot path; revocation via short `exp` (+ optional denylist).

Clients keep sending a **simple static API key** (best B2B DX); the edge does the
validation/caching and attaches a verified identity inward.

## Endpoints

| Route | Caller | Purpose |
|-------|--------|---------|
| `POST /v1/keys` | dashboard (Supabase JWT) | create a key (raw shown **once**) |
| `GET /v1/keys` | dashboard | list keys (masked) |
| `DELETE /v1/keys/{id}` | dashboard | revoke |
| `POST /v1/introspect` | edge/LB (internal) | validate key → org + scopes (cache this) |
| `POST /v1/token` | edge/LB (internal) | exchange key → short-lived JWT |
| `GET /.well-known/jwks.json` | anyone | public keys for offline JWT verify |
| `GET /healthz` | — | liveness |

## Storage & secrets

- Only a **hash** of the key secret is stored (`TODO`: argon2id); the raw key is
  returned exactly once at creation.
- Keys are scoped to an **org**; dashboard ops require a Supabase session whose
  user belongs to that org.
- Source of truth: **Supabase** for users/orgs; API keys in Supabase Postgres
  (`TODO`: `sqlx`). "Syncs with Supabase" = reads identity/membership from it.

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

Env (real build): `SUPABASE_URL`, `SUPABASE_JWKS_URL`, `DATABASE_URL`, JWT signing key.

## Related

- [`fiducia-load-balance.rs`](https://github.com/fiducia-cloud/fiducia-load-balance.rs) / [`fiducia-edge`](https://github.com/fiducia-cloud/fiducia-edge) — call `introspect` (and cache) to gate the API.
- [`fiducia-node.rs`](https://github.com/fiducia-cloud/fiducia-node.rs) — the coordination API being protected.
