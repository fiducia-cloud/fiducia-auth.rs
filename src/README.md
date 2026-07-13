# src — fiducia-auth service code

The Rust source for the auth server. It authenticates two planes without hitting
Supabase or the database on the hot path: B2B humans (Supabase session JWTs) and
their machines (static API keys).

Key files:

- `main.rs` — axum wiring; splits dashboard vs. internal routes and applies the
  Supabase-session guard.
- `supabase.rs` — verifies Supabase session JWTs offline via cached JWKS, with a
  `/auth/v1/user` fallback for shared-secret projects (dashboard plane).
- `keys.rs` — org-scoped, idempotent API-key create/list/rotate/revoke and
  fail-closed durable `introspect`; stores only a hash of HMAC-derived secrets
  and requires the matching org index (data plane).
- `token.rs` — mints short-lived fiducia JWTs and publishes the public JWKS so
  other components verify offline.
- `store.rs` — durable API-key storage in fiducia's own in-cluster KV, with
  authenticated node requests isolated under a dedicated service organization.
- `sync.rs` — background pull of Supabase org/plan rows into a local hot cache.
- `model.rs` — shared auth domain types.

Human org membership and roles come only from verified Supabase
`app_metadata`; customer-mintable API-key scopes never include operator/admin
authority. Durable key/index mutations use KV compare-and-set so concurrent
replicas cannot silently lose org-index entries or resurrect revoked keys. The
standalone customer app may call browser-facing routes only from the one exact
configured customer origin; admin cookies and admin routes are not part of this
service.
