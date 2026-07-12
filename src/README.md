# src — fiducia-auth service code

The Rust source for the auth server. It authenticates two planes without hitting
Supabase or the database on the hot path: B2B humans (Supabase session JWTs) and
their machines (static API keys).

Key files:

- `main.rs` — axum wiring; splits dashboard vs. internal routes and applies the
  Supabase-session guard.
- `supabase.rs` — verifies Supabase session JWTs offline via cached JWKS, with a
  `/auth/v1/user` fallback for shared-secret projects (dashboard plane).
- `keys.rs` — API-key create/list/revoke and `introspect`; stores only a hash of
  the secret (data plane).
- `token.rs` — mints short-lived fiducia JWTs and publishes the public JWKS so
  other components verify offline.
- `store.rs` — durable API-key storage in fiducia's own in-cluster KV.
- `sync.rs` — background pull of Supabase org/plan rows into a local hot cache.
- `model.rs` — shared auth domain types.
