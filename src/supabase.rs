//! Supabase session verification (skeleton) — the **dashboard** plane.
//!
//! B2B humans log into the dashboard via Supabase Auth and get a Supabase
//! session JWT. We verify that JWT **offline**: Supabase signs it, we fetch its
//! JWKS (public keys) *once* and cache them, then verify every request's
//! signature locally. So we hit Supabase only when the JWKS rotates — never
//! per request.
//!
//! "Syncs with Supabase" = Supabase is the source of truth for users; org
//! membership lives in a table we read (or receive via Supabase webhooks).

use crate::model::UserCtx;

/// Verifies a Supabase JWT and returns the caller identity, or `None` if invalid.
///
/// TODO: with `jsonwebtoken` + cached JWKS:
///   1. fetch `{SUPABASE_URL}/auth/v1/.well-known/jwks.json` once, cache it
///      (refresh on `kid` miss);
///   2. verify signature + `aud`/`exp`/`iss`;
///   3. read `sub` (user id) + email from claims;
///   4. look up org membership for that user.
pub async fn verify_session(_bearer_jwt: &str) -> Option<UserCtx> {
    // Skeleton: no verification yet.
    None
}

/// Holds the cached Supabase JWKS so verification never calls Supabase per
/// request. TODO: real fetch + `kid`-keyed cache with refresh.
#[derive(Default)]
pub struct JwksCache;

impl JwksCache {
    pub fn new() -> Self {
        JwksCache
    }
}
