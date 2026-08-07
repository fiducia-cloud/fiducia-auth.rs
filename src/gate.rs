//! Reusable verifier-side revocation gate.
//!
//! Every internal `fiducia-auth` JWT verifier must, per DEN-1119:
//! 1. perform normal offline JWT validation first (signature, issuer, audience,
//!    time) — that is `crate::token`'s job and happens *before* this gate;
//! 2. consult the bounded local revocation cache before tenant/permission
//!    authorization;
//! 3. coalesce concurrent refreshes per opaque token key;
//! 4. use a bounded control-plane timeout and separate reader credentials;
//! 5. allow only *fresh* cached negative decisions;
//! 6. deny stale/missing negative state until an authoritative refresh succeeds.
//!
//! This module provides that reusable gate on top of [`crate::cache`]. Wiring it
//! into each service's request middleware is the remaining per-service step; the
//! gate itself is transport-agnostic and unit-tested here against a mock
//! authority.
//!
//! # Fail-closed posture
//! The gate never returns [`Authorization::Allowed`] without fresh authoritative
//! evidence. A clock regression, a refresh timeout, or a refresh error all yield
//! [`Authorization::Unavailable`], which callers MUST treat as deny.
//!
//! # Cache identity
//! Cache and single-flight maps are keyed by a SHA-256 digest of length-delimited
//! issuer, audience, tenant, subject, and token-ID fields. Raw identity values are
//! not retained as map keys, and equal `jti` values in different tenants cannot
//! share authorization state.
//!
//! # Reader credentials
//! The gate consults whatever [`RevocationAuthority`] it is constructed with. In
//! production that authority is built with **reader-only** control-plane
//! credentials, kept distinct from the revocation-admin writer path (DEN-1121).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;

use crate::cache::{Decision, Lookup, RevocationCache};
use crate::revocation::{RevocationDecision, RevocationError, RevocationStore};
use crate::token::Claims;

/// Default bound on a single authoritative refresh.
pub const DEFAULT_REFRESH_TIMEOUT: Duration = Duration::from_secs(2);

/// The authoritative revocation source the gate refreshes from. Abstracted so
/// the gate is unit-testable without a live KV control plane. The returned
/// future is `Send` so the gate composes inside multi-threaded async runtimes.
pub trait RevocationAuthority: Send + Sync {
    fn check_revocation(
        &self,
        claims: &Claims,
        now: u64,
    ) -> impl std::future::Future<Output = Result<RevocationDecision, RevocationError>> + Send;
}

/// Production authority: the durable revocation ledger.
impl RevocationAuthority for RevocationStore {
    fn check_revocation(
        &self,
        claims: &Claims,
        now: u64,
    ) -> impl std::future::Future<Output = Result<RevocationDecision, RevocationError>> + Send {
        self.check(claims, now)
    }
}

/// Why a fresh decision could not be established. Every variant is fail-closed
/// (the caller denies) and identifier-free so it is safe to log as a metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// The local clock regressed; the cache refused to serve a decision.
    ClockRegression,
    /// The authority returned an error.
    RefreshFailed,
    /// The authority did not answer within the refresh timeout.
    RefreshTimedOut,
}

/// Outcome of a revocation authorization check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization {
    /// Fresh authoritative evidence the token is not revoked.
    Allowed,
    /// The token or its subject is revoked. Deny.
    Revoked,
    /// Revocation state could not be freshly established. Fail closed: deny.
    Unavailable(Unavailable),
}

fn decision_to_auth(decision: Decision) -> Authorization {
    match decision {
        Decision::Allow => Authorization::Allowed,
        Decision::Deny => Authorization::Revoked,
    }
}

/// Produce a fixed-size, opaque, tenant-scoped key for cache and single-flight
/// state. Length prefixes prevent ambiguous concatenations such as `["ab", "c"]`
/// and `["a", "bc"]` from sharing the same preimage representation.
fn revocation_cache_key(claims: &Claims) -> String {
    let mut digest = Sha256::new();
    for field in [
        claims.iss.as_bytes(),
        claims.aud.as_bytes(),
        claims.org_id.as_bytes(),
        claims.sub.as_bytes(),
        claims.jti.as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    to_hex(&digest.finalize())
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

/// A verifier-side gate that consults a bounded local [`RevocationCache`] and,
/// on stale/missing state, refreshes from a [`RevocationAuthority`] with
/// per-token single-flight coalescing and a bounded timeout.
pub struct RevocationGate<A: RevocationAuthority> {
    cache: Mutex<RevocationCache>,
    authority: A,
    refresh_timeout: Duration,
    key_locks: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
}

impl<A: RevocationAuthority> RevocationGate<A> {
    /// Construct a gate over an existing cache and authority.
    pub fn new(cache: RevocationCache, authority: A, refresh_timeout: Duration) -> Self {
        Self {
            cache: Mutex::new(cache),
            authority,
            refresh_timeout,
            key_locks: Mutex::new(HashMap::new()),
        }
    }

    /// Construct a gate with a default cache and refresh timeout.
    pub fn with_defaults(authority: A) -> Self {
        Self::new(
            RevocationCache::with_defaults(),
            authority,
            DEFAULT_REFRESH_TIMEOUT,
        )
    }

    /// Authorize a token that has already passed offline validation. `now` is
    /// the verifier's current Unix time for this request.
    pub async fn authorize(&self, claims: &Claims, now: u64) -> Authorization {
        let key = revocation_cache_key(claims);

        // Fast path: a fresh cached decision needs no lock and no authority call.
        match self.cache_lookup(&key, now) {
            Err(()) => return Authorization::Unavailable(Unavailable::ClockRegression),
            Ok(Lookup::Fresh(decision)) => return decision_to_auth(decision),
            Ok(Lookup::Stale) | Ok(Lookup::Miss) => {}
        }

        // Slow path: serialize refreshes for this opaque token identity.
        let lock = self.acquire_key(&key);
        let outcome = {
            let _guard = lock.lock().await;
            // Re-check under the guard: a peer may have just refreshed this key.
            match self.cache_lookup(&key, now) {
                Err(()) => Authorization::Unavailable(Unavailable::ClockRegression),
                Ok(Lookup::Fresh(decision)) => decision_to_auth(decision),
                Ok(Lookup::Stale) | Ok(Lookup::Miss) => self.refresh(claims, &key, now).await,
            }
        };
        self.release_key(&key, lock);
        outcome
    }

    /// Perform one authoritative refresh (already holding the per-key guard).
    async fn refresh(&self, claims: &Claims, key: &str, now: u64) -> Authorization {
        // Advance the cache clock at the earliest refresh point.
        if self.record_refresh_start(now).is_err() {
            return Authorization::Unavailable(Unavailable::ClockRegression);
        }

        let refresh = self.authority.check_revocation(claims, now);
        match tokio::time::timeout(self.refresh_timeout, refresh).await {
            Err(_elapsed) => Authorization::Unavailable(Unavailable::RefreshTimedOut),
            Ok(Err(_error)) => Authorization::Unavailable(Unavailable::RefreshFailed),
            Ok(Ok(decision)) => {
                let cached = if decision.revoked {
                    Decision::Deny
                } else {
                    Decision::Allow
                };
                match self.apply(key, cached, now) {
                    Ok(()) => decision_to_auth(cached),
                    // Clock regressed between refresh start and apply: fail closed.
                    Err(()) => Authorization::Unavailable(Unavailable::ClockRegression),
                }
            }
        }
    }

    fn cache_lookup(&self, key: &str, now: u64) -> Result<Lookup, ()> {
        self.cache
            .lock()
            .expect("gate cache mutex")
            .lookup(key, now)
            .map_err(|_| ())
    }

    fn record_refresh_start(&self, now: u64) -> Result<(), ()> {
        self.cache
            .lock()
            .expect("gate cache mutex")
            .record_refresh_start(now)
            .map_err(|_| ())
    }

    fn apply(&self, key: &str, decision: Decision, now: u64) -> Result<(), ()> {
        self.cache
            .lock()
            .expect("gate cache mutex")
            .apply_authoritative(key, decision, now)
            .map_err(|_| ())
    }

    fn acquire_key(&self, key: &str) -> Arc<AsyncMutex<()>> {
        let mut map = self.key_locks.lock().expect("gate key-lock mutex");
        map.entry(key.to_string())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    /// Drop the per-key lock, removing it from the map when no other task still
    /// holds it, so the map stays bounded by in-flight refreshes rather than by
    /// all tokens ever seen.
    fn release_key(&self, key: &str, lock: Arc<AsyncMutex<()>>) {
        let mut map = self.key_locks.lock().expect("gate key-lock mutex");
        // strong_count == map's reference (1) + this `lock` (1) when no waiter.
        if Arc::strong_count(&lock) <= 2 {
            map.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn claims_with_jti(jti: &str) -> Claims {
        Claims {
            sub: "user-1".to_string(),
            org_id: "tenant-1".to_string(),
            scopes: vec!["customer:self-service".to_string()],
            iss: "fiducia-auth".to_string(),
            aud: "fiducia-api".to_string(),
            iat: 1_000,
            exp: 2_000,
            jti: jti.to_string(),
        }
    }

    struct MockAuthority {
        revoked: bool,
        fail: bool,
        delay: Option<Duration>,
        calls: Arc<AtomicUsize>,
    }

    impl MockAuthority {
        fn allow() -> Self {
            Self {
                revoked: false,
                fail: false,
                delay: None,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn deny() -> Self {
            Self {
                revoked: true,
                ..Self::allow()
            }
        }

        fn failing() -> Self {
            Self {
                fail: true,
                ..Self::allow()
            }
        }

        fn slow(delay: Duration) -> Self {
            Self {
                delay: Some(delay),
                ..Self::allow()
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl RevocationAuthority for MockAuthority {
        fn check_revocation(
            &self,
            _claims: &Claims,
            _now: u64,
        ) -> impl std::future::Future<Output = Result<RevocationDecision, RevocationError>> + Send
        {
            let calls = self.calls.clone();
            let revoked = self.revoked;
            let fail = self.fail;
            let delay = self.delay;
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                if let Some(delay) = delay {
                    tokio::time::sleep(delay).await;
                }
                if fail {
                    return Err(RevocationError::CasRetriesExhausted);
                }
                Ok(RevocationDecision {
                    revoked,
                    matched_target: None,
                    generation: None,
                    expires_at: None,
                })
            }
        }
    }

    #[test]
    fn cache_identity_is_fixed_size_opaque_and_field_delimited() {
        let claims = claims_with_jti("tenant-visible-token-id");
        let key = revocation_cache_key(&claims);
        assert_eq!(key.len(), 64);
        assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!key.contains(&claims.org_id));
        assert!(!key.contains(&claims.sub));
        assert!(!key.contains(&claims.jti));

        let mut ambiguous_left = claims.clone();
        ambiguous_left.org_id = "ab".to_string();
        ambiguous_left.sub = "c".to_string();
        let mut ambiguous_right = claims;
        ambiguous_right.org_id = "a".to_string();
        ambiguous_right.sub = "bc".to_string();
        assert_ne!(
            revocation_cache_key(&ambiguous_left),
            revocation_cache_key(&ambiguous_right)
        );
    }

    #[tokio::test]
    async fn equal_jti_values_in_different_tenants_do_not_share_cache_state() {
        let gate = RevocationGate::with_defaults(MockAuthority::allow());
        let first = claims_with_jti("same-jti");
        let mut second = claims_with_jti("same-jti");
        second.org_id = "tenant-2".to_string();
        second.sub = "user-2".to_string();

        assert_eq!(gate.authorize(&first, 100).await, Authorization::Allowed);
        assert_eq!(gate.authorize(&second, 100).await, Authorization::Allowed);
        assert_eq!(gate.authority.call_count(), 2);
    }

    #[tokio::test]
    async fn allows_and_then_serves_from_cache() {
        let gate = RevocationGate::with_defaults(MockAuthority::allow());
        let claims = claims_with_jti("tok-a");
        assert_eq!(gate.authorize(&claims, 100).await, Authorization::Allowed);
        // Second call within the freshness budget must not re-hit the authority.
        assert_eq!(gate.authorize(&claims, 105).await, Authorization::Allowed);
        assert_eq!(gate.authority.call_count(), 1);
    }

    #[tokio::test]
    async fn revoked_is_returned_and_cached() {
        let gate = RevocationGate::with_defaults(MockAuthority::deny());
        let claims = claims_with_jti("tok-b");
        assert_eq!(gate.authorize(&claims, 100).await, Authorization::Revoked);
        assert_eq!(gate.authorize(&claims, 101).await, Authorization::Revoked);
        assert_eq!(gate.authority.call_count(), 1);
    }

    #[tokio::test]
    async fn fails_closed_on_authority_error() {
        let gate = RevocationGate::with_defaults(MockAuthority::failing());
        let claims = claims_with_jti("tok-c");
        assert_eq!(
            gate.authorize(&claims, 100).await,
            Authorization::Unavailable(Unavailable::RefreshFailed)
        );
    }

    #[tokio::test]
    async fn fails_closed_on_refresh_timeout() {
        let gate = RevocationGate::new(
            RevocationCache::with_defaults(),
            MockAuthority::slow(Duration::from_secs(30)),
            Duration::from_millis(20),
        );
        let claims = claims_with_jti("tok-d");
        assert_eq!(
            gate.authorize(&claims, 100).await,
            Authorization::Unavailable(Unavailable::RefreshTimedOut)
        );
    }

    #[tokio::test]
    async fn fails_closed_on_clock_regression_without_hitting_authority() {
        let gate = RevocationGate::with_defaults(MockAuthority::allow());
        let claims = claims_with_jti("tok-e");
        assert_eq!(gate.authorize(&claims, 100).await, Authorization::Allowed);
        // Clock moves backward: the cache refuses, gate fails closed, no new call.
        assert_eq!(
            gate.authorize(&claims, 50).await,
            Authorization::Unavailable(Unavailable::ClockRegression)
        );
        assert_eq!(gate.authority.call_count(), 1);
    }

    #[tokio::test]
    async fn stale_entry_triggers_a_fresh_refresh() {
        let gate = RevocationGate::new(
            RevocationCache::new(30, 64),
            MockAuthority::allow(),
            DEFAULT_REFRESH_TIMEOUT,
        );
        let claims = claims_with_jti("tok-f");
        assert_eq!(gate.authorize(&claims, 100).await, Authorization::Allowed);
        // Past the freshness budget -> stale -> a second authoritative refresh.
        assert_eq!(gate.authorize(&claims, 200).await, Authorization::Allowed);
        assert_eq!(gate.authority.call_count(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_refreshes_are_coalesced_per_key() {
        let gate = Arc::new(RevocationGate::new(
            RevocationCache::with_defaults(),
            MockAuthority::slow(Duration::from_millis(50)),
            DEFAULT_REFRESH_TIMEOUT,
        ));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let gate = gate.clone();
            handles.push(tokio::spawn(async move {
                let claims = claims_with_jti("tok-hot");
                gate.authorize(&claims, 100).await
            }));
        }
        for handle in handles {
            assert_eq!(handle.await.unwrap(), Authorization::Allowed);
        }
        // Single-flight: eight concurrent callers, one authority round-trip.
        assert_eq!(gate.authority.call_count(), 1);
        // And the per-key lock was cleaned up afterward.
        assert!(gate.key_locks.lock().unwrap().is_empty());
    }
}
