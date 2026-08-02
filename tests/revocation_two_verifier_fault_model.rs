//! DEN-1125 — deterministic two-verifier revocation fault model.
//!
//! A test-only reference authority plus two independent [`RevocationGate`]
//! verifiers driven over the public cache/gate contract. Everything is
//! deterministic: fixed logical Unix timestamps, no sleeps, no live network.
//! The reference authority answers synchronously from in-memory state, so a
//! gate's bounded refresh timeout is never actually exercised by wall-clock.
//!
//! # Freshness-deadline convention (assumption)
//! A decision observed at `t` with freshness budget `B` is *fresh* for
//! `now ∈ [t, t+B]` and *stale* for `now ≥ t+B+1`. This harness treats
//! `t+B+1` as the **freshness deadline**: the first instant at which a cached
//! decision no longer authorizes on its own. The bounded-freshness invariant
//! below is asserted against that point.
//!
//! # Known unproved surfaces (out of scope, per the ticket)
//! Multi-process / Kubernetes fault injection, real partitions or NTP failures,
//! production propagation SLOs, and request-path integration are **not** modeled
//! here — this is an in-process, logical-time reference model only.

use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, Mutex};

use fiducia_auth::cache::RevocationCache;
use fiducia_auth::gate::{
    Authorization, RevocationAuthority, RevocationGate, DEFAULT_REFRESH_TIMEOUT,
};
use fiducia_auth::revocation::{RevocationDecision, RevocationError};
use fiducia_auth::token::Claims;

/// Freshness budget used across the model.
const B: u64 = 30;

/// A deterministic in-memory revocation authority shared by both verifiers.
/// Clone shares the same state (via `Arc`), modeling one control plane.
#[derive(Clone, Default)]
struct ReferenceAuthority {
    state: Arc<Mutex<AuthorityState>>,
}

#[derive(Default)]
struct AuthorityState {
    revoked: HashSet<String>,
    outage: bool,
    calls: usize,
}

impl ReferenceAuthority {
    fn revoke(&self, jti: &str) {
        self.state.lock().unwrap().revoked.insert(jti.to_string());
    }
    fn lift(&self, jti: &str) {
        self.state.lock().unwrap().revoked.remove(jti);
    }
    fn set_outage(&self, outage: bool) {
        self.state.lock().unwrap().outage = outage;
    }
    fn calls(&self) -> usize {
        self.state.lock().unwrap().calls
    }
}

impl RevocationAuthority for ReferenceAuthority {
    fn check_revocation(
        &self,
        claims: &Claims,
        _now: u64,
    ) -> impl Future<Output = Result<RevocationDecision, RevocationError>> + Send {
        let state = self.state.clone();
        let jti = claims.jti.clone();
        async move {
            let mut state = state.lock().unwrap();
            state.calls += 1;
            if state.outage {
                // A control-plane outage is an error, not a decision.
                return Err(RevocationError::CasRetriesExhausted);
            }
            Ok(RevocationDecision {
                revoked: state.revoked.contains(&jti),
                matched_target: None,
                generation: None,
                expires_at: None,
            })
        }
    }
}

fn verifier(authority: ReferenceAuthority) -> RevocationGate<ReferenceAuthority> {
    RevocationGate::new(
        RevocationCache::new(B, 1024),
        authority,
        DEFAULT_REFRESH_TIMEOUT,
    )
}

fn claims(jti: &str, tenant: &str) -> Claims {
    Claims {
        sub: format!("sub-{jti}"),
        org_id: tenant.to_string(),
        scopes: Vec::new(),
        iss: "fiducia-auth".to_string(),
        aud: "fiducia-api".to_string(),
        iat: 0,
        exp: 10_000_000,
        jti: jti.to_string(),
    }
}

/// Cold cache + unreachable authority: both instances fail closed, never allow.
#[tokio::test]
async fn cold_start_fails_closed_on_both_instances() {
    let authority = ReferenceAuthority::default();
    authority.set_outage(true);
    let a = verifier(authority.clone());
    let b = verifier(authority.clone());
    let token = claims("tok", "t1");
    assert!(matches!(
        a.authorize(&token, 100).await,
        Authorization::Unavailable(_)
    ));
    assert!(matches!(
        b.authorize(&token, 100).await,
        Authorization::Unavailable(_)
    ));
}

/// Bounded-freshness invariant: a fresh negative authorizes within `[t, t+B]`
/// and is served from cache, but at the deadline `t+B+1` it must refresh rather
/// than serve the stale negative — proven by putting the authority in outage so
/// a wrongful stale serve would surface as `Allowed`.
#[tokio::test]
async fn fresh_negative_authorizes_within_bound_and_never_beyond_the_deadline() {
    let authority = ReferenceAuthority::default();
    let v = verifier(authority.clone());
    let token = claims("tok", "t1");

    assert_eq!(v.authorize(&token, 100).await, Authorization::Allowed);
    // Still fresh at the far edge of the budget; no second authority round-trip.
    assert_eq!(v.authorize(&token, 100 + B).await, Authorization::Allowed);
    assert_eq!(authority.calls(), 1);

    authority.set_outage(true);
    let at_deadline = v.authorize(&token, 100 + B + 1).await;
    assert!(matches!(at_deadline, Authorization::Unavailable(_)));
    assert_ne!(at_deadline, Authorization::Allowed);
}

/// An exact-token revoke reaches one instance before the other, then converges.
#[tokio::test]
async fn revoke_propagates_to_one_instance_before_the_other_then_converges() {
    let authority = ReferenceAuthority::default();
    let a = verifier(authority.clone());
    let b = verifier(authority.clone());
    let token = claims("tok", "t1");

    assert_eq!(a.authorize(&token, 100).await, Authorization::Allowed);
    assert_eq!(b.authorize(&token, 100).await, Authorization::Allowed);

    authority.revoke("tok");

    // Both caches are still fresh: real propagation lag, not a bug.
    assert_eq!(a.authorize(&token, 110).await, Authorization::Allowed);
    // A crosses its deadline first and refreshes into the revoke.
    assert_eq!(
        a.authorize(&token, 100 + B + 1).await,
        Authorization::Revoked
    );
    // B has not refreshed yet -> still authorizes until its own deadline.
    assert_eq!(b.authorize(&token, 120).await, Authorization::Allowed);
    // B crosses its deadline -> converges to revoked.
    assert_eq!(
        b.authorize(&token, 100 + B + 1).await,
        Authorization::Revoked
    );
}

/// A stale negative during a partition cannot be refreshed, so it fails closed.
#[tokio::test]
async fn stale_negative_fails_closed_during_partition() {
    let authority = ReferenceAuthority::default();
    let v = verifier(authority.clone());
    let token = claims("tok", "t1");
    assert_eq!(v.authorize(&token, 100).await, Authorization::Allowed);
    authority.set_outage(true);
    assert!(matches!(
        v.authorize(&token, 100 + B + 1).await,
        Authorization::Unavailable(_)
    ));
}

/// A stale positive during an authority outage never becomes `Allowed`.
#[tokio::test]
async fn stale_positive_never_becomes_allow_during_outage() {
    let authority = ReferenceAuthority::default();
    authority.revoke("tok");
    let v = verifier(authority.clone());
    let token = claims("tok", "t1");
    assert_eq!(v.authorize(&token, 100).await, Authorization::Revoked);
    authority.set_outage(true);
    let decision = v.authorize(&token, 100 + B + 1).await;
    assert_ne!(decision, Authorization::Allowed);
    assert!(matches!(
        decision,
        Authorization::Unavailable(_) | Authorization::Revoked
    ));
}

/// A backward clock step is rejected and does not replace cached state; the
/// regressed call never reaches the authority (out-of-order responses ignored).
#[tokio::test]
async fn wall_clock_regression_is_rejected_without_replacing_cached_state() {
    let authority = ReferenceAuthority::default();
    let v = verifier(authority.clone());
    let token = claims("tok", "t1");

    assert_eq!(v.authorize(&token, 200).await, Authorization::Allowed);
    assert!(matches!(
        v.authorize(&token, 150).await,
        Authorization::Unavailable(_)
    ));
    // Prior state intact: authorizing again at/after the high-water mark works,
    // and the regressed attempt never re-hit the authority.
    assert_eq!(v.authorize(&token, 200).await, Authorization::Allowed);
    assert_eq!(authority.calls(), 1);
}

/// A restarted verifier is cold and fails closed until it can refresh.
#[tokio::test]
async fn restarted_verifier_returns_to_cold_fail_closed() {
    let authority = ReferenceAuthority::default();
    let token = claims("tok", "t1");

    let v = verifier(authority.clone());
    assert_eq!(v.authorize(&token, 100).await, Authorization::Allowed);
    drop(v); // restart: state was in-memory only

    authority.set_outage(true);
    let restarted = verifier(authority.clone());
    assert!(matches!(
        restarted.authorize(&token, 100).await,
        Authorization::Unavailable(_)
    ));
}

/// A lift converges to `Allowed` only after the instance refreshes past its
/// freshness deadline.
#[tokio::test]
async fn lift_converges_only_after_refresh() {
    let authority = ReferenceAuthority::default();
    authority.revoke("tok");
    let v = verifier(authority.clone());
    let token = claims("tok", "t1");

    assert_eq!(v.authorize(&token, 100).await, Authorization::Revoked);
    authority.lift("tok");
    // Still revoked from cache until the deadline.
    assert_eq!(v.authorize(&token, 110).await, Authorization::Revoked);
    // Refreshes into the lift.
    assert_eq!(
        v.authorize(&token, 100 + B + 1).await,
        Authorization::Allowed
    );
}

/// Revoking one token never affects a different token's decision.
#[tokio::test]
async fn token_isolation() {
    let authority = ReferenceAuthority::default();
    authority.revoke("tok-a");
    let v = verifier(authority.clone());

    assert_eq!(
        v.authorize(&claims("tok-a", "t1"), 100).await,
        Authorization::Revoked
    );
    assert_eq!(
        v.authorize(&claims("tok-b", "t1"), 100).await,
        Authorization::Allowed
    );
    // A second tenant's distinct token is likewise unaffected.
    assert_eq!(
        v.authorize(&claims("tok-c", "t2"), 100).await,
        Authorization::Allowed
    );
}
