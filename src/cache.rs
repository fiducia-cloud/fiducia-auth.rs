//! Verifier-local revocation cache with a monotonic wall-clock guarantee.
//!
//! Fiducia internal-JWT verifiers consult the authoritative revocation ledger
//! (`crate::revocation`) but cannot afford a synchronous authority round-trip on
//! every request. This module provides a small, bounded, in-process cache of
//! authoritative revocation decisions with an explicit real-time freshness
//! budget.
//!
//! # Wall-clock assumption
//! The cache trusts the host Unix clock only to move *forward*. Freshness and
//! expiry are measured against the `now` (seconds since the Unix epoch) passed
//! by the caller. If the local clock moves backward after the cache has already
//! observed a later timestamp, a previously fresh negative (`Allow`) decision
//! could appear fresh again and extend authorization past its intended freshness
//! budget.
//!
//! To prevent that, every operation advances a per-instance **high-water mark**:
//! the greatest `now` the cache has ever observed. Any operation whose `now` is
//! below the high-water mark is rejected with [`ClockRegression`], never yields
//! a decision, and leaves existing cached state unchanged. Normal operation
//! resumes only once `now` reaches or passes the prior high-water mark.
//!
//! # Restart boundary
//! The high-water mark and all entries live in memory. A restarted cache is
//! therefore **cold**: it holds no entries and its high-water mark is zero, so
//! every lookup is a miss and the verifier fails closed (must consult the
//! authority) until an authoritative refresh repopulates it. A backward clock
//! step across a restart cannot resurrect a stale `Allow`, because no entry is
//! retained to serve.
//!
//! # Operational alert requirement
//! [`ClockRegression`] is a metrics-friendly, identifier-free signal. Operators
//! MUST alert on any occurrence: it means a verifier host clock moved backward,
//! which is a fail-closed condition rather than a normal event. The error
//! carries only the regression magnitude in seconds — never token, tenant,
//! subject, or token-id values.

use std::collections::HashMap;

use thiserror::Error;

/// Default real-time freshness budget for a cached decision, in seconds.
pub const DEFAULT_FRESHNESS_BUDGET_SECS: u64 = 30;
/// Default maximum number of distinct identities retained.
pub const DEFAULT_CAPACITY: usize = 65_536;

/// An authoritative revocation decision cached for one token identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The authority reports the identity is not revoked.
    Allow,
    /// The authority reports the identity is revoked. Callers fail closed.
    Deny,
}

/// Outcome of a cache lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    /// A decision observed within the freshness budget; safe to honor.
    Fresh(Decision),
    /// A known identity whose cached decision is older than the budget. The
    /// caller must re-consult the authority and fail closed in the meantime.
    Stale,
    /// No cached decision. The caller must consult the authority.
    Miss,
}

/// The local Unix clock moved backward, below the greatest value the cache has
/// already observed. Identifier-free by construction, so it is safe to log and
/// export as a metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("verifier cache observed a local clock regression of {regressed_by_secs}s below the high-water mark")]
pub struct ClockRegression {
    /// How far below the high-water mark the offered timestamp was, in seconds.
    pub regressed_by_secs: u64,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    decision: Decision,
    observed_at: u64,
}

/// A bounded, verifier-local cache of authoritative revocation decisions that
/// fails closed on any local wall-clock regression.
#[derive(Debug)]
pub struct RevocationCache {
    entries: HashMap<String, Entry>,
    high_water: u64,
    freshness_budget_secs: u64,
    capacity: usize,
}

impl RevocationCache {
    /// Create a cache with the given freshness budget and capacity. Both are
    /// clamped to at least `1` so a misconfiguration cannot silently disable
    /// caching bounds or make every entry instantly stale in a surprising way.
    pub fn new(freshness_budget_secs: u64, capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            high_water: 0,
            freshness_budget_secs: freshness_budget_secs.max(1),
            capacity: capacity.max(1),
        }
    }

    /// Create a cache with [`DEFAULT_FRESHNESS_BUDGET_SECS`] and
    /// [`DEFAULT_CAPACITY`].
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_FRESHNESS_BUDGET_SECS, DEFAULT_CAPACITY)
    }

    /// The greatest Unix timestamp this instance has observed.
    pub fn high_water(&self) -> u64 {
        self.high_water
    }

    /// Number of retained identities.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache currently retains no identities.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Advance the monotonic high-water mark, rejecting any regressed timestamp.
    /// This is the single choke point every mutating and reading operation
    /// passes through, so no path can observe `Allow` on a regressed clock.
    fn advance(&mut self, now: u64) -> Result<(), ClockRegression> {
        if now < self.high_water {
            return Err(ClockRegression {
                regressed_by_secs: self.high_water - now,
            });
        }
        self.high_water = now;
        Ok(())
    }

    /// Look up a cached decision. Advances the clock first, so a regressed `now`
    /// is rejected before any decision is returned.
    pub fn lookup(&mut self, key: &str, now: u64) -> Result<Lookup, ClockRegression> {
        self.advance(now)?;
        Ok(match self.entries.get(key) {
            Some(entry) if now.saturating_sub(entry.observed_at) <= self.freshness_budget_secs => {
                Lookup::Fresh(entry.decision)
            }
            Some(_) => Lookup::Stale,
            None => Lookup::Miss,
        })
    }

    /// Record that an authoritative refresh is starting. Advancing the clock
    /// here catches a regression at the earliest point, before any authority
    /// response is applied.
    pub fn record_refresh_start(&mut self, now: u64) -> Result<(), ClockRegression> {
        self.advance(now)
    }

    /// Apply an authoritative decision observed at `now`. On a regressed clock
    /// the decision is rejected and every existing entry is preserved unchanged.
    pub fn apply_authoritative(
        &mut self,
        key: &str,
        decision: Decision,
        now: u64,
    ) -> Result<(), ClockRegression> {
        self.advance(now)?;
        let entry = Entry {
            decision,
            observed_at: now,
        };
        if !self.entries.contains_key(key) && self.entries.len() >= self.capacity {
            self.evict_oldest();
        }
        self.entries.insert(key.to_string(), entry);
        Ok(())
    }

    /// Evict the entry with the smallest `observed_at`. Only called when a new
    /// identity would exceed capacity; keeping the cache bounded is itself a
    /// fail-closed property (an unbounded cache is a memory-exhaustion path).
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.observed_at)
            .map(|(key, _)| key.clone())
        {
            self.entries.remove(&oldest_key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "auth/revocations/v1/abc";
    const OTHER: &str = "auth/revocations/v1/def";

    #[test]
    fn miss_on_unknown_identity() {
        let mut cache = RevocationCache::with_defaults();
        assert_eq!(cache.lookup(KEY, 100).unwrap(), Lookup::Miss);
    }

    #[test]
    fn fresh_within_budget_then_stale_past_it() {
        let mut cache = RevocationCache::new(30, 16);
        cache
            .apply_authoritative(KEY, Decision::Allow, 100)
            .unwrap();
        assert_eq!(
            cache.lookup(KEY, 100).unwrap(),
            Lookup::Fresh(Decision::Allow)
        );
        // exactly at the budget boundary is still fresh
        assert_eq!(
            cache.lookup(KEY, 130).unwrap(),
            Lookup::Fresh(Decision::Allow)
        );
        // one second past the budget is stale
        assert_eq!(cache.lookup(KEY, 131).unwrap(), Lookup::Stale);
    }

    #[test]
    fn regression_after_a_fresh_negative_is_rejected_and_never_allows() {
        let mut cache = RevocationCache::new(30, 16);
        // A fresh negative (Allow == "not revoked") observed at t=100.
        cache
            .apply_authoritative(KEY, Decision::Allow, 100)
            .unwrap();
        // Clock regresses to t=90: lookup must fail closed, not return Allow.
        let err = cache.lookup(KEY, 90).unwrap_err();
        assert_eq!(
            err,
            ClockRegression {
                regressed_by_secs: 10
            }
        );
        // State is preserved: once the clock recovers, the entry is intact.
        assert_eq!(
            cache.lookup(KEY, 100).unwrap(),
            Lookup::Fresh(Decision::Allow)
        );
    }

    #[test]
    fn regression_during_refresh_start_is_rejected() {
        let mut cache = RevocationCache::with_defaults();
        cache.record_refresh_start(200).unwrap();
        let err = cache.record_refresh_start(150).unwrap_err();
        assert_eq!(
            err,
            ClockRegression {
                regressed_by_secs: 50
            }
        );
        assert_eq!(cache.high_water(), 200);
    }

    #[test]
    fn regression_during_response_application_preserves_state() {
        let mut cache = RevocationCache::new(30, 16);
        cache.apply_authoritative(KEY, Decision::Deny, 100).unwrap();
        // A regressed authoritative response is rejected...
        let err = cache
            .apply_authoritative(KEY, Decision::Allow, 80)
            .unwrap_err();
        assert_eq!(
            err,
            ClockRegression {
                regressed_by_secs: 20
            }
        );
        // ...and the prior Deny is unchanged.
        assert_eq!(
            cache.lookup(KEY, 100).unwrap(),
            Lookup::Fresh(Decision::Deny)
        );
    }

    #[test]
    fn recovery_at_or_after_prior_high_water_mark() {
        let mut cache = RevocationCache::new(30, 16);
        cache.apply_authoritative(KEY, Decision::Deny, 100).unwrap();
        // Regression is rejected but leaves the high-water mark at 100.
        assert!(cache.lookup(KEY, 70).is_err());
        assert_eq!(cache.high_water(), 100);
        // Resume exactly at the high-water mark.
        assert_eq!(
            cache.lookup(KEY, 100).unwrap(),
            Lookup::Fresh(Decision::Deny)
        );
        // And past it.
        assert!(cache.apply_authoritative(KEY, Decision::Allow, 110).is_ok());
        assert_eq!(
            cache.lookup(KEY, 110).unwrap(),
            Lookup::Fresh(Decision::Allow)
        );
    }

    #[test]
    fn cached_state_is_unchanged_after_a_rejected_operation() {
        let mut cache = RevocationCache::new(30, 16);
        cache.apply_authoritative(KEY, Decision::Deny, 500).unwrap();
        cache
            .apply_authoritative(OTHER, Decision::Allow, 500)
            .unwrap();
        let before_len = cache.len();
        // Every regressed operation kind is rejected.
        assert!(cache.lookup(KEY, 400).is_err());
        assert!(cache.record_refresh_start(400).is_err());
        assert!(cache
            .apply_authoritative(KEY, Decision::Allow, 400)
            .is_err());
        // Nothing changed: same size, same decisions.
        assert_eq!(cache.len(), before_len);
        assert_eq!(
            cache.lookup(KEY, 500).unwrap(),
            Lookup::Fresh(Decision::Deny)
        );
        assert_eq!(
            cache.lookup(OTHER, 500).unwrap(),
            Lookup::Fresh(Decision::Allow)
        );
    }

    #[test]
    fn restarted_cache_is_cold_and_fails_closed() {
        // A restart is modeled by a fresh instance: no entries, zero high-water.
        let mut restarted = RevocationCache::with_defaults();
        assert!(restarted.is_empty());
        assert_eq!(restarted.high_water(), 0);
        // A previously known identity is now a miss -> caller consults authority.
        assert_eq!(restarted.lookup(KEY, 100).unwrap(), Lookup::Miss);
    }

    #[test]
    fn bounded_capacity_evicts_oldest() {
        let mut cache = RevocationCache::new(1_000, 2);
        cache.apply_authoritative("a", Decision::Deny, 10).unwrap();
        cache.apply_authoritative("b", Decision::Deny, 20).unwrap();
        // Inserting a third distinct identity evicts the oldest ("a").
        cache.apply_authoritative("c", Decision::Deny, 30).unwrap();
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.lookup("a", 30).unwrap(), Lookup::Miss);
        assert_eq!(
            cache.lookup("b", 30).unwrap(),
            Lookup::Fresh(Decision::Deny)
        );
        assert_eq!(
            cache.lookup("c", 30).unwrap(),
            Lookup::Fresh(Decision::Deny)
        );
    }

    #[test]
    fn updating_existing_key_at_capacity_does_not_evict() {
        let mut cache = RevocationCache::new(1_000, 1);
        cache.apply_authoritative(KEY, Decision::Allow, 10).unwrap();
        // Re-applying the same key at capacity 1 updates in place.
        cache.apply_authoritative(KEY, Decision::Deny, 20).unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.lookup(KEY, 20).unwrap(),
            Lookup::Fresh(Decision::Deny)
        );
    }

    #[test]
    fn regression_never_returns_allow_even_when_a_fresh_allow_exists() {
        let mut cache = RevocationCache::new(30, 16);
        cache
            .apply_authoritative(KEY, Decision::Allow, 100)
            .unwrap();
        // The pivotal safety property: a regressed lookup must be an Err, not
        // Ok(Fresh(Allow)), even though a fresh Allow is present.
        match cache.lookup(KEY, 50) {
            Err(ClockRegression { regressed_by_secs }) => assert_eq!(regressed_by_secs, 50),
            other => panic!("expected ClockRegression, got {other:?}"),
        }
    }
}
