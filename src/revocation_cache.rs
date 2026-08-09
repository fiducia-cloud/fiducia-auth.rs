//! Bounded, fail-closed verifier-local cache for authoritative revocation decisions.
//!
//! This module deliberately accepts caller-supplied Unix timestamps instead of
//! reading the operating-system clock. Every public operation first checks a
//! cache-instance high-water mark. A timestamp below that mark is rejected and
//! cannot authorize, start a refresh, or replace cached state.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;

/// Opaque authority key, normally produced by `RevocationSelector::storage_key`.
///
/// The value is intentionally omitted from errors and diagnostics so callers can
/// count failures without exposing tenant, subject, or token identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RevocationCacheKey(String);

impl RevocationCacheKey {
    /// Creates a bounded opaque key suitable for local map indexing.
    pub fn new(value: impl Into<String>) -> Result<Self, RevocationCacheError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 512
            || value.chars().any(|character| character.is_control())
        {
            return Err(RevocationCacheError::InvalidKey);
        }
        Ok(Self(value))
    }

    /// Returns the opaque authority key without interpreting its identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Authoritative state for one opaque revocation target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityState {
    /// The target is not revoked at the authority generation supplied below.
    NotRevoked,
    /// The target is revoked until the exclusive Unix expiry, or indefinitely.
    Revoked { expires_at: Option<u64> },
}

/// One authoritative response that may be installed in a verifier cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityDecision {
    pub generation: u64,
    pub state: AuthorityState,
}

/// Opaque refresh identity returned by [`RevocationCache::begin_refresh`].
///
/// Responses must be applied with the matching identity. A response from an
/// older refresh is rejected after a newer refresh for the same key has started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshPermit {
    key: RevocationCacheKey,
    sequence: u64,
}

/// Fail-closed result of a local lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheDecision {
    Allow,
    Deny(DenyReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    Cold,
    Stale,
    Revoked,
    RevocationExpiredNeedsRefresh,
}

/// Metrics-safe cache error. No variant contains a cache key or identity value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationCacheError {
    InvalidFreshness,
    InvalidKey,
    ClockRegression { observed: u64, high_water: u64 },
    UnknownRefresh,
    SupersededRefresh,
    GenerationRegression { observed: u64, cached: u64 },
}

impl RevocationCacheError {
    /// Stable bounded label suitable for metrics dimensions.
    pub const fn metric_kind(self) -> &'static str {
        match self {
            Self::InvalidFreshness => "invalid_freshness",
            Self::InvalidKey => "invalid_key",
            Self::ClockRegression { .. } => "clock_regression",
            Self::UnknownRefresh => "unknown_refresh",
            Self::SupersededRefresh => "superseded_refresh",
            Self::GenerationRegression { .. } => "generation_regression",
        }
    }
}

impl fmt::Display for RevocationCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFreshness => formatter.write_str("invalid revocation-cache freshness"),
            Self::InvalidKey => formatter.write_str("invalid revocation-cache key"),
            Self::ClockRegression {
                observed,
                high_water,
            } => write!(
                formatter,
                "revocation-cache clock regressed: observed={observed}, high_water={high_water}"
            ),
            Self::UnknownRefresh => formatter.write_str("unknown revocation-cache refresh"),
            Self::SupersededRefresh => formatter.write_str("superseded revocation-cache refresh"),
            Self::GenerationRegression { observed, cached } => write!(
                formatter,
                "revocation generation regressed: observed={observed}, cached={cached}"
            ),
        }
    }
}

impl Error for RevocationCacheError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CacheEntry {
    decision: AuthorityDecision,
    fresh_until: u64,
}

/// Verifier-local bounded-freshness cache.
///
/// A newly constructed cache is cold and denies until an authoritative response
/// is applied. Restarting a verifier therefore creates an explicit cold,
/// fail-closed boundary rather than restoring an unverified local allow.
#[derive(Debug)]
pub struct RevocationCache {
    freshness_secs: u64,
    high_water: Option<u64>,
    next_refresh_sequence: u64,
    latest_refresh: HashMap<RevocationCacheKey, u64>,
    entries: HashMap<RevocationCacheKey, CacheEntry>,
}

impl RevocationCache {
    pub fn new(freshness_secs: u64) -> Result<Self, RevocationCacheError> {
        if freshness_secs == 0 {
            return Err(RevocationCacheError::InvalidFreshness);
        }
        Ok(Self {
            freshness_secs,
            high_water: None,
            next_refresh_sequence: 1,
            latest_refresh: HashMap::new(),
            entries: HashMap::new(),
        })
    }

    /// Returns the greatest accepted Unix timestamp for this cache instance.
    pub fn high_water(&self) -> Option<u64> {
        self.high_water
    }

    /// Performs a local decision. Every error must be handled as deny by callers.
    pub fn lookup(
        &mut self,
        key: &RevocationCacheKey,
        now: u64,
    ) -> Result<CacheDecision, RevocationCacheError> {
        self.observe_time(now)?;
        let Some(entry) = self.entries.get(key) else {
            return Ok(CacheDecision::Deny(DenyReason::Cold));
        };

        match entry.decision.state {
            AuthorityState::Revoked {
                expires_at: Some(expires_at),
            } if now >= expires_at => Ok(CacheDecision::Deny(
                DenyReason::RevocationExpiredNeedsRefresh,
            )),
            AuthorityState::Revoked { .. } => Ok(CacheDecision::Deny(DenyReason::Revoked)),
            AuthorityState::NotRevoked if now < entry.fresh_until => Ok(CacheDecision::Allow),
            AuthorityState::NotRevoked => Ok(CacheDecision::Deny(DenyReason::Stale)),
        }
    }

    /// Starts an authority refresh after accepting the caller's timestamp.
    pub fn begin_refresh(
        &mut self,
        key: RevocationCacheKey,
        now: u64,
    ) -> Result<RefreshPermit, RevocationCacheError> {
        self.observe_time(now)?;
        let sequence = self.next_refresh_sequence;
        self.next_refresh_sequence = self.next_refresh_sequence.saturating_add(1);
        self.latest_refresh.insert(key.clone(), sequence);
        Ok(RefreshPermit { key, sequence })
    }

    /// Applies an authoritative response without replacing state on rejection.
    pub fn apply_authoritative(
        &mut self,
        permit: RefreshPermit,
        decision: AuthorityDecision,
        now: u64,
    ) -> Result<(), RevocationCacheError> {
        self.observe_time(now)?;

        let Some(latest_sequence) = self.latest_refresh.get(&permit.key).copied() else {
            return Err(RevocationCacheError::UnknownRefresh);
        };
        if permit.sequence != latest_sequence {
            return Err(RevocationCacheError::SupersededRefresh);
        }
        if let Some(current) = self.entries.get(&permit.key) {
            if decision.generation < current.decision.generation {
                return Err(RevocationCacheError::GenerationRegression {
                    observed: decision.generation,
                    cached: current.decision.generation,
                });
            }
        }

        let fresh_until = now.saturating_add(self.freshness_secs);
        self.entries.insert(
            permit.key.clone(),
            CacheEntry {
                decision,
                fresh_until,
            },
        );
        self.latest_refresh.remove(&permit.key);
        Ok(())
    }

    /// Clears one key. This always leaves the target cold and denied.
    pub fn invalidate(
        &mut self,
        key: &RevocationCacheKey,
        now: u64,
    ) -> Result<(), RevocationCacheError> {
        self.observe_time(now)?;
        self.entries.remove(key);
        self.latest_refresh.remove(key);
        Ok(())
    }

    fn observe_time(&mut self, now: u64) -> Result<(), RevocationCacheError> {
        if let Some(high_water) = self.high_water {
            if now < high_water {
                return Err(RevocationCacheError::ClockRegression {
                    observed: now,
                    high_water,
                });
            }
        }
        self.high_water = Some(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(value: &str) -> RevocationCacheKey {
        RevocationCacheKey::new(value).expect("test key")
    }

    fn refresh(
        cache: &mut RevocationCache,
        key: RevocationCacheKey,
        generation: u64,
        state: AuthorityState,
        now: u64,
    ) {
        let permit = cache.begin_refresh(key, now).expect("begin refresh");
        cache
            .apply_authoritative(permit, AuthorityDecision { generation, state }, now)
            .expect("apply response");
    }

    #[test]
    fn cold_start_and_restart_fail_closed() {
        let target = key("tenant-a/token-1");
        let mut first = RevocationCache::new(10).expect("cache");
        assert_eq!(
            first.lookup(&target, 100),
            Ok(CacheDecision::Deny(DenyReason::Cold))
        );
        refresh(
            &mut first,
            target.clone(),
            1,
            AuthorityState::NotRevoked,
            100,
        );
        assert_eq!(first.lookup(&target, 101), Ok(CacheDecision::Allow));

        let mut restarted = RevocationCache::new(10).expect("cache");
        assert_eq!(
            restarted.lookup(&target, 101),
            Ok(CacheDecision::Deny(DenyReason::Cold))
        );
    }

    #[test]
    fn negative_authorizes_only_before_exclusive_freshness_deadline() {
        let target = key("tenant-a/token-1");
        let mut cache = RevocationCache::new(10).expect("cache");
        refresh(
            &mut cache,
            target.clone(),
            1,
            AuthorityState::NotRevoked,
            100,
        );
        assert_eq!(cache.lookup(&target, 109), Ok(CacheDecision::Allow));
        assert_eq!(
            cache.lookup(&target, 110),
            Ok(CacheDecision::Deny(DenyReason::Stale))
        );
    }

    #[test]
    fn stale_positive_remains_denied_during_authority_outage() {
        let target = key("tenant-a/token-1");
        let mut cache = RevocationCache::new(5).expect("cache");
        refresh(
            &mut cache,
            target.clone(),
            7,
            AuthorityState::Revoked { expires_at: None },
            100,
        );
        assert_eq!(
            cache.lookup(&target, 10_000),
            Ok(CacheDecision::Deny(DenyReason::Revoked))
        );
    }

    #[test]
    fn expired_revocation_never_turns_into_local_allow() {
        let target = key("tenant-a/token-1");
        let mut cache = RevocationCache::new(60).expect("cache");
        refresh(
            &mut cache,
            target.clone(),
            7,
            AuthorityState::Revoked {
                expires_at: Some(105),
            },
            100,
        );
        assert_eq!(
            cache.lookup(&target, 105),
            Ok(CacheDecision::Deny(
                DenyReason::RevocationExpiredNeedsRefresh
            ))
        );
    }

    #[test]
    fn regression_after_fresh_negative_fails_closed_and_recovers_at_high_water() {
        let target = key("tenant-a/token-1");
        let mut cache = RevocationCache::new(10).expect("cache");
        refresh(
            &mut cache,
            target.clone(),
            1,
            AuthorityState::NotRevoked,
            100,
        );
        assert_eq!(cache.lookup(&target, 105), Ok(CacheDecision::Allow));
        assert_eq!(
            cache.lookup(&target, 104),
            Err(RevocationCacheError::ClockRegression {
                observed: 104,
                high_water: 105,
            })
        );
        assert_eq!(cache.lookup(&target, 105), Ok(CacheDecision::Allow));
    }

    #[test]
    fn regression_during_refresh_start_does_not_create_a_permit() {
        let target = key("tenant-a/token-1");
        let mut cache = RevocationCache::new(10).expect("cache");
        assert_eq!(
            cache.lookup(&target, 100),
            Ok(CacheDecision::Deny(DenyReason::Cold))
        );
        assert_eq!(
            cache.begin_refresh(target.clone(), 99),
            Err(RevocationCacheError::ClockRegression {
                observed: 99,
                high_water: 100,
            })
        );
        let permit = cache.begin_refresh(target, 100).expect("recovery refresh");
        assert_eq!(permit.sequence, 1);
    }

    #[test]
    fn regression_during_response_application_preserves_cached_state() {
        let target = key("tenant-a/token-1");
        let mut cache = RevocationCache::new(10).expect("cache");
        refresh(
            &mut cache,
            target.clone(),
            5,
            AuthorityState::Revoked { expires_at: None },
            100,
        );
        let permit = cache.begin_refresh(target.clone(), 110).expect("refresh");
        assert_eq!(
            cache.apply_authoritative(
                permit.clone(),
                AuthorityDecision {
                    generation: 6,
                    state: AuthorityState::NotRevoked,
                },
                109,
            ),
            Err(RevocationCacheError::ClockRegression {
                observed: 109,
                high_water: 110,
            })
        );
        assert_eq!(
            cache.lookup(&target, 110),
            Ok(CacheDecision::Deny(DenyReason::Revoked))
        );
        cache
            .apply_authoritative(
                permit,
                AuthorityDecision {
                    generation: 6,
                    state: AuthorityState::NotRevoked,
                },
                110,
            )
            .expect("recover at high-water");
        assert_eq!(cache.lookup(&target, 110), Ok(CacheDecision::Allow));
    }

    #[test]
    fn delayed_out_of_order_response_is_ignored() {
        let target = key("tenant-a/token-1");
        let mut cache = RevocationCache::new(10).expect("cache");
        let older = cache.begin_refresh(target.clone(), 100).expect("older");
        let newer = cache.begin_refresh(target.clone(), 101).expect("newer");
        assert_eq!(
            cache.apply_authoritative(
                older,
                AuthorityDecision {
                    generation: 1,
                    state: AuthorityState::NotRevoked,
                },
                101,
            ),
            Err(RevocationCacheError::SupersededRefresh)
        );
        assert_eq!(
            cache.lookup(&target, 101),
            Ok(CacheDecision::Deny(DenyReason::Cold))
        );
        cache
            .apply_authoritative(
                newer,
                AuthorityDecision {
                    generation: 2,
                    state: AuthorityState::Revoked { expires_at: None },
                },
                101,
            )
            .expect("newer response");
        assert_eq!(
            cache.lookup(&target, 101),
            Ok(CacheDecision::Deny(DenyReason::Revoked))
        );
    }

    #[test]
    fn lower_authority_generation_cannot_replace_state() {
        let target = key("tenant-a/token-1");
        let mut cache = RevocationCache::new(10).expect("cache");
        refresh(
            &mut cache,
            target.clone(),
            8,
            AuthorityState::Revoked { expires_at: None },
            100,
        );
        let permit = cache.begin_refresh(target.clone(), 101).expect("refresh");
        assert_eq!(
            cache.apply_authoritative(
                permit,
                AuthorityDecision {
                    generation: 7,
                    state: AuthorityState::NotRevoked,
                },
                101,
            ),
            Err(RevocationCacheError::GenerationRegression {
                observed: 7,
                cached: 8,
            })
        );
        assert_eq!(
            cache.lookup(&target, 101),
            Ok(CacheDecision::Deny(DenyReason::Revoked))
        );
    }

    #[test]
    fn two_verifiers_converge_only_after_each_refreshes() {
        let target = key("tenant-a/token-1");
        let mut first = RevocationCache::new(10).expect("first");
        let mut second = RevocationCache::new(10).expect("second");
        refresh(
            &mut first,
            target.clone(),
            1,
            AuthorityState::NotRevoked,
            100,
        );
        refresh(
            &mut second,
            target.clone(),
            1,
            AuthorityState::NotRevoked,
            100,
        );

        refresh(
            &mut first,
            target.clone(),
            2,
            AuthorityState::Revoked { expires_at: None },
            101,
        );
        assert_eq!(
            first.lookup(&target, 101),
            Ok(CacheDecision::Deny(DenyReason::Revoked))
        );
        assert_eq!(second.lookup(&target, 101), Ok(CacheDecision::Allow));

        refresh(
            &mut second,
            target.clone(),
            2,
            AuthorityState::Revoked { expires_at: None },
            102,
        );
        refresh(
            &mut first,
            target.clone(),
            3,
            AuthorityState::NotRevoked,
            103,
        );
        assert_eq!(first.lookup(&target, 103), Ok(CacheDecision::Allow));
        assert_eq!(
            second.lookup(&target, 103),
            Ok(CacheDecision::Deny(DenyReason::Revoked))
        );
        refresh(
            &mut second,
            target.clone(),
            3,
            AuthorityState::NotRevoked,
            104,
        );
        assert_eq!(second.lookup(&target, 104), Ok(CacheDecision::Allow));
    }

    #[test]
    fn tenant_and_token_keys_are_isolated() {
        let tenant_a_token_1 = key("tenant-a/token-1");
        let tenant_a_token_2 = key("tenant-a/token-2");
        let tenant_b_token_1 = key("tenant-b/token-1");
        let mut cache = RevocationCache::new(10).expect("cache");
        refresh(
            &mut cache,
            tenant_a_token_1.clone(),
            1,
            AuthorityState::Revoked { expires_at: None },
            100,
        );
        refresh(
            &mut cache,
            tenant_a_token_2.clone(),
            1,
            AuthorityState::NotRevoked,
            100,
        );
        refresh(
            &mut cache,
            tenant_b_token_1.clone(),
            1,
            AuthorityState::NotRevoked,
            100,
        );
        assert_eq!(
            cache.lookup(&tenant_a_token_1, 101),
            Ok(CacheDecision::Deny(DenyReason::Revoked))
        );
        assert_eq!(
            cache.lookup(&tenant_a_token_2, 101),
            Ok(CacheDecision::Allow)
        );
        assert_eq!(
            cache.lookup(&tenant_b_token_1, 101),
            Ok(CacheDecision::Allow)
        );
    }

    #[test]
    fn metric_error_is_bounded_and_identity_free() {
        let error = RevocationCacheError::ClockRegression {
            observed: 10,
            high_water: 11,
        };
        assert_eq!(error.metric_kind(), "clock_regression");
        assert!(!error.to_string().contains("tenant"));
        assert!(!error.to_string().contains("token"));
    }
}
