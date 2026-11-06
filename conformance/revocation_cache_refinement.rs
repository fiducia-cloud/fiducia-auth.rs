//! Executable bounded refinement of the *production* revocation-cache module.
//! This independently computes the expected latest generation and decision for
//! two opaque tenant keys, replaying every 5-step schedule of seven operations.
//! Model scope: one verifier's in-memory cache, logical timestamps, no network/KV.
//! Unlike a copied cache model, this compiles the actual src/revocation_cache.rs.
#[path = "../src/revocation_cache.rs"]
#[allow(dead_code)]
mod production;

use production::{
    AuthorityDecision, AuthorityState, CacheDecision, DenyReason, RevocationCache,
    RevocationCacheError, RevocationCacheKey,
};

const OPERATIONS: usize = 7;
const STEPS: usize = 5;

#[derive(Clone, Copy)]
struct Expected {
    generation: u64,
    revoked: bool,
}

fn key(tenant: &str) -> RevocationCacheKey {
    RevocationCacheKey::new(format!("auth/revocations/v1/{tenant}/token"))
        .expect("bounded opaque key")
}
fn install(
    cache: &mut RevocationCache,
    target: &RevocationCacheKey,
    prior: Option<Expected>,
    revoked: bool,
    now: u64,
) -> Expected {
    let next = Expected {
        generation: prior.map_or(1, |old| old.generation + 1),
        revoked,
    };
    let permit = cache.begin_refresh(target.clone(), now).expect("begin");
    cache.apply_authoritative(
        permit,
        AuthorityDecision {
            generation: next.generation,
            state: if revoked {
                AuthorityState::Revoked { expires_at: None }
            } else {
                AuthorityState::NotRevoked
            },
        },
        now,
    )
    .expect("valid authoritative response");
    next
}
fn assert_decisions(cache: &mut RevocationCache, keys: &[RevocationCacheKey; 2], oracle: &[Option<Expected>; 2], now: u64) {
    for i in 0..2 {
        let actual = cache.lookup(&keys[i], now).expect("monotonic timestamp");
        let expected = match oracle[i] {
            None => CacheDecision::Deny(DenyReason::Cold),
            Some(Expected { revoked: true, .. }) => CacheDecision::Deny(DenyReason::Revoked),
            Some(Expected { revoked: false, .. }) => CacheDecision::Allow,
        };
        assert_eq!(actual, expected, "tenant {i} at t={now}");
    }
}
fn replay(mut schedule: usize) {
    let keys = [key("tenant-a"), key("tenant-b")];
    let mut cache = RevocationCache::new(100).expect("freshness");
    let mut oracle = [None; 2];
    for step in 0..STEPS {
        let now = 100 + step as u64;
        let action = schedule % OPERATIONS;
        schedule /= OPERATIONS;
        match action {
            0..=3 => {
                let i = if action < 2 { 0 } else { 1 };
                oracle[i] = Some(install(&mut cache, &keys[i], oracle[i], action % 2 == 1, now));
            }
            4 => {
                // Out-of-order replay from an older authoritative generation must
                // fail and must not change the cached decision.
                if let Some(old) = oracle[0] {
                    let permit = cache.begin_refresh(keys[0].clone(), now).expect("begin stale");
                    assert_eq!(
                        cache.apply_authoritative(
                            permit,
                            AuthorityDecision {
                                generation: old.generation - 1,
                                state: AuthorityState::NotRevoked,
                            },
                            now,
                        ),
                        Err(RevocationCacheError::GenerationRegression {
                            observed: old.generation - 1,
                            cached: old.generation,
                        }),
                    );
                }
            }
            5 => {
                // A response to a superseded refresh may never overwrite the
                // newer response, including when the old response was "allow".
                let superseded = cache.begin_refresh(keys[0].clone(), now).expect("first");
                let latest = cache.begin_refresh(keys[0].clone(), now).expect("second");
                assert_eq!(
                    cache.apply_authoritative(
                        superseded,
                        AuthorityDecision {
                            generation: oracle[0].map_or(1, |old| old.generation + 1),
                            state: AuthorityState::NotRevoked,
                        },
                        now,
                    ),
                    Err(RevocationCacheError::SupersededRefresh),
                );
                let revoked = !oracle[0].is_some_and(|old| old.revoked);
                let next = Expected {
                    generation: oracle[0].map_or(1, |old| old.generation + 1),
                    revoked,
                };
                cache.apply_authoritative(
                    latest,
                    AuthorityDecision {
                        generation: next.generation,
                        state: if revoked {
                            AuthorityState::Revoked { expires_at: None }
                        } else {
                            AuthorityState::NotRevoked
                        },
                    },
                    now,
                ).expect("latest authoritative response");
                oracle[0] = Some(next);
            }
            6 => {
                cache.invalidate(&keys[0], now).expect("invalidate");
                oracle[0] = None;
            }
            _ => unreachable!(),
        }
        assert_decisions(&mut cache, &keys, &oracle, now);
    }
}

#[test]
fn exhaustive_production_cache_refinement() {
    let cases = OPERATIONS.pow(STEPS as u32);
    for schedule in 0..cases {
        replay(schedule);
    }
    println!("SOURCE_COMPILED production cache refinement: {cases} complete schedules, {STEPS} steps each");
}
#[test]
fn clock_regression_fails_closed_without_changing_either_tenant() {
    let keys = [key("tenant-a"), key("tenant-b")];
    let mut cache = RevocationCache::new(100).unwrap();
    let mut oracle = [None; 2];
    oracle[0] = Some(install(&mut cache, &keys[0], None, false, 100));
    oracle[1] = Some(install(&mut cache, &keys[1], None, true, 101));
    assert!(matches!(
        cache.lookup(&keys[0], 100),
        Err(RevocationCacheError::ClockRegression { observed: 100, high_water: 101 }),
    ));
    assert_decisions(&mut cache, &keys, &oracle, 102);
}
