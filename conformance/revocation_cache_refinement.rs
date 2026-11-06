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

fn authoritative(
    cache: &mut RevocationCache,
    target: &RevocationCacheKey,
    generation: u64,
    revoked: bool,
    now: u64,
) -> Result<(), RevocationCacheError> {
    let permit = cache.begin_refresh(target.clone(), now).expect("begin refresh");
    cache.apply_authoritative(
        permit,
        AuthorityDecision {
            generation,
            state: if revoked {
                AuthorityState::Revoked { expires_at: None }
            } else {
                AuthorityState::NotRevoked
            },
        },
        now,
    )
}

#[test]
fn same_generation_allow_then_deny_fails_closed() {
    let target = key("tenant-a");
    let mut cache = RevocationCache::new(20).unwrap();
    authoritative(&mut cache, &target, 7, false, 100).unwrap();
    assert_eq!(cache.lookup(&target, 101), Ok(CacheDecision::Allow));
    assert_eq!(
        authoritative(&mut cache, &target, 7, true, 102),
        Err(RevocationCacheError::GenerationConflict { generation: 7 }),
    );
    assert_eq!(
        cache.lookup(&target, 103),
        Ok(CacheDecision::Deny(DenyReason::AuthorityGenerationConflict)),
    );
}

#[test]
fn same_generation_deny_then_allow_never_revives_token() {
    let target = key("tenant-a");
    let mut cache = RevocationCache::new(20).unwrap();
    authoritative(&mut cache, &target, 7, true, 100).unwrap();
    assert_eq!(
        authoritative(&mut cache, &target, 7, false, 101),
        Err(RevocationCacheError::GenerationConflict { generation: 7 }),
    );
    assert_ne!(cache.lookup(&target, 102), Ok(CacheDecision::Allow));
}

#[test]
fn quarantined_generation_requires_strict_authority_advance() {
    let target = key("tenant-a");
    let mut cache = RevocationCache::new(20).unwrap();
    authoritative(&mut cache, &target, 7, false, 100).unwrap();
    authoritative(&mut cache, &target, 7, true, 101).unwrap_err();

    // Neither a repeat of the original response nor a replay of the
    // conflicting response may remove quarantine.
    for (revoked, now) in [(false, 102), (true, 103)] {
        assert_eq!(
            authoritative(&mut cache, &target, 7, revoked, now),
            Err(RevocationCacheError::GenerationConflict { generation: 7 }),
        );
        assert_eq!(
            cache.lookup(&target, now),
            Ok(CacheDecision::Deny(DenyReason::AuthorityGenerationConflict)),
        );
    }
    assert_eq!(
        authoritative(&mut cache, &target, 6, false, 104),
        Err(RevocationCacheError::GenerationRegression {
            observed: 6,
            cached: 7,
        }),
    );
    authoritative(&mut cache, &target, 8, true, 105).unwrap();
    assert_eq!(cache.lookup(&target, 106), Ok(CacheDecision::Deny(DenyReason::Revoked)));
    authoritative(&mut cache, &target, 9, false, 107).unwrap();
    assert_eq!(cache.lookup(&target, 108), Ok(CacheDecision::Allow));
}

#[test]
fn one_tenant_generation_conflict_cannot_poison_another_tenant() {
    let first = key("tenant-a");
    let second = key("tenant-b");
    let mut cache = RevocationCache::new(20).unwrap();
    authoritative(&mut cache, &first, 7, false, 100).unwrap();
    authoritative(&mut cache, &second, 3, false, 100).unwrap();
    authoritative(&mut cache, &first, 7, true, 101).unwrap_err();
    assert_eq!(
        cache.lookup(&first, 102),
        Ok(CacheDecision::Deny(DenyReason::AuthorityGenerationConflict)),
    );
    assert_eq!(cache.lookup(&second, 102), Ok(CacheDecision::Allow));
}

#[test]
fn conflict_metric_label_never_contains_tenant_identity() {
    let error = RevocationCacheError::GenerationConflict { generation: 5 };
    assert_eq!(error.metric_kind(), "generation_conflict");
    assert!(!error.to_string().contains("tenant"));
}

#[test]
fn invalidation_must_not_launder_a_conflicted_generation_into_an_allow() {
    let target = key("tenant-a");
    let mut cache = RevocationCache::new(20).unwrap();
    authoritative(&mut cache, &target, 12, false, 100).unwrap();
    assert_eq!(
        authoritative(&mut cache, &target, 12, true, 101),
        Err(RevocationCacheError::GenerationConflict { generation: 12 }),
    );
    cache.invalidate(&target, 102).unwrap();
    assert_eq!(
        cache.lookup(&target, 102),
        Ok(CacheDecision::Deny(DenyReason::AuthorityGenerationConflict)),
    );
    assert_eq!(
        authoritative(&mut cache, &target, 12, false, 103),
        Err(RevocationCacheError::GenerationConflict { generation: 12 }),
    );
    authoritative(&mut cache, &target, 13, true, 104).unwrap();
    cache.invalidate(&target, 105).unwrap();
    assert_eq!(cache.lookup(&target, 105), Ok(CacheDecision::Deny(DenyReason::Cold)));
}
