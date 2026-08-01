use std::collections::HashMap;

use fiducia_auth::cache::{Decision, Lookup, RevocationCache};

const FRESHNESS_BUDGET_SECS: u64 = 10;
const CACHE_CAPACITY: usize = 32;

#[derive(Debug, Clone, Copy)]
struct AuthorityRecord {
    generation: u64,
    decision: Decision,
}

#[derive(Debug, Clone)]
struct AuthorityReply {
    key: String,
    request_id: u64,
    generation: u64,
    decision: Decision,
}

#[derive(Debug, Default)]
struct ReferenceAuthority {
    records: HashMap<String, AuthorityRecord>,
}

impl ReferenceAuthority {
    fn current(&self, key: &str) -> AuthorityRecord {
        self.records.get(key).copied().unwrap_or(AuthorityRecord {
            generation: 0,
            decision: Decision::Allow,
        })
    }

    fn reply(&self, key: &str, request_id: u64) -> AuthorityReply {
        let current = self.current(key);
        AuthorityReply {
            key: key.to_string(),
            request_id,
            generation: current.generation,
            decision: current.decision,
        }
    }

    fn revoke(&mut self, key: &str) -> u64 {
        self.transition(key, Decision::Deny)
    }

    fn lift(&mut self, key: &str) -> u64 {
        self.transition(key, Decision::Allow)
    }

    fn transition(&mut self, key: &str, decision: Decision) -> u64 {
        let next_generation = self.current(key).generation.saturating_add(1);
        self.records.insert(
            key.to_string(),
            AuthorityRecord {
                generation: next_generation,
                decision,
            },
        );
        next_generation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplyOutcome {
    Applied,
    IgnoredSuperseded,
    IgnoredGenerationRegression,
}

#[derive(Debug)]
struct TestVerifier {
    cache: RevocationCache,
    next_request_id: u64,
    latest_request: HashMap<String, u64>,
    latest_generation: HashMap<String, u64>,
}

impl TestVerifier {
    fn new() -> Self {
        Self {
            cache: RevocationCache::new(FRESHNESS_BUDGET_SECS, CACHE_CAPACITY),
            next_request_id: 1,
            latest_request: HashMap::new(),
            latest_generation: HashMap::new(),
        }
    }

    fn begin_refresh(&mut self, key: &str, now: u64) -> u64 {
        self.cache
            .record_refresh_start(now)
            .expect("deterministic test clock must be monotonic");
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(1);
        self.latest_request.insert(key.to_string(), request_id);
        request_id
    }

    fn apply(&mut self, reply: AuthorityReply, now: u64) -> ApplyOutcome {
        if self.latest_request.get(&reply.key).copied() != Some(reply.request_id) {
            return ApplyOutcome::IgnoredSuperseded;
        }
        if self
            .latest_generation
            .get(&reply.key)
            .is_some_and(|generation| reply.generation < *generation)
        {
            return ApplyOutcome::IgnoredGenerationRegression;
        }

        self.cache
            .apply_authoritative(&reply.key, reply.decision, now)
            .expect("deterministic test clock must be monotonic");
        self.latest_generation.insert(reply.key, reply.generation);
        ApplyOutcome::Applied
    }

    fn refresh_from(&mut self, authority: &ReferenceAuthority, key: &str, now: u64) {
        let request_id = self.begin_refresh(key, now);
        assert_eq!(
            self.apply(authority.reply(key, request_id), now),
            ApplyOutcome::Applied
        );
    }

    fn authorize(&mut self, key: &str, now: u64) -> bool {
        matches!(
            self.cache.lookup(key, now),
            Ok(Lookup::Fresh(Decision::Allow))
        )
    }
}

fn token_key(tenant: &str, token: &str) -> String {
    format!("auth/revocations/v1/{tenant}/{token}")
}

#[test]
fn cold_start_and_restart_fail_closed() {
    let key = token_key("tenant-a", "token-1");
    let authority = ReferenceAuthority::default();
    let mut first = TestVerifier::new();
    let mut second = TestVerifier::new();

    assert!(!first.authorize(&key, 100));
    assert!(!second.authorize(&key, 100));

    first.refresh_from(&authority, &key, 100);
    second.refresh_from(&authority, &key, 100);
    assert!(first.authorize(&key, 101));
    assert!(second.authorize(&key, 101));

    let mut restarted = TestVerifier::new();
    assert!(!restarted.authorize(&key, 101));
    restarted.refresh_from(&authority, &key, 101);
    assert!(restarted.authorize(&key, 101));
}

#[test]
fn negative_decision_never_authorizes_at_or_after_its_deadline() {
    let key = token_key("tenant-a", "token-1");
    let authority = ReferenceAuthority::default();
    let mut verifier = TestVerifier::new();
    verifier.refresh_from(&authority, &key, 100);

    // The public cache contract is inclusive at the integer-second budget
    // boundary, so the first stale instant is observed_at + budget + 1.
    let first_stale_instant = 100 + FRESHNESS_BUDGET_SECS + 1;
    assert!(verifier.authorize(&key, first_stale_instant - 1));
    assert!(!verifier.authorize(&key, first_stale_instant));
    assert!(!verifier.authorize(&key, first_stale_instant + 1_000));
}

#[test]
fn revoke_partition_outage_and_lift_converge_per_verifier() {
    let key = token_key("tenant-a", "token-1");
    let mut authority = ReferenceAuthority::default();
    let mut first = TestVerifier::new();
    let mut second = TestVerifier::new();
    first.refresh_from(&authority, &key, 100);
    second.refresh_from(&authority, &key, 100);

    authority.revoke(&key);
    first.refresh_from(&authority, &key, 102);
    assert!(!first.authorize(&key, 102));
    assert!(second.authorize(&key, 102));

    // The partitioned verifier fails closed as soon as its earlier negative is
    // stale, even though it cannot reach the authority.
    assert!(!second.authorize(&key, 111));
    second.refresh_from(&authority, &key, 112);
    assert!(!second.authorize(&key, 112));

    // A cached positive (revoked) decision remains deny throughout an outage,
    // regardless of age.
    assert!(!first.authorize(&key, 1_000));

    authority.lift(&key);
    first.refresh_from(&authority, &key, 1_001);
    assert!(first.authorize(&key, 1_001));
    assert!(!second.authorize(&key, 1_001));

    second.refresh_from(&authority, &key, 1_002);
    assert!(second.authorize(&key, 1_002));
}

#[test]
fn delayed_and_generation_regressed_responses_are_ignored() {
    let key = token_key("tenant-a", "token-1");
    let mut authority = ReferenceAuthority::default();
    let mut verifier = TestVerifier::new();

    let old_request = verifier.begin_refresh(&key, 100);
    let old_allow = authority.reply(&key, old_request);
    authority.revoke(&key);
    let new_request = verifier.begin_refresh(&key, 101);
    let new_deny = authority.reply(&key, new_request);

    assert_eq!(verifier.apply(new_deny, 101), ApplyOutcome::Applied);
    assert_eq!(
        verifier.apply(old_allow, 101),
        ApplyOutcome::IgnoredSuperseded
    );
    assert!(!verifier.authorize(&key, 101));

    let current_request = verifier.begin_refresh(&key, 102);
    let regressed = AuthorityReply {
        key: key.clone(),
        request_id: current_request,
        generation: 0,
        decision: Decision::Allow,
    };
    assert_eq!(
        verifier.apply(regressed, 102),
        ApplyOutcome::IgnoredGenerationRegression
    );
    assert!(!verifier.authorize(&key, 102));
}

#[test]
fn wall_clock_regression_rejects_without_replacing_cached_state() {
    let key = token_key("tenant-a", "token-1");
    let authority = ReferenceAuthority::default();
    let mut verifier = TestVerifier::new();
    verifier.refresh_from(&authority, &key, 200);
    assert!(verifier.authorize(&key, 205));

    // Every lookup error is a deny to the test verifier.
    assert!(!verifier.authorize(&key, 204));
    assert_eq!(verifier.cache.high_water(), 205);

    // At the prior high-water mark the original cached state is still intact.
    assert!(verifier.authorize(&key, 205));
}

#[test]
fn tenant_and_token_isolation_are_preserved() {
    let a1 = token_key("tenant-a", "token-1");
    let a2 = token_key("tenant-a", "token-2");
    let b1 = token_key("tenant-b", "token-1");
    let mut authority = ReferenceAuthority::default();
    authority.revoke(&a1);

    let mut verifier = TestVerifier::new();
    verifier.refresh_from(&authority, &a1, 100);
    verifier.refresh_from(&authority, &a2, 100);
    verifier.refresh_from(&authority, &b1, 100);

    assert!(!verifier.authorize(&a1, 101));
    assert!(verifier.authorize(&a2, 101));
    assert!(verifier.authorize(&b1, 101));
}
