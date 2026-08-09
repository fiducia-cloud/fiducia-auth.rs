# Deterministic two-verifier revocation fault model

DEN-1125 adds a test-only reference authority and two independent verifier instances around the public `fiducia_auth::cache::RevocationCache` contract introduced by DEN-1124.

## Deterministic model

The integration tests use fixed integer Unix timestamps. They perform no sleeps, network calls, background work, or operating-system clock reads. The reference authority assigns a monotonic generation to every revoke or lift. Each verifier independently starts a refresh, receives an authority reply, rejects superseded request IDs and lower generations, and then applies the accepted decision to its public cache.

The model treats every cache miss, stale entry, cached deny, or cache error as authorization denial.

## Bounded-freshness invariant

The cache contract considers an entry fresh while elapsed whole seconds are less than or equal to its configured freshness budget. Consequently, the first stale instant is:

```text
observed_at + freshness_budget_seconds + 1
```

The model asserts that a cached negative decision never authorizes at or after that first stale instant. It also asserts that a stale positive decision never becomes an allow during an authority outage.

## Fault trace

1. Both verifiers start cold and deny.
2. Each independently refreshes an authoritative negative decision and may allow only inside its bounded freshness window.
3. A token revoke reaches verifier A before verifier B. A denies immediately; B can use only its still-fresh earlier negative decision.
4. Once B reaches its first stale instant, it denies even while partitioned from the authority.
5. After B receives the revoke, both deny. A cached positive remains denied throughout authority outage and age.
6. A lift reaches verifier A before verifier B. A may allow only after its own accepted refresh; B remains denied until it independently refreshes the lifted generation.
7. A restarted verifier returns to a cold miss and denies until refreshed.
8. Delayed request replies, generation regressions, and wall-clock regressions do not replace the newer cached state.
9. Tenant and token keys remain isolated.

## Known unproved surfaces

This model validates only deterministic in-process state transitions. It does not establish a production propagation SLO, inject real packet loss or Kubernetes partitions, validate NTP behavior, model process scheduling, or prove deployment wiring. Those remain deployment-level verifier integration and fault-injection work.
