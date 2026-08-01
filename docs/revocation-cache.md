# Verifier revocation cache contract

This document defines the reusable verifier-local `RevocationCache` boundary introduced for DEN-1124 and the deterministic two-verifier model required by DEN-1125.

## Safety invariant

A cached `NotRevoked` decision may authorize only while `now < fresh_until`. At the exclusive freshness deadline and after it, the verifier denies until another authoritative response is accepted. A cached `Revoked` decision never degrades into a local allow: it remains denied during an authority outage, and an expired revocation remains denied with `RevocationExpiredNeedsRefresh` until the authority confirms a newer state.

Every public cache operation accepts an explicit Unix timestamp and observes one cache-instance high-water mark. Any timestamp below the greatest accepted timestamp returns the metrics-safe `clock_regression` error before changing refresh or cached-decision state. Callers must treat every cache error as deny. Normal operation resumes only when observed time reaches or exceeds the high-water mark.

The cache does not read the OS clock itself. Production callers remain responsible for supplying Unix time and alerting on `RevocationCacheError::metric_kind() == "clock_regression"`. Errors never include the opaque cache key, tenant, subject, or token ID.

## Restart boundary

The high-water mark and entries are intentionally process-local. A restarted verifier creates a new cache, is cold, and denies every target until authoritative refresh. Persisting local allow decisions across restart is outside this contract and would require a separate authenticated persistence design.

## Refresh ordering

`begin_refresh` returns an opaque permit. Starting a newer refresh for the same key supersedes older permits. `apply_authoritative` rejects delayed responses from superseded permits and rejects an authority generation below the currently cached generation. Rejected responses preserve the existing entry.

The opaque cache key should normally be the hashed `RevocationSelector::storage_key`, which keeps identity values out of cache diagnostics while preserving tenant and target isolation.

## Deterministic two-verifier trace

The unit model uses fixed timestamps and no sleeps or network calls:

1. Both verifier caches start cold and deny.
2. Generation 1 `NotRevoked` is refreshed independently into each cache; each may allow only before its exclusive freshness deadline.
3. Generation 2 `Revoked` reaches verifier A first. A denies immediately while B remains bounded by its still-fresh generation 1 negative decision.
4. Once B's negative decision reaches its freshness deadline, B denies even if the authority is unavailable.
5. Generation 2 reaches B; both deny. A stale positive remains denied for the entire authority outage.
6. Generation 3 `NotRevoked` (lift) reaches A first. Only A can allow within its new freshness window; B remains denied until it independently refreshes generation 3.
7. Restarting either verifier returns that instance to cold fail-closed state.
8. A wall-clock regression or delayed response never replaces cached state.

## Known unproved surfaces

This deterministic model proves only the in-process cache contract. It does not measure production propagation latency, model NTP behavior across hosts, inject real network partitions, validate Kubernetes rollout behavior, or establish a propagation SLO. Those require deployment-level fault injection and telemetry after verifier integration.
