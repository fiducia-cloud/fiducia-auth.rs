# Bounded formal safety: key-lifecycle-safety

## Proof obligation
API-key rotation, authoritative revocation, and explicit TTL-limited edge cache allowance.

Run `node formal/check_safety.mjs`. The oracle exhaustively enumerates its
explicit **finite** transition system, checks safety on every state and edge,
requires reachable nontrivial transitions, and tests known-bad mutants. The
bound is printed in its report. No external solver or credentials are required.

## Model assumptions and limits
The transitions describe the **intended contract**, not a verified extraction
of production behavior. Fairness, arbitrary-sized queues, multiple tenants,
real-time bounds, persistence and implementation refinement are **not proven**
unless separately tested. This is bounded model checking, not an unbounded proof.

## Follow-on release gate
Implement an auth/edge integration refinement harness with injected clock and proof that production maximum TTL bounds stale grants.
Record exact source/head SHA, test commands, exit status, and compiler/runner
provenance for any implementation-level verification. A passing workflow only
establishes the local bounded model result, **not** end-to-end correctness.
