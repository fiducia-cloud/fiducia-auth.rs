#!/usr/bin/env python3
from dataclasses import dataclass
from collections import deque

@dataclass(frozen=True)
class State:
    identity_proof: bool = False
    session_proof: bool = False
    tenant_bound: bool = False
    privileged: bool = False


def next_states(s: State):
    out = []
    if not s.identity_proof:
        out.append(State(True, s.session_proof, s.tenant_bound, False))
    if not s.session_proof:
        out.append(State(s.identity_proof, True, s.tenant_bound, False))
    if (s.identity_proof or s.session_proof) and not s.tenant_bound:
        out.append(State(s.identity_proof, s.session_proof, True, False))
    if s.identity_proof and s.session_proof and s.tenant_bound and not s.privileged:
        out.append(State(True, True, True, True))
    return out


def check(s: State):
    if s.privileged:
        assert s.identity_proof, "privileged auth without independent identity proof"
        assert s.session_proof, "privileged auth without independent session proof"
        assert s.tenant_bound, "privileged auth without tenant binding"


def main():
    start = State(); q = deque([start]); seen = {start}; edges = 0
    while q:
        s = q.popleft(); check(s)
        for n in next_states(s):
            edges += 1; check(n)
            if n not in seen:
                seen.add(n); q.append(n)
    assert any(s.privileged for s in seen)
    assert State(True, False, True, False) in seen
    assert State(False, True, True, False) in seen
    print(f"privileged auth model: {len(seen)} states, {edges} transitions")

if __name__ == "__main__":
    main()
