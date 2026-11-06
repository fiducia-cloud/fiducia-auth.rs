// Abstract, bounded independent revocation authorization model.
// Checks two tenants, three generations, pending proofs, revoke/lift and stale retries.
// DOES NOT prove KV linearizability or the production verifier cache implementation.
use std::collections::{HashSet, VecDeque};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
struct State {
    generation: [u8; 2],
    revoked: [bool; 2],
    pending: [u8; 2],
    commits: [u8; 2],
    denied_stale: bool,
    unsafe_commit: bool,
}
fn initial() -> State {
    State {
        generation: [1, 1],
        revoked: [false, false],
        pending: [0, 0],
        commits: [0, 0],
        denied_stale: false,
        unsafe_commit: false,
    }
}
fn safe(s: State) -> bool {
    !s.unsafe_commit && (0..2).all(|i| {
        (1..=3).contains(&s.generation[i]) &&
        s.pending[i] <= s.generation[i] &&
        s.commits[i] <= 2
    })
}
fn successors(s: State) -> Vec<(&'static str, State)> {
    let mut out = Vec::new();
    for i in 0..2 {
        if !s.revoked[i] && s.pending[i] == 0 && s.commits[i] < 2 {
            let mut next = s;
            next.pending[i] = s.generation[i];
            out.push(("begin_authorization", next));
        }
        if !s.revoked[i] && s.generation[i] < 3 {
            let mut next = s;
            next.generation[i] += 1;
            next.revoked[i] = true;
            out.push(("revoke_tenant_subject", next));
        }
        if s.revoked[i] && s.generation[i] < 3 {
            let mut next = s;
            next.generation[i] += 1;
            next.revoked[i] = false;
            out.push(("lift_revocation_new_generation", next));
        }
        if s.pending[i] > 0 {
            let mut next = s;
            if !s.revoked[i] && s.pending[i] == s.generation[i] &&
                s.commits[i] < 2 {
                next.commits[i] += 1;
                next.pending[i] = 0;
                out.push(("commit_authorized_action", next));
            } else {
                next.pending[i] = 0;
                next.denied_stale = true;
                out.push(("reject_revoked_or_stale_proof", next));
            }
        }
    }
    out
}
fn explore(inject_unsafe: bool) -> (usize, usize, bool, bool, Option<Vec<&'static str>>) {
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([(initial(), Vec::new())]);
    let mut edges = 0;
    let mut successful = false;
    let mut rejected = false;
    while let Some((s, trace)) = queue.pop_front() {
        if !seen.insert(s) { continue; }
        if !safe(s) {
            return (seen.len(), edges, successful, rejected, Some(trace));
        }
        successful |= s.commits[0] > 0 && s.commits[1] > 0;
        rejected |= s.denied_stale;
        let mut next = successors(s);
        if inject_unsafe {
            for i in 0..2 {
                if s.pending[i] > 0 && (s.revoked[i] || s.pending[i] != s.generation[i]) {
                    let mut bad = s;
                    bad.pending[i] = 0;
                    bad.unsafe_commit = true;
                    next.push(("UNSAFE:accept_revoked_or_stale_proof", bad));
                }
            }
        }
        for (label, after) in next {
            edges += 1;
            let mut path = trace.clone(); path.push(label);
            queue.push_back((after, path));
        }
    }
    (seen.len(), edges, successful, rejected, None)
}
#[test]
fn bounded_two_tenant_revocation_safety() {
    let (states, edges, successful, rejected, bad) = explore(false);
    assert!(bad.is_none(), "authorization invariant failed: {bad:?}");
    assert!(successful && rejected, "must reach valid permits and stale rejections");
    assert!(states > 25 && edges > 40);
    println!("HOST_ONLY tenant revocation model: {states} states, {edges} edges");
}
#[test]
fn unsafe_revoked_authorization_must_have_counterexample() {
    let (_, _, _, _, bad) = explore(true);
    let trace = bad.expect("unsafe authorization escaped checks");
    assert_eq!(trace.last(), Some(&"UNSAFE:accept_revoked_or_stale_proof"));
    println!("Expected stale authorization counterexample: {trace:?}");
}
