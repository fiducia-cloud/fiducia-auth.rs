use std::collections::{HashSet, VecDeque};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct State {
    identity_proof: bool,
    session_proof: bool,
    tenant_bound: bool,
    privileged: bool,
}

impl State {
    fn initial() -> Self {
        return Self {
            identity_proof: false,
            session_proof: false,
            tenant_bound: false,
            privileged: false,
        };
    }
}

fn next_states(state: State) -> Vec<State> {
    let mut out = Vec::new();

    if !state.identity_proof {
        out.push(State {
            identity_proof: true,
            session_proof: state.session_proof,
            tenant_bound: state.tenant_bound,
            privileged: false,
        });
    }

    if !state.session_proof {
        out.push(State {
            identity_proof: state.identity_proof,
            session_proof: true,
            tenant_bound: state.tenant_bound,
            privileged: false,
        });
    }

    if (state.identity_proof || state.session_proof) && !state.tenant_bound {
        out.push(State {
            identity_proof: state.identity_proof,
            session_proof: state.session_proof,
            tenant_bound: true,
            privileged: false,
        });
    }

    if state.identity_proof
        && state.session_proof
        && state.tenant_bound
        && !state.privileged
    {
        out.push(State {
            identity_proof: true,
            session_proof: true,
            tenant_bound: true,
            privileged: true,
        });
    }

    return out;
}

fn assert_safe(state: State) {
    if state.privileged {
        assert!(
            state.identity_proof,
            "privileged auth without independent identity proof"
        );
        assert!(
            state.session_proof,
            "privileged auth without independent session proof"
        );
        assert!(
            state.tenant_bound,
            "privileged auth without tenant binding"
        );
    }

    return;
}

fn main() {
    let start = State::initial();
    let mut queue = VecDeque::from([start]);
    let mut seen = HashSet::from([start]);
    let mut edges = 0_u64;

    while let Some(state) = queue.pop_front() {
        assert_safe(state);

        for next in next_states(state) {
            edges += 1;
            assert_safe(next);

            if seen.insert(next) {
                queue.push_back(next);
            }
        }
    }

    assert!(
        seen.iter().any(|state| state.privileged),
        "privileged state is unreachable"
    );
    assert!(
        seen.contains(&State {
            identity_proof: true,
            session_proof: false,
            tenant_bound: true,
            privileged: false,
        }),
        "identity-only proof state is unreachable"
    );
    assert!(
        seen.contains(&State {
            identity_proof: false,
            session_proof: true,
            tenant_bound: true,
            privileged: false,
        }),
        "session-only proof state is unreachable"
    );

    println!(
        "privileged auth model: {} states, {edges} transitions",
        seen.len()
    );

    return;
}
