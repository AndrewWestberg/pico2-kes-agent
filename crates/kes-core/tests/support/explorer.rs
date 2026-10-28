use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_states: usize,
    pub max_transitions: usize,
    pub max_depth: usize,
}

impl Limits {
    pub fn validate(self) -> Result<Self, &'static str> {
        if self.max_states == 0 || self.max_transitions == 0 {
            return Err("state and transition limits must be nonzero");
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counters {
    pub states: usize,
    pub transitions: usize,
    pub duplicate_states: usize,
    pub terminal_states: usize,
    pub deepest_state: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exhaustion {
    States,
    Transitions,
    Depth,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Complete(Counters),
    Inconclusive {
        counters: Counters,
        exhausted: Exhaustion,
    },
}

impl Outcome {
    pub const fn counters(self) -> Counters {
        match self {
            Self::Complete(counters) | Self::Inconclusive { counters, .. } => counters,
        }
    }

    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete(_))
    }
}

/// Breadth-first exploration visits every distinct ordered state reachable under
/// the supplied action alphabet and successor relation. Hitting any configured
/// limit is explicitly inconclusive; callers must not interpret partial counts
/// as a model pass.
pub fn explore<State, Action, Enabled, Successors>(
    initial: State,
    limits: Limits,
    enabled: Enabled,
    successors: Successors,
) -> Result<Outcome, &'static str>
where
    State: Clone + Ord,
    Action: Clone,
    Enabled: Fn(&State) -> Vec<Action>,
    Successors: Fn(&State, &Action) -> Vec<State>,
{
    let limits = limits.validate()?;
    let mut seen = BTreeMap::new();
    let mut queue = VecDeque::new();
    seen.insert(initial.clone(), 0usize);
    queue.push_back((initial, 0usize));
    let mut counters = Counters {
        states: 1,
        ..Counters::default()
    };

    while let Some((state, depth)) = queue.pop_front() {
        counters.deepest_state = counters.deepest_state.max(depth);
        let actions = enabled(&state);
        if actions.is_empty() {
            counters.terminal_states += 1;
            continue;
        }
        if depth == limits.max_depth {
            return Ok(Outcome::Inconclusive {
                counters,
                exhausted: Exhaustion::Depth,
            });
        }
        for action in actions {
            let next = successors(&state, &action);
            if next.is_empty() {
                counters.terminal_states += 1;
            }
            for successor in next {
                if counters.transitions == limits.max_transitions {
                    return Ok(Outcome::Inconclusive {
                        counters,
                        exhausted: Exhaustion::Transitions,
                    });
                }
                counters.transitions += 1;
                if seen.contains_key(&successor) {
                    counters.duplicate_states += 1;
                    continue;
                }
                if counters.states == limits.max_states {
                    return Ok(Outcome::Inconclusive {
                        counters,
                        exhausted: Exhaustion::States,
                    });
                }
                let next_depth = depth + 1;
                seen.insert(successor.clone(), next_depth);
                queue.push_back((successor, next_depth));
                counters.states += 1;
            }
        }
    }

    Ok(Outcome::Complete(counters))
}
