#[path = "support/actions.rs"]
mod actions;
#[path = "support/explorer.rs"]
mod explorer;

use actions::{Action, RaceOrder, SequenceConfig};
use explorer::{Exhaustion, Limits, Outcome};

#[test]
fn deterministic_g3_sequences_respect_pool_length_retry_and_fault_bounds() {
    let config = SequenceConfig::g3();
    let first = actions::generate(config, 0x1234_5678).unwrap();
    let replay = actions::generate(config, 0x1234_5678).unwrap();
    let other = actions::generate(config, 0x1234_5679).unwrap();
    assert_eq!(first, replay);
    assert_ne!(first, other);
    assert!((1..=256).contains(&first.actions.len()));
    for (index, action) in first.actions.iter().enumerate() {
        match action {
            Action::Enroll { pool }
            | Action::Generate { pool }
            | Action::Certify { pool }
            | Action::ResolveRace { pool, .. } => assert!(*pool < 64),
            Action::Retry { action_index } => assert!(usize::from(*action_index) < index),
            Action::TornWrite { byte } => assert!(*byte <= 256),
            Action::TornErase { byte } => assert!(*byte <= 4096),
            Action::AdvancePeriod { period } => assert!(*period < 64),
            Action::Reboot => {}
        }
    }
}

#[test]
fn finite_alphabet_contains_two_pools_three_periods_retries_faults_and_both_races() {
    let alphabet = actions::finite_model_actions();
    for pool in 0..2 {
        assert!(alphabet.contains(&Action::ResolveRace {
            pool,
            order: RaceOrder::ActivateThenDiscard,
        }));
        assert!(alphabet.contains(&Action::ResolveRace {
            pool,
            order: RaceOrder::DiscardThenActivate,
        }));
    }
    for period in 0..3 {
        assert!(alphabet.contains(&Action::AdvancePeriod { period }));
    }
    assert!(
        alphabet
            .iter()
            .any(|action| matches!(action, Action::Retry { .. }))
    );
    assert!(
        alphabet
            .iter()
            .any(|action| matches!(action, Action::TornWrite { .. }))
    );
    assert!(
        alphabet
            .iter()
            .any(|action| matches!(action, Action::TornErase { .. }))
    );
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ModelState {
    enrolled: u8,
    period: u8,
}

fn enabled(state: &ModelState) -> Vec<Action> {
    let mut actions = Vec::new();
    for pool in 0..2 {
        if state.enrolled & (1 << pool) == 0 {
            actions.push(Action::Enroll { pool });
        }
    }
    if state.period < 2 {
        actions.push(Action::AdvancePeriod {
            period: state.period + 1,
        });
    }
    actions
}

fn successors(state: &ModelState, action: &Action) -> Vec<ModelState> {
    let mut next = *state;
    match *action {
        Action::Enroll { pool } if pool < 2 => next.enrolled |= 1 << pool,
        Action::AdvancePeriod { period } if period == state.period + 1 && period < 3 => {
            next.period = period;
        }
        _ => return Vec::new(),
    }
    vec![next]
}

#[test]
fn explorer_exhausts_all_reachable_two_pool_three_period_states() {
    let result = explorer::explore(
        ModelState {
            enrolled: 0,
            period: 0,
        },
        Limits {
            max_states: 12,
            max_transitions: 64,
            max_depth: 4,
        },
        enabled,
        successors,
    )
    .unwrap();
    assert!(result.is_complete());
    let counters = result.counters();
    assert_eq!(counters.states, 12);
    assert_eq!(counters.deepest_state, 4);
    assert!(counters.transitions > counters.states);
    assert!(counters.duplicate_states > 0);
    assert_eq!(counters.terminal_states, 1);
}

#[test]
fn explorer_reports_limits_as_inconclusive_not_complete() {
    let result = explorer::explore(
        ModelState {
            enrolled: 0,
            period: 0,
        },
        Limits {
            max_states: 4,
            max_transitions: 64,
            max_depth: 4,
        },
        enabled,
        successors,
    )
    .unwrap();
    assert!(matches!(
        result,
        Outcome::Inconclusive {
            exhausted: Exhaustion::States,
            ..
        }
    ));
    assert!(!result.is_complete());
    assert_eq!(result.counters().states, 4);
}
