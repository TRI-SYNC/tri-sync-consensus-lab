//! Per-node state transitions.

use crate::types::{NodeState, Observation};

/// Records `obs` as the node's most recent reading.
pub fn set_observation(node: &mut NodeState, obs: Observation) {
    node.last_obs = Some(obs);
}

/// Locks the node's estimate by blending its own last observation with the
/// fused reference `r_star`, weighting its own observation by inverse
/// noise (a less noisy node trusts itself more).
pub fn fuse_lock(node: &mut NodeState, r_star: f64) {
    let (obs_value, sigma) = match &node.last_obs {
        Some(obs) => (obs.value, obs.sigma),
        None => (node.x, 1.0),
    };
    let self_weight = (1.0 / sigma.max(1e-9)).clamp(0.5, 5.0);
    node.x = (self_weight * obs_value + r_star) / (self_weight + 1.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_with_obs(value: f64, sigma: f64) -> NodeState {
        let mut node = NodeState {
            x: 0.0,
            reliability: 1.0,
            last_obs: None,
            clarified: false,
        };
        set_observation(
            &mut node,
            Observation {
                node_id: 0,
                value,
                sigma,
                t: 0,
            },
        );
        node
    }

    #[test]
    fn locks_between_own_observation_and_reference() {
        let mut node = node_with_obs(2.0, 1.0);
        fuse_lock(&mut node, 0.0);
        // self_weight = 1.0, so this is the midpoint of 2.0 and 0.0.
        assert!((node.x - 1.0).abs() < 1e-9, "got {}", node.x);
    }

    #[test]
    fn a_less_noisy_node_trusts_its_own_observation_more() {
        let mut node = node_with_obs(2.0, 0.2);
        fuse_lock(&mut node, 0.0);
        assert!(node.x > 1.0, "got {}", node.x);
    }
}
