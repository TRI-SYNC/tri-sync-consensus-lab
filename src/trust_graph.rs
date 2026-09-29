//! Per-node reliability updates.

use crate::types::NodeState;

/// Moves `node.reliability` toward a target derived from how close its
/// locked estimate is to `truth`, at learning rate `alpha`, clamped to
/// `[floor, ceil]`.
///
/// This is not something a real node could run: `truth` is the simulation's
/// ground truth, not anything a distributed node has access to. A
/// deployable version of this would compare a node's estimate against the
/// fused reference (`consensus::RStar`) or its neighbors' estimates
/// instead - never against the answer the simulation is trying to
/// discover. Implemented as called for; not a design endorsement.
pub fn update_reliability(node: &mut NodeState, truth: f64, alpha: f64, floor: f64, ceil: f64) {
    let error = (node.x - truth).abs();
    let target = 1.0 / (1.0 + error);
    let updated = node.reliability + alpha * (target - node.reliability);
    node.reliability = updated.clamp(floor, ceil);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_at(x: f64, reliability: f64) -> NodeState {
        NodeState {
            x,
            reliability,
            last_obs: None,
            clarified: false,
        }
    }

    #[test]
    fn reliability_rises_toward_one_when_error_is_zero() {
        let mut node = node_at(1.0, 0.5);
        update_reliability(&mut node, 1.0, 0.4, 0.05, 10.0);
        assert!(node.reliability > 0.5, "got {}", node.reliability);
    }

    #[test]
    fn reliability_falls_toward_zero_when_error_is_large() {
        let mut node = node_at(100.0, 0.5);
        update_reliability(&mut node, 0.0, 0.4, 0.05, 10.0);
        assert!(node.reliability < 0.5, "got {}", node.reliability);
    }

    #[test]
    fn stays_within_the_clamp() {
        let mut node = node_at(1.0, 9.9);
        for _ in 0..50 {
            update_reliability(&mut node, 1.0, 0.9, 0.05, 10.0);
        }
        assert!(node.reliability <= 10.0);
    }
}
