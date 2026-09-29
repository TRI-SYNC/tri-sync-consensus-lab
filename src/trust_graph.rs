//! Per-node reliability updates.

use crate::types::NodeState;

/// Moves `node.reliability` toward a target derived from how close its
/// locked estimate is to the fused reference `r_star`, at learning rate
/// `alpha`, clamped to `[floor, ceil]`.
///
/// Scores against `r_star` (`consensus::RStar::value`), not ground truth:
/// a real node has no access to the answer the simulation is trying to
/// discover, only to the group's own fused estimate. A node whose
/// observations keep disagreeing with the group still shows up here,
/// because `fuse_lock` only partially pulls `node.x` toward `r_star` (see
/// its self-weighting) - it doesn't erase the disagreement, just damps it.
pub fn update_reliability(node: &mut NodeState, r_star: f64, alpha: f64, floor: f64, ceil: f64) {
    let error = (node.x - r_star).abs();
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
