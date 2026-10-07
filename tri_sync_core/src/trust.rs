//! Trust updates: a scalar node-reliability update, and the directed
//! edge-weight (Δe) learning rule used by the graph/chain variants.

/// Moves `reliability` toward 1.0 when `estimate` is close to
/// `reference` and toward 0.0 when it isn't, clamped to `[floor, ceil]`.
/// `reference` must be something every node can locally compute or
/// observe (a fused reference value, or the chain's last agreed state)
/// - never ground truth, which no real node has access to.
///
/// Same formula as the existing (already-tested) `tri_sync::trust_graph::
/// update_reliability`: `target = 1 / (1 + error)`.
pub fn update_reliability(reliability: f64, estimate: f64, reference: f64, alpha: f64, floor: f64, ceil: f64) -> f64 {
    let error = (estimate - reference).abs();
    let target = 1.0 / (1.0 + error);
    (reliability + alpha * (target - reliability)).clamp(floor, ceil)
}

/// The Δe rule: grows or shrinks a directed edge weight `wij` based on
/// whether trusting neighbor `j` (in proportion to `share`, `j`'s share
/// of node `i`'s total incoming trust) made `i`'s fused estimate better
/// or worse than its own raw observation, both measured against
/// `reference` (the chain's last agreed state, or another value every
/// node can locally compute - never ground truth).
///
/// `delta_e = error_of_own_observation - error_of_fused_estimate`:
/// positive when fusing helped, negative when it hurt. Multiplicative
/// (`wij * exp(alpha_edge * share * delta_e)`) so weights can only
/// change sign-consistently and never cross zero in one step.
pub fn update_edge_weight(wij: f64, share: f64, delta_e: f64, alpha_edge: f64, floor: f64, ceil: f64) -> f64 {
    (wij * (alpha_edge * share * delta_e).exp()).max(floor).min(ceil)
}

/// Decays an edge weight toward the floor when the node it belongs to
/// was clarified out this step (too noisy to have contributed to any
/// fused estimate, so there's nothing to learn from) - a slow bleed
/// rather than an instant drop, so a briefly-noisy node doesn't lose
/// all standing at once.
pub fn decay_edge_weight(wij: f64, decay: f64, floor: f64, ceil: f64) -> f64 {
    (wij * decay).max(floor).min(ceil)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reliability_rises_toward_one_when_error_is_zero() {
        let r = update_reliability(0.5, 1.0, 1.0, 0.4, 0.05, 10.0);
        assert!(r > 0.5, "expected reliability to rise, got {r}");
    }

    #[test]
    fn reliability_falls_toward_zero_when_error_is_large() {
        let r = update_reliability(0.5, 0.0, 100.0, 0.4, 0.05, 10.0);
        assert!(r < 0.5, "expected reliability to fall, got {r}");
    }

    #[test]
    fn reliability_stays_within_the_clamp() {
        let r_hi = update_reliability(9.99, 1.0, 1.0, 0.9, 0.05, 10.0);
        assert!(r_hi <= 10.0);
        let r_lo = update_reliability(0.06, 0.0, 1000.0, 0.9, 0.05, 10.0);
        assert!(r_lo >= 0.05);
    }

    #[test]
    fn edge_weight_grows_when_fusing_helped() {
        let w = update_edge_weight(1.0, 0.5, 0.2, 1.2, 0.02, 3.0);
        assert!(w > 1.0, "expected growth, got {w}");
    }

    #[test]
    fn edge_weight_shrinks_when_fusing_hurt() {
        let w = update_edge_weight(1.0, 0.5, -0.2, 1.2, 0.02, 3.0);
        assert!(w < 1.0, "expected shrinkage, got {w}");
    }

    #[test]
    fn edge_weight_stays_within_the_clamp() {
        let w_hi = update_edge_weight(2.99, 1.0, 10.0, 1.2, 0.02, 3.0);
        assert!(w_hi <= 3.0);
        let w_lo = update_edge_weight(0.03, 1.0, -10.0, 1.2, 0.02, 3.0);
        assert!(w_lo >= 0.02);
    }

    #[test]
    fn decay_reduces_weight_and_respects_the_floor() {
        let w = decay_edge_weight(1.0, 0.995, 0.02, 3.0);
        assert!(w < 1.0 && w > 0.0);
        let w_floored = decay_edge_weight(0.02, 0.995, 0.02, 3.0);
        assert!(w_floored >= 0.02);
    }
}
