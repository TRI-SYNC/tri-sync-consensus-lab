//! The gating rule a node applies to its own local state before
//! trusting it directly. Identical to `tri_sync::invariants::clarity_gate`.

/// True when an observation's noise (`sigma`) is within the tolerance
/// (`tau`) for the current phase, meaning the node may fuse it directly.
/// False means the observation is too noisy to trust this cycle; the
/// caller should mark the node as needing clarification instead.
pub fn clarity_gate(sigma: f64, tau: f64) -> bool {
    sigma <= tau
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_when_noise_is_within_tolerance() {
        assert!(clarity_gate(0.5, 0.9));
        assert!(clarity_gate(0.9, 0.9));
    }

    #[test]
    fn fails_when_noise_exceeds_tolerance() {
        assert!(!clarity_gate(0.95, 0.9));
    }
}
