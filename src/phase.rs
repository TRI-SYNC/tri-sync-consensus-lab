//! Detecting when the system is diverging enough to switch sync speed.

/// Mean absolute distance of `xs` (non-clarified nodes' locked estimates)
/// from the fused reference. `f64::INFINITY` if no node contributed.
pub fn disagreement(xs: &[f64], r_star: f64) -> f64 {
    if xs.is_empty() {
        return f64::INFINITY;
    }
    xs.iter().map(|x| (x - r_star).abs()).sum::<f64>() / (xs.len() as f64)
}

/// True when disagreement has crossed the explosion threshold and the
/// system isn't already in a fast-sync window.
pub fn should_explode(d: f64, delta: f64, fast_sync_remaining: u64) -> bool {
    fast_sync_remaining == 0 && d < delta
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disagreement_is_infinite_with_no_contributors() {
        assert_eq!(disagreement(&[], 0.0), f64::INFINITY);
    }

    #[test]
    fn disagreement_is_mean_absolute_distance() {
        assert!((disagreement(&[1.0, 3.0], 2.0) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn does_not_explode_mid_fast_sync() {
        assert!(!should_explode(0.0, 1.0, 5));
    }

    #[test]
    fn explodes_when_idle_and_disagreement_is_low() {
        assert!(should_explode(0.1, 1.0, 0));
    }
}
