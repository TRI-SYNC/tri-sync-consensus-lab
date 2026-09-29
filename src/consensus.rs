//! Fusing many nodes' observations into one reference value.

use crate::types::{Observation, RStar};

fn clamp(x: f64, lo: f64, hi: f64) -> f64 {
    x.max(lo).min(hi)
}

/// Fuses `observations` into a single value using a trimmed weighted mean:
/// sorts by value, drops the extreme `trim_frac` fraction from each end,
/// then averages what's left weighted by `reliabilities`. Trimming first
/// keeps a handful of far-off values (noisy or bad-faith) from moving the
/// average at all, rather than merely down-weighting them. `confidence` is
/// the inverse of the trimmed core's own variance - tight agreement among
/// survivors gives high confidence, regardless of how many were trimmed.
pub fn robust_fuse(
    obs: &[Observation],
    reliabilities: &[f64],
    trim_frac: f64,
    version: u64,
) -> RStar {
    let mut pairs: Vec<(f64, f64)> = obs
        .iter()
        .zip(reliabilities.iter())
        .map(|(o, w)| (o.value, *w))
        .collect();
    pairs.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

    let n = pairs.len();
    let k = ((n as f64) * trim_frac).floor() as usize;
    let core = if n > 2 * k { &pairs[k..(n - k)] } else { &pairs[..] };

    let wsum: f64 = core.iter().map(|(_, w)| *w).sum();
    let r = if wsum > 0.0 {
        core.iter().map(|(v, w)| v * w).sum::<f64>() / wsum
    } else {
        core.iter().map(|(v, _)| *v).sum::<f64>() / (core.len().max(1) as f64)
    };

    let mean = r;
    let var = core.iter().map(|(v, _)| (v - mean) * (v - mean)).sum::<f64>() / (core.len().max(1) as f64);
    let conf = clamp(1.0 / (1.0 + var), 0.0, 1.0);

    let t = obs.first().map(|o| o.t).unwrap_or(0);
    RStar { value: r, confidence: conf, version, t }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(values: &[f64]) -> Vec<Observation> {
        values
            .iter()
            .enumerate()
            .map(|(i, &value)| Observation {
                node_id: i,
                value,
                sigma: 0.1,
                t: 0,
            })
            .collect()
    }

    #[test]
    fn trims_a_single_far_outlier() {
        let observations = obs(&[1.0, 1.1, 0.9, 1.0, 100.0]);
        let reliabilities = vec![1.0; observations.len()];
        let r = robust_fuse(&observations, &reliabilities, 0.2, 1);
        assert!((r.value - 1.0).abs() < 0.2, "got {}", r.value);
    }

    #[test]
    fn weights_by_reliability_when_untrimmed() {
        let observations = obs(&[0.0, 10.0]);
        let reliabilities = vec![9.0, 1.0];
        let r = robust_fuse(&observations, &reliabilities, 0.0, 1);
        assert!((r.value - 1.0).abs() < 1e-9, "got {}", r.value);
    }

    #[test]
    fn confidence_is_high_when_the_core_agrees() {
        let observations = obs(&[1.0, 1.0, 1.0, 1.0]);
        let reliabilities = vec![1.0; observations.len()];
        let r = robust_fuse(&observations, &reliabilities, 0.0, 1);
        assert!(r.confidence > 0.99, "got {}", r.confidence);
    }

    #[test]
    fn confidence_is_low_when_the_core_disagrees() {
        let observations = obs(&[-10.0, 10.0]);
        let reliabilities = vec![1.0; observations.len()];
        let r = robust_fuse(&observations, &reliabilities, 0.0, 1);
        assert!(r.confidence < 0.1, "got {}", r.confidence);
    }

    #[test]
    fn t_is_the_first_observations_t() {
        let mut observations = obs(&[1.0, 2.0]);
        observations[0].t = 42;
        let reliabilities = vec![1.0; observations.len()];
        let r = robust_fuse(&observations, &reliabilities, 0.0, 1);
        assert_eq!(r.t, 42);
    }
}
