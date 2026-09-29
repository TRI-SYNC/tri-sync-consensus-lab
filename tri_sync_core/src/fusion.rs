//! Trimmed, reliability-weighted fusion of several nodes' state vectors
//! into one reference value. Dimension-agnostic: works for a scalar
//! (`Vec<f64>` of length 1) or an n-dimensional state alike.

/// Fuses `values` (one `Vec<f64>` per contributing node, all the same
/// length) into a single vector using a trimmed weighted mean per
/// dimension: sorts each dimension's values, drops the extreme
/// `trim_frac` fraction from each end, then averages what's left
/// weighted by `weights`. Trimming first keeps a handful of far-off
/// values from moving the average at all, rather than merely
/// down-weighting them.
///
/// Panics if `values` is empty or `values`/`weights` differ in length -
/// both are caller bugs, not something to paper over silently.
pub fn trimmed_fuse(values: &[Vec<f64>], weights: &[f64], trim_frac: f64) -> Vec<f64> {
    assert!(!values.is_empty(), "trimmed_fuse: no values to fuse");
    assert_eq!(values.len(), weights.len(), "trimmed_fuse: values/weights length mismatch");

    let dim = values[0].len();
    let mut out = vec![0.0; dim];
    for k in 0..dim {
        let mut pairs: Vec<(f64, f64)> = values.iter().zip(weights.iter()).map(|(v, w)| (v[k], *w)).collect();
        pairs.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

        let n = pairs.len();
        let t = ((n as f64) * trim_frac).floor() as usize;
        let core = if n > 2 * t { &pairs[t..(n - t)] } else { &pairs[..] };

        let wsum: f64 = core.iter().map(|(_, w)| *w).sum();
        out[k] = if wsum > 0.0 {
            core.iter().map(|(v, w)| v * w).sum::<f64>() / wsum
        } else {
            core.iter().map(|(v, _)| *v).sum::<f64>() / (core.len().max(1) as f64)
        };
    }
    out
}

/// Euclidean distance between two equal-length vectors.
pub fn l2_distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| (x - y) * (x - y)).sum::<f64>().sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_a_single_far_outlier() {
        let values = vec![vec![1.0], vec![1.1], vec![0.9], vec![1.0], vec![100.0]];
        let weights = vec![1.0; 5];
        let out = trimmed_fuse(&values, &weights, 0.2);
        assert!((out[0] - 1.0).abs() < 0.2, "got {}", out[0]);
    }

    #[test]
    fn weights_by_reliability_when_untrimmed() {
        let values = vec![vec![0.0], vec![10.0]];
        let weights = vec![9.0, 1.0];
        let out = trimmed_fuse(&values, &weights, 0.0);
        assert!((out[0] - 1.0).abs() < 1e-9, "got {}", out[0]);
    }

    #[test]
    fn fuses_each_dimension_independently() {
        let values = vec![vec![0.0, 10.0], vec![10.0, 0.0]];
        let weights = vec![1.0, 1.0];
        let out = trimmed_fuse(&values, &weights, 0.0);
        assert!((out[0] - 5.0).abs() < 1e-9);
        assert!((out[1] - 5.0).abs() < 1e-9);
    }

    #[test]
    fn l2_distance_is_symmetric_and_zero_for_equal_vectors() {
        let a = vec![1.0, 2.0, 3.0];
        let b = vec![4.0, 0.0, 3.0];
        assert!((l2_distance(&a, &a)).abs() < 1e-12);
        assert!((l2_distance(&a, &b) - l2_distance(&b, &a)).abs() < 1e-12);
    }

    #[test]
    #[should_panic(expected = "no values to fuse")]
    fn panics_on_empty_input() {
        trimmed_fuse(&[], &[], 0.1);
    }
}
