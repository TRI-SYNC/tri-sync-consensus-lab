use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

/// Fixed by default so a run can be reproduced exactly; not yet exposed
/// as a CLI flag.
const SEED: u64 = 42;
use rand_distr::StandardNormal;

/// Nodes that report a deliberate, consistent lie instead of an honest
/// noisy reading - not a Sybil cluster or an equivocating signer, just
/// conflicting data: a fabricated value that doesn't track `truth`.
/// Chosen to be a clear minority (5 of 25 = 20%) of the network.
const MALICIOUS_NODES: [usize; 5] = [3, 8, 13, 18, 23];

/// The fixed offset a malicious node reports instead of the truth. Large
/// enough to matter (bigger than `eps_align`), not so large it would be
/// caught by a naive bounds check alone.
const LIE_BIAS: f64 = 3.0;

/// Malicious nodes get the network's lowest (most "confident-looking")
/// noise bucket, so `invariants::clarity_gate` never flags them - they
/// aren't caught by looking noisy. If anything catches them, it has to be
/// `consensus::robust_fuse`'s trimming or `trust_graph`'s reliability
/// scoring, not the noise-based gate.
const MALICIOUS_SIGMA: f64 = 0.15;

use tri_sync::types::{NodeState, Observation, TelemetryRow};
use tri_sync::{consensus, invariants, node, phase, telemetry, trust_graph};

/// Final state of a run, returned by `simulate` so both `main` (for the
/// printed adversarial summary) and tests (for invariant/reproducibility/
/// adversarial-separation assertions) can inspect it without re-running
/// the loop or scraping stdout.
struct Outcome {
    truth: f64,
    r_star_final: f64,
    nodes: Vec<NodeState>,
}

fn simulate(seed: u64, verbose: bool) -> Outcome {
    let mut rng = StdRng::seed_from_u64(seed);

    let n = 25usize;
    let mut nodes: Vec<NodeState> = (0..n).map(|_| NodeState{
        x: 0.0,
        reliability: 1.0,
        last_obs: None,
        clarified: false,
    }).collect();

    // Environment truth (toy scalar)
    let mut truth: f64 = 0.0;
    let drift: f64 = 0.03;
    let shock_prob: f64 = 0.04;
    let shock_mag: f64 = 2.8;

    // Thresholds
    let tau_normal = 1.05;
    let tau_fast = 0.75;
    let eps_align = 0.30;
    let delta_explode = 0.50;

    // Phase + completion
    let fast_cycles = 12u64;
    let complete_cycles = 10u64;

    // Trust update
    let alpha = 0.40;
    let floor = 0.05;
    let ceil = 10.0;

    let mut t: u64 = 0;
    let mut version: u64 = 0;
    let mut fast_sync_remaining: u64 = 0;
    let mut complete_streak: u64 = 0;
    // Always overwritten before use: the loop only exits via `break`
    // after its body (which sets this) has run at least once.
    #[allow(unused_assignments)]
    let mut r_star_final: f64 = 0.0;

    if verbose { telemetry::print_header(); }

    loop {
        t += 1;

        // ENV update
        truth += drift;
        if rng.gen::<f64>() < shock_prob {
            truth += if rng.gen::<bool>() { shock_mag } else { -shock_mag };
        }

        // OBSERVE
        let mut observations: Vec<Observation> = Vec::with_capacity(n);
        let mut reliabilities: Vec<f64> = Vec::with_capacity(n);

        for (i, nd) in nodes.iter_mut().enumerate() {
            let is_malicious = MALICIOUS_NODES.contains(&i);
            let sigma = if is_malicious {
                MALICIOUS_SIGMA
            } else {
                match i % 6 {
                    0 => 0.15, 1 => 0.25, 2 => 0.35, 3 => 0.55, 4 => 0.90, _ => 1.30
                }
            };
            let bias = if i % 11 == 0 { 0.08 } else if i % 17 == 0 { -0.08 } else { 0.0 };
            // Always draw, whether or not it's used, so the RNG stream
            // doesn't depend on which nodes are malicious - only what
            // each node reports does.
            let noise: f64 = rng.sample::<f64, _>(StandardNormal) * sigma;
            let obs_val = if is_malicious { truth + LIE_BIAS } else { truth + bias + noise };

            let obs = Observation { node_id: i, value: obs_val, sigma, t };
            node::set_observation(nd, obs.clone());

            observations.push(obs);
            reliabilities.push(nd.reliability);
        }

        // OTHERS -> R*
        version += 1;
        let rstar = consensus::robust_fuse(&observations, &reliabilities, 0.18, version);
        let r_star = rstar.value;
        r_star_final = r_star;

        // SELF -> lock (no drift) with clarity gate
        let tau = if fast_sync_remaining > 0 { tau_fast } else { tau_normal };
        let mut clarified = 0usize;
        for nd in nodes.iter_mut() {
            let sigma = nd.last_obs.as_ref().unwrap().sigma;
            if !invariants::clarity_gate(sigma, tau) {
                nd.clarified = true;
                clarified += 1;
                continue;
            }
            nd.clarified = false;
            node::fuse_lock(nd, r_star);
        }

        // Disagreement
        let xs: Vec<f64> = nodes.iter().filter(|n| !n.clarified).map(|n| n.x).collect();
        let d = phase::disagreement(&xs, r_star);

        // Trust update
        for nd in nodes.iter_mut() {
            trust_graph::update_reliability(nd, r_star, alpha, floor, ceil);
        }

        // Phase transition
        if phase::should_explode(d, delta_explode, fast_sync_remaining) {
            fast_sync_remaining = fast_cycles;
        }
        if fast_sync_remaining > 0 {
            fast_sync_remaining -= 1;
        }

        // Completion
        let all_ok = nodes.iter().all(|nd| !nd.clarified && (nd.x - r_star).abs() <= eps_align);
        if all_ok { complete_streak += 1; } else { complete_streak = 0; }
        let done = complete_streak >= complete_cycles;

        let mean_rel = nodes.iter().map(|n| n.reliability).sum::<f64>() / (n as f64);

        let row = TelemetryRow {
            t,
            truth,
            r_star,
            disagreement: d,
            clarified,
            mean_reliability: mean_rel,
            fast_sync_remaining,
            complete_streak,
            done,
        };

        if verbose && (t % 5 == 0 || done) {
            telemetry::print_row(&row);
        }

        if done {
            if verbose { println!("\n✅ COMPLETE: sustained alignment achieved."); }
            break;
        }
        if t >= 250 {
            // Completion requires every node, honest or not, within
            // eps_align of r_star - malicious nodes keep re-injecting
            // LIE_BIAS every step, so they never actually converge and
            // `done` structurally can't fire while they're present. That
            // is the expected outcome here, not a failure of the run.
            if verbose {
                println!(
                    "\nℹ️  Not completed within step budget (expected: malicious nodes \
                     never converge, so global completion can't fire while they're present)."
                );
            }
            break;
        }
    }

    Outcome { truth, r_star_final, nodes }
}

fn print_adversarial_summary(outcome: &Outcome) {
    let Outcome { truth, r_star_final, nodes } = outcome;
    println!("\n--- adversarial summary ---");
    println!("truth={truth:.4}  r_star={r_star_final:.4}  |truth - r_star|={:.4}",
        (truth - r_star_final).abs());

    let honest_rel: Vec<f64> = nodes.iter().enumerate()
        .filter(|(i, _)| !MALICIOUS_NODES.contains(i))
        .map(|(_, nd)| nd.reliability)
        .collect();
    let malicious_rel: Vec<f64> = MALICIOUS_NODES.iter().map(|&i| nodes[i].reliability).collect();
    let mean = |v: &[f64]| v.iter().sum::<f64>() / (v.len().max(1) as f64);

    println!(
        "mean reliability: honest={:.4} (n={})  malicious={:.4} (n={})",
        mean(&honest_rel), honest_rel.len(), mean(&malicious_rel), malicious_rel.len()
    );
    for &i in &MALICIOUS_NODES {
        println!(
            "  malicious node {i}: reliability={:.4}  |x - r_star|={:.4}",
            nodes[i].reliability, (nodes[i].x - r_star_final).abs()
        );
    }
}

fn main() {
    let outcome = simulate(SEED, true);
    print_adversarial_summary(&outcome);
}

#[cfg(test)]
mod sim_tests {
    use super::*;

    #[test]
    fn reproducible_given_the_same_seed() {
        let a = simulate(SEED, false);
        let b = simulate(SEED, false);
        assert_eq!(a.truth, b.truth);
        assert_eq!(a.r_star_final, b.r_star_final);
        for (na, nb) in a.nodes.iter().zip(b.nodes.iter()) {
            assert_eq!(na.reliability, nb.reliability);
            assert_eq!(na.x, nb.x);
        }
    }

    #[test]
    fn fused_reference_tracks_truth_despite_liars() {
        let outcome = simulate(SEED, false);
        // LIE_BIAS is 3.0; the fused reference should stay far closer to
        // truth than that despite 5 of 25 nodes lying every step.
        assert!(
            (outcome.truth - outcome.r_star_final).abs() < 0.5,
            "|truth - r_star| = {}",
            (outcome.truth - outcome.r_star_final).abs()
        );
    }

    #[test]
    fn liars_end_up_measurably_less_reliable_than_honest_nodes() {
        let outcome = simulate(SEED, false);
        let honest_mean: f64 = outcome.nodes.iter().enumerate()
            .filter(|(i, _)| !MALICIOUS_NODES.contains(i))
            .map(|(_, nd)| nd.reliability)
            .sum::<f64>() / (outcome.nodes.len() - MALICIOUS_NODES.len()) as f64;
        let malicious_mean: f64 = MALICIOUS_NODES.iter()
            .map(|&i| outcome.nodes[i].reliability)
            .sum::<f64>() / MALICIOUS_NODES.len() as f64;
        assert!(
            malicious_mean < honest_mean - 0.2,
            "malicious_mean={malicious_mean} honest_mean={honest_mean}"
        );
    }
}
