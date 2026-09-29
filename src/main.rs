use rand::Rng;
use rand_distr::StandardNormal;

use tri_sync::types::{NodeState, Observation, TelemetryRow};
use tri_sync::{consensus, invariants, node, phase, telemetry, trust_graph};

fn main() {
    let mut rng = rand::thread_rng();

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

    telemetry::print_header();

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
            let sigma = match i % 6 {
                0 => 0.15, 1 => 0.25, 2 => 0.35, 3 => 0.55, 4 => 0.90, _ => 1.30
            };
            let bias = if i % 11 == 0 { 0.08 } else if i % 17 == 0 { -0.08 } else { 0.0 };
            let noise: f64 = rng.sample::<f64, _>(StandardNormal) * sigma;
            let obs_val = truth + bias + noise;

            let obs = Observation { node_id: i, value: obs_val, sigma, t };
            node::set_observation(nd, obs.clone());

            observations.push(obs);
            reliabilities.push(nd.reliability);
        }

        // OTHERS -> R*
        version += 1;
        let rstar = consensus::robust_fuse(&observations, &reliabilities, 0.18, version);
        let r_star = rstar.value;

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
            trust_graph::update_reliability(nd, truth, alpha, floor, ceil);
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

        if t % 5 == 0 || done {
            telemetry::print_row(&row);
        }

        if done {
            println!("\n✅ COMPLETE: sustained alignment achieved.");
            break;
        }
        if t >= 250 {
            println!("\nℹ️  Not completed within step budget (normal under frequent shocks).");
            break;
        }
    }
}
