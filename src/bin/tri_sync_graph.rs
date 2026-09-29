use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

/// Fixed by default so a run can be reproduced exactly; not yet exposed
/// as a CLI flag.
const SEED: u64 = 42;
use rand_distr::StandardNormal;

use tri_sync::{invariants, telemetry};
use tri_sync::types::TelemetryRow;

fn clamp(x: f64, lo: f64, hi: f64) -> f64 { x.max(lo).min(hi) }
fn l2(v: &[f64]) -> f64 { v.iter().map(|x| x*x).sum::<f64>().sqrt() }
fn v_sub(a: &[f64], b: &[f64]) -> Vec<f64> { a.iter().zip(b.iter()).map(|(x,y)| x-y).collect() }

fn fuse_vec(values: &[Vec<f64>], weights: &[f64], trim_frac: f64) -> Vec<f64> {
    let d = values[0].len();
    let mut out = vec![0.0; d];
    for k in 0..d {
        let mut pairs: Vec<(f64,f64)> = values.iter().zip(weights.iter()).map(|(v,w)| (v[k], *w)).collect();
        pairs.sort_by(|a,b| a.0.partial_cmp(&b.0).unwrap());
        let n = pairs.len();
        let t = ((n as f64)*trim_frac).floor() as usize;
        let core = if n > 2*t { &pairs[t..(n-t)] } else { &pairs[..] };
        let wsum: f64 = core.iter().map(|(_,w)| *w).sum();
        out[k] = if wsum > 0.0 {
            core.iter().map(|(v,w)| v*w).sum::<f64>() / wsum
        } else {
            core.iter().map(|(v,_)| *v).sum::<f64>() / (core.len().max(1) as f64)
        };
    }
    out
}

fn main() {
    let mut rng = StdRng::seed_from_u64(SEED);

    let n: usize = 30;
    let d: usize = 4;

    // directed weights w_out[i][j]
    // BTreeMap, not HashMap: its iteration order is deterministic (ascending
    // by key) regardless of the process's random hash seed, whereas
    // HashMap's is not - and w_out is iterated inside a floating-point
    // sum/sort that feeds back into itself every step, so a random
    // iteration order alone was enough to make runs unreproducible even
    // with a fixed RNG seed.
    let mut w_out: Vec<std::collections::BTreeMap<usize, f64>> =
        vec![std::collections::BTreeMap::new(); n];

    for i in 0..n {
        for (step, w0) in [(1usize, 1.0f64), (2usize, 0.8f64)] {
            let j = (i + step) % n;
            w_out[i].insert(j, w0);
            w_out[j].insert(i, w0 * rng.gen_range(0.8..1.2));
        }
    }
    for _ in 0..(n*2) {
        let a = rng.gen_range(0..n);
        let b = rng.gen_range(0..n);
        if a != b {
            w_out[a].insert(b, rng.gen_range(0.2..0.8));
        }
    }

    // state
    let mut x_vec: Vec<Vec<f64>> = vec![vec![0.0; d]; n];
    let mut obs_vec: Vec<Vec<f64>> = vec![vec![0.0; d]; n];
    let mut sigma: Vec<f64> = vec![0.0; n];
    let mut clarified: Vec<bool> = vec![false; n];

    // potentials Φ
    let mut phi: Vec<f64> = (0..n).map(|i| (i as f64)/(n as f64 - 1.0) * 10.0).collect();

    // truth
    let mut truth: Vec<f64> = vec![0.0; d];
    let drift: f64 = 0.02;
    let shock_prob: f64 = 0.05;
    let shock_mag: f64 = 1.8;

    // thresholds
    let tau_normal: f64 = 0.9;
    let tau_fast: f64 = 0.65;
    let epsilon_align: f64 = 0.45;
    let delta_explode: f64 = 0.55;
    let fast_cycles: u64 = 12;
    let complete_cycles: u64 = 10;

    // learning
    let alpha_edge: f64 = 1.2;
    let w_floor: f64 = 0.02;
    let w_ceil: f64 = 3.0;

    // flows
    let flow_rate: f64 = 0.12;

    let mut t: u64 = 0;
    let mut fast_sync_remaining: u64 = 0;
    let mut complete_streak: u64 = 0;

    telemetry::print_header();

    loop {
        t += 1;

        // env
        for k in 0..d { truth[k] += drift; }
        if rng.gen::<f64>() < shock_prob {
            let k = rng.gen_range(0..d);
            truth[k] += if rng.gen::<bool>() { shock_mag } else { -shock_mag };
        }

        // observe
        for i in 0..n {
            let noise = match i % 6 { 0=>0.12, 1=>0.18, 2=>0.28, 3=>0.40, 4=>0.65, _=>0.95 };
            sigma[i] = noise;
            let bias = if i % 11 == 0 { 0.05 } else { 0.0 };

            let mut ov = vec![0.0; d];
            for k in 0..d {
                let eps: f64 = rng.sample::<f64, _>(StandardNormal) * noise;
                ov[k] = truth[k] + bias + eps;
            }
            obs_vec[i] = ov;
        }

        // local refs + shares
        let mut refs: Vec<Vec<f64>> = vec![vec![0.0; d]; n];
        let mut shares: Vec<Vec<(usize,f64)>> = vec![vec![]; n];

        for i in 0..n {
            let mut vals: Vec<Vec<f64>> = vec![obs_vec[i].clone()];
            let mut ws: Vec<f64> = vec![1.0];

            let mut neigh: Vec<(usize,f64)> = vec![];
            let mut sumw = 0.0;

            for (&j, &wij) in w_out[i].iter() {
                if wij <= 0.0 { continue; }
                let wcl = clamp(wij, 0.0, 5.0);
                vals.push(x_vec[j].clone());
                ws.push(wcl);
                neigh.push((j, wcl));
                sumw += wcl;
            }

            refs[i] = fuse_vec(&vals, &ws, 0.15);
            if sumw > 0.0 {
                shares[i] = neigh.into_iter().map(|(j,wc)| (j, wc/sumw)).collect();
            }
        }

        // lock
        let tau = if fast_sync_remaining > 0 { tau_fast } else { tau_normal };
        let mut clarified_count = 0usize;

        for i in 0..n {
            if !invariants::clarity_gate(sigma[i], tau) {
                clarified[i] = true;
                clarified_count += 1;
                continue;
            }
            clarified[i] = false;
            let self_w = clamp(1.0 / sigma[i].max(1e-9), 0.5, 5.0);
            for k in 0..d {
                x_vec[i][k] = (self_w * obs_vec[i][k] + 1.0 * refs[i][k]) / (self_w + 1.0);
            }
        }

        // Δe learning on outgoing edges
        for i in 0..n {
            if clarified[i] {
                let keys: Vec<usize> = w_out[i].keys().cloned().collect();
                for j in keys {
                    let wij = w_out[i].get(&j).cloned().unwrap_or(0.0);
                    w_out[i].insert(j, clamp(wij*0.995, w_floor, w_ceil));
                }
                continue;
            }

            let e_self = l2(&v_sub(&obs_vec[i], &truth));
            let e_fused = l2(&v_sub(&x_vec[i], &truth));
            let delta_e = e_self - e_fused;

            for (j, share) in shares[i].iter().cloned() {
                let wij = w_out[i].get(&j).cloned().unwrap_or(0.0);
                let wij_new = wij * (alpha_edge * share * delta_e).exp();
                w_out[i].insert(j, clamp(wij_new, w_floor, w_ceil));
            }
        }

        // flows
        let snapshot = w_out.clone();
        for i in 0..n {
            for (j, wij) in snapshot[i].iter() {
                if *wij <= 0.0 { continue; }
                let grad = phi[i] - phi[*j];
                let flow = flow_rate * (*wij) * grad;
                phi[i] -= flow;
                phi[*j] += flow;
            }
        }

        // disagreement
        let mut ds: Vec<f64> = vec![];
        for i in 0..n {
            if clarified[i] { continue; }
            ds.push(l2(&v_sub(&x_vec[i], &refs[i])));
        }
        let dval = if ds.is_empty() { f64::INFINITY } else { ds.iter().sum::<f64>() / (ds.len() as f64) };

        // phase
        if fast_sync_remaining == 0 && dval < delta_explode {
            fast_sync_remaining = fast_cycles;
        }
        if fast_sync_remaining > 0 { fast_sync_remaining -= 1; }

        // completion
        let all_ok = (0..n).all(|i| !clarified[i] && l2(&v_sub(&x_vec[i], &refs[i])) <= epsilon_align);
        if all_ok { complete_streak += 1; } else { complete_streak = 0; }
        let done = complete_streak >= complete_cycles;

        // mean edge weight for telemetry
        let mut sumw = 0.0;
        let mut cnt = 0usize;
        for i in 0..n {
            for (_, wij) in w_out[i].iter() { sumw += *wij; cnt += 1; }
        }
        let mean_w = if cnt == 0 { 0.0 } else { sumw / (cnt as f64) };

        let row = TelemetryRow {
            t,
            truth: l2(&truth),
            r_star: dval,
            disagreement: dval,
            clarified: clarified_count,
            mean_reliability: mean_w,
            fast_sync_remaining,
            complete_streak,
            done,
        };

        if t % 5 == 0 || done {
            telemetry::print_row(&row);
        }

        if done {
            println!("\n✅ COMPLETE: directed trust alignment achieved (sustained).");
            break;
        }
        if t >= 400 {
            println!("\nℹ️  Not completed within step budget (normal under shocks/noise).");
            break;
        }
    }
}
