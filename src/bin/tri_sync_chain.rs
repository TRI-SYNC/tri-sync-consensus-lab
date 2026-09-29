use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

/// Fixed by default so a run can be reproduced exactly; not yet exposed
/// as a CLI flag.
const SEED: u64 = 42;

/// Nodes that report a deliberate, consistent lie instead of an honest
/// noisy reading - conflicting data, not a Sybil cluster or an
/// equivocating signer. 6 of 30 = 20% of the network, avoiding the
/// indices that already get the small honest observation bias below.
const MALICIOUS_NODES: [usize; 6] = [3, 8, 13, 18, 23, 28];
/// The fixed offset a malicious node reports instead of the truth.
const LIE_BIAS: f64 = 3.0;
/// Malicious nodes get the network's lowest noise bucket, so
/// `invariants::clarity_gate` never treats them as suspiciously noisy -
/// only the trust-weighting mechanism can catch them.
const MALICIOUS_SIGMA: f64 = 0.12;
use rand_distr::StandardNormal;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{self, Write};

use tri_sync::invariants;
use tri_sync::types::TelemetryRow;

fn clamp(x: f64, lo: f64, hi: f64) -> f64 { x.max(lo).min(hi) }
fn l2(v: &[f64]) -> f64 { v.iter().map(|x| x*x).sum::<f64>().sqrt() }
fn v_sub(a: &[f64], b: &[f64]) -> Vec<f64> { a.iter().zip(b.iter()).map(|(x,y)| x-y).collect() }

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Block {
    height: u64,
    parent: String,
    state: Vec<f64>,
    confidence: f64,
    sig_weight: f64,
    hash: String,
}

fn hash_block(height: u64, parent: &str, state: &[f64], confidence: f64, sig_weight: f64) -> String {
    let payload = format!("{height}|{parent}|{:?}|{confidence:.6}|{sig_weight:.3}", state);
    let digest = sha256::digest(payload);
    digest[..16].to_string()
}

// tiny sha256 helper (no external dep)
mod sha256 {
    use sha2::{Digest, Sha256};
    pub fn digest(s: String) -> String {
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        let out = hasher.finalize();
        hex::encode(out)
    }
}

fn choose_head(a: &Block, b: &Block) -> bool {
    // return true if b is preferred over a
    if b.height != a.height { return b.height > a.height; }
    if (b.sig_weight - a.sig_weight).abs() > f64::EPSILON { return b.sig_weight > a.sig_weight; }
    if (b.confidence - a.confidence).abs() > f64::EPSILON { return b.confidence > a.confidence; }
    false
}

fn parse_args() -> (u64, String, String) {
    let mut steps: u64 = 400;
    let mut out = "../telemetry/telemetry.jsonl".to_string();
    let mut chain_log = "../telemetry/tri_sync_chain.blocks.jsonl".to_string();
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--steps" => { i += 1; steps = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(steps); }
            "--out" => { i += 1; out = args.get(i).cloned().unwrap_or(out); }
            "--chain-log" => { i += 1; chain_log = args.get(i).cloned().unwrap_or(chain_log); }
            _ => {}
        }
        i += 1;
    }
    (steps, out, chain_log)
}

/// Loads a persisted chain log (one JSON `Block` per line) into `blocks`,
/// replaying the same `choose_head` comparisons that were applied when
/// each block was originally created, in the same order, so the
/// resulting head is exactly what it would have been had the process
/// never stopped. Starts from `genesis` and returns the resulting head.
/// A line that fails to parse is treated as a corrupt log, not silently
/// skipped - the same posture as the rest of this crate takes toward
/// tampered or truncated state.
fn load_chain_log(
    path: &str,
    genesis: &Block,
    blocks: &mut HashMap<String, Block>,
) -> io::Result<String> {
    blocks.insert(genesis.hash.clone(), genesis.clone());
    let mut head = genesis.hash.clone();
    let Ok(contents) = std::fs::read_to_string(path) else {
        return Ok(head);
    };
    for (line_no, line) in contents.lines().enumerate() {
        if line.trim().is_empty() { continue; }
        let b: Block = serde_json::from_str(line).map_err(|e| {
            io::Error::other(format!("{path}:{}: corrupt chain log line: {e}", line_no + 1))
        })?;
        let cur = blocks.get(&head).unwrap().clone();
        if choose_head(&cur, &b) { head = b.hash.clone(); }
        blocks.insert(b.hash.clone(), b);
    }
    Ok(head)
}

fn main() -> io::Result<()> {
    // Dependencies used in this bin:
    // sha2 + hex are required; see Cargo.toml update.
    let (steps, out_path, chain_log_path) = parse_args();

    // Ensure output dir exists
    if let Some(parent) = std::path::Path::new(&out_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = std::path::Path::new(&chain_log_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = File::create(&out_path)?;

    let mut rng = StdRng::seed_from_u64(SEED);
    let n: usize = 30;
    let d: usize = 4;

    // Directed weights w_out[i][j]
    // BTreeMap, not HashMap: deterministic iteration order regardless of
    // the process's random hash seed. w_out is iterated inside a
    // floating-point sum/sort that feeds back into itself every step, so a
    // random iteration order alone made runs unreproducible even with a
    // fixed RNG seed.
    let mut w_out: Vec<BTreeMap<usize, f64>> = vec![BTreeMap::new(); n];
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

    // State
    let mut x_vec: Vec<Vec<f64>> = vec![vec![0.0; d]; n];
    let mut obs_vec: Vec<Vec<f64>> = vec![vec![0.0; d]; n];
    let mut sigma: Vec<f64> = vec![0.0; n];
    let mut clarified: Vec<bool> = vec![false; n];

    // Truth
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

    let mut fast_sync_remaining: u64 = 0;
    let mut complete_streak: u64 = 0;

    // R* chain store: replayed from chain_log_path if it already holds a
    // previous run's blocks, so the ledger actually persists across
    // process exits instead of always starting fresh from genesis.
    let mut blocks: HashMap<String, Block> = HashMap::new();
    let genesis = Block {
        height: 0,
        parent: "".to_string(),
        state: vec![0.0; d],
        confidence: 1.0,
        sig_weight: 999.0,
        hash: "GENESIS".to_string(),
    };
    let mut head = load_chain_log(&chain_log_path, &genesis, &mut blocks)?;
    let loaded_blocks = blocks.len() - 1; // exclude genesis
    if loaded_blocks > 0 {
        eprintln!(
            "resumed from {chain_log_path}: {loaded_blocks} blocks, head height {}",
            blocks.get(&head).unwrap().height
        );
    }
    let mut chain_log = std::fs::OpenOptions::new().create(true).append(true).open(&chain_log_path)?;
    let quorum: f64 = 10.0;
    let fork_prob: f64 = 0.08;
    let mut forks: u64 = 0;

    // Print and write NDJSON telemetry
    for t in 1..=steps {
        // env
        for k in 0..d { truth[k] += drift; }
        if rng.gen::<f64>() < shock_prob {
            let k = rng.gen_range(0..d);
            truth[k] += if rng.gen::<bool>() { shock_mag } else { -shock_mag };
        }

        // observe
        for i in 0..n {
            let is_malicious = MALICIOUS_NODES.contains(&i);
            let noise = if is_malicious {
                MALICIOUS_SIGMA
            } else {
                match i % 6 { 0=>0.12, 1=>0.18, 2=>0.28, 3=>0.40, 4=>0.65, _=>0.95 }
            };
            sigma[i] = noise;
            let bias = if i % 11 == 0 { 0.05 } else { 0.0 };
            let mut ov = vec![0.0; d];
            for k in 0..d {
                // Always draw, whether or not it's used, so the RNG
                // stream doesn't depend on which nodes are malicious.
                let eps: f64 = rng.sample::<f64, _>(StandardNormal) * noise;
                ov[k] = if is_malicious { truth[k] + LIE_BIAS } else { truth[k] + bias + eps };
            }
            obs_vec[i] = ov;
        }

        // head block
        let head_block = blocks.get(&head).unwrap().clone();

        // local refs from neighbors + head state (chain as shared reference)
        let mut refs: Vec<Vec<f64>> = vec![vec![0.0; d]; n];
        let mut shares: Vec<Vec<(usize,f64)>> = vec![vec![]; n];

        for i in 0..n {
            let mut vals: Vec<Vec<f64>> = vec![obs_vec[i].clone(), head_block.state.clone()];
            let mut ws: Vec<f64> = vec![1.0, 0.8]; // include chain reference as a stable neighbor

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

            // fuse dimension-wise
            refs[i] = {
                let d = vals[0].len();
                let mut out = vec![0.0; d];
                for kk in 0..d {
                    let mut pairs: Vec<(f64,f64)> = vals.iter().zip(ws.iter()).map(|(v,w)| (v[kk], *w)).collect();
                    pairs.sort_by(|a,b| a.0.partial_cmp(&b.0).unwrap());
                    let n2 = pairs.len();
                    let tr = ((n2 as f64)*0.15).floor() as usize;
                    let core = if n2 > 2*tr { &pairs[tr..(n2-tr)] } else { &pairs[..] };
                    let wsum: f64 = core.iter().map(|(_,w)| *w).sum();
                    out[kk] = if wsum > 0.0 { core.iter().map(|(v,w)| v*w).sum::<f64>() / wsum }
                              else { core.iter().map(|(v,_)| *v).sum::<f64>() / (core.len().max(1) as f64) };
                }
                out
            };

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

        // Δe edge learning
        for i in 0..n {
            if clarified[i] {
                let keys: Vec<usize> = w_out[i].keys().cloned().collect();
                for j in keys {
                    let wij = w_out[i].get(&j).cloned().unwrap_or(0.0);
                    w_out[i].insert(j, clamp(wij*0.995, w_floor, w_ceil));
                }
                continue;
            }
            // Against head_block.state (the chain's last agreed-upon
            // state, public to every node), not truth: no real node can
            // compare to ground truth. Comparing to refs[i] instead would
            // be circular - x_vec[i] is itself a blend toward refs[i], so
            // it would always look like an improvement by construction.
            // head_block.state is independent of this step's blend, so
            // this can genuinely go either way.
            let e_self = l2(&v_sub(&obs_vec[i], &head_block.state));
            let e_fused = l2(&v_sub(&x_vec[i], &head_block.state));
            let delta_e = e_self - e_fused;
            for (j, share) in shares[i].iter().cloned() {
                let wij = w_out[i].get(&j).cloned().unwrap_or(0.0);
                let wij_new = wij * (alpha_edge * share * delta_e).exp();
                w_out[i].insert(j, clamp(wij_new, w_floor, w_ceil));
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

        // propose 1-2 candidate blocks extending head (simulate forks)
        let proposals = if rng.gen::<f64>() < fork_prob { forks += 1; 2 } else { 1 };
        for _ in 0..proposals {
            // candidate state = mean of x_vec
            let mut cand = vec![0.0; d];
            for i in 0..n {
                for k in 0..d { cand[k] += x_vec[i][k]; }
            }
            for k in 0..d { cand[k] /= n as f64; }

            // confidence ~ inverse variance
            let mut var = 0.0;
            for i in 0..n {
                let diff = v_sub(&x_vec[i], &cand);
                var += l2(&diff).powi(2);
            }
            var /= n as f64;
            let conf = 1.0 / (1.0 + var);

            // Each node signs based on its OWN locked estimate x_vec[i],
            // not ground truth: does the candidate look closer to what
            // this node itself believes than the current head does. This
            // used to compare head_block.state and cand against truth
            // directly - identical for every node, so despite the loop
            // over i, every node reached the same yes/no answer and sigw
            // was always either 0.0 or exactly n.
            let mut sigw = 0.0;
            for x_i in &x_vec {
                let e_head_i = l2(&v_sub(&head_block.state, x_i));
                let e_cand_i = l2(&v_sub(&cand, x_i));
                if e_cand_i <= e_head_i { sigw += 1.0; }
            }

            if sigw >= quorum {
                let parent = head.clone();
                let height = blocks.get(&head).unwrap().height + 1;
                let hash = hash_block(height, &parent, &cand, conf, sigw);
                let b = Block { height, parent: parent.clone(), state: cand, confidence: conf, sig_weight: sigw, hash: hash.clone() };
                blocks.insert(hash.clone(), b.clone());
                writeln!(chain_log, "{}", serde_json::to_string(&b).unwrap())?;
                chain_log.flush()?;
                // fork choice
                let cur = blocks.get(&head).unwrap().clone();
                if choose_head(&cur, &b) { head = hash; }
            }
        }

        // mean edge weight
        let mut sumw = 0.0;
        let mut cnt = 0usize;
        for i in 0..n {
            for (_, wij) in w_out[i].iter() { sumw += *wij; cnt += 1; }
        }
        let mean_w = if cnt == 0 { 0.0 } else { sumw / (cnt as f64) };

        let head_h = blocks.get(&head).unwrap().height;

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

        // extend row with chain fields via a wrapper map
        let out_obj = serde_json::json!({
            "telemetry": row,
            "chain": { "head_height": head_h, "forks": forks, "head": head }
        });

        let line = serde_json::to_string(&out_obj).unwrap();
        println!("{line}");
        writeln!(file, "{line}")?;

        if done { break; }
    }

    println!("\n--- adversarial summary ---");
    let final_state = &blocks.get(&head).unwrap().state;
    println!("|head.state - truth| = {:.4}", l2(&v_sub(final_state, &truth)));

    let mean = |v: &[f64]| if v.is_empty() { 0.0 } else { v.iter().sum::<f64>() / v.len() as f64 };
    let incoming = |m: usize| -> Vec<f64> { w_out.iter().filter_map(|wi| wi.get(&m).copied()).collect() };
    let honest_incoming: Vec<f64> = (0..n).filter(|i| !MALICIOUS_NODES.contains(i)).flat_map(incoming).collect();
    let malicious_incoming: Vec<f64> = MALICIOUS_NODES.iter().copied().flat_map(incoming).collect();
    println!(
        "mean incoming trust weight: honest={:.4} (n={})  malicious={:.4} (n={})",
        mean(&honest_incoming), honest_incoming.len(),
        mean(&malicious_incoming), malicious_incoming.len()
    );

    Ok(())
}
