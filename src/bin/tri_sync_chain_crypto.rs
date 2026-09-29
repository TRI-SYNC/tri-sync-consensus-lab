// This sim correlates several same-length Vecs (nodes, x_vec, w_out, ...)
// by a shared `i`/`k` index throughout; the same explicit-index style is
// used even in loops that happen to touch only one Vec, for consistency
// with neighboring loops in the same function that touch several.
#![allow(clippy::needless_range_loop)]

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

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use sha2::{Digest, Sha256};

fn clamp(x: f64, lo: f64, hi: f64) -> f64 { x.max(lo).min(hi) }
fn l2(v: &[f64]) -> f64 { v.iter().map(|x| x*x).sum::<f64>().sqrt() }
fn v_sub(a: &[f64], b: &[f64]) -> Vec<f64> { a.iter().zip(b.iter()).map(|(x,y)| x-y).collect() }

fn hex16(bytes: &[u8]) -> String {
    let h = hex::encode(bytes);
    h[..16].to_string()
}

fn hash_vec(v: &[f64]) -> String {
    let mut hasher = Sha256::new();
    for x in v {
        hasher.update(format!("{x:.8}").as_bytes());
        hasher.update(b",");
    }
    hex16(&hasher.finalize())
}

fn hash_list(xs: &[String]) -> String {
    let mut hasher = Sha256::new();
    for s in xs {
        hasher.update(s.as_bytes());
        hasher.update(b"|");
    }
    hex16(&hasher.finalize())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SigEntry {
    node_id: usize,
    pubkey_hex: String,
    sig_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Block {
    height: u64,
    parent: String,
    state: Vec<f64>,
    confidence: f64,
    reconciles: Vec<String>,
    epoch: u64,
    signatures: Vec<SigEntry>,
    sig_weight: f64,
    hash: String,
}

fn canon_string(height: u64, parent: &str, state_hash: &str, confidence: f64, reconciles_hash: &str, epoch: u64) -> String {
    format!("{height}|{parent}|{state_hash}|{confidence:.8}|{reconciles_hash}|{epoch}")
}

fn block_hash(canon: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canon.as_bytes());
    hex16(&hasher.finalize())
}

fn prefer(a: &Block, b: &Block) -> bool {
    if b.height != a.height { return b.height > a.height; }
    if (b.sig_weight - a.sig_weight).abs() > f64::EPSILON { return b.sig_weight > a.sig_weight; }
    if (b.confidence - a.confidence).abs() > f64::EPSILON { return b.confidence > a.confidence; }
    false
}

/// Regenerates the node key registry for `epoch`, replacing `signing`/`verify` in place.
fn regen_keys(
    rng: &mut (impl Rng + rand::CryptoRng),
    epoch: u64,
    n: usize,
    signing: &mut Vec<SigningKey>,
    verify: &mut Vec<VerifyingKey>,
) {
    signing.clear();
    verify.clear();
    // consume RNG proportional to epoch (sim-only determinism hint)
    for _ in 0..(epoch as usize * 3).min(30) { let _: u64 = rng.gen(); }
    for _i in 0..n {
        let sk = SigningKey::generate(rng);
        let vk = sk.verifying_key();
        signing.push(sk);
        verify.push(vk);
    }
}

fn parse_args() -> (u64, String, String) {
    let mut steps: u64 = 600;
    let mut out = "../telemetry/telemetry.jsonl".to_string();
    let mut chain_log = "../telemetry/tri_sync_chain_crypto.blocks.jsonl".to_string();
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
/// replaying the same `prefer` comparisons that were applied when each
/// block was originally created, in the same order, so the resulting
/// head is exactly what it would have been had the process never
/// stopped. Starts from `genesis` and returns the resulting head. A line
/// that fails to parse is treated as a corrupt log, not silently skipped,
/// the same posture as the rest of this crate takes toward tampered or
/// truncated state.
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
        if prefer(&cur, &b) { head = b.hash.clone(); }
        blocks.insert(b.hash.clone(), b);
    }
    Ok(head)
}

/// Final state of a run, returned by `simulate` so both `main` (for the
/// printed adversarial summary) and tests can inspect it directly instead
/// of scraping stdout or the output files.
struct Outcome {
    truth: Vec<f64>,
    head_state: Vec<f64>,
    head_height: u64,
    #[allow(dead_code)] // only read by the persistence-resume test
    loaded_blocks: usize,
    w_out: Vec<BTreeMap<usize, f64>>,
    #[allow(dead_code)] // only read by the fork/reconcile structural-invariant tests
    blocks: HashMap<String, Block>,
    forks: u64,
    reconciles: u64,
    // The actual verifying-key registry used for each epoch during this
    // run, snapshotted as `regen_keys` was called for it. `regen_keys`
    // draws from the same shared RNG the rest of the simulation does, so
    // there's no way to reconstruct an old epoch's registry after the
    // fact by calling it again in isolation - the RNG has moved on.
    #[allow(dead_code)] // only read by the signature-verification test
    epoch_registries: HashMap<u64, Vec<VerifyingKey>>,
}

fn simulate(seed: u64, steps: u64, out_path: &str, chain_log_path: &str, verbose: bool) -> io::Result<Outcome> {
    if let Some(parent) = std::path::Path::new(out_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = std::path::Path::new(chain_log_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = File::create(out_path)?;

    let mut rng = StdRng::seed_from_u64(seed);
    let n: usize = 30;
    let d: usize = 4;

    // reliability weights
    let rel: Vec<f64> = (0..n).map(|i| match i % 6 { 0=>0.6, 1=>0.8, 2=>1.0, 3=>1.2, 4=>1.6, _=>2.0 }).collect();
    let rel_sum: f64 = rel.iter().sum();
    let quorum_w: f64 = rel_sum * 0.55;

    // Key rotation epochs
    let epoch_len: u64 = 200;

    // Node key registry for current epoch
    let mut signing: Vec<SigningKey> = vec![];
    let mut verify: Vec<VerifyingKey> = vec![];
    let mut current_epoch: u64 = 0;

    regen_keys(&mut rng, current_epoch, n, &mut signing, &mut verify);
    let mut epoch_registries: HashMap<u64, Vec<VerifyingKey>> = HashMap::new();
    epoch_registries.insert(current_epoch, verify.clone());

    // directed trust edges
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

    // state
    let mut x_vec: Vec<Vec<f64>> = vec![vec![0.0; d]; n];
    let mut obs_vec: Vec<Vec<f64>> = vec![vec![0.0; d]; n];
    let mut sigma: Vec<f64> = vec![0.0; n];
    let mut clarified: Vec<bool> = vec![false; n];

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

    let mut fast_sync_remaining: u64 = 0;
    let mut complete_streak: u64 = 0;

    // chain: replayed from chain_log_path if it already holds a previous
    // run's blocks, so the ledger actually persists across process exits
    // instead of always starting fresh from genesis.
    let mut blocks: HashMap<String, Block> = HashMap::new();
    let genesis = Block {
        height: 0,
        parent: "".into(),
        state: vec![0.0; d],
        confidence: 1.0,
        reconciles: vec![],
        epoch: 0,
        signatures: vec![],
        sig_weight: 999.0,
        hash: "GENESIS".into(),
    };
    let mut head = load_chain_log(chain_log_path, &genesis, &mut blocks)?;
    let loaded_blocks = blocks.len() - 1; // exclude genesis
    if loaded_blocks > 0 && verbose {
        eprintln!(
            "resumed from {chain_log_path}: {loaded_blocks} blocks, head height {}",
            blocks.get(&head).unwrap().height
        );
    }
    let mut chain_log = std::fs::OpenOptions::new().create(true).append(true).open(chain_log_path)?;

    // fork + reconcile tracking
    let fork_prob: f64 = 0.10;
    let mut forks: u64 = 0;
    let mut reconciles_count: u64 = 0;
    let mut height_candidates: HashMap<u64, Vec<String>> = HashMap::new();

    for t in 1..=steps {
        // epoch rotation
        let epoch = t / epoch_len;
        if epoch != current_epoch {
            current_epoch = epoch;
            regen_keys(&mut rng, current_epoch, n, &mut signing, &mut verify);
            epoch_registries.insert(current_epoch, verify.clone());
        }

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

        let head_block = blocks.get(&head).unwrap().clone();

        // local refs + shares
        let mut refs: Vec<Vec<f64>> = vec![vec![0.0; d]; n];
        let mut shares: Vec<Vec<(usize,f64)>> = vec![vec![]; n];

        for i in 0..n {
            let mut vals: Vec<Vec<f64>> = vec![obs_vec[i].clone(), head_block.state.clone()];
            let mut ws: Vec<f64> = vec![1.0, 0.8];

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

            // fuse dimension-wise with trimming
            refs[i] = {
                let dd = vals[0].len();
                let mut out = vec![0.0; dd];
                for kk in 0..dd {
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
        if fast_sync_remaining == 0 && dval < delta_explode { fast_sync_remaining = fast_cycles; }
        fast_sync_remaining = fast_sync_remaining.saturating_sub(1);

        // completion
        let all_ok = (0..n).all(|i| !clarified[i] && l2(&v_sub(&x_vec[i], &refs[i])) <= epsilon_align);
        if all_ok { complete_streak += 1; } else { complete_streak = 0; }
        let done = complete_streak >= complete_cycles;

        // propose blocks (forks): every proposal this step extends the
        // SAME parent at the SAME height, so a fork_prob step can produce
        // two true siblings instead of one candidate silently building on
        // top of the other. The winner is chosen once, after every
        // proposal for this step exists, not by racing head forward
        // after each one - racing forward is what let the second
        // proposal end up parented on the first.
        let proposals = if rng.gen::<f64>() < fork_prob { forks += 1; 2 } else { 1 };
        let candidate_height = head_block.height + 1;
        let mut created: Vec<Block> = vec![];

        for _ in 0..proposals {
            // Each proposer sees only a random subset of the network's
            // current x_vec, modeling asynchronous/partitioned
            // visibility - without this, cand (and everything derived
            // from it) is a deterministic function of x_vec alone, so two
            // proposals in the same fork step were always byte-identical
            // and reconciliation could never actually fire.
            let contributors: Vec<usize> = (0..n).filter(|_| rng.gen::<f64>() < 0.85).collect();
            let contributors: Vec<usize> =
                if contributors.is_empty() { (0..n).collect() } else { contributors };

            let mut cand = vec![0.0; d];
            for &i in &contributors { for k in 0..d { cand[k] += x_vec[i][k]; } }
            for k in 0..d { cand[k] /= contributors.len() as f64; }

            // confidence
            let mut var = 0.0;
            for &i in &contributors {
                let diff = v_sub(&x_vec[i], &cand);
                var += l2(&diff).powi(2);
            }
            var /= contributors.len() as f64;
            let conf = 1.0 / (1.0 + var);

            // Canonical string
            let st_hash = hash_vec(&cand);
            let rec_hash = hash_list(&[]);
            let canon = canon_string(candidate_height, &head_block.hash, &st_hash, conf, &rec_hash, epoch);

            // Each node decides whether to sign based on its OWN locked
            // estimate x_vec[i], not ground truth: does the candidate
            // look closer to what this node itself believes than the
            // current head does. Replaces the old rule, which compared
            // head_block.state and cand against truth directly - the same
            // yes/no answer for every node - with an arbitrary partial
            // fallback (rel[i] >= 1.2 && i % 2 == 0) for when that global
            // answer was no.
            let mut sigs: Vec<SigEntry> = vec![];
            let mut sigw = 0.0;

            for i in 0..n {
                let e_head_i = l2(&v_sub(&head_block.state, &x_vec[i]));
                let e_cand_i = l2(&v_sub(&cand, &x_vec[i]));
                let will_sign = e_cand_i <= e_head_i;
                if will_sign {
                    let sig: Signature = signing[i].sign(canon.as_bytes());
                    // sanity verify
                    verify[i].verify(canon.as_bytes(), &sig).unwrap();

                    sigs.push(SigEntry {
                        node_id: i,
                        pubkey_hex: hex::encode(verify[i].to_bytes()),
                        sig_hex: hex::encode(sig.to_bytes()),
                    });
                    sigw += rel[i];
                }
            }
            if sigw < quorum_w { continue; }

            let bh = block_hash(&canon);

            // verify signatures against registry for this epoch
            let mut verified_w = 0.0;
            for s in &sigs {
                if s.node_id >= n { continue; }
                let pk_bytes = match hex::decode(&s.pubkey_hex) { Ok(b) => b, Err(_) => continue };
                let pk_arr: [u8; 32] = match pk_bytes.try_into() { Ok(a) => a, Err(_) => continue };
                let vk = match VerifyingKey::from_bytes(&pk_arr) { Ok(v) => v, Err(_) => continue };
                if vk.to_bytes() != verify[s.node_id].to_bytes() { continue; }

                let sig_bytes = match hex::decode(&s.sig_hex) { Ok(b) => b, Err(_) => continue };
                let sig_arr: [u8; 64] = match sig_bytes.try_into() { Ok(a) => a, Err(_) => continue };
                let sig = Signature::from_bytes(&sig_arr);

                if vk.verify(canon.as_bytes(), &sig).is_ok() {
                    verified_w += rel[s.node_id];
                }
            }
            if verified_w < quorum_w { continue; }

            let b = Block {
                height: candidate_height,
                parent: head_block.hash.clone(),
                state: cand,
                confidence: conf,
                reconciles: vec![],
                epoch,
                signatures: sigs,
                sig_weight: verified_w,
                hash: bh.clone(),
            };

            blocks.insert(b.hash.clone(), b.clone());
            writeln!(chain_log, "{}", serde_json::to_string(&b).unwrap())?;
            chain_log.flush()?;
            created.push(b);
        }

        if !created.is_empty() {
            let mut best = head_block.clone();
            for b in &created {
                if prefer(&best, b) { best = b.clone(); }
            }
            head = best.hash.clone();

            let entry = height_candidates.entry(candidate_height).or_default();
            for b in &created {
                if !entry.contains(&b.hash) { entry.push(b.hash.clone()); }
            }
        }

        // reconcile forks with heavier signatures
        if let Some(cands) = height_candidates.get(&candidate_height).cloned() {
            if cands.len() >= 2 {
                let others: Vec<String> = cands.into_iter().filter(|x| x != &head).collect();
                if !others.is_empty() {
                    reconciles_count += 1;

                    let head_now = blocks.get(&head).unwrap().clone();
                    let st_hash = hash_vec(&head_now.state);
                    let rec_hash = hash_list(&others);
                    let canon = canon_string(head_now.height + 1, &head, &st_hash, head_now.confidence, &rec_hash, epoch);

                    let mut sigs: Vec<SigEntry> = vec![];
                    let mut sigw = 0.0;

                    for i in 0..n {
                        if rel[i] >= 1.0 {
                            let sig: Signature = signing[i].sign(canon.as_bytes());
                            sigs.push(SigEntry {
                                node_id: i,
                                pubkey_hex: hex::encode(verify[i].to_bytes()),
                                sig_hex: hex::encode(sig.to_bytes()),
                            });
                            sigw += rel[i];
                        }
                    }
                    if sigw >= quorum_w {
                        let bh = block_hash(&canon);
                        let rb = Block {
                            height: head_now.height + 1,
                            parent: head.clone(),
                            state: head_now.state.clone(),
                            confidence: head_now.confidence,
                            reconciles: others,
                            epoch,
                            signatures: sigs,
                            sig_weight: sigw,
                            hash: bh.clone(),
                        };
                        blocks.insert(rb.hash.clone(), rb.clone());
                        writeln!(chain_log, "{}", serde_json::to_string(&rb).unwrap())?;
                        chain_log.flush()?;
                        let cur = blocks.get(&head).unwrap().clone();
                        if prefer(&cur, &rb) { head = rb.hash.clone(); }
                        height_candidates.insert(candidate_height, vec![head.clone()]);
                    }
                }
            }
        }

        // telemetry
        let mut sumw = 0.0;
        let mut cnt = 0usize;
        for i in 0..n { for (_, wij) in w_out[i].iter() { sumw += *wij; cnt += 1; } }
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

        let out_obj = serde_json::json!({
            "telemetry": row,
            "chain": { "head_height": head_h, "forks": forks, "reconciles": reconciles_count, "head": head, "epoch": epoch }
        });

        let line = serde_json::to_string(&out_obj).unwrap();
        if verbose { println!("{line}"); }
        writeln!(file, "{line}")?;

        if done { break; }
    }

    let head_block = blocks.get(&head).unwrap().clone();
    Ok(Outcome {
        truth,
        head_state: head_block.state,
        head_height: head_block.height,
        loaded_blocks,
        w_out,
        blocks,
        forks,
        reconciles: reconciles_count,
        epoch_registries,
    })
}

fn mean(v: &[f64]) -> f64 { if v.is_empty() { 0.0 } else { v.iter().sum::<f64>() / v.len() as f64 } }

fn incoming(w_out: &[BTreeMap<usize, f64>], m: usize) -> Vec<f64> {
    w_out.iter().filter_map(|wi| wi.get(&m).copied()).collect()
}

fn print_adversarial_summary(outcome: &Outcome) {
    println!("\n--- adversarial summary ---");
    println!("final head height: {}  forks: {}  reconciles: {}", outcome.head_height, outcome.forks, outcome.reconciles);
    println!("|head.state - truth| = {:.4}", l2(&v_sub(&outcome.head_state, &outcome.truth)));

    let n = outcome.w_out.len();
    let honest_incoming: Vec<f64> = (0..n).filter(|i| !MALICIOUS_NODES.contains(i))
        .flat_map(|i| incoming(&outcome.w_out, i)).collect();
    let malicious_incoming: Vec<f64> = MALICIOUS_NODES.iter()
        .flat_map(|&i| incoming(&outcome.w_out, i)).collect();
    println!(
        "mean incoming trust weight: honest={:.4} (n={})  malicious={:.4} (n={})",
        mean(&honest_incoming), honest_incoming.len(),
        mean(&malicious_incoming), malicious_incoming.len()
    );
}

fn main() -> io::Result<()> {
    let (steps, out_path, chain_log_path) = parse_args();
    let outcome = simulate(SEED, steps, &out_path, &chain_log_path, true)?;
    print_adversarial_summary(&outcome);
    Ok(())
}

#[cfg(test)]
mod sim_tests {
    use super::*;

    fn tmp_path(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("tri_sync_chain_crypto_test_{}_{}", std::process::id(), name));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name).to_string_lossy().into_owned()
    }

    #[test]
    fn reproducible_given_the_same_seed() {
        let out = tmp_path("telemetry_a.jsonl");
        let a = simulate(SEED, 300, &out, &tmp_path("chain_a.jsonl"), false).unwrap();
        let b = simulate(SEED, 300, &out, &tmp_path("chain_b.jsonl"), false).unwrap();
        assert_eq!(a.truth, b.truth);
        assert_eq!(a.head_state, b.head_state);
        assert_eq!(a.head_height, b.head_height);
        assert_eq!(a.forks, b.forks);
        assert_eq!(a.reconciles, b.reconciles);
    }

    #[test]
    fn liars_end_up_with_lower_incoming_trust_than_honest_nodes() {
        // 300 steps was shown (manually) to briefly invert this
        // separation - this binary's step rate is bounded by ed25519
        // signing cost, so 300 steps just isn't enough samples. 600 shows
        // the expected direction clearly and reproducibly.
        let out = tmp_path("telemetry_b.jsonl");
        let outcome = simulate(SEED, 600, &out, &tmp_path("chain_c.jsonl"), false).unwrap();
        let n = outcome.w_out.len();
        let honest: Vec<f64> = (0..n).filter(|i| !MALICIOUS_NODES.contains(i))
            .flat_map(|i| incoming(&outcome.w_out, i)).collect();
        let malicious: Vec<f64> = MALICIOUS_NODES.iter()
            .flat_map(|&i| incoming(&outcome.w_out, i)).collect();
        assert!(
            mean(&malicious) < mean(&honest) - 0.1,
            "malicious={} honest={}", mean(&malicious), mean(&honest)
        );
    }

    #[test]
    fn every_block_extends_its_parent_by_exactly_one_height() {
        let out = tmp_path("telemetry_c.jsonl");
        let outcome = simulate(SEED, 300, &out, &tmp_path("chain_d.jsonl"), false).unwrap();
        for b in outcome.blocks.values() {
            if b.hash == "GENESIS" { continue; }
            let parent = outcome.blocks.get(&b.parent)
                .unwrap_or_else(|| panic!("block {} references missing parent {}", b.hash, b.parent));
            assert_eq!(
                b.height, parent.height + 1,
                "block {} has height {} but parent {} has height {}",
                b.hash, b.height, b.parent, parent.height
            );
        }
    }

    #[test]
    fn siblings_at_the_same_height_share_the_same_parent() {
        let out = tmp_path("telemetry_d.jsonl");
        let outcome = simulate(SEED, 300, &out, &tmp_path("chain_e.jsonl"), false).unwrap();
        let mut by_height: HashMap<u64, Vec<&Block>> = HashMap::new();
        for b in outcome.blocks.values() {
            if b.hash == "GENESIS" { continue; }
            by_height.entry(b.height).or_default().push(b);
        }
        for (height, group) in &by_height {
            if group.len() < 2 { continue; }
            let parent = &group[0].parent;
            for b in group {
                assert_eq!(&b.parent, parent, "two non-sibling blocks share height {height}");
            }
        }
    }

    #[test]
    fn every_signature_verifies_against_its_own_epochs_registry() {
        // A signature that only checked out against whatever `verify`
        // happened to hold at the end of the run (rather than the epoch
        // it was actually signed under) would silently pass a check
        // against just the final registry despite epoch rotation
        // invalidating old keys - this checks against the registry
        // snapshotted at the time each epoch was actually generated
        // during the run (`epoch_registries`), not a replay: `regen_keys`
        // draws from the same shared RNG as the rest of the simulation,
        // so an isolated replay of just the regen_keys calls drifts out
        // of sync with the real key material almost immediately.
        let out = tmp_path("telemetry_e.jsonl");
        let outcome = simulate(SEED, 300, &out, &tmp_path("chain_f.jsonl"), false).unwrap();
        assert!(outcome.epoch_registries.len() >= 2, "expected epoch rotation to have occurred in 300 steps");

        let mut checked = 0usize;
        for b in outcome.blocks.values() {
            if b.hash == "GENESIS" || b.signatures.is_empty() { continue; }
            let reg = outcome.epoch_registries.get(&b.epoch)
                .unwrap_or_else(|| panic!("no registry snapshot for epoch {}", b.epoch));
            for s in &b.signatures {
                let pk_bytes = hex::decode(&s.pubkey_hex).unwrap();
                let pk_arr: [u8; 32] = pk_bytes.try_into().unwrap();
                let vk = VerifyingKey::from_bytes(&pk_arr).unwrap();
                assert_eq!(vk.to_bytes(), reg[s.node_id].to_bytes(), "pubkey doesn't match epoch {} registry", b.epoch);

                let sig_bytes = hex::decode(&s.sig_hex).unwrap();
                let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
                let sig = Signature::from_bytes(&sig_arr);
                let st_hash = hash_vec(&b.state);
                let rec_hash = hash_list(&b.reconciles);
                let canon = canon_string(b.height, &b.parent, &st_hash, b.confidence, &rec_hash, b.epoch);
                assert!(vk.verify(canon.as_bytes(), &sig).is_ok(), "signature failed to verify for block {}", b.hash);
                checked += 1;
            }
        }
        assert!(checked > 0, "expected at least one signature to check");
    }

    #[test]
    fn resuming_from_a_chain_log_continues_instead_of_restarting() {
        let out = tmp_path("telemetry_f.jsonl");
        let log = tmp_path("chain_resume.jsonl");
        let first = simulate(SEED, 60, &out, &log, false).unwrap();
        assert_eq!(first.loaded_blocks, 0, "first run should start from genesis");

        let second = simulate(SEED, 60, &out, &log, false).unwrap();
        assert!(
            second.head_height > first.head_height,
            "resumed run should extend the chain, not restart it: first={} second={}",
            first.head_height, second.head_height
        );
    }

    #[test]
    fn a_corrupt_chain_log_line_is_a_hard_error_not_silently_skipped() {
        let log = tmp_path("chain_corrupt.jsonl");
        std::fs::write(&log, "not valid json at all\n").unwrap();
        let genesis = Block {
            height: 0, parent: String::new(), state: vec![0.0; 4], confidence: 1.0,
            reconciles: vec![], epoch: 0, signatures: vec![], sig_weight: 999.0, hash: "GENESIS".to_string(),
        };
        let mut blocks = HashMap::new();
        let err = load_chain_log(&log, &genesis, &mut blocks).unwrap_err();
        assert!(err.to_string().contains("corrupt chain log line"), "{err}");
    }
}
