use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

/// Fixed by default so a run can be reproduced exactly; not yet exposed
/// as a CLI flag.
const SEED: u64 = 42;
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

fn parse_args() -> (u64, String) {
    let mut steps: u64 = 600;
    let mut out = "../telemetry/telemetry.jsonl".to_string();
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--steps" => { i += 1; steps = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(steps); }
            "--out" => { i += 1; out = args.get(i).cloned().unwrap_or(out); }
            _ => {}
        }
        i += 1;
    }
    (steps, out)
}

fn main() -> io::Result<()> {
    let (steps, out_path) = parse_args();

    if let Some(parent) = std::path::Path::new(&out_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = File::create(&out_path)?;

    let mut rng = StdRng::seed_from_u64(SEED);
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

    // chain
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
    blocks.insert(genesis.hash.clone(), genesis.clone());
    let mut head = genesis.hash.clone();

    // fork + reconcile tracking
    let fork_prob: f64 = 0.10;
    let mut forks: u64 = 0;
    let mut reconciles_count: u64 = 0;
    let mut height_candidates: HashMap<u64, Vec<String>> = HashMap::new();

    for t in 1..=steps {
        // epoch rotation
        let epoch = (t / epoch_len) as u64;
        if epoch != current_epoch {
            current_epoch = epoch;
            regen_keys(&mut rng, current_epoch, n, &mut signing, &mut verify);
        }

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
            let e_self = l2(&v_sub(&obs_vec[i], &truth));
            let e_fused = l2(&v_sub(&x_vec[i], &truth));
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
        if fast_sync_remaining > 0 { fast_sync_remaining -= 1; }

        // completion
        let all_ok = (0..n).all(|i| !clarified[i] && l2(&v_sub(&x_vec[i], &refs[i])) <= epsilon_align);
        if all_ok { complete_streak += 1; } else { complete_streak = 0; }
        let done = complete_streak >= complete_cycles;

        // propose blocks (forks)
        let proposals = if rng.gen::<f64>() < fork_prob { forks += 1; 2 } else { 1 };
        let mut created: Vec<String> = vec![];

        for _ in 0..proposals {
            // candidate state = mean x_vec
            let mut cand = vec![0.0; d];
            for i in 0..n { for k in 0..d { cand[k] += x_vec[i][k]; } }
            for k in 0..d { cand[k] /= n as f64; }

            // confidence
            let mut var = 0.0;
            for i in 0..n {
                let diff = v_sub(&x_vec[i], &cand);
                var += l2(&diff).powi(2);
            }
            var /= n as f64;
            let conf = 1.0 / (1.0 + var);

            // Canonical string
            let st_hash = hash_vec(&cand);
            let rec_hash = hash_list(&[]);
            let canon = canon_string(head_block.height + 1, &head, &st_hash, conf, &rec_hash, epoch);

            // signers
            let e_head = l2(&v_sub(&head_block.state, &truth));
            let e_cand = l2(&v_sub(&cand, &truth));

            let mut sigs: Vec<SigEntry> = vec![];
            let mut sigw = 0.0;

            for i in 0..n {
                let will_sign = if e_cand <= e_head { true } else { rel[i] >= 1.2 && (i % 2 == 0) };
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
                height: head_block.height + 1,
                parent: head.clone(),
                state: cand,
                confidence: conf,
                reconciles: vec![],
                epoch,
                signatures: sigs,
                sig_weight: verified_w,
                hash: bh.clone(),
            };

            blocks.insert(b.hash.clone(), b.clone());
            created.push(b.hash.clone());

            let cur = blocks.get(&head).unwrap().clone();
            if prefer(&cur, &b) { head = b.hash.clone(); }
        }

        let hh = blocks.get(&head).unwrap().height;
        if !created.is_empty() {
            let entry = height_candidates.entry(hh).or_insert_with(Vec::new);
            for x in created {
                if !entry.contains(&x) { entry.push(x); }
            }
        }

        // reconcile forks with heavier signatures
        if let Some(cands) = height_candidates.get(&hh).cloned() {
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
                        let cur = blocks.get(&head).unwrap().clone();
                        if prefer(&cur, &rb) { head = rb.hash.clone(); }
                        height_candidates.insert(hh, vec![head.clone()]);
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
        println!("{line}");
        writeln!(file, "{line}")?;

        if done { break; }
    }

    Ok(())
}
