//! The networked consensus round loop: wires `tri_sync_core`'s fusion,
//! trust, and chain logic into real QUIC message exchange between
//! peers, driven by a periodic tick plus whatever arrives from
//! [`crate::net::serve`].
//!
//! **What's simplified here, disclosed plainly rather than glossed
//! over:**
//! - There is no real sensor. Every node computes the same
//!   deterministic synthetic "truth" from the block height alone (see
//!   `synthetic_truth`) and observes it with local noise - this
//!   stage's job is proving the consensus wiring works over a real
//!   network, not sourcing real sensor data.
//! - Quorum is a plain majority vote count (`> network_size / 2`), not
//!   the original simulation's continuous trust-weighted quorum.
//! - The Δe trust update below is a real leave-one-out recomputation
//!   (how much would the fused estimate have suffered without this
//!   peer's latest observation), which is the same *spirit* as the
//!   original rule, but it's computed from each node's own
//!   asynchronously-cached view of peers' observations, not from a
//!   synchronized simulation step with shared ground truth - so two
//!   nodes' trust views of the same peer can genuinely differ, which
//!   is a feature (asymmetric directed trust) rather than a bug.
//! - Epoch rotation isn't wired in: the epoch stays fixed at whatever
//!   `NodeState::init`/`load_or_init` set it to.
//! - Peer public keys are static, from `node.toml` - there's no
//!   in-band key discovery or epoch-based re-keying across the
//!   network yet.

use crate::config::NodeConfig;
use crate::net;
use crate::persistence::{Store, TrustEntry};
use crate::protocol::{BlockProposalMsg, BlockVoteMsg, Message, ObservationMsg, TrustUpdateMsg};
use crate::state::NodeState;
use ed25519_dalek::{Signature, VerifyingKey};
use rand::SeedableRng;
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::time::Duration;
use tri_sync_core::chain::{self, Block, SigEntry};
use tri_sync_core::crypto;
use tri_sync_core::fusion;
use tri_sync_core::trust;

const TRIM_FRAC: f64 = 0.2;
const RELIABILITY_ALPHA: f64 = 0.3;
const RELIABILITY_FLOOR: f64 = 0.05;
const RELIABILITY_CEIL: f64 = 1.0;
const EDGE_ALPHA: f64 = 1.0;
const EDGE_FLOOR: f64 = 0.02;
const EDGE_CEIL: f64 = 3.0;

struct PeerInfo {
    addr: SocketAddr,
    pubkey: VerifyingKey,
}

struct Ctx {
    config: NodeConfig,
    peers: HashMap<usize, PeerInfo>,
    all_ids: Vec<usize>,
    endpoint: quinn::Endpoint,
}

#[derive(Default)]
struct RoundState {
    /// This node's most recently seen observation from each id
    /// (including itself), regardless of which "round" it arrived in -
    /// deliberately not round-synchronized, so a slow or dropped peer
    /// just means fusion falls back to slightly stale data instead of
    /// blocking.
    latest_observations: HashMap<usize, Vec<f64>>,
    /// Candidate blocks by hash, kept until superseded by a committed
    /// block at the same or greater height.
    candidates: HashMap<String, Block>,
    /// Collected signatures by block hash.
    votes: HashMap<String, Vec<SigEntry>>,
}

/// A synthetic "true" trajectory every node observes noisily -
/// deterministic given the target height alone, so every process
/// computes the same ground truth with no coordination.
fn synthetic_truth(dim: usize, height: u64) -> Vec<f64> {
    (0..dim).map(|d| ((height as f64) * 0.3 + d as f64).sin() * 5.0).collect()
}

fn noisy_observation(dim: usize, height: u64, node_id: usize, rng: &mut impl rand::Rng) -> Vec<f64> {
    synthetic_truth(dim, height).into_iter().map(|v| v + rng.gen_range(-0.5..0.5) + (node_id as f64 * 0.01)).collect()
}

fn expected_proposer(all_ids: &[usize], height: u64) -> usize {
    all_ids[(height as usize) % all_ids.len()]
}

fn quorum_for(network_size: usize) -> usize {
    network_size / 2 + 1
}

fn decode_verifying_key(hex_str: &str) -> Option<VerifyingKey> {
    let bytes = hex::decode(hex_str).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

fn decode_signature(hex_str: &str) -> Option<Signature> {
    let bytes = hex::decode(hex_str).ok()?;
    let arr: [u8; 64] = bytes.try_into().ok()?;
    Some(Signature::from_bytes(&arr))
}

fn block_canon(block: &Block) -> String {
    let state_hash = chain::hash_vec(&block.state);
    let reconciles_hash = chain::hash_list(&block.reconciles);
    chain::canon_string(block.height, &block.parent, &state_hash, block.confidence, &reconciles_hash, block.epoch)
}

async fn broadcast(ctx: &Ctx, msg: &Message) {
    for peer in ctx.peers.values() {
        if let Err(e) = net::send_message(&ctx.endpoint, peer.addr, msg).await {
            eprintln!("tri_sync_node: send to {} failed: {e}", peer.addr);
        }
    }
}

fn log(line: impl std::fmt::Display) {
    println!("tri_sync_node: {line}");
    let _ = std::io::stdout().flush();
}

/// Runs the round loop until `duration` elapses (if given) or the
/// incoming-message channel closes. `node`/`store` are mutated and
/// persisted in place as blocks commit and trust updates.
pub async fn run(
    config: NodeConfig,
    mut node: NodeState,
    store: Store,
    endpoint: quinn::Endpoint,
    mut incoming: tokio::sync::mpsc::UnboundedReceiver<(SocketAddr, Message)>,
    duration: Option<Duration>,
) {
    let peers: HashMap<usize, PeerInfo> = config
        .peers
        .iter()
        .filter_map(|p| {
            let addr = p.addr.parse().ok()?;
            let pubkey = decode_verifying_key(&p.pubkey_hex)?;
            Some((p.id, PeerInfo { addr, pubkey }))
        })
        .collect();
    let mut all_ids: Vec<usize> = peers.keys().cloned().chain(std::iter::once(node.node_id)).collect();
    all_ids.sort_unstable();

    let ctx = Ctx { config, peers, all_ids, endpoint };
    let mut rs = RoundState::default();
    let mut rng = rand::rngs::StdRng::from_entropy();

    let mut ticker = tokio::time::interval(Duration::from_secs(ctx.config.round_interval_secs));
    let deadline = duration.map(|d| tokio::time::Instant::now() + d);
    // A real bug, caught by testing: checking the deadline only after a
    // select! branch resolves lets a run overrun by up to one full
    // round_interval_secs when the next tick is far off and no message
    // arrives - racing an explicit sleep-until-deadline branch instead
    // makes the cutoff exact.
    let deadline_sleep = async {
        match deadline {
            Some(dl) => tokio::time::sleep_until(dl).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(deadline_sleep);

    loop {
        tokio::select! {
            _ = &mut deadline_sleep => {
                log("--duration elapsed, shutting down cleanly.");
                break;
            }
            _ = ticker.tick() => {
                on_tick(&ctx, &mut node, &store, &mut rs, &mut rng).await;
            }
            received = incoming.recv() => {
                match received {
                    Some((_remote, msg)) => on_message(&ctx, &mut node, &store, &mut rs, msg).await,
                    None => break,
                }
            }
        }
    }
}

async fn on_tick(ctx: &Ctx, node: &mut NodeState, store: &Store, rs: &mut RoundState, rng: &mut impl rand::Rng) {
    let head = node.head().clone();
    let next_height = head.height + 1;

    let obs = noisy_observation(ctx.config.dim, next_height, node.node_id, rng);
    rs.latest_observations.insert(node.node_id, obs.clone());
    broadcast(ctx, &Message::Observation(ObservationMsg { sender: node.node_id, values: obs })).await;

    let proposer = expected_proposer(&ctx.all_ids, head.height);
    let already_proposed_here = rs.candidates.values().any(|b| b.parent == head.hash && b.height == next_height);
    if proposer == node.node_id && !already_proposed_here {
        propose_block(ctx, node, store, rs, &head).await;
    }
}

async fn propose_block(ctx: &Ctx, node: &mut NodeState, store: &Store, rs: &mut RoundState, head: &Block) {
    let ids: Vec<usize> = rs.latest_observations.keys().cloned().collect();
    let values: Vec<Vec<f64>> = ids.iter().map(|id| rs.latest_observations[id].clone()).collect();
    let weights: Vec<f64> =
        ids.iter().map(|&id| if id == node.node_id { 1.0 } else { *node.reliability.get(&id).unwrap_or(&0.5) }).collect();

    let fused = fusion::trimmed_fuse(&values, &weights, TRIM_FRAC);
    let spread = values.iter().map(|v| fusion::l2_distance(v, &fused)).sum::<f64>() / values.len() as f64;
    let confidence = (1.0 / (1.0 + spread)).clamp(0.0, 1.0);

    let mut block = Block {
        height: head.height + 1,
        parent: head.hash.clone(),
        state: fused,
        confidence,
        reconciles: vec![],
        epoch: node.epoch,
        signatures: vec![],
        sig_weight: 0.0,
        hash: String::new(),
    };
    let canon = block_canon(&block);
    block.hash = chain::block_hash(&canon);
    let my_sig = crypto::sign_canon(&node.signing_key, &canon);
    let my_entry = SigEntry { node_id: node.node_id, pubkey_hex: hex::encode(node.verifying_key.to_bytes()), sig_hex: hex::encode(my_sig.to_bytes()) };
    block.signatures = vec![my_entry.clone()];
    block.sig_weight = 1.0;

    log(format!("proposing height={} hash={} state={:?}", block.height, block.hash, block.state));

    rs.candidates.insert(block.hash.clone(), block.clone());
    rs.votes.entry(block.hash.clone()).or_default().push(my_entry);

    broadcast(ctx, &Message::BlockProposal(BlockProposalMsg { sender: node.node_id, block: block.clone() })).await;
    maybe_commit(ctx, node, store, rs, &block.hash).await;
}

async fn on_message(ctx: &Ctx, node: &mut NodeState, store: &Store, rs: &mut RoundState, msg: Message) {
    match msg {
        Message::Observation(o) => {
            if ctx.peers.contains_key(&o.sender) {
                rs.latest_observations.insert(o.sender, o.values);
            }
        }
        Message::BlockProposal(p) => handle_proposal(ctx, node, store, rs, p).await,
        Message::BlockVote(v) => handle_vote(ctx, node, store, rs, v).await,
        Message::TrustUpdate(t) => {
            log(format!("peer {} reports edge_weight {:.3} toward peer {}", t.sender, t.edge_weight, t.about_peer));
        }
        Message::State(_) => {} // informational only in this stage
    }
}

async fn handle_proposal(ctx: &Ctx, node: &mut NodeState, store: &Store, rs: &mut RoundState, p: BlockProposalMsg) {
    let head = node.head().clone();
    if p.block.parent != head.hash || p.block.height != head.height + 1 {
        return; // stale, forked, or premature proposal - not handled in this stage
    }
    let expected = expected_proposer(&ctx.all_ids, head.height);
    if p.sender != expected {
        eprintln!("tri_sync_node: ignoring proposal from {} - expected proposer is {}", p.sender, expected);
        return;
    }
    let Some(peer) = ctx.peers.get(&p.sender) else { return };
    let Some(their_sig_entry) = p.block.signatures.first() else { return };
    let Some(sig) = decode_signature(&their_sig_entry.sig_hex) else { return };

    let canon = block_canon(&p.block);
    if !crypto::verify_canon(&peer.pubkey, &canon, &sig) {
        eprintln!("tri_sync_node: invalid proposer signature from {}", p.sender);
        return;
    }
    let block_hash = chain::block_hash(&canon);
    if block_hash != p.block.hash {
        eprintln!("tri_sync_node: proposal hash mismatch from {}", p.sender);
        return;
    }

    rs.candidates.entry(block_hash.clone()).or_insert_with(|| p.block.clone());
    let tally = rs.votes.entry(block_hash.clone()).or_default();
    if !tally.iter().any(|e| e.node_id == p.sender) {
        tally.push(their_sig_entry.clone());
    }

    let already_voted = rs.votes[&block_hash].iter().any(|e| e.node_id == node.node_id);
    if !already_voted {
        let my_sig = crypto::sign_canon(&node.signing_key, &canon);
        let my_entry =
            SigEntry { node_id: node.node_id, pubkey_hex: hex::encode(node.verifying_key.to_bytes()), sig_hex: hex::encode(my_sig.to_bytes()) };
        rs.votes.get_mut(&block_hash).unwrap().push(my_entry.clone());
        log(format!("voting for height={} hash={block_hash}", p.block.height));
        broadcast(
            ctx,
            &Message::BlockVote(BlockVoteMsg {
                sender: node.node_id,
                block_hash: block_hash.clone(),
                pubkey_hex: my_entry.pubkey_hex,
                sig_hex: my_entry.sig_hex,
            }),
        )
        .await;
    }

    maybe_commit(ctx, node, store, rs, &block_hash).await;
}

async fn handle_vote(ctx: &Ctx, node: &mut NodeState, store: &Store, rs: &mut RoundState, v: BlockVoteMsg) {
    let known_pubkey = if v.sender == node.node_id { Some(node.verifying_key) } else { ctx.peers.get(&v.sender).map(|p| p.pubkey) };
    let Some(known_pubkey) = known_pubkey else { return };
    let Some(claimed_pubkey) = decode_verifying_key(&v.pubkey_hex) else { return };
    if claimed_pubkey != known_pubkey {
        eprintln!("tri_sync_node: vote from {} claims an unexpected pubkey", v.sender);
        return;
    }

    let Some(block) = rs.candidates.get(&v.block_hash).cloned() else {
        return; // vote arrived before the proposal - dropped; no retry in this stage
    };
    let Some(sig) = decode_signature(&v.sig_hex) else { return };
    let canon = block_canon(&block);
    if !crypto::verify_canon(&known_pubkey, &canon, &sig) {
        eprintln!("tri_sync_node: invalid vote signature from {}", v.sender);
        return;
    }

    let tally = rs.votes.entry(v.block_hash.clone()).or_default();
    if !tally.iter().any(|e| e.node_id == v.sender) {
        tally.push(SigEntry { node_id: v.sender, pubkey_hex: v.pubkey_hex, sig_hex: v.sig_hex });
    }

    maybe_commit(ctx, node, store, rs, &v.block_hash).await;
}

async fn maybe_commit(ctx: &Ctx, node: &mut NodeState, store: &Store, rs: &mut RoundState, block_hash: &str) {
    let head = node.head().clone();
    let Some(mut block) = rs.candidates.get(block_hash).cloned() else { return };
    if block.parent != head.hash {
        return; // superseded by a different committed block already
    }
    let Some(votes) = rs.votes.get(block_hash).cloned() else { return };
    if votes.len() < quorum_for(ctx.all_ids.len()) {
        return;
    }

    block.signatures = votes;
    block.sig_weight = block.signatures.len() as f64;

    apply_trust_updates(ctx, node, store, &block, rs).await;

    node.chain.push(block.clone());
    if let Err(e) = store.put_block(&block) {
        eprintln!("tri_sync_node: failed to persist committed block: {e}");
    }
    log(format!("COMMITTED height={} hash={} sig_weight={} state={:?}", block.height, block.hash, block.sig_weight, block.state));

    rs.candidates.retain(|_, b| b.height > block.height);
    let surviving: std::collections::HashSet<String> = rs.candidates.keys().cloned().collect();
    rs.votes.retain(|h, _| surviving.contains(h));
}

/// Real leave-one-out Δe: for each peer whose latest observation
/// contributed to `block.state`, re-fuse without them and see how much
/// worse the result gets relative to the committed state. A peer whose
/// removal barely changes anything, or whose own observation was close
/// to the committed state, gains trust; a peer whose observation was
/// an outlier loses it.
async fn apply_trust_updates(ctx: &Ctx, node: &mut NodeState, store: &Store, block: &Block, rs: &RoundState) {
    let ids: Vec<usize> = rs.latest_observations.keys().cloned().collect();
    if ids.len() < 2 {
        return;
    }
    let values: Vec<Vec<f64>> = ids.iter().map(|id| rs.latest_observations[id].clone()).collect();
    let weights: Vec<f64> =
        ids.iter().map(|&id| if id == node.node_id { 1.0 } else { *node.reliability.get(&id).unwrap_or(&0.5) }).collect();
    let share = 1.0 / ids.len() as f64;

    for (idx, &peer_id) in ids.iter().enumerate() {
        if peer_id == node.node_id {
            continue;
        }
        let without_values: Vec<Vec<f64>> = values.iter().enumerate().filter(|(i, _)| *i != idx).map(|(_, v)| v.clone()).collect();
        let without_weights: Vec<f64> = weights.iter().enumerate().filter(|(i, _)| *i != idx).map(|(_, w)| *w).collect();
        if without_values.is_empty() {
            continue;
        }
        let without = fusion::trimmed_fuse(&without_values, &without_weights, TRIM_FRAC);
        let delta_e = fusion::l2_distance(&without, &block.state);
        let peer_obs_error = fusion::l2_distance(&values[idx], &block.state);

        let old_rel = *node.reliability.get(&peer_id).unwrap_or(&0.5);
        let new_rel = trust::update_reliability(old_rel, peer_obs_error, 0.0, RELIABILITY_ALPHA, RELIABILITY_FLOOR, RELIABILITY_CEIL);
        let old_w = *node.edge_weight.get(&peer_id).unwrap_or(&1.0);
        let new_w = trust::update_edge_weight(old_w, share, delta_e, EDGE_ALPHA, EDGE_FLOOR, EDGE_CEIL);

        node.reliability.insert(peer_id, new_rel);
        node.edge_weight.insert(peer_id, new_w);
        if let Err(e) = store.put_trust(peer_id, TrustEntry { edge_weight: new_w, reliability: new_rel }) {
            eprintln!("tri_sync_node: failed to persist trust update for peer {peer_id}: {e}");
        }
        broadcast(ctx, &Message::TrustUpdate(TrustUpdateMsg { sender: node.node_id, about_peer: peer_id, edge_weight: new_w })).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposer_selection_is_deterministic_and_round_robins_by_height() {
        let ids = vec![0, 1, 2];
        assert_eq!(expected_proposer(&ids, 0), 0);
        assert_eq!(expected_proposer(&ids, 1), 1);
        assert_eq!(expected_proposer(&ids, 2), 2);
        assert_eq!(expected_proposer(&ids, 3), 0);
    }

    #[test]
    fn quorum_is_a_strict_majority() {
        assert_eq!(quorum_for(1), 1);
        assert_eq!(quorum_for(2), 2);
        assert_eq!(quorum_for(3), 2);
        assert_eq!(quorum_for(4), 3);
        assert_eq!(quorum_for(5), 3);
    }

    #[test]
    fn synthetic_truth_is_deterministic_given_the_same_height() {
        assert_eq!(synthetic_truth(3, 5), synthetic_truth(3, 5));
        assert_ne!(synthetic_truth(3, 5), synthetic_truth(3, 6));
    }

    #[test]
    fn block_canon_matches_chain_canon_string() {
        let block = Block { height: 1, parent: "GENESIS".to_string(), state: vec![1.0, 2.0], confidence: 0.9, reconciles: vec![], epoch: 0, signatures: vec![], sig_weight: 0.0, hash: String::new() };
        let expected = chain::canon_string(1, "GENESIS", &chain::hash_vec(&[1.0, 2.0]), 0.9, &chain::hash_list(&[]), 0);
        assert_eq!(block_canon(&block), expected);
    }

    #[test]
    fn decode_verifying_key_round_trips_a_real_key() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let hex_str = hex::encode(sk.verifying_key().to_bytes());
        assert_eq!(decode_verifying_key(&hex_str), Some(sk.verifying_key()));
    }

    #[test]
    fn decode_verifying_key_rejects_garbage() {
        assert_eq!(decode_verifying_key("not hex"), None);
        assert_eq!(decode_verifying_key("abcd"), None);
    }

    /// The real end-to-end claim this stage exists to prove: two
    /// separate `run()` instances, each with its own real LMDB store
    /// and real QUIC endpoints on loopback, independently committing
    /// the same sequence of blocks with matching hashes and full 2-of-2
    /// quorum - not mocked, and not just message delivery (Stage 5's
    /// job) but actual cryptographic agreement on chain content. This
    /// is the in-process, automated form of the manual two-OS-process
    /// test this stage was verified with.
    #[tokio::test]
    async fn two_real_nodes_reach_agreement_on_committed_blocks_over_real_quic() {
        use crate::config::PeerConfig;
        use crate::test_support::TempDir;
        use std::net::{IpAddr, Ipv4Addr};

        let dir_a = TempDir::new("consensus_a");
        let dir_b = TempDir::new("consensus_b");

        let sk_a = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let sk_b = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        let loopback = |port: u16| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let server_a = net::make_server_endpoint(loopback(0)).unwrap();
        let server_b = net::make_server_endpoint(loopback(0)).unwrap();
        let addr_a = server_a.local_addr().unwrap();
        let addr_b = server_b.local_addr().unwrap();

        let config_a = NodeConfig {
            node_id: 0,
            dim: 2,
            listen_addr: addr_a.to_string(),
            license_path: String::new(),
            data_dir: String::new(),
            round_interval_secs: 1,
            peers: vec![PeerConfig { id: 1, addr: addr_b.to_string(), pubkey_hex: hex::encode(sk_b.verifying_key().to_bytes()) }],
        };
        let config_b = NodeConfig {
            node_id: 1,
            dim: 2,
            listen_addr: addr_b.to_string(),
            license_path: String::new(),
            data_dir: String::new(),
            round_interval_secs: 1,
            peers: vec![PeerConfig { id: 0, addr: addr_a.to_string(), pubkey_hex: hex::encode(sk_a.verifying_key().to_bytes()) }],
        };

        let store_a = Store::open(dir_a.path()).unwrap();
        let store_b = Store::open(dir_b.path()).unwrap();

        let node_a = NodeState {
            node_id: 0,
            chain: vec![Block::genesis(2)],
            signing_key: sk_a.clone(),
            verifying_key: sk_a.verifying_key(),
            epoch: 0,
            edge_weight: HashMap::new(),
            reliability: HashMap::new(),
        };
        let node_b = NodeState {
            node_id: 1,
            chain: vec![Block::genesis(2)],
            signing_key: sk_b.clone(),
            verifying_key: sk_b.verifying_key(),
            epoch: 0,
            edge_weight: HashMap::new(),
            reliability: HashMap::new(),
        };

        let (tx_a, rx_a) = tokio::sync::mpsc::unbounded_channel();
        let (tx_b, rx_b) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(net::serve(server_a, tx_a));
        tokio::spawn(net::serve(server_b, tx_b));

        let client_a = net::make_client_endpoint().unwrap();
        let client_b = net::make_client_endpoint().unwrap();

        let duration = Duration::from_secs(6);
        tokio::join!(run(config_a, node_a, store_a, client_a, rx_a, Some(duration)), run(config_b, node_b, store_b, client_b, rx_b, Some(duration)));

        let blocks_a = Store::open(dir_a.path()).unwrap().all_blocks().unwrap();
        let blocks_b = Store::open(dir_b.path()).unwrap().all_blocks().unwrap();

        assert!(blocks_a.len() >= 2, "node A should have committed at least one real block, got {}", blocks_a.len());
        assert!(blocks_b.len() >= 2, "node B should have committed at least one real block, got {}", blocks_b.len());

        let common = blocks_a.len().min(blocks_b.len());
        for i in 0..common {
            assert_eq!(blocks_a[i].height, blocks_b[i].height);
            assert_eq!(blocks_a[i].hash, blocks_b[i].hash, "both nodes must agree on block {}'s hash", blocks_a[i].height);
            assert_eq!(blocks_a[i].sig_weight, 2.0, "a 2-node network should always reach full 2-of-2 quorum");
        }
    }
}
