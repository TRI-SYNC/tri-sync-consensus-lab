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
//! - Epoch rotation (Hardening 7) is real and live: every block's
//!   epoch is `tri_sync_core::chain::epoch_for_height(height)`, a pure
//!   function every node computes identically with no coordination,
//!   and `maybe_commit` updates/persists/logs `node.epoch` whenever a
//!   committed block crosses into a new one. What it deliberately does
//!   NOT do yet is re-key: the signing keypair stays the one from
//!   `node.toml`/persisted identity across every epoch. Rotating keys
//!   for real would mean a peer's configured pubkey goes stale the
//!   moment that peer rotates, with no way for this node to learn the
//!   new one - that needs the automated key-distribution mechanism
//!   that's its own, later hardening pass, not something to bolt on
//!   here incompletely.
//! - Peer public keys are static, from `node.toml` - there's no
//!   in-band key discovery yet (see the epoch point above for why
//!   that's a prerequisite for real re-keying, not an independent gap).
//! - Liveness fallback exists (`maybe_bump_view` hands off to the next
//!   proposer after a timeout, with catch-up so a lagging node adopts
//!   a legitimate later view instead of rejecting it), but it isn't a
//!   complete BFT view-change protocol: a node only *locks* its vote
//!   implicitly, by however far `expected_proposer`/signature checks
//!   let it advance, not via a quorum-certificate/"precommit" proof
//!   that an earlier view genuinely failed. In an adversarial or
//!   badly-partitioned network this leaves a real (if narrow) window
//!   where votes could split across two views' candidates for the same
//!   height. What *is* covered: a single node can never commit two
//!   blocks at the same height (`handle_proposal`'s parent-hash check
//!   is re-evaluated against the live head on every call, so a second
//!   candidate for an already-committed height is rejected outright,
//!   confirmed by a dedicated test); a proposal for an already-committed
//!   height that `tri_sync_core::chain::prefer` ranks above what was
//!   actually committed is detected and logged loudly as a safety
//!   violation, not silently auto-reorged onto unverified evidence.
//!   Closing the remaining window needs real locking/quorum
//!   certificates, which is out of scope for this pass.
//! - Per-peer health (`crate::health`) is tracked and exposed via
//!   `/metrics`, but purely observationally: it never changes who
//!   gets proposed to, voted for, or sent messages. Deliberately not
//!   wired into behavior - see that module's doc comment for why.

use crate::config::NodeConfig;
use crate::health;
use crate::metrics::Metrics;
use crate::net;
use crate::persistence::{Store, TrustEntry};
use crate::protocol::{self, BlockProposalMsg, BlockVoteMsg, Message, ObservationMsg, TrustUpdateMsg};
use crate::state::NodeState;
use ed25519_dalek::{Signature, VerifyingKey};
use rand::SeedableRng;
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
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
    metrics: Arc<Metrics>,
}

#[derive(Default)]
struct RoundState {
    /// This node's most recently seen observation from each id
    /// (including itself), regardless of which "round" it arrived in -
    /// deliberately not round-synchronized, so a slow or dropped peer
    /// just means fusion falls back to slightly stale data instead of
    /// blocking.
    latest_observations: HashMap<usize, Vec<f64>>,
    /// Candidate blocks by hash, paired with the view that produced
    /// them, kept until superseded by a committed block at the same or
    /// greater height. The view is tracked alongside the block (not
    /// on `Block` itself, which knows nothing about view-change) so a
    /// candidate from an abandoned view can be told apart from a fresh
    /// one at the same height.
    candidates: HashMap<String, (u64, Block)>,
    /// Collected signatures by block hash.
    votes: HashMap<String, Vec<SigEntry>>,
    /// The accepted view number per height - see `current_view`.
    view_for_height: HashMap<u64, u64>,
    /// The (height, view) this node is currently timing a proposer
    /// timeout for, and when that timer started - see
    /// `maybe_bump_view`. `None` until the first tick sets it.
    waiting_for: Option<(u64, u64)>,
    waiting_since: Option<tokio::time::Instant>,
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

/// The proposer for `height` at `view`: round-robins by `height + view`,
/// so bumping the view (see `maybe_bump_view`) hands off to the next
/// participant in a way every node computes identically without
/// needing to coordinate who goes next.
fn expected_proposer(all_ids: &[usize], height: u64, view: u64) -> usize {
    all_ids[((height + view) as usize) % all_ids.len()]
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

/// The view this node currently accepts for `height` - 0 until
/// something bumps it (nothing does yet; that's the view-change
/// stage). Any proposal/vote for `height` at a different view is
/// rejected: lower means a stale/replayed message, higher means a
/// view this node hasn't caught up to.
fn current_view(rs: &RoundState, height: u64) -> u64 {
    *rs.view_for_height.get(&height).unwrap_or(&0)
}

/// Checks whether this node has been waiting too long for `height`'s
/// current-view proposer, and bumps the view if so. Called every tick
/// before anything else, so a stalled proposer (offline, slow,
/// byzantine) doesn't stall the whole network.
///
/// Tracks `(height, view)` rather than just a timestamp: whenever
/// either changes underneath it (the head advanced past `height`, or
/// the view already moved on since this was last called), the timer
/// restarts from zero for the new pair instead of carrying over
/// elapsed time that belonged to a different wait. Returns `true` if a
/// bump happened just now.
fn maybe_bump_view(rs: &mut RoundState, height: u64, timeout: Duration) -> bool {
    let view = current_view(rs, height);
    let now = tokio::time::Instant::now();

    if rs.waiting_for != Some((height, view)) {
        rs.waiting_for = Some((height, view));
        rs.waiting_since = Some(now);
        return false;
    }

    let Some(started) = rs.waiting_since else {
        rs.waiting_since = Some(now);
        return false;
    };
    if now.duration_since(started) < timeout {
        return false;
    }

    let new_view = view + 1;
    rs.view_for_height.insert(height, new_view);
    rs.waiting_for = Some((height, new_view));
    rs.waiting_since = Some(now);
    true
}

/// Verifies `sig_hex` over `canon` against `sender`'s *configured*
/// pubkey (never a pubkey the message itself claims) - `false` for an
/// unknown sender, malformed signature, or bad match. The shared check
/// behind authenticating observation, state, and trust-update gossip.
fn verify_from_peer(ctx: &Ctx, sender: usize, canon: &str, sig_hex: &str) -> bool {
    let Some(peer) = ctx.peers.get(&sender) else { return false };
    let Some(sig) = decode_signature(sig_hex) else { return false };
    let ok = crypto::verify_canon(&peer.pubkey, canon, &sig);
    if ok {
        // Health only ever records a genuinely authenticated message -
        // see crate::health's doc comment on why an unverified claim
        // must never be able to inflate a peer's apparent health.
        ctx.metrics.record_peer_seen(sender);
    }
    ok
}

/// Fires a send to every peer as its own task and returns immediately,
/// rather than awaiting each one in turn. Sequential awaiting was a
/// real bug, caught by a live liveness test: one unreachable peer's
/// full connect timeout (see `net::CONNECT_TIMEOUT`) delayed delivery
/// to every *other* peer in the same broadcast, which starved the
/// view-change catch-up logic of the timely delivery it depends on -
/// two live nodes could each be stuck waiting ~5s behind a single dead
/// third peer on every tick, drifting their view-timeout clocks apart
/// faster than messages could ever catch up.
fn broadcast(ctx: &Ctx, msg: &Message) {
    for (&id, peer) in ctx.peers.iter() {
        let endpoint = ctx.endpoint.clone();
        let addr = peer.addr;
        let msg = msg.clone();
        let metrics = ctx.metrics.clone();
        tokio::spawn(async move {
            let ok = match net::send_message(&endpoint, addr, &msg).await {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("tri_sync_node: send to {addr} failed: {e}");
                    false
                }
            };
            // The transition comes from PeerHealth's own atomic
            // bookkeeping, not a before/after comparison here - this
            // task is one of several concurrent sends to the same
            // peer in a tick, and a local comparison raced its
            // siblings (caught live; see crate::health's doc comment).
            match metrics.record_send_result(id, ok) {
                Some(health::HealthTransition::BecameUnhealthy) => {
                    eprintln!(
                        "tri_sync_node: peer {id} ({addr}) marked unhealthy after {} consecutive failed sends",
                        health::UNHEALTHY_AFTER_CONSECUTIVE_FAILURES
                    );
                }
                Some(health::HealthTransition::Recovered) => {
                    log(format!("peer {id} ({addr}) recovered - a send succeeded after prior failures"));
                }
                Some(health::HealthTransition::NoChange) | None => {}
            }
        });
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
    metrics: Arc<Metrics>,
) {
    // config::load_from_str already rejected any unparseable peer addr
    // or pubkey_hex - expect(), not filter_map's silent drop, so a
    // config that somehow reaches here malformed fails loudly instead
    // of quietly shrinking the network.
    let peers: HashMap<usize, PeerInfo> = config
        .peers
        .iter()
        .map(|p| {
            let addr = p.addr.parse().expect("validated at config load");
            let pubkey = decode_verifying_key(&p.pubkey_hex).expect("validated at config load");
            (p.id, PeerInfo { addr, pubkey })
        })
        .collect();
    let mut all_ids: Vec<usize> = peers.keys().cloned().chain(std::iter::once(node.node_id)).collect();
    all_ids.sort_unstable();

    metrics.head_height.store(node.head().height, Ordering::Relaxed);
    reconcile_epoch_with_chain(&mut node, &store);
    metrics.epoch.store(node.epoch, Ordering::Relaxed);

    let ctx = Ctx { config, peers, all_ids, endpoint, metrics };
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

    let view_timeout = Duration::from_secs(ctx.config.round_interval_secs.saturating_mul(3).max(1));
    if maybe_bump_view(rs, next_height, view_timeout) {
        let new_view = current_view(rs, next_height);
        ctx.metrics.view_changes_total.fetch_add(1, Ordering::Relaxed);
        log(format!(
            "view-change: height={next_height} timed out waiting on proposer {}, advancing to view={new_view} (new proposer {})",
            expected_proposer(&ctx.all_ids, next_height, new_view - 1),
            expected_proposer(&ctx.all_ids, next_height, new_view)
        ));
    }

    let obs = noisy_observation(ctx.config.dim, next_height, node.node_id, rng);
    rs.latest_observations.insert(node.node_id, obs.clone());
    let obs_canon = protocol::observation_canon(node.node_id, &obs);
    let obs_sig = crypto::sign_canon(&node.signing_key, &obs_canon);
    broadcast(ctx, &Message::Observation(ObservationMsg { sender: node.node_id, values: obs, sig_hex: hex::encode(obs_sig.to_bytes()) }));

    let view = current_view(rs, next_height);
    let proposer = expected_proposer(&ctx.all_ids, next_height, view);
    let already_proposed_here = rs.candidates.values().any(|(v, b)| b.parent == head.hash && b.height == next_height && *v == view);
    if proposer == node.node_id && !already_proposed_here {
        propose_block(ctx, node, store, rs, &head, view).await;
    }
}

async fn propose_block(ctx: &Ctx, node: &mut NodeState, store: &Store, rs: &mut RoundState, head: &Block, view: u64) {
    let ids: Vec<usize> = rs.latest_observations.keys().cloned().collect();
    let values: Vec<Vec<f64>> = ids.iter().map(|id| rs.latest_observations[id].clone()).collect();
    let weights: Vec<f64> =
        ids.iter().map(|&id| if id == node.node_id { 1.0 } else { *node.reliability.get(&id).unwrap_or(&0.5) }).collect();

    let fused = fusion::trimmed_fuse(&values, &weights, TRIM_FRAC);
    let spread = values.iter().map(|v| fusion::l2_distance(v, &fused)).sum::<f64>() / values.len() as f64;
    let confidence = (1.0 / (1.0 + spread)).clamp(0.0, 1.0);

    let next_height = head.height + 1;
    let mut block = Block {
        height: next_height,
        parent: head.hash.clone(),
        state: fused,
        confidence,
        reconciles: vec![],
        // Derived from height, not read from node.epoch directly - see
        // chain::epoch_for_height's doc comment for why every node
        // converges on the same value with no coordination needed.
        // node.epoch is just maybe_commit's cached mirror of this,
        // kept for logging/metrics.
        epoch: chain::epoch_for_height(next_height),
        signatures: vec![],
        sig_weight: 0.0,
        hash: String::new(),
    };
    let identity_canon = protocol::block_canon(&block);
    block.hash = chain::block_hash(&identity_canon);
    let signing_canon = protocol::view_block_canon(view, &block);
    let my_sig = crypto::sign_canon(&node.signing_key, &signing_canon);
    let my_entry = SigEntry { node_id: node.node_id, pubkey_hex: hex::encode(node.verifying_key.to_bytes()), sig_hex: hex::encode(my_sig.to_bytes()) };
    block.signatures = vec![my_entry.clone()];
    block.sig_weight = 1.0;

    log(format!("proposing height={} view={view} hash={} state={:?}", block.height, block.hash, block.state));

    rs.candidates.insert(block.hash.clone(), (view, block.clone()));
    rs.votes.entry(block.hash.clone()).or_default().push(my_entry);

    broadcast(ctx, &Message::BlockProposal(BlockProposalMsg { sender: node.node_id, view, block: block.clone() }));
    maybe_commit(ctx, node, store, rs, &block.hash).await;
}

async fn on_message(ctx: &Ctx, node: &mut NodeState, store: &Store, rs: &mut RoundState, msg: Message) {
    match msg {
        Message::Observation(o) => {
            let canon = protocol::observation_canon(o.sender, &o.values);
            if verify_from_peer(ctx, o.sender, &canon, &o.sig_hex) {
                rs.latest_observations.insert(o.sender, o.values);
            } else {
                eprintln!("tri_sync_node: rejected observation from {} - unknown sender or invalid signature", o.sender);
            }
        }
        Message::BlockProposal(p) => handle_proposal(ctx, node, store, rs, p).await,
        Message::BlockVote(v) => handle_vote(ctx, node, store, rs, v).await,
        Message::TrustUpdate(t) => {
            let canon = protocol::trust_update_canon(t.sender, t.about_peer, t.edge_weight);
            if verify_from_peer(ctx, t.sender, &canon, &t.sig_hex) {
                log(format!("peer {} reports edge_weight {:.3} toward peer {}", t.sender, t.edge_weight, t.about_peer));
            } else {
                eprintln!("tri_sync_node: rejected trust-update from {} - unknown sender or invalid signature", t.sender);
            }
        }
        // Informational only in this stage - nothing acts on a peer's
        // broadcast state yet - but still authenticated so a bad
        // signature is visible rather than silently accepted.
        Message::State(s) => {
            let canon = protocol::state_canon(s.sender, &s.state, s.confidence);
            if !verify_from_peer(ctx, s.sender, &canon, &s.sig_hex) {
                eprintln!("tri_sync_node: rejected state broadcast from {} - unknown sender or invalid signature", s.sender);
            }
        }
    }
}

async fn handle_proposal(ctx: &Ctx, node: &mut NodeState, store: &Store, rs: &mut RoundState, p: BlockProposalMsg) {
    let head = node.head().clone();

    // Authenticate before trusting *any* of this message's content -
    // including the already-committed-height branch below, which used
    // to run `chain::prefer` and log a "SAFETY VIOLATION" alarm off an
    // unverified claim. That was a real bug: a forged message (no
    // relation to any actual peer key) could trigger a false alarm
    // purely as noise/confusion, since that branch returned before
    // ever reaching the signature check that only existed later in
    // this function for the normal height+1 path. Checking this first,
    // for every height, closes that - at the cost of spending a
    // signature verification on messages that stale-view/wrong-sender
    // checks would otherwise have rejected more cheaply; correctness
    // over that micro-optimization.
    let Some(peer) = ctx.peers.get(&p.sender) else {
        eprintln!("tri_sync_node: ignoring proposal from unknown sender {}", p.sender);
        return;
    };
    let Some(their_sig_entry) = p.block.signatures.first() else { return };
    let Some(sig) = decode_signature(&their_sig_entry.sig_hex) else { return };
    let identity_canon = protocol::block_canon(&p.block);
    let signing_canon = protocol::view_block_canon(p.view, &p.block);
    if !crypto::verify_canon(&peer.pubkey, &signing_canon, &sig) {
        eprintln!("tri_sync_node: invalid proposer signature from {}", p.sender);
        return;
    }
    let block_hash = chain::block_hash(&identity_canon);
    if block_hash != p.block.hash {
        eprintln!("tri_sync_node: proposal hash mismatch from {}", p.sender);
        return;
    }
    ctx.metrics.record_peer_seen(p.sender);

    if p.block.height <= head.height {
        // A proposal for a height this node has already committed, now
        // known to be genuinely signed by `p.sender` over exactly this
        // content. Compare it against what's actually in the chain
        // using tri_sync_core::chain::prefer - the same fork-choice
        // rule the original single-process simulation uses - but only
        // to *detect and loudly surface* a possible safety violation,
        // not to act on it: this node has no way to verify from one
        // message alone that the alternative is genuinely more
        // supported network-wide (versus a stale, reordered, or
        // honestly-but-independently-proposed message), so silently
        // rewriting already-persisted, already-committed history here
        // would be a real reorg performed on insufficient evidence.
        // That's a materially different (and riskier) situation than
        // the pre-commit candidate races handled below, where nothing
        // has been committed yet and just letting quorum decide is
        // safe.
        //
        // One honest limitation even with the signature verified:
        // `block_canon` (what's actually signed) deliberately excludes
        // `sig_weight` - it's filled in independently by each node from
        // its own accumulated vote count (see `maybe_commit`), not
        // claimed by the proposer - so a genuine peer could still send
        // a validly-signed block carrying a `sig_weight` field that
        // doesn't match reality. `prefer()` uses that field, so this
        // check can be fooled into comparing against an inflated number
        // by any authenticated-but-dishonest peer, not only forged
        // messages. That's a real gap; closing it needs sig_weight (or
        // the quorum it represents) to be independently reconstructible
        // from the votes carried on the block, which is out of scope
        // for this pass - logged loudly rather than acted on either
        // way, so the blast radius of being fooled here is a noisy log
        // line, never a silent reorg.
        if let Some(committed) = node.chain.get(p.block.height as usize).filter(|b| b.height == p.block.height) {
            if committed.hash != p.block.hash && chain::prefer(committed, &p.block) {
                ctx.metrics.forks_total.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "tri_sync_node: SAFETY VIOLATION - received a signed proposal from {} for already-committed height {} \
                     that tri_sync_core::chain::prefer ranks above what this node committed \
                     (their hash={} sig_weight={} vs our hash={} sig_weight={}) - NOT auto-reorging; \
                     this needs operator attention, two conflicting blocks may have been committed network-wide.",
                    p.sender, p.block.height, p.block.hash, p.block.sig_weight, committed.hash, committed.sig_weight
                );
            }
        }
        return;
    }
    if p.block.parent != head.hash || p.block.height != head.height + 1 {
        return; // premature - this node is behind and has no chain-sync capability yet
    }
    // Reject only a *stale* view outright (replay of an abandoned
    // view - Hardening 3). A view *ahead* of what this node has
    // tracked is legitimate catch-up, not rejected here: independent
    // per-node timeout clocks drift, and a node that's simply running
    // a tick behind must not be permanently stuck disagreeing with
    // the rest of the network. Whether to actually adopt it still
    // depends on the sender being the real expected proposer - checked
    // next - and the signature above having already checked out; an
    // unverified claim of a high view number proves nothing on its own.
    if p.view < current_view(rs, p.block.height) {
        eprintln!(
            "tri_sync_node: ignoring proposal from {} for stale view {} - this node is already past it for height {}",
            p.sender, p.view, p.block.height
        );
        return;
    }
    let expected = expected_proposer(&ctx.all_ids, p.block.height, p.view);
    if p.sender != expected {
        eprintln!("tri_sync_node: ignoring proposal from {} - expected proposer for view {} is {}", p.sender, p.view, expected);
        return;
    }

    if p.view > current_view(rs, p.block.height) {
        log(format!("catching up: adopting view={} for height={} from proposer {}", p.view, p.block.height, p.sender));
        rs.view_for_height.insert(p.block.height, p.view);
        rs.waiting_for = Some((p.block.height, p.view));
        rs.waiting_since = Some(tokio::time::Instant::now());
    }

    let is_new_fork = !rs.candidates.contains_key(&block_hash)
        && rs.candidates.values().any(|(_, b)| b.height == p.block.height && b.hash != block_hash);
    if is_new_fork {
        ctx.metrics.forks_total.fetch_add(1, Ordering::Relaxed);
        log(format!("fork observed at height={}: competing candidate {block_hash}", p.block.height));
    }
    rs.candidates.entry(block_hash.clone()).or_insert_with(|| (p.view, p.block.clone()));
    let tally = rs.votes.entry(block_hash.clone()).or_default();
    if !tally.iter().any(|e| e.node_id == p.sender) {
        tally.push(their_sig_entry.clone());
    }

    let already_voted = rs.votes[&block_hash].iter().any(|e| e.node_id == node.node_id);
    if !already_voted {
        let my_sig = crypto::sign_canon(&node.signing_key, &signing_canon);
        let my_entry =
            SigEntry { node_id: node.node_id, pubkey_hex: hex::encode(node.verifying_key.to_bytes()), sig_hex: hex::encode(my_sig.to_bytes()) };
        rs.votes.get_mut(&block_hash).unwrap().push(my_entry.clone());
        log(format!("voting for height={} view={} hash={block_hash}", p.block.height, p.view));
        broadcast(
            ctx,
            &Message::BlockVote(BlockVoteMsg {
                sender: node.node_id,
                view: p.view,
                block_hash: block_hash.clone(),
                pubkey_hex: my_entry.pubkey_hex,
                sig_hex: my_entry.sig_hex,
            }),
        );
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

    let Some((_, block)) = rs.candidates.get(&v.block_hash).cloned() else {
        return; // vote arrived before the proposal - dropped; no retry in this stage
    };
    // Same "reject only if stale, catch up if ahead" rule as
    // handle_proposal - in practice this candidate is only cached
    // once the corresponding proposal already caught this node up to
    // its view, so v.view > current_view should be rare, but the rule
    // stays consistent rather than assuming that.
    if v.view < current_view(rs, block.height) {
        eprintln!(
            "tri_sync_node: ignoring vote from {} for stale view {} - this node is already past it for height {}",
            v.sender, v.view, block.height
        );
        return;
    }
    let Some(sig) = decode_signature(&v.sig_hex) else { return };
    let signing_canon = protocol::view_block_canon(v.view, &block);
    if !crypto::verify_canon(&known_pubkey, &signing_canon, &sig) {
        eprintln!("tri_sync_node: invalid vote signature from {}", v.sender);
        return;
    }
    ctx.metrics.record_peer_seen(v.sender); // no-op if v.sender is this node's own id

    if v.view > current_view(rs, block.height) {
        rs.view_for_height.insert(block.height, v.view);
        rs.waiting_for = Some((block.height, v.view));
        rs.waiting_since = Some(tokio::time::Instant::now());
    }

    let tally = rs.votes.entry(v.block_hash.clone()).or_default();
    if !tally.iter().any(|e| e.node_id == v.sender) {
        tally.push(SigEntry { node_id: v.sender, pubkey_hex: v.pubkey_hex, sig_hex: v.sig_hex });
    }

    maybe_commit(ctx, node, store, rs, &v.block_hash).await;
}

/// Corrects `node.epoch` to match what `chain::epoch_for_height` says
/// it should be for the chain height just loaded, persisting the fix.
/// See the call site in `run` for why the persisted value can't
/// always be trusted as-is. A no-op (no log, no write) when they
/// already agree, which is the overwhelmingly common case.
fn reconcile_epoch_with_chain(node: &mut NodeState, store: &Store) {
    let authoritative_epoch = chain::epoch_for_height(node.head().height);
    if authoritative_epoch == node.epoch {
        return;
    }
    log(format!(
        "correcting persisted epoch {} -> {authoritative_epoch} to match loaded chain height {}",
        node.epoch,
        node.head().height
    ));
    node.epoch = authoritative_epoch;
    if let Err(e) = store.put_epoch(authoritative_epoch) {
        eprintln!("tri_sync_node: failed to persist corrected epoch: {e}");
    }
}

async fn maybe_commit(ctx: &Ctx, node: &mut NodeState, store: &Store, rs: &mut RoundState, block_hash: &str) {
    let head = node.head().clone();
    let Some((_, mut block)) = rs.candidates.get(block_hash).cloned() else { return };
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
    ctx.metrics.head_height.store(block.height, Ordering::Relaxed);
    if !block.reconciles.is_empty() {
        ctx.metrics.reconciles_total.fetch_add(1, Ordering::Relaxed);
    }
    log(format!("COMMITTED height={} hash={} sig_weight={} state={:?}", block.height, block.hash, block.sig_weight, block.state));

    // block.epoch (set by whoever proposed it, from the same pure
    // chain::epoch_for_height every honest node computes) is now this
    // node's own current epoch too, since this node's head just
    // advanced to match. Persisted so a restart can see it without
    // recomputing, and logged once per actual rotation, not every
    // commit, so the log stays meaningful at epoch boundaries instead
    // of repeating the same value every round_interval_secs.
    if block.epoch != node.epoch {
        log(format!("epoch rotated: {} -> {} at height={}", node.epoch, block.epoch, block.height));
        node.epoch = block.epoch;
        ctx.metrics.epoch.store(block.epoch, Ordering::Relaxed);
        if let Err(e) = store.put_epoch(block.epoch) {
            eprintln!("tri_sync_node: failed to persist rotated epoch: {e}");
        }
    }

    rs.candidates.retain(|_, (_, b)| b.height > block.height);
    let surviving: std::collections::HashSet<String> = rs.candidates.keys().cloned().collect();
    rs.votes.retain(|h, _| surviving.contains(h));
    // Not strictly required (the next tick's height/view mismatch in
    // maybe_bump_view would reset this anyway), but explicit here:
    // whatever this node was timing out on is resolved now that the
    // height actually committed.
    rs.waiting_for = None;
    rs.waiting_since = None;
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
        let trust_canon = protocol::trust_update_canon(node.node_id, peer_id, new_w);
        let trust_sig = crypto::sign_canon(&node.signing_key, &trust_canon);
        broadcast(
            ctx,
            &Message::TrustUpdate(TrustUpdateMsg {
                sender: node.node_id,
                about_peer: peer_id,
                edge_weight: new_w,
                sig_hex: hex::encode(trust_sig.to_bytes()),
            }),
        );
    }

    if !node.edge_weight.is_empty() {
        let mean = node.edge_weight.values().sum::<f64>() / node.edge_weight.len() as f64;
        ctx.metrics.set_mean_trust_weight(mean);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposer_selection_is_deterministic_and_round_robins_by_height() {
        let ids = vec![0, 1, 2];
        assert_eq!(expected_proposer(&ids, 0, 0), 0);
        assert_eq!(expected_proposer(&ids, 1, 0), 1);
        assert_eq!(expected_proposer(&ids, 2, 0), 2);
        assert_eq!(expected_proposer(&ids, 3, 0), 0);
    }

    #[test]
    fn proposer_selection_also_round_robins_by_view_bumping_the_hand_off() {
        let ids = vec![0, 1, 2];
        // Same height, escalating views - each view hands off to the
        // next participant, wrapping around.
        assert_eq!(expected_proposer(&ids, 5, 0), expected_proposer(&ids, 5, 0));
        let v0 = expected_proposer(&ids, 5, 0);
        let v1 = expected_proposer(&ids, 5, 1);
        let v2 = expected_proposer(&ids, 5, 2);
        assert_ne!(v0, v1);
        assert_ne!(v1, v2);
        assert_ne!(v0, v2);
    }

    #[test]
    fn quorum_is_a_strict_majority() {
        assert_eq!(quorum_for(1), 1);
        assert_eq!(quorum_for(2), 2);
        assert_eq!(quorum_for(3), 2);
        assert_eq!(quorum_for(4), 3);
        assert_eq!(quorum_for(5), 3);
    }

    // Uses tokio's virtual clock (paused, manually advanced) so these
    // run instantly instead of actually sleeping for the timeout.

    #[tokio::test(start_paused = true)]
    async fn maybe_bump_view_does_nothing_before_the_timeout_elapses() {
        let mut rs = RoundState::default();
        let timeout = Duration::from_secs(10);
        assert!(!maybe_bump_view(&mut rs, 5, timeout), "first call just starts the timer, it shouldn't bump yet");
        tokio::time::advance(Duration::from_secs(5)).await; // halfway there
        assert!(!maybe_bump_view(&mut rs, 5, timeout));
        assert_eq!(current_view(&rs, 5), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn maybe_bump_view_bumps_exactly_once_the_timeout_elapses() {
        let mut rs = RoundState::default();
        let timeout = Duration::from_secs(10);
        maybe_bump_view(&mut rs, 5, timeout); // starts the timer
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(maybe_bump_view(&mut rs, 5, timeout), "the timeout has fully elapsed, this call should bump");
        assert_eq!(current_view(&rs, 5), 1);

        // Immediately calling again shouldn't bump a second time - the
        // timer for the new view just started.
        assert!(!maybe_bump_view(&mut rs, 5, timeout));
        assert_eq!(current_view(&rs, 5), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn maybe_bump_view_can_bump_repeatedly_if_the_new_proposer_also_stalls() {
        let mut rs = RoundState::default();
        let timeout = Duration::from_secs(10);
        maybe_bump_view(&mut rs, 5, timeout);
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(maybe_bump_view(&mut rs, 5, timeout));
        assert_eq!(current_view(&rs, 5), 1);

        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(maybe_bump_view(&mut rs, 5, timeout), "a second stalled proposer should bump again");
        assert_eq!(current_view(&rs, 5), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn maybe_bump_view_restarts_the_timer_when_the_height_changes() {
        let mut rs = RoundState::default();
        let timeout = Duration::from_secs(10);
        maybe_bump_view(&mut rs, 5, timeout);
        tokio::time::advance(Duration::from_secs(9)).await; // almost timed out for height 5

        // The chain committed height 5 in the meantime - now waiting
        // on height 6 instead. The 9 elapsed seconds must not carry
        // over to height 6's fresh timer.
        assert!(!maybe_bump_view(&mut rs, 6, timeout));
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(!maybe_bump_view(&mut rs, 6, timeout), "only 9s elapsed for height 6's own timer, not enough to bump");
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
        assert_eq!(protocol::block_canon(&block), expected);
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

    fn test_ctx_with_one_peer() -> (Ctx, ed25519_dalek::SigningKey, ed25519_dalek::SigningKey) {
        use crate::config::PeerConfig;
        let self_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let peer_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let config = NodeConfig {
            node_id: 0,
            dim: 2,
            listen_addr: "127.0.0.1:0".to_string(),
            license_path: String::new(),
            data_dir: String::new(),
            round_interval_secs: 1,
            metrics_addr: None,
            peers: vec![PeerConfig { id: 1, addr: "127.0.0.1:1".to_string(), pubkey_hex: hex::encode(peer_sk.verifying_key().to_bytes()) }],
        };
        let peers = HashMap::from([(1, PeerInfo { addr: "127.0.0.1:1".parse().unwrap(), pubkey: peer_sk.verifying_key() })]);
        let endpoint = net::make_client_endpoint().unwrap();
        let ctx = Ctx { config, peers, all_ids: vec![0, 1], endpoint, metrics: Arc::new(Metrics::new(&[1])) };
        (ctx, self_sk, peer_sk)
    }

    #[tokio::test]
    async fn verify_from_peer_accepts_a_genuinely_valid_signature() {
        let (ctx, _self_sk, peer_sk) = test_ctx_with_one_peer();
        let canon = protocol::observation_canon(1, &[1.0, 2.0]);
        let sig = crypto::sign_canon(&peer_sk, &canon);
        assert_eq!(ctx.metrics.peer_health(1).unwrap().seconds_since_last_seen(), None, "not seen yet");
        assert!(verify_from_peer(&ctx, 1, &canon, &hex::encode(sig.to_bytes())));
        assert!(ctx.metrics.peer_health(1).unwrap().seconds_since_last_seen().is_some(), "a genuine signature should mark the peer seen (Hardening 6)");
    }

    #[tokio::test]
    async fn verify_from_peer_does_not_mark_an_unauthenticated_sender_seen() {
        let (ctx, self_sk, _peer_sk) = test_ctx_with_one_peer();
        let canon = protocol::observation_canon(1, &[1.0, 2.0]);
        let forged_sig = crypto::sign_canon(&self_sk, &canon); // wrong key
        assert!(!verify_from_peer(&ctx, 1, &canon, &hex::encode(forged_sig.to_bytes())));
        assert_eq!(ctx.metrics.peer_health(1).unwrap().seconds_since_last_seen(), None, "a forged signature must never count as having seen the real peer 1");
    }

    #[tokio::test]
    async fn verify_from_peer_rejects_an_unconfigured_sender() {
        let (ctx, _self_sk, peer_sk) = test_ctx_with_one_peer();
        let canon = protocol::observation_canon(99, &[1.0, 2.0]);
        let sig = crypto::sign_canon(&peer_sk, &canon);
        assert!(!verify_from_peer(&ctx, 99, &canon, &hex::encode(sig.to_bytes())), "sender 99 isn't a configured peer");
    }

    #[tokio::test]
    async fn verify_from_peer_rejects_a_signature_from_the_wrong_key() {
        let (ctx, self_sk, _peer_sk) = test_ctx_with_one_peer();
        let canon = protocol::observation_canon(1, &[1.0, 2.0]);
        // Signed by node 0's own key, not peer 1's configured key - the
        // exact spoofing attempt this authentication closes.
        let forged_sig = crypto::sign_canon(&self_sk, &canon);
        assert!(!verify_from_peer(&ctx, 1, &canon, &hex::encode(forged_sig.to_bytes())));
    }

    #[tokio::test]
    async fn verify_from_peer_rejects_tampered_content_under_a_genuine_signature() {
        let (ctx, _self_sk, peer_sk) = test_ctx_with_one_peer();
        let real_canon = protocol::observation_canon(1, &[1.0, 2.0]);
        let sig = crypto::sign_canon(&peer_sk, &real_canon);
        let tampered_canon = protocol::observation_canon(1, &[1.0, 999.0]);
        assert!(!verify_from_peer(&ctx, 1, &tampered_canon, &hex::encode(sig.to_bytes())));
    }

    /// `broadcast()` fires sends as detached spawned tasks (Hardening
    /// 4's fix for the sequential-await bug) - this confirms the
    /// health bookkeeping added in Hardening 6 actually reaches
    /// `ctx.metrics` from inside that spawned task, against a real
    /// unreachable address (nothing listens on 127.0.0.1:1), not just
    /// that `PeerHealth`'s own counters work in isolation.
    #[tokio::test]
    async fn broadcast_records_a_real_send_failure_against_the_right_peer() {
        let (ctx, _self_sk, _peer_sk) = test_ctx_with_one_peer(); // peer 1 at 127.0.0.1:1
        assert_eq!(ctx.metrics.peer_health(1).unwrap().total_sends(), 0);

        broadcast(&ctx, &Message::Observation(ObservationMsg { sender: 0, values: vec![1.0], sig_hex: "aa".to_string() }));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            if ctx.metrics.peer_health(1).unwrap().total_sends() > 0 {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "broadcast's spawned send never completed within the connect timeout");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        assert_eq!(ctx.metrics.peer_health(1).unwrap().total_send_failures(), 1);
        assert_eq!(ctx.metrics.peer_health(1).unwrap().consecutive_send_failures(), 1);
    }

    #[tokio::test]
    async fn a_spoofed_observation_is_never_folded_into_this_nodes_state() {
        let (ctx, self_sk, _peer_sk) = test_ctx_with_one_peer();
        let dir = crate::test_support::TempDir::new("spoofed_observation");
        let store = Store::open(dir.path()).unwrap();
        let mut node = NodeState {
            node_id: 0,
            chain: vec![Block::genesis(2)],
            signing_key: self_sk.clone(),
            verifying_key: self_sk.verifying_key(),
            epoch: 0,
            edge_weight: HashMap::new(),
            reliability: HashMap::new(),
        };
        let mut rs = RoundState::default();

        // Claims to be peer 1 but is signed with node 0's own key.
        let fake_values = vec![999.0, 999.0];
        let canon = protocol::observation_canon(1, &fake_values);
        let forged_sig = crypto::sign_canon(&self_sk, &canon);
        let spoofed = Message::Observation(ObservationMsg { sender: 1, values: fake_values, sig_hex: hex::encode(forged_sig.to_bytes()) });

        on_message(&ctx, &mut node, &store, &mut rs, spoofed).await;

        assert!(!rs.latest_observations.contains_key(&1), "a forged observation must never be accepted as peer 1's real data");
    }

    /// The real property this stage exists to prove: once this node's
    /// accepted view for a height has moved past 0, a proposal signed
    /// for the abandoned view 0 - with a completely genuine signature
    /// from the correct proposer - is still rejected. Without the view
    /// check, this exact message would be replayable indefinitely.
    #[tokio::test]
    async fn a_proposal_signed_for_an_abandoned_view_is_rejected_despite_a_genuine_signature() {
        let (ctx, self_sk, peer_sk) = test_ctx_with_one_peer();
        let dir = crate::test_support::TempDir::new("stale_view_proposal");
        let store = Store::open(dir.path()).unwrap();

        let head = Block {
            height: 1,
            parent: "GENESIS".to_string(),
            state: vec![0.0, 0.0],
            confidence: 1.0,
            reconciles: vec![],
            epoch: 0,
            signatures: vec![],
            sig_weight: 1.0,
            hash: "head1".to_string(),
        };
        let mut node = NodeState {
            node_id: 0,
            chain: vec![Block::genesis(2), head.clone()],
            signing_key: self_sk.clone(),
            verifying_key: self_sk.verifying_key(),
            epoch: 0,
            edge_weight: HashMap::new(),
            reliability: HashMap::new(),
        };
        let mut rs = RoundState::default();
        // This node has already view-changed height 2 up to view 1 -
        // simulated directly since Hardening 4 is what will drive this
        // automatically; the rejection logic under test doesn't care
        // how the bump happened.
        rs.view_for_height.insert(2, 1);

        // Peer 1 is the real expected proposer for head.height=1
        // (all_ids=[0,1], 1 % 2 == 1), and genuinely signs at view 0 -
        // the view this node has already abandoned for height 2.
        let mut block = Block {
            height: 2,
            parent: head.hash.clone(),
            state: vec![1.0, 1.0],
            confidence: 0.9,
            reconciles: vec![],
            epoch: 0,
            signatures: vec![],
            sig_weight: 0.0,
            hash: String::new(),
        };
        let identity_canon = protocol::block_canon(&block);
        block.hash = chain::block_hash(&identity_canon);
        let stale_view = 0u64;
        let signing_canon = protocol::view_block_canon(stale_view, &block);
        let sig = crypto::sign_canon(&peer_sk, &signing_canon);
        block.signatures = vec![SigEntry {
            node_id: 1,
            pubkey_hex: hex::encode(peer_sk.verifying_key().to_bytes()),
            sig_hex: hex::encode(sig.to_bytes()),
        }];
        block.sig_weight = 1.0;

        handle_proposal(&ctx, &mut node, &store, &mut rs, BlockProposalMsg { sender: 1, view: stale_view, block }).await;

        assert!(rs.candidates.is_empty(), "a proposal signed for an abandoned view must never be cached as a live candidate");
    }

    /// The fix for the real bug the manual liveness test caught: nodes
    /// time out independently, so one node's view can legitimately run
    /// ahead of another's. A validly-signed proposal from the correct
    /// expected proposer at a *higher* view than this node has tracked
    /// must be accepted and adopted (catch-up), not rejected the same
    /// way a stale one is - otherwise two live nodes whose timeout
    /// clocks drift can reject each other's proposals forever and
    /// never converge.
    #[tokio::test]
    async fn a_proposal_at_a_higher_view_from_the_correct_proposer_is_accepted_and_adopted() {
        let (ctx, self_sk, peer_sk) = test_ctx_with_one_peer(); // self=0, peer=1, all_ids=[0,1]
        let dir = crate::test_support::TempDir::new("view_catch_up");
        let store = Store::open(dir.path()).unwrap();

        let head = Block {
            height: 1,
            parent: "GENESIS".to_string(),
            state: vec![0.0, 0.0],
            confidence: 1.0,
            reconciles: vec![],
            epoch: 0,
            signatures: vec![],
            sig_weight: 1.0,
            hash: "head1".to_string(),
        };
        let mut node = NodeState {
            node_id: 0,
            chain: vec![Block::genesis(2), head.clone()],
            signing_key: self_sk.clone(),
            verifying_key: self_sk.verifying_key(),
            epoch: 0,
            edge_weight: HashMap::new(),
            reliability: HashMap::new(),
        };
        let mut rs = RoundState::default();
        assert_eq!(current_view(&rs, 2), 0, "this node hasn't tracked any view bump for height 2 yet");

        // Peer 1 is the real expected proposer for (height=2, view=1):
        // expected_proposer([0,1], 2, 1) == all_ids[(2+1)%2] == 1.
        let ahead_view = 1u64;
        assert_eq!(expected_proposer(&ctx.all_ids, 2, ahead_view), 1);

        let mut block = Block {
            height: 2,
            parent: head.hash.clone(),
            state: vec![2.0, 2.0],
            confidence: 0.9,
            reconciles: vec![],
            epoch: 0,
            signatures: vec![],
            sig_weight: 0.0,
            hash: String::new(),
        };
        let identity_canon = protocol::block_canon(&block);
        block.hash = chain::block_hash(&identity_canon);
        let signing_canon = protocol::view_block_canon(ahead_view, &block);
        let sig = crypto::sign_canon(&peer_sk, &signing_canon);
        block.signatures = vec![SigEntry {
            node_id: 1,
            pubkey_hex: hex::encode(peer_sk.verifying_key().to_bytes()),
            sig_hex: hex::encode(sig.to_bytes()),
        }];
        block.sig_weight = 1.0;

        handle_proposal(&ctx, &mut node, &store, &mut rs, BlockProposalMsg { sender: 1, view: ahead_view, block: block.clone() }).await;

        assert_eq!(current_view(&rs, 2), ahead_view, "this node should have caught up to the peer's higher view");
        // With only two participants, the proposer's own signature plus
        // this node's vote already meets quorum (2), so catch-up here
        // goes all the way to a real commit - not just passive caching
        // - which is the actually-correct end-to-end outcome.
        let committed = node.chain.last().expect("chain should have advanced");
        assert_eq!(committed.hash, block.hash, "the block from the higher view should be the one that committed");
        assert_eq!(committed.sig_weight, 2.0, "proposer's signature plus this node's vote");
    }

    /// Builds a `BlockProposalMsg` genuinely signed by `signer_sk` as
    /// `sender`, for the given height/parent/view, with `sig_weight`
    /// set afterward to whatever the test wants to claim (never covered
    /// by the signature - see the long comment in `handle_proposal`).
    fn signed_proposal(sender: usize, signer_sk: &ed25519_dalek::SigningKey, height: u64, parent: &str, view: u64, sig_weight: f64) -> BlockProposalMsg {
        let mut block = Block {
            height,
            parent: parent.to_string(),
            state: vec![height as f64, height as f64],
            confidence: 0.9,
            reconciles: vec![],
            epoch: 0,
            signatures: vec![],
            sig_weight: 0.0,
            hash: String::new(),
        };
        let identity_canon = protocol::block_canon(&block);
        block.hash = chain::block_hash(&identity_canon);
        let signing_canon = protocol::view_block_canon(view, &block);
        let sig = crypto::sign_canon(signer_sk, &signing_canon);
        block.signatures = vec![SigEntry {
            node_id: sender,
            pubkey_hex: hex::encode(signer_sk.verifying_key().to_bytes()),
            sig_hex: hex::encode(sig.to_bytes()),
        }];
        block.sig_weight = sig_weight;
        BlockProposalMsg { sender, view, block }
    }

    /// The bug this stage's own code review caught before any test
    /// did: the already-committed-height branch used to run
    /// `chain::prefer` and log a "SAFETY VIOLATION" off whatever a
    /// message claimed, before any signature was checked for that
    /// code path. A forged message - unrelated to any real peer key,
    /// garbage `sig_hex`, an inflated `sig_weight` - must now be
    /// rejected for being unauthenticated, never reach `prefer()`, and
    /// never increment `forks_total`.
    #[tokio::test]
    async fn a_forged_proposal_for_an_already_committed_height_never_triggers_a_safety_violation() {
        let (ctx, self_sk, _peer_sk) = test_ctx_with_one_peer();
        let dir = crate::test_support::TempDir::new("forged_already_committed");
        let store = Store::open(dir.path()).unwrap();

        let committed = Block {
            height: 1,
            parent: "GENESIS".to_string(),
            state: vec![0.0, 0.0],
            confidence: 0.5,
            reconciles: vec![],
            epoch: 0,
            signatures: vec![],
            sig_weight: 1.0,
            hash: "real-head-1".to_string(),
        };
        let mut node = NodeState {
            node_id: 0,
            chain: vec![Block::genesis(2), committed.clone()],
            signing_key: self_sk.clone(),
            verifying_key: self_sk.verifying_key(),
            epoch: 0,
            edge_weight: HashMap::new(),
            reliability: HashMap::new(),
        };
        let mut rs = RoundState::default();

        // Claims to be from peer 1, massively outweighs the real
        // commit, but carries a completely made-up signature - not
        // produced by peer 1's or anyone's real key.
        let mut forged = Block {
            height: 1,
            parent: "GENESIS".to_string(),
            state: vec![999.0, 999.0],
            confidence: 0.99,
            reconciles: vec![],
            epoch: 0,
            signatures: vec![SigEntry { node_id: 1, pubkey_hex: "ab".repeat(32), sig_hex: "cd".repeat(64) }],
            sig_weight: 1000.0,
            hash: String::new(),
        };
        let identity_canon = protocol::block_canon(&forged);
        forged.hash = chain::block_hash(&identity_canon);

        handle_proposal(&ctx, &mut node, &store, &mut rs, BlockProposalMsg { sender: 1, view: 0, block: forged }).await;

        assert_eq!(ctx.metrics.forks_total.load(Ordering::Relaxed), 0, "an unauthenticated message must never count as an observed fork");
        assert_eq!(node.chain.last().unwrap().hash, "real-head-1", "committed history must never be touched by an unverified message");
    }

    /// The flip side: a *genuinely* signed proposal from a real,
    /// configured peer, for an already-committed height, that
    /// `chain::prefer` ranks above what this node committed, must be
    /// detected and counted (so an operator watching `forks_total` can
    /// notice) - but still never auto-reorged. This is a real, if
    /// disclosed-as-narrow, use of `tri_sync_core::chain::prefer` in
    /// the live node loop.
    #[tokio::test]
    async fn a_genuinely_signed_conflicting_proposal_for_an_already_committed_height_is_detected_but_not_reorged() {
        let (ctx, self_sk, peer_sk) = test_ctx_with_one_peer();
        let dir = crate::test_support::TempDir::new("genuine_conflict_already_committed");
        let store = Store::open(dir.path()).unwrap();

        let committed = Block {
            height: 1,
            parent: "GENESIS".to_string(),
            state: vec![0.0, 0.0],
            confidence: 0.5,
            reconciles: vec![],
            epoch: 0,
            signatures: vec![],
            sig_weight: 1.0,
            hash: "real-head-1".to_string(),
        };
        let mut node = NodeState {
            node_id: 0,
            chain: vec![Block::genesis(2), committed.clone()],
            signing_key: self_sk.clone(),
            verifying_key: self_sk.verifying_key(),
            epoch: 0,
            edge_weight: HashMap::new(),
            reliability: HashMap::new(),
        };
        let mut rs = RoundState::default();

        // Genuinely signed by peer 1's real configured key, for the
        // same height, with a higher sig_weight than what actually
        // committed - `prefer()` ranks it above `committed`.
        let proposal = signed_proposal(1, &peer_sk, 1, "GENESIS", 0, 5.0);
        assert_ne!(proposal.block.hash, committed.hash, "must be a genuinely different block, not the same one re-sent");

        handle_proposal(&ctx, &mut node, &store, &mut rs, proposal).await;

        assert_eq!(ctx.metrics.forks_total.load(Ordering::Relaxed), 1, "a genuinely-authenticated conflicting commit must be counted");
        assert_eq!(node.chain.last().unwrap().hash, "real-head-1", "detecting the conflict must never silently rewrite already-committed history");
    }

    /// A genuinely signed proposal for an already-committed height
    /// that `prefer()` does NOT rank above what's already committed
    /// (lower sig_weight) must be silently ignored - not every
    /// authenticated re-proposal of an old height is a fork worth
    /// alarming about.
    #[tokio::test]
    async fn a_genuine_but_weaker_proposal_for_an_already_committed_height_is_silently_ignored() {
        let (ctx, self_sk, peer_sk) = test_ctx_with_one_peer();
        let dir = crate::test_support::TempDir::new("genuine_weaker_already_committed");
        let store = Store::open(dir.path()).unwrap();

        let committed = Block {
            height: 1,
            parent: "GENESIS".to_string(),
            state: vec![0.0, 0.0],
            confidence: 0.5,
            reconciles: vec![],
            epoch: 0,
            signatures: vec![],
            sig_weight: 5.0,
            hash: "real-head-1".to_string(),
        };
        let mut node = NodeState {
            node_id: 0,
            chain: vec![Block::genesis(2), committed.clone()],
            signing_key: self_sk.clone(),
            verifying_key: self_sk.verifying_key(),
            epoch: 0,
            edge_weight: HashMap::new(),
            reliability: HashMap::new(),
        };
        let mut rs = RoundState::default();

        let proposal = signed_proposal(1, &peer_sk, 1, "GENESIS", 0, 1.0);

        handle_proposal(&ctx, &mut node, &store, &mut rs, proposal).await;

        assert_eq!(ctx.metrics.forks_total.load(Ordering::Relaxed), 0, "a weaker competing block is not a safety violation worth counting");
        assert_eq!(node.chain.last().unwrap().hash, "real-head-1");
    }

    /// The structural claim documented in this module's doc comment:
    /// a single node can never locally commit two different blocks at
    /// the same height, because `maybe_commit`'s parent-hash check is
    /// re-evaluated against the live head on every call. Proven here
    /// by driving two competing, independently-proposed candidates for
    /// the same height through the real `handle_proposal`/`maybe_commit`
    /// path with a 1-of-1 quorum (`all_ids = [0]`), rather than just
    /// asserted from reading the code.
    #[tokio::test]
    async fn a_single_node_can_never_locally_double_commit_at_the_same_height() {
        let self_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let config = NodeConfig {
            node_id: 0,
            dim: 2,
            listen_addr: "127.0.0.1:0".to_string(),
            license_path: String::new(),
            data_dir: String::new(),
            round_interval_secs: 1,
            metrics_addr: None,
            peers: vec![],
        };
        let endpoint = net::make_client_endpoint().unwrap();
        let ctx = Ctx { config, peers: HashMap::new(), all_ids: vec![0], endpoint, metrics: Arc::new(Metrics::default()) };
        let dir = crate::test_support::TempDir::new("no_local_double_commit");
        let store = Store::open(dir.path()).unwrap();
        let mut node = NodeState {
            node_id: 0,
            chain: vec![Block::genesis(2)],
            signing_key: self_sk.clone(),
            verifying_key: self_sk.verifying_key(),
            epoch: 0,
            edge_weight: HashMap::new(),
            reliability: HashMap::new(),
        };
        let mut rs = RoundState::default();
        rs.latest_observations.insert(0, vec![1.0, 1.0]);

        let head = node.head().clone();
        propose_block(&ctx, &mut node, &store, &mut rs, &head, 0).await;
        assert_eq!(node.chain.len(), 2, "1-of-1 quorum should commit immediately");
        let first_hash = node.chain.last().unwrap().hash.clone();

        // A second, independently-proposed candidate for the exact
        // same (now-committed) height, with different content so it
        // hashes differently. If `maybe_commit` ever re-committed on
        // top of the already-advanced head, this would silently
        // double the chain length or overwrite history.
        rs.latest_observations.insert(0, vec![2.0, 2.0]);
        let still_head_at_height_0 = Block::genesis(2); // the pre-commit head, reused as the stale parent
        propose_block(&ctx, &mut node, &store, &mut rs, &still_head_at_height_0, 0).await;

        assert_eq!(node.chain.len(), 2, "a second candidate for an already-committed height must never be committed on top");
        assert_eq!(node.chain.last().unwrap().hash, first_hash, "the real committed block must be untouched");
    }

    /// Drives a real single-node (1-of-1 quorum) chain across a real
    /// epoch boundary through the actual propose/commit path, not by
    /// calling `chain::epoch_for_height` directly - proving
    /// `maybe_commit` really does update, persist, and log the
    /// rotation when it happens, and leaves `node.epoch` alone
    /// otherwise.
    #[tokio::test]
    async fn maybe_commit_rotates_and_persists_the_epoch_exactly_at_the_boundary() {
        let self_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let config = NodeConfig {
            node_id: 0,
            dim: 2,
            listen_addr: "127.0.0.1:0".to_string(),
            license_path: String::new(),
            data_dir: String::new(),
            round_interval_secs: 1,
            metrics_addr: None,
            peers: vec![],
        };
        let endpoint = net::make_client_endpoint().unwrap();
        let ctx = Ctx { config, peers: HashMap::new(), all_ids: vec![0], endpoint, metrics: Arc::new(Metrics::default()) };
        let dir = crate::test_support::TempDir::new("epoch_rotation_boundary");
        let store = Store::open(dir.path()).unwrap();
        let mut node = NodeState {
            node_id: 0,
            chain: vec![Block::genesis(2)],
            signing_key: self_sk.clone(),
            verifying_key: self_sk.verifying_key(),
            epoch: 0,
            edge_weight: HashMap::new(),
            reliability: HashMap::new(),
        };
        let mut rs = RoundState::default();
        rs.latest_observations.insert(0, vec![1.0, 1.0]);

        // Commit up through height BLOCKS_PER_EPOCH - 1: still epoch 0.
        for h in 1..chain::BLOCKS_PER_EPOCH {
            let head = node.head().clone();
            propose_block(&ctx, &mut node, &store, &mut rs, &head, 0).await;
            assert_eq!(node.chain.last().unwrap().height, h);
            assert_eq!(node.chain.last().unwrap().epoch, 0, "height {h} should still be epoch 0");
            assert_eq!(node.epoch, 0);
        }
        assert_eq!(store.get_epoch().unwrap(), None, "nothing has rotated yet, so nothing new should be persisted beyond genesis's implicit 0");

        // This commit lands exactly on height BLOCKS_PER_EPOCH - the
        // real rotation.
        let head = node.head().clone();
        propose_block(&ctx, &mut node, &store, &mut rs, &head, 0).await;
        let committed = node.chain.last().unwrap();
        assert_eq!(committed.height, chain::BLOCKS_PER_EPOCH);
        assert_eq!(committed.epoch, 1, "this height belongs to epoch 1");
        assert_eq!(node.epoch, 1, "maybe_commit should have updated node.epoch to match");
        assert_eq!(store.get_epoch().unwrap(), Some(1), "the rotation must be persisted, not just held in memory");

        // One more commit just past the boundary: epoch should stay at
        // 1, not keep incrementing every block.
        let head = node.head().clone();
        propose_block(&ctx, &mut node, &store, &mut rs, &head, 0).await;
        assert_eq!(node.chain.last().unwrap().epoch, 1);
        assert_eq!(node.epoch, 1);
    }

    #[test]
    fn reconcile_epoch_with_chain_corrects_a_stale_persisted_epoch_to_match_height() {
        let self_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let dir = crate::test_support::TempDir::new("reconcile_epoch_stale");
        let store = Store::open(dir.path()).unwrap();
        let tall_block = Block { height: chain::BLOCKS_PER_EPOCH * 2, parent: "GENESIS".to_string(), ..Block::genesis(2) };
        let mut node = NodeState {
            node_id: 0,
            chain: vec![Block::genesis(2), tall_block],
            signing_key: self_sk.clone(),
            verifying_key: self_sk.verifying_key(),
            epoch: 0, // stale - the loaded chain's height says this should be epoch 2
            edge_weight: HashMap::new(),
            reliability: HashMap::new(),
        };

        reconcile_epoch_with_chain(&mut node, &store);

        assert_eq!(node.epoch, 2, "should be corrected to match the real chain height, not left at the stale loaded value");
        assert_eq!(store.get_epoch().unwrap(), Some(2), "the correction must be persisted too");
    }

    #[test]
    fn reconcile_epoch_with_chain_is_a_no_op_when_already_consistent() {
        let self_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let dir = crate::test_support::TempDir::new("reconcile_epoch_consistent");
        let store = Store::open(dir.path()).unwrap();
        let mut node = NodeState {
            node_id: 0,
            chain: vec![Block::genesis(2)],
            signing_key: self_sk.clone(),
            verifying_key: self_sk.verifying_key(),
            epoch: 0,
            edge_weight: HashMap::new(),
            reliability: HashMap::new(),
        };

        reconcile_epoch_with_chain(&mut node, &store);

        assert_eq!(node.epoch, 0);
        assert_eq!(store.get_epoch().unwrap(), None, "nothing to correct, so nothing should be written");
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
            metrics_addr: None,
            peers: vec![PeerConfig { id: 1, addr: addr_b.to_string(), pubkey_hex: hex::encode(sk_b.verifying_key().to_bytes()) }],
        };
        let config_b = NodeConfig {
            node_id: 1,
            dim: 2,
            listen_addr: addr_b.to_string(),
            license_path: String::new(),
            data_dir: String::new(),
            round_interval_secs: 1,
            metrics_addr: None,
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
        let metrics_a = Arc::new(Metrics::default());
        let metrics_b = Arc::new(Metrics::default());
        tokio::join!(
            run(config_a, node_a, store_a, client_a, rx_a, Some(duration), metrics_a.clone()),
            run(config_b, node_b, store_b, client_b, rx_b, Some(duration), metrics_b.clone())
        );

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

        let last_a = blocks_a.last().unwrap();
        let last_b = blocks_b.last().unwrap();
        assert_eq!(metrics_a.head_height.load(Ordering::Relaxed), last_a.height, "metrics head_height should track the real committed chain");
        assert_eq!(metrics_b.head_height.load(Ordering::Relaxed), last_b.height);
        assert!(metrics_a.mean_trust_weight() > 0.0, "trust toward the peer should have grown from real observations");
        assert!(metrics_b.mean_trust_weight() > 0.0);
    }
}
