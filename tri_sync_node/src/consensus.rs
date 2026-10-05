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
//!   committed block crosses into a new one. It still deliberately
//!   does NOT tie the *signing key* to chain epoch - rotating that is
//!   a separate, on-demand action (see the next point), not something
//!   that happens automatically at an epoch boundary.
//! - Peer public keys start from `node.toml`, but aren't static
//!   anymore (Hardening 8): `--rotate-key` lets an operator generate a
//!   new identity for this node and announce it to every configured
//!   peer, signed by the *old* key to prove continuity;
//!   `handle_key_rotation` is the receiving side, which verifies that
//!   proof, updates its live `ctx.peers` entry, and persists it so a
//!   restart doesn't need to relearn it. A strictly-increasing
//!   `rotation_seq` per sender stops a captured announcement from
//!   being replayed later to roll a peer's trusted key back to a
//!   since-superseded one. Disclosed as narrow, not full membership
//!   management: this only ever updates the key of an *existing*,
//!   already-configured peer id - it doesn't add, remove, or discover
//!   peers, doesn't retry a rotation a peer missed while offline, and
//!   doesn't touch `all_ids`/quorum/`network_size`, all of which stay
//!   exactly as `node.toml` originally described. Real dynamic
//!   membership change is a much harder, separate problem (safely
//!   changing who counts toward quorum needs its own agreement
//!   protocol) and staying out of that is deliberate, not an oversight.
//!   A real bug surfaced by an actual two-process rotation test (not a
//!   unit test - the in-process ones all passed first try): rotating
//!   while the rotating node's own old process was still running let
//!   it keep signing with the old key for a few more seconds, which
//!   peers now correctly rejected (including that node's own vote on
//!   a block a peer was mid-committing) - and since catching up on an
//!   already-committed height a node is *behind* on isn't something
//!   this node loop can do (only being behind on *view* has a
//!   catch-up path, in `handle_proposal`/`handle_vote` below), that
//!   peer got stuck on that height permanently. Not fixed by adding
//!   chain-sync here (out of scope for this pass); fixed by requiring
//!   the operator to stop the old process before rotating, which a
//!   live rerun of the same two-process scenario confirmed resolves
//!   it completely - see `main`'s `--rotate-key` doc comment.
//! - Liveness fallback (`maybe_bump_view` hands off to the next
//!   proposer after a timeout, with catch-up so a lagging node adopts
//!   a legitimate later view instead of rejecting it) is now backed by
//!   a real two-phase quorum-certificate lock, closing what used to be
//!   a disclosed safety gap rather than just documenting it. The old
//!   design let a single-phase vote's mere existence nudge a node
//!   toward a view it hadn't independently verified was genuinely
//!   supported, which in an adversarial or badly-partitioned network
//!   left a real window where votes could split across two views'
//!   candidates for the same height. The fix: a **prevote** (what used
//!   to be called a "vote" - `handle_vote`/`BlockVoteMsg`, unchanged on
//!   the wire) never commits anything by itself. Only once a node's
//!   own prevote tally for a (block_hash, view) pair reaches quorum -
//!   a genuine "polka", proof the network actually supports it, not
//!   just a claim - does that node **lock** onto it
//!   (`RoundState::locked`, persisted via `persistence::LockRecord` so
//!   a restart can't forget) and cast a **precommit**
//!   (`handle_precommit`/`PrecommitMsg`), signed over a
//!   domain-separated string (`protocol::precommit_canon`) that a
//!   prevote signature can never be replayed into. A block only
//!   commits once its *precommit* tally - not its prevote tally -
//!   reaches quorum (`maybe_commit`). Once locked on a height, a node
//!   refuses to prevote for a different candidate there unless it
//!   independently observes a prevote QC for that different candidate
//!   first (`maybe_cast_own_prevote`) - it can be outvoted, but never
//!   talked into switching by a bare, unverified claim. Prevote/
//!   precommit tallies are kept per (hash, view) pair, never merged
//!   across views for the same content, so a signature made for one
//!   view can never be counted toward a different view's quorum even
//!   when the block content is byte-identical (`RoundState::prevotes`/
//!   `precommits`'s doc comments); `legitimate_rounds` closes the
//!   generalization of the single-tally escalating-fake-vote bug an
//!   earlier adversarial-review pass fixed, across this new per-view
//!   keying. What this closes, concretely, and what a dedicated test
//!   (`locking_prevents_two_conflicting_blocks_from_both_reaching_a_precommit_quorum_certificate`)
//!   proves rather than just asserts: two disjoint candidates for the
//!   same height can no longer both reach a precommit QC, even when a
//!   node that already locked on one later receives a fully-valid,
//!   correctly-signed proposal for the other at a higher view - it
//!   caches and tallies that proposal (so the network *can* still
//!   reach quorum on it, preserving liveness) but withholds its own
//!   prevote until that tally itself proves a real polka. One
//!   deliberately bounded, honestly-narrower liveness tradeoff this
//!   makes (never a safety one): a node that's locked on a height,
//!   should it become that height's next proposer after a view-change
//!   timeout, does not self-re-propose its locked content - it simply
//!   defers proposing that round (`propose_block`'s early return) and
//!   waits for its lock to resolve via normal quorum-certificate
//!   gossip, or to be unlocked by a genuine polka for something else.
//!   Never fuses and proposes a *fresh* candidate while locked, which
//!   is the one thing that would be unsafe.
//! - Per-peer health (`crate::health`) is tracked and exposed via
//!   `/metrics`, but purely observationally: it never changes who
//!   gets proposed to, voted for, or sent messages. Deliberately not
//!   wired into behavior - see that module's doc comment for why.
//! - Operational hardening (Hardening 9): `run`'s loop now handles
//!   SIGTERM/SIGINT, logging and exiting cleanly instead of relying on
//!   `--duration` or a bare SIGKILL - the difference between a real
//!   deployment (`systemd`/`docker stop`) being able to tell "stopped"
//!   from "crashed" or not. Every `log`/`warn` line is now prefixed
//!   with a UTC timestamp (`log_timestamp`, reusing `crate::license`'s
//!   dependency-free calendar math) - added directly because of a real
//!   debugging session (Hardening 8's live rotation test) where
//!   correlating two unstamped node logs by eye was slow enough to
//!   nearly obscure the actual bug.
//! - `RoundState`'s `candidates`/`prevotes`/`precommits` maps are now
//!   capped (`MAX_CANDIDATES_PER_HEIGHT`, in `handle_proposal`): a
//!   legitimate-but-malicious expected proposer flooding many distinct
//!   signed proposals for one (height, view) used to grow those maps
//!   without bound, since nothing prunes them until the height
//!   actually commits. A new hash is dropped once the current height
//!   already has `MAX_CANDIDATES_PER_HEIGHT` distinct candidates
//!   cached; a repeat of an already-cached hash is unaffected, so its
//!   vote tally can still reach quorum normally. The cap is sized to
//!   absorb several honest view-changes' worth of legitimate
//!   candidates, not just one.

use crate::config::NodeConfig;
use crate::health;
use crate::license;
use crate::metrics::Metrics;
use crate::net;
use crate::persistence::{LockRecord, PeerKeyRecord, Store, TrustEntry};
use crate::protocol::{self, BlockProposalMsg, BlockVoteMsg, KeyRotationMsg, Message, ObservationMsg, PrecommitMsg, TrustUpdateMsg};
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

/// Caps how many distinct candidate block hashes `RoundState` will ever
/// track for a single height at once - see `handle_proposal`'s use of
/// it, and the module doc comment's note on the resource-exhaustion
/// vector this closes. Sized generously enough for several honest
/// view-changes to each leave behind their own legitimate candidate
/// (a real, if unusual, pattern - not just the attack), while still
/// bounding a *malicious* expected proposer's ability to flood many
/// distinct signed proposals for one (height, view) into unbounded
/// memory growth.
const MAX_CANDIDATES_PER_HEIGHT: usize = 8;
const TRIM_FRAC: f64 = 0.2;
const RELIABILITY_ALPHA: f64 = 0.3;
const RELIABILITY_FLOOR: f64 = 0.05;
const RELIABILITY_CEIL: f64 = 1.0;
const EDGE_ALPHA: f64 = 1.0;
const EDGE_FLOOR: f64 = 0.02;
const EDGE_CEIL: f64 = 3.0;

/// `rotation_seq` is 0 for a peer still on its `node.toml`-configured
/// key; a successful `handle_key_rotation` bumps it and replaces
/// `pubkey` in place - see `crate::protocol`'s doc comment on
/// `KeyRotationMsg` for why that's safe against replay.
#[derive(Debug, Clone, Copy)]
struct PeerInfo {
    addr: SocketAddr,
    pubkey: VerifyingKey,
    rotation_seq: u64,
}

struct Ctx {
    config: NodeConfig,
    /// Mutable at runtime (Hardening 8's key rotation), unlike every
    /// other `Ctx` field - a `std::sync::RwLock`, not `tokio::sync`,
    /// since every access here is a quick read-or-write with no `.await`
    /// held across the lock (see `broadcast`'s snapshot-then-drop
    /// pattern for why that matters to keep true).
    peers: std::sync::RwLock<HashMap<usize, PeerInfo>>,
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
    /// Cached block content by hash - content only, not paired with a
    /// single view. Deliberately so: the *same* block content can be
    /// legitimately proposed/prevoted for at more than one view over
    /// its lifetime (e.g. a locked node re-proposing nothing new, or a
    /// slow network re-delivering an earlier proposal) - see
    /// `legitimate_rounds` for how a specific (hash, view) pairing is
    /// told apart from an arbitrary one. Kept until superseded by a
    /// committed block at the same or greater height.
    candidates: HashMap<String, Block>,
    /// The (block_hash, view) pairs this node has seen a genuinely
    /// legitimate proposal for - i.e. correctly signed by that view's
    /// `expected_proposer`, over `view_block_canon(view, block)`.
    /// A prevote or precommit for a pair *not* in this set is dropped
    /// outright, regardless of whether `block_hash` is separately
    /// cached in `candidates`: nothing has established that a real
    /// round at that specific view ever happened, so counting it
    /// would let a single signer manufacture quorum evidence out of
    /// nothing - generalizes, across views, the same fix an earlier
    /// adversarial-review pass made for the single-tally design (see
    /// `handle_vote`'s history).
    legitimate_rounds: std::collections::HashSet<(String, u64)>,
    /// Prevote tally per (block_hash, view) - signatures over
    /// `protocol::view_block_canon(view, block)`. Kept separate per
    /// view (not merged into one tally per hash) so a signature made
    /// for one view can never be counted toward another's quorum,
    /// even for byte-identical block content.
    prevotes: HashMap<(String, u64), Vec<SigEntry>>,
    /// Precommit tally per (block_hash, view) - signatures over
    /// `protocol::precommit_canon(view, block)`, a domain-separated
    /// string distinct from what a prevote signs, so a prevote
    /// signature can never be replayed as a precommit. A block only
    /// ever commits once ITS precommit tally (not its prevote tally)
    /// reaches quorum - see `maybe_precommit`/`maybe_commit` and this
    /// module's doc comment on quorum-certificate locking.
    precommits: HashMap<(String, u64), Vec<SigEntry>>,
    /// The (view, block_hash) this node is currently locked on, per
    /// height - set only once this node has itself verified a real
    /// prevote *quorum certificate* ("polka") for it, in
    /// `maybe_precommit`. Once locked, this node will not prevote for
    /// a different candidate at this height without independently
    /// observing a prevote QC for that different candidate first -
    /// see `maybe_cast_own_prevote`. This is the mechanism that closes
    /// the safety gap this module used to disclose: a vote's mere
    /// existence is no longer ever enough, on its own, to nudge a
    /// node toward a view it hasn't independently verified is
    /// genuinely supported by quorum.
    locked: HashMap<u64, (u64, String)>,
    /// The (height, view) pairs this node has itself proposed at -
    /// prevents `on_tick` from re-proposing (and re-broadcasting) at
    /// the same round on every tick until the view actually advances.
    proposed_rounds: std::collections::HashSet<(u64, u64)>,
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
    let Some(peer) = ctx.peers.read().unwrap().get(&sender).copied() else { return false };
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
    // Snapshot and drop the lock immediately rather than hold a read
    // guard across the loop (let alone into a spawned task): a
    // key-rotation write must never be blocked behind, or forced to
    // wait on, however long a round of sends takes.
    let snapshot: Vec<(usize, PeerInfo)> = ctx.peers.read().unwrap().iter().map(|(&id, &info)| (id, info)).collect();
    for (id, peer) in snapshot {
        let endpoint = ctx.endpoint.clone();
        let addr = peer.addr;
        let pubkey = peer.pubkey;
        let msg = msg.clone();
        let metrics = ctx.metrics.clone();
        tokio::spawn(async move {
            // Pinned to this peer's currently-known identity (its
            // node.toml pubkey, or whatever a later key rotation
            // superseded it with - see crate::net's doc comment) -
            // never the unpinned opt-out, on the one path real traffic
            // actually takes.
            let ok = match net::send_message(&endpoint, addr, Some(pubkey), &msg).await {
                Ok(()) => true,
                Err(e) => {
                    warn(format!("send to {addr} failed: {e}"));
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

/// `YYYY-MM-DDTHH:MM:SSZ`, UTC, built from the same dependency-free
/// calendar math `crate::license` already uses for expiry checks
/// (`license::civil_from_days`) rather than pulling in a date/time
/// crate just to stamp log lines.
///
/// Added after a real debugging session (Hardening 8's rotation live
/// test) where correlating two separate nodes' unstamped log files by
/// eye - "did this rejection happen before or after that restart?" -
/// was slow and error-prone enough to nearly hide the actual bug.
fn log_timestamp() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let (y, m, d) = license::civil_from_days((secs / 86_400) as i64);
    let sod = secs % 86_400;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", sod / 3600, (sod % 3600) / 60, sod % 60)
}

fn log(line: impl std::fmt::Display) {
    println!("{} tri_sync_node: {line}", log_timestamp());
    let _ = std::io::stdout().flush();
}

/// Same timestamp prefix as `log`, for the warning/rejection paths
/// that go to stderr instead - so a rejection can be correlated by
/// time against another node's log just as easily as a success.
fn warn(line: impl std::fmt::Display) {
    eprintln!("{} tri_sync_node: {line}", log_timestamp());
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
    // A persisted PeerKeyRecord (a rotation this node already accepted
    // in some earlier run) always wins over node.toml's original entry
    // - that's the whole point of persisting it in handle_key_rotation:
    // an operator never has to manually edit every peer's config file
    // again after the first time a rotation is learned.
    let peers: HashMap<usize, PeerInfo> = config
        .peers
        .iter()
        .map(|p| {
            let addr = p.addr.parse().expect("validated at config load");
            match store.get_peer_key(p.id) {
                Ok(Some(record)) => match decode_verifying_key(&record.pubkey_hex) {
                    Some(pubkey) => {
                        log(format!("peer {} loaded with its rotated key (rotation_seq={})", p.id, record.rotation_seq));
                        return (p.id, PeerInfo { addr, pubkey, rotation_seq: record.rotation_seq });
                    }
                    None => warn(format!("persisted key for peer {} is corrupt, falling back to node.toml", p.id)),
                },
                Ok(None) => {}
                Err(e) => warn(format!("failed to read persisted key for peer {}: {e} - falling back to node.toml", p.id)),
            }
            let pubkey = decode_verifying_key(&p.pubkey_hex).expect("validated at config load");
            (p.id, PeerInfo { addr, pubkey, rotation_seq: 0 })
        })
        .collect();
    let mut all_ids: Vec<usize> = peers.keys().cloned().chain(std::iter::once(node.node_id)).collect();
    all_ids.sort_unstable();

    metrics.head_height.store(node.head().height, Ordering::Relaxed);
    reconcile_epoch_with_chain(&mut node, &store);
    metrics.epoch.store(node.epoch, Ordering::Relaxed);

    let ctx = Ctx { config, peers: std::sync::RwLock::new(peers), all_ids, endpoint, metrics };
    let mut rs = RoundState::default();
    // Restore this node's quorum-certificate lock across a restart -
    // forgetting it would let this node re-prevote for a conflicting
    // block at the same height, reopening exactly the safety gap
    // locking exists to close. A record for a height this node has
    // already committed past (or that simply doesn't match the
    // in-flight height) is stale and ignored - see
    // `persistence::LockRecord`'s doc comment for why only one height
    // is ever in flight at a time.
    match store.get_lock() {
        Ok(Some(record)) if record.height == node.head().height + 1 => {
            log(format!(
                "restored lock on height={} view={} hash={} from a previous run",
                record.height, record.view, record.block_hash
            ));
            rs.locked.insert(record.height, (record.view, record.block_hash));
        }
        Ok(_) => {}
        Err(e) => warn(format!("failed to read persisted lock: {e} - starting unlocked")),
    }
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

    // Operational hardening: a real deployment is stopped by `systemd`/
    // `docker stop`/an operator's `kill`, all of which send SIGTERM
    // first - without a handler, that's indistinguishable from a crash
    // (no "shutting down cleanly" log, no chance to do so) and only
    // SIGKILL after the grace period actually stops the process. SIGINT
    // (Ctrl+C) is handled the same way for an operator running this in
    // a foreground terminal. Unix-only (SIGTERM has no Windows
    // equivalent); this project's CI matrix is Linux/macOS, both Unix.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("installing a SIGTERM handler should never fail outside extreme resource exhaustion");

    loop {
        tokio::select! {
            _ = &mut deadline_sleep => {
                log("--duration elapsed, shutting down cleanly.");
                break;
            }
            _ = sigterm.recv() => {
                log("received SIGTERM, shutting down cleanly.");
                break;
            }
            _ = tokio::signal::ctrl_c() => {
                log("received SIGINT, shutting down cleanly.");
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
    if proposer == node.node_id && !rs.proposed_rounds.contains(&(next_height, view)) {
        propose_block(ctx, node, store, rs, &head, view).await;
    }
}

async fn propose_block(ctx: &Ctx, node: &mut NodeState, store: &Store, rs: &mut RoundState, head: &Block, view: u64) {
    let next_height = head.height + 1;

    // A node that's locked on this height (a real prevote quorum
    // certificate was observed for some candidate here - see
    // `maybe_precommit`) must never fuse and propose a *fresh*
    // candidate while locked: that could never reach a prevote QC
    // past every other locked node's own refusal to prevote for a
    // conflicting value without first seeing one (`maybe_cast_own_prevote`),
    // so it would just waste a slot in the `MAX_CANDIDATES_PER_HEIGHT`
    // cap. Re-proposing the exact locked content would be safe, but
    // is deliberately not attempted here either - a narrower, honestly
    // bounded liveness tradeoff (never a safety one) documented in
    // this module's doc comment. Simplest correct behavior: defer
    // proposing this round and let the lock resolve via normal
    // quorum-certificate gossip, or be unlocked by a genuine polka for
    // something else.
    if let Some((locked_view, locked_hash)) = rs.locked.get(&next_height) {
        log(format!(
            "height={next_height}: this node is locked on {locked_hash} (view={locked_view}) - deferring this proposer turn (view={view}) rather than proposing a fresh candidate while locked"
        ));
        rs.proposed_rounds.insert((next_height, view));
        return;
    }

    let ids: Vec<usize> = rs.latest_observations.keys().cloned().collect();
    let values: Vec<Vec<f64>> = ids.iter().map(|id| rs.latest_observations[id].clone()).collect();
    let weights: Vec<f64> =
        ids.iter().map(|&id| if id == node.node_id { 1.0 } else { *node.reliability.get(&id).unwrap_or(&0.5) }).collect();

    let fused = fusion::trimmed_fuse(&values, &weights, TRIM_FRAC);
    let spread = values.iter().map(|v| fusion::l2_distance(v, &fused)).sum::<f64>() / values.len() as f64;
    let confidence = (1.0 / (1.0 + spread)).clamp(0.0, 1.0);

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

    rs.candidates.insert(block.hash.clone(), block.clone());
    rs.legitimate_rounds.insert((block.hash.clone(), view));
    rs.prevotes.entry((block.hash.clone(), view)).or_default().push(my_entry);
    rs.proposed_rounds.insert((next_height, view));

    broadcast(ctx, &Message::BlockProposal(BlockProposalMsg { sender: node.node_id, view, block: block.clone() }));
    maybe_precommit(ctx, node, store, rs, &block.hash, view).await;
}

async fn on_message(ctx: &Ctx, node: &mut NodeState, store: &Store, rs: &mut RoundState, msg: Message) {
    match msg {
        Message::Observation(o) => {
            let canon = protocol::observation_canon(o.sender, &o.values);
            if verify_from_peer(ctx, o.sender, &canon, &o.sig_hex) {
                rs.latest_observations.insert(o.sender, o.values);
            } else {
                warn(format!("rejected observation from {} - unknown sender or invalid signature", o.sender));
            }
        }
        Message::BlockProposal(p) => handle_proposal(ctx, node, store, rs, p).await,
        Message::BlockVote(v) => handle_vote(ctx, node, store, rs, v).await,
        Message::Precommit(pc) => handle_precommit(ctx, node, store, rs, pc).await,
        Message::TrustUpdate(t) => {
            let canon = protocol::trust_update_canon(t.sender, t.about_peer, t.edge_weight);
            if verify_from_peer(ctx, t.sender, &canon, &t.sig_hex) {
                log(format!("peer {} reports edge_weight {:.3} toward peer {}", t.sender, t.edge_weight, t.about_peer));
            } else {
                warn(format!("rejected trust-update from {} - unknown sender or invalid signature", t.sender));
            }
        }
        // Informational only in this stage - nothing acts on a peer's
        // broadcast state yet - but still authenticated so a bad
        // signature is visible rather than silently accepted.
        Message::State(s) => {
            let canon = protocol::state_canon(s.sender, &s.state, s.confidence);
            if !verify_from_peer(ctx, s.sender, &canon, &s.sig_hex) {
                warn(format!("rejected state broadcast from {} - unknown sender or invalid signature", s.sender));
            }
        }
        Message::KeyRotation(k) => handle_key_rotation(ctx, store, k).await,
    }
}

/// Accepts a peer's self-announced key rotation if (a) the sender is
/// already a known peer, (b) `rotation_seq` is strictly ahead of the
/// last one accepted from them (replay/rollback protection - see
/// `crate::protocol::KeyRotationMsg`'s doc comment), and (c) the
/// signature verifies against the sender's *currently* trusted key,
/// proving continuity from the old identity to the new one. On
/// success, updates the live `ctx.peers` entry immediately and
/// persists it so a future restart doesn't need to relearn it.
async fn handle_key_rotation(ctx: &Ctx, store: &Store, msg: KeyRotationMsg) {
    let KeyRotationMsg { sender, new_pubkey_hex, rotation_seq, sig_hex } = msg;

    let Some(current) = ctx.peers.read().unwrap().get(&sender).copied() else {
        warn(format!("ignoring key rotation from unknown peer {sender}"));
        return;
    };
    if rotation_seq <= current.rotation_seq {
        eprintln!(
            "tri_sync_node: ignoring stale or replayed key rotation from {sender} (seq {rotation_seq} <= already-accepted {})",
            current.rotation_seq
        );
        return;
    }
    let Some(sig) = decode_signature(&sig_hex) else { return };
    let canon = protocol::key_rotation_canon(sender, &new_pubkey_hex, rotation_seq);
    if !crypto::verify_canon(&current.pubkey, &canon, &sig) {
        warn(format!("invalid key-rotation signature from {sender} - rejecting, keeping the current key"));
        return;
    }
    let Some(new_pubkey) = decode_verifying_key(&new_pubkey_hex) else {
        warn(format!("key rotation from {sender} carries an unparseable new pubkey - rejecting"));
        return;
    };

    {
        let mut peers = ctx.peers.write().unwrap();
        if let Some(info) = peers.get_mut(&sender) {
            info.pubkey = new_pubkey;
            info.rotation_seq = rotation_seq;
        }
    }
    if let Err(e) = store.put_peer_key(sender, &PeerKeyRecord { pubkey_hex: new_pubkey_hex, rotation_seq }) {
        warn(format!("accepted key rotation from {sender} in memory but failed to persist it: {e}"));
    }
    log(format!("accepted key rotation from peer {sender}: now trusting its new key (rotation_seq={rotation_seq})"));
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
    let Some(peer) = ctx.peers.read().unwrap().get(&p.sender).copied() else {
        warn(format!("ignoring proposal from unknown sender {}", p.sender));
        return;
    };
    let Some(their_sig_entry) = p.block.signatures.first() else { return };
    let Some(sig) = decode_signature(&their_sig_entry.sig_hex) else { return };
    let identity_canon = protocol::block_canon(&p.block);
    let signing_canon = protocol::view_block_canon(p.view, &p.block);
    if !crypto::verify_canon(&peer.pubkey, &signing_canon, &sig) {
        warn(format!("invalid proposer signature from {}", p.sender));
        return;
    }
    let block_hash = chain::block_hash(&identity_canon);
    if block_hash != p.block.hash {
        warn(format!("proposal hash mismatch from {}", p.sender));
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
        warn(format!("ignoring proposal from {} - expected proposer for view {} is {}", p.sender, p.view, expected));
        return;
    }

    if p.view > current_view(rs, p.block.height) {
        log(format!("catching up: adopting view={} for height={} from proposer {}", p.view, p.block.height, p.sender));
        rs.view_for_height.insert(p.block.height, p.view);
        rs.waiting_for = Some((p.block.height, p.view));
        rs.waiting_since = Some(tokio::time::Instant::now());
    }

    let is_new_fork =
        !rs.candidates.contains_key(&block_hash) && rs.candidates.values().any(|b| b.height == p.block.height && b.hash != block_hash);
    if is_new_fork {
        ctx.metrics.forks_total.fetch_add(1, Ordering::Relaxed);
        log(format!("fork observed at height={}: competing candidate {block_hash}", p.block.height));
    }
    // Closes a real, disclosed resource-exhaustion vector: a
    // legitimate-but-malicious expected proposer is still free to sign
    // many *distinct* blocks for the same (height, view) - nothing
    // above this point depends on content, only on who's allowed to
    // propose - and each distinct hash would otherwise grow
    // `candidates`/`prevotes`/`precommits` forever, since none of them
    // are pruned until the height actually commits (see
    // `maybe_commit`). Only a brand-new hash is capped; a repeat of
    // one already cached still proceeds below so its tallies can keep
    // growing toward quorum.
    if !rs.candidates.contains_key(&block_hash) {
        let distinct_at_height = rs.candidates.values().filter(|b| b.height == p.block.height).count();
        if distinct_at_height >= MAX_CANDIDATES_PER_HEIGHT {
            warn(format!(
                "dropping proposal from {} for height {} - already tracking {MAX_CANDIDATES_PER_HEIGHT} distinct \
                 candidates there (resource-exhaustion cap)",
                p.sender, p.block.height
            ));
            return;
        }
    }
    rs.candidates.entry(block_hash.clone()).or_insert_with(|| p.block.clone());
    // This (hash, view) pair is now legitimate: a correctly-signed
    // proposal from this view's real expected proposer established it
    // - see `RoundState::legitimate_rounds`'s doc comment for why a
    // prevote/precommit for a pair that never passed through here is
    // dropped outright, regardless of whether the hash alone is known.
    rs.legitimate_rounds.insert((block_hash.clone(), p.view));
    let tally = rs.prevotes.entry((block_hash.clone(), p.view)).or_default();
    if !tally.iter().any(|e| e.node_id == p.sender) {
        tally.push(their_sig_entry.clone());
    }

    maybe_cast_own_prevote(ctx, node, rs, p.block.height, p.view, &block_hash, &signing_canon);
    maybe_precommit(ctx, node, store, rs, &block_hash, p.view).await;
}

async fn handle_vote(ctx: &Ctx, node: &mut NodeState, store: &Store, rs: &mut RoundState, v: BlockVoteMsg) {
    let known_pubkey =
        if v.sender == node.node_id { Some(node.verifying_key) } else { ctx.peers.read().unwrap().get(&v.sender).map(|p| p.pubkey) };
    let Some(known_pubkey) = known_pubkey else { return };
    let Some(claimed_pubkey) = decode_verifying_key(&v.pubkey_hex) else { return };
    if claimed_pubkey != known_pubkey {
        warn(format!("vote from {} claims an unexpected pubkey", v.sender));
        return;
    }

    let Some(block) = rs.candidates.get(&v.block_hash).cloned() else {
        return; // vote arrived before the proposal - dropped; no retry in this stage
    };
    // A real bug, found by a focused adversarial review (not a test):
    // this used to accept any v.view >= current_view and, if strictly
    // greater, adopt it as the new current view - treating the vote's
    // own view claim as evidence a round at that view genuinely
    // happened. It doesn't: a vote is self-signed by the voter alone,
    // who can freely construct view_block_canon(view, block) for any
    // view number over any block they already know about, with no
    // proposer ever actually proposing at that view. That let a single
    // authenticated-but-malicious peer manufacture an endless stream of
    // escalating "votes" that kept resetting every honest node's
    // view-change timeout, so quorum could never form.
    //
    // The fix (now generalized across views - a candidate's content
    // can legitimately be prevoted-for at more than one view over its
    // lifetime, see `RoundState::legitimate_rounds`'s doc comment):
    // a vote's (block_hash, view) pair must itself be one
    // `handle_proposal` already marked legitimate, which only ever
    // happens via a real proposal correctly signed by that view's
    // `expected_proposer`. A vote can never establish a view's
    // legitimacy on its own; it can only ever agree with one a
    // legitimate proposal already did.
    if !rs.legitimate_rounds.contains(&(v.block_hash.clone(), v.view)) {
        warn(format!(
            "ignoring vote from {} claiming view {} for height {} - no legitimate proposal was ever seen for that (hash, view) pair",
            v.sender, v.view, block.height
        ));
        return;
    }
    let Some(sig) = decode_signature(&v.sig_hex) else { return };
    let signing_canon = protocol::view_block_canon(v.view, &block);
    if !crypto::verify_canon(&known_pubkey, &signing_canon, &sig) {
        warn(format!("invalid vote signature from {}", v.sender));
        return;
    }
    ctx.metrics.record_peer_seen(v.sender); // no-op if v.sender is this node's own id

    let tally = rs.prevotes.entry((v.block_hash.clone(), v.view)).or_default();
    if !tally.iter().any(|e| e.node_id == v.sender) {
        tally.push(SigEntry { node_id: v.sender, pubkey_hex: v.pubkey_hex, sig_hex: v.sig_hex });
    }

    maybe_cast_own_prevote(ctx, node, rs, block.height, v.view, &v.block_hash, &signing_canon);
    maybe_precommit(ctx, node, store, rs, &v.block_hash, v.view).await;
}

/// Casts this node's own prevote for (`block_hash`, `view`) - already
/// established as a legitimate pair by the caller - and broadcasts
/// it, unless this node has already prevoted for this exact pair, or
/// is locked on a *different* block at `height` and the prevote tally
/// for this pair hasn't itself reached quorum yet. That second
/// condition is the only thing ever allowed to override an existing
/// lock: a real, independently-observed prevote quorum certificate
/// ("polka") for the new candidate - never a bare claim. See this
/// module's doc comment on quorum-certificate locking.
fn maybe_cast_own_prevote(ctx: &Ctx, node: &NodeState, rs: &mut RoundState, height: u64, view: u64, block_hash: &str, signing_canon: &str) {
    let key = (block_hash.to_string(), view);
    let already_voted = rs.prevotes.get(&key).map(|t| t.iter().any(|e| e.node_id == node.node_id)).unwrap_or(false);
    if already_voted {
        return;
    }
    if let Some((_, locked_hash)) = rs.locked.get(&height) {
        if locked_hash != block_hash {
            let tally_len = rs.prevotes.get(&key).map(|t| t.len()).unwrap_or(0);
            if tally_len < quorum_for(ctx.all_ids.len()) {
                return; // still locked elsewhere - no polka yet for this candidate
            }
            log(format!(
                "height={height}: observed a prevote quorum for {block_hash} at view={view} - overriding this node's existing lock on a different candidate (unlocking)"
            ));
        }
    }
    let my_sig = crypto::sign_canon(&node.signing_key, signing_canon);
    let my_entry = SigEntry { node_id: node.node_id, pubkey_hex: hex::encode(node.verifying_key.to_bytes()), sig_hex: hex::encode(my_sig.to_bytes()) };
    rs.prevotes.entry(key).or_default().push(my_entry.clone());
    log(format!("prevoting for height={height} view={view} hash={block_hash}"));
    broadcast(
        ctx,
        &Message::BlockVote(BlockVoteMsg {
            sender: node.node_id,
            view,
            block_hash: block_hash.to_string(),
            pubkey_hex: my_entry.pubkey_hex,
            sig_hex: my_entry.sig_hex,
        }),
    );
}

/// Once this node's own prevote tally for (`block_hash`, `view`)
/// reaches quorum - a genuine polka, proof the network actually
/// supports it, not just a signer's claim - this locks the node onto
/// it (persisted via `persistence::LockRecord` so a restart can't
/// forget and later re-prevote for a conflicting block), casts this
/// node's own precommit (signed over `protocol::precommit_canon`, a
/// string a prevote signature can never be replayed into), and checks
/// whether the *precommit* tally has itself reached quorum.
async fn maybe_precommit(ctx: &Ctx, node: &mut NodeState, store: &Store, rs: &mut RoundState, block_hash: &str, view: u64) {
    let Some(block) = rs.candidates.get(block_hash).cloned() else { return };
    let key = (block_hash.to_string(), view);
    let Some(tally) = rs.prevotes.get(&key) else { return };
    if tally.len() < quorum_for(ctx.all_ids.len()) {
        return;
    }
    if let Some((locked_view, locked_hash)) = rs.locked.get(&block.height) {
        if *locked_view == view && locked_hash == block_hash {
            return; // already locked + precommitted here - nothing new to do
        }
    }

    rs.locked.insert(block.height, (view, block_hash.to_string()));
    if let Err(e) = store.put_lock(&LockRecord { height: block.height, view, block_hash: block_hash.to_string() }) {
        warn(format!("failed to persist lock for height={}: {e}", block.height));
    }

    let precommit_canon_str = protocol::precommit_canon(view, &block);
    let my_sig = crypto::sign_canon(&node.signing_key, &precommit_canon_str);
    let my_entry = SigEntry { node_id: node.node_id, pubkey_hex: hex::encode(node.verifying_key.to_bytes()), sig_hex: hex::encode(my_sig.to_bytes()) };
    let ptally = rs.precommits.entry(key.clone()).or_default();
    if !ptally.iter().any(|e| e.node_id == node.node_id) {
        ptally.push(my_entry.clone());
    }
    log(format!("precommitting (locked) for height={} view={view} hash={block_hash}", block.height));
    broadcast(
        ctx,
        &Message::Precommit(PrecommitMsg {
            sender: node.node_id,
            view,
            block_hash: block_hash.to_string(),
            pubkey_hex: my_entry.pubkey_hex,
            sig_hex: my_entry.sig_hex,
        }),
    );

    maybe_commit(ctx, node, store, rs, block_hash, view).await;
}

/// Verifies and tallies an incoming precommit - the second-phase,
/// domain-separated signature that's the only thing `maybe_commit`
/// ever actually counts toward finalizing a block. See this module's
/// doc comment on quorum-certificate locking.
async fn handle_precommit(ctx: &Ctx, node: &mut NodeState, store: &Store, rs: &mut RoundState, pc: PrecommitMsg) {
    let known_pubkey =
        if pc.sender == node.node_id { Some(node.verifying_key) } else { ctx.peers.read().unwrap().get(&pc.sender).map(|p| p.pubkey) };
    let Some(known_pubkey) = known_pubkey else { return };
    let Some(claimed_pubkey) = decode_verifying_key(&pc.pubkey_hex) else { return };
    if claimed_pubkey != known_pubkey {
        warn(format!("precommit from {} claims an unexpected pubkey", pc.sender));
        return;
    }
    let Some(block) = rs.candidates.get(&pc.block_hash).cloned() else {
        return; // precommit for a candidate we haven't cached - dropped; no retry in this stage
    };
    if !rs.legitimate_rounds.contains(&(pc.block_hash.clone(), pc.view)) {
        warn(format!(
            "ignoring precommit from {} claiming view {} for height {} - no legitimate proposal was ever seen for that (hash, view) pair",
            pc.sender, pc.view, block.height
        ));
        return;
    }
    let Some(sig) = decode_signature(&pc.sig_hex) else { return };
    let canon = protocol::precommit_canon(pc.view, &block);
    if !crypto::verify_canon(&known_pubkey, &canon, &sig) {
        warn(format!("invalid precommit signature from {}", pc.sender));
        return;
    }
    ctx.metrics.record_peer_seen(pc.sender);

    let tally = rs.precommits.entry((pc.block_hash.clone(), pc.view)).or_default();
    if !tally.iter().any(|e| e.node_id == pc.sender) {
        tally.push(SigEntry { node_id: pc.sender, pubkey_hex: pc.pubkey_hex, sig_hex: pc.sig_hex });
    }

    maybe_commit(ctx, node, store, rs, &pc.block_hash, pc.view).await;
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
        warn(format!("failed to persist corrected epoch: {e}"));
    }
}

async fn maybe_commit(ctx: &Ctx, node: &mut NodeState, store: &Store, rs: &mut RoundState, block_hash: &str, view: u64) {
    let head = node.head().clone();
    let Some(mut block) = rs.candidates.get(block_hash).cloned() else { return };
    if block.parent != head.hash {
        return; // superseded by a different committed block already
    }
    // Gated on the *precommit* tally, never the prevote one - a block
    // only ever finalizes once a real quorum of nodes independently
    // locked onto it (see `maybe_precommit`), not merely prevoted for
    // it. This is the core of what closes this module's disclosed
    // safety gap: committing used to only ever require one round of
    // signatures, which is what let votes for two different views'
    // candidates at the same height both have a real chance to reach
    // quorum in an adversarial/partitioned network.
    let Some(precommits) = rs.precommits.get(&(block_hash.to_string(), view)).cloned() else { return };
    if precommits.len() < quorum_for(ctx.all_ids.len()) {
        return;
    }

    block.signatures = precommits;
    block.sig_weight = block.signatures.len() as f64;

    apply_trust_updates(ctx, node, store, &block, rs).await;

    node.chain.push(block.clone());
    if let Err(e) = store.put_block(&block) {
        warn(format!("failed to persist committed block: {e}"));
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
            warn(format!("failed to persist rotated epoch: {e}"));
        }
    }

    rs.candidates.retain(|_, b| b.height > block.height);
    let surviving: std::collections::HashSet<String> = rs.candidates.keys().cloned().collect();
    rs.legitimate_rounds.retain(|(h, _)| surviving.contains(h));
    rs.prevotes.retain(|(h, _), _| surviving.contains(h));
    rs.precommits.retain(|(h, _), _| surviving.contains(h));
    // A real gap a focused code review caught: this used to prune
    // candidates/votes down to heights still in play but never
    // view_for_height, so any height that ever needed a view-change
    // (common in practice, not rare) left a permanent entry behind for
    // the life of the process - unbounded growth on a long-running
    // node. Mirrors the retain pattern above - now also covering
    // `locked`/`proposed_rounds`, the two maps the quorum-certificate
    // locking pass added.
    rs.view_for_height.retain(|&h, _| h > block.height);
    rs.locked.retain(|&h, _| h > block.height);
    rs.proposed_rounds.retain(|&(h, _)| h > block.height);
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
    let total_weight: f64 = weights.iter().sum();

    for (idx, &peer_id) in ids.iter().enumerate() {
        if peer_id == node.node_id {
            continue;
        }
        // A real bug a focused code review caught: this used to be a
        // flat `1.0 / ids.len()` for every peer, ignoring
        // trust::update_edge_weight's own documented contract (see
        // tri_sync_core/src/trust.rs) that `share` is this peer's
        // share of this node's *total* incoming trust - i.e.
        // weight-proportional, not uniform. A barely-trusted peer's
        // edge weight was swinging exactly as fast as an established
        // peer's for the same-sized error, defeating the point of
        // weighting trust at all. Falls back to the old uniform value
        // only if every weight were somehow zero - defensive, not
        // expected, since this node's own entry is always 1.0 above.
        let share = if total_weight > 0.0 { weights[idx] / total_weight } else { 1.0 / ids.len() as f64 };
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
            warn(format!("failed to persist trust update for peer {peer_id}: {e}"));
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
    fn log_timestamp_has_the_expected_shape_and_a_plausible_year() {
        let ts = log_timestamp();
        assert_eq!(ts.len(), 20, "YYYY-MM-DDTHH:MM:SSZ is exactly 20 chars, got {ts:?}");
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[13..14], ":");
        assert_eq!(&ts[16..17], ":");
        assert_eq!(&ts[19..20], "Z");
        let year: u32 = ts[0..4].parse().expect("year digits should parse");
        assert!((2020..2200).contains(&year), "sanity bound on the current year, got {year}");
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
        let peers = HashMap::from([(1, PeerInfo { addr: "127.0.0.1:1".parse().unwrap(), pubkey: peer_sk.verifying_key(), rotation_seq: 0 })]);
        let endpoint = net::make_client_endpoint().unwrap();
        let ctx = Ctx { config, peers: std::sync::RwLock::new(peers), all_ids: vec![0, 1], endpoint, metrics: Arc::new(Metrics::new(&[1])) };
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

    fn signed_key_rotation(sender: usize, old_sk: &ed25519_dalek::SigningKey, new_pubkey_hex: &str, rotation_seq: u64) -> KeyRotationMsg {
        let canon = protocol::key_rotation_canon(sender, new_pubkey_hex, rotation_seq);
        let sig = crypto::sign_canon(old_sk, &canon);
        KeyRotationMsg { sender, new_pubkey_hex: new_pubkey_hex.to_string(), rotation_seq, sig_hex: hex::encode(sig.to_bytes()) }
    }

    #[tokio::test]
    async fn a_genuine_key_rotation_is_accepted_updates_ctx_peers_and_is_persisted() {
        let (ctx, _self_sk, peer_sk) = test_ctx_with_one_peer(); // peer 1, currently trusted key = peer_sk
        let dir = crate::test_support::TempDir::new("key_rotation_accepted");
        let store = Store::open(dir.path()).unwrap();

        let new_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let new_pubkey_hex = hex::encode(new_sk.verifying_key().to_bytes());
        let msg = signed_key_rotation(1, &peer_sk, &new_pubkey_hex, 1);

        handle_key_rotation(&ctx, &store, msg).await;

        let updated = ctx.peers.read().unwrap().get(&1).copied().expect("peer 1 should still be known");
        assert_eq!(updated.pubkey, new_sk.verifying_key(), "ctx.peers must be updated to the new key immediately");
        assert_eq!(updated.rotation_seq, 1);

        let persisted = store.get_peer_key(1).unwrap().expect("the rotation must be persisted");
        assert_eq!(persisted.pubkey_hex, new_pubkey_hex);
        assert_eq!(persisted.rotation_seq, 1);
    }

    /// The actual end-to-end point of accepting a rotation: a real
    /// proposal from peer 1, signed with its *new* key, must now
    /// verify - not just that `ctx.peers` holds the new key in
    /// isolation (the test above), but that `handle_proposal`'s own
    /// signature check, run fresh afterward, actually agrees.
    #[tokio::test]
    async fn a_proposal_signed_with_the_newly_rotated_key_verifies_after_rotation() {
        let (ctx, self_sk, peer_sk) = test_ctx_with_one_peer(); // self=0, peer=1, all_ids=[0,1]
        let dir = crate::test_support::TempDir::new("key_rotation_then_proposal");
        let store = Store::open(dir.path()).unwrap();

        let new_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let new_pubkey_hex = hex::encode(new_sk.verifying_key().to_bytes());
        handle_key_rotation(&ctx, &store, signed_key_rotation(1, &peer_sk, &new_pubkey_hex, 1)).await;
        assert_eq!(ctx.peers.read().unwrap().get(&1).unwrap().pubkey, new_sk.verifying_key(), "sanity: rotation took effect");

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

        // height=1, view=0: expected_proposer([0,1], 1, 0) == 1, so
        // peer 1 is the legitimate proposer here.
        assert_eq!(expected_proposer(&ctx.all_ids, 1, 0), 1);
        let proposal = signed_proposal(1, &new_sk, 1, "GENESIS", 0, 1.0);

        handle_proposal(&ctx, &mut node, &store, &mut rs, proposal.clone()).await;

        // With a 2-node network (quorum 2): the proposer's embedded
        // signature plus this node's own prevote reach a prevote
        // quorum, which locks this node and casts its own precommit -
        // but that's still only 1 of the 2 precommits needed. The
        // peer's own precommit (on a real node, driven by it
        // independently reaching the same prevote quorum) is what
        // actually finalizes it here.
        let peer_precommit = signed_precommit(1, &new_sk, &proposal.block.hash, 0, &proposal.block);
        handle_precommit(&ctx, &mut node, &store, &mut rs, peer_precommit).await;

        // maybe_commit prunes the now-committed candidate, so checking
        // the real chain (not rs.candidates) is the correct success
        // signal here.
        let committed = node.chain.last().expect("the proposal should have verified, prevoted, precommitted, and committed");
        assert_eq!(committed.hash, proposal.block.hash, "the committed block must be the one signed with the newly-rotated key");
    }

    #[tokio::test]
    async fn a_key_rotation_signed_with_the_wrong_key_is_rejected() {
        let (ctx, self_sk, _peer_sk) = test_ctx_with_one_peer(); // peer 1's real key is peer_sk, not self_sk
        let dir = crate::test_support::TempDir::new("key_rotation_wrong_signer");
        let store = Store::open(dir.path()).unwrap();

        let new_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let new_pubkey_hex = hex::encode(new_sk.verifying_key().to_bytes());
        // Signed by this node's own key, impersonating peer 1 - not a
        // genuine continuity proof from peer 1's real old key.
        let msg = signed_key_rotation(1, &self_sk, &new_pubkey_hex, 1);

        handle_key_rotation(&ctx, &store, msg).await;

        assert_ne!(ctx.peers.read().unwrap().get(&1).unwrap().pubkey, new_sk.verifying_key(), "an impersonated rotation must never take effect");
        assert_eq!(store.get_peer_key(1).unwrap(), None, "nothing should be persisted either");
    }

    #[tokio::test]
    async fn a_rotation_from_an_unknown_sender_is_ignored() {
        let (ctx, _self_sk, _peer_sk) = test_ctx_with_one_peer();
        let dir = crate::test_support::TempDir::new("key_rotation_unknown_sender");
        let store = Store::open(dir.path()).unwrap();
        let unrelated_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let new_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let msg = signed_key_rotation(99, &unrelated_sk, &hex::encode(new_sk.verifying_key().to_bytes()), 1);

        handle_key_rotation(&ctx, &store, msg).await; // must not panic on an unknown id

        assert!(ctx.peers.read().unwrap().get(&99).is_none());
    }

    /// The real property this message type exists to prevent (see
    /// `protocol::KeyRotationMsg`'s doc comment): a captured, genuinely
    /// valid rotation announcement replayed *after* a later rotation
    /// has already superseded it must not roll the trusted key back.
    #[tokio::test]
    async fn a_replayed_rotation_with_a_stale_seq_cannot_roll_back_a_later_one() {
        let (ctx, _self_sk, peer_sk) = test_ctx_with_one_peer();
        let dir = crate::test_support::TempDir::new("key_rotation_replay");
        let store = Store::open(dir.path()).unwrap();

        let key_b = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let rotate_to_b = signed_key_rotation(1, &peer_sk, &hex::encode(key_b.verifying_key().to_bytes()), 1);
        handle_key_rotation(&ctx, &store, rotate_to_b.clone()).await;
        assert_eq!(ctx.peers.read().unwrap().get(&1).unwrap().pubkey, key_b.verifying_key());

        let key_c = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        // The real next rotation is signed by key_b (the now-current
        // key) at a higher seq.
        let rotate_to_c = signed_key_rotation(1, &key_b, &hex::encode(key_c.verifying_key().to_bytes()), 2);
        handle_key_rotation(&ctx, &store, rotate_to_c).await;
        assert_eq!(ctx.peers.read().unwrap().get(&1).unwrap().pubkey, key_c.verifying_key());

        // An attacker replays the original A->B announcement (genuinely
        // signed, by the real old key, but at the now-stale seq=1).
        handle_key_rotation(&ctx, &store, rotate_to_b).await;

        assert_eq!(
            ctx.peers.read().unwrap().get(&1).unwrap().pubkey,
            key_c.verifying_key(),
            "a stale-seq replay must never roll the trusted key back to a superseded one"
        );
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

        // With only two participants, the proposer's own signature plus
        // this node's prevote already meets prevote quorum (2), so
        // catch-up reaches a real lock + this node's own precommit in
        // this same call. The peer's own precommit (driven, on a real
        // node, by it independently reaching the same prevote quorum)
        // is what actually finalizes it.
        let peer_precommit = signed_precommit(1, &peer_sk, &block.hash, ahead_view, &block);
        handle_precommit(&ctx, &mut node, &store, &mut rs, peer_precommit).await;

        // (Checking current_view(&rs, 2) here would no longer prove
        // anything either way: maybe_commit now prunes view_for_height
        // for a height the instant it commits, so its absence just
        // means "committed", not "never caught up" - the commit
        // itself, signed at ahead_view, is the real proof the catch-up
        // happened.)
        let committed = node.chain.last().expect("chain should have advanced");
        assert_eq!(committed.hash, block.hash, "the block from the higher view should be the one that committed");
        assert_eq!(committed.sig_weight, 2.0, "proposer's precommit plus this node's own precommit");
        assert!(!rs.view_for_height.contains_key(&2), "the now-committed height's view bookkeeping should be pruned");
    }

    /// Builds a `BlockProposalMsg` genuinely signed by `signer_sk` as
    /// `sender`, for the given height/parent/view, with `sig_weight`
    /// set afterward to whatever the test wants to claim (never covered
    /// by the signature - see the long comment in `handle_proposal`).
    fn signed_proposal(sender: usize, signer_sk: &ed25519_dalek::SigningKey, height: u64, parent: &str, view: u64, sig_weight: f64) -> BlockProposalMsg {
        signed_proposal_with_state(sender, signer_sk, height, parent, view, sig_weight, vec![height as f64, height as f64])
    }

    /// Same as `signed_proposal`, but with an explicit `state` vector -
    /// lets a test construct multiple distinctly-hashed blocks for the
    /// same height/view (`state` feeds `block_canon`, so varying it is
    /// the whole point here, e.g. for `MAX_CANDIDATES_PER_HEIGHT`'s
    /// cap test).
    fn signed_proposal_with_state(
        sender: usize,
        signer_sk: &ed25519_dalek::SigningKey,
        height: u64,
        parent: &str,
        view: u64,
        sig_weight: f64,
        state: Vec<f64>,
    ) -> BlockProposalMsg {
        let mut block = Block {
            height,
            parent: parent.to_string(),
            state,
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

    fn signed_vote(sender: usize, signer_sk: &ed25519_dalek::SigningKey, block_hash: &str, view: u64, block: &Block) -> BlockVoteMsg {
        let signing_canon = protocol::view_block_canon(view, block);
        let sig = crypto::sign_canon(signer_sk, &signing_canon);
        BlockVoteMsg {
            sender,
            view,
            block_hash: block_hash.to_string(),
            pubkey_hex: hex::encode(signer_sk.verifying_key().to_bytes()),
            sig_hex: hex::encode(sig.to_bytes()),
        }
    }

    /// Builds a genuine second-phase precommit - see
    /// `protocol::precommit_canon`'s doc comment for why this signs a
    /// different string than `signed_vote`'s prevote.
    fn signed_precommit(sender: usize, signer_sk: &ed25519_dalek::SigningKey, block_hash: &str, view: u64, block: &Block) -> PrecommitMsg {
        let canon = protocol::precommit_canon(view, block);
        let sig = crypto::sign_canon(signer_sk, &canon);
        PrecommitMsg {
            sender,
            view,
            block_hash: block_hash.to_string(),
            pubkey_hex: hex::encode(signer_sk.verifying_key().to_bytes()),
            sig_hex: hex::encode(sig.to_bytes()),
        }
    }

    /// A real bug a focused code review caught: `apply_trust_updates`
    /// used to pass the same flat `1/n` share to every peer regardless
    /// of their actual reliability, when `trust::update_edge_weight`'s
    /// own contract says `share` must be weight-proportional. Proven
    /// here the direct way: run the identical scenario (same
    /// observations, same committed block.state, same starting
    /// edge_weight) twice, differing only in the peer's starting
    /// `reliability` (which feeds into its `weights` entry and so its
    /// `share`) - under the old flat-share bug the two runs produced
    /// byte-identical resulting edge weights; under the fix they must
    /// differ, since a higher-weight peer now gets a proportionally
    /// larger adjustment for the same-sized error.
    #[tokio::test]
    async fn apply_trust_updates_gives_a_higher_weight_peer_a_larger_adjustment_for_the_same_error() {
        async fn run_with_peer_reliability(peer_reliability: f64) -> f64 {
            let (ctx, self_sk, _peer_sk) = test_ctx_with_one_peer(); // self=0, peer=1
            let dir = crate::test_support::TempDir::new(&format!("trust_share_{peer_reliability}"));
            let store = Store::open(dir.path()).unwrap();
            let mut node = NodeState {
                node_id: 0,
                chain: vec![Block::genesis(1)],
                signing_key: self_sk.clone(),
                verifying_key: self_sk.verifying_key(),
                epoch: 0,
                edge_weight: HashMap::from([(1, 1.0)]),
                reliability: HashMap::from([(1, peer_reliability)]),
            };
            let mut rs = RoundState::default();
            rs.latest_observations.insert(0, vec![0.0]);
            rs.latest_observations.insert(1, vec![10.0]);
            // block.state is deliberately independent of any real
            // fusion output - apply_trust_updates only ever measures
            // distances *from* it, so an arbitrary fixed value is
            // enough to drive a reproducible, comparable delta_e.
            let block = Block { height: 1, state: vec![5.0], ..Block::genesis(1) };

            apply_trust_updates(&ctx, &mut node, &store, &block, &rs).await;

            *node.edge_weight.get(&1).unwrap()
        }

        let low_weight_result = run_with_peer_reliability(0.1).await;
        let high_weight_result = run_with_peer_reliability(0.9).await;

        assert_ne!(
            low_weight_result, high_weight_result,
            "share must depend on the peer's actual weight - under the flat-1/n bug these were identical regardless of reliability"
        );
    }

    /// A real liveness bug a focused adversarial code review caught,
    /// not any test: `handle_vote` used to treat `v.view > current_view`
    /// alone as proof a round at that view really happened and adopt
    /// it, resetting the view-change timeout - but a vote is self-signed
    /// by the voter alone, who can construct `view_block_canon(view,
    /// block)` for *any* view over a block they already know about,
    /// with no proposer ever actually proposing at that view. That let
    /// a single authenticated peer manufacture an endless stream of
    /// escalating fake votes and keep the network from ever holding a
    /// view still long enough to reach quorum. Proven fixed here: a
    /// vote claiming a view that doesn't match the view the candidate
    /// was actually cached under must be rejected outright, with no
    /// effect on this node's view bookkeeping at all.
    #[tokio::test]
    async fn a_vote_claiming_a_different_view_than_the_cached_candidate_cannot_escalate_the_view() {
        let (ctx, self_sk, peer_sk) = test_ctx_with_one_peer(); // self=0, peer=1, all_ids=[0,1]
        let dir = crate::test_support::TempDir::new("vote_view_escalation_attack");
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

        // A genuine candidate, legitimately cached at view 0 (as
        // handle_proposal would have left it after accepting a real
        // proposal - constructed directly here since only the cached
        // (view, block) state matters for this test).
        let proposal = signed_proposal(1, &peer_sk, 1, "GENESIS", 0, 1.0);
        let block_hash = proposal.block.hash.clone();
        rs.candidates.insert(block_hash.clone(), proposal.block.clone());
        rs.legitimate_rounds.insert((block_hash.clone(), 0));
        rs.prevotes.insert((block_hash.clone(), 0), proposal.block.signatures.clone());
        assert_eq!(current_view(&rs, 1), 0);

        // The attack: peer 1 (a real, correctly-configured peer) signs
        // a "vote" for that same block claiming view 99 - perfectly
        // valid cryptographically, since they hold the real key and
        // can sign any view_block_canon they like. No proposal was
        // ever legitimately seen for (block_hash, 99), so it must be
        // rejected regardless of whose signature it carries.
        let fake_escalation = signed_vote(1, &peer_sk, &block_hash, 99, &proposal.block);
        handle_vote(&ctx, &mut node, &store, &mut rs, fake_escalation).await;

        assert_eq!(current_view(&rs, 1), 0, "a vote alone must never be able to advance the view");
        assert!(rs.waiting_for.is_none(), "no legitimate view-change timeout should have been touched");
        assert_eq!(rs.prevotes.get(&(block_hash.clone(), 0)).unwrap().len(), 1, "the fabricated vote must not be tallied");
        assert!(!rs.prevotes.contains_key(&(block_hash, 99)), "an illegitimate (hash, view) pair must never even get a tally bucket");
        assert_eq!(node.chain.len(), 1, "nothing should have committed off a rejected vote");
    }

    /// The flip side: a genuine vote whose claimed view matches the
    /// view the candidate was actually cached under must still work
    /// normally and be able to reach quorum - the fix above closes a
    /// hole without breaking real voting.
    #[tokio::test]
    async fn a_genuine_vote_at_the_candidates_actual_view_is_accepted_and_can_reach_quorum() {
        let (ctx, self_sk, peer_sk) = test_ctx_with_one_peer(); // self=0, peer=1, quorum=2
        let dir = crate::test_support::TempDir::new("vote_genuine_view_match");
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

        let proposal = signed_proposal(1, &peer_sk, 1, "GENESIS", 0, 1.0);
        let block_hash = proposal.block.hash.clone();
        rs.candidates.insert(block_hash.clone(), proposal.block.clone());
        rs.legitimate_rounds.insert((block_hash.clone(), 0));
        rs.prevotes.insert((block_hash.clone(), 0), proposal.block.signatures.clone());

        // Node 0's own vote, matching the candidate's real view - the
        // second prevote needed to reach the 2-of-2 prevote quorum,
        // which locks this node and casts its own precommit.
        let my_vote = signed_vote(0, &self_sk, &block_hash, 0, &proposal.block);
        handle_vote(&ctx, &mut node, &store, &mut rs, my_vote).await;
        assert!(node.chain.last().unwrap().hash != block_hash, "a prevote quorum alone must not commit - only a precommit quorum can");

        // The peer's own precommit - driven, on a real node, by it
        // independently reaching the same prevote quorum - is what
        // actually finalizes it.
        let peer_precommit = signed_precommit(1, &peer_sk, &block_hash, 0, &proposal.block);
        handle_precommit(&ctx, &mut node, &store, &mut rs, peer_precommit).await;

        let committed = node.chain.last().expect("a genuine matching-view vote should have let this commit");
        assert_eq!(committed.hash, block_hash);
        assert_eq!(committed.sig_weight, 2.0);
    }

    /// The capstone proof for this module's quorum-certificate locking:
    /// two disjoint candidates for the same height can never both
    /// reach a precommit QC, even when a node locks on one and later
    /// receives a fully legitimate, correctly-signed proposal for the
    /// other at a higher view - exactly the adversarial/partitioned
    /// scenario this module's doc comment used to disclose as an open
    /// safety gap. 4 participants (quorum 3): block A is legitimately
    /// proposed at view 0 and reaches a genuine prevote quorum, which
    /// locks node 0 onto it - but its precommit tally stops at 1 and
    /// can never grow again, because nothing in this test ever gives
    /// it another precommit. Block B is then legitimately proposed at
    /// view 1 (by the real expected proposer for that view); node 0
    /// refuses to prevote for it while locked on A, *even though* B's
    /// proposal and every incoming vote for it are all genuinely
    /// signed - until B's own prevote tally independently reaches
    /// quorum (a real polka), at which point node 0 unlocks, switches,
    /// and B - not A - goes on to reach a precommit QC and commit.
    #[tokio::test]
    async fn locking_prevents_two_conflicting_blocks_from_both_reaching_a_precommit_quorum_certificate() {
        use crate::config::PeerConfig;
        let self_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let peer_sks: Vec<ed25519_dalek::SigningKey> = (0..3).map(|_| ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)).collect();
        let config = NodeConfig {
            node_id: 0,
            dim: 2,
            listen_addr: "127.0.0.1:0".to_string(),
            license_path: String::new(),
            data_dir: String::new(),
            round_interval_secs: 1,
            metrics_addr: None,
            peers: (1..=3)
                .map(|id| PeerConfig {
                    id,
                    addr: format!("127.0.0.1:{id}"),
                    pubkey_hex: hex::encode(peer_sks[id - 1].verifying_key().to_bytes()),
                })
                .collect(),
        };
        let peers = HashMap::from_iter((1..=3).map(|id| {
            (id, PeerInfo { addr: format!("127.0.0.1:{id}").parse().unwrap(), pubkey: peer_sks[id - 1].verifying_key(), rotation_seq: 0 })
        }));
        let endpoint = net::make_client_endpoint().unwrap();
        let ctx = Ctx { config, peers: std::sync::RwLock::new(peers), all_ids: vec![0, 1, 2, 3], endpoint, metrics: Arc::new(Metrics::new(&[1, 2, 3])) };
        let dir = crate::test_support::TempDir::new("locking_prevents_split_commit");
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

        // expected_proposer([0,1,2,3], 1, 0) == 1; expected_proposer(..., 1, 1) == 2.
        assert_eq!(expected_proposer(&ctx.all_ids, 1, 0), 1);
        assert_eq!(expected_proposer(&ctx.all_ids, 1, 1), 2);

        // --- View 0: block A is legitimately proposed and reaches a real prevote quorum. ---
        let a = signed_proposal_with_state(1, &peer_sks[0], 1, "GENESIS", 0, 1.0, vec![1.0, 1.0]);
        handle_proposal(&ctx, &mut node, &store, &mut rs, a.clone()).await; // prevotes[(A,0)]: peer1 + self = 2
        let vote_a_from_2 = signed_vote(2, &peer_sks[1], &a.block.hash, 0, &a.block);
        handle_vote(&ctx, &mut node, &store, &mut rs, vote_a_from_2).await; // prevotes[(A,0)] = 3 = quorum -> locks on A

        assert_eq!(rs.locked.get(&1), Some(&(0, a.block.hash.clone())), "a genuine prevote quorum must lock this node onto A");
        assert_eq!(node.chain.len(), 1, "A's precommit tally is only 1 (this node's own) - nowhere near quorum 3, so nothing has committed");

        // --- View 1: block B is a different, equally legitimate proposal - but node 0 is locked on A. ---
        let b = signed_proposal_with_state(2, &peer_sks[1], 1, "GENESIS", 1, 1.0, vec![2.0, 2.0]);
        assert_ne!(a.block.hash, b.block.hash, "A and B must be genuinely different candidates for this test to mean anything");
        handle_proposal(&ctx, &mut node, &store, &mut rs, b.clone()).await; // prevotes[(B,1)]: peer2 only = 1

        assert_eq!(rs.locked.get(&1), Some(&(0, a.block.hash.clone())), "a merely-legitimate competing proposal must not break an existing lock");
        assert!(
            rs.prevotes.get(&(b.block.hash.clone(), 1)).unwrap().iter().all(|e| e.node_id != 0),
            "node 0 must not prevote for B while locked on A, with no polka for B yet"
        );

        // A second, genuine vote for B - still short of quorum (2 of 3).
        let vote_b_from_1 = signed_vote(1, &peer_sks[0], &b.block.hash, 1, &b.block);
        handle_vote(&ctx, &mut node, &store, &mut rs, vote_b_from_1).await;
        assert_eq!(rs.locked.get(&1), Some(&(0, a.block.hash.clone())), "still short of a real polka for B - the lock on A must hold");

        // --- The polka: a THIRD genuine vote for B reaches prevote quorum - real evidence, not a claim. ---
        let vote_b_from_3 = signed_vote(3, &peer_sks[2], &b.block.hash, 1, &b.block);
        handle_vote(&ctx, &mut node, &store, &mut rs, vote_b_from_3).await;

        assert_eq!(rs.locked.get(&1), Some(&(1, b.block.hash.clone())), "a genuine prevote QC for B must unlock A and lock onto B instead");
        assert_eq!(
            rs.precommits.get(&(a.block.hash.clone(), 0)).unwrap().len(),
            1,
            "A's precommit tally must be frozen forever at 1 - nothing in this scenario ever gives it a second"
        );
        assert_eq!(node.chain.len(), 1, "B has only this node's own precommit so far - not yet quorum");

        // The other two participants' precommits for B finalize it.
        let precommit_b_from_1 = signed_precommit(1, &peer_sks[0], &b.block.hash, 1, &b.block);
        handle_precommit(&ctx, &mut node, &store, &mut rs, precommit_b_from_1).await;
        let precommit_b_from_2 = signed_precommit(2, &peer_sks[1], &b.block.hash, 1, &b.block);
        handle_precommit(&ctx, &mut node, &store, &mut rs, precommit_b_from_2).await;

        let committed = node.chain.last().expect("B should have reached a real precommit quorum and committed");
        assert_eq!(committed.hash, b.block.hash, "B, never A, must be the one that actually committed");
    }

    /// Domain separation end-to-end, not just at the `protocol::*_canon`
    /// string level: a peer's perfectly genuine *prevote* signature
    /// (over `view_block_canon`) must be rejected by `handle_precommit`
    /// when replayed as a claimed precommit, because it doesn't verify
    /// against `precommit_canon`. If this ever passed, the two-phase
    /// design would be theater - a single signature could satisfy
    /// both phases at once.
    #[tokio::test]
    async fn a_prevote_signature_cannot_be_replayed_as_a_precommit() {
        let (ctx, self_sk, peer_sk) = test_ctx_with_one_peer(); // self=0, peer=1
        let dir = crate::test_support::TempDir::new("no_prevote_precommit_replay");
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

        let proposal = signed_proposal(1, &peer_sk, 1, "GENESIS", 0, 1.0);
        handle_proposal(&ctx, &mut node, &store, &mut rs, proposal.clone()).await;
        // With a 2-node network, the proposer's embedded sig + this
        // node's own auto-prevote already reach prevote quorum, so
        // this node has already locked and cast its own *genuine*
        // precommit by this point - the real baseline to compare
        // against below, not an empty tally.
        let genuine_precommits_so_far = rs.precommits.get(&(proposal.block.hash.clone(), 0)).cloned().unwrap_or_default();
        assert_eq!(genuine_precommits_so_far.len(), 1, "sanity: this node's own real precommit, from reaching prevote quorum above");

        // A real prevote from peer 1, genuinely signed over
        // view_block_canon - valid as a prevote, never as a precommit.
        let genuine_prevote = signed_vote(1, &peer_sk, &proposal.block.hash, 0, &proposal.block);
        let replayed_as_precommit = PrecommitMsg {
            sender: genuine_prevote.sender,
            view: genuine_prevote.view,
            block_hash: genuine_prevote.block_hash.clone(),
            pubkey_hex: genuine_prevote.pubkey_hex.clone(),
            sig_hex: genuine_prevote.sig_hex.clone(),
        };
        handle_precommit(&ctx, &mut node, &store, &mut rs, replayed_as_precommit).await;

        assert_eq!(
            rs.precommits.get(&(proposal.block.hash.clone(), 0)).cloned().unwrap_or_default(),
            genuine_precommits_so_far,
            "a replayed prevote signature must never be accepted as a precommit - the tally must be untouched by it"
        );
        assert_eq!(node.chain.len(), 1, "nothing should have committed off a forged precommit (still only 1 of 2 needed precommits)");
    }

    /// Proves the lock survives a restart - not just asserted from
    /// reading `run`'s loading code, but by actually driving a fresh
    /// `RoundState` through the same `store.get_lock()` path `run`
    /// uses, then confirming a conflicting prevote is still rejected
    /// afterward exactly as it would have been pre-restart. Forgetting
    /// the lock across a restart would reopen the same safety gap
    /// quorum-certificate locking exists to close.
    #[tokio::test]
    async fn a_lock_survives_a_simulated_restart_and_still_blocks_a_conflicting_prevote() {
        let (ctx, self_sk, peer_sk) = test_ctx_with_one_peer(); // self=0, peer=1, quorum=2
        let dir = crate::test_support::TempDir::new("lock_survives_restart");
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

        let a = signed_proposal_with_state(1, &peer_sk, 1, "GENESIS", 0, 1.0, vec![1.0, 1.0]);
        handle_proposal(&ctx, &mut node, &store, &mut rs, a.clone()).await; // prevotes[(A,0)] = peer1 + self = 2 = quorum -> locks on A
        assert_eq!(rs.locked.get(&1), Some(&(0, a.block.hash.clone())));
        assert_eq!(store.get_lock().unwrap(), Some(LockRecord { height: 1, view: 0, block_hash: a.block.hash.clone() }), "the lock must be persisted, not just in memory");

        // Simulate a restart: a brand-new, empty RoundState (as a real
        // process restart would start with), restoring only what
        // `run` itself restores from the store.
        let mut rs_after_restart = RoundState::default();
        let record = store.get_lock().unwrap().expect("the lock must still be on disk");
        assert_eq!(record.height, node.head().height + 1, "sanity: this is the in-flight height, not a stale record");
        rs_after_restart.locked.insert(record.height, (record.view, record.block_hash));

        // A different, equally legitimate proposal B at a higher view
        // - without the restored lock, this node would have nothing
        // stopping it from prevoting for B. View 2 (not 1): with only
        // two participants, expected_proposer(height=1, view) cycles
        // back to peer 1 only on even views, and it must still be
        // peer 1 - not this node itself - proposing, for "a real
        // peer's legitimate proposal" to mean anything here.
        assert_eq!(expected_proposer(&ctx.all_ids, 1, 2), 1);
        let b = signed_proposal_with_state(1, &peer_sk, 1, "GENESIS", 2, 1.0, vec![2.0, 2.0]);
        handle_proposal(&ctx, &mut node, &store, &mut rs_after_restart, b.clone()).await;

        assert!(
            rs_after_restart.prevotes.get(&(b.block.hash.clone(), 2)).unwrap().iter().all(|e| e.node_id != 0),
            "the restored lock must still block this node's own prevote for a different candidate, with no polka observed yet"
        );
        assert_eq!(rs_after_restart.locked.get(&1), Some(&(0, a.block.hash)), "the restored lock must be untouched by a merely-legitimate competing proposal");
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

    /// The resource-exhaustion vector this module's doc comment
    /// disclosed and `MAX_CANDIDATES_PER_HEIGHT` now closes: nothing
    /// before the new cap check depends on a proposal's *content*,
    /// only on whether `p.sender` is the legitimately expected
    /// proposer for that (height, view) - so that one real peer, using
    /// only their genuine key, could previously sign an unbounded
    /// number of distinctly-hashed blocks for the same (height, view)
    /// and grow `candidates`/`votes` forever (neither is pruned until
    /// the height actually commits). Proven here by sending one more
    /// distinct proposal than the cap allows, from the real expected
    /// proposer each time, and checking the maps stopped growing - not
    /// just asserted from reading the code.
    #[tokio::test]
    async fn candidates_per_height_are_capped_against_a_flooding_expected_proposer() {
        use crate::config::PeerConfig;
        // 4 participants (quorum = 3) rather than `test_ctx_with_one_peer`'s
        // 2 (quorum = 2): with only 2, the very first flood proposal's
        // embedded signature plus this node's own automatic vote would
        // already reach quorum and commit immediately, pruning
        // `candidates` right back down to empty before the flood could
        // ever be observed accumulating. With quorum 3, two signatures
        // (proposer + self) leave every flooded candidate genuinely
        // pending, which is what this test needs to see.
        let self_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let peer_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let other_sks = [ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng), ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)];
        let config = NodeConfig {
            node_id: 0,
            dim: 2,
            listen_addr: "127.0.0.1:0".to_string(),
            license_path: String::new(),
            data_dir: String::new(),
            round_interval_secs: 1,
            metrics_addr: None,
            peers: vec![
                PeerConfig { id: 1, addr: "127.0.0.1:1".to_string(), pubkey_hex: hex::encode(peer_sk.verifying_key().to_bytes()) },
                PeerConfig { id: 2, addr: "127.0.0.1:2".to_string(), pubkey_hex: hex::encode(other_sks[0].verifying_key().to_bytes()) },
                PeerConfig { id: 3, addr: "127.0.0.1:3".to_string(), pubkey_hex: hex::encode(other_sks[1].verifying_key().to_bytes()) },
            ],
        };
        let peers = HashMap::from([
            (1, PeerInfo { addr: "127.0.0.1:1".parse().unwrap(), pubkey: peer_sk.verifying_key(), rotation_seq: 0 }),
            (2, PeerInfo { addr: "127.0.0.1:2".parse().unwrap(), pubkey: other_sks[0].verifying_key(), rotation_seq: 0 }),
            (3, PeerInfo { addr: "127.0.0.1:3".parse().unwrap(), pubkey: other_sks[1].verifying_key(), rotation_seq: 0 }),
        ]);
        let endpoint = net::make_client_endpoint().unwrap();
        let ctx = Ctx { config, peers: std::sync::RwLock::new(peers), all_ids: vec![0, 1, 2, 3], endpoint, metrics: Arc::new(Metrics::new(&[1, 2, 3])) };
        let dir = crate::test_support::TempDir::new("candidate_flood_cap");
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

        for i in 0..(MAX_CANDIDATES_PER_HEIGHT + 3) {
            let proposal = signed_proposal_with_state(1, &peer_sk, 1, "GENESIS", 0, 1.0, vec![i as f64, 0.0]);
            handle_proposal(&ctx, &mut node, &store, &mut rs, proposal).await;
        }

        let distinct_at_height_1 = rs.candidates.values().filter(|b| b.height == 1).count();
        assert_eq!(distinct_at_height_1, MAX_CANDIDATES_PER_HEIGHT, "the cap must hold even though every flood message was genuinely signed");
        assert_eq!(
            rs.prevotes.len(),
            MAX_CANDIDATES_PER_HEIGHT,
            "prevotes is only ever populated alongside candidates (one (hash, view) bucket per flooded hash, all at view 0), so it must be bounded the same way"
        );

        // The flip side: the very first candidate (cached before the
        // cap was ever hit, and already carrying 2 of the 3 prevotes
        // it needs - peer 1's embedded proposal plus node 0's own
        // automatic prevote from inside `handle_proposal`) must still
        // be perfectly usable - the cap rejects brand-new hashes once
        // full, it does not evict or disturb anything already cached.
        let first = signed_proposal_with_state(1, &peer_sk, 1, "GENESIS", 0, 1.0, vec![0.0, 0.0]);
        assert!(rs.candidates.contains_key(&first.block.hash), "a candidate cached before the cap filled up must not have been evicted");
        assert_eq!(
            rs.prevotes.get(&(first.block.hash.clone(), 0)).unwrap().len(),
            2,
            "proposer + this node's own auto-prevote, from the flood loop above"
        );
        let third_vote = signed_vote(2, &other_sks[0], &first.block.hash, 0, &first.block);
        handle_vote(&ctx, &mut node, &store, &mut rs, third_vote).await;
        assert_ne!(node.chain.last().unwrap().hash, first.block.hash, "a prevote quorum alone must not commit - only a precommit quorum can");

        // The other two participants' own precommits - driven, on a
        // real node, by each of them independently reaching the same
        // prevote quorum - are what actually finalizes it.
        let precommit_from_2 = signed_precommit(2, &other_sks[0], &first.block.hash, 0, &first.block);
        handle_precommit(&ctx, &mut node, &store, &mut rs, precommit_from_2).await;
        let precommit_from_3 = signed_precommit(3, &other_sks[1], &first.block.hash, 0, &first.block);
        handle_precommit(&ctx, &mut node, &store, &mut rs, precommit_from_3).await;
        assert_eq!(node.chain.last().unwrap().hash, first.block.hash, "quorum must still be reachable for an already-cached candidate despite the flood");
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
        let ctx = Ctx { config, peers: std::sync::RwLock::new(HashMap::new()), all_ids: vec![0], endpoint, metrics: Arc::new(Metrics::default()) };
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

    /// A real resource leak a focused code review caught: `maybe_commit`
    /// pruned `candidates`/`votes` down to heights still in play but
    /// never `view_for_height`, so a height that needed a view-change -
    /// common in practice, not a corner case - left a permanent entry
    /// behind for the life of the process. Proven fixed by driving a
    /// real commit through a height that has a view-change entry and
    /// confirming it's gone afterward.
    #[tokio::test]
    async fn maybe_commit_prunes_view_for_height_for_the_height_that_just_committed() {
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
        let ctx = Ctx { config, peers: std::sync::RwLock::new(HashMap::new()), all_ids: vec![0], endpoint, metrics: Arc::new(Metrics::default()) };
        let dir = crate::test_support::TempDir::new("prune_view_for_height");
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
        // Simulates height 1 having already gone through a view-change
        // up to view 3 before the eventually-successful proposal.
        rs.view_for_height.insert(1, 3);

        let head = node.head().clone();
        propose_block(&ctx, &mut node, &store, &mut rs, &head, 3).await;

        assert_eq!(node.chain.len(), 2, "1-of-1 quorum should commit immediately");
        assert!(!rs.view_for_height.contains_key(&1), "the committed height's view-change bookkeeping must be pruned, not kept forever");
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
        let ctx = Ctx { config, peers: std::sync::RwLock::new(HashMap::new()), all_ids: vec![0], endpoint, metrics: Arc::new(Metrics::default()) };
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
        let server_a = net::make_server_endpoint(loopback(0), &sk_a).unwrap();
        let server_b = net::make_server_endpoint(loopback(0), &sk_b).unwrap();
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
