//! `tri_sync_node`: self-hosted, network-capable tri-sync node.
//!
//! This binary loads `node.toml`, verifies `license.toml` against it,
//! initializes or restores state (keys, chain, trust), starts the QUIC
//! P2P transport, and runs the networked consensus round loop - see
//! [`tri_sync_node::consensus`] for what that loop actually does and
//! what's simplified about it.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use tri_sync_core::chain::MembershipChange;
use tri_sync_core::crypto;
use tri_sync_node::protocol::{self, KeyRotationMsg, MembershipProposalMsg, Message};
use tri_sync_node::{config, consensus, license, metrics, net, persistence, state};

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let node_toml_path = args.next().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("node.toml"));

    // `--duration <secs>`: run the server for a bounded time then exit
    // cleanly, instead of forever. Meant for scripted tests; a real
    // deployment is run with no duration and left running until killed.
    //
    // `--show-identity`: initialize (or load) state and print this
    // node's public key, then exit immediately - no QUIC server, no
    // consensus round. An operator needs this to learn a new node's
    // pubkey before distributing it into peers' node.toml files; it
    // also avoids what a bootstrap-then-reconfigure workflow would
    // otherwise trip over, since the consensus loop's round timer fires
    // an immediate first tick and (with no peers yet configured) would
    // self-commit a block before the real peer list is ever written.
    //
    // `--rotate-key`: generate a fresh signing key, persist it as this
    // node's new identity, and broadcast a signed announcement (proven
    // by the *old* key) to every currently-configured peer so they
    // update their trusted pubkey for this node automatically - see
    // `consensus::handle_key_rotation` for how a peer accepts one.
    // Exits immediately like `--show-identity`, rather than continuing
    // into a normal run, so an operator can confirm the announcement
    // went out before deciding to restart the node for real.
    //
    // REQUIRED operator sequence, found to matter by an actual live
    // multi-process test, not assumed: stop this node's main process
    // FIRST, then run `--rotate-key`, then start it again normally.
    // Running `--rotate-key` while the old process is still live races
    // it: the still-running old process keeps signing with the old key
    // for as long as it's up, so a peer that already accepted the new
    // key correctly rejects those late old-key messages (expected) -
    // but if one of those rejected messages was this node's own vote
    // on a block the peer is actively trying to commit, that peer
    // could be left stuck on that height until chain-sync (see
    // `consensus`'s module doc comment) kicks in and catches it back
    // up on its own. Stopping first removes the race entirely: there's
    // no old-keyed process left to send anything peers now correctly
    // reject, so there's nothing to recover from in the first place.
    //
    // `--propose-add-peer <id> <addr> <pubkey_hex>` / `--propose-remove-peer
    // <id>`: sign a [`MembershipChange`] with this node's own key and
    // broadcast it to every peer in *this* node's `node.toml` as a
    // [`MembershipProposalMsg`] - see `consensus`'s module doc comment
    // on dynamic membership for the full mechanism. Exits immediately
    // like `--rotate-key`/`--show-identity`, rather than continuing
    // into a normal run.
    //
    // This is a liveness convenience only, never the safety mechanism
    // itself: broadcasting a proposal doesn't change anything by
    // itself - it only asks whichever of *those* peers next becomes
    // proposer to attach the change to its own next block, which still
    // has to earn a real precommit quorum under the actual current
    // membership before it takes effect, exactly like any other block.
    // Disclosed limitation, honestly narrow rather than hidden: this
    // only reaches peers in this node's own `node.toml`, which may not
    // be every current member if membership has already diverged (a
    // peer added since this file was last edited, say) - a real gap
    // in how promptly a change gets proposed, but not a safety one,
    // since the quorum requirement above holds regardless of who
    // proposed the change or how they heard about it.
    let mut duration_secs: Option<u64> = None;
    let mut show_identity_only = false;
    let mut rotate_key_only = false;
    let mut propose_add_peer: Option<(usize, String, String)> = None;
    let mut propose_remove_peer: Option<usize> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--duration" => duration_secs = args.next().and_then(|s| s.parse().ok()),
            "--show-identity" => show_identity_only = true,
            "--rotate-key" => rotate_key_only = true,
            "--propose-add-peer" => {
                let id = args.next().and_then(|s| s.parse().ok());
                let addr = args.next();
                let pubkey_hex = args.next();
                match (id, addr, pubkey_hex) {
                    (Some(id), Some(addr), Some(pubkey_hex)) => propose_add_peer = Some((id, addr, pubkey_hex)),
                    _ => {
                        eprintln!("tri_sync_node: --propose-add-peer requires <id> <addr> <pubkey_hex>");
                        return ExitCode::FAILURE;
                    }
                }
            }
            "--propose-remove-peer" => {
                let Some(id) = args.next().and_then(|s| s.parse().ok()) else {
                    eprintln!("tri_sync_node: --propose-remove-peer requires <id>");
                    return ExitCode::FAILURE;
                };
                propose_remove_peer = Some(id);
            }
            _ => {}
        }
    }

    let node_toml_str = match std::fs::read_to_string(&node_toml_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tri_sync_node: cannot read node config {}: {e}", node_toml_path.display());
            return ExitCode::FAILURE;
        }
    };

    let config = match config::load_from_str(&node_toml_str) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tri_sync_node: {e}");
            return ExitCode::FAILURE;
        }
    };

    let license_str = match std::fs::read_to_string(&config.license_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tri_sync_node: cannot read license file {}: {e}", config.license_path);
            return ExitCode::FAILURE;
        }
    };

    let lic = match license::parse_and_verify(&license_str, license::LICENSE_PUBLIC_KEY_HEX) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("tri_sync_node: license rejected: {e}");
            return ExitCode::FAILURE;
        }
    };

    let network_size = config.network_size();
    if !lic.allows_node_count(network_size as u32) {
        eprintln!(
            "tri_sync_node: node.toml configures {network_size} node(s) (this node + {} peer(s)), \
             but the license for '{}' allows at most {} node(s)",
            config.peers.len(),
            lic.org,
            lic.max_nodes
        );
        return ExitCode::FAILURE;
    }

    println!(
        "tri_sync_node: license OK - org='{}' max_nodes={} features={:?} expiry={}",
        lic.org, lic.max_nodes, lic.features, lic.expiry
    );

    let store = match persistence::Store::open(std::path::Path::new(&config.data_dir)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tri_sync_node: cannot open data_dir {}: {e}", config.data_dir);
            return ExitCode::FAILURE;
        }
    };

    let (node_state, loaded_from_disk) = match state::NodeState::load_or_init(&config, &store, &mut OsRng) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tri_sync_node: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "tri_sync_node: node {} {} - dim={} listen_addr={} peers={:?} pubkey={} head_height={} head_hash={}",
        node_state.node_id,
        if loaded_from_disk { "restored from data_dir" } else { "initialized fresh" },
        config.dim,
        config.listen_addr,
        config.peers.iter().map(|p| p.id).collect::<Vec<_>>(),
        hex::encode(node_state.verifying_key.to_bytes()),
        node_state.head().height,
        node_state.head().hash,
    );

    if show_identity_only {
        return ExitCode::SUCCESS;
    }

    if rotate_key_only {
        return rotate_key(&config, &store, &node_state.signing_key).await;
    }

    if let Some((id, addr, pubkey_hex)) = propose_add_peer {
        return propose_membership_change(&config, &node_state.signing_key, MembershipChange::Add { node_id: id, addr, pubkey_hex }).await;
    }
    if let Some(id) = propose_remove_peer {
        return propose_membership_change(&config, &node_state.signing_key, MembershipChange::Remove { node_id: id }).await;
    }

    let listen_addr: std::net::SocketAddr = match config.listen_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("tri_sync_node: invalid listen_addr '{}': {e}", config.listen_addr);
            return ExitCode::FAILURE;
        }
    };

    let server_endpoint = match net::make_server_endpoint(listen_addr, &node_state.signing_key) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("tri_sync_node: cannot start QUIC server on {listen_addr}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let client_endpoint = match net::make_client_endpoint() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("tri_sync_node: cannot start QUIC client endpoint: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("tri_sync_node: listening on {listen_addr}");
    let _ = std::io::stdout().flush();

    let peer_ids: Vec<usize> = config.peers.iter().map(|p| p.id).collect();
    let node_metrics = std::sync::Arc::new(metrics::Metrics::new(&peer_ids));
    if let Some(metrics_addr_str) = &config.metrics_addr {
        let metrics_addr: std::net::SocketAddr = metrics_addr_str.parse().expect("validated at config load");
        match metrics::serve(metrics_addr, node_metrics.clone()) {
            Ok(_handle) => println!("tri_sync_node: serving Prometheus metrics on http://{metrics_addr}/metrics"),
            Err(e) => eprintln!("tri_sync_node: cannot start metrics server on {metrics_addr}: {e}"),
        }
    }

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(net::serve(server_endpoint, tx));

    let duration = duration_secs.map(std::time::Duration::from_secs);
    consensus::run(config, node_state, store, client_endpoint, rx, duration, node_metrics).await;

    ExitCode::SUCCESS
}

/// Generates a fresh signing key, persists it as this node's new
/// identity, and announces it to every configured peer (signed by the
/// *old* key, proving continuity - see `protocol::KeyRotationMsg`).
///
/// **Caller must have already stopped this node's own main process.**
/// See the `--rotate-key` usage note above the `main` flag parser for
/// the real, live-tested reason: running this alongside a still-up old
/// process races it and can wedge a peer that's mid-vote.
///
/// Persists before broadcasting: if this process dies partway through
/// notifying peers, this node's own on-disk identity is unambiguous
/// either way, and the peers that *did* receive the announcement have
/// already moved on - there's no way to "undo" a partial broadcast
/// that wouldn't just be a second, equally-partial one.
///
/// Disclosed limitation, not solved here: a peer that's offline (or
/// otherwise misses the announcement) at rotation time has no way to
/// learn the new key automatically afterward - there's no retry or
/// resend of a missed announcement in this pass. Re-running
/// `--rotate-key` doesn't help either, since that mints a *new* key
/// and seq rather than resending the same one; recovering a peer that
/// missed an announcement needs a manual nudge (e.g. restarting it
/// after it next receives a signed message from this node's new key
/// through some other path) outside this mechanism's scope.
async fn rotate_key(config: &config::NodeConfig, store: &persistence::Store, old_signing_key: &SigningKey) -> ExitCode {
    let new_signing_key = SigningKey::generate(&mut OsRng);
    let new_pubkey_hex = hex::encode(new_signing_key.verifying_key().to_bytes());

    let next_seq = match store.get_own_rotation_seq() {
        Ok(seq) => seq.unwrap_or(0) + 1,
        Err(e) => {
            eprintln!("tri_sync_node: cannot read this node's rotation counter: {e}");
            return ExitCode::FAILURE;
        }
    };

    let canon = protocol::key_rotation_canon(config.node_id, &new_pubkey_hex, next_seq);
    let sig = crypto::sign_canon(old_signing_key, &canon);
    let msg = Message::KeyRotation(KeyRotationMsg {
        sender: config.node_id,
        new_pubkey_hex: new_pubkey_hex.clone(),
        rotation_seq: next_seq,
        sig_hex: hex::encode(sig.to_bytes()),
    });

    if let Err(e) = store.put_signing_key(&new_signing_key) {
        eprintln!("tri_sync_node: failed to persist the new key - aborting before notifying any peer: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = store.put_own_rotation_seq(next_seq) {
        eprintln!("tri_sync_node: failed to persist the new rotation counter - aborting before notifying any peer: {e}");
        return ExitCode::FAILURE;
    }
    println!("tri_sync_node: persisted new identity locally - new pubkey={new_pubkey_hex} rotation_seq={next_seq}");

    let endpoint = match net::make_client_endpoint() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("tri_sync_node: new key is persisted, but cannot open a client endpoint to notify peers: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut any_failed = false;
    for peer in &config.peers {
        let addr: std::net::SocketAddr = peer.addr.parse().expect("validated at config load");
        // config::load_from_str already validated pubkey_hex at config
        // load time, so this can only fail if that validation and this
        // decode somehow disagree - never expected in practice.
        let peer_pubkey = hex::decode(&peer.pubkey_hex).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()).and_then(|a| VerifyingKey::from_bytes(&a).ok());
        match net::send_message(&endpoint, addr, peer_pubkey, &msg).await {
            Ok(()) => println!("tri_sync_node: notified peer {} at {addr}", peer.id),
            Err(e) => {
                eprintln!("tri_sync_node: failed to notify peer {} at {addr}: {e}", peer.id);
                any_failed = true;
            }
        }
    }

    println!("tri_sync_node: key rotation complete - restart this node normally to use the new identity");
    if any_failed {
        eprintln!("tri_sync_node: at least one peer was not notified - see the disclosed limitation in this binary's --rotate-key handling");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Signs `change` with this node's own key and broadcasts it to every
/// peer in this node's `node.toml` as a [`MembershipProposalMsg`] -
/// see the `--propose-add-peer`/`--propose-remove-peer` usage note
/// above the `main` flag parser for what this does and doesn't
/// guarantee. Broadcasting itself changes nothing: it only asks
/// whichever of these peers next becomes proposer to attach `change`
/// to its own next block (`consensus::handle_membership_proposal`),
/// which still has to earn a real precommit quorum under the actual
/// current membership before anything takes effect.
async fn propose_membership_change(config: &config::NodeConfig, signing_key: &SigningKey, change: MembershipChange) -> ExitCode {
    let canon = protocol::membership_proposal_canon(config.node_id, &change);
    let sig = crypto::sign_canon(signing_key, &canon);
    let msg = Message::MembershipProposal(MembershipProposalMsg { sender: config.node_id, change: change.clone(), sig_hex: hex::encode(sig.to_bytes()) });
    println!("tri_sync_node: proposing membership change {change:?}");

    let endpoint = match net::make_client_endpoint() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("tri_sync_node: cannot open a client endpoint to propose this change: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut any_failed = false;
    for peer in &config.peers {
        let addr: std::net::SocketAddr = peer.addr.parse().expect("validated at config load");
        let peer_pubkey = hex::decode(&peer.pubkey_hex).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()).and_then(|a| VerifyingKey::from_bytes(&a).ok());
        match net::send_message(&endpoint, addr, peer_pubkey, &msg).await {
            Ok(()) => println!("tri_sync_node: sent proposal to peer {} at {addr}", peer.id),
            Err(e) => {
                eprintln!("tri_sync_node: failed to send proposal to peer {} at {addr}: {e}", peer.id);
                any_failed = true;
            }
        }
    }

    println!(
        "tri_sync_node: proposal sent - it takes effect only once whichever peer proposes next attaches it to a block that reaches real quorum"
    );
    if any_failed {
        eprintln!(
            "tri_sync_node: at least one configured peer was not reached - this is a liveness gap only (see this binary's usage note); \
             the change may still get proposed by a peer that did receive it"
        );
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
