//! `tri_sync_node`: self-hosted, network-capable tri-sync node.
//!
//! This binary currently loads `node.toml`, verifies `license.toml`
//! against it, and initializes in-memory state (keys, genesis chain,
//! trust toward configured peers) - Stages 1-3 of the
//! networked-commercial-node feature. Starting the P2P transport,
//! persisting state, and running real consensus rounds over the network
//! are later stages - see the crate's git history for the staged
//! build-out.

mod config;
mod license;
mod state;

use rand::rngs::OsRng;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let node_toml_path = std::env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("node.toml"));

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

    let node_state = state::NodeState::init(&config, &mut OsRng);

    println!(
        "tri_sync_node: node {} initialized - dim={} listen_addr={} peers={:?} pubkey={} genesis_hash={}",
        node_state.node_id,
        config.dim,
        config.listen_addr,
        config.peers.iter().map(|p| p.id).collect::<Vec<_>>(),
        hex::encode(node_state.verifying_key.to_bytes()),
        node_state.head().hash,
    );

    println!("tri_sync_node: no P2P transport yet (later stage) - shutting down cleanly.");
    ExitCode::SUCCESS
}
