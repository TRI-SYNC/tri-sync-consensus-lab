//! `tri_sync_node`: self-hosted, network-capable tri-sync node.
//!
//! This binary loads `node.toml`, verifies `license.toml` against it,
//! initializes or restores state (keys, chain, trust), and then serves
//! the QUIC P2P transport, printing every message it receives. Running
//! real consensus rounds over that transport is the next stage - see
//! the crate's git history for the staged build-out.

use rand::rngs::OsRng;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use tri_sync_node::{config, license, net, persistence, state};

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let node_toml_path = args.next().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("node.toml"));

    // `--duration <secs>`: run the server for a bounded time then exit
    // cleanly, instead of forever. Meant for scripted tests; a real
    // deployment is run with no duration and left running until killed.
    let mut duration_secs: Option<u64> = None;
    while let Some(arg) = args.next() {
        if arg == "--duration" {
            duration_secs = args.next().and_then(|s| s.parse().ok());
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

    let listen_addr: std::net::SocketAddr = match config.listen_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("tri_sync_node: invalid listen_addr '{}': {e}", config.listen_addr);
            return ExitCode::FAILURE;
        }
    };

    let endpoint = match net::make_server_endpoint(listen_addr) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("tri_sync_node: cannot start QUIC server on {listen_addr}: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("tri_sync_node: listening on {listen_addr}");
    let _ = std::io::stdout().flush();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(net::serve(endpoint, tx));

    let print_loop = async {
        while let Some((remote, msg)) = rx.recv().await {
            println!("tri_sync_node: received from {remote}: {msg:?}");
            // stdout is fully (not line-) buffered when redirected to a
            // file or pipe, so a killed process can lose buffered log
            // lines - flush after every message so a tailed log is
            // never behind reality.
            let _ = std::io::stdout().flush();
        }
    };

    match duration_secs {
        Some(secs) => {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(secs), print_loop).await;
            println!("tri_sync_node: --duration elapsed, shutting down cleanly.");
        }
        None => print_loop.await,
    }

    ExitCode::SUCCESS
}
