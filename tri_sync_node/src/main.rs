//! `tri_sync_node`: self-hosted, network-capable tri-sync node.
//!
//! This binary loads `node.toml`, verifies `license.toml` against it,
//! initializes or restores state (keys, chain, trust), starts the QUIC
//! P2P transport, and runs the networked consensus round loop - see
//! [`tri_sync_node::consensus`] for what that loop actually does and
//! what's simplified about it.

use rand::rngs::OsRng;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
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
    let mut duration_secs: Option<u64> = None;
    let mut show_identity_only = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--duration" => duration_secs = args.next().and_then(|s| s.parse().ok()),
            "--show-identity" => show_identity_only = true,
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

    let listen_addr: std::net::SocketAddr = match config.listen_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("tri_sync_node: invalid listen_addr '{}': {e}", config.listen_addr);
            return ExitCode::FAILURE;
        }
    };

    let server_endpoint = match net::make_server_endpoint(listen_addr) {
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
