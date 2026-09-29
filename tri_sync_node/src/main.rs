//! `tri_sync_node`: self-hosted, network-capable tri-sync node.
//!
//! This binary currently only enforces the license (Stage 2 of the
//! networked-commercial-node feature). Loading `node.toml`, starting the
//! P2P transport, and running real consensus rounds land in later
//! stages - see the crate's git history for the staged build-out.

mod license;

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let license_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("license.toml"));

    let toml_str = match std::fs::read_to_string(&license_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tri_sync_node: cannot read license file {}: {e}", license_path.display());
            return ExitCode::FAILURE;
        }
    };

    match license::parse_and_verify(&toml_str, license::LICENSE_PUBLIC_KEY_HEX) {
        Ok(lic) => {
            println!(
                "tri_sync_node: license OK - org='{}' max_nodes={} features={:?} expiry={}",
                lic.org, lic.max_nodes, lic.features, lic.expiry
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("tri_sync_node: license rejected: {e}");
            ExitCode::FAILURE
        }
    }
}
