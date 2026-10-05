//! `tri_sync_node_probe`: a small operational/test tool that connects
//! to a running `tri_sync_node` over QUIC and sends one hand-crafted
//! [`tri_sync_node::protocol::Message`], then exits. Exists so the P2P
//! transport can be exercised against a real running node from another
//! process, not just unit-tested in-process.
//!
//! Deliberately unpinned by default (`--expect-pubkey` opts in): this
//! tool exists to probe/attack a real node from outside, including
//! sending to a target whose TLS identity the caller doesn't know or
//! trust yet - exactly the scenario `crate::net`'s pinned verification
//! would otherwise refuse by design. Pass `--expect-pubkey <hex>` to
//! instead exercise the real, pinned production path this tool's
//! messages would take from `crate::consensus::broadcast`.

use std::net::SocketAddr;
use std::process::ExitCode;
use tri_sync_node::net;
use tri_sync_node::protocol::Message;

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(addr_str), Some(msg_json)) = (args.next(), args.next()) else {
        eprintln!("usage: tri_sync_node_probe <peer_addr> <message-json> [--expect-pubkey <hex>]");
        return ExitCode::FAILURE;
    };
    let mut expect_pubkey_hex: Option<String> = None;
    while let Some(arg) = args.next() {
        if arg == "--expect-pubkey" {
            expect_pubkey_hex = args.next();
        }
    }

    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("tri_sync_node_probe: invalid address '{addr_str}': {e}");
            return ExitCode::FAILURE;
        }
    };

    let msg: Message = match serde_json::from_str(&msg_json) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("tri_sync_node_probe: invalid message JSON: {e}");
            return ExitCode::FAILURE;
        }
    };

    let expect_pubkey = match expect_pubkey_hex {
        Some(hex_str) => match hex::decode(&hex_str).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()).and_then(|a| ed25519_dalek::VerifyingKey::from_bytes(&a).ok()) {
            Some(pk) => Some(pk),
            None => {
                eprintln!("tri_sync_node_probe: --expect-pubkey value is not a valid Ed25519 public key");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    let endpoint = match net::make_client_endpoint() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("tri_sync_node_probe: cannot create client endpoint: {e}");
            return ExitCode::FAILURE;
        }
    };

    match net::send_message(&endpoint, addr, expect_pubkey, &msg).await {
        Ok(()) => {
            println!("tri_sync_node_probe: sent {msg:?} to {addr}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("tri_sync_node_probe: send to {addr} failed: {e}");
            ExitCode::FAILURE
        }
    }
}
