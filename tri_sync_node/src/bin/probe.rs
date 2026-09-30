//! `tri_sync_node_probe`: a small operational/test tool that connects
//! to a running `tri_sync_node` over QUIC and sends one hand-crafted
//! [`tri_sync_node::protocol::Message`], then exits. Exists so the P2P
//! transport can be exercised against a real running node from another
//! process, not just unit-tested in-process.

use std::net::SocketAddr;
use std::process::ExitCode;
use tri_sync_node::net;
use tri_sync_node::protocol::Message;

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(addr_str), Some(msg_json)) = (args.next(), args.next()) else {
        eprintln!("usage: tri_sync_node_probe <peer_addr> <message-json>");
        return ExitCode::FAILURE;
    };

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

    let endpoint = match net::make_client_endpoint() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("tri_sync_node_probe: cannot create client endpoint: {e}");
            return ExitCode::FAILURE;
        }
    };

    match net::send_message(&endpoint, addr, &msg).await {
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
