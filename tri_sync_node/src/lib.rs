//! Library surface for `tri_sync_node`'s three binaries (`tri_sync_node`
//! itself, the `tri_sync_node_probe` test/ops tool, and the
//! `tri_sync_node_license_tool` license-signing CLI): config and
//! license loading, persisted and in-memory node state, and the QUIC
//! P2P transport.

pub mod config;
pub mod consensus;
pub mod health;
pub mod license;
pub mod metrics;
pub mod net;
pub mod persistence;
pub mod protocol;
pub mod state;
#[cfg(test)]
pub mod test_support;
