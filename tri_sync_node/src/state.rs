//! In-memory node state: this node's keypair, its genesis-only chain,
//! and its trust view of each configured peer.
//!
//! Building this from `tri_sync_core` types (rather than duplicating
//! them) is the whole point of Stage 1's extraction. Persisting this
//! state to disk is Stage 4; networking it is Stage 5.

use crate::config::NodeConfig;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{CryptoRng, RngCore};
use std::collections::HashMap;
use tri_sync_core::chain::Block;

/// Starting edge weight toward a peer with no observations yet - close
/// to the ~1.0 a freshly-added edge starts at in the existing
/// simulation binaries (`tri_sync_chain_crypto`), before Δe-learning
/// has adjusted it up or down.
pub const NEUTRAL_EDGE_WEIGHT: f64 = 1.0;

/// Starting reliability estimate for a peer with no observations yet:
/// the midpoint of `update_reliability`'s usual `[0, 1]` range - neither
/// trusted nor distrusted until evidence says otherwise.
pub const NEUTRAL_RELIABILITY: f64 = 0.5;

// signing_key/epoch/edge_weight/reliability aren't read by this stage's
// main.rs yet - they're consumed once P2P transport and consensus
// rounds (Stage 5+) actually sign messages and update trust. Already
// exercised by this module's own tests.
#[allow(dead_code)]
pub struct NodeState {
    pub node_id: usize,
    pub chain: Vec<Block>,
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub epoch: u64,
    /// This node's edge weight toward each peer, keyed by peer id.
    pub edge_weight: HashMap<usize, f64>,
    /// This node's reliability estimate for each peer, keyed by peer id.
    pub reliability: HashMap<usize, f64>,
}

impl NodeState {
    /// Builds the initial state for `config`: a fresh Ed25519 keypair
    /// for epoch 0 (via `tri_sync_core::crypto::regen_keys`), a
    /// single-block genesis chain, and neutral trust toward every
    /// configured peer.
    pub fn init(config: &NodeConfig, rng: &mut (impl RngCore + CryptoRng)) -> NodeState {
        let mut signing = Vec::new();
        let mut verify = Vec::new();
        tri_sync_core::crypto::regen_keys(rng, 0, 1, &mut signing, &mut verify);

        let edge_weight = config.peers.iter().map(|p| (p.id, NEUTRAL_EDGE_WEIGHT)).collect();
        let reliability = config.peers.iter().map(|p| (p.id, NEUTRAL_RELIABILITY)).collect();

        NodeState {
            node_id: config.node_id,
            chain: vec![Block::genesis(config.dim)],
            signing_key: signing.remove(0),
            verifying_key: verify[0],
            epoch: 0,
            edge_weight,
            reliability,
        }
    }

    pub fn head(&self) -> &Block {
        self.chain.last().expect("chain always has at least the genesis block")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NodeConfig, PeerConfig};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn test_config() -> NodeConfig {
        NodeConfig {
            node_id: 0,
            dim: 3,
            listen_addr: "0.0.0.0:9000".to_string(),
            license_path: "license.toml".to_string(),
            peers: vec![
                PeerConfig { id: 1, addr: "127.0.0.1:9001".to_string() },
                PeerConfig { id: 2, addr: "127.0.0.1:9002".to_string() },
            ],
        }
    }

    #[test]
    fn init_builds_a_genesis_only_chain_of_the_configured_dimension() {
        let config = test_config();
        let mut rng = StdRng::seed_from_u64(1);
        let state = NodeState::init(&config, &mut rng);
        assert_eq!(state.chain.len(), 1);
        assert_eq!(state.head().height, 0);
        assert_eq!(state.head().state.len(), 3);
        assert_eq!(state.head().hash, "GENESIS");
    }

    #[test]
    fn init_gives_neutral_trust_toward_every_configured_peer_and_nobody_else() {
        let config = test_config();
        let mut rng = StdRng::seed_from_u64(1);
        let state = NodeState::init(&config, &mut rng);
        assert_eq!(state.edge_weight.get(&1), Some(&NEUTRAL_EDGE_WEIGHT));
        assert_eq!(state.edge_weight.get(&2), Some(&NEUTRAL_EDGE_WEIGHT));
        assert_eq!(state.reliability.get(&1), Some(&NEUTRAL_RELIABILITY));
        assert_eq!(state.edge_weight.len(), 2);
        assert_eq!(state.reliability.len(), 2);
    }

    #[test]
    fn the_signing_key_and_verifying_key_are_a_matching_pair() {
        let config = test_config();
        let mut rng = StdRng::seed_from_u64(1);
        let state = NodeState::init(&config, &mut rng);
        assert_eq!(state.signing_key.verifying_key(), state.verifying_key);
    }

    #[test]
    fn init_is_deterministic_given_the_same_seed() {
        let config = test_config();
        let state_a = NodeState::init(&config, &mut StdRng::seed_from_u64(42));
        let state_b = NodeState::init(&config, &mut StdRng::seed_from_u64(42));
        assert_eq!(state_a.verifying_key, state_b.verifying_key);
    }

    #[test]
    fn a_node_with_no_configured_peers_starts_with_empty_trust_maps() {
        let mut config = test_config();
        config.peers.clear();
        let mut rng = StdRng::seed_from_u64(1);
        let state = NodeState::init(&config, &mut rng);
        assert!(state.edge_weight.is_empty());
        assert!(state.reliability.is_empty());
    }
}
