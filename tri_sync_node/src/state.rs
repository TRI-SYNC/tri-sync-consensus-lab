//! Node state: this node's keypair, its chain, and its trust view of
//! each configured peer - built fresh via [`NodeState::init`] or
//! restored from an LMDB [`crate::persistence::Store`] via
//! [`NodeState::load_or_init`].
//!
//! Building this from `tri_sync_core` types (rather than duplicating
//! them) is the whole point of Stage 1's extraction. Networking it is
//! Stage 5.

use crate::config::NodeConfig;
use crate::persistence::{PersistError, Store, TrustEntry};
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

    /// Restores state from `store` if it holds a previously-persisted
    /// signing key, merging in neutral trust for any peer in `config`
    /// that isn't in the store yet (e.g. newly added since last run).
    /// Otherwise builds fresh state via [`NodeState::init`] and persists
    /// it immediately. Returns `(state, was_loaded_from_disk)`.
    pub fn load_or_init(
        config: &NodeConfig,
        store: &Store,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(NodeState, bool), PersistError> {
        let Some(signing_key) = store.get_signing_key()? else {
            let state = NodeState::init(config, rng);
            store.put_signing_key(&state.signing_key)?;
            store.put_epoch(state.epoch)?;
            store.put_block(&state.chain[0])?;
            for (&peer_id, &edge_weight) in &state.edge_weight {
                let reliability = state.reliability[&peer_id];
                store.put_trust(peer_id, TrustEntry { edge_weight, reliability })?;
            }
            return Ok((state, false));
        };

        let verifying_key = signing_key.verifying_key();
        let epoch = store.get_epoch()?.unwrap_or(0);
        let mut chain = store.all_blocks()?;
        if chain.is_empty() {
            chain.push(Block::genesis(config.dim));
        }

        let mut edge_weight = HashMap::new();
        let mut reliability = HashMap::new();
        for peer in &config.peers {
            let entry = match store.get_trust(peer.id)? {
                Some(e) => e,
                None => {
                    let fresh = TrustEntry { edge_weight: NEUTRAL_EDGE_WEIGHT, reliability: NEUTRAL_RELIABILITY };
                    store.put_trust(peer.id, fresh)?;
                    fresh
                }
            };
            edge_weight.insert(peer.id, entry.edge_weight);
            reliability.insert(peer.id, entry.reliability);
        }

        Ok((
            NodeState { node_id: config.node_id, chain, signing_key, verifying_key, epoch, edge_weight, reliability },
            true,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NodeConfig, PeerConfig};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    const DUMMY_PUBKEY: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn test_config() -> NodeConfig {
        NodeConfig {
            node_id: 0,
            dim: 3,
            listen_addr: "0.0.0.0:9000".to_string(),
            license_path: "license.toml".to_string(),
            data_dir: "data".to_string(),
            round_interval_secs: 3,
            metrics_addr: None,
            peers: vec![
                PeerConfig { id: 1, addr: "127.0.0.1:9001".to_string(), pubkey_hex: DUMMY_PUBKEY[..64].to_string() },
                PeerConfig { id: 2, addr: "127.0.0.1:9002".to_string(), pubkey_hex: DUMMY_PUBKEY[..64].to_string() },
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

    // --- load_or_init ---

    #[test]
    fn load_or_init_persists_fresh_state_and_reports_it_was_not_loaded() {
        let dir = crate::test_support::TempDir::new("load_or_init_fresh");
        let store = Store::open(dir.path()).unwrap();
        let config = test_config();
        let (state, loaded) = NodeState::load_or_init(&config, &store, &mut StdRng::seed_from_u64(1)).unwrap();
        assert!(!loaded);
        assert_eq!(store.get_signing_key().unwrap().unwrap().to_bytes(), state.signing_key.to_bytes());
        assert_eq!(store.all_blocks().unwrap().len(), 1);
    }

    #[test]
    fn load_or_init_restores_the_same_identity_and_chain_across_a_simulated_restart() {
        let dir = crate::test_support::TempDir::new("load_or_init_restart");
        let config = test_config();

        let first_pubkey = {
            let store = Store::open(dir.path()).unwrap();
            let (state, loaded) = NodeState::load_or_init(&config, &store, &mut StdRng::seed_from_u64(1)).unwrap();
            assert!(!loaded);
            state.verifying_key
        }; // store dropped: simulates the process exiting

        let store = Store::open(dir.path()).unwrap();
        let (state, loaded) = NodeState::load_or_init(&config, &store, &mut StdRng::seed_from_u64(999)).unwrap();
        assert!(loaded, "second call should have found the persisted identity");
        assert_eq!(state.verifying_key, first_pubkey, "restart must not generate a new identity");
        assert_eq!(state.chain.len(), 1);
    }

    #[test]
    fn load_or_init_fills_in_neutral_trust_for_a_peer_added_after_the_last_restart() {
        let dir = crate::test_support::TempDir::new("load_or_init_new_peer");
        let mut config = test_config();
        config.peers.truncate(1); // only peer 1, first run

        {
            let store = Store::open(dir.path()).unwrap();
            NodeState::load_or_init(&config, &store, &mut StdRng::seed_from_u64(1)).unwrap();
        }

        config.peers.push(PeerConfig {
            id: 2,
            addr: "127.0.0.1:9002".to_string(),
            pubkey_hex: DUMMY_PUBKEY[..64].to_string(),
        }); // peer 2 added later
        let store = Store::open(dir.path()).unwrap();
        let (state, loaded) = NodeState::load_or_init(&config, &store, &mut StdRng::seed_from_u64(1)).unwrap();
        assert!(loaded);
        assert_eq!(state.edge_weight.get(&1), Some(&NEUTRAL_EDGE_WEIGHT), "existing peer's trust preserved");
        assert_eq!(state.edge_weight.get(&2), Some(&NEUTRAL_EDGE_WEIGHT), "new peer gets neutral trust");
        assert_eq!(store.get_trust(2).unwrap(), Some(TrustEntry { edge_weight: NEUTRAL_EDGE_WEIGHT, reliability: NEUTRAL_RELIABILITY }));
    }
}
