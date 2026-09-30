//! The five peer-to-peer message types, wire-serialized as JSON.
//!
//! **Every message type carries an Ed25519 signature.** Earlier this
//! was true only of [`BlockProposalMsg`]/[`BlockVoteMsg`]; observation
//! and trust-update gossip were unsigned, which meant anyone who could
//! reach a node's QUIC port could inject fake observations or trust
//! reports just by claiming a known peer's node id. The `*_canon`
//! functions here build the exact byte string each message type signs
//! (prefixed per type so a signature for one kind of message can never
//! be replayed as another); `crate::consensus` signs on send and
//! verifies against the claimed sender's *configured* pubkey - never
//! whatever pubkey a message happens to carry - on receipt. This
//! module still doesn't verify anything itself; it only defines what
//! gets signed. Note this closes spoofing, not replay: an old,
//! validly-signed message can still be re-sent verbatim until a view
//! number or similar is added.
//!
//! The transport layer ([`crate::net`]) deliberately does not verify
//! peer TLS certificates either - see that module's doc comment for
//! why message-level signing is the real authentication boundary.

use serde::{Deserialize, Serialize};
use tri_sync_core::chain::{self, Block};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Message {
    Observation(ObservationMsg),
    State(StateMsg),
    BlockProposal(BlockProposalMsg),
    BlockVote(BlockVoteMsg),
    TrustUpdate(TrustUpdateMsg),
}

/// A raw sensor observation, broadcast before fusion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservationMsg {
    pub sender: usize,
    pub values: Vec<f64>,
    pub sig_hex: String,
}

/// The exact string an [`ObservationMsg`] signs.
pub fn observation_canon(sender: usize, values: &[f64]) -> String {
    format!("obs|{sender}|{}", chain::hash_vec(values))
}

/// A node's fused state estimate, broadcast after a fusion round.
/// Not yet produced or consumed by `crate::consensus`'s round loop -
/// signing support exists so it's ready when that changes, not because
/// anything sends it today.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateMsg {
    pub sender: usize,
    pub state: Vec<f64>,
    pub confidence: f64,
    pub sig_hex: String,
}

/// The exact string a [`StateMsg`] signs.
pub fn state_canon(sender: usize, state: &[f64], confidence: f64) -> String {
    format!("state|{sender}|{}|{confidence:.8}", chain::hash_vec(state))
}

/// A proposed next block for the chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockProposalMsg {
    pub sender: usize,
    pub block: Block,
}

/// A vote (signature) on a proposed block, identified by its hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockVoteMsg {
    pub sender: usize,
    pub block_hash: String,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

/// A gossiped update to how much `sender` trusts `about_peer`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustUpdateMsg {
    pub sender: usize,
    pub about_peer: usize,
    pub edge_weight: f64,
    pub sig_hex: String,
}

/// The exact string a [`TrustUpdateMsg`] signs.
pub fn trust_update_canon(sender: usize, about_peer: usize, edge_weight: f64) -> String {
    format!("trust|{sender}|{about_peer}|{edge_weight:.8}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_message_variant_round_trips_through_json() {
        let messages = vec![
            Message::Observation(ObservationMsg { sender: 1, values: vec![1.0, 2.0], sig_hex: "aa".to_string() }),
            Message::State(StateMsg { sender: 1, state: vec![1.0], confidence: 0.9, sig_hex: "bb".to_string() }),
            Message::BlockProposal(BlockProposalMsg { sender: 1, block: Block::genesis(2) }),
            Message::BlockVote(BlockVoteMsg {
                sender: 1,
                block_hash: "abc".to_string(),
                pubkey_hex: "def".to_string(),
                sig_hex: "ghi".to_string(),
            }),
            Message::TrustUpdate(TrustUpdateMsg { sender: 1, about_peer: 2, edge_weight: 1.5, sig_hex: "cc".to_string() }),
        ];
        for msg in messages {
            let json = serde_json::to_string(&msg).unwrap();
            let back: Message = serde_json::from_str(&json).unwrap();
            assert_eq!(msg, back);
        }
    }

    #[test]
    fn malformed_json_is_rejected_without_panicking() {
        assert!(serde_json::from_str::<Message>("not json").is_err());
        assert!(serde_json::from_str::<Message>(r#"{"Bogus": {}}"#).is_err());
    }

    #[test]
    fn observation_canon_is_sensitive_to_sender_and_values() {
        assert_eq!(observation_canon(1, &[1.0, 2.0]), observation_canon(1, &[1.0, 2.0]));
        assert_ne!(observation_canon(1, &[1.0, 2.0]), observation_canon(2, &[1.0, 2.0]));
        assert_ne!(observation_canon(1, &[1.0, 2.0]), observation_canon(1, &[1.0, 2.1]));
    }

    #[test]
    fn state_canon_is_sensitive_to_every_field() {
        assert_ne!(state_canon(1, &[1.0], 0.9), state_canon(2, &[1.0], 0.9));
        assert_ne!(state_canon(1, &[1.0], 0.9), state_canon(1, &[1.1], 0.9));
        assert_ne!(state_canon(1, &[1.0], 0.9), state_canon(1, &[1.0], 0.8));
    }

    #[test]
    fn trust_update_canon_is_sensitive_to_every_field() {
        assert_ne!(trust_update_canon(1, 2, 1.5), trust_update_canon(2, 2, 1.5));
        assert_ne!(trust_update_canon(1, 2, 1.5), trust_update_canon(1, 3, 1.5));
        assert_ne!(trust_update_canon(1, 2, 1.5), trust_update_canon(1, 2, 1.6));
    }

    #[test]
    fn canon_strings_of_different_message_types_never_collide() {
        // Same sender/id-ish numbers fed to each canon fn - the type
        // prefix must keep them apart even if the rest coincides.
        let a = observation_canon(1, &[2.0]);
        let b = state_canon(1, &[2.0], 0.0);
        let c = trust_update_canon(1, 0, 2.0);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }
}
