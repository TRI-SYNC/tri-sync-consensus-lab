//! The five peer-to-peer message types, wire-serialized as JSON.
//!
//! Message *authentication* is not this module's job: a
//! [`BlockVoteMsg`]/[`BlockProposalMsg`] carries its own Ed25519
//! signature (verified with `tri_sync_core::crypto`), and the
//! transport layer (see [`crate::net`]) deliberately does not verify
//! peer TLS certificates - see that module's doc comment for why.

use serde::{Deserialize, Serialize};
use tri_sync_core::chain::Block;

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
}

/// A node's fused state estimate, broadcast after a fusion round.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateMsg {
    pub sender: usize,
    pub state: Vec<f64>,
    pub confidence: f64,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_message_variant_round_trips_through_json() {
        let messages = vec![
            Message::Observation(ObservationMsg { sender: 1, values: vec![1.0, 2.0] }),
            Message::State(StateMsg { sender: 1, state: vec![1.0], confidence: 0.9 }),
            Message::BlockProposal(BlockProposalMsg { sender: 1, block: Block::genesis(2) }),
            Message::BlockVote(BlockVoteMsg {
                sender: 1,
                block_hash: "abc".to_string(),
                pubkey_hex: "def".to_string(),
                sig_hex: "ghi".to_string(),
            }),
            Message::TrustUpdate(TrustUpdateMsg { sender: 1, about_peer: 2, edge_weight: 1.5 }),
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
}
