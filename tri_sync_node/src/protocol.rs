//! The seven peer-to-peer message types, wire-serialized as JSON.
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
//! gets signed.
//!
//! [`BlockProposalMsg`]/[`BlockVoteMsg`] additionally carry a `view`
//! number, folded into what they sign via [`view_block_canon`] rather
//! than the block's own [`block_canon`] alone - a signature made for
//! one view can never be replayed into a different one, even if the
//! block content is identical. Right now every height only ever has
//! one view (nothing bumps it yet - that's the liveness/view-change
//! stage), so this doesn't change observable behavior today; it's the
//! mechanism that stage relies on for safety, tested on its own before
//! anything drives it.
//!
//! The transport layer ([`crate::net`]) deliberately does not verify
//! peer TLS certificates either - see that module's doc comment for
//! why message-level signing is the real authentication boundary.
//!
//! [`KeyRotationMsg`] (Hardening 8) is the odd one out: every other
//! message signs with the sender's *current* key and is verified
//! against it. This one signs with the sender's *old* key to vouch
//! for a *new* one - continuity of identity across a rotation, not a
//! claim about the message's own content. [`key_rotation_canon`]
//! folds in a `rotation_seq` that must strictly increase per sender
//! (tracked by whoever receives it, not by this module), so a
//! captured announcement can't be replayed later to roll a peer's
//! trusted key back to a since-superseded one.

use serde::{Deserialize, Serialize};
use tri_sync_core::chain::{self, Block};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Message {
    Observation(ObservationMsg),
    State(StateMsg),
    BlockProposal(BlockProposalMsg),
    BlockVote(BlockVoteMsg),
    Precommit(PrecommitMsg),
    TrustUpdate(TrustUpdateMsg),
    KeyRotation(KeyRotationMsg),
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
    pub view: u64,
    pub block: Block,
}

/// A vote (signature) on a proposed block, identified by its hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockVoteMsg {
    pub sender: usize,
    pub view: u64,
    pub block_hash: String,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

/// The canonical form of `block` alone (independent of view) - what
/// identifies a specific proposed block regardless of which view
/// produced it. Used for `Block::hash` / `BlockVoteMsg::block_hash`.
pub fn block_canon(block: &Block) -> String {
    let state_hash = chain::hash_vec(&block.state);
    let reconciles_hash = chain::hash_list(&block.reconciles);
    chain::canon_string(block.height, &block.parent, &state_hash, block.confidence, &reconciles_hash, block.epoch)
}

/// The exact string a [`BlockProposalMsg`]/[`BlockVoteMsg`] signs: the
/// view folded in front of the block's own canonical form.
pub fn view_block_canon(view: u64, block: &Block) -> String {
    format!("view|{view}|{}", block_canon(block))
}

/// A precommit (second-phase signature) on a block that has already
/// reached a *prevote* quorum certificate at `view` - the signer is
/// locking onto it. See `crate::consensus`'s module doc comment on
/// quorum-certificate locking for why this needs its own message type
/// rather than reusing [`BlockVoteMsg`]: a precommit must sign a
/// string ([`precommit_canon`]) that a prevote signature can never be
/// replayed into, or the two phases wouldn't actually be separate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrecommitMsg {
    pub sender: usize,
    pub view: u64,
    pub block_hash: String,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

/// The exact string a [`PrecommitMsg`] signs - domain-separated from
/// [`view_block_canon`] (what a proposal/prevote signs for the same
/// `view`/`block`) by the `PRECOMMIT|` prefix, so a signature made for
/// one phase can never be verified as valid for the other, even over
/// the identical view and block.
pub fn precommit_canon(view: u64, block: &Block) -> String {
    format!("PRECOMMIT|{}", view_block_canon(view, block))
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

/// `sender` announcing a new signing key, signed with their *old* one.
/// See this module's doc comment for why that's the opposite of every
/// other message type here, and why `rotation_seq` matters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyRotationMsg {
    pub sender: usize,
    pub new_pubkey_hex: String,
    pub rotation_seq: u64,
    pub sig_hex: String,
}

/// The exact string a [`KeyRotationMsg`] signs - with the sender's
/// OLD key, not the new one it's announcing.
pub fn key_rotation_canon(sender: usize, new_pubkey_hex: &str, rotation_seq: u64) -> String {
    format!("keyrot|{sender}|{new_pubkey_hex}|{rotation_seq}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_message_variant_round_trips_through_json() {
        let messages = vec![
            Message::Observation(ObservationMsg { sender: 1, values: vec![1.0, 2.0], sig_hex: "aa".to_string() }),
            Message::State(StateMsg { sender: 1, state: vec![1.0], confidence: 0.9, sig_hex: "bb".to_string() }),
            Message::BlockProposal(BlockProposalMsg { sender: 1, view: 0, block: Block::genesis(2) }),
            Message::BlockVote(BlockVoteMsg {
                sender: 1,
                view: 0,
                block_hash: "abc".to_string(),
                pubkey_hex: "def".to_string(),
                sig_hex: "ghi".to_string(),
            }),
            Message::Precommit(PrecommitMsg {
                sender: 1,
                view: 0,
                block_hash: "abc".to_string(),
                pubkey_hex: "def".to_string(),
                sig_hex: "jkl".to_string(),
            }),
            Message::TrustUpdate(TrustUpdateMsg { sender: 1, about_peer: 2, edge_weight: 1.5, sig_hex: "cc".to_string() }),
            Message::KeyRotation(KeyRotationMsg { sender: 1, new_pubkey_hex: "dd".to_string(), rotation_seq: 1, sig_hex: "ee".to_string() }),
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
    fn view_block_canon_is_sensitive_to_view_even_for_the_identical_block() {
        let block = Block::genesis(2);
        assert_eq!(view_block_canon(0, &block), view_block_canon(0, &block));
        assert_ne!(view_block_canon(0, &block), view_block_canon(1, &block));
    }

    #[test]
    fn view_block_canon_still_reflects_changes_to_the_block_itself() {
        let a = Block::genesis(2);
        let mut b = Block::genesis(2);
        b.height = 5;
        assert_ne!(view_block_canon(0, &a), view_block_canon(0, &b));
    }

    /// The whole point of a separate precommit phase (see
    /// `crate::consensus`'s module doc comment on quorum-certificate
    /// locking) depends on this: a signature made over what a
    /// prevote/proposal signs must never also verify as a valid
    /// precommit for the identical view and block, or the two phases
    /// wouldn't actually be cryptographically separate.
    #[test]
    fn precommit_canon_never_collides_with_view_block_canon() {
        let block = Block::genesis(2);
        assert_ne!(precommit_canon(0, &block), view_block_canon(0, &block));
    }

    #[test]
    fn precommit_canon_is_sensitive_to_view_and_block() {
        let a = Block::genesis(2);
        let mut b = Block::genesis(2);
        b.height = 5;
        assert_eq!(precommit_canon(0, &a), precommit_canon(0, &a));
        assert_ne!(precommit_canon(0, &a), precommit_canon(1, &a));
        assert_ne!(precommit_canon(0, &a), precommit_canon(0, &b));
    }

    #[test]
    fn canon_strings_of_different_message_types_never_collide() {
        // Same sender/id-ish numbers fed to each canon fn - the type
        // prefix must keep them apart even if the rest coincides.
        let a = observation_canon(1, &[2.0]);
        let b = state_canon(1, &[2.0], 0.0);
        let c = trust_update_canon(1, 0, 2.0);
        let d = key_rotation_canon(1, "0", 2);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
        assert_ne!(a, d);
        assert_ne!(b, d);
        assert_ne!(c, d);
    }

    #[test]
    fn key_rotation_canon_is_sensitive_to_every_field() {
        assert_eq!(key_rotation_canon(1, "abcd", 5), key_rotation_canon(1, "abcd", 5));
        assert_ne!(key_rotation_canon(1, "abcd", 5), key_rotation_canon(2, "abcd", 5));
        assert_ne!(key_rotation_canon(1, "abcd", 5), key_rotation_canon(1, "abce", 5));
        assert_ne!(key_rotation_canon(1, "abcd", 5), key_rotation_canon(1, "abcd", 6));
    }
}
