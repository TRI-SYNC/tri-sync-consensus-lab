//! The ten peer-to-peer message types, wire-serialized as JSON.
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
//! block content is identical. [`PrecommitMsg`] signs a third,
//! further domain-separated string ([`precommit_canon`]) built from
//! that same `view_block_canon`, so a prevote and a precommit can
//! never be confused for each other either - see `crate::consensus`'s
//! module doc comment on quorum-certificate locking for why that
//! separation is load-bearing for safety, not just tidiness.
//!
//! [`BlockRequestMsg`]/[`BlockResponseMsg`] (chain-sync) are the odd
//! ones out structurally: the real safety property for a synced block
//! doesn't come from the envelope signature at all, but from each
//! [`Block`]'s own already-embedded quorum-certificate `signatures` -
//! independently reconstructible and verifiable by anyone via
//! `Block::committed_at_view` plus [`precommit_canon`], with no need
//! to trust whoever happens to be relaying it. The envelope is signed
//! anyway, consistently with every other message type here, so a
//! forged request/response is still rejected before its contents are
//! trusted at all.
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
    BlockRequest(BlockRequestMsg),
    BlockResponse(BlockResponseMsg),
    MembershipProposal(MembershipProposalMsg),
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
    let membership_hash = chain::hash_membership_change(&block.membership_change);
    chain::canon_string(block.height, &block.parent, &state_hash, block.confidence, &reconciles_hash, block.epoch, &membership_hash)
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

/// A request to catch up: "send me every committed block you have
/// starting at `from_height`." Sent when a node observes (via a
/// proposal for a height it can't yet accept) that the network has
/// moved further ahead than it has - see `crate::consensus`'s
/// chain-sync handling.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockRequestMsg {
    pub sender: usize,
    pub from_height: u64,
    pub sig_hex: String,
}

/// The exact string a [`BlockRequestMsg`] signs.
pub fn block_request_canon(sender: usize, from_height: u64) -> String {
    format!("blockreq|{sender}|{from_height}")
}

/// The reply to a [`BlockRequestMsg`]: every committed block the
/// responder has at or above the requested height, oldest first, up
/// to `crate::consensus`'s own batch cap (a single response is never
/// unbounded). Each block carries its own already-formed
/// quorum-certificate `signatures` - the receiving node verifies
/// those directly (via `Block::committed_at_view` and
/// [`precommit_canon`]) rather than trusting this message's own
/// signature for anything beyond "a known peer really sent this
/// batch, not a forged one."
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockResponseMsg {
    pub sender: usize,
    pub blocks: Vec<Block>,
    pub sig_hex: String,
}

/// The exact string a [`BlockResponseMsg`] signs - over a digest of
/// the batch's blocks (by their own already-computed, content-derived
/// `hash` field, cheaper than re-hashing full block content) rather
/// than the full payload, since a response can be large.
pub fn block_response_canon(sender: usize, blocks: &[Block]) -> String {
    let hashes: Vec<String> = blocks.iter().map(|b| b.hash.clone()).collect();
    format!("blockresp|{sender}|{}", chain::hash_list(&hashes))
}

/// `sender` (which must be a *current* member - checked on receipt,
/// never by this type itself) proposing a change to who counts toward
/// quorum. Accepting this only ever means "I'll attach this to the
/// next block I propose" - see `crate::consensus`'s module doc
/// comment on dynamic membership for why that's enough: the change
/// itself still only takes effect if that specific block goes on to
/// reach a real precommit quorum under the *current* membership, so
/// a proposal alone, from however many senders, can never itself
/// change who counts toward anything.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MembershipProposalMsg {
    pub sender: usize,
    pub change: chain::MembershipChange,
    pub sig_hex: String,
}

/// The exact string a [`MembershipProposalMsg`] signs.
pub fn membership_proposal_canon(sender: usize, change: &chain::MembershipChange) -> String {
    format!("memberprop|{sender}|{}", chain::hash_membership_change(&Some(change.clone())))
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
            Message::BlockRequest(BlockRequestMsg { sender: 1, from_height: 5, sig_hex: "ff".to_string() }),
            Message::BlockResponse(BlockResponseMsg { sender: 1, blocks: vec![Block::genesis(2)], sig_hex: "gg".to_string() }),
            Message::MembershipProposal(MembershipProposalMsg {
                sender: 1,
                change: chain::MembershipChange::Add { node_id: 2, addr: "127.0.0.1:2".to_string(), pubkey_hex: "ab".repeat(32) },
                sig_hex: "hh".to_string(),
            }),
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
        let e = block_request_canon(1, 2);
        let f = block_response_canon(1, &[Block::genesis(1)]);
        let g = membership_proposal_canon(1, &chain::MembershipChange::Remove { node_id: 2 });
        let all = [&a, &b, &c, &d, &e, &f, &g];
        for (i, x) in all.iter().enumerate() {
            for (j, y) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(x, y, "canon strings at indices {i} and {j} must never collide");
                }
            }
        }
    }

    #[test]
    fn block_request_canon_is_sensitive_to_every_field() {
        assert_eq!(block_request_canon(1, 5), block_request_canon(1, 5));
        assert_ne!(block_request_canon(1, 5), block_request_canon(2, 5));
        assert_ne!(block_request_canon(1, 5), block_request_canon(1, 6));
    }

    #[test]
    fn block_response_canon_is_sensitive_to_sender_and_block_content() {
        let mut b = Block::genesis(2);
        b.height = 3;
        let identity_canon = block_canon(&b);
        b.hash = chain::block_hash(&identity_canon);
        assert_eq!(block_response_canon(1, &[Block::genesis(2)]), block_response_canon(1, &[Block::genesis(2)]));
        assert_ne!(block_response_canon(1, &[Block::genesis(2)]), block_response_canon(2, &[Block::genesis(2)]));
        assert_ne!(block_response_canon(1, &[Block::genesis(2)]), block_response_canon(1, &[b]));
        assert_ne!(block_response_canon(1, &[Block::genesis(2)]), block_response_canon(1, &[]));
    }

    #[test]
    fn key_rotation_canon_is_sensitive_to_every_field() {
        assert_eq!(key_rotation_canon(1, "abcd", 5), key_rotation_canon(1, "abcd", 5));
        assert_ne!(key_rotation_canon(1, "abcd", 5), key_rotation_canon(2, "abcd", 5));
        assert_ne!(key_rotation_canon(1, "abcd", 5), key_rotation_canon(1, "abce", 5));
        assert_ne!(key_rotation_canon(1, "abcd", 5), key_rotation_canon(1, "abcd", 6));
    }
}
