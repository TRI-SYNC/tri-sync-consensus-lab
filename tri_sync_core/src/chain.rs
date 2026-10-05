//! Block/chain types, canonical hashing, and fork-choice - extracted
//! verbatim (verified against the source, not from memory) from
//! `tri_sync_chain_crypto`, the most complete existing chain variant
//! (signed blocks, weighted quorum, fork reconciliation).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn hex16(bytes: &[u8]) -> String {
    let h = hex::encode(bytes);
    h[..16].to_string()
}

/// Digests a state vector into a fixed-size hash instead of formatting
/// it directly into the canonical signing string below - keeps
/// `canon_string` a fixed shape regardless of the vector's
/// dimensionality.
pub fn hash_vec(v: &[f64]) -> String {
    let mut hasher = Sha256::new();
    for x in v {
        hasher.update(format!("{x:.8}").as_bytes());
        hasher.update(b",");
    }
    hex16(&hasher.finalize())
}

/// Same reasoning as `hash_vec`, for the list of a reconcile block's
/// superseded sibling hashes: a fixed-size digest instead of a
/// canon_string whose length would otherwise grow with how many
/// siblings a given fork happened to produce.
pub fn hash_list(xs: &[String]) -> String {
    let mut hasher = Sha256::new();
    for s in xs {
        hasher.update(s.as_bytes());
        hasher.update(b"|");
    }
    hex16(&hasher.finalize())
}

pub fn canon_string(
    height: u64,
    parent: &str,
    state_hash: &str,
    confidence: f64,
    reconciles_hash: &str,
    epoch: u64,
    membership_hash: &str,
) -> String {
    format!("{height}|{parent}|{state_hash}|{confidence:.8}|{reconciles_hash}|{epoch}|{membership_hash}")
}

/// A proposed change to who counts toward quorum - see `Block::
/// membership_change`'s doc comment for how one takes effect.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MembershipChange {
    Add { node_id: usize, addr: String, pubkey_hex: String },
    Remove { node_id: usize },
}

/// A fixed-size digest of `mc`, folded into `canon_string` the same
/// way `hash_vec`/`hash_list` are - a `None` change hashes to a fixed
/// sentinel distinct from any real change. Nothing needs to recover
/// the original value from this hash, only to notice if it changes,
/// so a plain delimited encoding is enough - no need for a full
/// serialization dependency just for this.
pub fn hash_membership_change(mc: &Option<MembershipChange>) -> String {
    let encoded = match mc {
        None => "none".to_string(),
        Some(MembershipChange::Add { node_id, addr, pubkey_hex }) => format!("add|{node_id}|{addr}|{pubkey_hex}"),
        Some(MembershipChange::Remove { node_id }) => format!("remove|{node_id}"),
    };
    let mut hasher = Sha256::new();
    hasher.update(encoded.as_bytes());
    hex16(&hasher.finalize())
}

pub fn block_hash(canon: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canon.as_bytes());
    hex16(&hasher.finalize())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigEntry {
    pub node_id: usize,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Block {
    pub height: u64,
    pub parent: String,
    pub state: Vec<f64>,
    pub confidence: f64,
    pub reconciles: Vec<String>,
    pub epoch: u64,
    pub signatures: Vec<SigEntry>,
    pub sig_weight: f64,
    pub hash: String,
    /// The view whose quorum-certificate `signatures` actually is -
    /// filled in independently at commit time (like `signatures`/
    /// `sig_weight`, and likewise excluded from `canon_string`/
    /// `block_hash`: it's a fact *about* the block, not part of its
    /// identity). What lets anyone who did *not* participate in
    /// committing a block still independently verify it later purely
    /// from its persisted form - chain-sync's whole premise - by
    /// reconstructing exactly what each signature in `signatures` was
    /// supposed to sign.
    ///
    /// `#[serde(default)]`: a block persisted before this field
    /// existed deserializes with `0`, which is only actually correct
    /// if it really did commit at view 0. A node resuming from
    /// pre-existing data recorded before this field shipped can't
    /// retroactively recover the true value, so such a block may fail
    /// re-verification by a node syncing it fresh later - a disclosed,
    /// one-time migration edge case, not a live concern for any block
    /// committed after this field was added.
    #[serde(default)]
    pub committed_at_view: u64,
    /// A change to who counts toward quorum, carried by this block
    /// and taking effect the instant this block itself reaches a real
    /// quorum-certificate under the membership as it stood *before*
    /// this block - see `crate::consensus`'s module doc comment on
    /// dynamic membership for the full mechanism, and why piggybacking
    /// on the existing block-commit path (rather than a separate
    /// membership protocol) is what makes this safe with no new
    /// agreement machinery. Part of this block's real identity (folded
    /// into `canon_string` via `hash_membership_change`), unlike
    /// `signatures`/`sig_weight`/`committed_at_view`: changing it
    /// changes what this block actually *is*, not just what's known
    /// about it after the fact.
    #[serde(default)]
    pub membership_change: Option<MembershipChange>,
}

impl Block {
    /// The all-zero genesis block for a state vector of dimension `dim`.
    pub fn genesis(dim: usize) -> Block {
        Block {
            height: 0,
            parent: String::new(),
            state: vec![0.0; dim],
            confidence: 1.0,
            reconciles: vec![],
            epoch: 0,
            signatures: vec![],
            sig_weight: 999.0,
            hash: "GENESIS".to_string(),
            committed_at_view: 0,
            membership_change: None,
        }
    }
}

/// True if `b` is preferred over `a` as head. Height dominates
/// absolutely - a taller chain always wins regardless of how
/// well-supported or confident a same-or-lower-height rival is - and
/// only among equal heights does sig_weight (how much support a block
/// actually got) get to break the tie before confidence (how tight the
/// contributing estimates were) does.
pub fn prefer(a: &Block, b: &Block) -> bool {
    if b.height != a.height { return b.height > a.height; }
    if (b.sig_weight - a.sig_weight).abs() > f64::EPSILON { return b.sig_weight > a.sig_weight; }
    if (b.confidence - a.confidence).abs() > f64::EPSILON { return b.confidence > a.confidence; }
    false
}

/// How many committed blocks make up one epoch. Arbitrary but
/// disclosed: small enough to actually observe a rotation in a short
/// real run or test, not tied to any particular `round_interval_secs`
/// since epoch rotation is keyed off committed height, not wall-clock
/// time (see `epoch_for_height`).
pub const BLOCKS_PER_EPOCH: u64 = 10;

/// The epoch a block at `height` belongs to. Deliberately a pure
/// function of height rather than a wall-clock timer: every node
/// converges on the same committed height through consensus itself,
/// so deriving epoch from height means every honest node agrees on
/// the current epoch with no separate coordination needed - unlike
/// `crate::consensus`'s view-change timers (Hardening 4), which
/// genuinely do drift across independently-clocked nodes and need
/// catch-up logic precisely because of that.
pub fn epoch_for_height(height: u64) -> u64 {
    height / BLOCKS_PER_EPOCH
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_for_height_is_zero_for_the_whole_first_epoch() {
        for h in 0..BLOCKS_PER_EPOCH {
            assert_eq!(epoch_for_height(h), 0);
        }
    }

    #[test]
    fn epoch_for_height_increments_exactly_at_each_boundary() {
        assert_eq!(epoch_for_height(BLOCKS_PER_EPOCH - 1), 0);
        assert_eq!(epoch_for_height(BLOCKS_PER_EPOCH), 1);
        assert_eq!(epoch_for_height(2 * BLOCKS_PER_EPOCH - 1), 1);
        assert_eq!(epoch_for_height(2 * BLOCKS_PER_EPOCH), 2);
    }

    #[test]
    fn epoch_for_height_is_monotonically_non_decreasing() {
        let mut prev = epoch_for_height(0);
        for h in 1..(5 * BLOCKS_PER_EPOCH) {
            let e = epoch_for_height(h);
            assert!(e == prev || e == prev + 1, "epoch must never jump by more than one or ever decrease");
            prev = e;
        }
    }

    #[test]
    fn taller_chain_always_wins_regardless_of_weight_or_confidence() {
        let a = Block { height: 5, sig_weight: 100.0, confidence: 1.0, ..Block::genesis(1) };
        let b = Block { height: 6, sig_weight: 0.0, confidence: 0.0, ..Block::genesis(1) };
        assert!(prefer(&a, &b));
        assert!(!prefer(&b, &a));
    }

    #[test]
    fn equal_height_breaks_tie_on_sig_weight_before_confidence() {
        let a = Block { height: 5, sig_weight: 1.0, confidence: 0.99, ..Block::genesis(1) };
        let b = Block { height: 5, sig_weight: 2.0, confidence: 0.01, ..Block::genesis(1) };
        assert!(prefer(&a, &b), "higher sig_weight should win despite lower confidence");
    }

    #[test]
    fn equal_height_and_weight_breaks_tie_on_confidence() {
        let a = Block { height: 5, sig_weight: 1.0, confidence: 0.5, ..Block::genesis(1) };
        let b = Block { height: 5, sig_weight: 1.0, confidence: 0.9, ..Block::genesis(1) };
        assert!(prefer(&a, &b));
    }

    #[test]
    fn hash_functions_are_deterministic() {
        let v = vec![1.0, 2.0, 3.0];
        assert_eq!(hash_vec(&v), hash_vec(&v));
        let xs = vec!["a".to_string(), "b".to_string()];
        assert_eq!(hash_list(&xs), hash_list(&xs));
    }

    #[test]
    fn different_state_vectors_hash_differently() {
        assert_ne!(hash_vec(&[1.0, 2.0]), hash_vec(&[1.0, 2.1]));
    }
}
