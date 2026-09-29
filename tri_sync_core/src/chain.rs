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

pub fn canon_string(height: u64, parent: &str, state_hash: &str, confidence: f64, reconciles_hash: &str, epoch: u64) -> String {
    format!("{height}|{parent}|{state_hash}|{confidence:.8}|{reconciles_hash}|{epoch}")
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

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
