//! LMDB-backed persistence (via `heed`) for blocks, trust, this node's
//! keypair, epoch metadata, (Hardening 8) rotated peer keys plus this
//! node's own key-rotation counter, this node's current
//! quorum-certificate lock (`LockRecord`), and the current dynamic
//! membership set (`MemberRecord`) - see `crate::consensus`'s module
//! doc comment for both.
//!
//! `heed` was chosen over RocksDB specifically because its LMDB source
//! is small and compiles in seconds in a sandboxed build, confirmed by
//! actually building it here, not assumed from the crate's description.

use byteorder::BigEndian;
use ed25519_dalek::SigningKey;
use heed::types::{Bytes, SerdeJson, Str, U64};
use heed::{Database, Env, EnvOpenOptions};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tri_sync_core::chain::Block;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TrustEntry {
    pub edge_weight: f64,
    pub reliability: f64,
}

/// A peer's current pubkey as last learned from a validly-signed
/// [`crate::protocol::KeyRotationMsg`] (Hardening 8), superseding
/// whatever `node.toml` originally configured for that peer.
/// `rotation_seq` is the strictly-increasing value from that message,
/// kept so a later restart can still reject a replayed, now-stale
/// announcement without needing to have stayed running.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerKeyRecord {
    pub pubkey_hex: String,
    pub rotation_seq: u64,
}

const SIGNING_KEY_KEY: &str = "signing_key";
const EPOCH_KEY: &str = "epoch";
const OWN_ROTATION_SEQ_KEY: &str = "own_rotation_seq";
const LOCK_KEY: &str = "lock";

/// This node's quorum-certificate lock (see `crate::consensus`'s
/// module doc comment) for whichever height is currently in flight -
/// persisted so a restart can't forget it and re-prevote for a
/// conflicting block, which would reopen exactly the safety gap
/// locking exists to close. At most one height is ever in flight at a
/// time (the same invariant `RoundState` relies on elsewhere), so a
/// single slot is enough; `run` ignores a loaded record whose height
/// is not exactly `head.height + 1` (already committed past, or
/// stale) rather than trusting it blindly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LockRecord {
    pub height: u64,
    pub view: u64,
    pub block_hash: String,
}

const MEMBERSHIP_INITIALIZED_KEY: &str = "membership_initialized";

/// A currently-recognized peer's address and key, keyed by node id in
/// the `members` database - the durable record of dynamic membership
/// (see `crate::consensus`'s module doc comment). Once
/// `mark_membership_initialized` has been called (the first time this
/// node ever starts), this - not `node.toml` - is the source of truth
/// for who's in the network: `node.toml`'s `[[peers]]` entries are
/// only ever a bootstrap seed for a brand-new data_dir.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemberRecord {
    pub addr: String,
    pub pubkey_hex: String,
}

#[derive(Debug)]
pub struct PersistError(String);

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "persistence error: {}", self.0)
    }
}

impl std::error::Error for PersistError {}

impl From<heed::Error> for PersistError {
    fn from(e: heed::Error) -> Self {
        PersistError(e.to_string())
    }
}

pub struct Store {
    env: Env,
    blocks: Database<U64<BigEndian>, SerdeJson<Block>>,
    trust: Database<U64<BigEndian>, SerdeJson<TrustEntry>>,
    keys: Database<Str, Bytes>,
    meta: Database<Str, U64<BigEndian>>,
    peer_keys: Database<U64<BigEndian>, SerdeJson<PeerKeyRecord>>,
    locks: Database<Str, SerdeJson<LockRecord>>,
    members: Database<U64<BigEndian>, SerdeJson<MemberRecord>>,
}

impl Store {
    /// Opens (creating if necessary) an LMDB environment at `dir` with
    /// the seven databases this node needs.
    pub fn open(dir: &Path) -> Result<Store, PersistError> {
        std::fs::create_dir_all(dir).map_err(|e| PersistError(format!("creating {}: {e}", dir.display())))?;
        // SAFETY: heed's `open` is unsafe because opening the same LMDB
        // environment concurrently from unrelated processes with
        // mismatched configuration (map size, max_dbs) is undefined
        // behavior. This node is the only process expected to open its
        // own data_dir, with a fixed max_dbs below.
        let env = unsafe { EnvOpenOptions::new().max_dbs(7).open(dir) }
            .map_err(|e| PersistError(format!("opening LMDB env at {}: {e}", dir.display())))?;

        let mut wtxn = env.write_txn()?;
        let blocks = env.create_database(&mut wtxn, Some("blocks"))?;
        let trust = env.create_database(&mut wtxn, Some("trust"))?;
        let keys = env.create_database(&mut wtxn, Some("keys"))?;
        let meta = env.create_database(&mut wtxn, Some("meta"))?;
        let peer_keys = env.create_database(&mut wtxn, Some("peer_keys"))?;
        let locks = env.create_database(&mut wtxn, Some("locks"))?;
        let members = env.create_database(&mut wtxn, Some("members"))?;
        wtxn.commit()?;

        Ok(Store { env, blocks, trust, keys, meta, peer_keys, locks, members })
    }

    pub fn put_block(&self, block: &Block) -> Result<(), PersistError> {
        let mut wtxn = self.env.write_txn()?;
        self.blocks.put(&mut wtxn, &block.height, block)?;
        wtxn.commit()?;
        Ok(())
    }

    /// All persisted blocks, ordered by ascending height.
    pub fn all_blocks(&self) -> Result<Vec<Block>, PersistError> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for entry in self.blocks.iter(&rtxn)? {
            let (_, block) = entry?;
            out.push(block);
        }
        Ok(out)
    }

    pub fn put_trust(&self, peer_id: usize, entry: TrustEntry) -> Result<(), PersistError> {
        let mut wtxn = self.env.write_txn()?;
        self.trust.put(&mut wtxn, &(peer_id as u64), &entry)?;
        wtxn.commit()?;
        Ok(())
    }

    pub fn get_trust(&self, peer_id: usize) -> Result<Option<TrustEntry>, PersistError> {
        let rtxn = self.env.read_txn()?;
        Ok(self.trust.get(&rtxn, &(peer_id as u64))?)
    }

    pub fn put_signing_key(&self, sk: &SigningKey) -> Result<(), PersistError> {
        let mut wtxn = self.env.write_txn()?;
        self.keys.put(&mut wtxn, SIGNING_KEY_KEY, sk.to_bytes().as_slice())?;
        wtxn.commit()?;
        Ok(())
    }

    /// The persisted signing key, if any. `Ok(None)` means no key has
    /// ever been persisted (a fresh data_dir); `Err` means the stored
    /// bytes are corrupt - callers should treat that as a hard failure,
    /// not silently regenerate a new identity.
    pub fn get_signing_key(&self) -> Result<Option<SigningKey>, PersistError> {
        let rtxn = self.env.read_txn()?;
        match self.keys.get(&rtxn, SIGNING_KEY_KEY)? {
            None => Ok(None),
            Some(bytes) => {
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| PersistError("stored signing key is not 32 bytes - data_dir is corrupt".to_string()))?;
                Ok(Some(SigningKey::from_bytes(&arr)))
            }
        }
    }

    pub fn put_epoch(&self, epoch: u64) -> Result<(), PersistError> {
        let mut wtxn = self.env.write_txn()?;
        self.meta.put(&mut wtxn, EPOCH_KEY, &epoch)?;
        wtxn.commit()?;
        Ok(())
    }

    pub fn get_epoch(&self) -> Result<Option<u64>, PersistError> {
        let rtxn = self.env.read_txn()?;
        Ok(self.meta.get(&rtxn, EPOCH_KEY)?)
    }

    /// Records a peer's rotated key, superseding `node.toml`'s
    /// original entry for that peer on every future load.
    pub fn put_peer_key(&self, peer_id: usize, record: &PeerKeyRecord) -> Result<(), PersistError> {
        let mut wtxn = self.env.write_txn()?;
        self.peer_keys.put(&mut wtxn, &(peer_id as u64), record)?;
        wtxn.commit()?;
        Ok(())
    }

    /// The last key rotation accepted from `peer_id`, if any.
    pub fn get_peer_key(&self, peer_id: usize) -> Result<Option<PeerKeyRecord>, PersistError> {
        let rtxn = self.env.read_txn()?;
        Ok(self.peer_keys.get(&rtxn, &(peer_id as u64))?)
    }

    /// This node's own rotation counter for its *outgoing*
    /// [`crate::protocol::KeyRotationMsg`] announcements - distinct
    /// from `peer_keys`, which tracks what's been accepted *from*
    /// peers. `None` means this node has never rotated its own key.
    pub fn put_own_rotation_seq(&self, seq: u64) -> Result<(), PersistError> {
        let mut wtxn = self.env.write_txn()?;
        self.meta.put(&mut wtxn, OWN_ROTATION_SEQ_KEY, &seq)?;
        wtxn.commit()?;
        Ok(())
    }

    pub fn get_own_rotation_seq(&self) -> Result<Option<u64>, PersistError> {
        let rtxn = self.env.read_txn()?;
        Ok(self.meta.get(&rtxn, OWN_ROTATION_SEQ_KEY)?)
    }

    /// Persists this node's current quorum-certificate lock (see
    /// [`LockRecord`]). Overwrites any previous record - there is
    /// only ever one height in flight at a time.
    pub fn put_lock(&self, record: &LockRecord) -> Result<(), PersistError> {
        let mut wtxn = self.env.write_txn()?;
        self.locks.put(&mut wtxn, LOCK_KEY, record)?;
        wtxn.commit()?;
        Ok(())
    }

    /// This node's persisted lock, if any. `None` means either this
    /// node has never locked, or its one in-flight height already
    /// committed (callers should ignore a record whose `height` is no
    /// longer `head.height + 1` rather than treating `None` as the
    /// only "nothing to restore" case).
    pub fn get_lock(&self) -> Result<Option<LockRecord>, PersistError> {
        let rtxn = self.env.read_txn()?;
        Ok(self.locks.get(&rtxn, LOCK_KEY)?)
    }

    /// Records (or updates) a currently-recognized peer.
    pub fn put_member(&self, node_id: usize, record: &MemberRecord) -> Result<(), PersistError> {
        let mut wtxn = self.env.write_txn()?;
        self.members.put(&mut wtxn, &(node_id as u64), record)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Removes a peer that a committed `MembershipChange::Remove` took
    /// out of the network. A no-op, not an error, if it's already gone.
    pub fn remove_member(&self, node_id: usize) -> Result<(), PersistError> {
        let mut wtxn = self.env.write_txn()?;
        self.members.delete(&mut wtxn, &(node_id as u64))?;
        wtxn.commit()?;
        Ok(())
    }

    /// Every currently-recognized peer (this node excluded, same as
    /// `node.toml`'s `[[peers]]` list and `Ctx::peers` never include
    /// self either).
    pub fn all_members(&self) -> Result<Vec<(usize, MemberRecord)>, PersistError> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for entry in self.members.iter(&rtxn)? {
            let (id, record) = entry?;
            out.push((id as usize, record));
        }
        Ok(out)
    }

    /// Marks that this node's membership set has been seeded at least
    /// once - see [`MemberRecord`]'s doc comment for why that flips
    /// which source (`node.toml` vs this store) `run` trusts.
    pub fn mark_membership_initialized(&self) -> Result<(), PersistError> {
        let mut wtxn = self.env.write_txn()?;
        self.meta.put(&mut wtxn, MEMBERSHIP_INITIALIZED_KEY, &1)?;
        wtxn.commit()?;
        Ok(())
    }

    pub fn is_membership_initialized(&self) -> Result<bool, PersistError> {
        let rtxn = self.env.read_txn()?;
        Ok(self.meta.get(&rtxn, MEMBERSHIP_INITIALIZED_KEY)?.unwrap_or(0) == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use ed25519_dalek::SigningKey;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn corrupt_signing_key_bytes_are_a_hard_error_not_a_silent_regeneration() {
        let dir = TempDir::new("corrupt_key");
        let store = Store::open(dir.path()).unwrap();
        // Bypass put_signing_key to write a malformed value directly,
        // simulating on-disk corruption or a foreign writer.
        let mut wtxn = store.env.write_txn().unwrap();
        store.keys.put(&mut wtxn, SIGNING_KEY_KEY, b"not 32 bytes").unwrap();
        wtxn.commit().unwrap();

        match store.get_signing_key() {
            Err(PersistError(msg)) => assert!(msg.contains("corrupt"), "unexpected message: {msg}"),
            other => panic!("expected a hard error on corrupt key bytes, got {other:?}"),
        }
    }

    #[test]
    fn a_block_written_can_be_read_back_by_height() {
        let dir = TempDir::new("blocks");
        let store = Store::open(dir.path()).unwrap();
        let block = Block::genesis(3);
        store.put_block(&block).unwrap();
        let all = store.all_blocks().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].hash, "GENESIS");
    }

    #[test]
    fn blocks_come_back_ordered_by_ascending_height() {
        let dir = TempDir::new("block_order");
        let store = Store::open(dir.path()).unwrap();
        let mut b1 = Block::genesis(1);
        b1.height = 5;
        let mut b2 = Block::genesis(1);
        b2.height = 1;
        store.put_block(&b1).unwrap();
        store.put_block(&b2).unwrap();
        let all = store.all_blocks().unwrap();
        assert_eq!(all.iter().map(|b| b.height).collect::<Vec<_>>(), vec![1, 5]);
    }

    #[test]
    fn trust_entries_round_trip() {
        let dir = TempDir::new("trust");
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.get_trust(7).unwrap(), None);
        store.put_trust(7, TrustEntry { edge_weight: 1.5, reliability: 0.7 }).unwrap();
        assert_eq!(store.get_trust(7).unwrap(), Some(TrustEntry { edge_weight: 1.5, reliability: 0.7 }));
    }

    #[test]
    fn a_signing_key_round_trips_byte_for_byte() {
        let dir = TempDir::new("keys");
        let store = Store::open(dir.path()).unwrap();
        assert!(store.get_signing_key().unwrap().is_none());
        let sk = SigningKey::generate(&mut StdRng::seed_from_u64(1));
        store.put_signing_key(&sk).unwrap();
        let loaded = store.get_signing_key().unwrap().expect("should be present");
        assert_eq!(loaded.to_bytes(), sk.to_bytes());
    }

    #[test]
    fn epoch_round_trips() {
        let dir = TempDir::new("epoch");
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.get_epoch().unwrap(), None);
        store.put_epoch(3).unwrap();
        assert_eq!(store.get_epoch().unwrap(), Some(3));
    }

    #[test]
    fn peer_key_round_trips_and_a_later_write_overwrites_the_earlier_one() {
        let dir = TempDir::new("peer_key");
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.get_peer_key(1).unwrap(), None);

        let first = PeerKeyRecord { pubkey_hex: "aa".repeat(32), rotation_seq: 1 };
        store.put_peer_key(1, &first).unwrap();
        assert_eq!(store.get_peer_key(1).unwrap(), Some(first));

        let second = PeerKeyRecord { pubkey_hex: "bb".repeat(32), rotation_seq: 2 };
        store.put_peer_key(1, &second).unwrap();
        assert_eq!(store.get_peer_key(1).unwrap(), Some(second), "a newer rotation must overwrite, not append");

        // A different peer's record is independent.
        assert_eq!(store.get_peer_key(2).unwrap(), None);
    }

    #[test]
    fn lock_round_trips_and_a_later_write_overwrites_the_earlier_one() {
        let dir = TempDir::new("lock");
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.get_lock().unwrap(), None);

        let first = LockRecord { height: 1, view: 0, block_hash: "aaa".to_string() };
        store.put_lock(&first).unwrap();
        assert_eq!(store.get_lock().unwrap(), Some(first));

        let second = LockRecord { height: 1, view: 1, block_hash: "bbb".to_string() };
        store.put_lock(&second).unwrap();
        assert_eq!(store.get_lock().unwrap(), Some(second), "only one height is ever in flight - a new lock replaces, not appends");
    }

    #[test]
    fn members_round_trip_and_removal_actually_removes() {
        let dir = TempDir::new("members");
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.all_members().unwrap(), vec![]);
        assert!(!store.is_membership_initialized().unwrap());

        store.put_member(1, &MemberRecord { addr: "127.0.0.1:1".to_string(), pubkey_hex: "aa".repeat(32) }).unwrap();
        store.put_member(2, &MemberRecord { addr: "127.0.0.1:2".to_string(), pubkey_hex: "bb".repeat(32) }).unwrap();
        store.mark_membership_initialized().unwrap();

        let mut members = store.all_members().unwrap();
        members.sort_by_key(|(id, _)| *id);
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].0, 1);
        assert_eq!(members[1].0, 2);
        assert!(store.is_membership_initialized().unwrap());

        store.remove_member(1).unwrap();
        let members = store.all_members().unwrap();
        assert_eq!(members.len(), 1, "a removed member must actually be gone, not just marked");
        assert_eq!(members[0].0, 2);

        // Removing something already gone is a no-op, not an error.
        store.remove_member(1).unwrap();
    }

    #[test]
    fn own_rotation_seq_round_trips() {
        let dir = TempDir::new("own_rotation_seq");
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.get_own_rotation_seq().unwrap(), None, "never rotated yet");
        store.put_own_rotation_seq(1).unwrap();
        assert_eq!(store.get_own_rotation_seq().unwrap(), Some(1));
        store.put_own_rotation_seq(2).unwrap();
        assert_eq!(store.get_own_rotation_seq().unwrap(), Some(2));
    }

    #[test]
    fn state_survives_reopening_the_same_directory() {
        let dir = TempDir::new("restart");
        {
            let store = Store::open(dir.path()).unwrap();
            let sk = SigningKey::generate(&mut StdRng::seed_from_u64(9));
            store.put_signing_key(&sk).unwrap();
            store.put_epoch(2).unwrap();
            store.put_block(&Block::genesis(2)).unwrap();
            store.put_trust(1, TrustEntry { edge_weight: 2.0, reliability: 0.9 }).unwrap();
        } // store (and its Env) dropped here, simulating process exit

        let reopened = Store::open(dir.path()).unwrap();
        assert!(reopened.get_signing_key().unwrap().is_some());
        assert_eq!(reopened.get_epoch().unwrap(), Some(2));
        assert_eq!(reopened.all_blocks().unwrap().len(), 1);
        assert_eq!(reopened.get_trust(1).unwrap(), Some(TrustEntry { edge_weight: 2.0, reliability: 0.9 }));
    }
}
