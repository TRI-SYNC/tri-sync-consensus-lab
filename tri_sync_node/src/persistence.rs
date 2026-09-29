//! LMDB-backed persistence (via `heed`) for blocks, trust, this node's
//! keypair, and epoch metadata.
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

const SIGNING_KEY_KEY: &str = "signing_key";
const EPOCH_KEY: &str = "epoch";

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
}

impl Store {
    /// Opens (creating if necessary) an LMDB environment at `dir` with
    /// the four databases this node needs.
    pub fn open(dir: &Path) -> Result<Store, PersistError> {
        std::fs::create_dir_all(dir).map_err(|e| PersistError(format!("creating {}: {e}", dir.display())))?;
        // SAFETY: heed's `open` is unsafe because opening the same LMDB
        // environment concurrently from unrelated processes with
        // mismatched configuration (map size, max_dbs) is undefined
        // behavior. This node is the only process expected to open its
        // own data_dir, with a fixed max_dbs below.
        let env = unsafe { EnvOpenOptions::new().max_dbs(4).open(dir) }
            .map_err(|e| PersistError(format!("opening LMDB env at {}: {e}", dir.display())))?;

        let mut wtxn = env.write_txn()?;
        let blocks = env.create_database(&mut wtxn, Some("blocks"))?;
        let trust = env.create_database(&mut wtxn, Some("trust"))?;
        let keys = env.create_database(&mut wtxn, Some("keys"))?;
        let meta = env.create_database(&mut wtxn, Some("meta"))?;
        wtxn.commit()?;

        Ok(Store { env, blocks, trust, keys, meta })
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
