//! Pure consensus logic for tri-sync-consensus-lab: trimmed fusion
//! ([`fusion`]), trust/edge-weight learning ([`trust`]), the clarity
//! gate ([`clarity`]), block/chain types and fork-choice ([`chain`]),
//! and Ed25519 signing with epoch rotation ([`crypto`]).
//!
//! This crate does no networking and no file I/O - every function here
//! takes its state as plain arguments and returns a value or mutates
//! what it's given, nothing more. `tri_sync_node` (networking,
//! persistence, license enforcement) is the first consumer of it that
//! isn't itself a pure-simulation binary.
//!
//! Every function in this crate was checked against the corresponding
//! already-verified logic in the existing `tri_sync_chain_crypto`
//! binary before being written here, not copied from memory - see each
//! module's tests.

pub mod chain;
pub mod clarity;
pub mod crypto;
pub mod fusion;
pub mod trust;
