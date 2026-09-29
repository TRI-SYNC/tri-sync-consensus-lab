//! Shared building blocks for the `tri_sync_*` simulation binaries: a
//! trimmed-weighted-mean fusion estimator ([`consensus::robust_fuse`]), a
//! per-node trust/reliability update ([`trust_graph::update_reliability`]),
//! per-node lock/observation state transitions ([`node`]), fast-sync phase
//! detection ([`phase`]), a noise-based self-trust gate ([`invariants`]),
//! shared data shapes ([`types`]), and plain-text telemetry reporting
//! ([`telemetry`]).
//!
//! This crate is the shared library; the simulations themselves - what
//! each binary actually models, what's verified about them, and what
//! isn't - are documented in the repository's README, not here.

pub mod consensus;
pub mod invariants;
pub mod node;
pub mod phase;
pub mod telemetry;
pub mod trust_graph;
pub mod types;
