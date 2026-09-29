//! Shared data shapes for a node-based simulation and its telemetry.

use serde::{Deserialize, Serialize};

/// A single node's reading at step `t`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub node_id: usize,
    pub value: f64,
    pub sigma: f64,
    pub t: u64,
}

/// A fused reference value: [`crate::consensus::robust_fuse`]'s output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RStar {
    pub value: f64,
    pub confidence: f64,
    pub version: u64,
    pub t: u64,
}

/// A node's local state: its locked estimate, its reliability weight, its
/// most recent observation, and whether it was too noisy to lock this step.
#[derive(Debug, Clone)]
pub struct NodeState {
    pub x: f64,
    pub reliability: f64,
    pub last_obs: Option<Observation>,
    pub clarified: bool,
}

/// One step's worth of simulation telemetry.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct TelemetryRow {
    pub t: u64,
    pub truth: f64,
    pub r_star: f64,
    pub disagreement: f64,
    pub clarified: usize,
    pub mean_reliability: f64,
    pub fast_sync_remaining: u64,
    pub complete_streak: u64,
    pub done: bool,
}
