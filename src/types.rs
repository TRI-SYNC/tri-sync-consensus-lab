//! Shared data shapes reported out of a simulation run.

use serde::Serialize;

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
