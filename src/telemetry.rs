//! Plain-text stdout reporting for a simulation run.

use crate::types::TelemetryRow;

/// Prints the column header line matching [`print_row`]'s layout.
pub fn print_header() {
    println!(
        "{:>6} {:>10} {:>10} {:>10} {:>10} {:>10} {:>8} {:>8} {:>6}",
        "t", "truth", "r_star", "disagree", "clarified", "mean_rel", "fastsync", "streak", "done"
    );
}

/// Prints one telemetry row, aligned to [`print_header`]'s columns.
pub fn print_row(row: &TelemetryRow) {
    println!(
        "{:>6} {:>10.4} {:>10.4} {:>10.4} {:>10} {:>10.4} {:>8} {:>8} {:>6}",
        row.t,
        row.truth,
        row.r_star,
        row.disagreement,
        row.clarified,
        row.mean_reliability,
        row.fast_sync_remaining,
        row.complete_streak,
        row.done
    );
}
