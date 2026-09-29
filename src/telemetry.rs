//! Plain-text stdout reporting for a simulation run.

use crate::types::TelemetryRow;

pub fn print_header() {
    println!("t    truth     R*        D      fast  clar  meanRel  streak  done");
    println!("------------------------------------------------------------------");
}

pub fn print_row(r: &TelemetryRow) {
    println!(
        "{:3}  {:8.3}  {:8.3}  {:6.3}   {:3}   {:3}   {:7.3}   {:4}   {}",
        r.t, r.truth, r.r_star, r.disagreement, r.fast_sync_remaining, r.clarified,
        r.mean_reliability, r.complete_streak, r.done
    );
}
