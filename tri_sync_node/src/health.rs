//! Per-peer network-health tracking.
//!
//! **Deliberately observational, not behavioral.** A "sick" peer is
//! still proposed to, still counted toward quorum, still sent every
//! message - nothing here changes `crate::consensus`'s behavior.
//! Wiring health into proposer selection (skip a known-dead peer's
//! turn) or message routing would be a real feature, but it's also a
//! real way to accidentally weaken the liveness/view-change guarantees
//! Hardening 4 just established and tested - a peer this node
//! currently believes is dead is exactly the case view-change already
//! has to handle correctly regardless, and a health-based shortcut
//! that disagreed with that path would be two sources of truth for the
//! same question. So this stage only ever counts and exposes; closing
//! the loop (acting on health) is left for a later, deliberate pass.
//!
//! Lock-free by construction: the set of peer ids is fixed once
//! `Metrics`/`PeerHealth` entries are built at start-up (from
//! `node.toml`), so concurrent updates only ever touch the atomics
//! *inside* an existing entry, never the map itself.
//!
//! **A real race, caught live rather than in a unit test.** The first
//! version of `record_send_result` just mutated counters and left
//! healthy/unhealthy transition detection to the caller (load health
//! before the send, load it again after, compare). Live-testing two
//! real node processes - kill one, watch the other's logs - showed
//! the "marked unhealthy" line printed repeatedly instead of once:
//! `crate::consensus::broadcast` fires one independently-spawned send
//! per message type per tick, so several sends to the *same* dead peer
//! land close together, each reading the same pre-failure state before
//! any of them had recorded their own result, each concluding it was
//! the one that crossed the threshold. Fixed by moving the transition
//! check inside the atomic update itself (`fetch_add`/`swap`'s
//! returned previous value), so only the call that actually lands on
//! the threshold - a property of the single atomic operation, not of
//! two separate reads around it - ever reports a transition.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Consecutive failed sends after which a peer is reported unhealthy.
/// Arbitrary but disclosed: three strikes tolerates a single dropped
/// UDP datagram or one slow tick without flapping the verdict, while
/// still catching a peer that's actually gone within a few rounds.
pub const UNHEALTHY_AFTER_CONSECUTIVE_FAILURES: u64 = 3;

/// What a single `PeerHealth::record_send_result` call actually
/// changed - see that method's doc comment for why this can't be
/// reconstructed from two separate before/after reads at the call
/// site without racing concurrent sends to the same peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthTransition {
    NoChange,
    BecameUnhealthy,
    Recovered,
}

#[derive(Debug, Default)]
pub struct PeerHealth {
    total_sends: AtomicU64,
    total_send_failures: AtomicU64,
    consecutive_send_failures: AtomicU64,
    /// Unix seconds of the last message this node authenticated as
    /// genuinely from this peer (any message type) - 0 if never. Only
    /// ever set after signature verification succeeds, so a peer can
    /// never inflate its own apparent health by having someone else
    /// forge messages claiming to be them.
    last_seen_unix_secs: AtomicU64,
}

impl PeerHealth {
    /// Records one send's outcome and reports whether *this call* was
    /// the one that crossed the health threshold in either direction -
    /// never a before/after snapshot taken by the caller. That
    /// distinction matters because `crate::consensus::broadcast` fires
    /// several sends to the same peer concurrently (one per message
    /// type in a tick) as independently spawned tasks: a caller-side
    /// "was healthy, now isn't" comparison would race against a
    /// sibling task doing the same comparison against the same
    /// pre-update state, and both could report the same transition.
    /// `fetch_add`/`swap` are atomic read-and-modify-in-one-step, so
    /// only the single call that actually lands on the threshold ever
    /// sees that exact value - reported here rather than reconstructed
    /// from two separate loads outside this type.
    pub fn record_send_result(&self, ok: bool) -> HealthTransition {
        self.total_sends.fetch_add(1, Ordering::Relaxed);
        if ok {
            let prev = self.consecutive_send_failures.swap(0, Ordering::Relaxed);
            if prev >= UNHEALTHY_AFTER_CONSECUTIVE_FAILURES {
                HealthTransition::Recovered
            } else {
                HealthTransition::NoChange
            }
        } else {
            self.total_send_failures.fetch_add(1, Ordering::Relaxed);
            let prev = self.consecutive_send_failures.fetch_add(1, Ordering::Relaxed);
            if prev + 1 == UNHEALTHY_AFTER_CONSECUTIVE_FAILURES {
                HealthTransition::BecameUnhealthy
            } else {
                HealthTransition::NoChange
            }
        }
    }

    pub fn record_authenticated_message(&self) {
        self.last_seen_unix_secs.store(unix_now(), Ordering::Relaxed);
    }

    pub fn total_sends(&self) -> u64 {
        self.total_sends.load(Ordering::Relaxed)
    }

    pub fn total_send_failures(&self) -> u64 {
        self.total_send_failures.load(Ordering::Relaxed)
    }

    pub fn consecutive_send_failures(&self) -> u64 {
        self.consecutive_send_failures.load(Ordering::Relaxed)
    }

    /// Seconds since the last authenticated message from this peer, or
    /// `None` if none has ever arrived.
    pub fn seconds_since_last_seen(&self) -> Option<u64> {
        let last = self.last_seen_unix_secs.load(Ordering::Relaxed);
        if last == 0 {
            return None;
        }
        Some(unix_now().saturating_sub(last))
    }

    /// A simple, disclosed-as-crude verdict: unhealthy once
    /// consecutive send failures reach the threshold. Never considers
    /// message receipt on its own - a peer can be legitimately silent
    /// (not its turn to propose or vote) without this node ever having
    /// tried to send it anything, so "healthy" here means "sendable",
    /// not "definitely alive."
    pub fn is_healthy(&self) -> bool {
        self.consecutive_send_failures() < UNHEALTHY_AFTER_CONSECUTIVE_FAILURES
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_peer_is_healthy_and_has_never_been_seen() {
        let h = PeerHealth::default();
        assert!(h.is_healthy());
        assert_eq!(h.seconds_since_last_seen(), None);
        assert_eq!(h.consecutive_send_failures(), 0);
    }

    #[test]
    fn repeated_failures_eventually_flip_health_and_a_success_resets_it() {
        let h = PeerHealth::default();
        for _ in 0..UNHEALTHY_AFTER_CONSECUTIVE_FAILURES - 1 {
            h.record_send_result(false);
            assert!(h.is_healthy(), "not enough consecutive failures yet");
        }
        h.record_send_result(false);
        assert!(!h.is_healthy(), "threshold reached, should now be unhealthy");

        h.record_send_result(true);
        assert!(h.is_healthy(), "a single success resets the consecutive-failure streak");
        assert_eq!(h.total_sends(), UNHEALTHY_AFTER_CONSECUTIVE_FAILURES + 1);
        assert_eq!(h.total_send_failures(), UNHEALTHY_AFTER_CONSECUTIVE_FAILURES);
    }

    #[test]
    fn an_interleaved_success_prevents_reaching_the_threshold() {
        let h = PeerHealth::default();
        h.record_send_result(false);
        h.record_send_result(false);
        h.record_send_result(true); // resets the streak
        h.record_send_result(false);
        h.record_send_result(false);
        assert!(h.is_healthy(), "the reset means only 2 consecutive failures since the last success");
    }

    #[test]
    fn recording_an_authenticated_message_sets_seconds_since_last_seen_to_near_zero() {
        let h = PeerHealth::default();
        h.record_authenticated_message();
        let secs = h.seconds_since_last_seen().expect("should now be Some");
        assert!(secs < 2, "should be nearly zero seconds ago, got {secs}");
    }

    #[test]
    fn record_send_result_reports_the_transition_exactly_once_in_each_direction() {
        let h = PeerHealth::default();
        for _ in 0..UNHEALTHY_AFTER_CONSECUTIVE_FAILURES - 1 {
            assert_eq!(h.record_send_result(false), HealthTransition::NoChange);
        }
        assert_eq!(h.record_send_result(false), HealthTransition::BecameUnhealthy, "this call lands exactly on the threshold");
        assert_eq!(h.record_send_result(false), HealthTransition::NoChange, "already unhealthy, not a new transition");

        assert_eq!(h.record_send_result(true), HealthTransition::Recovered);
        assert_eq!(h.record_send_result(true), HealthTransition::NoChange, "already healthy, a second success isn't a new transition");
    }

    /// The real bug this stage's own live multi-process test caught:
    /// several concurrent callers racing to report a transition off
    /// two separate before/after reads would double-report it. Proven
    /// here by actually racing real OS threads against one shared
    /// `PeerHealth`, not just asserting it from reading the fixed code.
    #[test]
    fn concurrent_failures_report_the_unhealthy_transition_exactly_once() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;

        let h = Arc::new(PeerHealth::default());
        // Get to one failure away from the threshold single-threaded,
        // so the race is specifically over *which* concurrent call is
        // the one that crosses it.
        for _ in 0..UNHEALTHY_AFTER_CONSECUTIVE_FAILURES - 1 {
            h.record_send_result(false);
        }

        let became_unhealthy_count = Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let h = h.clone();
                let count = became_unhealthy_count.clone();
                std::thread::spawn(move || {
                    if h.record_send_result(false) == HealthTransition::BecameUnhealthy {
                        count.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        assert_eq!(became_unhealthy_count.load(Ordering::Relaxed), 1, "exactly one of the racing calls must land on the threshold");
    }
}
