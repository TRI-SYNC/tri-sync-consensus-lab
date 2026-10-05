//! Optional Prometheus metrics: head height, forks observed, blocks
//! that reconciled a fork, (Hardening 4) view-changes triggered by a
//! stalled proposer, mean trust weight toward this node's peers,
//! (Hardening 6) per-peer network health - see `crate::health` for
//! what "health" means here and why it's purely observational - and
//! (Hardening 7) this node's current epoch.
//!
//! **Honest note on `forks`/`reconciles`.** `forks_total` counts two
//! real, distinct things (see `consensus::handle_proposal`): a
//! competing pre-commit candidate at a not-yet-decided height (common
//! during view-change hand-offs, always harmless - whichever reaches
//! quorum first wins, the other is just dropped), and the far more
//! serious case of a proposal for an *already-committed* height that
//! `tri_sync_core::chain::prefer` ranks above what this node actually
//! committed - a potential safety violation, logged loudly rather than
//! auto-reorged, since one message isn't enough evidence to safely
//! rewrite committed history. `reconciles_total` stays structurally at
//! zero in this design: a block's identity and signatures are fixed at
//! proposal time, before any fork is knowable, so there's no safe way
//! to retroactively record which siblings a commit superseded without
//! invalidating the very signatures that make the block trustworthy -
//! doing that for real would need a different flow (an explicit
//! re-proposal step, re-signed by a fresh quorum), which is out of
//! scope here.

use crate::health::{HealthTransition, PeerHealth};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

/// `mean_trust_weight` is stored as the bit pattern of an `f64` inside
/// an `AtomicU64` - a plain store/load of one value, not a
/// read-modify-write, so no lock is needed for a single gauge.
#[derive(Debug, Default)]
pub struct Metrics {
    pub head_height: AtomicU64,
    pub forks_total: AtomicU64,
    pub reconciles_total: AtomicU64,
    /// Times this node bumped a height's view after its proposer timed
    /// out - see `crate::consensus`'s liveness/view-change handling.
    pub view_changes_total: AtomicU64,
    /// This node's current epoch - see `tri_sync_core::chain::epoch_for_height`.
    pub epoch: AtomicU64,
    mean_trust_weight_bits: AtomicU64,
    /// One entry per configured peer, built once at start-up from
    /// `node.toml` - see `crate::health` for why the map itself never
    /// needs to change after that, only the atomics inside each entry.
    peer_health: HashMap<usize, PeerHealth>,
}

impl Metrics {
    /// Builds a `Metrics` with a health entry pre-created for each id
    /// in `peer_ids`, so `peer_health`/`record_send_result`/
    /// `record_peer_seen` below are no-ops for an unconfigured id
    /// rather than silently losing data for a configured one.
    pub fn new(peer_ids: &[usize]) -> Metrics {
        Metrics { peer_health: peer_ids.iter().map(|&id| (id, PeerHealth::default())).collect(), ..Default::default() }
    }

    pub fn set_mean_trust_weight(&self, value: f64) {
        self.mean_trust_weight_bits.store(value.to_bits(), Ordering::Relaxed);
    }

    pub fn mean_trust_weight(&self) -> f64 {
        f64::from_bits(self.mean_trust_weight_bits.load(Ordering::Relaxed))
    }

    pub fn peer_health(&self, peer_id: usize) -> Option<&PeerHealth> {
        self.peer_health.get(&peer_id)
    }

    /// Returns `None` for an unconfigured peer id, otherwise the
    /// `HealthTransition` `PeerHealth::record_send_result` reports -
    /// see that method for why the transition must come from there,
    /// not from a separate before/after comparison here.
    pub fn record_send_result(&self, peer_id: usize, ok: bool) -> Option<HealthTransition> {
        self.peer_health.get(&peer_id).map(|h| h.record_send_result(ok))
    }

    pub fn record_peer_seen(&self, peer_id: usize) {
        if let Some(h) = self.peer_health.get(&peer_id) {
            h.record_authenticated_message();
        }
    }

    fn render(&self) -> String {
        let mut out = format!(
            "# HELP tri_sync_head_height Current chain head block height.\n\
             # TYPE tri_sync_head_height gauge\n\
             tri_sync_head_height {}\n\
             # HELP tri_sync_forks_total Competing block candidates observed at the same height.\n\
             # TYPE tri_sync_forks_total counter\n\
             tri_sync_forks_total {}\n\
             # HELP tri_sync_reconciles_total Committed blocks that reconciled a fork.\n\
             # TYPE tri_sync_reconciles_total counter\n\
             tri_sync_reconciles_total {}\n\
             # HELP tri_sync_mean_trust_weight Mean edge weight across all tracked peers.\n\
             # TYPE tri_sync_mean_trust_weight gauge\n\
             tri_sync_mean_trust_weight {}\n\
             # HELP tri_sync_view_changes_total Times a height's proposer timed out and view advanced.\n\
             # TYPE tri_sync_view_changes_total counter\n\
             tri_sync_view_changes_total {}\n\
             # HELP tri_sync_epoch This node's current epoch, derived from its committed chain height.\n\
             # TYPE tri_sync_epoch gauge\n\
             tri_sync_epoch {}\n",
            self.head_height.load(Ordering::Relaxed),
            self.forks_total.load(Ordering::Relaxed),
            self.reconciles_total.load(Ordering::Relaxed),
            self.mean_trust_weight(),
            self.view_changes_total.load(Ordering::Relaxed),
            self.epoch.load(Ordering::Relaxed),
        );

        if !self.peer_health.is_empty() {
            out.push_str(
                "# HELP tri_sync_peer_healthy Whether this node currently considers a peer healthy (1) or not (0), based on consecutive send failures.\n\
                 # TYPE tri_sync_peer_healthy gauge\n",
            );
            let mut ids: Vec<&usize> = self.peer_health.keys().collect();
            ids.sort_unstable();
            for &id in &ids {
                let h = &self.peer_health[id];
                out.push_str(&format!("tri_sync_peer_healthy{{peer=\"{id}\"}} {}\n", if h.is_healthy() { 1 } else { 0 }));
            }
            out.push_str(
                "# HELP tri_sync_peer_consecutive_send_failures Consecutive failed sends to a peer since its last successful send.\n\
                 # TYPE tri_sync_peer_consecutive_send_failures gauge\n",
            );
            for &id in &ids {
                out.push_str(&format!("tri_sync_peer_consecutive_send_failures{{peer=\"{id}\"}} {}\n", self.peer_health[id].consecutive_send_failures()));
            }
            out.push_str(
                "# HELP tri_sync_peer_seconds_since_last_seen Seconds since the last authenticated message received from a peer. Absent if none has ever arrived.\n\
                 # TYPE tri_sync_peer_seconds_since_last_seen gauge\n",
            );
            for &id in &ids {
                if let Some(secs) = self.peer_health[id].seconds_since_last_seen() {
                    out.push_str(&format!("tri_sync_peer_seconds_since_last_seen{{peer=\"{id}\"}} {secs}\n"));
                }
            }
        }

        out
    }
}

#[derive(Debug)]
pub struct MetricsError(String);

impl std::fmt::Display for MetricsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "metrics server error: {}", self.0)
    }
}

impl std::error::Error for MetricsError {}

/// Serves `GET /metrics` (Prometheus text exposition format) on `addr`
/// until the process exits. `tiny_http` is synchronous, so this runs on
/// its own OS thread rather than as a tokio task.
pub fn serve(addr: SocketAddr, metrics: std::sync::Arc<Metrics>) -> Result<std::thread::JoinHandle<()>, MetricsError> {
    let server = tiny_http::Server::http(addr).map_err(|e| MetricsError(e.to_string()))?;
    Ok(std::thread::spawn(move || {
        for request in server.incoming_requests() {
            let body = metrics.render();
            let response = tiny_http::Response::from_string(body)
                .with_header(tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/plain; version=0.0.4"[..]).unwrap());
            let _ = request.respond(response);
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_current_values_of_every_metric() {
        let metrics = Metrics::default();
        metrics.head_height.store(7, Ordering::Relaxed);
        metrics.forks_total.store(2, Ordering::Relaxed);
        metrics.reconciles_total.store(1, Ordering::Relaxed);
        metrics.view_changes_total.store(4, Ordering::Relaxed);
        metrics.epoch.store(3, Ordering::Relaxed);
        metrics.set_mean_trust_weight(1.5);

        let text = metrics.render();
        assert!(text.contains("tri_sync_head_height 7"));
        assert!(text.contains("tri_sync_forks_total 2"));
        assert!(text.contains("tri_sync_reconciles_total 1"));
        assert!(text.contains("tri_sync_mean_trust_weight 1.5"));
        assert!(text.contains("tri_sync_view_changes_total 4"));
        assert!(text.contains("tri_sync_epoch 3"));
    }

    #[test]
    fn mean_trust_weight_round_trips_through_the_atomic_bit_store() {
        let metrics = Metrics::default();
        metrics.set_mean_trust_weight(0.0);
        assert_eq!(metrics.mean_trust_weight(), 0.0);
        metrics.set_mean_trust_weight(-3.25);
        assert_eq!(metrics.mean_trust_weight(), -3.25);
    }

    #[test]
    fn a_metrics_with_no_configured_peers_renders_no_peer_health_lines() {
        let metrics = Metrics::default();
        let text = metrics.render();
        assert!(!text.contains("tri_sync_peer_healthy"), "no peers configured, nothing to report");
    }

    #[test]
    fn render_includes_per_peer_health_for_every_configured_peer() {
        let metrics = Metrics::new(&[1, 2]);
        metrics.record_send_result(1, true);
        for _ in 0..3 {
            metrics.record_send_result(2, false);
        }
        metrics.record_peer_seen(1);

        let text = metrics.render();
        assert!(text.contains("tri_sync_peer_healthy{peer=\"1\"} 1"), "peer 1 just had a successful send: {text}");
        assert!(text.contains("tri_sync_peer_healthy{peer=\"2\"} 0"), "peer 2 hit the failure threshold: {text}");
        assert!(text.contains("tri_sync_peer_consecutive_send_failures{peer=\"2\"} 3"));
        assert!(text.contains("tri_sync_peer_seconds_since_last_seen{peer=\"1\"}"), "peer 1 was marked seen: {text}");
        assert!(!text.contains("tri_sync_peer_seconds_since_last_seen{peer=\"2\"}"), "peer 2 was never seen, only sent to: {text}");
    }

    #[test]
    fn record_send_result_and_record_peer_seen_are_no_ops_for_an_unconfigured_peer() {
        let metrics = Metrics::new(&[1]);
        metrics.record_send_result(99, false); // must not panic
        metrics.record_peer_seen(99);
        assert!(metrics.peer_health(99).is_none());
    }

    #[test]
    fn a_real_http_get_to_slash_metrics_returns_prometheus_text() {
        let metrics = std::sync::Arc::new(Metrics::default());
        metrics.head_height.store(3, Ordering::Relaxed);
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        // Bind on port 0 directly to learn the OS-assigned port, then
        // hand that same listener to tiny_http via from_listener - the
        // pub fn above only takes an address, so this constructs a
        // server the same way for the purpose of this test.
        let listener = std::net::TcpListener::bind(addr).unwrap();
        let bound_addr = listener.local_addr().unwrap();
        let server = tiny_http::Server::from_listener(listener, None).unwrap();
        let metrics_for_thread = metrics.clone();
        let handle = std::thread::spawn(move || {
            if let Ok(request) = server.recv() {
                let body = metrics_for_thread.render();
                let response = tiny_http::Response::from_string(body);
                let _ = request.respond(response);
            }
        });

        let body = ureq_get(bound_addr);
        assert!(body.contains("tri_sync_head_height 3"), "unexpected body: {body}");
        handle.join().unwrap();
    }

    /// A tiny hand-rolled HTTP/1.0 GET, so this test doesn't need an
    /// HTTP client dependency just to hit a local test server.
    fn ureq_get(addr: SocketAddr) -> String {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(b"GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n").unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response.split("\r\n\r\n").nth(1).unwrap_or_default().to_string()
    }
}
