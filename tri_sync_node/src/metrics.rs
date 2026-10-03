//! Optional Prometheus metrics: head height, forks observed, blocks
//! that reconciled a fork, and mean trust weight toward this node's
//! peers.
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
    mean_trust_weight_bits: AtomicU64,
}

impl Metrics {
    pub fn set_mean_trust_weight(&self, value: f64) {
        self.mean_trust_weight_bits.store(value.to_bits(), Ordering::Relaxed);
    }

    pub fn mean_trust_weight(&self) -> f64 {
        f64::from_bits(self.mean_trust_weight_bits.load(Ordering::Relaxed))
    }

    fn render(&self) -> String {
        format!(
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
             tri_sync_view_changes_total {}\n",
            self.head_height.load(Ordering::Relaxed),
            self.forks_total.load(Ordering::Relaxed),
            self.reconciles_total.load(Ordering::Relaxed),
            self.mean_trust_weight(),
            self.view_changes_total.load(Ordering::Relaxed),
        )
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
        metrics.set_mean_trust_weight(1.5);

        let text = metrics.render();
        assert!(text.contains("tri_sync_head_height 7"));
        assert!(text.contains("tri_sync_forks_total 2"));
        assert!(text.contains("tri_sync_reconciles_total 1"));
        assert!(text.contains("tri_sync_mean_trust_weight 1.5"));
        assert!(text.contains("tri_sync_view_changes_total 4"));
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
