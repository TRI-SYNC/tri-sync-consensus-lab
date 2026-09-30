//! QUIC transport (via `quinn`, TLS 1.3 via `rustls`) carrying
//! [`crate::protocol::Message`]s between peers.
//!
//! **What TLS does and doesn't provide here.** Every connection is
//! encrypted with a real, freshly-generated self-signed certificate
//! (via `rcgen`), so traffic is confidential and tamper-evident in
//! transit. But the client deliberately does **not** validate the
//! server's certificate against anything (see the `SkipServerVerification`
//! type below) - there is no shared CA and no
//! certificate-pinning of peers yet, so TLS here is encryption, not
//! peer authentication. Authentication is handled one layer up, at the
//! message level: a [`crate::protocol::BlockVoteMsg`] /
//! [`crate::protocol::BlockProposalMsg`] carries its own Ed25519
//! signature, checked with `tri_sync_core::crypto` against the
//! sender's known public key. Don't rely on "the TLS handshake
//! succeeded" as a proxy for "this peer is who it claims to be."

use crate::protocol::Message;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;

const ALPN: &[u8] = b"tri-sync/1";
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
/// QUIC has no immediate "connection refused" signal like TCP - an
/// unreachable peer just never responds, and without a bound the
/// handshake retries for a very long time (confirmed here: over a
/// minute). A node gossiping to peers that may be down must not hang
/// that long per peer.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug)]
pub struct NetError(String);

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "net error: {}", self.0)
    }
}

impl std::error::Error for NetError {}

fn err(e: impl std::fmt::Display) -> NetError {
    NetError(e.to_string())
}

fn self_signed_cert() -> Result<(rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>), NetError> {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["tri-sync-node".to_string()]).map_err(err)?;
    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
    Ok((cert_der, key_der))
}

/// A `rustls` server-cert verifier that accepts anything - see this
/// module's doc comment for why that's an acceptable tradeoff here and
/// not a general-purpose recommendation.
#[derive(Debug)]
struct SkipServerVerification(rustls::crypto::CryptoProvider);

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Builds a QUIC server endpoint bound to `listen_addr`, with a fresh
/// self-signed certificate.
pub fn make_server_endpoint(listen_addr: SocketAddr) -> Result<quinn::Endpoint, NetError> {
    let (cert, key) = self_signed_cert()?;
    // Explicit provider: this binary links both `ring` and `aws-lc-rs`
    // transitively (via quinn's and rustls' default features), so
    // rustls' auto-detecting `builder()` can't pick one on its own.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(err)?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(err)?;
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic_crypto = QuicServerConfig::try_from(server_crypto).map_err(err)?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let endpoint = quinn::Endpoint::server(server_config, listen_addr).map_err(err)?;
    Ok(endpoint)
}

/// Builds a QUIC client endpoint bound to an OS-assigned local port.
pub fn make_client_endpoint() -> Result<quinn::Endpoint, NetError> {
    let provider = rustls::crypto::ring::default_provider();
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(Arc::new(provider.clone()))
        .with_safe_default_protocol_versions()
        .map_err(err)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification(provider)))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic_crypto = QuicClientConfig::try_from(client_crypto).map_err(err)?;
    let client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(err)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Connects to `addr` (bounded by a fixed connect timeout - an
/// unreachable peer must not hang the caller) and sends `msg` on a fresh
/// unidirectional stream.
///
/// `send.finish()` only marks the stream as done locally - it does not
/// guarantee the bytes have actually reached the peer. A process that
/// drops the connection (or exits) immediately after `finish()` can
/// lose data that was still in flight: confirmed here, where the
/// naive version of this function reported every send as successful
/// while the receiving node logged nothing. `send.stopped()` waits
/// until the peer has actually received the whole stream (or reset
/// it), which is the fix.
pub async fn send_message(endpoint: &quinn::Endpoint, addr: SocketAddr, msg: &Message) -> Result<(), NetError> {
    let connecting = endpoint.connect(addr, "tri-sync-node").map_err(err)?;
    let connection = tokio::time::timeout(CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| NetError(format!("connecting to {addr} timed out after {CONNECT_TIMEOUT:?}")))?
        .map_err(err)?;
    let mut send = connection.open_uni().await.map_err(err)?;
    let bytes = serde_json::to_vec(msg).map_err(err)?;
    send.write_all(&bytes).await.map_err(err)?;
    send.finish().map_err(err)?;
    send.stopped().await.map_err(err)?;
    Ok(())
}

/// Accepts incoming connections on `endpoint` forever, forwarding every
/// successfully-decoded [`Message`] (paired with the connection's
/// remote address) to `tx`. Malformed frames and connection errors are
/// logged to stderr and otherwise ignored - one bad peer must not take
/// down the server.
pub async fn serve(endpoint: quinn::Endpoint, tx: tokio::sync::mpsc::UnboundedSender<(SocketAddr, Message)>) {
    while let Some(incoming) = endpoint.accept().await {
        let tx = tx.clone();
        tokio::spawn(async move {
            let remote = incoming.remote_address();
            let connection = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("tri_sync_node: connection from {remote} failed: {e}");
                    return;
                }
            };
            loop {
                let mut recv = match connection.accept_uni().await {
                    Ok(r) => r,
                    Err(_) => break, // peer closed the connection
                };
                match recv.read_to_end(MAX_MESSAGE_BYTES).await {
                    Ok(bytes) => match serde_json::from_slice::<Message>(&bytes) {
                        Ok(msg) => {
                            let _ = tx.send((remote, msg));
                        }
                        Err(e) => eprintln!("tri_sync_node: malformed message from {remote}: {e}"),
                    },
                    Err(e) => eprintln!("tri_sync_node: stream read error from {remote}: {e}"),
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ObservationMsg;
    use std::net::{IpAddr, Ipv4Addr};

    /// Real QUIC over real localhost sockets - two independently-built
    /// endpoints, not fakes. Confirms the whole stack (self-signed TLS,
    /// the ring provider setup, the uni-stream framing, and
    /// `send.stopped()` actually waiting for delivery) works end to end,
    /// as a fast in-process complement to the manual multi-process test
    /// this stage was verified with.
    #[tokio::test]
    async fn a_message_sent_to_a_real_server_endpoint_is_received_intact() {
        let server_endpoint = make_server_endpoint(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(serve(server_endpoint, tx));

        let client_endpoint = make_client_endpoint().unwrap();
        let msg = Message::Observation(ObservationMsg { sender: 7, values: vec![1.0, 2.0, 3.0] });
        send_message(&client_endpoint, server_addr, &msg).await.unwrap();

        let (_, received) = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("should receive within 5s")
            .expect("channel should not have closed");
        assert_eq!(received, msg);
    }

    #[tokio::test]
    async fn connecting_to_an_unreachable_address_fails_within_the_connect_timeout_not_forever() {
        let client_endpoint = make_client_endpoint().unwrap();
        // Nothing listens on this loopback port.
        let dead_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let msg = Message::Observation(ObservationMsg { sender: 1, values: vec![0.0] });

        let started = tokio::time::Instant::now();
        let result = send_message(&client_endpoint, dead_addr, &msg).await;
        let elapsed = started.elapsed();

        assert!(result.is_err());
        assert!(elapsed < CONNECT_TIMEOUT + std::time::Duration::from_secs(2), "took {elapsed:?}, should be bounded");
    }
}
