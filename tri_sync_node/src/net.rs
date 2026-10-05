//! QUIC transport (via `quinn`, TLS 1.3 via `rustls`) carrying
//! [`crate::protocol::Message`]s between peers.
//!
//! **What TLS does and doesn't provide here.** Every connection is
//! encrypted with a real, self-signed certificate, so traffic is
//! confidential and tamper-evident in transit. The authenticity
//! boundary that actually matters for consensus safety remains one
//! layer up, at the message level - a [`crate::protocol::BlockVoteMsg`]/
//! [`crate::protocol::BlockProposalMsg`] carries its own Ed25519
//! signature, checked with `tri_sync_core::crypto` against the
//! sender's known public key regardless of which connection carried
//! it - and that's deliberate: it's the only check that still works
//! once dynamic membership exists and a peer's current key can change.
//!
//! What changed from this module's earlier, more limited design: the
//! TLS certificate is no longer a throwaway unrelated keypair the
//! client simply trusted blindly (`SkipServerVerification` used to
//! accept any server certificate at all, encryption with no identity
//! check whatsoever). Each node's certificate is now generated *from*
//! its real Ed25519 identity key (`self_signed_cert_from_identity`) -
//! the certificate's own public key literally *is* that node's
//! `verifying_key` - and `send_message` pins the expected server to a
//! specific known pubkey via [`PinnedServerVerification`], extracting
//! the presented certificate's embedded Ed25519 key
//! (`extract_ed25519_spki_pubkey`) and rejecting the connection
//! outright on any mismatch, before a single `Message` byte is sent.
//! That closes a real, previously-disclosed gap: an on-path attacker
//! could complete a TLS handshake as if it *were* a trusted peer and
//! sit in the middle of a connection, undetected at the transport
//! layer, for as long as every message happened to still carry a
//! valid application-level signature of its own, versus never even
//! completing the handshake now. `expected_server_pubkey: None` is a
//! narrow, explicit opt-out, used by the adversarial probe binary and
//! a couple of tests that don't have a real peer identity to pin to.
//! It is never the default, and never reachable from the production
//! `broadcast` path in `crate::consensus`.

use crate::protocol::Message;
use ed25519_dalek::{SigningKey, VerifyingKey};
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

/// Wraps a raw 32-byte Ed25519 seed in the fixed PKCS8 v1 DER template
/// RFC 8410 defines for an Ed25519 private key, so it can be handed to
/// `rcgen`/`rustls`: `SEQUENCE { INTEGER 0, SEQUENCE { OID
/// 1.3.101.112 }, OCTET STRING ( OCTET STRING (seed) ) }`. Every byte
/// here except the seed itself is fixed by the RFC - there is nothing
/// to compute, only to concatenate.
fn ed25519_pkcs8_der(signing_key: &SigningKey) -> Vec<u8> {
    const PREFIX: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    let mut out = Vec::with_capacity(PREFIX.len() + 32);
    out.extend_from_slice(&PREFIX);
    out.extend_from_slice(&signing_key.to_bytes());
    out
}

/// RFC 8410 guarantees Ed25519's SubjectPublicKeyInfo
/// `AlgorithmIdentifier` never carries parameters, so this 10-byte
/// sequence - `SEQUENCE { OID 1.3.101.112 }` followed by the BIT
/// STRING header for a 32-byte, zero-unused-bits key - is fixed and
/// always immediately precedes the raw public key bytes in *any*
/// well-formed Ed25519 certificate. Locating it is exact, not a
/// heuristic: the OID alone is already a unique 9-byte tag that can't
/// occur by coincidence elsewhere in a DER certificate.
const ED25519_SPKI_PREFIX: [u8; 10] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// Extracts the raw 32-byte Ed25519 public key embedded in a
/// certificate's SubjectPublicKeyInfo. `None` if the certificate
/// isn't an Ed25519 cert at all (no parser dependency needed: this
/// crate only ever generates Ed25519 certs itself via
/// [`self_signed_cert_from_identity`], so a non-match here means a
/// malformed or wrong-algorithm peer certificate, not a real one this
/// code produced).
fn extract_ed25519_spki_pubkey(cert_der: &[u8]) -> Option<[u8; 32]> {
    let pos = cert_der.windows(ED25519_SPKI_PREFIX.len()).position(|w| w == ED25519_SPKI_PREFIX)?;
    let start = pos + ED25519_SPKI_PREFIX.len();
    cert_der.get(start..start + 32)?.try_into().ok()
}

/// Builds a real, self-signed TLS certificate whose own public key
/// *is* `signing_key`'s - see this module's doc comment for why that
/// matters: it's what lets a peer verify, via
/// [`extract_ed25519_spki_pubkey`]/[`PinnedServerVerification`], that
/// the certificate presented during a handshake genuinely belongs to
/// a specific known node identity, not just some unrelated
/// certificate that happens to also be valid TLS.
fn self_signed_cert_from_identity(
    signing_key: &SigningKey,
) -> Result<(rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>), NetError> {
    let pkcs8_der = ed25519_pkcs8_der(signing_key);
    let key_pair =
        rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8_der.clone()), &rcgen::PKCS_ED25519)
            .map_err(err)?;
    let cert = rcgen::CertificateParams::new(vec!["tri-sync-node".to_string()]).map_err(err)?.self_signed(&key_pair).map_err(err)?;
    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8_der.into());
    Ok((cert_der, key_der))
}

/// A `rustls` server-cert verifier that accepts *only* a certificate
/// whose embedded Ed25519 public key matches `expected_pubkey` -
/// everything else about the handshake (structure, TLS version, the
/// actual handshake signature) still goes through normal `rustls`
/// checks via `verify_tls1{2,3}_signature`. This is the pinning that
/// closes this module's disclosed transport-identity gap: encryption
/// alone used to be all TLS provided here, with the application-level
/// signature on every `Message` as the only real authenticity check.
/// Now the connection itself is refused outright if the server isn't
/// cryptographically provable as the specific peer being dialed.
#[derive(Debug)]
struct PinnedServerVerification {
    provider: rustls::crypto::CryptoProvider,
    expected_pubkey: VerifyingKey,
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerVerification {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let Some(presented) = extract_ed25519_spki_pubkey(end_entity.as_ref()) else {
            return Err(rustls::Error::General("server certificate does not carry a parseable Ed25519 public key".to_string()));
        };
        if presented != self.expected_pubkey.to_bytes() {
            return Err(rustls::Error::General(format!(
                "server certificate identity mismatch: expected {}, got {}",
                hex::encode(self.expected_pubkey.to_bytes()),
                hex::encode(presented)
            )));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A `rustls` server-cert verifier that accepts anything - the
/// explicit, narrow opt-out used only where there is no real peer
/// identity to pin to (the adversarial probe binary, and a couple of
/// transport-level tests) - see this module's doc comment. Never used
/// by the production `broadcast` path.
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

/// Builds a QUIC server endpoint bound to `listen_addr`, with a real
/// self-signed certificate tied to this node's own Ed25519 identity -
/// see [`self_signed_cert_from_identity`].
pub fn make_server_endpoint(listen_addr: SocketAddr, signing_key: &SigningKey) -> Result<quinn::Endpoint, NetError> {
    let (cert, key) = self_signed_cert_from_identity(signing_key)?;
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

/// Builds a client config pinned to `expected_pubkey` - see
/// [`PinnedServerVerification`] - or, if `expected_pubkey` is `None`,
/// one that accepts any server certificate at all (the narrow,
/// explicit opt-out this module's doc comment describes).
fn client_config_for(expected_pubkey: Option<VerifyingKey>) -> Result<quinn::ClientConfig, NetError> {
    let provider = rustls::crypto::ring::default_provider();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider.clone())).with_safe_default_protocol_versions().map_err(err)?.dangerous();
    let mut client_crypto = match expected_pubkey {
        Some(expected_pubkey) => builder.with_custom_certificate_verifier(Arc::new(PinnedServerVerification { provider, expected_pubkey })),
        None => builder.with_custom_certificate_verifier(Arc::new(SkipServerVerification(provider))),
    }
    .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic_crypto = QuicClientConfig::try_from(client_crypto).map_err(err)?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_crypto)))
}

/// Builds a QUIC client endpoint bound to an OS-assigned local port,
/// with no default client config - every connection this module makes
/// goes through `connect_with` in [`send_message`], which always
/// picks pinned-or-explicitly-unpinned per the call, rather than
/// risking a silently-unpinned fallback.
pub fn make_client_endpoint() -> Result<quinn::Endpoint, NetError> {
    let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(err)?;
    Ok(endpoint)
}

/// Connects to `addr` (bounded by a fixed connect timeout - an
/// unreachable peer must not hang the caller) and sends `msg` on a fresh
/// unidirectional stream.
///
/// `expected_server_pubkey`: the Ed25519 identity this connection's
/// server certificate must present to be trusted at all - see this
/// module's doc comment and [`PinnedServerVerification`]. `None` is a
/// narrow, explicit opt-out for callers with no real peer identity to
/// pin to; the production `crate::consensus::broadcast` path always
/// passes `Some`.
///
/// `send.finish()` only marks the stream as done locally - it does not
/// guarantee the bytes have actually reached the peer. A process that
/// drops the connection (or exits) immediately after `finish()` can
/// lose data that was still in flight: confirmed here, where the
/// naive version of this function reported every send as successful
/// while the receiving node logged nothing. `send.stopped()` waits
/// until the peer has actually received the whole stream (or reset
/// it), which is the fix.
pub async fn send_message(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    expected_server_pubkey: Option<VerifyingKey>,
    msg: &Message,
) -> Result<(), NetError> {
    let client_config = client_config_for(expected_server_pubkey)?;
    let connecting = endpoint.connect_with(client_config, addr, "tri-sync-node").map_err(err)?;
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
    /// endpoints, not fakes. Confirms the whole stack (a real
    /// identity-bound self-signed cert, pinned verification against
    /// that exact identity, the ring provider setup, the uni-stream
    /// framing, and `send.stopped()` actually waiting for delivery)
    /// works end to end, as a fast in-process complement to the manual
    /// multi-process test this stage was verified with.
    #[tokio::test]
    async fn a_message_sent_to_a_real_server_endpoint_is_received_intact() {
        let server_identity = SigningKey::generate(&mut rand::rngs::OsRng);
        let server_endpoint = make_server_endpoint(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), &server_identity).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(serve(server_endpoint, tx));

        let client_endpoint = make_client_endpoint().unwrap();
        let msg = Message::Observation(ObservationMsg { sender: 7, values: vec![1.0, 2.0, 3.0], sig_hex: "aa".to_string() });
        send_message(&client_endpoint, server_addr, Some(server_identity.verifying_key()), &msg).await.unwrap();

        let (_, received) = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("should receive within 5s")
            .expect("channel should not have closed");
        assert_eq!(received, msg);
    }

    /// The actual security property pinning exists for: a server
    /// presenting a real, validly-self-signed certificate - just not
    /// the one belonging to the identity the caller actually expected
    /// - must be rejected before any message is ever sent, not merely
    /// logged or warned about.
    #[tokio::test]
    async fn a_server_certificate_for_the_wrong_identity_is_rejected() {
        let server_identity = SigningKey::generate(&mut rand::rngs::OsRng);
        let server_endpoint = make_server_endpoint(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), &server_identity).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(serve(server_endpoint, tx));

        let wrong_identity = SigningKey::generate(&mut rand::rngs::OsRng);
        assert_ne!(server_identity.verifying_key(), wrong_identity.verifying_key(), "sanity: must be genuinely different identities");

        let client_endpoint = make_client_endpoint().unwrap();
        let msg = Message::Observation(ObservationMsg { sender: 7, values: vec![1.0], sig_hex: "aa".to_string() });
        let result = send_message(&client_endpoint, server_addr, Some(wrong_identity.verifying_key()), &msg).await;

        assert!(result.is_err(), "a real, validly self-signed certificate for the WRONG identity must still be rejected");
    }

    #[tokio::test]
    async fn connecting_to_an_unreachable_address_fails_within_the_connect_timeout_not_forever() {
        let client_endpoint = make_client_endpoint().unwrap();
        // Nothing listens on this loopback port.
        let dead_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let msg = Message::Observation(ObservationMsg { sender: 1, values: vec![0.0], sig_hex: "aa".to_string() });

        let started = tokio::time::Instant::now();
        let result = send_message(&client_endpoint, dead_addr, None, &msg).await;
        let elapsed = started.elapsed();

        assert!(result.is_err());
        assert!(elapsed < CONNECT_TIMEOUT + std::time::Duration::from_secs(2), "took {elapsed:?}, should be bounded");
    }

    /// `extract_ed25519_spki_pubkey` against a real generated
    /// certificate, not a hand-crafted byte string - proves the
    /// fixed-prefix search actually recovers the right 32 bytes from
    /// genuine `rcgen` output, not just from bytes this test invented
    /// to match the prefix by construction.
    #[test]
    fn extract_ed25519_spki_pubkey_recovers_the_real_identity_from_a_generated_cert() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let (cert_der, _key_der) = self_signed_cert_from_identity(&signing_key).unwrap();
        let extracted = extract_ed25519_spki_pubkey(cert_der.as_ref()).expect("a cert this module generated must always parse");
        assert_eq!(extracted, signing_key.verifying_key().to_bytes());
    }

    #[test]
    fn extract_ed25519_spki_pubkey_returns_none_for_non_certificate_bytes() {
        assert_eq!(extract_ed25519_spki_pubkey(b"not a certificate at all"), None);
    }
}
