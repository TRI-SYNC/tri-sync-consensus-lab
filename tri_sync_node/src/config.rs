//! `node.toml` parsing and validation.
//!
//! Pure string-in, struct-out parsing with no file I/O - `main.rs` reads
//! `node.toml` from disk and hands the string to [`load_from_str`].

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PeerConfig {
    pub id: usize,
    pub addr: String,
    /// This peer's Ed25519 public key, hex-encoded - exchanged out of
    /// band before deployment (there is no in-band key discovery yet).
    /// Required so block proposals and votes from this peer can be
    /// verified against a key the operator actually expects, not
    /// whatever key a message happens to claim.
    pub pubkey_hex: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct NodeConfig {
    pub node_id: usize,
    pub dim: usize,
    pub listen_addr: String,
    #[serde(default = "default_license_path")]
    pub license_path: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default = "default_round_interval_secs")]
    pub round_interval_secs: u64,
    /// Address to serve Prometheus metrics on (`/metrics`), e.g.
    /// `"127.0.0.1:9898"`. Omit to disable - metrics are optional.
    #[serde(default)]
    pub metrics_addr: Option<String>,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

fn default_license_path() -> String {
    "license.toml".to_string()
}

fn default_data_dir() -> String {
    "data".to_string()
}

fn default_round_interval_secs() -> u64 {
    3
}

impl NodeConfig {
    /// Total nodes in this deployment: this node plus its configured
    /// peers. What a license's `max_nodes` is checked against.
    pub fn network_size(&self) -> usize {
        1 + self.peers.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Toml(String),
    ZeroDimension,
    BadListenAddr(String),
    DuplicatePeerId(usize),
    DuplicatePeerAddr(usize),
    PeerIdMatchesOwnNodeId(usize),
    PeerAddrMatchesOwnListenAddr(usize),
    BadPeerAddr(usize),
    BadPeerPubkey(usize),
    ZeroRoundInterval,
    BadMetricsAddr(String),
    MetricsAddrMatchesListenAddr,
    EmptyLicensePath,
    EmptyDataDir,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Toml(e) => write!(f, "node.toml is not valid TOML: {e}"),
            ConfigError::ZeroDimension => write!(f, "node.toml: dim must be at least 1"),
            ConfigError::BadListenAddr(a) => write!(f, "node.toml: listen_addr '{a}' is not a valid host:port address"),
            ConfigError::DuplicatePeerId(id) => write!(f, "node.toml: peer id {id} is listed more than once"),
            ConfigError::DuplicatePeerAddr(id) => {
                write!(f, "node.toml: peer id {id}'s addr is already used by another configured peer")
            }
            ConfigError::PeerIdMatchesOwnNodeId(id) => {
                write!(f, "node.toml: peer id {id} is the same as this node's own node_id")
            }
            ConfigError::PeerAddrMatchesOwnListenAddr(id) => {
                write!(f, "node.toml: peer id {id}'s addr is the same as this node's own listen_addr")
            }
            ConfigError::BadPeerAddr(id) => write!(f, "node.toml: peer id {id}'s addr is not a valid host:port address"),
            ConfigError::BadPeerPubkey(id) => {
                write!(f, "node.toml: peer id {id}'s pubkey_hex is not a valid 32-byte hex-encoded Ed25519 public key")
            }
            ConfigError::ZeroRoundInterval => write!(f, "node.toml: round_interval_secs must be at least 1"),
            ConfigError::BadMetricsAddr(a) => write!(f, "node.toml: metrics_addr '{a}' is not a valid host:port address"),
            ConfigError::MetricsAddrMatchesListenAddr => {
                write!(f, "node.toml: metrics_addr must not be the same as listen_addr")
            }
            ConfigError::EmptyLicensePath => write!(f, "node.toml: license_path must not be empty"),
            ConfigError::EmptyDataDir => write!(f, "node.toml: data_dir must not be empty"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// True only if `hex_str` decodes to exactly 32 bytes that are also a
/// valid compressed Ed25519 point - not just the right length. A real
/// gap this closes: roughly half of all 32-byte values are *not* valid
/// points (confirmed empirically), so a length-only check let a
/// malformed-but-right-length `pubkey_hex` pass validation here and
/// then panic the whole process later at `consensus.rs`'s
/// `decode_verifying_key(...).expect("validated at config load")` -
/// exactly the loud-failure-at-config-load-time this module's own doc
/// comment promises, defeated by checking the wrong thing.
fn is_valid_ed25519_pubkey_hex(hex_str: &str) -> bool {
    let Ok(bytes) = hex::decode(hex_str) else { return false };
    let Ok(arr): Result<[u8; 32], _> = bytes.try_into() else { return false };
    ed25519_dalek::VerifyingKey::from_bytes(&arr).is_ok()
}

/// Parses and validates `toml_str` as a `node.toml` file. Every address
/// field is checked for real parseability here - not just
/// non-emptiness - so a typo'd address fails loudly at config-load
/// time instead of either a confusing runtime error (`listen_addr`) or,
/// worse, a peer that silently drops out of the network because its
/// unparseable `addr` never even reaches `consensus::run`'s peer map.
pub fn load_from_str(toml_str: &str) -> Result<NodeConfig, ConfigError> {
    let config: NodeConfig = toml::from_str(toml_str).map_err(|e| ConfigError::Toml(e.to_string()))?;

    if config.dim == 0 {
        return Err(ConfigError::ZeroDimension);
    }
    let listen_addr: std::net::SocketAddr =
        config.listen_addr.parse().map_err(|_| ConfigError::BadListenAddr(config.listen_addr.clone()))?;
    if config.round_interval_secs == 0 {
        return Err(ConfigError::ZeroRoundInterval);
    }
    if config.license_path.trim().is_empty() {
        return Err(ConfigError::EmptyLicensePath);
    }
    if config.data_dir.trim().is_empty() {
        return Err(ConfigError::EmptyDataDir);
    }
    if let Some(addr) = &config.metrics_addr {
        let metrics_addr: std::net::SocketAddr = addr.parse().map_err(|_| ConfigError::BadMetricsAddr(addr.clone()))?;
        if metrics_addr == listen_addr {
            return Err(ConfigError::MetricsAddrMatchesListenAddr);
        }
    }

    let mut seen_ids = std::collections::HashSet::new();
    let mut seen_addrs = std::collections::HashSet::new();
    for peer in &config.peers {
        if peer.id == config.node_id {
            return Err(ConfigError::PeerIdMatchesOwnNodeId(peer.id));
        }
        if !seen_ids.insert(peer.id) {
            return Err(ConfigError::DuplicatePeerId(peer.id));
        }
        let peer_addr: std::net::SocketAddr = peer.addr.parse().map_err(|_| ConfigError::BadPeerAddr(peer.id))?;
        if peer_addr == listen_addr {
            return Err(ConfigError::PeerAddrMatchesOwnListenAddr(peer.id));
        }
        if !seen_addrs.insert(peer_addr) {
            return Err(ConfigError::DuplicatePeerAddr(peer.id));
        }
        if !is_valid_ed25519_pubkey_hex(&peer.pubkey_hex) {
            return Err(ConfigError::BadPeerPubkey(peer.id));
        }
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMMY_PUBKEY: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn a_well_formed_config_with_peers_parses_and_validates() {
        let toml = format!(
            r#"
            node_id = 0
            dim = 3
            listen_addr = "0.0.0.0:9000"

            [[peers]]
            id = 1
            addr = "127.0.0.1:9001"
            pubkey_hex = "{k}"

            [[peers]]
            id = 2
            addr = "127.0.0.1:9002"
            pubkey_hex = "{k}"
        "#,
            k = &DUMMY_PUBKEY[..64]
        );
        let config = load_from_str(&toml).expect("should parse");
        assert_eq!(config.node_id, 0);
        assert_eq!(config.dim, 3);
        assert_eq!(config.peers.len(), 2);
        assert_eq!(config.network_size(), 3);
        assert_eq!(config.license_path, "license.toml");
        assert_eq!(config.round_interval_secs, 3);
    }

    #[test]
    fn license_path_defaults_when_omitted_but_can_be_overridden() {
        let toml = r#"
            node_id = 0
            dim = 1
            listen_addr = "0.0.0.0:9000"
            license_path = "custom_license.toml"
        "#;
        let config = load_from_str(toml).expect("should parse");
        assert_eq!(config.license_path, "custom_license.toml");
    }

    #[test]
    fn round_interval_secs_defaults_when_omitted_but_can_be_overridden() {
        let toml = r#"
            node_id = 0
            dim = 1
            listen_addr = "0.0.0.0:9000"
            round_interval_secs = 10
        "#;
        let config = load_from_str(toml).expect("should parse");
        assert_eq!(config.round_interval_secs, 10);
    }

    #[test]
    fn zero_round_interval_is_rejected() {
        let toml = r#"
            node_id = 0
            dim = 1
            listen_addr = "0.0.0.0:9000"
            round_interval_secs = 0
        "#;
        assert_eq!(load_from_str(toml), Err(ConfigError::ZeroRoundInterval));
    }

    #[test]
    fn a_config_with_no_peers_is_a_valid_single_node_deployment() {
        let toml = r#"
            node_id = 0
            dim = 1
            listen_addr = "0.0.0.0:9000"
        "#;
        let config = load_from_str(toml).expect("should parse");
        assert_eq!(config.network_size(), 1);
    }

    #[test]
    fn zero_dimension_is_rejected() {
        let toml = r#"
            node_id = 0
            dim = 0
            listen_addr = "0.0.0.0:9000"
        "#;
        assert_eq!(load_from_str(toml), Err(ConfigError::ZeroDimension));
    }

    #[test]
    fn empty_listen_addr_is_rejected() {
        let toml = r#"
            node_id = 0
            dim = 1
            listen_addr = "   "
        "#;
        assert_eq!(load_from_str(toml), Err(ConfigError::BadListenAddr("   ".to_string())));
    }

    #[test]
    fn a_listen_addr_missing_a_port_is_rejected() {
        let toml = r#"
            node_id = 0
            dim = 1
            listen_addr = "127.0.0.1"
        "#;
        assert_eq!(load_from_str(toml), Err(ConfigError::BadListenAddr("127.0.0.1".to_string())));
    }

    #[test]
    fn a_malformed_peer_addr_is_rejected() {
        let toml = format!(
            r#"
            node_id = 0
            dim = 1
            listen_addr = "0.0.0.0:9000"

            [[peers]]
            id = 1
            addr = "not-an-address"
            pubkey_hex = "{}"
        "#,
            &DUMMY_PUBKEY[..64]
        );
        assert_eq!(load_from_str(&toml), Err(ConfigError::BadPeerAddr(1)));
    }

    #[test]
    fn a_peer_addr_matching_this_nodes_own_listen_addr_is_rejected() {
        let toml = format!(
            r#"
            node_id = 0
            dim = 1
            listen_addr = "127.0.0.1:9000"

            [[peers]]
            id = 1
            addr = "127.0.0.1:9000"
            pubkey_hex = "{}"
        "#,
            &DUMMY_PUBKEY[..64]
        );
        assert_eq!(load_from_str(&toml), Err(ConfigError::PeerAddrMatchesOwnListenAddr(1)));
    }

    #[test]
    fn two_peers_sharing_the_same_addr_are_rejected() {
        let toml = format!(
            r#"
            node_id = 0
            dim = 1
            listen_addr = "0.0.0.0:9000"

            [[peers]]
            id = 1
            addr = "127.0.0.1:9001"
            pubkey_hex = "{k}"

            [[peers]]
            id = 2
            addr = "127.0.0.1:9001"
            pubkey_hex = "{k}"
        "#,
            k = &DUMMY_PUBKEY[..64]
        );
        assert_eq!(load_from_str(&toml), Err(ConfigError::DuplicatePeerAddr(2)));
    }

    #[test]
    fn metrics_addr_matching_listen_addr_is_rejected() {
        let toml = r#"
            node_id = 0
            dim = 1
            listen_addr = "127.0.0.1:9000"
            metrics_addr = "127.0.0.1:9000"
        "#;
        assert_eq!(load_from_str(toml), Err(ConfigError::MetricsAddrMatchesListenAddr));
    }

    #[test]
    fn a_bad_metrics_addr_is_still_rejected() {
        let toml = r#"
            node_id = 0
            dim = 1
            listen_addr = "127.0.0.1:9000"
            metrics_addr = "not an address"
        "#;
        assert_eq!(load_from_str(toml), Err(ConfigError::BadMetricsAddr("not an address".to_string())));
    }

    #[test]
    fn an_empty_license_path_is_rejected() {
        let toml = r#"
            node_id = 0
            dim = 1
            listen_addr = "127.0.0.1:9000"
            license_path = "   "
        "#;
        assert_eq!(load_from_str(toml), Err(ConfigError::EmptyLicensePath));
    }

    #[test]
    fn an_empty_data_dir_is_rejected() {
        let toml = r#"
            node_id = 0
            dim = 1
            listen_addr = "127.0.0.1:9000"
            data_dir = "   "
        "#;
        assert_eq!(load_from_str(toml), Err(ConfigError::EmptyDataDir));
    }

    #[test]
    fn a_peer_sharing_this_nodes_own_id_is_rejected() {
        let toml = format!(
            r#"
            node_id = 5
            dim = 1
            listen_addr = "0.0.0.0:9000"

            [[peers]]
            id = 5
            addr = "127.0.0.1:9001"
            pubkey_hex = "{}"
        "#,
            &DUMMY_PUBKEY[..64]
        );
        assert_eq!(load_from_str(&toml), Err(ConfigError::PeerIdMatchesOwnNodeId(5)));
    }

    #[test]
    fn duplicate_peer_ids_are_rejected() {
        let toml = format!(
            r#"
            node_id = 0
            dim = 1
            listen_addr = "0.0.0.0:9000"

            [[peers]]
            id = 1
            addr = "127.0.0.1:9001"
            pubkey_hex = "{k}"

            [[peers]]
            id = 1
            addr = "127.0.0.1:9002"
            pubkey_hex = "{k}"
        "#,
            k = &DUMMY_PUBKEY[..64]
        );
        assert_eq!(load_from_str(&toml), Err(ConfigError::DuplicatePeerId(1)));
    }

    #[test]
    fn a_malformed_peer_pubkey_is_rejected() {
        let toml = r#"
            node_id = 0
            dim = 1
            listen_addr = "0.0.0.0:9000"

            [[peers]]
            id = 1
            addr = "127.0.0.1:9001"
            pubkey_hex = "not hex"
        "#;
        assert_eq!(load_from_str(toml), Err(ConfigError::BadPeerPubkey(1)));
    }

    #[test]
    fn a_peer_pubkey_of_the_wrong_length_is_rejected() {
        let toml = r#"
            node_id = 0
            dim = 1
            listen_addr = "0.0.0.0:9000"

            [[peers]]
            id = 1
            addr = "127.0.0.1:9001"
            pubkey_hex = "abcd"
        "#;
        assert_eq!(load_from_str(toml), Err(ConfigError::BadPeerPubkey(1)));
    }

    #[test]
    fn a_peer_pubkey_of_the_right_length_but_not_a_valid_curve_point_is_rejected() {
        // A real bug a focused code review caught: the old check only
        // verified 32 bytes, not that they're a valid compressed
        // Ed25519 point - roughly half of all 32-byte values aren't
        // (confirmed empirically). This exact value decodes to 32
        // bytes but VerifyingKey::from_bytes rejects it.
        let toml = r#"
            node_id = 0
            dim = 1
            listen_addr = "0.0.0.0:9000"

            [[peers]]
            id = 1
            addr = "127.0.0.1:9001"
            pubkey_hex = "0000000000000000000000000000000000000000000000000000000000000001"
        "#;
        assert_eq!(load_from_str(toml), Err(ConfigError::BadPeerPubkey(1)));
    }

    #[test]
    fn a_peer_missing_pubkey_hex_is_rejected_without_panicking() {
        let toml = r#"
            node_id = 0
            dim = 1
            listen_addr = "0.0.0.0:9000"

            [[peers]]
            id = 1
            addr = "127.0.0.1:9001"
        "#;
        assert!(matches!(load_from_str(toml), Err(ConfigError::Toml(_))));
    }

    #[test]
    fn malformed_toml_is_rejected_without_panicking() {
        assert!(matches!(load_from_str("not valid toml {{{"), Err(ConfigError::Toml(_))));
    }

    #[test]
    fn missing_required_fields_are_rejected_without_panicking() {
        assert!(matches!(load_from_str("node_id = 0"), Err(ConfigError::Toml(_))));
    }
}
