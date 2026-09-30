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
    EmptyListenAddr,
    DuplicatePeerId(usize),
    PeerIdMatchesOwnNodeId(usize),
    BadPeerPubkey(usize),
    ZeroRoundInterval,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Toml(e) => write!(f, "node.toml is not valid TOML: {e}"),
            ConfigError::ZeroDimension => write!(f, "node.toml: dim must be at least 1"),
            ConfigError::EmptyListenAddr => write!(f, "node.toml: listen_addr must not be empty"),
            ConfigError::DuplicatePeerId(id) => write!(f, "node.toml: peer id {id} is listed more than once"),
            ConfigError::PeerIdMatchesOwnNodeId(id) => {
                write!(f, "node.toml: peer id {id} is the same as this node's own node_id")
            }
            ConfigError::BadPeerPubkey(id) => {
                write!(f, "node.toml: peer id {id}'s pubkey_hex is not a valid 32-byte hex-encoded Ed25519 public key")
            }
            ConfigError::ZeroRoundInterval => write!(f, "node.toml: round_interval_secs must be at least 1"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Parses and validates `toml_str` as a `node.toml` file.
pub fn load_from_str(toml_str: &str) -> Result<NodeConfig, ConfigError> {
    let config: NodeConfig = toml::from_str(toml_str).map_err(|e| ConfigError::Toml(e.to_string()))?;

    if config.dim == 0 {
        return Err(ConfigError::ZeroDimension);
    }
    if config.listen_addr.trim().is_empty() {
        return Err(ConfigError::EmptyListenAddr);
    }
    if config.round_interval_secs == 0 {
        return Err(ConfigError::ZeroRoundInterval);
    }

    let mut seen = std::collections::HashSet::new();
    for peer in &config.peers {
        if peer.id == config.node_id {
            return Err(ConfigError::PeerIdMatchesOwnNodeId(peer.id));
        }
        if !seen.insert(peer.id) {
            return Err(ConfigError::DuplicatePeerId(peer.id));
        }
        let valid_pubkey = hex::decode(&peer.pubkey_hex).ok().filter(|b| b.len() == 32).is_some();
        if !valid_pubkey {
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
        assert_eq!(load_from_str(toml), Err(ConfigError::EmptyListenAddr));
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
