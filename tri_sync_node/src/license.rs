//! Offline license verification for `tri_sync_node`.
//!
//! `license.toml` carries `org`, `max_nodes`, `features`, `expiry`
//! (`YYYY-MM-DD`), and `signature` (a hex-encoded Ed25519 signature over
//! the other four fields). This module only parses and verifies that
//! file's contents against an embedded public key - it does no file
//! I/O; `main.rs` reads `license.toml` from disk and hands the string to
//! [`parse_and_verify`], then exits the process if it returns an `Err`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Ed25519 public key that every license signature is checked against.
///
/// This is a development key generated for this repository so the
/// verification path can be tested end-to-end for real (see
/// `tri_sync_node/license.example.toml`, signed with its matching
/// private key). It must be replaced with a real production keypair
/// before any license is issued to a paying customer, and the private
/// half must never be committed to this repository - it stays with
/// whoever issues licenses (see `LICENSE.md`, contact tri@trisync.dev).
pub const LICENSE_PUBLIC_KEY_HEX: &str =
    "e82126f49e38641692abc6166bf172033267195bfdf12d7c9396089548b8bdbf";

#[derive(Debug, Clone, Deserialize)]
struct LicenseFile {
    org: String,
    max_nodes: u32,
    features: Vec<String>,
    expiry: String,
    signature: String,
}

/// A license that has already passed signature and expiry checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct License {
    pub org: String,
    pub max_nodes: u32,
    pub features: Vec<String>,
    pub expiry: String,
}

impl License {
    // Feature gating isn't wired to any specific feature name yet
    // (Stage 5+ networking/persistence code will use this); already
    // exercised by this module's own tests.
    #[allow(dead_code)]
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }

    /// True if running `n` nodes is within this license's `max_nodes`.
    pub fn allows_node_count(&self, n: u32) -> bool {
        n <= self.max_nodes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseError {
    Toml(String),
    BadPublicKey,
    BadSignatureEncoding,
    SignatureInvalid,
    BadExpiryFormat(String),
    Expired { expiry: String, today: String },
}

impl std::fmt::Display for LicenseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseError::Toml(e) => write!(f, "license.toml is not valid TOML: {e}"),
            LicenseError::BadPublicKey => write!(f, "embedded license public key is malformed"),
            LicenseError::BadSignatureEncoding => write!(f, "license signature is not valid hex-encoded Ed25519"),
            LicenseError::SignatureInvalid => write!(f, "license signature does not match its contents - the file was altered or was never signed with the expected key"),
            LicenseError::BadExpiryFormat(e) => write!(f, "license expiry '{e}' is not a valid YYYY-MM-DD date"),
            LicenseError::Expired { expiry, today } => write!(f, "license expired on {expiry} (today is {today})"),
        }
    }
}

impl std::error::Error for LicenseError {}

/// The exact byte string a license's signature is computed over.
/// `features` is sorted before joining so that reordering the list in
/// the TOML file (which changes nothing about what's licensed) doesn't
/// change the signature.
pub fn canonical_string(org: &str, max_nodes: u32, features: &[String], expiry: &str) -> String {
    let mut sorted: Vec<&str> = features.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    format!("{org}|{max_nodes}|{}|{expiry}", sorted.join(","))
}

/// Parses `toml_str` as a license file and verifies its signature
/// against `pubkey_hex`, then checks it hasn't expired. Returns the
/// verified [`License`] on success, or a [`LicenseError`] describing
/// exactly what failed - never panics on malformed input.
pub fn parse_and_verify(toml_str: &str, pubkey_hex: &str) -> Result<License, LicenseError> {
    let raw: LicenseFile = toml::from_str(toml_str).map_err(|e| LicenseError::Toml(e.to_string()))?;

    let pubkey_bytes = hex::decode(pubkey_hex).map_err(|_| LicenseError::BadPublicKey)?;
    let pubkey_arr: [u8; 32] = pubkey_bytes.try_into().map_err(|_| LicenseError::BadPublicKey)?;
    let vk = VerifyingKey::from_bytes(&pubkey_arr).map_err(|_| LicenseError::BadPublicKey)?;

    let sig_bytes = hex::decode(&raw.signature).map_err(|_| LicenseError::BadSignatureEncoding)?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| LicenseError::BadSignatureEncoding)?;
    let sig = Signature::from_bytes(&sig_arr);

    let canon = canonical_string(&raw.org, raw.max_nodes, &raw.features, &raw.expiry);
    if vk.verify(canon.as_bytes(), &sig).is_err() {
        return Err(LicenseError::SignatureInvalid);
    }

    let expiry_days = civil_days_from_iso(&raw.expiry)
        .ok_or_else(|| LicenseError::BadExpiryFormat(raw.expiry.clone()))?;
    let today_days = today_civil_days();
    if expiry_days < today_days {
        return Err(LicenseError::Expired {
            expiry: raw.expiry.clone(),
            today: civil_iso_from_days(today_days),
        });
    }

    Ok(License {
        org: raw.org,
        max_nodes: raw.max_nodes,
        features: raw.features,
        expiry: raw.expiry,
    })
}

// --- Minimal calendar math, dependency-free -------------------------
//
// Howard Hinnant's "days_from_civil" / "civil_from_days" (public
// domain, http://howardhinnant.github.io/date_algorithms.html), used
// instead of pulling in a date/time crate for a single expiry
// comparison. Self-validated by round-trip tests below rather than
// trusted on the strength of the citation alone.

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m as i64 + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn parse_iso_date(s: &str) -> Option<(i64, u32, u32)> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 || parts[0].len() != 4 || parts[1].len() != 2 || parts[2].len() != 2 {
        return None;
    }
    let y: i64 = parts[0].parse().ok()?;
    let m: u32 = parts[1].parse().ok()?;
    let d: u32 = parts[2].parse().ok()?;
    Some((y, m, d))
}

/// Parses a `YYYY-MM-DD` string into days-since-1970-01-01, rejecting
/// any string that doesn't round-trip through the calendar math (e.g.
/// `2023-02-30`) rather than silently normalizing it.
fn civil_days_from_iso(s: &str) -> Option<i64> {
    let (y, m, d) = parse_iso_date(s)?;
    if !(1..=12).contains(&m) {
        return None;
    }
    let days = days_from_civil(y, m, d);
    if civil_from_days(days) == (y, m, d) {
        Some(days)
    } else {
        None
    }
}

fn civil_iso_from_days(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

fn today_civil_days() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs();
    (secs / 86_400) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    // --- calendar math self-checks ---

    #[test]
    fn unix_epoch_is_day_zero() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn day_before_epoch_is_minus_one() {
        assert_eq!(days_from_civil(1969, 12, 31), -1);
    }

    #[test]
    fn leap_day_round_trips() {
        let days = days_from_civil(2024, 2, 29);
        assert_eq!(civil_from_days(days), (2024, 2, 29));
    }

    #[test]
    fn a_wide_range_of_dates_round_trip_through_days_and_back() {
        for y in [1, 999, 1970, 2000, 2024, 2099, 3000] {
            for m in 1..=12u32 {
                for d in [1u32, 15, 28] {
                    let days = days_from_civil(y, m, d);
                    assert_eq!(civil_from_days(days), (y, m, d), "failed for {y:04}-{m:02}-{d:02}");
                }
            }
        }
    }

    #[test]
    fn invalid_calendar_dates_are_rejected() {
        assert_eq!(civil_days_from_iso("2023-02-30"), None); // Feb has 28/29 days
        assert_eq!(civil_days_from_iso("2023-13-01"), None); // no month 13
        assert_eq!(civil_days_from_iso("not-a-date"), None);
        assert_eq!(civil_days_from_iso("2023-1-1"), None); // must be zero-padded
    }

    // --- license verification ---

    fn test_keypair() -> SigningKey {
        let mut rng = StdRng::seed_from_u64(7);
        SigningKey::generate(&mut rng)
    }

    fn make_license_toml(sk: &SigningKey, org: &str, max_nodes: u32, features: &[&str], expiry: &str) -> String {
        let features: Vec<String> = features.iter().map(|s| s.to_string()).collect();
        let canon = canonical_string(org, max_nodes, &features, expiry);
        let sig = sk.sign(canon.as_bytes());
        let features_toml = features.iter().map(|f| format!("\"{f}\"")).collect::<Vec<_>>().join(", ");
        format!(
            "org = \"{org}\"\nmax_nodes = {max_nodes}\nfeatures = [{features_toml}]\nexpiry = \"{expiry}\"\nsignature = \"{}\"\n",
            hex::encode(sig.to_bytes())
        )
    }

    #[test]
    fn a_validly_signed_unexpired_license_is_accepted() {
        let sk = test_keypair();
        let vk_hex = hex::encode(sk.verifying_key().to_bytes());
        let toml = make_license_toml(&sk, "Acme Corp", 5, &["chain_weighted", "http_api"], "2999-01-01");
        let license = parse_and_verify(&toml, &vk_hex).expect("should verify");
        assert_eq!(license.org, "Acme Corp");
        assert_eq!(license.max_nodes, 5);
        assert!(license.has_feature("http_api"));
        assert!(!license.has_feature("nonexistent"));
        assert!(license.allows_node_count(5));
        assert!(!license.allows_node_count(6));
    }

    #[test]
    fn feature_order_does_not_affect_signature_validity() {
        let sk = test_keypair();
        let vk_hex = hex::encode(sk.verifying_key().to_bytes());
        // Sign with one order, but the file lists them in another -
        // canonicalization sorts both the same way.
        let canon = canonical_string("Acme", 1, &["b".to_string(), "a".to_string()], "2999-01-01");
        let sig = sk.sign(canon.as_bytes());
        let toml = format!(
            "org = \"Acme\"\nmax_nodes = 1\nfeatures = [\"a\", \"b\"]\nexpiry = \"2999-01-01\"\nsignature = \"{}\"\n",
            hex::encode(sig.to_bytes())
        );
        assert!(parse_and_verify(&toml, &vk_hex).is_ok());
    }

    #[test]
    fn a_tampered_field_fails_verification() {
        let sk = test_keypair();
        let vk_hex = hex::encode(sk.verifying_key().to_bytes());
        let toml = make_license_toml(&sk, "Acme Corp", 5, &["http_api"], "2999-01-01");
        let tampered = toml.replace("max_nodes = 5", "max_nodes = 500");
        assert_eq!(parse_and_verify(&tampered, &vk_hex), Err(LicenseError::SignatureInvalid));
    }

    #[test]
    fn a_signature_from_the_wrong_key_is_rejected() {
        let sk = test_keypair();
        let other_sk = SigningKey::generate(&mut StdRng::seed_from_u64(99));
        let vk_hex = hex::encode(other_sk.verifying_key().to_bytes());
        let toml = make_license_toml(&sk, "Acme Corp", 5, &["http_api"], "2999-01-01");
        assert_eq!(parse_and_verify(&toml, &vk_hex), Err(LicenseError::SignatureInvalid));
    }

    #[test]
    fn an_expired_license_is_rejected_even_with_a_valid_signature() {
        let sk = test_keypair();
        let vk_hex = hex::encode(sk.verifying_key().to_bytes());
        let toml = make_license_toml(&sk, "Acme Corp", 5, &["http_api"], "2000-01-01");
        match parse_and_verify(&toml, &vk_hex) {
            Err(LicenseError::Expired { expiry, .. }) => assert_eq!(expiry, "2000-01-01"),
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_expiry_date_is_rejected() {
        let sk = test_keypair();
        let vk_hex = hex::encode(sk.verifying_key().to_bytes());
        let toml = make_license_toml(&sk, "Acme Corp", 5, &["http_api"], "not-a-date");
        assert!(matches!(parse_and_verify(&toml, &vk_hex), Err(LicenseError::BadExpiryFormat(_))));
    }

    #[test]
    fn malformed_toml_is_rejected_without_panicking() {
        let vk_hex = LICENSE_PUBLIC_KEY_HEX;
        assert!(matches!(parse_and_verify("not valid toml {{{", vk_hex), Err(LicenseError::Toml(_))));
    }

    #[test]
    fn a_signature_that_is_not_valid_hex_is_rejected_without_panicking() {
        let toml = "org = \"Acme\"\nmax_nodes = 1\nfeatures = []\nexpiry = \"2999-01-01\"\nsignature = \"not hex\"\n";
        assert_eq!(parse_and_verify(toml, LICENSE_PUBLIC_KEY_HEX), Err(LicenseError::BadSignatureEncoding));
    }

    /// The end-to-end real path: a license file signed with the actual
    /// private key matching `LICENSE_PUBLIC_KEY_HEX` (kept out of this
    /// repository), verified against the real embedded constant - not a
    /// synthetic ad hoc keypair like the tests above.
    #[test]
    fn the_real_example_license_verifies_against_the_embedded_production_key() {
        let toml = include_str!("../license.example.toml");
        let license = parse_and_verify(toml, LICENSE_PUBLIC_KEY_HEX).expect("example license should verify");
        assert_eq!(license.org, "TriSync Example Org");
        assert_eq!(license.max_nodes, 5);
        assert!(license.has_feature("chain_crypto"));
    }
}
