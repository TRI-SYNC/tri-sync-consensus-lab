//! `tri_sync_node_license_tool`: the actual tool "whoever issues
//! licenses" (see `LICENSE.md`) uses to mint a keypair and sign
//! `license.toml` files - this didn't exist before, which meant the
//! only way to produce a validly-signed license was to hand-write a
//! throwaway script against `tri_sync_node::license`'s internals. A
//! real commercial deployment needs this to be a real, repeatable
//! tool, not a one-off.
//!
//! ```text
//! tri_sync_node_license_tool generate-key
//! tri_sync_node_license_tool sign --private-key <hex> --org <name> --max-nodes <n> --expiry <YYYY-MM-DD> [--features <csv>] [--out <path>]
//! ```
//!
//! **This tool never generates the real production keypair for you as
//! a side effect of anything else.** `generate-key` prints a keypair
//! and exits - nothing is persisted, nothing is sent anywhere. Run it
//! yourself, on a machine you trust, and move the private key straight
//! into your organization's own secret storage; this tool has no
//! opinion on what that storage is and deliberately never writes the
//! private key to disk itself. `LICENSE_PUBLIC_KEY_HEX` in
//! `tri_sync_node::license` must be updated to match the public half
//! before any license signed with the new key will verify.

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::process::ExitCode;
use tri_sync_node::license;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return ExitCode::FAILURE;
    };

    match command.as_str() {
        "generate-key" => generate_key(),
        "sign" => sign(args),
        _ => {
            print_usage();
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!(
        "usage:\n  \
         tri_sync_node_license_tool generate-key\n  \
         tri_sync_node_license_tool sign --private-key <hex> --org <name> --max-nodes <n> --expiry <YYYY-MM-DD> [--features <csv>] [--out <path>]"
    );
}

/// Mints a fresh Ed25519 keypair and prints both halves - nothing is
/// written to disk or anywhere else. The operator is responsible for
/// moving the private key into real secret storage and for updating
/// `LICENSE_PUBLIC_KEY_HEX` with the printed public key; this tool has
/// no way to do either safely on its own and doesn't try to.
fn generate_key() -> ExitCode {
    let signing_key = SigningKey::generate(&mut OsRng);
    let private_hex = hex::encode(signing_key.to_bytes());
    let public_hex = hex::encode(signing_key.verifying_key().to_bytes());

    println!("public_key_hex  = {public_hex}");
    println!("private_key_hex = {private_hex}");
    eprintln!();
    eprintln!("tri_sync_node_license_tool: the private key above is shown exactly once and is not stored anywhere by this tool.");
    eprintln!("Move it into your organization's own secret storage now - it is unrecoverable once this terminal's scrollback is gone.");
    eprintln!("Update LICENSE_PUBLIC_KEY_HEX in tri_sync_node/src/license.rs to the public_key_hex above before signing any real license with this key.");
    ExitCode::SUCCESS
}

struct SignArgs {
    private_key_hex: String,
    org: String,
    max_nodes: u32,
    expiry: String,
    features: Vec<String>,
    out: Option<String>,
}

fn parse_sign_args(mut args: impl Iterator<Item = String>) -> Result<SignArgs, String> {
    let mut private_key_hex = None;
    let mut org = None;
    let mut max_nodes = None;
    let mut expiry = None;
    let mut features: Vec<String> = vec![];
    let mut out = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--private-key" => private_key_hex = Some(args.next().ok_or("--private-key requires a value")?),
            "--org" => org = Some(args.next().ok_or("--org requires a value")?),
            "--max-nodes" => {
                let raw = args.next().ok_or("--max-nodes requires a value")?;
                max_nodes = Some(raw.parse::<u32>().map_err(|_| format!("--max-nodes value '{raw}' is not a valid non-negative integer"))?);
            }
            "--expiry" => expiry = Some(args.next().ok_or("--expiry requires a value")?),
            "--features" => {
                let raw = args.next().ok_or("--features requires a value")?;
                features = raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect();
            }
            "--out" => out = Some(args.next().ok_or("--out requires a value")?),
            other => return Err(format!("unrecognized argument '{other}'")),
        }
    }

    Ok(SignArgs {
        private_key_hex: private_key_hex.ok_or("--private-key is required")?,
        org: org.ok_or("--org is required")?,
        max_nodes: max_nodes.ok_or("--max-nodes is required")?,
        expiry: expiry.ok_or("--expiry is required")?,
        features,
        out,
    })
}

fn sign(args: impl Iterator<Item = String>) -> ExitCode {
    let parsed = match parse_sign_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("tri_sync_node_license_tool: {e}");
            print_usage();
            return ExitCode::FAILURE;
        }
    };

    let toml_out = match build_signed_license(&parsed) {
        Ok(toml) => toml,
        Err(e) => {
            eprintln!("tri_sync_node_license_tool: {e}");
            return ExitCode::FAILURE;
        }
    };

    match &parsed.out {
        Some(path) => match std::fs::write(path, &toml_out) {
            Ok(()) => {
                println!("tri_sync_node_license_tool: wrote a validly-signed license to {path}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("tri_sync_node_license_tool: failed to write {path}: {e}");
                ExitCode::FAILURE
            }
        },
        None => {
            print!("{toml_out}");
            ExitCode::SUCCESS
        }
    }
}

/// The actual signing logic, separated from `sign`'s CLI/file-I/O
/// concerns so it can be exercised directly by this file's own tests
/// without shelling out to the built binary.
fn build_signed_license(parsed: &SignArgs) -> Result<String, String> {
    let key_bytes = hex::decode(&parsed.private_key_hex)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or("--private-key must be 64 hex characters (32 bytes)")?;
    let signing_key = SigningKey::from_bytes(&key_bytes);

    // Rejects an expiry string this tool's own signature would later
    // fail to verify against anyway (license::parse_and_verify applies
    // the identical check) - catches a typo'd date (e.g. a day that
    // doesn't exist) before issuing a license carrying it, rather than
    // after a customer's node rejects it.
    if license::civil_days_from_iso(&parsed.expiry).is_none() {
        return Err(format!("--expiry '{}' is not a valid YYYY-MM-DD calendar date", parsed.expiry));
    }

    let canon = license::canonical_string(&parsed.org, parsed.max_nodes, &parsed.features, &parsed.expiry);
    let signature = signing_key.sign(canon.as_bytes());
    let toml_out = render_license_toml(&parsed.org, parsed.max_nodes, &parsed.features, &parsed.expiry, &hex::encode(signature.to_bytes()));

    // Self-check before ever emitting the file: verify it the same
    // way a real node would, against the public key this private key
    // actually corresponds to. A license this tool itself can't
    // verify must never be handed to a customer.
    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    if let Err(e) = license::parse_and_verify(&toml_out, &public_key_hex) {
        return Err(format!(
            "internal error - the license this tool just signed does not verify against its own key: {e}. \
             This should never happen; please report it rather than issuing this license."
        ));
    }

    Ok(toml_out)
}

fn render_license_toml(org: &str, max_nodes: u32, features: &[String], expiry: &str, signature_hex: &str) -> String {
    let features_toml = features.iter().map(|f| format!("\"{f}\"")).collect::<Vec<_>>().join(", ");
    format!(
        "org = \"{org}\"\nmax_nodes = {max_nodes}\nfeatures = [{features_toml}]\nexpiry = \"{expiry}\"\nsignature = \"{signature_hex}\"\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> impl Iterator<Item = String> {
        v.iter().map(|s| s.to_string()).collect::<Vec<_>>().into_iter()
    }

    #[test]
    fn parse_sign_args_accepts_every_flag_including_a_multi_value_feature_list() {
        let parsed = parse_sign_args(args(&[
            "--private-key", "ab", "--org", "Acme", "--max-nodes", "7", "--expiry", "2030-01-01", "--features", "a, b ,c", "--out", "/tmp/x.toml",
        ]))
        .unwrap();
        assert_eq!(parsed.private_key_hex, "ab");
        assert_eq!(parsed.org, "Acme");
        assert_eq!(parsed.max_nodes, 7);
        assert_eq!(parsed.expiry, "2030-01-01");
        assert_eq!(parsed.features, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        assert_eq!(parsed.out, Some("/tmp/x.toml".to_string()));
    }

    #[test]
    fn parse_sign_args_defaults_features_to_empty_and_out_to_none() {
        let parsed = parse_sign_args(args(&["--private-key", "ab", "--org", "Acme", "--max-nodes", "1", "--expiry", "2030-01-01"])).unwrap();
        assert_eq!(parsed.features, Vec::<String>::new());
        assert_eq!(parsed.out, None);
    }

    #[test]
    fn parse_sign_args_rejects_each_missing_required_flag() {
        assert!(parse_sign_args(args(&["--org", "Acme", "--max-nodes", "1", "--expiry", "2030-01-01"])).is_err());
        assert!(parse_sign_args(args(&["--private-key", "ab", "--max-nodes", "1", "--expiry", "2030-01-01"])).is_err());
        assert!(parse_sign_args(args(&["--private-key", "ab", "--org", "Acme", "--expiry", "2030-01-01"])).is_err());
        assert!(parse_sign_args(args(&["--private-key", "ab", "--org", "Acme", "--max-nodes", "1"])).is_err());
    }

    #[test]
    fn parse_sign_args_rejects_a_non_numeric_max_nodes() {
        assert!(parse_sign_args(args(&["--private-key", "ab", "--org", "Acme", "--max-nodes", "not-a-number", "--expiry", "2030-01-01"])).is_err());
    }

    #[test]
    fn parse_sign_args_rejects_an_unrecognized_flag() {
        assert!(parse_sign_args(args(&["--private-key", "ab", "--org", "Acme", "--max-nodes", "1", "--expiry", "2030-01-01", "--bogus", "x"])).is_err());
    }

    fn test_key_hex() -> String {
        hex::encode(SigningKey::generate(&mut OsRng).to_bytes())
    }

    /// The actual end-to-end claim: a license this tool signs is one
    /// `license::parse_and_verify` genuinely accepts against the
    /// matching public key - not just "the tool didn't crash".
    #[test]
    fn a_signed_license_actually_verifies_against_its_signing_keys_public_half() {
        let private_key_hex = test_key_hex();
        let signing_key = SigningKey::from_bytes(&<[u8; 32]>::try_from(hex::decode(&private_key_hex).unwrap()).unwrap());
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

        let parsed = SignArgs {
            private_key_hex,
            org: "Acme Corp".to_string(),
            max_nodes: 10,
            expiry: "2031-06-15".to_string(),
            features: vec!["chain_crypto".to_string(), "http_api".to_string()],
            out: None,
        };
        let toml_out = build_signed_license(&parsed).expect("a well-formed request should sign successfully");

        let license = license::parse_and_verify(&toml_out, &public_key_hex).expect("the signed license must verify against its own public key");
        assert_eq!(license.org, "Acme Corp");
        assert_eq!(license.max_nodes, 10);
        assert!(license.has_feature("chain_crypto"));
        assert!(license.has_feature("http_api"));
    }

    /// The same license, signed by a *different* key, must never
    /// verify against this one's public half - proves the tool isn't
    /// accidentally embedding or trusting the wrong key anywhere.
    #[test]
    fn a_license_signed_by_a_different_key_does_not_verify_against_this_ones_public_key() {
        let parsed = SignArgs {
            private_key_hex: test_key_hex(),
            org: "Acme Corp".to_string(),
            max_nodes: 10,
            expiry: "2031-06-15".to_string(),
            features: vec![],
            out: None,
        };
        let toml_out = build_signed_license(&parsed).unwrap();

        let unrelated_public_key_hex = hex::encode(SigningKey::generate(&mut OsRng).verifying_key().to_bytes());
        assert!(license::parse_and_verify(&toml_out, &unrelated_public_key_hex).is_err());
    }

    #[test]
    fn build_signed_license_rejects_a_private_key_of_the_wrong_length() {
        let parsed = SignArgs {
            private_key_hex: "ab".to_string(),
            org: "Acme".to_string(),
            max_nodes: 1,
            expiry: "2030-01-01".to_string(),
            features: vec![],
            out: None,
        };
        assert!(build_signed_license(&parsed).is_err());
    }

    #[test]
    fn build_signed_license_rejects_a_calendar_date_that_does_not_exist() {
        let parsed = SignArgs {
            private_key_hex: test_key_hex(),
            org: "Acme".to_string(),
            max_nodes: 1,
            expiry: "2025-02-30".to_string(), // February never has 30 days
            features: vec![],
            out: None,
        };
        assert!(build_signed_license(&parsed).is_err());
    }

    #[test]
    fn render_license_toml_sorts_nothing_but_preserves_every_field_round_trippably() {
        let toml_out = render_license_toml("Acme", 3, &["b".to_string(), "a".to_string()], "2030-01-01", "deadbeef");
        assert!(toml_out.contains("org = \"Acme\""));
        assert!(toml_out.contains("max_nodes = 3"));
        assert!(toml_out.contains("features = [\"b\", \"a\"]"));
        assert!(toml_out.contains("expiry = \"2030-01-01\""));
        assert!(toml_out.contains("signature = \"deadbeef\""));
    }
}
