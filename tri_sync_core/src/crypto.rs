//! Ed25519 signing and epoch-based key rotation - extracted verbatim
//! (verified against the source) from `tri_sync_chain_crypto`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::Rng;

/// Regenerates the node key registry for `epoch`, replacing
/// `signing`/`verify` in place.
pub fn regen_keys(
    rng: &mut (impl Rng + rand::CryptoRng),
    epoch: u64,
    n: usize,
    signing: &mut Vec<SigningKey>,
    verify: &mut Vec<VerifyingKey>,
) {
    signing.clear();
    verify.clear();
    // consume RNG proportional to epoch (sim-only determinism hint)
    for _ in 0..(epoch as usize * 3).min(30) { let _: u64 = rng.gen(); }
    for _i in 0..n {
        let sk = SigningKey::generate(rng);
        let vk = sk.verifying_key();
        signing.push(sk);
        verify.push(vk);
    }
}

/// Signs `canon` (a canonical block string from `chain::canon_string`)
/// with `sk`.
pub fn sign_canon(sk: &SigningKey, canon: &str) -> Signature {
    sk.sign(canon.as_bytes())
}

/// Verifies `sig` over `canon` against `vk`. Returns `false` on any
/// failure (wrong key, tampered canon string, malformed signature) -
/// never panics on untrusted input.
pub fn verify_canon(vk: &VerifyingKey, canon: &str, sig: &Signature) -> bool {
    vk.verify(canon.as_bytes(), sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn regen_keys_is_deterministic_given_the_same_seed_and_epoch() {
        let mut rng_a = StdRng::seed_from_u64(42);
        let mut rng_b = StdRng::seed_from_u64(42);
        let (mut sa, mut va) = (vec![], vec![]);
        let (mut sb, mut vb) = (vec![], vec![]);
        regen_keys(&mut rng_a, 0, 5, &mut sa, &mut va);
        regen_keys(&mut rng_b, 0, 5, &mut sb, &mut vb);
        for (a, b) in va.iter().zip(vb.iter()) {
            assert_eq!(a.to_bytes(), b.to_bytes());
        }
    }

    #[test]
    fn different_epochs_produce_different_keys() {
        let mut rng = StdRng::seed_from_u64(42);
        let (mut signing, mut verify) = (vec![], vec![]);
        regen_keys(&mut rng, 0, 3, &mut signing, &mut verify);
        let epoch0 = verify.clone();
        regen_keys(&mut rng, 1, 3, &mut signing, &mut verify);
        assert_ne!(epoch0[0].to_bytes(), verify[0].to_bytes());
    }

    #[test]
    fn a_signature_verifies_against_the_signing_keys_own_verifying_key() {
        let mut rng = StdRng::seed_from_u64(1);
        let (mut signing, mut verify) = (vec![], vec![]);
        regen_keys(&mut rng, 0, 1, &mut signing, &mut verify);
        let canon = "5|GENESIS|abcd|1.00000000|efgh|0";
        let sig = sign_canon(&signing[0], canon);
        assert!(verify_canon(&verify[0], canon, &sig));
    }

    #[test]
    fn a_tampered_canon_string_fails_verification() {
        let mut rng = StdRng::seed_from_u64(1);
        let (mut signing, mut verify) = (vec![], vec![]);
        regen_keys(&mut rng, 0, 1, &mut signing, &mut verify);
        let sig = sign_canon(&signing[0], "original canon string");
        assert!(!verify_canon(&verify[0], "tampered canon string", &sig));
    }

    #[test]
    fn a_signature_from_a_different_epochs_key_fails_verification() {
        let mut rng = StdRng::seed_from_u64(1);
        let (mut signing, mut verify) = (vec![], vec![]);
        regen_keys(&mut rng, 0, 1, &mut signing, &mut verify);
        let epoch0_verify = verify[0];
        let canon = "canon string";
        let sig = sign_canon(&signing[0], canon);

        regen_keys(&mut rng, 1, 1, &mut signing, &mut verify);
        assert!(!verify_canon(&verify[0], canon, &sig), "epoch 1 key shouldn't verify an epoch 0 signature");
        assert!(verify_canon(&epoch0_verify, canon, &sig), "the original epoch 0 key still should");
    }
}
