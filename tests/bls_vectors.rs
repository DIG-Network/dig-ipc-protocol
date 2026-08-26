//! Cross-VERSION AugScheme KATs for the signature half of the IPC contract.
//!
//! `tests/conformance.rs` pins the bytes each domain-separated builder PRODUCES. It does not pin what
//! happens after those bytes are signed — every signature there is only length-checked — so a change in
//! the underlying BLS implementation would leave that suite fully green while every signature the app
//! mints stops verifying on the engine. These vectors close that gap.
//!
//! **Provenance, and why these numbers are not circular.** They were measured against `chia-bls 0.26`
//! (the line this crate carried before the ecosystem chia-line convergence, dig_ecosystem#3161) and are
//! asserted here against `0.36.1`. They therefore prove the two lines agree byte-for-byte, which is the
//! only property that matters when one side of the IPC channel upgrades before the other.
//!
//! A moved vector means the CRYPTO changed. Never adjust one to match altered code — stop and report.

use chia_bls::SecretKey;
use dig_ipc_protocol::{
    challenge_message, sign_callback_message, user_sign_message, verify_signature, Signature,
    SigningPublicKey,
};
use sha2::{Digest, Sha256};

/// The KAT signing key, DERIVED rather than a hard-coded literal (CodeQL) but fully deterministic.
fn signing_key() -> SecretKey {
    let seed: [u8; 32] = Sha256::digest(b"dig-ipc-protocol bls vector key v1").into();
    SecretKey::from_seed(&seed)
}

/// The KAT nonce, matching `tests/conformance.rs`'s derivation.
fn nonce() -> [u8; 32] {
    Sha256::digest(b"dig-ipc-protocol conformance nonce vector v1").into()
}

const DID: &str = "did:chia:conformance";

/// G1 public key of `signing_key()`, 48 bytes.
const PUBKEY_HEX: &str = "80d950bbdd153fe665fb11d29696b0ed44501bd2d77c83ac342a68d97f81f7a1efd7a9123e3c5ef5cc48f3edfcce864b";
/// AugScheme signature over `challenge_message(nonce, DID)`.
const CHALLENGE_SIG_HEX: &str = "9563571105f7de288e0c5878434250dc30625fe5eba0c581483beafb46986dec97d99a0a71920dc5588894834cc5e20716701cc3c4764cbad06f11ef3dab62e7dfb909caab95f0ff1f519584f5790d0439cc95d77a798afd4c92f68b32536c88";
/// AugScheme signature over `sign_callback_message("spend", b"bundle-bytes")`.
const CALLBACK_SIG_HEX: &str = "91aecb0e6823b8ff48d6d19d79e09d7e20fae3ef221f8846bbace5dfbbc8a54d31f507c2de89193937697a523297209e08e60490b505a305cd931bc55f046e1550b80529defeaa643b7386609fb12e075cae5d168930a3ecdf4d559532db97e1";
/// AugScheme signature over `user_sign_message(b"attest this")`.
const USER_SIG_HEX: &str = "858c6ff11517cefa07478a8c8aba0429d5b5762f8113bf4949b0a20100578a7da9f10111df29eafcdb970cd90f058f7f0052810b71cea52274e68a5775edffdb4b970ab1e330e88c3f75b830d489278d8c400031cd25ce2bb6c11f51cd95699b";

/// The derived key must itself be stable — otherwise the three signature vectors below would be
/// pinning a different key than the one their comments name, and could not detect a keygen change.
#[test]
fn the_kat_public_key_is_stable_across_chia_bls_lines() {
    assert_eq!(
        hex::encode(signing_key().public_key().to_bytes()),
        PUBKEY_HEX
    );
}

/// Each builder's message, signed under AugScheme, reproduces the vector measured on the prior line —
/// and this crate's own `verify_signature` accepts it.
#[test]
fn augscheme_signatures_over_each_builder_match_the_golden_vectors() {
    let sk = signing_key();
    let pk = SigningPublicKey::new(sk.public_key().to_bytes());

    let cases: [(Vec<u8>, &str); 3] = [
        (challenge_message(&nonce(), DID), CHALLENGE_SIG_HEX),
        (
            sign_callback_message("spend", b"bundle-bytes").expect("payload type fits u16"),
            CALLBACK_SIG_HEX,
        ),
        (user_sign_message(b"attest this"), USER_SIG_HEX),
    ];

    for (message, expected_hex) in cases {
        let signature = chia_bls::sign(&sk, &message);
        assert_eq!(hex::encode(signature.to_bytes()), expected_hex);
        assert!(verify_signature(
            &pk,
            &message,
            &Signature::new(signature.to_bytes())
        ));
    }
}

/// The vectors are only meaningful if `verify_signature` can actually say no: a signature minted over
/// one builder's message must not verify against another's, or every vector above would pass under a
/// verifier that ignores its message argument.
#[test]
fn a_signature_does_not_verify_against_a_different_builders_message() {
    let sk = signing_key();
    let pk = SigningPublicKey::new(sk.public_key().to_bytes());
    let challenge = challenge_message(&nonce(), DID);
    let user = user_sign_message(b"attest this");

    let over_challenge = Signature::new(chia_bls::sign(&sk, &challenge).to_bytes());
    assert!(verify_signature(&pk, &challenge, &over_challenge));
    assert!(!verify_signature(&pk, &user, &over_challenge));
}
