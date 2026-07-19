//! Conformance KATs: golden hex vectors that pin the byte-exact output of every domain-separated
//! message builder, plus the cross-protocol-oracle negatives. An independent reimplementation (or a
//! refactor of this one) MUST reproduce these vectors byte-for-byte, or a signature minted by one side
//! will fail to verify on the other. A change here is a BREAKING protocol change — never adjust a
//! vector to match altered code; the vector is the contract.

use dig_ipc_protocol::{
    challenge_message, sign_callback_message, user_sign_message, verify_signature, Signature,
    SigningPublicKey, SESSION_CHALLENGE_DOMAIN, SIGNATURE_LEN, SIGN_CALLBACK_DOMAIN,
    USER_SIGN_DOMAIN,
};
use ed25519_dalek::{Signer as _, SigningKey};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

/// A fixed but DERIVED test DID + nonce, so no cryptographic value is a hard-coded literal (CodeQL).
const DID: &str = "did:chia:conformance";

fn nonce() -> [u8; 32] {
    Sha256::digest(b"dig-ipc-protocol conformance nonce vector v1").into()
}

/// The domain tags, pinned as hex so the vectors below are reproducible from this file alone. These
/// ARE the wire contract — a change here is a breaking protocol change.
const SESSION_DOMAIN_HEX: &str = "4449474e45542d53455353494f4e2d7631";
const SIGN_DOMAIN_HEX: &str = "4449474e45542d5349474e2d7631";
const USER_DOMAIN_HEX: &str = "4449474e45542d555345522d5349474e2d7631";
/// SHA-256("dig-ipc-protocol conformance nonce vector v1"), the derived KAT nonce.
const NONCE_HEX: &str = "5de26a7911315eb9c036bea7fb8bc14d31a7f6e32857adf411ece95171f98736";

#[test]
fn domain_tags_match_the_golden_hex() {
    assert_eq!(hex::encode(SESSION_CHALLENGE_DOMAIN), SESSION_DOMAIN_HEX);
    assert_eq!(hex::encode(SIGN_CALLBACK_DOMAIN), SIGN_DOMAIN_HEX);
    assert_eq!(hex::encode(USER_SIGN_DOMAIN), USER_DOMAIN_HEX);
    assert_eq!(hex::encode(nonce()), NONCE_HEX);
}

#[test]
fn challenge_message_golden_vector() {
    // DIGNET-SESSION-v1 ‖ nonce(32) ‖ "did:chia:conformance"
    let m = challenge_message(&nonce(), DID);
    assert_eq!(
        hex::encode(&m),
        "4449474e45542d53455353494f4e2d7631\
5de26a7911315eb9c036bea7fb8bc14d31a7f6e32857adf411ece95171f98736\
6469643a636869613a636f6e666f726d616e6365"
    );
}

#[test]
fn sign_callback_message_golden_vector() {
    // DIGNET-SIGN-v1 ‖ len16("spend")=0x0005 ‖ "spend" ‖ "bundle-bytes"
    let m = sign_callback_message("spend", b"bundle-bytes").unwrap();
    assert_eq!(
        hex::encode(&m),
        "4449474e45542d5349474e2d763100057370656e6462756e646c652d6279746573"
    );
}

#[test]
fn user_sign_message_golden_vector() {
    // DIGNET-USER-SIGN-v1 ‖ "attest this"
    let m = user_sign_message(b"attest this");
    assert_eq!(
        hex::encode(&m),
        "4449474e45542d555345522d5349474e2d76316174746573742074686973"
    );
}

// --- Cross-protocol-oracle negatives (the 3 the crate MUST defeat) ---------------------------------

fn app_signer() -> SigningKey {
    let mut secret = [0u8; 32];
    ChaCha20Rng::seed_from_u64(20260718).fill_bytes(&mut secret);
    SigningKey::from_bytes(&secret)
}

fn pubkey(key: &SigningKey) -> SigningPublicKey {
    SigningPublicKey::new(key.verifying_key().to_bytes())
}

fn sign(key: &SigningKey, message: &[u8]) -> Signature {
    Signature::new(key.sign(message).to_bytes())
}

#[test]
fn oracle_negative_a_callback_signature_is_not_an_attach_signature() {
    // A malicious engine crafts a callback whose payload is BYTE-FOR-BYTE a valid attach challenge,
    // hoping the returned signature attaches a session. Domain separation must defeat it.
    let key = app_signer();
    let forged = challenge_message(&nonce(), DID);
    let sig = sign(&key, &sign_callback_message("spend", &forged).unwrap());
    assert!(
        !verify_signature(&pubkey(&key), &forged, &sig),
        "a callback signature verified as an attach challenge — oracle open"
    );
}

#[test]
fn oracle_negative_a_user_sign_is_not_an_attach_or_callback_signature() {
    let key = app_signer();
    let forged_attach = challenge_message(&nonce(), DID);
    let sig_a = sign(&key, &user_sign_message(&forged_attach));
    assert!(!verify_signature(&pubkey(&key), &forged_attach, &sig_a));

    let forged_cb = sign_callback_message("spend", b"bundle").unwrap();
    let sig_c = sign(&key, &user_sign_message(&forged_cb));
    assert!(!verify_signature(&pubkey(&key), &forged_cb, &sig_c));
}

#[test]
fn oracle_negative_a_callback_message_never_starts_with_the_session_domain() {
    // The structural invariant behind the oracle defeat: the three purpose messages carry disjoint
    // leading tags, so no crafted input to one can produce a byte string parsing as another.
    let cb = sign_callback_message("t", b"p").unwrap();
    let us = user_sign_message(b"m");
    assert!(!cb.starts_with(SESSION_CHALLENGE_DOMAIN));
    assert!(!us.starts_with(SESSION_CHALLENGE_DOMAIN));
    assert!(!us.starts_with(SIGN_CALLBACK_DOMAIN));
    let attach = challenge_message(&nonce(), DID);
    assert!(!attach.starts_with(SIGN_CALLBACK_DOMAIN));
    assert!(!attach.starts_with(USER_SIGN_DOMAIN));
}

#[test]
fn signature_length_is_the_contract_constant() {
    let key = app_signer();
    let sig = sign(&key, b"anything");
    assert_eq!(sig.as_bytes().len(), SIGNATURE_LEN);
}
