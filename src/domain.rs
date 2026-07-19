//! The signed-message contract: domain separators, the byte-exact message builders the app signs
//! and the engine verifies, and the Ed25519 key/signature newtypes.
//!
//! This module is the security core of the IPC contract. Every signature the app's slot-`0x0010`
//! identity key produces MUST carry a unique per-purpose domain-separation tag, so a signature minted
//! for one purpose can never be replayed as a valid signature for another (a cross-protocol signing
//! oracle). The three purposes — session attach, engine `sign` callback, and user-initiated
//! `dign sign` — each own a distinct tag, and no purpose ever signs un-prefixed caller bytes.
//!
//! The builders are PURE and CANONICAL: the app and the engine (and any independent reimplementation)
//! MUST reconstruct these byte strings identically, or a valid signature will fail to verify. The
//! conformance KATs in `tests/` pin the exact hex output of each builder as a change-detector.

/// The number of bytes in an Ed25519 signing public key (`dig-identity` slot `0x0010`).
pub const SIGNING_KEY_LEN: usize = 32;

/// The number of bytes in an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// The number of bytes in a session-attach challenge nonce (a 256-bit random value the engine mints
/// per `begin`). Large enough that two honest `begin`s never collide and an attacker cannot guess a
/// nonce to precompute a signature over.
pub const NONCE_LEN: usize = 32;

/// The domain separator prepended to every session-attach challenge, so a signature minted for the
/// session handshake can never be replayed as a signature over a spend, an SMT write, or any other
/// message the identity key signs. Canonical — the engine builds the identical challenge to verify.
pub const SESSION_CHALLENGE_DOMAIN: &[u8] = b"DIGNET-SESSION-v1";

/// The domain separator for the engine→app `sign` callback. Distinct from
/// [`SESSION_CHALLENGE_DOMAIN`], so a callback signature can NEVER equal an attach-challenge signature
/// — nor any other message the identity key signs — even when the engine chooses the callback payload
/// to be byte-for-byte a valid attach challenge. Canonical: the engine reconstructs the identical byte
/// string to verify.
pub const SIGN_CALLBACK_DOMAIN: &[u8] = b"DIGNET-SIGN-v1";

/// The domain separator for a user-initiated `dign sign` (the local gateway path): a signature the
/// user explicitly requests over their OWN message with the active profile's identity key. A THIRD
/// distinct purpose tag, separate from both [`SESSION_CHALLENGE_DOMAIN`] and [`SIGN_CALLBACK_DOMAIN`],
/// so a `dign sign` signature can NEVER be replayed as a session attach or an engine/dapp
/// spend-callback authorization. Canonical: any verifier reconstructs the identical byte string via
/// [`user_sign_message`].
pub const USER_SIGN_DOMAIN: &[u8] = b"DIGNET-USER-SIGN-v1";

/// An Ed25519 signing public key — `dig-identity` slot `0x0010`. A newtype (not a bare `[u8; 32]`) so
/// the contract has no `dig-*` dependency yet callers cannot accidentally pass an encryption key or a
/// nonce where a signing key is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigningPublicKey([u8; SIGNING_KEY_LEN]);

impl SigningPublicKey {
    /// Wrap raw public-key bytes.
    pub const fn new(bytes: [u8; SIGNING_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw public-key bytes.
    pub const fn as_bytes(&self) -> &[u8; SIGNING_KEY_LEN] {
        &self.0
    }

    /// The lowercase-hex encoding — the form carried on the wire (`signing_pubkey_hex`, `pubkey_hex`).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a lowercase-hex public key (the inverse of [`to_hex`](Self::to_hex)). Returns `None` when
    /// the input is not exactly [`SIGNING_KEY_LEN`] hex-decoded bytes.
    pub fn from_hex(hex_str: &str) -> Option<Self> {
        let bytes = hex::decode(hex_str).ok()?;
        Some(Self(bytes.try_into().ok()?))
    }
}

/// An Ed25519 signature over a domain-separated message. A newtype for the same reason as
/// [`SigningPublicKey`]: the boundary types carry meaning, not bare byte arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Wrap raw signature bytes.
    pub const fn new(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw signature bytes.
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

/// Builds the exact bytes the identity key signs to attach a session: the domain separator, then the
/// engine's nonce, then the profile DID. Pure and canonical — the engine reconstructs the identical
/// message to verify, so app and engine MUST agree on this construction byte-for-byte.
pub fn challenge_message(nonce: &[u8], profile_did: &str) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(SESSION_CHALLENGE_DOMAIN.len() + nonce.len() + profile_did.len());
    message.extend_from_slice(SESSION_CHALLENGE_DOMAIN);
    message.extend_from_slice(nonce);
    message.extend_from_slice(profile_did.as_bytes());
    message
}

/// Builds the exact bytes the identity key signs for an engine `sign` callback:
///
/// ```text
/// SIGN_CALLBACK_DOMAIN ‖ len16(payload_type) ‖ payload_type ‖ payload
/// ```
///
/// where `len16` is the big-endian `u16` byte length of `payload_type`. The length prefix makes the
/// `payload_type ‖ payload` boundary unambiguous, so `(type="a", payload="bc")` cannot collide with
/// `(type="ab", payload="c")`. The [`SIGN_CALLBACK_DOMAIN`] tag — distinct from
/// [`SESSION_CHALLENGE_DOMAIN`] — guarantees a callback signature can never equal an attach-challenge
/// signature (or any other identity-key signature), closing the cross-protocol signing oracle a
/// malicious engine would otherwise exploit by submitting a crafted `payload`.
///
/// Pure and canonical. `payload_type` is bounded to [`u16::MAX`] bytes (labels are short); a longer
/// label returns `None` — a protocol error the caller rejects before signing.
pub fn sign_callback_message(payload_type: &str, payload: &[u8]) -> Option<Vec<u8>> {
    let type_len = u16::try_from(payload_type.len()).ok()?;
    let mut message =
        Vec::with_capacity(SIGN_CALLBACK_DOMAIN.len() + 2 + payload_type.len() + payload.len());
    message.extend_from_slice(SIGN_CALLBACK_DOMAIN);
    message.extend_from_slice(&type_len.to_be_bytes());
    message.extend_from_slice(payload_type.as_bytes());
    message.extend_from_slice(payload);
    Some(message)
}

/// Builds the exact bytes the identity key signs for a user-initiated `dign sign`:
///
/// ```text
/// USER_SIGN_DOMAIN ‖ message
/// ```
///
/// `message` is the single trailing field, so — unlike [`sign_callback_message`], which joins two
/// variable fields and therefore length-prefixes the first — no length prefix is needed: the
/// [`USER_SIGN_DOMAIN`] tag is a fixed-length constant and everything after it is the message, an
/// unambiguous parse. The tag closes the cross-protocol signing oracle: because it differs from every
/// other `0x0010` purpose tag at a fixed leading position, no crafted `message` can make this output
/// equal a session-attach challenge ([`challenge_message`]) or an engine/dapp callback message
/// ([`sign_callback_message`]).
///
/// Pure and canonical — all producers and verifiers MUST agree on this construction byte-for-byte.
pub fn user_sign_message(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(USER_SIGN_DOMAIN.len() + message.len());
    out.extend_from_slice(USER_SIGN_DOMAIN);
    out.extend_from_slice(message);
    out
}

/// Verify an Ed25519 `signature` over `message` against a `signing_public_key` (slot `0x0010`). The
/// engine half of the contract: the app signs a domain-separated message in-process (its private key
/// never crossing the IPC boundary), and the engine calls this to confirm the signature binds the
/// session — or the callback — to exactly the attaching key.
///
/// Uses `verify_strict` (rejects the malleable / small-order edge cases), so a signature that a
/// permissive verifier might accept for the wrong key is rejected here.
pub fn verify_signature(
    signing_public_key: &SigningPublicKey,
    message: &[u8],
    signature: &Signature,
) -> bool {
    let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(signing_public_key.as_bytes())
    else {
        return false;
    };
    verifying_key
        .verify_strict(
            message,
            &ed25519_dalek::Signature::from_bytes(signature.as_bytes()),
        )
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:chia:testprofile";

    fn nonce() -> [u8; NONCE_LEN] {
        use sha2::{Digest, Sha256};
        Sha256::digest(b"domain test nonce fixture").into()
    }

    #[test]
    fn challenge_is_domain_separated_and_deterministic() {
        let m = challenge_message(&nonce(), DID);
        assert!(m.starts_with(SESSION_CHALLENGE_DOMAIN));
        assert_eq!(m, challenge_message(&nonce(), DID));
        assert_ne!(m, challenge_message(b"other-nonce", DID));
        assert_ne!(m, challenge_message(&nonce(), "did:chia:someoneelse"));
    }

    #[test]
    fn sign_callback_message_disambiguates_the_type_payload_boundary() {
        let a = sign_callback_message("a", b"bc").unwrap();
        let b = sign_callback_message("ab", b"c").unwrap();
        assert_ne!(a, b);
        assert!(a.starts_with(SIGN_CALLBACK_DOMAIN));
        assert!(!a.starts_with(SESSION_CHALLENGE_DOMAIN));
    }

    #[test]
    fn sign_callback_message_rejects_an_overlong_type() {
        let huge = "x".repeat(usize::from(u16::MAX) + 1);
        assert!(sign_callback_message(&huge, b"p").is_none());
    }

    #[test]
    fn user_sign_message_is_domain_separated_and_pairwise_distinct() {
        let m = user_sign_message(b"attest this");
        assert!(m.starts_with(USER_SIGN_DOMAIN));
        assert!(!m.starts_with(SESSION_CHALLENGE_DOMAIN));
        assert!(!m.starts_with(SIGN_CALLBACK_DOMAIN));
        assert_eq!(&m[USER_SIGN_DOMAIN.len()..], b"attest this");
        assert_ne!(USER_SIGN_DOMAIN, SESSION_CHALLENGE_DOMAIN);
        assert_ne!(USER_SIGN_DOMAIN, SIGN_CALLBACK_DOMAIN);
    }

    #[test]
    fn public_key_hex_round_trips() {
        let key = SigningPublicKey::new([7u8; SIGNING_KEY_LEN]);
        assert_eq!(SigningPublicKey::from_hex(&key.to_hex()), Some(key));
        assert!(SigningPublicKey::from_hex("zz").is_none());
        assert!(SigningPublicKey::from_hex(&"aa".repeat(31)).is_none());
    }

    #[test]
    fn verify_rejects_a_bad_key_or_signature() {
        // An all-zero "signature" cannot verify for a random-looking key; the point is the function
        // fails closed on garbage rather than panicking.
        let key = SigningPublicKey::new([1u8; SIGNING_KEY_LEN]);
        assert!(!verify_signature(
            &key,
            b"msg",
            &Signature::new([0u8; SIGNATURE_LEN])
        ));
    }
}
