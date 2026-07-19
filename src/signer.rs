//! The signing seams: the app's identity signer, the custody sign-policy gate, and the engine's
//! DID→pubkey resolver. Each is a narrow trait so the private key stays owned by the app's keystore
//! and the engine's DID resolution stays owned by the engine — this crate names the capability, the
//! consumer implements it.

use crate::domain::{Signature, SigningPublicKey};

/// The signing capability the app-side session client needs from the unlocked identity, WITHOUT
/// holding the raw key. The production implementation borrows the U4/U5 in-memory identity; tests
/// inject a fake. Keeping this a narrow seam is what enforces the custody boundary: the role-half can
/// sign and name the public key, but can never read, copy, or transmit the private key.
pub trait SessionSigner {
    /// The Ed25519 signing public key (`dig-identity` slot `0x0010`).
    fn signing_public_key(&self) -> SigningPublicKey;

    /// Sign `message` with the in-memory identity key, returning only the detached signature.
    fn sign(&self, message: &[u8]) -> Signature;

    /// Sign `message`, or return `None` when the identity is currently unavailable (e.g. the active
    /// profile is locked). A caller that must NOT frame a bogus/all-zero signature into a success
    /// response uses this instead of [`sign`](Self::sign) and maps `None` to a `LOCKED` error.
    ///
    /// The default assumes an always-available signer; a profile-backed signer overrides it to return
    /// `None` on a locked profile.
    fn try_sign(&self, message: &[u8]) -> Option<Signature> {
        Some(self.sign(message))
    }

    /// The signing public key as lowercase hex — the form carried on the wire (`signing_pubkey_hex`,
    /// `pubkey_hex`).
    fn signing_public_key_hex(&self) -> String {
        self.signing_public_key().to_hex()
    }
}

/// The engine's resolver from a profile DID to its published slot-`0x0010` signing key. The engine
/// uses it during `attach` to backstop that the key advertised in `begin` really is the DID's
/// published identity key, so an app cannot attach one DID while proving possession of an unrelated
/// key. A seam because DID resolution (on-chain / cached) is the engine's concern, not the contract's.
pub trait DidSigningKeyResolver {
    /// The published slot-`0x0010` signing key for `profile_did`, or `None` when the DID is unknown or
    /// its identity is unresolvable.
    fn resolve_signing_key(&self, profile_did: &str) -> Option<SigningPublicKey>;
}

/// A decoded engine `sign` callback presented to a [`SignPolicy`] for authorization. Borrows the
/// request so a policy can inspect it without the payload being copied out of the channel.
pub struct SignRequest<'a> {
    /// The session the engine is signing on behalf of.
    pub session_id: &'a str,
    /// The engine-assigned operation id, for correlation and audit.
    pub op_id: &'a str,
    /// The engine's label for what kind of payload this is (a spend bundle, an SMT write, …).
    pub payload_type: &'a str,
    /// The raw bytes the engine wants signed (already base64-decoded).
    pub payload: &'a [u8],
    /// Optional engine-supplied context (human-readable description, amounts, recipient) a policy or a
    /// confirmation prompt can surface.
    pub context: Option<&'a serde_json::Value>,
}

/// A [`SignPolicy`]'s ruling on one engine `sign` callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignDecision {
    /// Sign the payload and return the signature to the engine.
    Allow,
    /// Refuse; the reason is returned to the engine as a JSON-RPC error (never signed).
    Deny(String),
}

/// The custody gate for engine-initiated signing. The engine chooses the callback payload, so a
/// blanket "sign anything the engine asks" would let a compromised engine mint arbitrary signatures
/// with the user's key. Every session client MUST supply a policy; there is deliberately no
/// default-allow. Production policies range from user-confirmation prompts to a `payload_type`
/// allowlist; tests use [`AllowAllSignPolicy`] / [`DenyAllSignPolicy`].
pub trait SignPolicy {
    /// Rule on whether the in-memory identity key may sign `request`.
    fn authorize(&self, request: &SignRequest<'_>) -> SignDecision;
}

/// A trivially-permissive [`SignPolicy`] for tests and non-signing contexts. Production code MUST use
/// a real policy (confirmation / allowlist) — signing whatever the engine asks defeats the custody
/// gate.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllSignPolicy;

impl SignPolicy for AllowAllSignPolicy {
    fn authorize(&self, _request: &SignRequest<'_>) -> SignDecision {
        SignDecision::Allow
    }
}

/// A [`SignPolicy`] that refuses every engine `sign` callback — the safe default and a test double.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllSignPolicy;

impl SignPolicy for DenyAllSignPolicy {
    fn authorize(&self, _request: &SignRequest<'_>) -> SignDecision {
        SignDecision::Deny("signing is disabled by policy".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> SignRequest<'static> {
        SignRequest {
            session_id: "s",
            op_id: "o",
            payload_type: "spend",
            payload: b"bytes",
            context: None,
        }
    }

    #[test]
    fn allow_all_allows_and_deny_all_denies() {
        assert_eq!(
            AllowAllSignPolicy.authorize(&request()),
            SignDecision::Allow
        );
        assert!(matches!(
            DenyAllSignPolicy.authorize(&request()),
            SignDecision::Deny(_)
        ));
    }
}
