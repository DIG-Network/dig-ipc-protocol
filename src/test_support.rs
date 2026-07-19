//! Deterministic test doubles shared by the module unit tests. Compiled only under `cfg(test)`.

use std::collections::VecDeque;

use ed25519_dalek::{Signer as _, SigningKey};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use crate::domain::{Signature, SigningPublicKey, NONCE_LEN};
use crate::signer::{DidSigningKeyResolver, SessionSigner};
use crate::transport::{FrameTransport, SessionEntropy};

/// A deterministic Ed25519 [`SessionSigner`] seeded from a `u64`, so tests pin an identity without a
/// hard-coded key. Also usable as the DID resolver target.
pub struct TestSigner {
    key: SigningKey,
}

impl TestSigner {
    /// A signer with keys derived deterministically from `seed` (via ChaCha20, not a hard-coded key).
    pub fn seeded(seed: u64) -> Self {
        let mut secret = [0u8; 32];
        ChaCha20Rng::seed_from_u64(seed).fill_bytes(&mut secret);
        Self {
            key: SigningKey::from_bytes(&secret),
        }
    }

    /// The public key as the contract newtype.
    pub fn public(&self) -> SigningPublicKey {
        SigningPublicKey::new(self.key.verifying_key().to_bytes())
    }
}

impl SessionSigner for TestSigner {
    fn signing_public_key(&self) -> SigningPublicKey {
        self.public()
    }

    fn sign(&self, message: &[u8]) -> Signature {
        Signature::new(self.key.sign(message).to_bytes())
    }
}

/// A [`SessionSigner`] that models a lockable, profile-backed identity: when unlocked it signs like a
/// [`TestSigner`]; when locked, [`try_sign`](SessionSigner::try_sign) returns `None` and the infallible
/// [`sign`](SessionSigner::sign) returns the all-zero **fail-safe** signature (mirroring the production
/// `ProfileSessionSigner`). Lets a test prove callers fail closed on a locked profile rather than
/// framing the bogus all-zero signature.
pub struct LockableSigner {
    inner: TestSigner,
    locked: bool,
}

impl LockableSigner {
    /// A lockable signer seeded like [`TestSigner::seeded`], initially in the given `locked` state.
    pub fn seeded(seed: u64, locked: bool) -> Self {
        Self {
            inner: TestSigner::seeded(seed),
            locked,
        }
    }
}

impl SessionSigner for LockableSigner {
    fn signing_public_key(&self) -> SigningPublicKey {
        self.inner.public()
    }

    fn sign(&self, message: &[u8]) -> Signature {
        // The fail-safe: a locked profile has no key, so the infallible path returns the all-zero
        // (non-verifying) signature. A fail-closed caller must use `try_sign` and never frame this.
        match self.try_sign(message) {
            Some(signature) => signature,
            None => Signature::new([0u8; crate::domain::SIGNATURE_LEN]),
        }
    }

    fn try_sign(&self, message: &[u8]) -> Option<Signature> {
        if self.locked {
            None
        } else {
            Some(self.inner.sign(message))
        }
    }
}

/// A resolver that maps a single known DID to a fixed key (the engine's DID→key backstop under test).
pub struct StubResolver {
    pub did: String,
    pub key: SigningPublicKey,
}

impl DidSigningKeyResolver for StubResolver {
    fn resolve_signing_key(&self, profile_did: &str) -> Option<SigningPublicKey> {
        (profile_did == self.did).then_some(self.key)
    }
}

/// A [`SessionEntropy`] that yields a fixed, derived sequence of nonces so a handshake is fully
/// reproducible. Each call returns SHA-256(seed ‖ counter) — never a hard-coded literal (CodeQL).
pub struct SeqEntropy {
    counter: std::cell::Cell<u64>,
    seed: &'static [u8],
}

impl SeqEntropy {
    /// A sequence keyed by `seed`.
    pub fn new(seed: &'static [u8]) -> Self {
        Self {
            counter: std::cell::Cell::new(0),
            seed,
        }
    }
}

impl SessionEntropy for SeqEntropy {
    fn fill_nonce(&self) -> [u8; NONCE_LEN] {
        let n = self.counter.get();
        self.counter.set(n + 1);
        let mut hasher = Sha256::new();
        hasher.update(self.seed);
        hasher.update(n.to_be_bytes());
        hasher.finalize().into()
    }
}

/// A scripted in-memory [`FrameTransport`]: `incoming` frames are what the peer "sends" (popped in
/// order); `outgoing` records every frame this side sent, so tests can assert on the wire bytes.
#[derive(Default)]
pub struct FakeTransport {
    pub incoming: VecDeque<String>,
    pub outgoing: Vec<String>,
}

impl FakeTransport {
    /// A transport scripted with the peer's frames, in order.
    pub fn scripted(frames: impl IntoIterator<Item = String>) -> Self {
        Self {
            incoming: frames.into_iter().collect(),
            outgoing: Vec::new(),
        }
    }
}

impl FrameTransport for FakeTransport {
    fn send_frame(&mut self, frame: &str) -> std::io::Result<()> {
        self.outgoing.push(frame.to_string());
        Ok(())
    }

    fn recv_frame(&mut self) -> std::io::Result<String> {
        self.incoming
            .pop_front()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
    }
}
