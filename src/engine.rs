//! The engine role-half: [`EngineSessionRegistry`] mints per-handshake challenges, verifies the app's
//! attach signature against the DID's published identity key, and tracks open sessions. The engine
//! holds NO user key — it only verifies — so this half never signs anything.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use crate::bounds::{ENGINE_CAPABILITIES, MAX_PENDING_CANDIDATES};
use crate::domain::{
    challenge_message, verify_signature, Signature, SigningPublicKey, SIGNATURE_LEN,
};
use crate::signer::DidSigningKeyResolver;
use crate::transport::SessionEntropy;
use crate::wire::{
    AttachParams, AttachResult, BeginParams, BeginResult, ProfileAttachment, RpcError,
    SignErrorCode,
};

/// Why the engine refused a `control.session.attach`. Each maps to a stable [`SignErrorCode`] the app
/// keys its UX off, via [`to_rpc_error`](AttachError::to_rpc_error).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttachError {
    /// The `session_candidate` is not outstanding — never issued, already consumed (a replay), or
    /// evicted. Maps to `AUTH_REQUIRED`: the app must `begin` again.
    #[error("no outstanding session candidate for this attach")]
    UnknownCandidate,

    /// The attaching DID has no resolvable published signing key. Maps to `AUTH_REQUIRED`.
    #[error("the attaching DID has no resolvable signing key")]
    UnknownDid,

    /// The key the app advertised in `begin` is not the DID's published slot-`0x0010` key — the app
    /// tried to attach one DID while proving possession of an unrelated key. Maps to `BAD_MAC`.
    #[error("advertised key does not match the DID's published identity key")]
    KeyMismatch,

    /// The challenge signature did not verify against the attaching key. Maps to `BAD_MAC`.
    #[error("the attach challenge signature did not verify")]
    BadSignature,

    /// A field was malformed (bad base64/hex, wrong signature length). Maps to `AUTH_REQUIRED`.
    #[error("malformed attach request: {0}")]
    Malformed(String),
}

impl AttachError {
    /// The stable [`SignErrorCode`] this failure surfaces to the app.
    pub const fn error_code(&self) -> SignErrorCode {
        match self {
            Self::UnknownCandidate | Self::UnknownDid | Self::Malformed(_) => {
                SignErrorCode::AuthRequired
            }
            Self::KeyMismatch | Self::BadSignature => SignErrorCode::BadMac,
        }
    }

    /// The JSON-RPC error the engine returns to the app for this failure.
    pub fn to_rpc_error(&self) -> RpcError {
        self.error_code().to_rpc_error()
    }
}

/// One outstanding handshake between `begin` and `attach`: the nonce the app must sign and the key it
/// advertised, held until the matching `attach` arrives (or the candidate is evicted).
#[derive(Debug, Clone)]
struct PendingCandidate {
    nonce: [u8; crate::domain::NONCE_LEN],
    advertised_key: SigningPublicKey,
    profile_did: String,
}

/// The engine's session state: outstanding handshake candidates and open sessions. Generic over the
/// [`SessionEntropy`] (nonce + id source) and the [`DidSigningKeyResolver`] (the DID→key backstop) so
/// the contract stays testable and the engine supplies the real implementations.
pub struct EngineSessionRegistry<E: SessionEntropy, R: DidSigningKeyResolver> {
    entropy: E,
    resolver: R,
    /// Outstanding handshakes keyed by candidate token. Insertion order is tracked in `candidate_order`
    /// so the oldest is evicted once [`MAX_PENDING_CANDIDATES`] is exceeded.
    pending: HashMap<String, PendingCandidate>,
    candidate_order: std::collections::VecDeque<String>,
    /// Open sessions keyed by session id.
    sessions: HashMap<String, ProfileAttachment>,
}

impl<E: SessionEntropy, R: DidSigningKeyResolver> EngineSessionRegistry<E, R> {
    /// Build a registry with the engine's `entropy` (nonce/id source) and DID `resolver`.
    pub fn new(entropy: E, resolver: R) -> Self {
        Self {
            entropy,
            resolver,
            pending: HashMap::new(),
            candidate_order: std::collections::VecDeque::new(),
            sessions: HashMap::new(),
        }
    }

    /// Handle `control.session.begin`: mint a fresh nonce + opaque candidate, remember the pending
    /// handshake, and return the challenge for the app to sign.
    ///
    /// # Errors
    ///
    /// [`AttachError::Malformed`] if the advertised `signing_pubkey_hex` is not a valid 48-byte key.
    pub fn begin(&mut self, params: &BeginParams) -> Result<BeginResult, AttachError> {
        let advertised_key = SigningPublicKey::from_hex(&params.signing_pubkey_hex)
            .ok_or_else(|| AttachError::Malformed("signing_pubkey_hex".to_string()))?;

        let nonce = self.entropy.fill_nonce();
        let candidate = hex::encode(self.entropy.fill_nonce());

        self.evict_if_full();
        self.candidate_order.push_back(candidate.clone());
        self.pending.insert(
            candidate.clone(),
            PendingCandidate {
                nonce,
                advertised_key,
                profile_did: params.profile_did.clone(),
            },
        );

        Ok(BeginResult {
            nonce_b64: BASE64.encode(nonce),
            session_candidate: candidate,
        })
    }

    /// Handle `control.session.attach`: consume the pending candidate, backstop that the attaching DID
    /// really published the advertised key, verify the challenge signature, and open a session.
    ///
    /// The candidate is single-use — consumed whether the attach succeeds or fails — so a captured
    /// candidate + signature can never be replayed to open a second session.
    ///
    /// # Errors
    ///
    /// An [`AttachError`] describing the refusal; the engine returns its
    /// [`to_rpc_error`](AttachError::to_rpc_error) to the app.
    pub fn attach(&mut self, params: &AttachParams) -> Result<AttachResult, AttachError> {
        let pending = self
            .take_candidate(&params.session_candidate)
            .ok_or(AttachError::UnknownCandidate)?;

        // The attach must carry the same DID the begin did — otherwise the signed challenge (which
        // binds the begin DID) is being reused under a different attachment.
        if pending.profile_did != params.profile.did {
            return Err(AttachError::KeyMismatch);
        }

        // Backstop: the DID's PUBLISHED identity key must equal the key advertised in begin, so an app
        // cannot attach one DID while proving possession of an unrelated key.
        let published = self
            .resolver
            .resolve_signing_key(&params.profile.did)
            .ok_or(AttachError::UnknownDid)?;
        if published != pending.advertised_key {
            return Err(AttachError::KeyMismatch);
        }

        let signature = decode_signature(&params.signature_b64)?;
        let message = challenge_message(&pending.nonce, &params.profile.did);
        if !verify_signature(&pending.advertised_key, &message, &signature) {
            return Err(AttachError::BadSignature);
        }

        let session_id = hex::encode(self.entropy.fill_nonce());
        self.sessions
            .insert(session_id.clone(), params.profile.clone());

        Ok(AttachResult {
            session_id,
            engine_capabilities: ENGINE_CAPABILITIES.iter().map(|c| c.to_string()).collect(),
        })
    }

    /// Handle `control.session.detach`: drop the engine's in-memory context for `session_id`. Returns
    /// whether a session was actually removed (a detach of an unknown session is a harmless no-op).
    pub fn detach(&mut self, session_id: &str) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    /// The profile attachment for an open `session_id`, if any.
    pub fn session(&self, session_id: &str) -> Option<&ProfileAttachment> {
        self.sessions.get(session_id)
    }

    /// How many sessions are currently open.
    pub fn open_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// How many handshakes are outstanding (begun but not yet attached).
    pub fn pending_candidates(&self) -> usize {
        self.pending.len()
    }

    /// Consume and return the pending candidate for `token`, keeping the order queue consistent.
    fn take_candidate(&mut self, token: &str) -> Option<PendingCandidate> {
        let pending = self.pending.remove(token)?;
        if let Some(pos) = self.candidate_order.iter().position(|c| c == token) {
            self.candidate_order.remove(pos);
        }
        Some(pending)
    }

    /// Evict the oldest outstanding candidate when the pending map is at capacity, so a flood of
    /// never-attached `begin`s cannot grow engine state without bound.
    fn evict_if_full(&mut self) {
        while self.pending.len() >= MAX_PENDING_CANDIDATES {
            match self.candidate_order.pop_front() {
                Some(oldest) => {
                    self.pending.remove(&oldest);
                }
                None => break,
            }
        }
    }
}

/// Decode a base64 signature into the fixed-length [`Signature`] newtype.
fn decode_signature(signature_b64: &str) -> Result<Signature, AttachError> {
    let bytes = BASE64
        .decode(signature_b64.as_bytes())
        .map_err(|_| AttachError::Malformed("signature_b64 is not base64".to_string()))?;
    let bytes: [u8; SIGNATURE_LEN] = bytes
        .try_into()
        .map_err(|_| AttachError::Malformed(format!("signature is not {SIGNATURE_LEN} bytes")))?;
    Ok(Signature::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::SessionSigner;
    use crate::test_support::{SeqEntropy, StubResolver, TestSigner};

    const DID: &str = "did:chia:alice";

    fn registry(app: &TestSigner) -> EngineSessionRegistry<SeqEntropy, StubResolver> {
        EngineSessionRegistry::new(
            SeqEntropy::new(b"engine-test-seed"),
            StubResolver {
                did: DID.to_string(),
                key: app.public(),
            },
        )
    }

    fn profile() -> ProfileAttachment {
        ProfileAttachment {
            did: DID.to_string(),
            subscriptions: vec![],
            config_digest: "d".to_string(),
        }
    }

    /// Drive a genuine begin→attach the way the app would, returning the attach params the engine
    /// receives.
    fn honest_attach(app: &TestSigner, begin: &BeginResult) -> AttachParams {
        let nonce = BASE64.decode(&begin.nonce_b64).unwrap();
        let signature = app.sign(&challenge_message(&nonce, DID));
        AttachParams {
            session_candidate: begin.session_candidate.clone(),
            signature_b64: BASE64.encode(signature.as_bytes()),
            profile: profile(),
        }
    }

    #[test]
    fn honest_handshake_opens_a_session() {
        let app = TestSigner::seeded(7);
        let mut engine = registry(&app);
        let begin = engine
            .begin(&BeginParams {
                profile_did: DID.to_string(),
                signing_pubkey_hex: app.public().to_hex(),
            })
            .unwrap();
        assert_eq!(engine.pending_candidates(), 1);

        let attach = engine.attach(&honest_attach(&app, &begin)).unwrap();
        assert_eq!(engine.open_sessions(), 1);
        assert_eq!(engine.pending_candidates(), 0, "candidate is single-use");
        assert!(engine.session(&attach.session_id).is_some());
        assert!(attach.engine_capabilities.contains(&"sync".to_string()));

        assert!(engine.detach(&attach.session_id));
        assert_eq!(engine.open_sessions(), 0);
        assert!(
            !engine.detach(&attach.session_id),
            "second detach is a no-op"
        );
    }

    #[test]
    fn a_forged_signature_is_rejected_as_bad_mac() {
        let app = TestSigner::seeded(7);
        let mut engine = registry(&app);
        let begin = engine
            .begin(&BeginParams {
                profile_did: DID.to_string(),
                signing_pubkey_hex: app.public().to_hex(),
            })
            .unwrap();

        // A stranger signs the challenge — the published-key backstop resolves to `app`, so the
        // signature fails to verify.
        let stranger = TestSigner::seeded(999);
        let mut params = honest_attach(&app, &begin);
        let nonce = BASE64.decode(&begin.nonce_b64).unwrap();
        params.signature_b64 =
            BASE64.encode(stranger.sign(&challenge_message(&nonce, DID)).as_bytes());

        let err = engine.attach(&params).unwrap_err();
        assert_eq!(err, AttachError::BadSignature);
        assert_eq!(err.error_code(), SignErrorCode::BadMac);
    }

    #[test]
    fn advertising_a_key_the_did_did_not_publish_is_a_key_mismatch() {
        // The app advertises a stranger's key in begin, but the DID resolves to `app`'s key. The
        // published-key backstop rejects before any signature is even checked.
        let app = TestSigner::seeded(7);
        let stranger = TestSigner::seeded(999);
        let mut engine = registry(&app);
        let begin = engine
            .begin(&BeginParams {
                profile_did: DID.to_string(),
                signing_pubkey_hex: stranger.public().to_hex(),
            })
            .unwrap();
        let params = honest_attach(&stranger, &begin);
        let err = engine.attach(&params).unwrap_err();
        assert_eq!(err, AttachError::KeyMismatch);
    }

    #[test]
    fn attach_rejects_a_malformed_signature() {
        let app = TestSigner::seeded(7);
        let mut engine = registry(&app);
        let begin = engine
            .begin(&BeginParams {
                profile_did: DID.to_string(),
                signing_pubkey_hex: app.public().to_hex(),
            })
            .unwrap();
        let mut params = honest_attach(&app, &begin);
        params.signature_b64 = "!!not-base64".to_string();
        assert!(matches!(
            engine.attach(&params),
            Err(AttachError::Malformed(_))
        ));
    }

    #[test]
    fn a_replayed_candidate_is_unknown_on_the_second_attach() {
        let app = TestSigner::seeded(7);
        let mut engine = registry(&app);
        let begin = engine
            .begin(&BeginParams {
                profile_did: DID.to_string(),
                signing_pubkey_hex: app.public().to_hex(),
            })
            .unwrap();
        let params = honest_attach(&app, &begin);
        engine.attach(&params).unwrap();

        let err = engine.attach(&params).unwrap_err();
        assert_eq!(err, AttachError::UnknownCandidate);
        assert_eq!(err.error_code(), SignErrorCode::AuthRequired);
    }

    #[test]
    fn an_unresolvable_did_is_rejected() {
        let app = TestSigner::seeded(7);
        let mut engine = EngineSessionRegistry::new(
            SeqEntropy::new(b"seed"),
            StubResolver {
                did: "did:chia:someone-else".to_string(),
                key: app.public(),
            },
        );
        let begin = engine
            .begin(&BeginParams {
                profile_did: DID.to_string(),
                signing_pubkey_hex: app.public().to_hex(),
            })
            .unwrap();
        let err = engine.attach(&honest_attach(&app, &begin)).unwrap_err();
        assert_eq!(err, AttachError::UnknownDid);
    }

    #[test]
    fn begin_rejects_a_malformed_pubkey() {
        let app = TestSigner::seeded(7);
        let mut engine = registry(&app);
        let err = engine
            .begin(&BeginParams {
                profile_did: DID.to_string(),
                signing_pubkey_hex: "not-hex".to_string(),
            })
            .unwrap_err();
        assert!(matches!(err, AttachError::Malformed(_)));
    }

    #[test]
    fn pending_candidates_are_capped() {
        let app = TestSigner::seeded(7);
        let mut engine = registry(&app);
        for _ in 0..MAX_PENDING_CANDIDATES + 10 {
            engine
                .begin(&BeginParams {
                    profile_did: DID.to_string(),
                    signing_pubkey_hex: app.public().to_hex(),
                })
                .unwrap();
        }
        assert!(engine.pending_candidates() <= MAX_PENDING_CANDIDATES);
    }
}
