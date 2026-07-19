//! The app role-half: [`SessionClient`] drives the begin→attach handshake, services engine `sign`
//! callbacks, detaches, and re-attaches after a dropped pipe. The app's private key never leaves the
//! process — only signatures and the public key cross the wire.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::bounds::MAX_INTERLEAVED_CALLBACKS;
use crate::domain::{challenge_message, sign_callback_message};
use crate::signer::{SessionSigner, SignDecision, SignPolicy, SignRequest};
use crate::transport::FrameTransport;
use crate::wire::{
    AttachParams, AttachResult, BeginParams, BeginResult, DetachParams, DetachResult,
    IncomingFrame, ProfileAttachment, RpcError, RpcErrorReply, RpcRequest, RpcResult,
    SignCallbackParams, SignCallbackResult, SignErrorCode, JSONRPC_VERSION, METHOD_ATTACH,
    METHOD_BEGIN, METHOD_DETACH, METHOD_SIGN,
};

/// A live, attached engine session. One exists per active profile (the app is multi-session aware;
/// see [`SessionRegistry`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The engine-assigned session identifier, echoed on `detach` and correlated in `sign` callbacks.
    pub session_id: String,
    /// The capabilities the engine advertised for this session.
    pub engine_capabilities: Vec<String>,
    /// The DID whose identity attached this session.
    pub profile_did: String,
}

/// Errors from driving a session over the IPC channel.
///
/// A denied or malformed engine `sign` callback is NOT one of these — it is answered to the engine as a
/// JSON-RPC error and does not fail the local caller. These variants are for failures that break the
/// app's own handshake or read loop.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The transport failed — most importantly [`std::io::ErrorKind::UnexpectedEof`], the dropped-pipe
    /// signal that triggers a re-attach.
    #[error("session transport I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A frame was not well-formed JSON-RPC.
    #[error("malformed session frame: {0}")]
    Frame(#[from] serde_json::Error),

    /// The engine answered a handshake request with a JSON-RPC error.
    #[error("engine rejected the request: [{code}] {message}")]
    Engine {
        /// The JSON-RPC error code the engine returned.
        code: i64,
        /// The human-readable message the engine returned.
        message: String,
    },

    /// A handshake response arrived for a request id the app was not awaiting — a desynchronized
    /// channel.
    #[error("engine reply id did not match the pending request")]
    IdMismatch,

    /// A frame the app expected to be a response carried neither a result nor an error.
    #[error("engine frame was neither a valid response nor a known callback")]
    MalformedResponse,

    /// [`SessionClient::handle_next_sign_callback`] read a frame that was not a `sign` callback.
    #[error("expected an engine sign callback but received a different frame")]
    NotASignCallback,

    /// The engine streamed more than [`MAX_INTERLEAVED_CALLBACKS`] `sign` callbacks without answering
    /// the pending handshake request — a wedged or hostile engine.
    #[error("engine sent too many interleaved callbacks without a response")]
    TooManyCallbacks,
}

/// The app-side session client: owns the transport to one engine connection, the [`SessionSigner`]
/// (the unlocked identity), and the [`SignPolicy`] custody gate. Drives the begin→attach handshake,
/// services engine `sign` callbacks, detaches, and re-attaches after a dropped pipe.
///
/// One client drives one connection (hence one profile's session). The app runs several — one per
/// active profile — and tracks their [`Session`] handles in a [`SessionRegistry`].
pub struct SessionClient<T: FrameTransport, S: SessionSigner, P: SignPolicy> {
    transport: T,
    signer: S,
    policy: P,
    next_id: u64,
}

impl<T: FrameTransport, S: SessionSigner, P: SignPolicy> SessionClient<T, S, P> {
    /// Build a client over an already-connected `transport`, signing with `signer` and gating engine
    /// `sign` callbacks through `policy`.
    pub fn new(transport: T, signer: S, policy: P) -> Self {
        Self {
            transport,
            signer,
            policy,
            next_id: 1,
        }
    }

    /// Run the full identity-authenticated handshake for `profile` and return the opened [`Session`]:
    /// `begin` to obtain the nonce + candidate, sign the domain-separated challenge with the in-memory
    /// key, then `attach`. The private key never leaves the process — only the signature and the
    /// public key cross the wire.
    ///
    /// # Errors
    ///
    /// [`SessionError::Io`] if the pipe drops (the re-attach trigger), [`SessionError::Engine`] if the
    /// engine rejects begin or attach, or a frame/parse error on a malformed reply.
    pub fn begin_and_attach(
        &mut self,
        profile: ProfileAttachment,
    ) -> Result<Session, SessionError> {
        let begin_pubkey_hex = self.signer.signing_public_key_hex();
        let begin: BeginResult = self.call(
            METHOD_BEGIN,
            BeginParams {
                profile_did: profile.did.clone(),
                signing_pubkey_hex: begin_pubkey_hex.clone(),
            },
        )?;

        let nonce = BASE64
            .decode(begin.nonce_b64.as_bytes())
            .map_err(|_| SessionError::MalformedResponse)?;

        // We advertised `signer`'s public key in `begin`, and we attach `profile.did`; assert locally
        // the key we sign with is the one we advertised, so a future refactor that let them diverge
        // trips in debug builds rather than silently attaching a mismatched identity.
        debug_assert_eq!(
            self.signer.signing_public_key_hex(),
            begin_pubkey_hex,
            "the attach signature must use the same identity key advertised in begin"
        );
        let signature = self.signer.sign(&challenge_message(&nonce, &profile.did));

        let attach: AttachResult = self.call(
            METHOD_ATTACH,
            AttachParams {
                session_candidate: begin.session_candidate,
                signature_b64: BASE64.encode(signature.as_bytes()),
                profile: profile.clone(),
            },
        )?;

        Ok(Session {
            session_id: attach.session_id,
            engine_capabilities: attach.engine_capabilities,
            profile_did: profile.did,
        })
    }

    /// Detach `session` (logout / profile switch / exit): tell the engine to drop its in-memory context
    /// for this session.
    ///
    /// # Errors
    ///
    /// [`SessionError::Io`] if the pipe is already gone (which effectively achieves the same end — the
    /// engine drops the session when the connection closes), or [`SessionError::Engine`] on a reported
    /// problem.
    pub fn detach(&mut self, session: &Session) -> Result<(), SessionError> {
        let _: DetachResult = self.call(
            METHOD_DETACH,
            DetachParams {
                session_id: session.session_id.clone(),
            },
        )?;
        Ok(())
    }

    /// Re-establish a session after an engine restart or a dropped pipe: swap in a freshly-connected
    /// `transport` and re-run the handshake.
    ///
    /// # Errors
    ///
    /// As [`begin_and_attach`](Self::begin_and_attach).
    pub fn reattach(
        &mut self,
        transport: T,
        profile: ProfileAttachment,
    ) -> Result<Session, SessionError> {
        self.transport = transport;
        self.next_id = 1;
        self.begin_and_attach(profile)
    }

    /// Read one frame and, if it is an engine `sign` callback, service it: decode the payload, gate it
    /// through the [`SignPolicy`], sign with the in-memory key on approval, and answer the engine with
    /// `{ signature_b64, pubkey_hex }` (or a JSON-RPC error on denial / bad payload). The private key
    /// is never returned — only the signature. Returns the [`SignDecision`] taken, for the caller's
    /// audit log.
    ///
    /// # Errors
    ///
    /// [`SessionError::NotASignCallback`] if the frame was not a `sign` request, or a transport/parse
    /// error.
    pub fn handle_next_sign_callback(&mut self) -> Result<SignDecision, SessionError> {
        let raw = self.transport.recv_frame()?;
        let frame: IncomingFrame = serde_json::from_str(&raw)?;
        match frame.method.as_deref() {
            Some(METHOD_SIGN) => self.service_sign_callback(frame),
            _ => Err(SessionError::NotASignCallback),
        }
    }

    /// Service a parsed `sign` callback frame: policy-gate, sign, and reply. Factored out so the read
    /// loop can also service callbacks that interleave with a pending handshake response.
    fn service_sign_callback(
        &mut self,
        frame: IncomingFrame,
    ) -> Result<SignDecision, SessionError> {
        let id = frame.id.clone().unwrap_or(serde_json::Value::Null);
        let params: SignCallbackParams =
            serde_json::from_value(frame.params.unwrap_or(serde_json::Value::Null))?;

        let payload = match BASE64.decode(params.payload_b64.as_bytes()) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.send_error(
                    &id,
                    SignErrorCode::SignDenied.code(),
                    "sign payload is not valid base64",
                )?;
                return Ok(SignDecision::Deny("invalid base64 payload".to_string()));
            }
        };

        let decision = self.policy.authorize(&SignRequest {
            session_id: &params.session_id,
            op_id: &params.op_id,
            payload_type: &params.payload_type,
            payload: &payload,
            context: params.context.as_ref(),
        });

        match &decision {
            SignDecision::Allow => {
                // Sign the DOMAIN-SEPARATED, length-prefixed message — never the engine's raw bytes.
                // This closes the cross-protocol signing oracle: a malicious engine cannot choose a
                // `payload` that makes this signature verify as an attach challenge (or any other
                // identity-key signature), because the `DIGNET-SIGN-v1` tag can never equal the
                // `DIGNET-SESSION-v1` (or any other) tag those messages carry.
                match sign_callback_message(&params.payload_type, &payload) {
                    Some(message) => {
                        let signature = self.signer.sign(&message);
                        self.send_result(
                            &id,
                            SignCallbackResult {
                                signature_b64: BASE64.encode(signature.as_bytes()),
                                pubkey_hex: self.signer.signing_public_key_hex(),
                            },
                        )?;
                    }
                    None => {
                        self.send_error(
                            &id,
                            SignErrorCode::SignDenied.code(),
                            "sign payload_type exceeds the maximum length",
                        )?;
                        return Ok(SignDecision::Deny("payload_type too long".to_string()));
                    }
                }
            }
            SignDecision::Deny(reason) => {
                self.send_error(&id, SignErrorCode::SignDenied.code(), reason)?;
            }
        }
        Ok(decision)
    }

    /// Send a JSON-RPC request and read its response, servicing any engine `sign` callback that
    /// interleaves before the response arrives (the connection is full-duplex). Returns the typed
    /// result, or [`SessionError::Engine`] if the engine answered with an error.
    fn call<Q: Serialize, R: for<'de> Deserialize<'de>>(
        &mut self,
        method: &str,
        params: Q,
    ) -> Result<R, SessionError> {
        let id = self.next_id;
        self.next_id += 1;
        let request = serde_json::to_string(&RpcRequest {
            jsonrpc: JSONRPC_VERSION,
            id,
            method,
            params,
        })?;
        self.transport.send_frame(&request)?;
        self.read_response(id)
    }

    /// Read frames until the response for `awaited_id` arrives, servicing interleaved `sign` callbacks
    /// along the way.
    fn read_response<R: for<'de> Deserialize<'de>>(
        &mut self,
        awaited_id: u64,
    ) -> Result<R, SessionError> {
        let mut callbacks_serviced = 0usize;
        loop {
            let raw = self.transport.recv_frame()?;
            let frame: IncomingFrame = serde_json::from_str(&raw)?;

            if frame.method.as_deref() == Some(METHOD_SIGN) {
                callbacks_serviced += 1;
                if callbacks_serviced > MAX_INTERLEAVED_CALLBACKS {
                    return Err(SessionError::TooManyCallbacks);
                }
                self.service_sign_callback(frame)?;
                continue;
            }

            if frame.id.as_ref().and_then(serde_json::Value::as_u64) != Some(awaited_id) {
                return Err(SessionError::IdMismatch);
            }
            if let Some(error) = frame.error {
                return Err(SessionError::Engine {
                    code: error.code,
                    message: error.message,
                });
            }
            let result = frame.result.ok_or(SessionError::MalformedResponse)?;
            return Ok(serde_json::from_value(result)?);
        }
    }

    /// Write a JSON-RPC success reply to an engine-initiated request.
    fn send_result<V: Serialize>(
        &mut self,
        id: &serde_json::Value,
        result: V,
    ) -> Result<(), SessionError> {
        let frame = serde_json::to_string(&RpcResult {
            jsonrpc: JSONRPC_VERSION,
            id,
            result,
        })?;
        self.transport.send_frame(&frame).map_err(SessionError::Io)
    }

    /// Write a JSON-RPC error reply to an engine-initiated request.
    fn send_error(
        &mut self,
        id: &serde_json::Value,
        code: i64,
        message: &str,
    ) -> Result<(), SessionError> {
        let frame = serde_json::to_string(&RpcErrorReply {
            jsonrpc: JSONRPC_VERSION,
            id,
            error: RpcError {
                code,
                message: message.to_string(),
            },
        })?;
        self.transport.send_frame(&frame).map_err(SessionError::Io)
    }
}

/// The app's map of live sessions, one per active profile — multi-session awareness (fast-user-
/// switching and concurrent profiles). Keyed by profile DID.
#[derive(Debug, Default)]
pub struct SessionRegistry {
    by_did: HashMap<String, Session>,
}

impl SessionRegistry {
    /// A registry with no sessions.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record (or replace) the live session for its profile DID.
    pub fn insert(&mut self, session: Session) {
        self.by_did.insert(session.profile_did.clone(), session);
    }

    /// The live session for `profile_did`, if one is attached.
    pub fn get(&self, profile_did: &str) -> Option<&Session> {
        self.by_did.get(profile_did)
    }

    /// Drop and return the session for `profile_did` (on detach / logout).
    pub fn remove(&mut self, profile_did: &str) -> Option<Session> {
        self.by_did.remove(profile_did)
    }

    /// How many sessions are currently attached.
    pub fn len(&self) -> usize {
        self.by_did.len()
    }

    /// Whether no session is attached.
    pub fn is_empty(&self) -> bool {
        self.by_did.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{verify_signature, Signature, SigningPublicKey, SIGNATURE_LEN};
    use crate::signer::{AllowAllSignPolicy, DenyAllSignPolicy};
    use crate::test_support::{FakeTransport, TestSigner};
    use sha2::{Digest, Sha256};

    const DID: &str = "did:chia:testprofile";

    /// A derived (never hard-coded) nonce fixture — the production nonce is minted by the engine.
    fn nonce() -> Vec<u8> {
        Sha256::digest(b"dig-ipc-protocol client test nonce fixture").to_vec()
    }

    fn profile() -> ProfileAttachment {
        ProfileAttachment {
            did: DID.to_string(),
            subscriptions: vec!["store-a".to_string()],
            config_digest: "cfg-digest".to_string(),
        }
    }

    fn begin_frame(id: u64) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"result":{{"nonce_b64":"{}","session_candidate":"cand-1"}}}}"#,
            BASE64.encode(nonce())
        )
    }

    fn attach_frame(id: u64) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"result":{{"session_id":"sess-1","engine_capabilities":["content.serve","sync"]}}}}"#
        )
    }

    fn attach_signature_verifies(outgoing: &str, expected: &SigningPublicKey) -> bool {
        let sent: serde_json::Value = serde_json::from_str(outgoing).unwrap();
        let sig_b64 = sent["params"]["signature_b64"].as_str().unwrap();
        let sig: [u8; SIGNATURE_LEN] = BASE64.decode(sig_b64).unwrap().try_into().unwrap();
        verify_signature(
            expected,
            &challenge_message(&nonce(), DID),
            &Signature::new(sig),
        )
    }

    #[test]
    fn begin_then_attach_happy_path_opens_a_session() {
        let signer = TestSigner::seeded(42);
        let pubkey = signer.public();
        let transport = FakeTransport::scripted([begin_frame(1), attach_frame(2)]);
        let mut client = SessionClient::new(transport, signer, AllowAllSignPolicy);

        let session = client.begin_and_attach(profile()).unwrap();

        assert_eq!(session.session_id, "sess-1");
        assert_eq!(session.profile_did, DID);
        assert_eq!(session.engine_capabilities, ["content.serve", "sync"]);
        assert!(attach_signature_verifies(
            &client.transport.outgoing[1],
            &pubkey
        ));
    }

    #[test]
    fn attach_signature_is_rejected_for_a_foreign_key() {
        let signer = TestSigner::seeded(42);
        let stranger = TestSigner::seeded(999);
        let transport = FakeTransport::scripted([begin_frame(1), attach_frame(2)]);
        let mut client = SessionClient::new(transport, signer, AllowAllSignPolicy);

        client.begin_and_attach(profile()).unwrap();

        assert!(!attach_signature_verifies(
            &client.transport.outgoing[1],
            &stranger.public()
        ));
    }

    #[test]
    fn begin_propagates_an_engine_error() {
        let err = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"unknown profile"}}"#;
        let transport = FakeTransport::scripted([err.to_string()]);
        let mut client = SessionClient::new(transport, TestSigner::seeded(1), AllowAllSignPolicy);

        match client.begin_and_attach(profile()) {
            Err(SessionError::Engine { code, message }) => {
                assert_eq!(code, -32000);
                assert_eq!(message, "unknown profile");
            }
            other => panic!("expected an engine error, got {other:?}"),
        }
    }

    #[test]
    fn sign_callback_returns_a_signature_without_exposing_the_key() {
        let signer = TestSigner::seeded(42);
        let pubkey = signer.public();
        let payload = b"spend-bundle-bytes";
        let callback = format!(
            r#"{{"jsonrpc":"2.0","id":77,"method":"sign","params":{{"session_id":"sess-1","op_id":"op-9","payload_type":"spend","payload_b64":"{}","context":{{"amount":5}}}}}}"#,
            BASE64.encode(payload)
        );
        let transport = FakeTransport::scripted([callback]);
        let mut client = SessionClient::new(transport, signer, AllowAllSignPolicy);

        let decision = client.handle_next_sign_callback().unwrap();
        assert_eq!(decision, SignDecision::Allow);

        let reply: serde_json::Value = serde_json::from_str(&client.transport.outgoing[0]).unwrap();
        assert_eq!(reply["id"], 77);
        let sig_b64 = reply["result"]["signature_b64"].as_str().unwrap();
        let sig: [u8; SIGNATURE_LEN] = BASE64.decode(sig_b64).unwrap().try_into().unwrap();
        let signature = Signature::new(sig);
        let signed = sign_callback_message("spend", payload).unwrap();
        assert!(verify_signature(&pubkey, &signed, &signature));
        assert!(
            !verify_signature(&pubkey, payload, &signature),
            "the signature must NOT verify over the raw payload — it is domain-separated"
        );
        assert_eq!(reply["result"]["pubkey_hex"], pubkey.to_hex());
        assert!(reply["result"].get("private_key").is_none());
    }

    #[test]
    fn sign_callback_cannot_be_used_as_an_attach_signing_oracle() {
        let signer = TestSigner::seeded(42);
        let pubkey = signer.public();
        let forged_payload = challenge_message(&nonce(), DID);
        let callback = format!(
            r#"{{"jsonrpc":"2.0","id":13,"method":"sign","params":{{"session_id":"s","op_id":"o","payload_type":"spend","payload_b64":"{}"}}}}"#,
            BASE64.encode(&forged_payload)
        );
        let transport = FakeTransport::scripted([callback]);
        let mut client = SessionClient::new(transport, signer, AllowAllSignPolicy);

        client.handle_next_sign_callback().unwrap();

        let reply: serde_json::Value = serde_json::from_str(&client.transport.outgoing[0]).unwrap();
        let sig_b64 = reply["result"]["signature_b64"].as_str().unwrap();
        let sig: [u8; SIGNATURE_LEN] = BASE64.decode(sig_b64).unwrap().try_into().unwrap();
        let signature = Signature::new(sig);

        assert!(
            !verify_signature(&pubkey, &forged_payload, &signature),
            "cross-protocol signing oracle: a callback signature verified as an attach challenge"
        );
        let signed = sign_callback_message("spend", &forged_payload).unwrap();
        assert!(verify_signature(&pubkey, &signed, &signature));
    }

    #[test]
    fn sign_callback_denied_by_policy_returns_an_error_and_no_signature() {
        let callback = format!(
            r#"{{"jsonrpc":"2.0","id":88,"method":"sign","params":{{"session_id":"sess-1","op_id":"op-1","payload_type":"spend","payload_b64":"{}"}}}}"#,
            BASE64.encode(b"anything")
        );
        let transport = FakeTransport::scripted([callback]);
        let mut client = SessionClient::new(transport, TestSigner::seeded(1), DenyAllSignPolicy);

        let decision = client.handle_next_sign_callback().unwrap();
        assert!(matches!(decision, SignDecision::Deny(_)));

        let reply: serde_json::Value = serde_json::from_str(&client.transport.outgoing[0]).unwrap();
        assert_eq!(reply["id"], 88);
        assert_eq!(reply["error"]["code"], SignErrorCode::SignDenied.code());
        assert!(reply.get("result").is_none());
    }

    #[test]
    fn sign_callback_with_a_bad_payload_returns_an_error() {
        let callback = r#"{"jsonrpc":"2.0","id":5,"method":"sign","params":{"session_id":"s","op_id":"o","payload_type":"spend","payload_b64":"not!!base64"}}"#;
        let transport = FakeTransport::scripted([callback.to_string()]);
        let mut client = SessionClient::new(transport, TestSigner::seeded(1), AllowAllSignPolicy);

        let decision = client.handle_next_sign_callback().unwrap();
        assert!(matches!(decision, SignDecision::Deny(_)));
        let reply: serde_json::Value = serde_json::from_str(&client.transport.outgoing[0]).unwrap();
        assert_eq!(reply["error"]["code"], SignErrorCode::SignDenied.code());
    }

    #[test]
    fn handle_next_sign_callback_rejects_a_non_callback_frame() {
        let transport = FakeTransport::scripted([attach_frame(1)]);
        let mut client = SessionClient::new(transport, TestSigner::seeded(1), AllowAllSignPolicy);
        assert!(matches!(
            client.handle_next_sign_callback(),
            Err(SessionError::NotASignCallback)
        ));
    }

    #[test]
    fn a_sign_callback_interleaved_before_a_response_is_serviced() {
        let interleaved = format!(
            r#"{{"jsonrpc":"2.0","id":500,"method":"sign","params":{{"session_id":"s","op_id":"o","payload_type":"t","payload_b64":"{}"}}}}"#,
            BASE64.encode(b"x")
        );
        let transport = FakeTransport::scripted([interleaved, begin_frame(1), attach_frame(2)]);
        let mut client = SessionClient::new(transport, TestSigner::seeded(1), AllowAllSignPolicy);

        let session = client.begin_and_attach(profile()).unwrap();
        assert_eq!(session.session_id, "sess-1");
        let serviced = client.transport.outgoing.iter().any(|frame| {
            serde_json::from_str::<serde_json::Value>(frame)
                .map(|v| v["id"] == 500 && v.get("result").is_some())
                .unwrap_or(false)
        });
        assert!(serviced);
    }

    #[test]
    fn a_dropped_pipe_surfaces_as_an_io_error_then_reattach_recovers() {
        let dropped = FakeTransport::default();
        let mut client = SessionClient::new(dropped, TestSigner::seeded(1), AllowAllSignPolicy);
        match client.begin_and_attach(profile()) {
            Err(SessionError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof),
            other => panic!("expected an EOF I/O error, got {other:?}"),
        }

        let fresh = FakeTransport::scripted([begin_frame(1), attach_frame(2)]);
        let session = client.reattach(fresh, profile()).unwrap();
        assert_eq!(session.session_id, "sess-1");
    }

    #[test]
    fn detach_sends_the_session_id() {
        let ack = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        let transport = FakeTransport::scripted([ack.to_string()]);
        let mut client = SessionClient::new(transport, TestSigner::seeded(1), AllowAllSignPolicy);
        let session = Session {
            session_id: "sess-42".to_string(),
            engine_capabilities: vec![],
            profile_did: DID.to_string(),
        };

        client.detach(&session).unwrap();

        let sent: serde_json::Value = serde_json::from_str(&client.transport.outgoing[0]).unwrap();
        assert_eq!(sent["method"], METHOD_DETACH);
        assert_eq!(sent["params"]["session_id"], "sess-42");
    }

    #[test]
    fn read_response_gives_up_after_too_many_interleaved_callbacks() {
        let flood = (0..MAX_INTERLEAVED_CALLBACKS + 1).map(|i| {
            format!(
                r#"{{"jsonrpc":"2.0","id":{i},"method":"sign","params":{{"session_id":"s","op_id":"o","payload_type":"t","payload_b64":"{}"}}}}"#,
                BASE64.encode(b"x")
            )
        });
        let transport = FakeTransport::scripted(flood);
        let mut client = SessionClient::new(transport, TestSigner::seeded(1), AllowAllSignPolicy);
        assert!(matches!(
            client.begin_and_attach(profile()),
            Err(SessionError::TooManyCallbacks)
        ));
    }

    #[test]
    fn registry_tracks_one_session_per_profile() {
        let mut registry = SessionRegistry::new();
        assert!(registry.is_empty());
        let alice = Session {
            session_id: "a".to_string(),
            engine_capabilities: vec![],
            profile_did: "did:chia:alice".to_string(),
        };
        let bob = Session {
            session_id: "b".to_string(),
            engine_capabilities: vec![],
            profile_did: "did:chia:bob".to_string(),
        };
        registry.insert(alice.clone());
        registry.insert(bob);
        assert_eq!(registry.len(), 2);
        assert_eq!(registry.get("did:chia:alice"), Some(&alice));
        let removed = registry.remove("did:chia:bob").unwrap();
        assert_eq!(removed.session_id, "b");
        assert_eq!(registry.len(), 1);
    }
}
