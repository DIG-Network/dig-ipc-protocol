//! The JSON-RPC 2.0 wire contract: the `control.session.*` method names, the request/response
//! parameter and result shapes, the engine→app `sign` callback shape, the envelope helpers both role-
//! halves frame with, and the stable APP-SIGN error taxonomy.
//!
//! These types ARE the on-wire encoding shared by the app and the engine, so they live in the shared
//! crate rather than being duplicated on each side. Field names are the wire contract — renaming one
//! is a breaking protocol change.

use serde::{Deserialize, Serialize};

/// The JSON-RPC version string every frame carries.
pub const JSONRPC_VERSION: &str = "2.0";

/// `control.session.begin` — the app opens a handshake, advertising the profile DID + its slot-`0x0010`
/// signing pubkey; the engine replies with a nonce + an opaque session candidate.
pub const METHOD_BEGIN: &str = "control.session.begin";

/// `control.session.attach` — the app returns the signed challenge + its profile attachment; the
/// engine verifies and opens the session.
pub const METHOD_ATTACH: &str = "control.session.attach";

/// `control.session.detach` — the app tears a session down (logout / profile switch / exit).
pub const METHOD_DETACH: &str = "control.session.detach";

/// `sign` — the engine→app callback: the engine asks the app to sign an engine-initiated operation's
/// payload with the in-memory identity key.
pub const METHOD_SIGN: &str = "sign";

// --- Handshake parameters + results ----------------------------------------------------------------

/// `control.session.begin` request parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeginParams {
    /// The profile DID the app is attaching.
    pub profile_did: String,
    /// The app's slot-`0x0010` Ed25519 signing public key, lowercase hex. The engine verifies the
    /// attach challenge against THIS key and binds the session to the DID's published key.
    pub signing_pubkey_hex: String,
}

/// `control.session.begin` result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeginResult {
    /// The engine's per-handshake challenge nonce, base64. The app signs
    /// [`challenge_message`](crate::challenge_message)`(nonce, profile_did)`.
    pub nonce_b64: String,
    /// An opaque token the engine issued for this pending handshake; echoed on `attach`.
    pub session_candidate: String,
}

/// `control.session.attach` request parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachParams {
    /// The candidate token from [`BeginResult`].
    pub session_candidate: String,
    /// The detached signature over the domain-separated challenge, base64.
    pub signature_b64: String,
    /// The profile attachment the engine should serve this session with.
    pub profile: ProfileAttachment,
}

/// `control.session.attach` result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachResult {
    /// The engine-assigned session identifier, echoed on `detach` and correlated in `sign` callbacks.
    pub session_id: String,
    /// The capabilities the engine advertised for this session (see
    /// [`ENGINE_CAPABILITIES`](crate::ENGINE_CAPABILITIES)).
    #[serde(default)]
    pub engine_capabilities: Vec<String>,
}

/// `control.session.detach` request parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetachParams {
    /// The session to drop.
    pub session_id: String,
}

/// `control.session.detach` result (an empty ack).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetachResult {}

/// The active profile's attachment payload — the `{ did, subscriptions, config_digest }` the app
/// pushes to the engine on attach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileAttachment {
    /// The profile DID being attached.
    pub did: String,
    /// The subscriptions the engine should serve for this session.
    pub subscriptions: Vec<String>,
    /// A digest of the profile's config, so the engine can detect config drift without seeing the
    /// (sealed) config itself.
    pub config_digest: String,
}

// --- The engine→app `sign` callback ----------------------------------------------------------------

/// `sign` callback request parameters (engine → app).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignCallbackParams {
    /// The session the engine is signing on behalf of.
    pub session_id: String,
    /// The engine-assigned operation id, for correlation and audit.
    pub op_id: String,
    /// The engine's label for what kind of payload this is (a spend bundle, an SMT write, …).
    pub payload_type: String,
    /// The raw bytes the engine wants signed, base64.
    pub payload_b64: String,
    /// Optional engine-supplied context (human-readable description, amounts, recipient) a policy or
    /// a confirmation prompt can surface.
    #[serde(default)]
    pub context: Option<serde_json::Value>,
}

/// `sign` callback result (app → engine): the detached signature over the domain-separated callback
/// message, and the public key it was made with. NEVER the private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignCallbackResult {
    /// The detached signature, base64.
    pub signature_b64: String,
    /// The signing public key, lowercase hex.
    pub pubkey_hex: String,
}

// --- JSON-RPC 2.0 envelope -------------------------------------------------------------------------

/// A JSON-RPC request the app sends (`id` is a `u64` the client assigns and awaits).
#[derive(Debug, Serialize)]
pub struct RpcRequest<'a, P: Serialize> {
    /// Always [`JSONRPC_VERSION`].
    pub jsonrpc: &'static str,
    /// The request id the sender correlates the response by.
    pub id: u64,
    /// The method name.
    pub method: &'a str,
    /// The typed parameters.
    pub params: P,
}

/// A JSON-RPC success reply to an engine-initiated request (the app answering a `sign` callback).
#[derive(Debug, Serialize)]
pub struct RpcResult<'a, V: Serialize> {
    /// Always [`JSONRPC_VERSION`].
    pub jsonrpc: &'static str,
    /// The id echoed from the request being answered.
    pub id: &'a serde_json::Value,
    /// The typed result.
    pub result: V,
}

/// A JSON-RPC error reply to an engine-initiated request.
#[derive(Debug, Serialize)]
pub struct RpcErrorReply<'a> {
    /// Always [`JSONRPC_VERSION`].
    pub jsonrpc: &'static str,
    /// The id echoed from the request being answered.
    pub id: &'a serde_json::Value,
    /// The error body.
    pub error: RpcError,
}

/// A JSON-RPC error object (`{ code, message }`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcError {
    /// The numeric JSON-RPC error code.
    pub code: i64,
    /// The human-readable message. For APP-SIGN errors this carries the [`SignErrorCode`] symbol.
    pub message: String,
}

/// A frame arriving from the peer — either a response to a request (`result`/`error` set) or a
/// peer-initiated request such as the `sign` callback (`method`/`params` set). Every field is optional
/// so one type parses both directions of the full-duplex channel.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct IncomingFrame {
    /// The correlation id, if present.
    #[serde(default)]
    pub id: Option<serde_json::Value>,
    /// The method, set on a peer-initiated request.
    #[serde(default)]
    pub method: Option<String>,
    /// The parameters, set on a peer-initiated request.
    #[serde(default)]
    pub params: Option<serde_json::Value>,
    /// The result, set on a success response.
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    /// The error, set on an error response.
    #[serde(default)]
    pub error: Option<RpcError>,
}

// --- The APP-SIGN error taxonomy -------------------------------------------------------------------

/// The stable symbolic error codes the extension and the app key their UX off. Each carries a numeric
/// JSON-RPC `code` (an application-specific range, distinct from the JSON-RPC reserved `-32xxx` band)
/// and its canonical symbol string, sent as the error `message` so both the numeric and symbolic forms
/// are on the wire. Renaming a symbol or renumbering a code is a breaking protocol change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignErrorCode {
    /// No valid pairing/authorization for this frame (unpaired / revoked).
    AuthRequired,
    /// Pairing-token MAC verification failed.
    BadMac,
    /// Frame nonce not strictly greater than the last accepted — a replay.
    Replay,
    /// The user (or policy) denied the pairing confirm.
    PairDenied,
    /// The origin is not connected/whitelisted for the active profile.
    ConnectRequired,
    /// The sign request was denied (by policy or the user).
    SignDenied,
    /// No confirmer available (headless — fail closed rather than blind-sign).
    NoConfirmer,
    /// The active profile is locked; there is no key to sign with.
    Locked,
}

impl SignErrorCode {
    /// The canonical symbol string — sent as the JSON-RPC error `message`.
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::AuthRequired => "AUTH_REQUIRED",
            Self::BadMac => "BAD_MAC",
            Self::Replay => "REPLAY",
            Self::PairDenied => "PAIR_DENIED",
            Self::ConnectRequired => "CONNECT_REQUIRED",
            Self::SignDenied => "SIGN_DENIED",
            Self::NoConfirmer => "NO_CONFIRMER",
            Self::Locked => "LOCKED",
        }
    }

    /// The numeric JSON-RPC error code (application range, one per symbol).
    pub const fn code(self) -> i64 {
        match self {
            Self::AuthRequired => -33001,
            Self::BadMac => -33002,
            Self::Replay => -33003,
            Self::PairDenied => -33010,
            Self::ConnectRequired => -33020,
            Self::SignDenied => -33030,
            Self::NoConfirmer => -33034,
            Self::Locked => -33040,
        }
    }

    /// Build the JSON-RPC [`RpcError`] for this code (numeric `code` + symbol `message`).
    pub fn to_rpc_error(self) -> RpcError {
        RpcError {
            code: self.code(),
            message: self.symbol().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every taxonomy entry, so the symbol strings + codes are pinned as the wire contract and a
    /// rename/renumber trips the test (a breaking protocol change must be deliberate).
    const ALL: &[(SignErrorCode, &str, i64)] = &[
        (SignErrorCode::AuthRequired, "AUTH_REQUIRED", -33001),
        (SignErrorCode::BadMac, "BAD_MAC", -33002),
        (SignErrorCode::Replay, "REPLAY", -33003),
        (SignErrorCode::PairDenied, "PAIR_DENIED", -33010),
        (SignErrorCode::ConnectRequired, "CONNECT_REQUIRED", -33020),
        (SignErrorCode::SignDenied, "SIGN_DENIED", -33030),
        (SignErrorCode::NoConfirmer, "NO_CONFIRMER", -33034),
        (SignErrorCode::Locked, "LOCKED", -33040),
    ];

    #[test]
    fn error_taxonomy_symbols_and_codes_are_pinned() {
        for (code, symbol, num) in ALL {
            assert_eq!(code.symbol(), *symbol);
            assert_eq!(code.code(), *num);
            let rpc = code.to_rpc_error();
            assert_eq!(rpc.code, *num);
            assert_eq!(rpc.message, *symbol);
        }
    }

    #[test]
    fn error_codes_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for (code, _, _) in ALL {
            assert!(seen.insert(code.code()), "duplicate code {}", code.code());
        }
    }

    #[test]
    fn wire_types_round_trip_through_json() {
        let params = BeginParams {
            profile_did: "did:chia:x".to_string(),
            signing_pubkey_hex: "ab".repeat(32),
        };
        let json = serde_json::to_string(&params).unwrap();
        let back: BeginParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back.profile_did, params.profile_did);

        let attach = AttachResult {
            session_id: "s".to_string(),
            engine_capabilities: vec!["sync".to_string()],
        };
        let json = serde_json::to_string(&attach).unwrap();
        let back: AttachResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.engine_capabilities, attach.engine_capabilities);

        // engine_capabilities defaults to empty when absent.
        let minimal: AttachResult = serde_json::from_str(r#"{"session_id":"s"}"#).unwrap();
        assert!(minimal.engine_capabilities.is_empty());
    }

    #[test]
    fn incoming_frame_parses_both_a_response_and_a_request() {
        let response: IncomingFrame =
            serde_json::from_str(r#"{"id":1,"result":{"ok":true}}"#).unwrap();
        assert!(response.result.is_some());
        assert!(response.method.is_none());

        let request: IncomingFrame =
            serde_json::from_str(r#"{"id":2,"method":"sign","params":{}}"#).unwrap();
        assert_eq!(request.method.as_deref(), Some("sign"));
    }
}
