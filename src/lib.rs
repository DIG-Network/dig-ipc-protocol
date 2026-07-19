//! # dig-ipc-protocol — the canonical dig-app ⇄ dig-node IPC session/signing contract
//!
//! This crate is the single source of truth for the local IPC channel between the branded user app
//! (dig-app — the identity holder) and the identity-agnostic engine (dig-node). Both sides depend on
//! THIS crate rather than each maintaining a byte-identical copy of the contract, so the two can never
//! silently drift.
//!
//! ## What it owns
//!
//! - **The signed-message contract** ([`domain`]) — the domain separators and the byte-exact builders
//!   the app signs and the engine verifies ([`challenge_message`], [`sign_callback_message`],
//!   [`user_sign_message`]), plus [`verify_signature`] and the [`SigningPublicKey`] / [`Signature`]
//!   newtypes. Three distinct purpose tags guarantee no signature minted for one purpose can be
//!   replayed as another (a cross-protocol signing oracle).
//! - **Frame + resource bounds** ([`bounds`]) — [`MAX_FRAME_BYTES`], [`MAX_INTERLEAVED_CALLBACKS`],
//!   [`MAX_PENDING_CANDIDATES`], and the advertised [`ENGINE_CAPABILITIES`].
//! - **The JSON-RPC 2.0 wire types** ([`wire`]) — the `control.session.*` method names, the request/
//!   response shapes, the `sign` callback shape, the envelope helpers, and the stable
//!   [`SignErrorCode`] taxonomy.
//! - **The seam traits + the two generic role-halves** — [`SessionSigner`], [`SignPolicy`],
//!   [`FrameTransport`], [`DidSigningKeyResolver`], [`SessionEntropy`]; the app-side [`SessionClient`]
//!   and the engine-side [`EngineSessionRegistry`]. Consumers implement the seams; the role-halves are
//!   the shared protocol logic. Test doubles ([`LineTransport`], [`OsEntropy`], [`AllowAllSignPolicy`],
//!   [`DenyAllSignPolicy`]) ship with the crate.
//!
//! ## Custody boundary
//!
//! The user's private key never crosses the IPC channel: the app signs in-process behind the
//! [`SessionSigner`] seam and returns only a signature. The engine holds no user key — it only
//! [`verify_signature`]s. The [`SignPolicy`] is a mandatory custody gate (no default-allow) because the
//! engine chooses the callback payload; blind-signing whatever the engine asks would let a compromised
//! engine mint arbitrary signatures with the user's key.
//!
//! It is a LEAF crate: no `dig-*` dependencies, so both consumers can depend on it freely.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bounds;
pub mod client;
pub mod domain;
pub mod engine;
pub mod signer;
#[cfg(test)]
mod test_support;
pub mod transport;
pub mod wire;

pub use bounds::{
    ENGINE_CAPABILITIES, MAX_FRAME_BYTES, MAX_INTERLEAVED_CALLBACKS, MAX_PENDING_CANDIDATES,
};
pub use client::{Session, SessionClient, SessionError, SessionRegistry};
pub use domain::{
    challenge_message, sign_callback_message, user_sign_message, verify_signature, Signature,
    SigningPublicKey, NONCE_LEN, SESSION_CHALLENGE_DOMAIN, SIGNATURE_LEN, SIGNING_KEY_LEN,
    SIGN_CALLBACK_DOMAIN, USER_SIGN_DOMAIN,
};
pub use engine::{AttachError, EngineSessionRegistry};
pub use signer::{
    AllowAllSignPolicy, DenyAllSignPolicy, DidSigningKeyResolver, SessionSigner, SignDecision,
    SignPolicy, SignRequest,
};
pub use transport::{FrameTransport, LineTransport, OsEntropy, SessionEntropy};
pub use wire::{
    AttachParams, AttachResult, BeginParams, BeginResult, DetachParams, DetachResult,
    IncomingFrame, ProfileAttachment, RpcError, RpcErrorReply, RpcRequest, RpcResult,
    SignCallbackParams, SignCallbackResult, SignErrorCode, JSONRPC_VERSION, METHOD_ATTACH,
    METHOD_BEGIN, METHOD_DETACH, METHOD_SIGN,
};
