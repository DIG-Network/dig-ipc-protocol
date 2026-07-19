# dig-ipc-protocol

The canonical **dig-app ⇄ dig-node** IPC session/signing contract. One ecosystem definition of the
local IPC channel between the branded user app (the identity holder) and the identity-agnostic engine,
so the two can never silently drift. Leaf crate — no `dig-*` dependencies.

- **License:** Apache-2.0 OR MIT
- **Spec:** [`SPEC.md`](./SPEC.md) (normative) — this README is the at-a-glance interface reference.

```toml
[dependencies]
dig-ipc-protocol = "0.1"
```

The app's private identity key (`dig-identity` slot `0x0010`, Ed25519) NEVER crosses the channel: the
app signs a domain-separated message in-process and returns only the detached signature; the engine
holds no key and only verifies.

---

## Full interface reference

### Constants

| Name | Type | Value |
|---|---|---|
| `SESSION_CHALLENGE_DOMAIN` | `&[u8]` | `b"DIGNET-SESSION-v1"` |
| `SIGN_CALLBACK_DOMAIN` | `&[u8]` | `b"DIGNET-SIGN-v1"` |
| `USER_SIGN_DOMAIN` | `&[u8]` | `b"DIGNET-USER-SIGN-v1"` |
| `SIGNING_KEY_LEN` | `usize` | `32` |
| `SIGNATURE_LEN` | `usize` | `64` |
| `NONCE_LEN` | `usize` | `32` |
| `MAX_FRAME_BYTES` | `u64` | `1_048_576` (1 MiB) |
| `MAX_INTERLEAVED_CALLBACKS` | `usize` | `64` |
| `MAX_PENDING_CANDIDATES` | `usize` | `256` |
| `ENGINE_CAPABILITIES` | `&[&str]` | `["content.serve","content.fetch","sync","subscribe"]` |
| `JSONRPC_VERSION` | `&str` | `"2.0"` |
| `METHOD_BEGIN` | `&str` | `"control.session.begin"` |
| `METHOD_ATTACH` | `&str` | `"control.session.attach"` |
| `METHOD_DETACH` | `&str` | `"control.session.detach"` |
| `METHOD_SIGN` | `&str` | `"sign"` |

### Domain-separated message builders (byte-exact — app signs, engine verifies)

```rust
fn challenge_message(nonce: &[u8], profile_did: &str) -> Vec<u8>;
// DIGNET-SESSION-v1 ‖ nonce ‖ profile_did

fn sign_callback_message(payload_type: &str, payload: &[u8]) -> Option<Vec<u8>>;
// DIGNET-SIGN-v1 ‖ len16(payload_type) ‖ payload_type ‖ payload   (None if type > u16::MAX)

fn user_sign_message(message: &[u8]) -> Vec<u8>;
// DIGNET-USER-SIGN-v1 ‖ message

fn verify_signature(pk: &SigningPublicKey, message: &[u8], sig: &Signature) -> bool;
// Ed25519 verify_strict
```

Golden hex vectors (KATs):

```
DIGNET-SESSION-v1                 = 4449474e45542d53455353494f4e2d7631
DIGNET-SIGN-v1                    = 4449474e45542d5349474e2d7631
DIGNET-USER-SIGN-v1               = 4449474e45542d555345522d5349474e2d7631
sign_callback_message("spend","bundle-bytes")
                                  = 4449474e45542d5349474e2d7631 0005 7370656e64 62756e646c652d6279746573
user_sign_message("attest this")  = 4449474e45542d555345522d5349474e2d7631 6174746573742074686973
```

### Key/signature newtypes

```rust
struct SigningPublicKey([u8; 32]);   // slot 0x0010 Ed25519 public key
  fn new(bytes: [u8; 32]) -> Self
  fn as_bytes(&self) -> &[u8; 32]
  fn to_hex(&self) -> String
  fn from_hex(hex_str: &str) -> Option<Self>

struct Signature([u8; 64]);          // Ed25519 signature
  fn new(bytes: [u8; 64]) -> Self
  fn as_bytes(&self) -> &[u8; 64]
```

### Wire types (JSON-RPC 2.0 — field names ARE the contract)

| Method | Params | Result |
|---|---|---|
| `control.session.begin` | `BeginParams { profile_did: String, signing_pubkey_hex: String }` | `BeginResult { nonce_b64: String, session_candidate: String }` |
| `control.session.attach` | `AttachParams { session_candidate: String, signature_b64: String, profile: ProfileAttachment }` | `AttachResult { session_id: String, engine_capabilities: Vec<String> }` |
| `control.session.detach` | `DetachParams { session_id: String }` | `DetachResult {}` |
| `sign` (engine→app) | `SignCallbackParams { session_id, op_id, payload_type, payload_b64, context: Option<Value> }` | `SignCallbackResult { signature_b64: String, pubkey_hex: String }` |

```rust
struct ProfileAttachment { did: String, subscriptions: Vec<String>, config_digest: String }

// Envelope helpers
struct RpcRequest<'a, P> { jsonrpc: &'static str, id: u64, method: &'a str, params: P }
struct RpcResult<'a, V>  { jsonrpc: &'static str, id: &'a Value, result: V }
struct RpcErrorReply<'a> { jsonrpc: &'static str, id: &'a Value, error: RpcError }
struct RpcError { code: i64, message: String }
struct IncomingFrame { id: Option<Value>, method: Option<String>, params: Option<Value>,
                       result: Option<Value>, error: Option<RpcError> }  // parses both directions
```

### Error taxonomy — `SignErrorCode`

```rust
enum SignErrorCode { AuthRequired, BadMac, Replay, PairDenied, ConnectRequired,
                     SignDenied, NoConfirmer, Locked }
  fn symbol(self) -> &'static str      // sent as the JSON-RPC error `message`
  fn code(self) -> i64                 // numeric application-range code
  fn to_rpc_error(self) -> RpcError
```

| Symbol | Code | Meaning |
|---|---|---|
| `AUTH_REQUIRED` | -33001 | Unpaired / revoked / unknown candidate / unknown DID. |
| `BAD_MAC` | -33002 | Bad attach signature or advertised-key ≠ DID's published key. |
| `REPLAY` | -33003 | Frame nonce not strictly greater than the last accepted. |
| `PAIR_DENIED` | -33010 | Pairing confirm denied. |
| `CONNECT_REQUIRED` | -33020 | Origin not connected/whitelisted. |
| `SIGN_DENIED` | -33030 | Sign request denied (policy or user). |
| `NO_CONFIRMER` | -33034 | No confirmer available (headless — fail closed). |
| `LOCKED` | -33040 | Active profile locked; no key to sign with. |

### Seam traits (the consumer implements; the crate defines)

```rust
trait SessionSigner {                                    // app: the unlocked identity
    fn signing_public_key(&self) -> SigningPublicKey;
    fn sign(&self, message: &[u8]) -> Signature;
    fn try_sign(&self, message: &[u8]) -> Option<Signature> { Some(self.sign(message)) }
    fn signing_public_key_hex(&self) -> String { self.signing_public_key().to_hex() }
}

trait SignPolicy {                                       // app: mandatory custody gate (no default-allow)
    fn authorize(&self, request: &SignRequest<'_>) -> SignDecision;
}

trait DidSigningKeyResolver {                            // engine: DID → published key backstop
    fn resolve_signing_key(&self, profile_did: &str) -> Option<SigningPublicKey>;
}

trait FrameTransport {                                   // both: newline-delimited JSON frames
    fn send_frame(&mut self, frame: &str) -> io::Result<()>;
    fn recv_frame(&mut self) -> io::Result<String>;
}

trait SessionEntropy {                                   // engine: challenge-nonce source
    fn fill_nonce(&self) -> [u8; 32];
}

struct SignRequest<'a> { session_id: &'a str, op_id: &'a str, payload_type: &'a str,
                         payload: &'a [u8], context: Option<&'a Value> }
enum SignDecision { Allow, Deny(String) }
```

Shipped implementations / test doubles: `LineTransport<R, W>` (over any reader/writer),
`OsEntropy` (OS CSPRNG), `AllowAllSignPolicy`, `DenyAllSignPolicy`.

### Role-halves

```rust
// App side — drives begin→attach, services `sign` callbacks, detaches, re-attaches.
struct SessionClient<T: FrameTransport, S: SessionSigner, P: SignPolicy>;
  fn new(transport: T, signer: S, policy: P) -> Self
  fn begin_and_attach(&mut self, profile: ProfileAttachment) -> Result<Session, SessionError>
  fn detach(&mut self, session: &Session) -> Result<(), SessionError>
  fn reattach(&mut self, transport: T, profile: ProfileAttachment) -> Result<Session, SessionError>
  fn handle_next_sign_callback(&mut self) -> Result<SignDecision, SessionError>

struct Session { session_id: String, engine_capabilities: Vec<String>, profile_did: String }

struct SessionRegistry;   // app's DID → Session map (multi-session)
  fn new() / insert(Session) / get(&str) -> Option<&Session>
  fn remove(&str) -> Option<Session> / len() / is_empty()

enum SessionError { Io, Frame, Engine { code, message }, IdMismatch,
                    MalformedResponse, NotASignCallback, TooManyCallbacks }

// Engine side — mints challenges, verifies attach, tracks sessions. Holds NO user key.
struct EngineSessionRegistry<E: SessionEntropy, R: DidSigningKeyResolver>;
  fn new(entropy: E, resolver: R) -> Self
  fn begin(&mut self, params: &BeginParams) -> Result<BeginResult, AttachError>
  fn attach(&mut self, params: &AttachParams) -> Result<AttachResult, AttachError>
  fn detach(&mut self, session_id: &str) -> bool
  fn session(&self, session_id: &str) -> Option<&ProfileAttachment>
  fn open_sessions(&self) -> usize / pending_candidates(&self) -> usize

enum AttachError { UnknownCandidate, UnknownDid, KeyMismatch, BadSignature, Malformed(String) }
  fn error_code(&self) -> SignErrorCode
  fn to_rpc_error(&self) -> RpcError
```

## Handshake, at a glance

1. App → `begin { profile_did, signing_pubkey_hex }` → engine mints nonce + candidate.
2. App signs `challenge_message(nonce, profile_did)` with the in-memory key.
3. App → `attach { session_candidate, signature_b64, profile }`. Engine consumes the candidate,
   checks the DID's published key == advertised key, verifies the signature, opens the session.
4. Engine → `sign { session_id, op_id, payload_type, payload_b64, context? }`. App gates via
   `SignPolicy`, signs `sign_callback_message(payload_type, payload)`, returns `{ signature_b64,
   pubkey_hex }` — never the key.
5. App → `detach { session_id }` on logout / switch / exit.

## Security invariants

Private key never on the wire · every signature domain-separated · `SignPolicy` mandatory (no
default-allow) · single-use candidates + DID→key backstop · `verify_strict` · §bounds enforced both
sides. See [`SPEC.md`](./SPEC.md) §6.
