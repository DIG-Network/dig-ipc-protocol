# dig-ipc-protocol — normative specification

This document is the authoritative contract for the local IPC channel between **dig-app** (the branded
user application — the identity holder) and **dig-node** (the identity-agnostic engine). An independent
reimplementation of either side MUST conform to this specification byte-for-byte. Where this document
and the code disagree, the conformance KATs in `tests/conformance.rs` are the tie-breaker.

Layering: this file is the repo's own contract; the cross-repo interaction map is the superproject
`SYSTEM.md`; the app-side handshake narrative lives in dig-app `SPEC.md` §5.3. All three MUST agree.

## 1. Roles and trust boundary

- **App (client):** holds the user's private identity key (`dig-identity` slot `0x0010`, BLS12-381 G1).
  It proves possession of the key to the engine and, thereafter, signs engine-initiated operations
  in-process. The private key MUST NEVER be serialized onto the channel.
- **Engine (server):** holds NO user key. It mints challenges, verifies signatures, and tracks
  sessions. It cannot itself sign anything with the user's identity.
- **Channel:** a per-user, newline-delimited JSON-RPC 2.0 stream over an OS pipe / Unix domain socket.
  Both endpoints are local; the OS per-user ACL is the confidentiality boundary (ecosystem §5.4 — this
  channel moves only session-control frames and detached signatures, never recipient-directed content).

## 2. Domain-separated signed messages (byte-exact)

Every signature the slot-`0x0010` key produces MUST be over a domain-separated message. The three
purposes carry pairwise-distinct leading tags, so a signature minted for one purpose can never verify
as another (a cross-protocol signing oracle).

| Purpose | Domain tag (ASCII) | Message layout |
|---|---|---|
| Session attach | `DIGNET-SESSION-v1` | `DOMAIN ‖ nonce ‖ profile_did` |
| Engine `sign` callback | `DIGNET-SIGN-v1` | `DOMAIN ‖ len16(payload_type) ‖ payload_type ‖ payload` |
| User `dign sign` | `DIGNET-USER-SIGN-v1` | `DOMAIN ‖ message` |

- `nonce` is exactly `NONCE_LEN` (32) bytes.
- `len16(x)` is the big-endian `u16` byte length of `x`; `payload_type` longer than `u16::MAX` bytes is
  a protocol error and MUST be rejected before signing (the builder returns `None`).
- `profile_did`, `payload_type`, `message` are UTF-8 byte sequences.
- Signatures are BLS12-381 AugScheme (G2), `SIGNATURE_LEN` (96) bytes, verified against a
  `SIGNING_KEY_LEN` (48)-byte compressed G1 public key; malformed key/signature bytes fail closed
  (never panic).

Golden vectors (KATs, `tests/conformance.rs`) — all hex:

```
DIGNET-SESSION-v1                 = 4449474e45542d53455353494f4e2d7631
DIGNET-SIGN-v1                    = 4449474e45542d5349474e2d7631
DIGNET-USER-SIGN-v1               = 4449474e45542d555345522d5349474e2d7631
challenge_message(nonce,did)      = 4449474e45542d53455353494f4e2d7631 ‖ <nonce32> ‖ 6469643a636869613a636f6e666f726d616e6365
sign_callback_message("spend",…)  = 4449474e45542d5349474e2d7631 0005 7370656e64 62756e646c652d6279746573
user_sign_message("attest this")  = 4449474e45542d555345522d5349474e2d7631 6174746573742074686973
```

## 3. Wire protocol (JSON-RPC 2.0)

All frames carry `"jsonrpc":"2.0"` and are exactly one line of JSON (the newline is the framing). The
app assigns integer `id`s to its requests; the engine echoes the `id` of the request it answers.

### 3.1 `control.session.begin` (app → engine)

Request `params`: `{ profile_did: string, signing_pubkey_hex: string }` (lowercase hex, 48 bytes).
Result: `{ nonce_b64: string, session_candidate: string }` — the nonce (base64) to sign and an opaque
single-use candidate token. The app MUST reject a decoded nonce that is not exactly `NONCE_LEN` (32)
bytes (`InvalidNonceLength`) BEFORE signing the challenge: the fixed-length nonce is what makes the
`DOMAIN ‖ nonce ‖ profile_did` concatenation an unambiguous parse without a delimiter, so a
wrong-length nonce is never signed over.

### 3.2 `control.session.attach` (app → engine)

Request `params`: `{ session_candidate: string, signature_b64: string, profile: ProfileAttachment }`.
`ProfileAttachment = { did: string, subscriptions: string[], config_digest: string }`.
Result: `{ session_id: string, engine_capabilities: string[] }`.

The engine MUST: (a) consume the candidate (single-use — a second attach with the same candidate fails
`UNKNOWN`/`AUTH_REQUIRED`); (b) require `profile.did` to equal the DID from `begin`; (c) resolve the
DID's published slot-`0x0010` key and require it to equal the key advertised in `begin`
(`KeyMismatch`/`BAD_MAC` otherwise); (d) verify the challenge signature over
`challenge_message(nonce, profile.did)` (`BadSignature`/`BAD_MAC` otherwise); then open the session.

### 3.3 `control.session.detach` (app → engine)

Request `params`: `{ session_id: string }`. Result: `{}`. Detaching an unknown session is a no-op.

### 3.4 `sign` callback (engine → app, same connection)

The engine asks the app to sign an engine-initiated operation. Request `params`:
`{ session_id, op_id, payload_type, payload_b64, context? }`.
On approval the app replies `{ signature_b64, pubkey_hex }`, the signature over
`sign_callback_message(payload_type, payload)`. The reply MUST NOT contain the private key.
On denial / bad payload the app replies a JSON-RPC error (§5); the request is never signed. If the
active profile is locked when the app would sign, the app MUST reply `LOCKED` (§5) and MUST NOT frame a
success envelope carrying a bogus/all-zero fail-safe signature — signing fails CLOSED.

The callback is full-duplex with the handshake: a `sign` callback MAY arrive interleaved before a
handshake response, and both sides MUST service it in order.

## 4. Bounds

| Constant | Value | Purpose |
|---|---|---|
| `MAX_FRAME_BYTES` | 1 MiB | Reject a newline-less giant frame (OOM defense). |
| `MAX_INTERLEAVED_CALLBACKS` | 64 | App gives up if the engine floods callbacks without answering. |
| `MAX_PENDING_CANDIDATES` | 256 | Engine evicts the oldest un-attached candidate (state-growth defense). |
| `NONCE_LEN` | 32 | Attach-challenge nonce length. |
| `SIGNING_KEY_LEN` | 48 | BLS12-381 compressed G1 public-key length. |
| `SIGNATURE_LEN` | 96 | BLS12-381 compressed G2 AugScheme signature length. |
| `ENGINE_CAPABILITIES` | `["content.serve","content.fetch","sync","subscribe"]` | Default advertised set. |

## 5. Error taxonomy (APP-SIGN)

Each symbol is sent as the JSON-RPC error `message`; the numeric `code` is in an application range
(distinct from the JSON-RPC reserved `-32xxx` band). Renaming a symbol or renumbering a code is a
BREAKING protocol change.

| Symbol | Code | Meaning |
|---|---|---|
| `AUTH_REQUIRED` | -33001 | No valid pairing/authorization (unpaired / revoked / unknown candidate / unknown DID). |
| `BAD_MAC` | -33002 | Signature / MAC verification failed (bad attach signature or key mismatch). |
| `REPLAY` | -33003 | Frame nonce not strictly greater than the last accepted. |
| `PAIR_DENIED` | -33010 | Pairing confirm denied. |
| `CONNECT_REQUIRED` | -33020 | Origin not connected/whitelisted. |
| `SIGN_DENIED` | -33030 | Sign request denied (policy or user). |
| `NO_CONFIRMER` | -33034 | No confirmer available (headless — fail closed). |
| `LOCKED` | -33040 | Active profile locked; no key to sign with. |

## 6. Security invariants (MUST)

1. The private key never crosses the channel; the app returns only detached signatures + the pubkey.
2. Every identity-key signature is domain-separated; no purpose signs un-prefixed caller bytes.
3. The `SignPolicy` gate is mandatory — there is no default-allow for engine `sign` callbacks.
4. Attach candidates are single-use; the DID→published-key backstop binds the session to the DID.
5. Signature verification uses `verify_strict`.
6. Both sides enforce the §4 bounds.
