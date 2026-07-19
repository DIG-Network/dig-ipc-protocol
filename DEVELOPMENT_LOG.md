# DEVELOPMENT_LOG — dig-ipc-protocol

High-signal, durable realizations from developing this crate. Concise facts with context, not a
change diary.

## The fixed-length nonce IS the delimiter in the attach challenge (#4)

`challenge_message` builds `SESSION_CHALLENGE_DOMAIN ‖ nonce ‖ profile_did` with NO length delimiter
between fields. The fixed 32-byte (`NONCE_LEN`) nonce is precisely what keeps that concatenation an
unambiguous parse — a wrong-length nonce could shift the boundary and let `(nonce, did)` collide with
`(nonce', did')`. Two rules follow, and they pull in opposite directions:

- The **client MUST assert `nonce.len() == NONCE_LEN`** on the engine-supplied nonce, in
  `begin_and_attach`, BEFORE signing (rejects as `SessionError::InvalidNonceLength`). Enforcing the
  already-SPEC'd contract client-side means a malformed-length nonce is never signed over.
- The **builder `challenge_message` MUST NOT `debug_assert!` the nonce length.** It is a pure canonical
  byte-builder shared with the negative KATs — e.g. `challenge_message(b"other-nonce", DID)` in the
  domain-separation test deliberately feeds a non-32-byte nonce to prove distinct inputs yield distinct
  bytes. A `debug_assert!` there would panic those tests. Enforcement belongs at the trust boundary
  (the client, on wire input), not in the pure builder.
