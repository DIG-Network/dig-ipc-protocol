# Contributing to dig-ipc-protocol

Thanks for your interest in improving the canonical dig-app ⇄ dig-node IPC protocol.
This is a security-sensitive, signature-verification crate that defines the contract
between the branded user app (the identity holder) and the identity-agnostic engine —
please read this before opening a PR.

## Prerequisites

- [Rust](https://rustup.rs), stable toolchain (auto-selected by `rustup`)
  with `rustfmt` and `clippy` components.

## Build & test

```sh
# build the crate
cargo build

# run the full test suite
cargo test
```

## The gate (must pass before a PR is merged)

CI runs these on every PR (`.github/workflows/ci.yml`); run them locally first:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo build --release
cargo doc --no-deps
```

Coverage gate (≥80% lines, enforced in CI):

```sh
cargo llvm-cov nextest --all --retries 2 --fail-under-lines 80
```

## Commit conventions

- Use clear, imperative commit subjects following Conventional Commits format
  (e.g. `feat: …`, `fix: …`, `docs: …`, `test: …`).
- Keep one logical change per commit where practical.
- End every commit with a `Co-Authored-By: Claude <noreply@anthropic.com>` trailer
  when Claude helps author it.

## Where things live

This is a **leaf crate** — no `dig-*` dependencies, so both consumers can depend on it freely.

| Module | Responsibility |
|---|---|
| `domain` | Domain-separated message builders for signing/verification (challenge, sign-callback, user-sign) |
| `wire` | JSON-RPC 2.0 envelope types, the `control.session.*` methods, and the stable `SignErrorCode` taxonomy |
| `signer` | The `SessionSigner`, `SignPolicy`, `DidSigningKeyResolver` seam traits and test doubles |
| `transport` | The `FrameTransport` and `SessionEntropy` traits, plus `LineTransport` and `OsEntropy` implementations |
| `client` | The app-side `SessionClient` and `SessionRegistry` — drives begin→attach, services sign callbacks |
| `engine` | The engine-side `EngineSessionRegistry` — validates signatures, tracks sessions (holds no user key) |
| `bounds` | Frame size limits, max interleaved callbacks, pending candidate cap, and advertised engine capabilities |

## Security

This crate defines the security boundary between the identity-holding app and the
engine. Key invariants:

- **Private key never on the wire.** The app signs in-process and returns only
  the signature; the engine verifies but never signs.
- **Every signature is domain-separated.** Three distinct domains (challenge,
  sign-callback, user-sign) guarantee no signature can be replayed across purposes.
- **`SignPolicy` is mandatory and has no default-allow.** Blind-signing whatever
  the engine asks would let a compromised engine forge the user's signature.
- **Single-use challenge candidates** with DID→key backstop verification.

For anything security-relevant, read the `README.md` and `SPEC.md` first. Report
vulnerabilities privately to the maintainers rather than opening a public issue.

## Pull requests

1. Branch from `main`.
2. Make the gate green locally (all checks above must pass).
3. Open a PR with a clear description of the change and its rationale; reference
   any related issue. Keep the diff focused.
4. Bump the version in `Cargo.toml` as the last commit before merge (patch for
   docs/tests/chores, minor for new capability, major for breaking changes).
   Every PR requires a version increment (enforced in CI).
