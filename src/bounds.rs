//! Frame and resource bounds that keep each side of the IPC channel safe from a compromised or buggy
//! local peer, plus the engine's advertised capability set.
//!
//! The channel is a per-user pipe/socket between the app and the engine on the same host. Both sides
//! are local, but the trust boundary is real: a compromised engine must not be able to OOM the app
//! with a giant frame or wedge it in an endless callback stream, and a hostile app must not be able to
//! exhaust the engine with unbounded pending handshake state. These constants bound every such vector.

/// The largest single IPC frame a line transport will read (1 MiB). Session-control frames and a
/// detached signature are tiny; even a spend/SMT payload in a `sign` callback is far under this. The
/// cap bounds a compromised peer's ability to OOM its counterpart with a newline-less giant frame.
pub const MAX_FRAME_BYTES: u64 = 1024 * 1024;

/// The most engine `sign` callbacks the [`SessionClient`](crate::SessionClient) will service while
/// awaiting a single handshake response before giving up. Bounds a compromised engine that would
/// otherwise wedge the app in an endless callback stream instead of answering the request.
pub const MAX_INTERLEAVED_CALLBACKS: usize = 64;

/// The most outstanding session candidates the [`EngineSessionRegistry`](crate::EngineSessionRegistry)
/// will hold between `begin` and `attach` before it starts evicting the oldest. Bounds a hostile app
/// that floods `begin`s (each mints a nonce + candidate) without ever attaching, which would otherwise
/// grow the engine's pending-candidate map without limit.
pub const MAX_PENDING_CANDIDATES: usize = 256;

/// The capabilities the engine advertises to an attached session (`attach` → `engine_capabilities`).
/// The app keys which operations it may drive off this set. Canonical default set; an engine MAY
/// advertise a superset, and the app MUST tolerate capabilities it does not recognize.
pub const ENGINE_CAPABILITIES: &[&str] = &["content.serve", "content.fetch", "sync", "subscribe"];
