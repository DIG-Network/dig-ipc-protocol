//! The transport and entropy seams: how a role-half moves JSON frames, and where the engine gets its
//! challenge nonces. Both are traits so the protocol logic is transport-agnostic and unit-testable;
//! the crate ships production and test implementations of each.

use std::io::{self, BufRead, BufReader, Read, Write};

use crate::bounds::MAX_FRAME_BYTES;
use crate::domain::NONCE_LEN;

/// A newline-delimited JSON-RPC frame transport — the per-user named pipe / Unix domain socket
/// abstracted so the protocol logic is transport-agnostic and unit-testable. Each frame is one line of
/// JSON; the newline is the framing.
pub trait FrameTransport {
    /// Send one JSON frame (the implementation appends the newline and flushes).
    fn send_frame(&mut self, frame: &str) -> io::Result<()>;

    /// Receive one JSON frame (a single line, newline stripped). A closed channel surfaces as
    /// [`io::ErrorKind::UnexpectedEof`] — the signal a role-half treats as a dropped pipe.
    fn recv_frame(&mut self) -> io::Result<String>;
}

/// A [`FrameTransport`] over any byte-stream reader/writer pair — a `UnixStream` (with a `try_clone`d
/// half), a Windows named-pipe handle, or an in-memory duplex in tests. The read half is buffered so
/// framing is cheap; the write half is flushed after every frame so the peer sees requests promptly.
pub struct LineTransport<R: Read, W: Write> {
    reader: BufReader<R>,
    writer: W,
}

impl<R: Read, W: Write> LineTransport<R, W> {
    /// Build a transport from an already-connected reader and writer (typically the two halves of one
    /// duplex stream).
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
        }
    }
}

impl<R: Read, W: Write> FrameTransport for LineTransport<R, W> {
    fn send_frame(&mut self, frame: &str) -> io::Result<()> {
        self.writer.write_all(frame.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }

    fn recv_frame(&mut self) -> io::Result<String> {
        // Read one newline-delimited frame, but NEVER more than MAX_FRAME_BYTES: the peer is local,
        // but a compromised or buggy one could otherwise stream a newline-less multi-GB "frame" and
        // OOM this process. Cap the read and reject an over-long frame instead.
        let mut buf = Vec::new();
        let read = (&mut self.reader)
            .take(MAX_FRAME_BYTES)
            .read_until(b'\n', &mut buf)?;
        if read == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        if buf.last() != Some(&b'\n') && buf.len() as u64 >= MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer frame exceeds the maximum size",
            ));
        }
        let text = String::from_utf8(buf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "peer frame is not UTF-8"))?;
        Ok(text.trim_end_matches(['\n', '\r']).to_string())
    }
}

/// The source of session-challenge nonces the engine mints on `begin`. A seam so tests can pin a
/// deterministic nonce while production draws from the OS CSPRNG ([`OsEntropy`]).
pub trait SessionEntropy {
    /// Fill a fresh [`NONCE_LEN`]-byte challenge nonce. Each call MUST return an independent,
    /// unpredictable value — a repeated or guessable nonce would let an attacker precompute or replay
    /// an attach signature.
    fn fill_nonce(&self) -> [u8; NONCE_LEN];
}

/// The production [`SessionEntropy`]: draws each nonce from the operating-system CSPRNG.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl SessionEntropy for OsEntropy {
    fn fill_nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).expect("the OS CSPRNG must be available to mint a nonce");
        nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn line_transport_round_trips_frames_over_a_byte_stream() {
        let reader = Cursor::new(b"{\"a\":1}\n{\"b\":2}\n".to_vec());
        let mut transport = LineTransport::new(reader, Vec::<u8>::new());
        assert_eq!(transport.recv_frame().unwrap(), r#"{"a":1}"#);
        assert_eq!(transport.recv_frame().unwrap(), r#"{"b":2}"#);
        assert_eq!(
            transport.recv_frame().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        transport.send_frame(r#"{"c":3}"#).unwrap();
        assert_eq!(transport.writer, b"{\"c\":3}\n");
    }

    #[test]
    fn line_transport_rejects_an_oversized_frame_instead_of_oom() {
        let giant = vec![b'x'; (MAX_FRAME_BYTES + 16) as usize];
        let mut transport = LineTransport::new(Cursor::new(giant), Vec::<u8>::new());
        assert_eq!(
            transport.recv_frame().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn os_entropy_yields_distinct_nonces() {
        let e = OsEntropy;
        assert_ne!(e.fill_nonce(), e.fill_nonce());
    }
}
