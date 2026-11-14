//! What a protocol switch becomes (src/proxy.rs): the client's connection and the upstream's
//! joined, bytes copied both ways as they are until either side closes — or until the server ends
//! the tunnel itself (it stops, its configuration was reloaded and `stream_close_delay` is set
//! or the new one no longer names the tunnel's upstream, `stream_timeout` ran out).
//!
//! Nothing is read of what passes but, for WebSocket, where the frames begin (`Frames`: the frame
//! headers, never a payload). That is what lets the server say goodbye: when it ends a tunnel it
//! writes a Close frame (1001, going away) to each side that is between two frames, so that the
//! client knows a restart from a failure and comes back at once; a side that is in the middle of
//! a frame is only closed (a frame put there would be read as that frame's payload).
//!
//! Each tunnel counts what it copied and tells who ended it (`Closed`), for the access log's line
//! at its close (src/accesslog.rs), and is counted while open (`open`, and per upstream address
//! in src/upstreams.rs).

use crate::upstreams::Server;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// As tokio's `copy_bidirectional`: one buffer a direction.
const BUFFER: usize = 8 * 1024;

/// How long a goodbye may take: the Close frames written, and each side waited for to close.
const GOODBYE: Duration = Duration::from_secs(1);

/// WebSocket's "going away" (RFC 6455 §7.4.1): the server is going down, come back.
const GOING_AWAY: [u8; 2] = 1001u16.to_be_bytes();

static OPEN: AtomicUsize = AtomicUsize::new(0);

/// Tunnels open in the process now.
pub fn open() -> usize {
    OPEN.load(Ordering::Relaxed)
}

/// A tunnel counted as open, in the process and at its upstream address, until dropped.
pub(crate) struct Counted(Arc<Server>);

impl Counted {
    pub(crate) fn at(server: &Arc<Server>) -> Counted {
        OPEN.fetch_add(1, Ordering::Relaxed);
        server.tunnels.fetch_add(1, Ordering::Relaxed);
        Counted(server.clone())
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.0.tunnels.fetch_sub(1, Ordering::Relaxed);
        OPEN.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Who ended a tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// The client: its Close frame came first, or its connection closed or failed first.
    Client,
    /// The upstream, likewise.
    Upstream,
    /// The server stopped.
    Stop,
    /// The configuration was reloaded (`stream_close_delay`).
    Reload,
    /// A reload put a configuration in place that no longer names the tunnel's upstream.
    Removed,
    /// `stream_timeout` ran out.
    Timeout,
}

impl End {
    /// As the access log names it (`closed_by`).
    pub fn as_str(self) -> &'static str {
        match self {
            End::Client => "client",
            End::Upstream => "upstream",
            End::Stop => "stop",
            End::Reload => "reload",
            End::Removed => "upstream_removed",
            End::Timeout => "stream_timeout",
        }
    }
}

/// A tunnel's end: who ended it and what it carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closed {
    pub end: End,
    /// Bytes the client sent, as they went to the upstream.
    pub from_client: u64,
    /// Bytes that went to the client.
    pub to_client: u64,
}

/// Where the WebSocket frames of one direction begin, from their headers alone (RFC 6455 §5.2):
/// two bytes, then the longer forms of the length, then the mask key (counted with the payload).
#[derive(Default)]
struct Frames {
    /// Bytes of the frame under way still to pass: its mask key and payload.
    remaining: u64,
    /// Header bytes of the frame under way seen so far; 0 between frames.
    seen: u8,
    /// Bytes of the extended length still to come, and the length so far.
    more: u8,
    length: u64,
    masked: bool,
    /// A Close frame began: nothing follows it in this direction.
    closing: bool,
}

impl Frames {
    /// `bytes` passed, in the order sent, however they are cut.
    fn pass(&mut self, mut bytes: &[u8]) {
        while let Some((&byte, rest)) = bytes.split_first() {
            if self.remaining > 0 {
                let within = self.remaining.min(bytes.len() as u64);
                self.remaining -= within;
                bytes = &bytes[within as usize..];
                continue;
            }
            bytes = rest;
            match self.seen {
                0 => {
                    self.closing |= byte & 0x0f == 0x8;
                    self.seen = 1;
                }
                1 => {
                    self.masked = byte & 0x80 != 0;
                    match byte & 0x7f {
                        126 => self.extended(2),
                        127 => self.extended(8),
                        length => self.payload(u64::from(length)),
                    }
                }
                _ => {
                    self.length = self.length << 8 | u64::from(byte);
                    self.more -= 1;
                    if self.more == 0 {
                        self.payload(self.length);
                    }
                }
            }
        }
    }

    fn extended(&mut self, bytes: u8) {
        self.more = bytes;
        self.length = 0;
        self.seen = 2;
    }

    /// The header is whole: `length` bytes of payload follow, after the mask key.
    fn payload(&mut self, length: u64) {
        self.remaining = length.saturating_add(if self.masked { 4 } else { 0 });
        self.seen = 0;
    }

    /// Between two frames, none of them a Close: a Close frame may be put here.
    fn open_between(&self) -> bool {
        self.seen == 0 && self.remaining == 0 && !self.closing
    }
}

/// Which end of a direction failed.
enum Fault {
    Source,
    Sink,
}

/// One direction: what is read from its source is written to its sink, and the source's end is
/// passed on (the sink's write side is shut down).
struct Pipe {
    buffer: Box<[u8]>,
    /// The part of the buffer read and not yet written.
    at: usize,
    filled: usize,
    /// The source ended.
    ended: bool,
    /// And the sink was told.
    done: bool,
    unflushed: bool,
    copied: u64,
    /// WebSocket: where its frames begin, as written to the sink.
    frames: Option<Frames>,
}

impl Pipe {
    fn new(websocket: bool) -> Pipe {
        Pipe {
            buffer: vec![0u8; BUFFER].into_boxed_slice(),
            at: 0,
            filled: 0,
            ended: false,
            done: false,
            unflushed: false,
            copied: 0,
            frames: websocket.then(Frames::default),
        }
    }

    /// Copies while both ends are ready; `Ready(Ok)` once the source ended and the sink was told.
    fn poll<R, W>(&mut self, cx: &mut Context<'_>, source: &mut R, sink: &mut W) -> Poll<Result<(), Fault>>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            if self.done {
                return Poll::Ready(Ok(()));
            }
            if self.at < self.filled {
                let written = ready!(Pin::new(&mut *sink).poll_write(cx, &self.buffer[self.at..self.filled]));
                let written = match written {
                    Ok(0) | Err(_) => return Poll::Ready(Err(Fault::Sink)),
                    Ok(written) => written,
                };
                if let Some(frames) = &mut self.frames {
                    frames.pass(&self.buffer[self.at..self.at + written]);
                }
                self.at += written;
                self.copied += written as u64;
                self.unflushed = true;
                continue;
            }
            if self.ended {
                // Flushes what was written, then ends the sink's write side.
                if ready!(Pin::new(&mut *sink).poll_shutdown(cx)).is_err() {
                    return Poll::Ready(Err(Fault::Sink));
                }
                self.done = true;
                return Poll::Ready(Ok(()));
            }
            let mut read = ReadBuf::new(&mut self.buffer);
            match Pin::new(&mut *source).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) => {
                    let filled = read.filled().len();
                    self.at = 0;
                    self.filled = filled;
                    self.ended = filled == 0;
                }
                Poll::Ready(Err(_)) => return Poll::Ready(Err(Fault::Source)),
                Poll::Pending => {
                    // Nothing more to write for now: what was written goes out.
                    if self.unflushed {
                        if ready!(Pin::new(&mut *sink).poll_flush(cx)).is_err() {
                            return Poll::Ready(Err(Fault::Sink));
                        }
                        self.unflushed = false;
                    }
                    return Poll::Pending;
                }
            }
        }
    }

    /// A Close frame may be written to this direction's sink: it is open, and between two frames.
    fn takes_close(&self) -> bool {
        !self.done && self.frames.as_ref().is_some_and(Frames::open_between)
    }

    fn closing(&self) -> bool {
        self.frames.as_ref().is_some_and(|frames| frames.closing)
    }
}

/// The two connections of a tunnel and its two directions.
struct Joined<C, U> {
    client: C,
    upstream: U,
    up: Pipe,
    down: Pipe,
    /// The side whose connection ended first.
    first: Option<End>,
    /// The side whose Close frame came first (WebSocket).
    said_close: Option<End>,
}

impl<C, U> Joined<C, U>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    /// Copies both ways; resolves with the side that ended the tunnel once both directions are
    /// done, or one of them failed.
    fn poll_copy(&mut self, cx: &mut Context<'_>) -> Poll<End> {
        let up = self.up.poll(cx, &mut self.client, &mut self.upstream);
        let down = self.down.poll(cx, &mut self.upstream, &mut self.client);
        if self.said_close.is_none() {
            self.said_close = match (self.up.closing(), self.down.closing()) {
                (true, _) => Some(End::Client),
                (false, true) => Some(End::Upstream),
                (false, false) => None,
            };
        }
        let failed = match (&up, &down) {
            (Poll::Ready(Err(Fault::Source)), _) | (_, Poll::Ready(Err(Fault::Sink))) => Some(End::Client),
            (Poll::Ready(Err(Fault::Sink)), _) | (_, Poll::Ready(Err(Fault::Source))) => Some(End::Upstream),
            _ => None,
        };
        if up.is_ready() {
            self.first.get_or_insert(End::Client);
        }
        if down.is_ready() {
            self.first.get_or_insert(End::Upstream);
        }
        if let Some(side) = failed {
            return Poll::Ready(self.said_close.or(self.first).unwrap_or(side));
        }
        if up.is_ready() && down.is_ready() {
            return Poll::Ready(self.said_close.or(self.first).unwrap_or(End::Client));
        }
        Poll::Pending
    }

    /// The server ends the tunnel: a Close frame to each side that can take one, each side's
    /// write end closed, and what a side still sends read and dropped until it closes too (closing
    /// with its bytes unread would reset the connection, and a reset may take the Close frame from
    /// the peer's buffer before it is read) — all within `GOODBYE`.
    async fn goodbye(&mut self) {
        let (to_client, to_upstream) = (self.down.takes_close(), self.up.takes_close());
        let both = async {
            tokio::join!(
                part(&mut self.client, to_client.then(|| close_frame(None))),
                part(&mut self.upstream, to_upstream.then(|| close_frame(Some(mask_key())))),
            );
        };
        let _ = tokio::time::timeout(GOODBYE, both).await;
    }
}

/// One side of a goodbye (`Joined::goodbye`).
async fn part<S: AsyncRead + AsyncWrite + Unpin>(side: &mut S, frame: Option<Vec<u8>>) {
    if let Some(frame) = frame
        && side.write_all(&frame).await.is_err()
    {
        return;
    }
    if side.shutdown().await.is_err() {
        return;
    }
    let mut dropped = [0u8; 512];
    while matches!(side.read(&mut dropped).await, Ok(read) if read > 0) {}
}

/// A Close frame with the status 1001; to a server (the upstream) it is masked with `key`, as
/// every frame of a client is (RFC 6455 §5.3).
fn close_frame(key: Option<[u8; 4]>) -> Vec<u8> {
    match key {
        None => vec![0x88, 0x02, GOING_AWAY[0], GOING_AWAY[1]],
        Some(key) => vec![
            0x88,
            0x82,
            key[0],
            key[1],
            key[2],
            key[3],
            GOING_AWAY[0] ^ key[0],
            GOING_AWAY[1] ^ key[1],
        ],
    }
}

/// A mask key, different on every call (the standard library's randomly keyed hasher).
fn mask_key() -> [u8; 4] {
    use std::hash::BuildHasher;
    let bits = std::hash::RandomState::new().hash_one(std::time::Instant::now());
    (bits as u32).to_be_bytes()
}

/// Runs a tunnel between `client` and `upstream` to its end: until either side closes, or `ours`
/// resolves — the server's own reason to end it (`End::Stop`, `Reload`, `Removed` or `Timeout`),
/// on which it says goodbye. `websocket`: the protocol switched to is WebSocket (its frames are followed).
pub(crate) async fn run<C, U>(client: C, upstream: U, websocket: bool, ours: impl Future<Output = End>) -> Closed
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut joined = Joined {
        client,
        upstream,
        up: Pipe::new(websocket),
        down: Pipe::new(websocket),
        first: None,
        said_close: None,
    };
    let (end, by_server) = {
        let copied = poll_fn(|cx| joined.poll_copy(cx));
        tokio::select! {
            biased;
            end = copied => (end, false),
            end = ours => (end, true),
        }
    };
    if by_server {
        joined.goodbye().await;
    }
    Closed {
        end,
        from_client: joined.up.copied,
        to_client: joined.down.copied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;

    /// A frame: `opcode` with FIN, `payload` bytes of zeros, masked or not.
    fn frame(opcode: u8, payload: usize, masked: bool) -> Vec<u8> {
        let mut out = vec![0x80 | opcode];
        let mask = if masked { 0x80 } else { 0 };
        match payload {
            0..=125 => out.push(mask | payload as u8),
            126..=65535 => {
                out.push(mask | 126);
                out.extend_from_slice(&(payload as u16).to_be_bytes());
            }
            _ => {
                out.push(mask | 127);
                out.extend_from_slice(&(payload as u64).to_be_bytes());
            }
        }
        if masked {
            out.extend_from_slice(&[1, 2, 3, 4]);
        }
        out.extend(std::iter::repeat_n(0u8, payload));
        out
    }

    #[test]
    fn frames_are_followed_however_the_bytes_are_cut() {
        let mut stream = Vec::new();
        for (payload, masked) in [
            (0, false),
            (5, true),
            (125, false),
            (126, true),
            (70_000, false),
            (0, true),
        ] {
            stream.extend(frame(0x2, payload, masked));
        }
        // Whole, byte by byte, and in uneven pieces: between frames at the end, never a Close.
        for step in [stream.len(), 1, 7, 4096] {
            let mut frames = Frames::default();
            for piece in stream.chunks(step) {
                frames.pass(piece);
            }
            assert!(frames.open_between(), "pieces of {step}");
        }
        // In the middle of a header, of a mask key and of a payload: not between frames.
        let one = frame(0x1, 300, true);
        for cut in [1, 2, 3, 5, 7, 8, 100, one.len() - 1] {
            let mut frames = Frames::default();
            frames.pass(&one[..cut]);
            assert!(!frames.open_between(), "cut at {cut}");
            frames.pass(&one[cut..]);
            assert!(frames.open_between(), "whole after a cut at {cut}");
        }
        // After a Close frame nothing may follow, whole or not.
        let mut frames = Frames::default();
        frames.pass(&frame(0x1, 3, false));
        frames.pass(&frame(0x8, 2, false));
        assert!(frames.closing && !frames.open_between());
    }

    #[test]
    fn close_frames_say_going_away() {
        assert_eq!(close_frame(None), [0x88, 0x02, 0x03, 0xe9]);
        let masked = close_frame(Some([0xa1, 0xb2, 0xc3, 0xd4]));
        assert_eq!(masked[..6], [0x88, 0x82, 0xa1, 0xb2, 0xc3, 0xd4]);
        assert_eq!([masked[6] ^ 0xa1, masked[7] ^ 0xb2], [0x03, 0xe9]);
        // Each is one whole frame to the tracker.
        for frame in [close_frame(None), masked] {
            let mut frames = Frames::default();
            frames.pass(&frame);
            assert!(frames.closing && frames.seen == 0 && frames.remaining == 0);
        }
    }

    async fn read_all(side: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
        let mut all = Vec::new();
        side.read_to_end(&mut all).await.unwrap();
        all
    }

    #[tokio::test]
    async fn bytes_are_copied_and_counted_and_the_first_to_close_is_named() {
        let (mut client, client_side) = tokio::io::duplex(1024);
        let (mut upstream, upstream_side) = tokio::io::duplex(1024);
        let tunnel = tokio::spawn(run(client_side, upstream_side, false, pending()));
        let sent: Vec<u8> = (0..50_000u32).map(|i| i as u8).collect();
        let (mut upstream_read, mut upstream_write) = tokio::io::split(&mut upstream);
        let echo = async {
            let mut got = vec![0u8; sent.len()];
            upstream_read.read_exact(&mut got).await.unwrap();
            upstream_write.write_all(b"answer").await.unwrap();
            got
        };
        let (written, got) = tokio::join!(client.write_all(&sent), echo);
        written.unwrap();
        assert_eq!(got, sent);
        let mut answer = [0u8; 6];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"answer");
        // The upstream closes its side: the client reads the end, and closing too ends the tunnel.
        upstream_write.shutdown().await.unwrap();
        assert!(read_all(&mut client).await.is_empty());
        client.shutdown().await.unwrap();
        let closed = tunnel.await.unwrap();
        assert_eq!(
            closed,
            Closed {
                end: End::Upstream,
                from_client: 50_000,
                to_client: 6
            }
        );
    }

    #[tokio::test]
    async fn the_side_whose_close_frame_came_first_ended_it() {
        let (mut client, client_side) = tokio::io::duplex(1024);
        let (mut upstream, upstream_side) = tokio::io::duplex(1024);
        let tunnel = tokio::spawn(run(client_side, upstream_side, true, pending()));
        // The client says Close; the server answers and, as servers do, closes first.
        let close = frame(0x8, 2, true);
        client.write_all(&close).await.unwrap();
        let mut got = vec![0u8; close.len()];
        upstream.read_exact(&mut got).await.unwrap();
        upstream.write_all(&frame(0x8, 2, false)).await.unwrap();
        upstream.shutdown().await.unwrap();
        assert_eq!(read_all(&mut client).await, frame(0x8, 2, false));
        client.shutdown().await.unwrap();
        assert_eq!(tunnel.await.unwrap().end, End::Client);
    }

    #[tokio::test]
    async fn the_server_says_goodbye_between_frames_only() {
        // Between frames on both sides: each gets a Close frame, the upstream's masked.
        let (mut client, client_side) = tokio::io::duplex(1024);
        let (mut upstream, upstream_side) = tokio::io::duplex(1024);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let ours = async {
            let _ = stopped.await;
            End::Stop
        };
        let tunnel = tokio::spawn(run(client_side, upstream_side, true, ours));
        let message = frame(0x1, 10, false);
        upstream.write_all(&message).await.unwrap();
        let mut got = vec![0u8; message.len()];
        client.read_exact(&mut got).await.unwrap();
        stop.send(()).unwrap();
        assert_eq!(read_all(&mut client).await, close_frame(None));
        let to_upstream = read_all(&mut upstream).await;
        assert_eq!(to_upstream.len(), 8);
        assert_eq!(to_upstream[..2], [0x88, 0x82]);
        let key = &to_upstream[2..6];
        assert_eq!([to_upstream[6] ^ key[0], to_upstream[7] ^ key[1]], GOING_AWAY);
        drop((client, upstream));
        let closed = tunnel.await.unwrap();
        assert_eq!((closed.end, closed.to_client), (End::Stop, message.len() as u64));

        // The client in the middle of a frame from the upstream: it is only closed; the upstream,
        // which sent nothing whole to break, still gets its Close frame.
        let (mut client, client_side) = tokio::io::duplex(1024);
        let (mut upstream, upstream_side) = tokio::io::duplex(1024);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let ours = async {
            let _ = stopped.await;
            End::Timeout
        };
        let tunnel = tokio::spawn(run(client_side, upstream_side, true, ours));
        let whole = frame(0x2, 100, false);
        let half = &whole[..40];
        upstream.write_all(half).await.unwrap();
        let mut got = vec![0u8; half.len()];
        client.read_exact(&mut got).await.unwrap();
        stop.send(()).unwrap();
        assert!(read_all(&mut client).await.is_empty(), "no frame inside a frame");
        assert_eq!(read_all(&mut upstream).await.len(), 8);
        drop((client, upstream));
        assert_eq!(tunnel.await.unwrap().end, End::Timeout);

        // Another protocol than WebSocket: closed, nothing written.
        let (mut client, client_side) = tokio::io::duplex(1024);
        let (mut upstream, upstream_side) = tokio::io::duplex(1024);
        let tunnel = tokio::spawn(run(client_side, upstream_side, false, async { End::Reload }));
        assert!(read_all(&mut client).await.is_empty());
        assert!(read_all(&mut upstream).await.is_empty());
        drop((client, upstream));
        assert_eq!(tunnel.await.unwrap().end, End::Reload);
    }

    #[tokio::test]
    async fn a_side_that_does_not_close_is_not_waited_for_beyond_the_goodbye() {
        let (mut client, client_side) = tokio::io::duplex(1024);
        let (_upstream, upstream_side) = tokio::io::duplex(1024);
        let started = std::time::Instant::now();
        let closed = run(client_side, upstream_side, true, async { End::Stop }).await;
        assert_eq!(closed.end, End::Stop);
        assert!(started.elapsed() < GOODBYE + Duration::from_secs(2));
        assert_eq!(read_all(&mut client).await, close_frame(None));
    }
}
