//! A size limit for HTTP/3 frames other than DATA. The h3 crate reads a whole HEADERS frame (or a
//! frame of an unknown type) into memory before it looks at its size, and reading it out of QUIC
//! opens the flow-control window again, so one client could make the server buffer any amount.
//! These wrappers of the h3-quinn streams follow the frame boundaries of what the client sends and
//! end the stream as soon as a frame other than DATA announces more than the limit; request bodies
//! (DATA) and the QPACK streams' instructions flow as before.

use bytes::{Buf, Bytes};
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};
use std::task::{Context, Poll, ready};

/// H3_EXCESSIVE_LOAD (RFC 9114 §8.1): the peer is generating excessive load.
const EXCESSIVE_LOAD: u64 = 0x0107;
/// Unidirectional stream types (RFC 9114 §6.2, RFC 9204 §4.2).
const CONTROL_STREAM: u64 = 0x00;

/// A QUIC connection whose streams carry at most `limit` bytes in any frame other than DATA.
pub struct Connection {
    inner: h3_quinn::Connection,
    limit: u64,
}

impl Connection {
    pub fn new(conn: quinn::Connection, limit: u64) -> Connection {
        Connection {
            inner: h3_quinn::Connection::new(conn),
            limit,
        }
    }
}

impl<B: Buf> quic::Connection<B> for Connection {
    type RecvStream = RecvStream;
    type OpenStreams = OpenStreams;

    fn poll_accept_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        let stream = ready!(quic::Connection::<B>::poll_accept_recv(&mut self.inner, cx))?;
        Poll::Ready(Ok(RecvStream::new(stream, Frames::unidirectional(self.limit))))
    }

    fn poll_accept_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        let stream = ready!(quic::Connection::<B>::poll_accept_bidi(&mut self.inner, cx))?;
        Poll::Ready(Ok(BidiStream::new(stream, self.limit)))
    }

    fn opener(&self) -> Self::OpenStreams {
        OpenStreams {
            inner: quic::Connection::<B>::opener(&self.inner),
            limit: self.limit,
        }
    }
}

impl<B: Buf> quic::OpenStreams<B> for Connection {
    type BidiStream = BidiStream<B>;
    type SendStream = h3_quinn::SendStream<B>;

    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        let stream = ready!(quic::OpenStreams::<B>::poll_open_bidi(&mut self.inner, cx))?;
        Poll::Ready(Ok(BidiStream::new(stream, self.limit)))
    }

    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        quic::OpenStreams::<B>::close(&mut self.inner, code, reason)
    }
}

pub struct OpenStreams {
    inner: h3_quinn::OpenStreams,
    limit: u64,
}

impl<B: Buf> quic::OpenStreams<B> for OpenStreams {
    type BidiStream = BidiStream<B>;
    type SendStream = h3_quinn::SendStream<B>;

    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        let stream = ready!(quic::OpenStreams::<B>::poll_open_bidi(&mut self.inner, cx))?;
        Poll::Ready(Ok(BidiStream::new(stream, self.limit)))
    }

    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        quic::OpenStreams::<B>::close(&mut self.inner, code, reason)
    }
}

/// A request stream: frames from its first byte.
pub struct BidiStream<B: Buf> {
    send: h3_quinn::SendStream<B>,
    recv: RecvStream,
}

impl<B: Buf> BidiStream<B> {
    fn new(stream: h3_quinn::BidiStream<B>, limit: u64) -> BidiStream<B> {
        let (send, recv) = quic::BidiStream::split(stream);
        BidiStream {
            send,
            recv: RecvStream::new(recv, Frames::request(limit)),
        }
    }
}

impl<B: Buf> quic::BidiStream<B> for BidiStream<B> {
    type SendStream = h3_quinn::SendStream<B>;
    type RecvStream = RecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

impl<B: Buf> quic::RecvStream for BidiStream<B> {
    type Buf = Bytes;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code)
    }

    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

impl<B: Buf> quic::SendStream<B> for BidiStream<B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code)
    }

    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

pub struct RecvStream {
    inner: h3_quinn::RecvStream,
    frames: Frames,
}

impl RecvStream {
    fn new(inner: h3_quinn::RecvStream, frames: Frames) -> RecvStream {
        RecvStream { inner, frames }
    }
}

impl quic::RecvStream for RecvStream {
    type Buf = Bytes;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        let data = ready!(self.inner.poll_data(cx))?;
        if let Some(bytes) = &data
            && self.frames.feed(bytes).is_err()
        {
            self.inner.stop_sending(EXCESSIVE_LOAD);
            return Poll::Ready(Err(StreamErrorIncoming::StreamTerminated {
                error_code: EXCESSIVE_LOAD,
            }));
        }
        Poll::Ready(Ok(data))
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.inner.stop_sending(error_code)
    }

    fn recv_id(&self) -> StreamId {
        self.inner.recv_id()
    }
}

/// A frame other than DATA longer than the limit, or an unframed stream carrying more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLarge;

/// Where a stream is in its frames (RFC 9114 §7.1: type and length as QUIC varints, then payload).
#[derive(Debug)]
pub struct Frames {
    limit: u64,
    state: State,
    /// A varint being read and the bytes of it seen so far.
    varint: [u8; 8],
    have: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    /// A unidirectional stream: its type comes first.
    StreamType,
    FrameType,
    FrameLength {
        frame_type: u64,
    },
    Payload {
        remaining: u64,
    },
    /// Not framed (QPACK instructions, unknown stream types): at most `limit` bytes in all.
    Unframed {
        remaining: u64,
    },
}

impl Frames {
    pub fn request(limit: u64) -> Frames {
        Frames::starting(limit, State::FrameType)
    }

    pub fn unidirectional(limit: u64) -> Frames {
        Frames::starting(limit, State::StreamType)
    }

    fn starting(limit: u64, state: State) -> Frames {
        Frames {
            limit,
            state,
            varint: [0; 8],
            have: 0,
        }
    }

    /// Follows the frames through `data`; `Err` when a frame other than DATA is longer than the
    /// limit (or an unframed stream carries more).
    pub fn feed(&mut self, mut data: &[u8]) -> Result<(), TooLarge> {
        while !data.is_empty() {
            match self.state {
                State::Payload { remaining } | State::Unframed { remaining } => {
                    let unframed = matches!(self.state, State::Unframed { .. });
                    let taken = remaining.min(data.len() as u64);
                    if unframed && taken < data.len() as u64 {
                        return Err(TooLarge);
                    }
                    data = &data[taken as usize..];
                    let remaining = remaining - taken;
                    self.state = match (unframed, remaining) {
                        (true, remaining) => State::Unframed { remaining },
                        (false, 0) => State::FrameType,
                        (false, remaining) => State::Payload { remaining },
                    };
                }
                State::StreamType | State::FrameType | State::FrameLength { .. } => {
                    let Some(value) = self.varint(&mut data) else { continue };
                    self.state = match self.state {
                        State::StreamType if value == CONTROL_STREAM => State::FrameType,
                        State::StreamType => State::Unframed { remaining: self.limit },
                        State::FrameType => State::FrameLength { frame_type: value },
                        State::FrameLength { frame_type } => {
                            // DATA (0x0) is a request body; anything else is held whole by h3.
                            if frame_type != 0x0 && value > self.limit {
                                return Err(TooLarge);
                            }
                            if value == 0 {
                                State::FrameType
                            } else {
                                State::Payload { remaining: value }
                            }
                        }
                        other => other,
                    };
                }
            }
        }
        Ok(())
    }

    /// Takes bytes of a varint from `data`; its value once complete.
    fn varint(&mut self, data: &mut &[u8]) -> Option<u64> {
        while let Some((&byte, rest)) = data.split_first() {
            *data = rest;
            self.varint[self.have] = byte;
            self.have += 1;
            let size = 1usize << (self.varint[0] >> 6);
            if self.have == size {
                let mut value = u64::from(self.varint[0] & 0x3f);
                for &b in &self.varint[1..size] {
                    value = (value << 8) | u64::from(b);
                }
                self.have = 0;
                return Some(value);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A QUIC varint (RFC 9000 §16).
    fn varint(value: u64) -> Vec<u8> {
        match value {
            0..=63 => vec![value as u8],
            64..=16383 => (value as u16 | 0x4000).to_be_bytes().to_vec(),
            16384..=1_073_741_823 => (value as u32 | 0x8000_0000).to_be_bytes().to_vec(),
            _ => (value | 0xc000_0000_0000_0000).to_be_bytes().to_vec(),
        }
    }

    fn frame(frame_type: u64, payload_len: u64) -> Vec<u8> {
        let mut out = varint(frame_type);
        out.extend(varint(payload_len));
        out.extend(std::iter::repeat_n(b'x', payload_len as usize));
        out
    }

    #[test]
    fn data_frames_of_any_size_pass_and_large_headers_do_not() {
        let mut frames = Frames::request(100);
        let mut stream = frame(0x1, 100);
        stream.extend(frame(0x0, 100_000));
        stream.extend(frame(0x1, 40));
        // Byte by byte and in one piece: the same verdict.
        for chunk in stream.chunks(1) {
            frames.feed(chunk).unwrap();
        }
        Frames::request(100).feed(&stream).unwrap();

        let big = frame(0x1, 101);
        assert!(
            Frames::request(100).feed(&big[..4]).is_err(),
            "rejected by its length, before the payload"
        );
        // An unknown (reserved) frame type is held whole by h3 too.
        assert!(Frames::request(100).feed(&varint(0x21)).is_ok());
        let mut grease = varint(0x21);
        grease.extend(varint(1 << 20));
        assert!(Frames::request(100).feed(&grease).is_err());
    }

    #[test]
    fn control_stream_frames_and_qpack_streams_are_limited() {
        let mut control = varint(CONTROL_STREAM);
        control.extend(frame(0x4, 10));
        Frames::unidirectional(100).feed(&control).unwrap();
        let mut huge = varint(CONTROL_STREAM);
        huge.extend(varint(0x21));
        huge.extend(varint(5000));
        assert!(Frames::unidirectional(100).feed(&huge).is_err());

        // QPACK encoder stream (0x02): instructions, not frames — 100 bytes in all.
        let mut qpack = Frames::unidirectional(100);
        qpack.feed(&varint(0x02)).unwrap();
        qpack.feed(&[0u8; 60]).unwrap();
        qpack.feed(&[0u8; 40]).unwrap();
        assert!(qpack.feed(&[0u8; 1]).is_err());
    }
}
