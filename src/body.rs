//! Request and response bodies: one type for files from memory, proxied streams and compressed
//! streams, whatever the protocol (HTTP/1.1, HTTP/2, HTTP/3). Bytes known at once (a file from
//! memory, a ready answer, `respond`) and no body at all are held as they are; only a stream is
//! boxed, so a ready answer's body costs no allocation.

use bytes::Bytes;
use http_body::{Frame, SizeHint};
use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody;
use std::pin::Pin;
use std::task::{Context, Poll};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub struct Body(Kind);

enum Kind {
    Empty,
    /// Sent whole as one frame; `None` once it was.
    Full(Option<Bytes>),
    Stream(UnsyncBoxBody<Bytes, BoxError>),
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Kind::Empty => f.write_str("Body::Empty"),
            Kind::Full(bytes) => write!(f, "Body::Full({} bytes)", bytes.as_ref().map_or(0, Bytes::len)),
            Kind::Stream(_) => f.write_str("Body::Stream"),
        }
    }
}

pub fn full(bytes: impl Into<Bytes>) -> Body {
    let bytes = bytes.into();
    // As http-body-util's `Full`: an empty buffer is no frame at all.
    Body(if bytes.is_empty() {
        Kind::Empty
    } else {
        Kind::Full(Some(bytes))
    })
}

pub fn empty() -> Body {
    Body(Kind::Empty)
}

/// Any body whose errors convert into `BoxError` (hyper's `Incoming`, encoders…).
pub fn boxed<B>(body: B) -> Body
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    Body(Kind::Stream(body.map_err(Into::into).boxed_unsync()))
}

impl http_body::Body for Body {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match &mut self.get_mut().0 {
            Kind::Empty => Poll::Ready(None),
            Kind::Full(bytes) => Poll::Ready(bytes.take().map(|bytes| Ok(Frame::data(bytes)))),
            Kind::Stream(stream) => Pin::new(stream).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.0 {
            Kind::Empty => true,
            Kind::Full(bytes) => bytes.is_none(),
            Kind::Stream(stream) => stream.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.0 {
            Kind::Empty => SizeHint::with_exact(0),
            Kind::Full(bytes) => SizeHint::with_exact(bytes.as_ref().map_or(0, |b| b.len() as u64)),
            Kind::Stream(stream) => stream.size_hint(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body::Body as _;

    #[tokio::test]
    async fn bodies_give_their_bytes_and_sizes() {
        let body = full("hello");
        assert_eq!(body.size_hint().exact(), Some(5));
        assert!(!body.is_end_stream());
        assert_eq!(&body.collect().await.unwrap().to_bytes()[..], b"hello");
        let body = full(Bytes::new());
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(empty().is_end_stream());
        let stream = boxed(http_body_util::Full::new(Bytes::from_static(b"abc")));
        assert_eq!(stream.size_hint().exact(), Some(3));
        assert_eq!(&stream.collect().await.unwrap().to_bytes()[..], b"abc");
    }
}
