//! HTTP/3 over QUIC (quinn + h3): each request stream goes through the same handler as HTTP/1.1
//! and HTTP/2; request bodies are read and response bodies sent as they are produced.
//!
//! 0-RTT: a client resuming a session may send requests before the handshake completes, and the
//! answers go out at once (0.5-RTT). Tickets are single-use (src/tls.rs), so a captured ClientHello
//! cannot be replayed against this process; still, a request accepted before the handshake is
//! confirmed is answered only if it is safe (GET, HEAD, OPTIONS) and is passed on with
//! `Early-Data: 1`; anything else gets 425 Too Early and the browser repeats it after the handshake
//! (RFC 8470).

use crate::body::{Body, BoxError, boxed};
use crate::config::Limits;
use crate::guard::{Activity, Admission, Due, Permit, Tracked};
use crate::server::{ConnState, ServerState, handle_with_log};
use bytes::{Buf, Bytes};
use h3::server::{RequestResolver, RequestStream};
use http::header::{CONNECTION, DATE, HOST, TRANSFER_ENCODING, UPGRADE};
use http::{HeaderName, StatusCode};
use http::{HeaderValue, Method, Request, Response, Version};
use http_body::Frame;
use http_body_util::BodyExt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Instant;
use tokio::sync::watch;

/// With this many handshakes under way, clients whose address is not yet proven get a Retry first
/// (one more round trip for them; spoofed addresses never complete it, so they cost no handshake).
const RETRY_ABOVE: usize = 64;

pub async fn serve(
    endpoint: quinn::Endpoint,
    state: Arc<ServerState>,
    stop: watch::Receiver<bool>,
    limits: Limits,
    admission: Arc<Admission>,
) {
    let handshakes = Arc::new(AtomicUsize::new(0));
    // The server's stop, watched once here and passed on to the connections through a channel of
    // their own (as src/server.rs `accept_loop` does).
    let (local_stop, _) = watch::channel(false);
    let mut stopped = std::pin::pin!(async move {
        let mut stop = stop;
        while !*stop.borrow_and_update() {
            if stop.changed().await.is_err() {
                break;
            }
        }
    });
    loop {
        let incoming = tokio::select! {
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => break,
            },
            () = &mut stopped => {
                // No new connections; open ones are told to finish (GOAWAY) below.
                endpoint.set_server_config(None);
                local_stop.send_replace(true);
                break;
            }
        };
        if !incoming.remote_address_validated()
            && incoming.may_retry()
            && handshakes.load(Ordering::Acquire) >= RETRY_ABOVE
        {
            let _ = incoming.retry();
            continue;
        }
        let remote = incoming.remote_address();
        let remote = SocketAddr::new(remote.ip().to_canonical(), remote.port());
        let Some(permit) = admission.admit(remote.ip(), state.trusts(remote.ip())) else {
            tracing::debug!(%remote, "QUIC connection refused: too many open");
            incoming.refuse();
            continue;
        };
        let stop = local_stop.subscribe();
        let handshakes = handshakes.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let _permit: Permit = permit;
            if let Err(e) = connection(incoming, remote, state, stop, limits, handshakes).await {
                tracing::debug!(error = %e, "HTTP/3 connection ended with an error");
            }
        });
    }
}

/// Counts a handshake under way until dropped.
struct Handshake(Arc<AtomicUsize>);

impl Drop for Handshake {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

async fn connection(
    incoming: quinn::Incoming,
    remote: SocketAddr,
    state: Arc<ServerState>,
    mut stop: watch::Receiver<bool>,
    limits: Limits,
    handshakes: Arc<AtomicUsize>,
) -> Result<(), BoxError> {
    handshakes.fetch_add(1, Ordering::AcqRel);
    let handshake = Handshake(handshakes);
    // `confirmed`: the handshake has completed; until then requests are early data. With 0-RTT the
    // completion is awaited in the connection's own loop below, no task of its own.
    let (conn, accepted) = match incoming.accept()?.into_0rtt() {
        Ok((conn, accepted)) => (conn, Some(accepted)),
        Err(connecting) => (tokio::time::timeout(limits.read_header, connecting).await??, None),
    };
    let mut confirmed = accepted.is_none();
    let mut accepted = std::pin::pin!(async move {
        match accepted {
            Some(accepted) => {
                accepted.await;
            }
            None => std::future::pending().await,
        }
    });
    drop(handshake);
    // The name the handshake asked for, for the Host check (src/server.rs `misdirected`).
    let sni = conn
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.server_name);
    let served = state.connection_named(remote, sni.as_deref());
    let retire = state.retire(&served);
    let hints = served.may_hint();
    let quic = conn.clone();
    let activity = Activity::new();
    // Headers past `max_header_size` get 431 from h3; a frame may still hold them encoded.
    let mut h3 = h3::server::builder()
        .max_field_section_size(limits.max_header as u64)
        .build::<_, Bytes>(crate::h3limit::Connection::new(
            conn,
            limits.h3_frame.max(limits.max_header as u64),
        ))
        .await?;
    let mut stopping = *stop.borrow();
    if stopping {
        h3.shutdown(0).await?;
    }
    // Since when a graceful close of our own (idle, or WEB_RELOAD=drain) is under way.
    let mut closing: Option<Instant> = None;
    let mut retiring = std::pin::pin!(async move {
        match retire {
            Some(retire) => retire.due().await,
            None => std::future::pending().await,
        }
    });
    let mut retired = false;
    // One timer, set when a deadline is due and only when it changes (as src/guard.rs `drive`).
    let mut timer = std::pin::pin!(tokio::time::sleep_until(Instant::now().into()));
    let mut armed: Option<Instant> = None;
    loop {
        let due = match closing {
            Some(since) => Some((since + limits.grace, Due::Cut)),
            None if stopping => None,
            None => activity.next(&limits),
        };
        if let Some((when, _)) = due
            && armed != Some(when)
        {
            timer.as_mut().reset(when.into());
            armed = Some(when);
        }
        tokio::select! {
            accepted = h3.accept() => match accepted {
                Ok(Some(resolver)) => {
                    let served = served.clone();
                    let early = !confirmed;
                    let flight = activity.begin(Version::HTTP_3);
                    tokio::spawn(async move {
                        let _flight = flight;
                        if let Err(e) = request(resolver, served, early, hints, limits).await {
                            tracing::debug!(error = %e, "HTTP/3 request failed");
                        }
                    });
                }
                Ok(None) => break,
                Err(e) => {
                    if !e.is_h3_no_error() {
                        return Err(Box::new(e));
                    }
                    break;
                }
            },
            // 0-RTT: the handshake completed; requests from here on are not early data.
            () = &mut accepted, if !confirmed => confirmed = true,
            changed = stop.changed(), if !stopping => {
                stopping = true;
                if changed.is_ok() {
                    h3.shutdown(0).await?;
                }
            }
            // A reload left this connection on the old configuration: its moment to close.
            () = &mut retiring, if !retired && !stopping && closing.is_none() => {
                retired = true;
                closing = Some(Instant::now());
                h3.shutdown(0).await?;
            }
            // The last request ended: the idle clock starts; look again.
            () = activity.quiet() => {}
            () = &mut timer, if due.is_some() => {
                armed = None;
                match due {
                    Some((_, Due::Close)) if closing.is_none() => {
                        closing = Some(Instant::now());
                        h3.shutdown(0).await?;
                    }
                    Some((_, Due::Cut)) => {
                        quic.close(0u32.into(), b"idle");
                        break;
                    }
                    _ => {}
                }
            },
        }
        // Asked to finish (idle, or a reload with WEB_RELOAD=drain) and no request left: closed now
        // rather than after `grace`; what the client had not sent yet it sends again on a new
        // connection, as after any GOAWAY.
        if closing.is_some() && activity.is_quiet() {
            quic.close(H3_NO_ERROR, b"");
            break;
        }
    }
    Ok(())
}

/// The HTTP/3 code for a connection closed without error.
const H3_NO_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0x100);

/// A send under the stall limit: a client that takes nothing for that long loses the stream.
async fn within<T, E: Into<BoxError>>(
    limits: &Limits,
    sending: impl Future<Output = Result<T, E>>,
) -> Result<T, BoxError> {
    match tokio::time::timeout(limits.stall, sending).await {
        Ok(result) => result.map_err(Into::into),
        Err(_) => Err("the client stopped reading the response".into()),
    }
}

/// One request: `hints` when a route of the connection's routing may send Early Hints (the channel
/// they take is made only then).
async fn request(
    resolver: RequestResolver<crate::h3limit::Connection, Bytes>,
    conn: Arc<ConnState>,
    early: bool,
    hints: bool,
    limits: Limits,
) -> Result<(), BoxError> {
    let (request, stream) = tokio::time::timeout(limits.read_header, resolver.resolve_request()).await??;
    let (mut send, recv) = stream.split();
    if early && !safe_early(request.method()) {
        let mut response = Response::new(());
        *response.status_mut() = StatusCode::from_u16(425).expect("valid status");
        response.headers_mut().insert(DATE, crate::date::now());
        within(&limits, send.send_response(response)).await?;
        within(&limits, send.finish()).await?;
        return Ok(());
    }
    let head = request.method() == Method::HEAD;
    let (mut parts, ()) = request.into_parts();
    if early {
        parts
            .headers
            .insert(HeaderName::from_static("early-data"), HeaderValue::from_static("1"));
    }
    parts.version = Version::HTTP_3;
    if !parts.headers.contains_key(HOST)
        && let Some(authority) = parts.uri.authority()
        && let Ok(value) = HeaderValue::from_str(authority.as_str())
    {
        parts.headers.insert(HOST, value);
    }
    let body = RecvBody::body(recv);
    let request = crate::server::stall_limited(Request::from_parts(parts, body), limits.stall);
    let (response, log) = if hints {
        // Early Hints (`respond 103`) go out as they come, while the final response is worked out.
        let (hints, mut hinted) = tokio::sync::mpsc::channel(4);
        let mut request = request;
        request.extensions_mut().insert(crate::handler::EarlyHints(hints));
        let handling = handle_with_log(conn, request);
        let mut handling = std::pin::pin!(handling);
        let early = |headers: http::HeaderMap| {
            let mut early = Response::new(());
            *early.status_mut() = StatusCode::EARLY_HINTS;
            *early.headers_mut() = headers;
            early
        };
        let response = loop {
            tokio::select! {
                biased;
                Some(headers) = hinted.recv() => within(&limits, send.send_response(early(headers))).await?,
                response = &mut handling => break response,
            }
        };
        // Hints given in the same step as the answer still go first.
        while let Ok(headers) = hinted.try_recv() {
            within(&limits, send.send_response(early(headers))).await?;
        }
        response
    } else {
        handle_with_log(conn, request).await
    };
    // The log line is written when the body has been sent (or given up): with the body here, as
    // the TCP protocols carry it in theirs.
    let (mut head_parts, body) = response.into_parts();
    let mut body = Tracked::new(body, None, log);
    for name in [CONNECTION, TRANSFER_ENCODING, UPGRADE] {
        head_parts.headers.remove(name);
    }
    head_parts.headers.remove("keep-alive");
    head_parts.headers.remove("proxy-connection");
    let result = async {
        within(&limits, send.send_response(Response::from_parts(head_parts, ()))).await?;
        if !head {
            send_body(&mut send, &mut body, &limits).await?;
        }
        within(&limits, send.finish()).await
    }
    .await;
    if result.is_err() {
        send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
    }
    result
}

async fn send_body(
    send: &mut RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    body: &mut Tracked,
    limits: &Limits,
) -> Result<(), BoxError> {
    while let Some(frame) = body.frame().await {
        match frame?.into_data() {
            Ok(data) => {
                if !data.is_empty() {
                    within(limits, send.send_data(data)).await?;
                }
            }
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    within(limits, send.send_trailers(trailers)).await?;
                }
            }
        }
    }
    Ok(())
}

/// Requests that may be answered from early data (they change nothing if replayed).
fn safe_early(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// The request body as it arrives on the QUIC stream (trailers are not passed on).
struct RecvBody {
    stream: RequestStream<crate::h3limit::RecvStream, Bytes>,
    /// Data the look at the stream's end (`new`) found already there.
    first: Option<Bytes>,
    done: bool,
}

impl RecvBody {
    /// The body of a request stream: the empty body, with no allocation, when the stream has
    /// already ended (a GET's does, with its headers); otherwise the stream as it arrives.
    fn body(mut stream: RequestStream<crate::h3limit::RecvStream, Bytes>) -> Body {
        // One look without waiting (nothing is woken): what is there is kept for the first poll.
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let (first, done) = match stream.poll_recv_data(&mut cx) {
            Poll::Ready(Ok(None)) => return crate::body::empty(),
            Poll::Ready(Ok(Some(mut buf))) => (Some(buf.copy_to_bytes(buf.remaining())), false),
            Poll::Ready(Err(_)) | Poll::Pending => (None, false),
        };
        boxed(RecvBody { stream, first, done })
    }
}

impl http_body::Body for RecvBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.done {
            return Poll::Ready(None);
        }
        if let Some(first) = self.first.take() {
            return Poll::Ready(Some(Ok(Frame::data(first))));
        }
        match ready!(self.stream.poll_recv_data(cx)) {
            Ok(Some(mut buf)) => {
                let bytes = buf.copy_to_bytes(buf.remaining());
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Ok(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            Err(e) => {
                self.done = true;
                Poll::Ready(Some(Err(Box::new(e))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_safe_methods_are_answered_early() {
        assert!(safe_early(&Method::GET));
        assert!(safe_early(&Method::HEAD));
        assert!(safe_early(&Method::OPTIONS));
        assert!(!safe_early(&Method::POST));
        assert!(!safe_early(&Method::PUT));
        assert!(!safe_early(&Method::DELETE));
        assert!(!safe_early(&Method::PATCH));
    }
}
