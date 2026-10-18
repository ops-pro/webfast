//! What keeps one client from holding the server's connections (src/config.rs, `Limits`):
//!
//! - **Admission**: open connections are limited overall and per client address (an IPv6 /64
//!   counts as one address); trusted proxies are not limited per address, as many clients come
//!   through them. A connection over a limit is closed at once.
//! - **Activity**: a connection that has no request in progress — none yet within `read_header`,
//!   or none for `idle` since the last one — is closed gracefully (HTTP/2: GOAWAY, then the open
//!   streams finish); a graceful close that does not end within `grace` is cut.
//! - **Stall**: a response the client stops taking (the socket accepts nothing, a slow reader)
//!   for `stall` cuts the connection. A slow but moving download resets the clock with every write.
//! - **Stalled request body** (`StalledBody`): a request body the client stops sending for `stall`
//!   (a slow POST to a proxied path would otherwise hold this connection and an upstream one for
//!   as long as the client likes) fails, and the proxy answers 408.
//!
//! The connection's own future checks this after each time it runs, so the timer always follows
//! the latest state; its streams' tasks (HTTP/2) wake it whenever they send.

use crate::body::{Body, BoxError};
use crate::config::Limits;
use bytes::Bytes;
use http_body::{Frame, SizeHint};
use rustc_hash::FxHashMap;
use std::future::Future;
use std::io::IoSlice;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, watch};

/// Open connections of a server (TCP and QUIC), overall and per client address.
pub struct Admission {
    max: usize,
    max_per_ip: usize,
    open: AtomicUsize,
    per_ip: Mutex<FxHashMap<IpAddr, usize>>,
    /// Signalled when the last connection closes (for shutdown).
    closed: Notify,
}

impl Admission {
    pub fn new(limits: &Limits) -> Arc<Admission> {
        Arc::new(Admission {
            max: limits.max_connections,
            max_per_ip: limits.max_per_ip,
            open: AtomicUsize::new(0),
            per_ip: Mutex::new(FxHashMap::default()),
            closed: Notify::new(),
        })
    }

    /// A place for a connection from `ip`, or `None` when a limit is reached.
    pub fn admit(self: &Arc<Self>, ip: IpAddr, trusted: bool) -> Option<Permit> {
        let open = self.open.fetch_add(1, Ordering::AcqRel) + 1;
        let mut permit = Permit {
            admission: self.clone(),
            address: None,
        };
        if self.max > 0 && open > self.max {
            return None;
        }
        if self.max_per_ip > 0 && !trusted {
            let address = address_key(ip);
            let mut per_ip = self.per_ip.lock().unwrap_or_else(PoisonError::into_inner);
            let count = per_ip.entry(address).or_insert(0);
            if *count >= self.max_per_ip {
                return None;
            }
            *count += 1;
            permit.address = Some(address);
        }
        Some(permit)
    }

    pub fn open(&self) -> usize {
        self.open.load(Ordering::Acquire)
    }

    /// Waits until no connection is open.
    pub async fn all_closed(&self) {
        loop {
            let notified = self.closed.notified();
            if self.open() == 0 {
                return;
            }
            notified.await;
        }
    }
}

/// IPv6 addresses count per /64 (one subscriber's network); IPv4 per address.
pub(crate) fn address_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                0,
                0,
                0,
                0,
            ))
        }
        v4 => v4,
    }
}

/// A connection's place; given back when dropped.
pub struct Permit {
    admission: Arc<Admission>,
    address: Option<IpAddr>,
}

/// A connection's place, carried by its requests: a WebSocket tunnel (src/proxy.rs) keeps it until
/// it closes, so tunnels count against the limits as the connections they came from; and the
/// server's stop, on which a tunnel closes (as Caddy closes them when it stops). One reference
/// count per connection: cloning it for a request touches nothing that other connections share.
#[derive(Clone)]
pub struct Place(Arc<Held>);

struct Held {
    _permit: Permit,
    stop: watch::Receiver<bool>,
}

impl Place {
    pub fn new(permit: Permit, stop: watch::Receiver<bool>) -> Place {
        Place(Arc::new(Held { _permit: permit, stop }))
    }

    /// Resolves when the server stops.
    pub async fn stopped(self) {
        let mut stop = self.0.stop.clone();
        while !*stop.borrow_and_update() {
            if stop.changed().await.is_err() {
                // The server is gone without a stop: nothing will ask the tunnel to close.
                std::future::pending::<()>().await;
            }
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        if let Some(address) = self.address {
            let mut per_ip = self.admission.per_ip.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(count) = per_ip.get_mut(&address) {
                *count -= 1;
                if *count == 0 {
                    per_ip.remove(&address);
                }
            }
        }
        if self.admission.open.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.admission.closed.notify_waiters();
        }
    }
}

/// What a connection is doing, shared by its requests, its I/O and its driver.
pub struct Activity {
    started: Instant,
    /// Requests whose response has not ended.
    active: AtomicUsize,
    seen_request: AtomicBool,
    /// Milliseconds after `started` when the last request began or ended.
    last: AtomicU64,
    /// Milliseconds after `started`, plus one, since when a write has been waiting for the socket;
    /// 0 when none is.
    blocked: AtomicU64,
    /// Signalled when the last request in progress ends (for drivers that wait in `select!`).
    quiet: Notify,
}

impl Activity {
    pub fn new() -> Arc<Activity> {
        Arc::new(Activity {
            started: Instant::now(),
            active: AtomicUsize::new(0),
            seen_request: AtomicBool::new(false),
            last: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            quiet: Notify::new(),
        })
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// A request begins; it ends when the returned value is dropped (with its response body).
    pub fn begin(self: &Arc<Self>) -> InFlight {
        self.active.fetch_add(1, Ordering::AcqRel);
        self.seen_request.store(true, Ordering::Release);
        self.last.store(self.now_ms(), Ordering::Release);
        InFlight(self.clone())
    }

    fn write_waits(&self) {
        let now = self.now_ms() + 1;
        let _ = self
            .blocked
            .compare_exchange(0, now, Ordering::AcqRel, Ordering::Acquire);
    }

    fn write_moved(&self) {
        self.blocked.store(0, Ordering::Release);
    }

    /// Resolves after the last request in progress ends.
    pub async fn quiet(&self) {
        self.quiet.notified().await
    }

    /// No request is in progress.
    pub fn is_quiet(&self) -> bool {
        self.active.load(Ordering::Acquire) == 0
    }

    /// When the connection is next due for something, and what.
    pub fn next(&self, limits: &Limits) -> (Instant, Due) {
        let blocked = self.blocked.load(Ordering::Acquire);
        if blocked != 0 {
            return (
                self.started + Duration::from_millis(blocked - 1) + limits.stall,
                Due::Cut,
            );
        }
        if self.active.load(Ordering::Acquire) == 0 {
            if !self.seen_request.load(Ordering::Acquire) {
                return (self.started + limits.read_header, Due::Close);
            }
            let last = Duration::from_millis(self.last.load(Ordering::Acquire));
            return (self.started + last + limits.idle, Due::Close);
        }
        // Requests in progress and writes moving: nothing due; look again later.
        (Instant::now() + limits.idle, Due::Nothing)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Due {
    Nothing,
    /// Close gracefully.
    Close,
    /// Cut now.
    Cut,
}

/// A request in progress; its end when dropped.
pub struct InFlight(Arc<Activity>);

impl Drop for InFlight {
    fn drop(&mut self) {
        let activity = &self.0;
        activity.last.store(activity.now_ms(), Ordering::Release);
        if activity.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            activity.quiet.notify_waiters();
        }
    }
}

/// A response body that keeps its request counted as in progress until it ends.
pub struct Tracked {
    inner: Body,
    _flight: InFlight,
}

impl Tracked {
    pub fn new(inner: Body, flight: InFlight) -> Tracked {
        Tracked { inner, _flight: flight }
    }
}

impl http_body::Body for Tracked {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Set when a request body timed out (`StalledBody`); kept in the request's extensions so the
/// handler that was reading the body (the proxy) can tell a stalled client from a failed upstream.
#[derive(Debug, Clone, Default)]
pub struct BodyStalled(pub Arc<AtomicBool>);

impl BodyStalled {
    pub fn happened(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// The error a stalled request body ends with.
#[derive(Debug)]
pub struct StalledError;

impl std::fmt::Display for StalledError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the client stopped sending the request body")
    }
}

impl std::error::Error for StalledError {}

/// A request body that must keep moving: with no frame for `stall` it ends with an error and
/// marks `BodyStalled`. A body that is already complete (no body, or one hyper has buffered) never
/// arms the timer.
pub struct StalledBody {
    inner: Body,
    stall: Duration,
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
    stalled: BodyStalled,
}

impl StalledBody {
    pub fn new(inner: Body, stall: Duration, stalled: BodyStalled) -> StalledBody {
        StalledBody {
            inner,
            stall,
            timer: None,
            stalled,
        }
    }
}

impl http_body::Body for StalledBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(frame) => {
                self.timer = None;
                Poll::Ready(frame)
            }
            Poll::Pending => {
                let stall = self.stall;
                let timer = self.timer.get_or_insert_with(|| Box::pin(tokio::time::sleep(stall)));
                if timer.as_mut().poll(cx).is_ready() {
                    self.stalled.0.store(true, Ordering::Release);
                    return Poll::Ready(Some(Err(Box::new(StalledError))));
                }
                Poll::Pending
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Set when a request body is over its `request_body` limit (`LimitedBody`): announced by its
/// Content-Length, or found while it arrived. Kept in the request's extensions so that the proxy
/// answers 413 — at once, without calling the upstream, when the length said so.
#[derive(Debug, Clone, Default)]
pub struct BodyTooLarge(pub Arc<AtomicBool>);

impl BodyTooLarge {
    pub fn happened(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn mark(&self) {
        self.0.store(true, Ordering::Release);
    }
}

/// The error a request body over its limit ends with.
#[derive(Debug)]
pub struct TooLargeError;

impl std::fmt::Display for TooLargeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the request body is larger than the request_body limit")
    }
}

impl std::error::Error for TooLargeError {}

/// A request body of at most `max` bytes (`request_body { max_size }`, as Caddy's): one whose
/// length announces more is marked at once and fails when read; one that sends more fails at the
/// frame that goes over.
pub struct LimitedBody {
    inner: Body,
    remaining: u64,
    too_large: BodyTooLarge,
    announced: bool,
}

impl LimitedBody {
    pub fn new(inner: Body, max: u64, too_large: BodyTooLarge) -> LimitedBody {
        let announced = http_body::Body::size_hint(&inner).lower() > max;
        if announced {
            too_large.mark();
        }
        LimitedBody {
            inner,
            remaining: max,
            too_large,
            announced,
        }
    }
}

impl http_body::Body for LimitedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.announced {
            return Poll::Ready(Some(Err(Box::new(TooLargeError))));
        }
        let polled = std::task::ready!(Pin::new(&mut self.inner).poll_frame(cx));
        if let Some(Ok(frame)) = &polled
            && let Some(data) = frame.data_ref()
        {
            let len = data.len() as u64;
            if len > self.remaining {
                self.too_large.mark();
                return Poll::Ready(Some(Err(Box::new(TooLargeError))));
            }
            self.remaining -= len;
        }
        Poll::Ready(polled)
    }

    fn is_end_stream(&self) -> bool {
        !self.announced && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// A socket that tells its connection's `Activity` when writes wait and when they move.
pub struct Io<T> {
    inner: T,
    activity: Arc<Activity>,
}

impl<T> Io<T> {
    pub fn new(inner: T, activity: Arc<Activity>) -> Io<T> {
        Io { inner, activity }
    }

    fn watch<R>(&self, polled: Poll<std::io::Result<R>>) -> Poll<std::io::Result<R>> {
        match &polled {
            Poll::Pending => self.activity.write_waits(),
            Poll::Ready(_) => self.activity.write_moved(),
        }
        polled
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Io<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Io<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.watch(polled)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.watch(polled)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_flush(cx);
        self.watch(polled)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.watch(polled)
    }
}

/// When a connection that a reload left on the old configuration closes (WEB_RELOAD=drain): once
/// the port's configuration is newer than the connection's, at a moment drawn at random within
/// `window` — so that the connections a reload leaves behind close spread over it, and their
/// clients come back spread over it too, instead of all at once.
pub struct Retire {
    /// The port's configuration generation, sent by each reload.
    pub reloads: watch::Receiver<u64>,
    /// The connection's.
    pub generation: u64,
    pub window: Duration,
}

impl Retire {
    /// Resolves at the connection's moment to close; never when no reload comes.
    pub async fn due(mut self) {
        while *self.reloads.borrow_and_update() <= self.generation {
            if self.reloads.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
        tokio::time::sleep(self.window.mul_f64(random_fraction())).await;
    }
}

/// A number in [0, 1), different on every call (the standard library's randomly keyed hasher).
fn random_fraction() -> f64 {
    use std::hash::BuildHasher;
    let bits = std::hash::RandomState::new().hash_one(Instant::now());
    (bits >> 11) as f64 / (1u64 << 53) as f64
}

/// What may end a connection besides itself: the server's stop, and with WEB_RELOAD=drain a
/// reload (`retire`).
pub struct Ends {
    pub stop: watch::Receiver<bool>,
    pub retire: Option<Retire>,
}

/// Runs a connection to its end under `limits`. `graceful` asks it to finish gracefully (hyper's
/// `graceful_shutdown`); when `stop` turns true (server shutdown) that is asked too and the
/// connection is then waited for — the server bounds that wait itself. With `retire`, a reload
/// asks it to finish too, at its moment (WEB_RELOAD=drain); a close of our own is cut after `grace`.
pub async fn drive<C: Future>(
    connection: C,
    graceful: impl Fn(Pin<&mut C>),
    activity: &Activity,
    limits: &Limits,
    ends: Ends,
) {
    let Ends { stop, retire } = ends;
    let mut connection = std::pin::pin!(connection);
    let mut stopped = std::pin::pin!(async move {
        let mut stop = stop;
        while !*stop.borrow_and_update() {
            if stop.changed().await.is_err() {
                break;
            }
        }
    });
    let mut retiring = std::pin::pin!(async move {
        match retire {
            Some(retire) => retire.due().await,
            None => std::future::pending().await,
        }
    });
    let mut retired = false;
    let mut timer = std::pin::pin!(tokio::time::sleep(limits.idle));
    let mut armed: Option<Instant> = None;
    // Since when a graceful close of our own (idle) is under way.
    let mut closing: Option<Instant> = None;
    let mut stopping = false;
    std::future::poll_fn(|cx| {
        loop {
            if !stopping && stopped.as_mut().poll(cx).is_ready() {
                stopping = true;
                graceful(connection.as_mut());
            }
            if !stopping && !retired && closing.is_none() && retiring.as_mut().poll(cx).is_ready() {
                retired = true;
                closing = Some(Instant::now());
                graceful(connection.as_mut());
            }
            if connection.as_mut().poll(cx).is_ready() {
                return Poll::Ready(());
            }
            if stopping {
                return Poll::Pending;
            }
            let (when, due) = match closing {
                Some(since) => (since + limits.grace, Due::Cut),
                None => activity.next(limits),
            };
            if armed != Some(when) {
                timer.as_mut().reset(when.into());
                armed = Some(when);
            }
            if timer.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            armed = None;
            match due {
                Due::Nothing => {}
                Due::Cut => return Poll::Ready(()),
                Due::Close => {
                    closing = Some(Instant::now());
                    graceful(connection.as_mut());
                }
            }
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_counts_per_address_and_overall() {
        let limits = Limits {
            max_connections: 3,
            max_per_ip: 2,
            ..Limits::default()
        };
        let admission = Admission::new(&limits);
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:3:4:5:6".parse().unwrap();
        let b_same_net: IpAddr = "2001:db8:1:2:ffff::1".parse().unwrap();
        let first = admission.admit(a, false).unwrap();
        let _second = admission.admit(a, false).unwrap();
        assert!(admission.admit(a, false).is_none(), "per address");
        let _v6 = admission.admit(b, false).unwrap();
        assert!(
            admission.admit(b_same_net, false).is_none(),
            "overall (3), and the /64 counts too"
        );
        drop(first);
        assert_eq!(admission.open(), 3 - 1);
        let proxy: IpAddr = "10.0.0.2".parse().unwrap();
        let _through_proxy = admission.admit(proxy, true).unwrap();
        assert!(
            admission.admit(proxy, true).is_none(),
            "the overall limit binds trusted proxies too"
        );
    }

    #[tokio::test]
    async fn request_bodies_over_the_limit_fail() {
        use http_body_util::BodyExt;
        // Content-Length over the limit: marked at once, before anything is read.
        let flag = BodyTooLarge::default();
        let body = LimitedBody::new(crate::body::full(vec![0u8; 101]), 100, flag.clone());
        assert!(flag.happened());
        assert!(body.collect().await.is_err());
        // Within it: passes whole.
        let flag = BodyTooLarge::default();
        let body = LimitedBody::new(crate::body::full(vec![0u8; 100]), 100, flag.clone());
        assert_eq!(body.collect().await.unwrap().to_bytes().len(), 100);
        assert!(!flag.happened());
        // No length announced: the frame that goes over fails.
        let frames = vec![
            Ok::<_, BoxError>(Frame::data(Bytes::from(vec![0u8; 60]))),
            Ok(Frame::data(Bytes::from(vec![0u8; 60]))),
        ];
        let stream = http_body_util::StreamBody::new(tokio_stream::iter(frames));
        let flag = BodyTooLarge::default();
        let mut body = LimitedBody::new(crate::body::boxed(stream), 100, flag.clone());
        assert!(!flag.happened(), "nothing announced");
        assert!(body.frame().await.unwrap().is_ok(), "60 bytes: within");
        assert!(body.frame().await.unwrap().is_err(), "120 bytes: over");
        assert!(flag.happened());
    }

    #[test]
    fn idle_and_stalled_connections_fall_due() {
        let limits = Limits::default();
        let activity = Activity::new();
        let (when, due) = activity.next(&limits);
        assert_eq!(due, Due::Close, "no first request yet");
        assert!(when <= activity.started + limits.read_header);
        let flight = activity.begin();
        assert_eq!(activity.next(&limits).1, Due::Nothing);
        activity.write_waits();
        let (when, due) = activity.next(&limits);
        assert_eq!(due, Due::Cut);
        assert!(when <= Instant::now() + limits.stall);
        activity.write_moved();
        drop(flight);
        let (when, due) = activity.next(&limits);
        assert_eq!(due, Due::Close);
        assert!(when > Instant::now() + limits.idle - Duration::from_secs(1));
    }
}
