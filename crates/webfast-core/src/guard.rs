//! What keeps one client from holding the server's connections (src/config.rs, `Limits`):
//!
//! - **Admission**: open connections are limited overall and per client address (an IPv6 /64
//!   counts as one address); trusted proxies are not limited per address, as many clients come
//!   through them. A connection over a limit is closed at once.
//! - **Activity**: a connection that has no request in progress — none yet within `read_header`,
//!   or none for `idle` since the last one (HTTP/1.1: the next request's head within `read_header`
//!   of the last response, as hyper's own header timeout did, but with one timer per connection
//!   rather than one per request) — is closed gracefully (HTTP/2: GOAWAY, then the open streams
//!   finish); a graceful close that does not end within `grace` is cut.
//! - **Stall**: a response the client stops taking (the socket accepts nothing, a slow reader)
//!   for `stall` cuts the connection. A slow but moving download resets the clock with every write.
//! - **Stalled request body** (`StalledBody`): a request body the client stops sending for `stall`
//!   (a slow POST to a proxied path would otherwise hold this connection and an upstream one for
//!   as long as the client likes) fails, and the proxy answers 408.
//!
//! The connection's own future checks this after each time it runs, so the timer always follows
//! the latest state; the end of its last request in progress wakes it (`Activity::quiet`), as its
//! streams' tasks (HTTP/2) end their bodies on their own.

use crate::accesslog::Logged;
use crate::body::{Body, BoxError};
use crate::config::Limits;
use bytes::Bytes;
use http::Version;
use http_body::{Frame, SizeHint};
use rustc_hash::FxHashMap;
use std::future::Future;
use std::hash::{BuildHasher, BuildHasherDefault};
use std::io::IoSlice;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, watch};

/// Open connections of a server (TCP and QUIC), overall and per client address.
pub struct Admission {
    max: usize,
    max_per_ip: usize,
    open: AtomicUsize,
    /// The counts per address, in shards by the address's hash: every accept and close on every
    /// core takes one of these locks, so they are many, each on its own cache line.
    per_ip: Box<[Shard]>,
    /// Signalled when the last connection closes (for shutdown).
    closed: Notify,
}

const SHARDS: usize = 64;

#[repr(align(64))]
struct Shard(Mutex<FxHashMap<IpAddr, usize>>);

impl Admission {
    pub fn new(limits: &Limits) -> Arc<Admission> {
        Arc::new(Admission {
            max: limits.max_connections,
            max_per_ip: limits.max_per_ip,
            open: AtomicUsize::new(0),
            per_ip: (0..SHARDS).map(|_| Shard(Mutex::new(FxHashMap::default()))).collect(),
            closed: Notify::new(),
        })
    }

    fn shard(&self, address: IpAddr) -> &Mutex<FxHashMap<IpAddr, usize>> {
        let hash = BuildHasherDefault::<rustc_hash::FxHasher>::default().hash_one(address);
        &self.per_ip[(hash as usize) % SHARDS].0
    }

    /// A place for a connection from `ip`, or `None` when a limit is reached.
    pub fn admit(self: &Arc<Self>, ip: IpAddr, trusted: bool) -> Option<Permit> {
        let address = (self.max_per_ip > 0 && !trusted).then(|| address_key(ip));
        self.take(address).ok()
    }

    /// A place counted for `address` (its key; `None`: not counted per address), or which limit
    /// is reached.
    fn take(self: &Arc<Self>, address: Option<IpAddr>) -> Result<Permit, Full> {
        // Relaxed: the count orders nothing else; `all_closed` reads it with Acquire after the
        // Release of the close that may have made it zero.
        let open = self.open.fetch_add(1, Ordering::Relaxed) + 1;
        let mut permit = Permit {
            admission: self.clone(),
            address: None,
        };
        if self.max > 0 && open > self.max {
            return Err(Full::Server);
        }
        if let Some(address) = address {
            let mut per_ip = self.shard(address).lock().unwrap_or_else(PoisonError::into_inner);
            let count = per_ip.entry(address).or_insert(0);
            if *count >= self.max_per_ip {
                return Err(Full::Address);
            }
            *count += 1;
            permit.address = Some(address);
        }
        Ok(permit)
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

/// IPv6 addresses count per /64 (one subscriber's network); IPv4 per address: the key the
/// connection limits, the rate limits and the modules' bans count a client by.
pub fn address_key(ip: IpAddr) -> IpAddr {
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

/// Which limit left no place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Full {
    /// The server's open connections (WEB_MAX_CONNECTIONS).
    Server,
    /// The client address's (WEB_MAX_CONNECTIONS_PER_IP).
    Address,
}

/// A connection's place; given back when dropped.
pub struct Permit {
    admission: Arc<Admission>,
    address: Option<IpAddr>,
}

/// A connection's place, carried by its requests: a WebSocket tunnel (src/proxy.rs) keeps it until
/// it closes, so tunnels count against the limits as the connections they came from; the
/// server's stop, on which a tunnel closes (as Caddy closes them when it stops); and the
/// connection's activity, for a tunnel that takes one stream of it (`tunnel`). One reference
/// count per connection: cloning it for a request touches nothing that other connections share.
/// The stop is the listener's own copy of the server's (src/server.rs `accept_loop`), so that a
/// connection's start and end touch nothing every core shares either.
#[derive(Clone)]
pub struct Place(Arc<Held>);

struct Held {
    _permit: Permit,
    stop: watch::Receiver<bool>,
    activity: Arc<Activity>,
}

impl Place {
    pub fn new(permit: Permit, stop: watch::Receiver<bool>, activity: Arc<Activity>) -> Place {
        Place(Arc::new(Held {
            _permit: permit,
            stop,
            activity,
        }))
    }

    /// A tunnel on one of the connection's streams (HTTP/2, RFC 8441). It takes a place of its
    /// own, counted as its connection's is (for the same address, or for none behind a trusted
    /// proxy): a tunnel is one connection of the limits whichever way it was opened, as a
    /// WebSocket over HTTP/1.1 takes its whole connection. `Err`: the limit that leaves it none.
    /// While what is returned lives, the connection has a request in progress (it is not idle,
    /// however quiet the tunnel) and a close of the server's own (after a reload with
    /// WEB_RELOAD=drain) waits for it.
    pub fn tunnel(&self, version: Version) -> Result<Tunneling, Full> {
        let held = &self.0._permit;
        let permit = held.admission.take(held.address)?;
        let activity = &self.0.activity;
        activity.tunnels.fetch_add(1, Ordering::AcqRel);
        Ok(Tunneling(activity.begin(version), permit))
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
            let mut per_ip = self
                .admission
                .shard(address)
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(count) = per_ip.get_mut(&address) {
                *count -= 1;
                if *count == 0 {
                    per_ip.remove(&address);
                }
            }
        }
        if self.admission.open.fetch_sub(1, Ordering::Release) == 1 {
            self.admission.closed.notify_waiters();
        }
    }
}

/// A tunnel open on one of a connection's streams (`Place::tunnel`), with its own place; its end
/// when dropped.
pub struct Tunneling(InFlight, #[allow(dead_code)] Permit);

impl Drop for Tunneling {
    fn drop(&mut self) {
        let activity = &self.0.0;
        activity.tunnels.fetch_sub(1, Ordering::AcqRel);
        // The driver looks again: a close that waited for this tunnel has its deadline back.
        activity.quiet.notify_waiters();
    }
}

/// The port's reloads as a request that may become a tunnel saw them (src/server.rs): the
/// configuration it was routed with, the channel that tells of a newer one, and the upstreams
/// the port's proxies name, as each reload leaves them.
#[derive(Clone)]
pub struct Reloads {
    pub reloads: watch::Receiver<u64>,
    pub generation: u64,
    pub upstreams: watch::Receiver<Arc<[http::uri::Authority]>>,
}

impl Reloads {
    /// When a tunnel made under that configuration closes after a reload: at a moment within
    /// `window` (`stream_close_delay`).
    pub fn retire(self, window: Duration) -> Retire {
        Retire {
            reloads: self.reloads,
            generation: self.generation,
            window,
        }
    }

    /// Resolves when a reload puts a configuration in place whose proxies no longer name
    /// `upstream` (as written in the Caddyfile): the instance was taken out, and what is still
    /// open to it is to go. Never, while every reload keeps the name.
    pub async fn removed(mut self, upstream: http::uri::Authority) {
        loop {
            if self.upstreams.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
            if !self.upstreams.borrow_and_update().contains(&upstream) {
                return;
            }
        }
    }
}

/// What a connection is doing, shared by its requests, its I/O and its driver.
pub struct Activity {
    started: Instant,
    /// Requests whose response has not ended.
    active: AtomicUsize,
    /// Tunnels open on its streams (HTTP/2), each counted in `active` too.
    tunnels: AtomicUsize,
    seen_request: AtomicBool,
    /// The connection speaks HTTP/1.x (known with its first request): between requests the next
    /// head is due within `read_header`, as on a new connection; HTTP/2 and HTTP/3 frame their
    /// heads, and only `idle` applies.
    h1: AtomicBool,
    /// Milliseconds after `started` when the last request began or ended.
    last: AtomicU64,
    /// Milliseconds after `started`, plus one, since when a write has been waiting for the socket;
    /// 0 when none is.
    blocked: AtomicU64,
    /// Signalled when the last request in progress ends (for drivers that wait in `select!`).
    quiet: Notify,
    /// The connection is to end with nothing more written (a 444 of the request filter): every
    /// write fails from here on.
    cut: AtomicBool,
}

impl Activity {
    pub fn new() -> Arc<Activity> {
        Arc::new(Activity {
            started: Instant::now(),
            active: AtomicUsize::new(0),
            tunnels: AtomicUsize::new(0),
            seen_request: AtomicBool::new(false),
            h1: AtomicBool::new(false),
            last: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            quiet: Notify::new(),
            cut: AtomicBool::new(false),
        })
    }

    /// Ends the connection without another byte written: the socket's writes fail from now on, so
    /// hyper gives up on the response and the connection closes.
    pub fn cut(&self) {
        self.cut.store(true, Ordering::Release);
    }

    pub fn is_cut(&self) -> bool {
        self.cut.load(Ordering::Acquire)
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// A request (on `version`) begins; it ends when the returned value is dropped (with its
    /// response body).
    pub fn begin(self: &Arc<Self>, version: Version) -> InFlight {
        self.active.fetch_add(1, Ordering::AcqRel);
        if !self.seen_request.load(Ordering::Relaxed) {
            self.h1.store(version <= Version::HTTP_11, Ordering::Relaxed);
            self.seen_request.store(true, Ordering::Release);
        }
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

    /// The same, to poll in place: made before the active count is looked at, it resolves even
    /// when the last request ends between that look and its first poll.
    pub fn quiet_notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.quiet.notified()
    }

    /// No request is in progress.
    pub fn is_quiet(&self) -> bool {
        self.active.load(Ordering::Acquire) == 0
    }

    /// When the connection is next due for something, and what; `None` with requests in progress
    /// and writes moving (the end of the last request wakes the driver: `quiet_notified`).
    pub fn next(&self, limits: &Limits) -> Option<(Instant, Due)> {
        let blocked = self.blocked.load(Ordering::Acquire);
        if blocked != 0 {
            return Some((
                self.started + Duration::from_millis(blocked - 1) + limits.stall,
                Due::Cut,
            ));
        }
        if self.active.load(Ordering::Acquire) == 0 {
            if !self.seen_request.load(Ordering::Acquire) {
                return Some((self.started + limits.read_header, Due::Close));
            }
            let last = Duration::from_millis(self.last.load(Ordering::Acquire));
            let gap = if self.h1.load(Ordering::Relaxed) {
                limits.idle.min(limits.read_header)
            } else {
                limits.idle
            };
            return Some((self.started + last + gap, Due::Close));
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Due {
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

/// A response body that keeps its request counted as in progress until it ends, and writes its
/// access log line then (`Logged`, when the site logs). One wrapper, not boxed: hyper takes it as
/// it is.
pub struct Tracked {
    inner: Body,
    _flight: Option<InFlight>,
    log: Option<Logged>,
}

impl Tracked {
    pub fn new(inner: Body, flight: Option<InFlight>, log: Option<Logged>) -> Tracked {
        Tracked {
            inner,
            _flight: flight,
            log,
        }
    }
}

impl http_body::Body for Tracked {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let polled = ready!(Pin::new(&mut self.inner).poll_frame(cx));
        if let Some(log) = &mut self.log {
            match &polled {
                Some(Ok(frame)) => log.count(frame),
                Some(Err(_)) | None => log.finish(),
            }
        }
        Poll::Ready(polled)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// The error a stalled request body ends with. The handler that was sending the body on (the proxy)
/// finds it in the failure's chain of causes (`body_fault`): a stalled client, not a failed upstream.
#[derive(Debug)]
pub struct StalledError;

impl std::fmt::Display for StalledError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the client stopped sending the request body")
    }
}

impl std::error::Error for StalledError {}

/// A request body that must keep moving: with no frame for `stall` it ends with `StalledError`. A
/// body that is already complete (no body, or one hyper has buffered) never arms the timer. The
/// timer lives in the body (pinned once boxed) and is set again at each wait, not made anew.
pub struct StalledBody {
    inner: Body,
    stall: Duration,
    timer: tokio::time::Sleep,
    /// The timer is set for the wait under way.
    armed: bool,
}

impl StalledBody {
    pub fn new(inner: Body, stall: Duration) -> StalledBody {
        StalledBody {
            inner,
            stall,
            // Not registered with the runtime until it is set and polled.
            timer: tokio::time::sleep_until(far_future()),
            armed: false,
        }
    }
}

/// What a failed request says about the client's body, from the failure's chain of causes (hyper
/// keeps the body's error as the cause of the request's): 408 for a body that stalled, 413 for one
/// over its limit; `None` when the body was not at fault.
pub fn body_fault(error: &(dyn std::error::Error + 'static)) -> Option<http::StatusCode> {
    let mut cause = Some(error);
    while let Some(e) = cause {
        if e.is::<StalledError>() {
            return Some(http::StatusCode::REQUEST_TIMEOUT);
        }
        if e.is::<TooLargeError>() {
            return Some(http::StatusCode::PAYLOAD_TOO_LARGE);
        }
        cause = e.source();
    }
    None
}

/// A deadline that never comes (as tokio's own `far_future`: 30 years, within every clock's range).
fn far_future() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(86400 * 365 * 30)
}

impl http_body::Body for StalledBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        // SAFETY: `timer` is never moved out of or replaced while pinned (only `reset` and `poll`,
        // both through the pin below); the other fields are `Unpin` and used by plain reference.
        let this = unsafe { self.get_unchecked_mut() };
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(frame) => {
                this.armed = false;
                Poll::Ready(frame)
            }
            Poll::Pending => {
                // SAFETY: a projection of the pinned `self` to its `timer` field (see above).
                let mut timer = unsafe { Pin::new_unchecked(&mut this.timer) };
                if !this.armed {
                    timer.as_mut().reset(tokio::time::Instant::now() + this.stall);
                    this.armed = true;
                }
                if timer.poll(cx).is_ready() {
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

/// The error a request body over its limit ends with (found by `body_fault`).
#[derive(Debug)]
pub struct TooLargeError;

impl std::fmt::Display for TooLargeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the request body is larger than the request_body limit")
    }
}

impl std::error::Error for TooLargeError {}

/// A request body of at most `max` bytes (`request_body { max_size }`, as Caddy's): one whose
/// length announces more fails when read (`announced`: the caller answers 413 at once, without
/// sending anything on); one that sends more fails at the frame that goes over.
pub struct LimitedBody {
    inner: Body,
    remaining: u64,
    announced: bool,
}

impl LimitedBody {
    pub fn new(inner: Body, max: u64) -> LimitedBody {
        LimitedBody {
            announced: http_body::Body::size_hint(&inner).lower() > max,
            inner,
            remaining: max,
        }
    }

    /// The body's announced length is over the limit.
    pub fn announced(&self) -> bool {
        self.announced
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

/// What a write on a cut connection fails with.
fn cut_error() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "the connection was cut")
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
        if self.activity.is_cut() {
            return Poll::Ready(Err(cut_error()));
        }
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.watch(polled)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        if self.activity.is_cut() {
            return Poll::Ready(Err(cut_error()));
        }
        let polled = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.watch(polled)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.activity.is_cut() {
            return Poll::Ready(Err(cut_error()));
        }
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
///
/// The timer is set only when a deadline is due and only when it changes: with requests in
/// progress it is left alone, and the end of the last one wakes this future to set it.
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
    let mut timer = std::pin::pin!(tokio::time::sleep_until(far_future()));
    let mut armed: Option<Instant> = None;
    // The end of the last request in progress (its body ends in a stream's own task on HTTP/2).
    let mut quiet = std::pin::pin!(activity.quiet_notified());
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
            // Made anew before the active count is read: an end after that read still wakes us.
            // Polled until it waits, so that the next end (a request's, a tunnel's) wakes us too.
            while quiet.as_mut().poll(cx).is_ready() {
                quiet.set(activity.quiet_notified());
            }
            let due = match closing {
                // A tunnel on one of its streams outlives the close, as one that took its whole
                // connection does: nothing is cut while it is open but a write that stalls.
                Some(_) if activity.tunnels.load(Ordering::Acquire) > 0 => {
                    activity.next(limits).filter(|(_, due)| *due == Due::Cut)
                }
                Some(since) => Some((since + limits.grace, Due::Cut)),
                None => activity.next(limits),
            };
            let Some((when, due)) = due else {
                // Requests in progress and writes moving: whatever is set may fire, and is then
                // looked at again here.
                return Poll::Pending;
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

    /// A tunnel on a stream of a connection takes a place as its connection does: for the same
    /// address, or overall only behind a trusted proxy; and gives it back when it ends.
    #[test]
    fn a_tunnel_on_a_stream_takes_a_place_of_its_own() {
        let limits = Limits {
            max_connections: 3,
            max_per_ip: 2,
            ..Limits::default()
        };
        let admission = Admission::new(&limits);
        let stop = watch::channel(false).1;
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let place = Place::new(admission.admit(a, false).unwrap(), stop.clone(), Activity::new());
        let tunnel = place.tunnel(Version::HTTP_2).unwrap();
        assert!(
            admission.admit(a, false).is_none(),
            "the tunnel holds the address's second place"
        );
        assert_eq!(place.tunnel(Version::HTTP_2).err(), Some(Full::Address));
        assert_eq!(admission.open(), 2, "a place refused is not kept");
        drop(tunnel);
        let again = place.tunnel(Version::HTTP_2).unwrap();
        // Behind a trusted proxy: not counted for the address, as its connection is not.
        let proxy: IpAddr = "10.0.0.2".parse().unwrap();
        let through = Place::new(admission.admit(proxy, true).unwrap(), stop, Activity::new());
        assert_eq!(through.tunnel(Version::HTTP_2).err(), Some(Full::Server));
        drop(again);
        let _tunnel = through.tunnel(Version::HTTP_2).unwrap();
        assert_eq!(admission.open(), 3);
    }

    #[tokio::test]
    async fn request_bodies_over_the_limit_fail() {
        use http_body_util::BodyExt;
        // Content-Length over the limit: known at once, before anything is read.
        let body = LimitedBody::new(crate::body::full(vec![0u8; 101]), 100);
        assert!(body.announced());
        let error = body.collect().await.expect_err("fails when read");
        assert_eq!(body_fault(&*error), Some(http::StatusCode::PAYLOAD_TOO_LARGE));
        // Within it: passes whole.
        let body = LimitedBody::new(crate::body::full(vec![0u8; 100]), 100);
        assert!(!body.announced());
        assert_eq!(body.collect().await.unwrap().to_bytes().len(), 100);
        // No length announced: the frame that goes over fails.
        let frames = vec![
            Ok::<_, BoxError>(Frame::data(Bytes::from(vec![0u8; 60]))),
            Ok(Frame::data(Bytes::from(vec![0u8; 60]))),
        ];
        let stream = http_body_util::StreamBody::new(tokio_stream::iter(frames));
        let mut body = LimitedBody::new(crate::body::boxed(stream), 100);
        assert!(!body.announced(), "nothing announced");
        assert!(body.frame().await.unwrap().is_ok(), "60 bytes: within");
        let error = body.frame().await.unwrap().expect_err("120 bytes: over");
        assert_eq!(body_fault(&*error), Some(http::StatusCode::PAYLOAD_TOO_LARGE));
        // Wrapped the way hyper wraps a body's error (as the cause): still found; an unrelated error
        // is not.
        #[derive(Debug)]
        struct Wrapped(BoxError);
        impl std::fmt::Display for Wrapped {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("request failed")
            }
        }
        impl std::error::Error for Wrapped {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&*self.0)
            }
        }
        assert_eq!(body_fault(&Wrapped(error)), Some(http::StatusCode::PAYLOAD_TOO_LARGE));
        assert_eq!(body_fault(&Wrapped("connection reset".into())), None);
    }

    #[test]
    fn idle_and_stalled_connections_fall_due() {
        let limits = Limits::default();
        let activity = Activity::new();
        let (when, due) = activity.next(&limits).unwrap();
        assert_eq!(due, Due::Close, "no first request yet");
        assert!(when <= activity.started + limits.read_header);
        let flight = activity.begin(Version::HTTP_2);
        assert_eq!(activity.next(&limits), None, "a request in progress");
        activity.write_waits();
        let (when, due) = activity.next(&limits).unwrap();
        assert_eq!(due, Due::Cut);
        assert!(when <= Instant::now() + limits.stall);
        activity.write_moved();
        drop(flight);
        let (when, due) = activity.next(&limits).unwrap();
        assert_eq!(due, Due::Close);
        assert!(when > Instant::now() + limits.idle - Duration::from_secs(1));
    }

    #[test]
    fn between_requests_http1_heads_are_due_within_read_header() {
        let limits = Limits {
            read_header: Duration::from_secs(30),
            idle: Duration::from_secs(300),
            ..Limits::default()
        };
        // HTTP/1.1: the next head within `read_header` of the last response (hyper's semantics).
        let activity = Activity::new();
        drop(activity.begin(Version::HTTP_11));
        let (when, due) = activity.next(&limits).unwrap();
        assert_eq!(due, Due::Close);
        assert!(when <= Instant::now() + limits.read_header);
        // HTTP/2 frames its heads: `idle`.
        let activity = Activity::new();
        drop(activity.begin(Version::HTTP_2));
        let (when, _) = activity.next(&limits).unwrap();
        assert!(when > Instant::now() + limits.idle - Duration::from_secs(1));
        // The shorter of the two when `idle` is the shorter.
        let short = Limits {
            idle: Duration::from_secs(5),
            ..limits
        };
        let activity = Activity::new();
        drop(activity.begin(Version::HTTP_11));
        let (when, _) = activity.next(&short).unwrap();
        assert!(when <= Instant::now() + short.idle);
    }

    #[tokio::test]
    async fn a_stalled_request_body_fails_with_one_timer() {
        use http_body_util::BodyExt;
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, BoxError>>(4);
        tx.send(Ok(Frame::data(Bytes::from_static(b"first")))).await.unwrap();
        let stream = http_body_util::StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx));
        let mut body = crate::body::boxed(StalledBody::new(crate::body::boxed(stream), Duration::from_millis(200)));
        assert!(body.frame().await.unwrap().is_ok());
        // Moving within the limit: the timer is set again, not run out.
        tokio::time::sleep(Duration::from_millis(120)).await;
        tx.send(Ok(Frame::data(Bytes::from_static(b"second")))).await.unwrap();
        assert!(body.frame().await.unwrap().is_ok());
        // Then nothing: the body ends with the stall error.
        let started = Instant::now();
        let error = body.frame().await.unwrap().expect_err("stalled");
        assert_eq!(body_fault(&*error), Some(http::StatusCode::REQUEST_TIMEOUT));
        assert!(started.elapsed() >= Duration::from_millis(150));
        drop(tx);
    }
}
