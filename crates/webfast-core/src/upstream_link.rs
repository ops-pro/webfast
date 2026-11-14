//! The proxy's own connections to an upstream: everything but plain HTTP/1.1, which stays with
//! the pooled client (src/proxy.rs `client`). `transport http { versions … }`, as Caddy reads it:
//!
//! - **over TLS** (`https://` upstreams, `transport http { tls… }`): with `2` among the versions
//!   (the default is `1.1 2`) every handshake offers HTTP/2 and HTTP/1.1, and the upstream
//!   chooses; with `1.1` alone only HTTP/1.1 is offered. An HTTP/1.1 connection is kept for the
//!   next request when its response has been read to the end; an HTTP/2 connection is one per
//!   upstream address, shared by its requests.
//! - **`h2c`** (`h2c://` upstreams, `versions h2c`): HTTP/2 without TLS, from the first byte (no
//!   upgrade from HTTP/1.1), one connection per address.
//! - **`3`**: HTTP/3 over QUIC, one connection per address, and nothing else: there is no fall
//!   back to a version over TCP.
//!
//! The connections belong to the address they go to (`Link`, one in every `Server` of
//! src/upstreams.rs), so they go when a reload or a change of the name's addresses takes the
//! server out, once the responses under way on them have ended.
//!
//! Why not the pooled client for all of it: it takes the address to connect to and the
//! `:authority` of an HTTP/2 request from one URI, and here they differ — a request goes to an
//! address with the Host of the upstream as written, or of the client.
//!
//! `keepalive` (2 minutes unless set) is how long a connection without requests is kept;
//! `keepalive off` keeps none: every request makes its own.

use crate::body::{Body, BoxError};
use crate::guard::body_fault;
use crate::upstream_tls::UpstreamTls;
use crate::upstreams::{Server, now_ms};
use bytes::{Buf, Bytes};
use http::header::{CONNECTION, HOST, TE, TRANSFER_ENCODING, UPGRADE};
use http::uri::{Authority, PathAndQuery, Scheme};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, Version};
use http_body::{Body as _, Frame};
use http_body_util::BodyExt;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll, ready};
use std::time::Duration;
use tokio::net::TcpStream;

/// The head of a response at most, over HTTP/2 and HTTP/3 (hyper's HTTP/1.1 client reads about
/// as much; its HTTP/2 default is 16 KiB, which a response with many cookies passes).
const MAX_HEAD: u32 = 512 * 1024;

/// HTTP/2: a connection with requests under way that says nothing is asked whether it is there
/// this often, and given up when it does not answer in time.
const H2_PING: Duration = Duration::from_secs(30);
const H2_PING_TIMEOUT: Duration = Duration::from_secs(10);

/// QUIC: a connection is kept open by a packet this often (a response may take longer to come
/// than the idle timeout), and is lost when nothing comes from the upstream for `QUIC_IDLE`.
const QUIC_PING: Duration = Duration::from_secs(10);
const QUIC_IDLE: Duration = Duration::from_secs(30);

/// The HTTP/3 code for a connection closed without error.
const H3_NO_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0x100);

/// `transport http { versions … }`: the versions of HTTP the upstreams are spoken to in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Versions {
    pub http1: bool,
    /// HTTP/2 over TLS, when the upstream takes it in the handshake.
    pub http2: bool,
    /// HTTP/2 without TLS.
    pub h2c: bool,
    pub http3: bool,
}

impl Default for Versions {
    /// `1.1 2`, as Caddy.
    fn default() -> Versions {
        Versions {
            http1: true,
            http2: true,
            h2c: false,
            http3: false,
        }
    }
}

impl Versions {
    /// `h2c 2`: what an `h2c://` upstream sets, as Caddy.
    pub const H2C: Versions = Versions {
        http1: false,
        http2: true,
        h2c: true,
        http3: false,
    };

    /// The words of `versions`.
    pub fn parse<'w>(words: impl IntoIterator<Item = &'w str>) -> Result<Versions, String> {
        let mut versions = Versions {
            http1: false,
            http2: false,
            h2c: false,
            http3: false,
        };
        let mut any = false;
        for word in words {
            any = true;
            match word {
                "1.1" => versions.http1 = true,
                "2" => versions.http2 = true,
                "h2c" => versions.h2c = true,
                "3" => versions.http3 = true,
                other => return Err(format!("versions: {other:?} is not one of 1.1, 2, h2c, 3")),
            }
        }
        if !any {
            return Err("versions takes 1.1, 2, h2c or 3".into());
        }
        if versions.http3 && (versions.http1 || versions.http2 || versions.h2c) {
            return Err("versions: 3 goes alone (HTTP/3 to an upstream does not fall back to another version)".into());
        }
        Ok(versions)
    }
}

/// How a request reaches an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// Plain HTTP/1.1, by the pooled client.
    Pooled,
    /// Over TLS; `http2`: HTTP/2 when the upstream takes it, else (and without) HTTP/1.1.
    Tls { http2: bool },
    /// HTTP/2 without TLS.
    H2c,
    /// HTTP/3.
    Http3,
}

/// A request as it goes to an upstream: its Host is among the headers.
pub struct Outgoing {
    pub method: Method,
    pub path_and_query: Option<PathAndQuery>,
    pub headers: HeaderMap,
    pub body: Body,
}

impl Outgoing {
    fn path(&self) -> PathAndQuery {
        self.path_and_query
            .clone()
            .unwrap_or_else(|| PathAndQuery::from_static("/"))
    }

    /// As HTTP/1.1 sends it: the path as the target, Host among the headers.
    fn http1(self) -> Request<Body> {
        let target = Uri::from(self.path());
        let mut request = Request::new(self.body);
        *request.method_mut() = self.method;
        *request.uri_mut() = target;
        *request.headers_mut() = self.headers;
        request
    }

    /// As HTTP/2 sends it: the target with a scheme and an authority (`target`), no Host field.
    fn http2(mut self, scheme: Scheme, server: &Server) -> Request<Body> {
        let path = self.path();
        let target = target(&mut self.headers, scheme, path, server);
        let mut request = Request::new(self.body);
        *request.method_mut() = self.method;
        *request.uri_mut() = target;
        *request.version_mut() = Version::HTTP_2;
        *request.headers_mut() = self.headers;
        request
    }

    /// The same request once more, for one without a body.
    fn again(&self) -> Outgoing {
        Outgoing {
            method: self.method.clone(),
            path_and_query: self.path_and_query.clone(),
            headers: self.headers.clone(),
            body: crate::body::empty(),
        }
    }

    /// A request a connection gave back unsent, as it was.
    fn unsent(request: Request<Body>) -> Outgoing {
        let (parts, body) = request.into_parts();
        let mut headers = parts.headers;
        if !headers.contains_key(HOST)
            && let Some(authority) = parts.uri.authority()
            && let Ok(host) = HeaderValue::from_str(authority.as_str())
        {
            headers.insert(HOST, host);
        }
        Outgoing {
            method: parts.method,
            path_and_query: parts.uri.path_and_query().cloned(),
            headers,
            body,
        }
    }
}

/// The target of a request over HTTP/2 or HTTP/3: `:scheme`, `:authority` and `:path` are read
/// from it. The authority is the Host the request would have had over HTTP/1.1, taken out of the
/// headers (the two are one thing there); one that is no authority: the upstream as written.
fn target(headers: &mut HeaderMap, scheme: Scheme, path: PathAndQuery, server: &Server) -> Uri {
    let authority = headers
        .remove(HOST)
        .and_then(|host| Authority::try_from(host.as_bytes()).ok())
        .unwrap_or_else(|| server.name.clone());
    let mut parts = http::uri::Parts::default();
    parts.scheme = Some(scheme);
    parts.authority = Some(authority);
    parts.path_and_query = Some(path);
    Uri::from_parts(parts).expect("a scheme, an authority and a path are a URI")
}

/// The fields of one connection, which HTTP/3 has no place for (hyper takes them off an HTTP/2
/// request itself). `header_up` may have put one there: the proxy's own are gone by now.
fn without_connection_fields(mut headers: HeaderMap) -> HeaderMap {
    for name in [CONNECTION, TRANSFER_ENCODING, UPGRADE] {
        headers.remove(name);
    }
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
    if headers.get(TE).is_some_and(|value| value != "trailers") {
        headers.remove(TE);
    }
    headers
}

/// Why a request got no answer from an upstream.
#[derive(Debug)]
pub struct Failed {
    /// No connection, or nothing of the request went out on it: another upstream may take it.
    pub connect: bool,
    /// The client's body was at fault (src/guard.rs `body_fault`): what to answer.
    pub fault: Option<StatusCode>,
    pub error: String,
}

impl Failed {
    pub fn connect(error: impl std::fmt::Display) -> Failed {
        Failed {
            connect: true,
            fault: None,
            error: error.to_string(),
        }
    }

    fn exchange(error: &(dyn std::error::Error + 'static)) -> Failed {
        Failed {
            connect: false,
            fault: body_fault(error),
            error: chain(error),
        }
    }
}

/// An error with what caused it, in one line.
pub fn chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(error) = cause {
        let more = error.to_string();
        if !text.contains(&more) {
            text.push_str(": ");
            text.push_str(&more);
        }
        cause = error.source();
    }
    text
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// When a shared connection last carried a request. The handles to it tell whether one is under
/// way: the link's own, and one for every request until its response's body is dropped.
struct Usage {
    last: AtomicU64,
}

impl Usage {
    fn new() -> Arc<Usage> {
        Arc::new(Usage {
            last: AtomicU64::new(now_ms()),
        })
    }

    fn touch(&self) {
        self.last.store(now_ms(), Ordering::Relaxed);
    }
}

/// A request under way on a shared connection.
pub struct InUse(Arc<Usage>);

impl Drop for InUse {
    fn drop(&mut self) {
        self.0.touch();
    }
}

/// Resolves when the shared connection of `usage` has carried nothing for `keepalive`, or is
/// nobody's any more; never without a `keepalive` (the connection is then one request's, and
/// goes with it).
async fn idle(usage: Weak<Usage>, keepalive: Option<Duration>) {
    let Some(keepalive) = keepalive else {
        return std::future::pending().await;
    };
    let limit = keepalive.as_millis() as u64;
    let mut wait = keepalive;
    loop {
        tokio::time::sleep(wait.max(Duration::from_millis(50))).await;
        let Some(usage) = usage.upgrade() else {
            return;
        };
        // The link's handle and this one: any other is a request under way.
        let busy = Arc::strong_count(&usage) > 2;
        let quiet = now_ms().saturating_sub(usage.last.load(Ordering::Relaxed));
        if !busy && quiet >= limit {
            return;
        }
        wait = if busy {
            keepalive
        } else {
            Duration::from_millis(limit - quiet)
        };
    }
}

/// An HTTP/1.1 connection kept for the next request.
struct Idle1 {
    sender: http1::SendRequest<Body>,
    since: u64,
}

/// The HTTP/2 connection the requests to an address share.
#[derive(Clone)]
struct Shared2 {
    sender: http2::SendRequest<Body>,
    usage: Arc<Usage>,
}

type Sender3 = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// The HTTP/3 connection the requests to an address share.
#[derive(Clone)]
struct Shared3 {
    sender: Sender3,
    quic: quinn::Connection,
    usage: Arc<Usage>,
}

/// The connections to one address (src/upstreams.rs `Server`).
#[derive(Default)]
pub struct Link {
    idle: Arc<Mutex<Vec<Idle1>>>,
    http2: Mutex<Option<Shared2>>,
    http3: Mutex<Option<Shared3>>,
    /// A connection the requests would share is made by one of them at a time; the others wait
    /// for it and use it.
    dialing: tokio::sync::Mutex<()>,
    /// Connection attempts that failed: one that fails is the answer for those that waited for
    /// it, too (they do not each try again, one after another).
    failures: AtomicU64,
    /// The last handshake over TLS chose HTTP/1.1: such connections are one request's each, so
    /// they are made side by side, not one at a time. Every one of them still offers HTTP/2.
    http1: AtomicBool,
}

impl Link {
    /// A kept HTTP/1.1 connection that is ready for a request; those that have closed, or have
    /// waited past `keepalive`, are dropped on the way.
    fn idle1(&self, keepalive: Option<Duration>) -> Option<http1::SendRequest<Body>> {
        let mut idle = locked(&self.idle);
        let now = now_ms();
        let mut i = idle.len();
        while i > 0 {
            i -= 1;
            let entry = &idle[i];
            let stale = keepalive.is_none_or(|keep| now.saturating_sub(entry.since) >= keep.as_millis() as u64);
            if stale || entry.sender.is_closed() {
                idle.swap_remove(i);
            } else if entry.sender.is_ready() {
                return Some(idle.swap_remove(i).sender);
            }
        }
        None
    }

    fn shared2(&self) -> Option<Shared2> {
        let mut slot = locked(&self.http2);
        if slot.as_ref().is_some_and(|shared| shared.sender.is_closed()) {
            *slot = None;
        }
        slot.clone()
    }

    fn forget2(&self, shared: &Shared2) {
        let mut slot = locked(&self.http2);
        if slot
            .as_ref()
            .is_some_and(|kept| Arc::ptr_eq(&kept.usage, &shared.usage))
        {
            *slot = None;
        }
    }

    fn shared3(&self) -> Option<Shared3> {
        let mut slot = locked(&self.http3);
        if slot.as_ref().is_some_and(|shared| shared.quic.close_reason().is_some()) {
            *slot = None;
        }
        slot.clone()
    }

    fn forget3(&self, shared: &Shared3) {
        let mut slot = locked(&self.http3);
        if slot
            .as_ref()
            .is_some_and(|kept| Arc::ptr_eq(&kept.usage, &shared.usage))
        {
            *slot = None;
        }
    }
}

/// What sending on a connection came to.
enum Sent {
    Answered(Response<Incoming>),
    /// The connection had closed: nothing of the request went out, and here it is again.
    Unsent(Outgoing),
    /// The upstream took the request and refused it unprocessed: its connection is closing.
    Refused(Failed),
    Failed(Failed),
}

/// How many connections a request may go through that give it back, or refuse it.
#[derive(Default)]
struct Tries(u32);

impl Tries {
    const MOST: u32 = 6;

    /// Whether the request may go to another connection (counted then).
    fn another(&mut self) -> bool {
        self.0 += 1;
        self.0 < Tries::MOST
    }

    fn spent() -> Failed {
        Failed::connect("the upstream closes its connections before a request is taken")
    }
}

/// What a request does after a connection.
enum Next {
    Done(Result<Response<Incoming>, Failed>),
    /// To another connection, with this.
    Again(Outgoing),
}

/// `out` on the shared HTTP/2 connection `shared`, which the link forgets when it turns out to
/// be closed or closing.
async fn try2(link: &Link, shared: Shared2, scheme: Scheme, server: &Server, out: Outgoing, tries: &mut Tries) -> Next {
    // A request without a body can be sent again after the connection took it and refused it,
    // as Go's transport does it for Caddy (one with a body has given it away).
    let again = out.body.is_end_stream().then(|| out.again());
    match send2(shared.clone(), scheme, server, out).await {
        Sent::Answered(response) => Next::Done(Ok(response)),
        Sent::Failed(failed) => Next::Done(Err(failed)),
        Sent::Unsent(back) => {
            link.forget2(&shared);
            if tries.another() {
                Next::Again(back)
            } else {
                Next::Done(Err(Tries::spent()))
            }
        }
        Sent::Refused(failed) => {
            link.forget2(&shared);
            match again {
                Some(again) if tries.another() => Next::Again(again),
                _ => Next::Done(Err(failed)),
            }
        }
    }
}

/// Whether an HTTP/2 error says the upstream processed nothing of the request: its stream was
/// refused, or was opened after the last one the upstream's goodbye (GOAWAY, without an error)
/// says it took. Such a request is safe to send again (RFC 9113 §8.7).
fn refused2(error: &hyper::Error) -> bool {
    let mut cause = std::error::Error::source(error);
    while let Some(error) = cause {
        if let Some(error) = error.downcast_ref::<h2::Error>() {
            return match error.reason() {
                Some(h2::Reason::REFUSED_STREAM) => true,
                Some(h2::Reason::NO_ERROR) => error.is_go_away() && error.is_remote(),
                _ => false,
            };
        }
        cause = error.source();
    }
    false
}

/// The same of an HTTP/3 error: the upstream reset the stream with H3_REQUEST_REJECTED
/// (RFC 9114 §4.1.1).
fn refused3(error: &h3::error::StreamError) -> bool {
    matches!(
        error,
        h3::error::StreamError::RemoteTerminate { code, .. } if *code == h3::error::Code::H3_REQUEST_REJECTED
    )
}

/// A new connection over TCP.
enum Made {
    Http1(http1::SendRequest<Body>),
    Http2(Shared2),
}

/// QUIC for the upstreams of one proxy.
struct Quic {
    config: quinn::ClientConfig,
    /// The sockets the connections are made from, one per address family, bound at the first
    /// request (binding needs the runtime, which a configuration being read may not have).
    endpoints: [Mutex<Option<quinn::Endpoint>>; 2],
}

impl Quic {
    fn endpoint(&self, v6: bool) -> std::io::Result<quinn::Endpoint> {
        let mut slot = locked(&self.endpoints[usize::from(v6)]);
        if let Some(endpoint) = &*slot {
            return Ok(endpoint.clone());
        }
        let local: SocketAddr = if v6 {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        };
        let endpoint = quinn::Endpoint::client(local)?;
        *slot = Some(endpoint.clone());
        Ok(endpoint)
    }
}

/// How the requests of one `reverse_proxy` reach its upstreams when not by the pooled client.
pub struct Links {
    tls: Option<Arc<UpstreamTls>>,
    versions: Versions,
    dial_timeout: Duration,
    keepalive: Option<Duration>,
    quic: Option<Quic>,
}

impl std::fmt::Debug for Links {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Links")
            .field("tls", &self.tls.is_some())
            .field("versions", &self.versions)
            .finish_non_exhaustive()
    }
}

impl Links {
    /// `None`: the pooled client is all this proxy needs (plain HTTP/1.1).
    pub fn new(
        tls: Option<Arc<UpstreamTls>>,
        versions: Versions,
        dial_timeout: Duration,
        keepalive: Option<Duration>,
    ) -> anyhow::Result<Option<Links>> {
        if tls.is_none() && !versions.h2c && !versions.http3 {
            return Ok(None);
        }
        let quic = match (&tls, versions.http3) {
            (Some(tls), true) => {
                let mut config = tls.quic()?;
                let mut transport = quinn::TransportConfig::default();
                transport.max_idle_timeout(Some(
                    quinn::IdleTimeout::try_from(QUIC_IDLE).expect("the idle timeout fits"),
                ));
                transport.keep_alive_interval(Some(QUIC_PING));
                config.transport_config(Arc::new(transport));
                Some(Quic {
                    config,
                    endpoints: [Mutex::new(None), Mutex::new(None)],
                })
            }
            (None, true) => anyhow::bail!("versions 3 needs TLS to the upstream"),
            _ => None,
        };
        Ok(Some(Links {
            tls,
            versions,
            dial_timeout,
            keepalive: keepalive.filter(|keep| !keep.is_zero()),
            quic,
        }))
    }

    /// How an upstream on `port` is reached (`tls_except_ports` leaves some without TLS).
    pub fn via(&self, port: u16) -> Via {
        if self.versions.http3 {
            Via::Http3
        } else if self.tls.as_ref().is_some_and(|tls| tls.applies(port)) {
            Via::Tls {
                http2: self.versions.http2 || self.versions.h2c,
            }
        } else if self.versions.h2c {
            Via::H2c
        } else {
            Via::Pooled
        }
    }

    /// Sends `out` to `server` and waits for the head of its answer.
    pub async fn exchange(&self, server: &Server, via: Via, out: Outgoing) -> Result<Response<Incoming>, Failed> {
        let mut response = match via {
            Via::Pooled => return Err(Failed::connect("plain HTTP/1.1 goes by the pooled client")),
            Via::Tls { http2 } => self.over_tcp(server, true, http2, out).await?,
            Via::H2c => self.over_tcp(server, false, true, out).await?,
            Via::Http3 => self.over_quic(server, out).await?,
        };
        // As an answer of the pooled client: the version is the client's connection's to say.
        *response.version_mut() = Version::HTTP_11;
        Ok(response)
    }

    async fn over_tcp(
        &self,
        server: &Server,
        tls: bool,
        http2: bool,
        mut out: Outgoing,
    ) -> Result<Response<Incoming>, Failed> {
        let link = &server.link;
        let scheme = if tls { Scheme::HTTPS } else { Scheme::HTTP };
        let home = match self.keepalive {
            Some(_) => Arc::downgrade(&link.idle),
            None => Weak::new(),
        };
        // A connection — one kept from before, or the shared one another request has just made —
        // may have closed, or be closing: the request then comes back unsent, or (without a
        // body) refused, and goes to the next connection, or to a new one.
        let mut tries = Tries::default();
        loop {
            if http2 && let Some(shared) = link.shared2() {
                match try2(link, shared, scheme.clone(), server, out, &mut tries).await {
                    Next::Done(done) => return done,
                    Next::Again(back) => out = back,
                }
                continue;
            }
            if tls && let Some(sender) = link.idle1(self.keepalive) {
                match send1(sender, home.clone(), out).await {
                    Sent::Answered(response) => return Ok(response),
                    Sent::Failed(failed) | Sent::Refused(failed) => return Err(failed),
                    Sent::Unsent(back) => out = back,
                }
                continue;
            }
            match self.connect(server, tls, http2).await? {
                Made::Http1(sender) => match send1(sender, home.clone(), out).await {
                    Sent::Answered(response) => return Ok(response),
                    Sent::Failed(failed) | Sent::Refused(failed) => return Err(failed),
                    Sent::Unsent(back) if tries.another() => out = back,
                    Sent::Unsent(_) => return Err(Tries::spent()),
                },
                Made::Http2(shared) => match try2(link, shared, scheme.clone(), server, out, &mut tries).await {
                    Next::Done(done) => return done,
                    Next::Again(back) => out = back,
                },
            }
        }
    }

    /// A new connection over TCP for a request, or the shared one another request made while
    /// this one waited.
    async fn connect(&self, server: &Server, tls: bool, http2: bool) -> Result<Made, Failed> {
        let link = &server.link;
        let sharing = http2 && self.keepalive.is_some();
        let ours = |link: &Link| tls && link.http1.load(Ordering::Relaxed);
        let _turn = if sharing && !ours(link) {
            let seen = link.failures.load(Ordering::Relaxed);
            let turn = link.dialing.lock().await;
            if let Some(shared) = link.shared2() {
                return Ok(Made::Http2(shared));
            }
            if link.failures.load(Ordering::Relaxed) != seen {
                return Err(Failed::connect(
                    "the connection this request waited for could not be made",
                ));
            }
            // The one waited for chose HTTP/1.1: this request's own is made beside the others'.
            (!ours(link)).then_some(turn)
        } else {
            None
        };
        let made = self.dial(server, tls, http2).await;
        match &made {
            Err(_) => {
                link.failures.fetch_add(1, Ordering::Relaxed);
            }
            Ok(Made::Http1(_)) => link.http1.store(true, Ordering::Relaxed),
            Ok(Made::Http2(shared)) => {
                link.http1.store(false, Ordering::Relaxed);
                if sharing {
                    *locked(&link.http2) = Some(shared.clone());
                }
            }
        }
        made
    }

    async fn dial(&self, server: &Server, tls: bool, http2: bool) -> Result<Made, Failed> {
        let tcp = match tokio::time::timeout(self.dial_timeout, TcpStream::connect(server.addr)).await {
            Ok(Ok(tcp)) => tcp,
            Ok(Err(error)) => return Err(Failed::connect(error)),
            Err(_) => return Err(Failed::connect("connection timed out")),
        };
        let _ = tcp.set_nodelay(true);
        if !tls {
            // h2c: HTTP/2 from the first byte.
            return self.handshake2(TokioIo::new(tcp)).await.map(Made::Http2);
        }
        let Some(settings) = &self.tls else {
            return Err(Failed::connect("this proxy has no TLS"));
        };
        let name = settings.name_for(server.name.host()).map_err(Failed::connect)?;
        let stream = settings
            .handshake(name, tcp, http2)
            .await
            .map_err(|error| Failed::connect(format_args!("TLS: {error}")))?;
        if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
            return self.handshake2(TokioIo::new(stream)).await.map(Made::Http2);
        }
        let (sender, connection) = http1::handshake::<_, Body>(TokioIo::new(stream))
            .await
            .map_err(Failed::connect)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Made::Http1(sender))
    }

    async fn handshake2<T>(&self, io: T) -> Result<Shared2, Failed>
    where
        T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        let mut builder = http2::Builder::new(TokioExecutor::new());
        builder
            .timer(TokioTimer::new())
            .keep_alive_interval(H2_PING)
            .keep_alive_timeout(H2_PING_TIMEOUT)
            .max_header_list_size(MAX_HEAD);
        let (sender, connection) = builder.handshake::<_, Body>(io).await.map_err(Failed::connect)?;
        let usage = Usage::new();
        let idle = idle(Arc::downgrade(&usage), self.keepalive);
        tokio::spawn(async move {
            // Dropped when idle for too long: with no request under way it closes at once.
            tokio::select! {
                _ = connection => {}
                () = idle => {}
            }
        });
        Ok(Shared2 { sender, usage })
    }

    async fn over_quic(&self, server: &Server, mut out: Outgoing) -> Result<Response<Incoming>, Failed> {
        let link = &server.link;
        // A connection — one kept from before, or the shared one another request has just made —
        // may take no more requests (closed, or told to finish), or take this one and refuse it:
        // the request then goes to another, after a refusal only without a body.
        let mut tries = Tries::default();
        'exchange: loop {
            let mut shared = match link.shared3() {
                Some(shared) => shared,
                None => self.connect_quic(server).await?,
            };
            shared.usage.touch();
            // The last connection tried takes the headers; before it they are kept.
            let again = tries.another();
            let mut headers = if again {
                out.headers.clone()
            } else {
                std::mem::take(&mut out.headers)
            };
            let mut head = Request::new(());
            *head.method_mut() = out.method.clone();
            *head.uri_mut() = target(&mut headers, Scheme::HTTPS, out.path(), server);
            *head.headers_mut() = without_connection_fields(headers);
            let stream = match shared.sender.send_request(head).await {
                Ok(stream) => stream,
                Err(_) if again => {
                    link.forget3(&shared);
                    continue;
                }
                Err(error) => return Err(Failed::connect(error)),
            };
            let (mut send, mut recv) = stream.split();
            // The request's body goes out while the answer is waited for (and after its head has
            // come: an upstream may answer as it reads).
            let bodiless = out.body.is_end_stream();
            let (upload, mut fault) = if bodiless {
                send.finish().await.map_err(|error| Failed::exchange(&error))?;
                (None, None)
            } else {
                let body = std::mem::replace(&mut out.body, crate::body::empty());
                let (said, fault) = tokio::sync::oneshot::channel();
                let task = tokio::spawn(upload(send, body, said));
                (Some(Upload(task)), Some(fault))
            };
            let mut watching = fault.is_some();
            let response = loop {
                let answered = match fault.as_mut().filter(|_| watching) {
                    Some(fault) => tokio::select! {
                        biased;
                        answered = recv.recv_response() => answered,
                        said = fault => match said {
                            // The client's body failed, by the client's doing.
                            Ok(status) => {
                                return Err(Failed {
                                    connect: false,
                                    fault: Some(status),
                                    error: "the request body failed".to_string(),
                                });
                            }
                            // It has all gone out.
                            Err(_) => {
                                watching = false;
                                continue;
                            }
                        },
                    },
                    None => recv.recv_response().await,
                };
                match answered {
                    // 103 and the like are not passed on.
                    Ok(response) if response.status().is_informational() => {}
                    Ok(response) => break response,
                    Err(error) if again && bodiless && refused3(&error) => {
                        link.forget3(&shared);
                        continue 'exchange;
                    }
                    Err(error) => return Err(Failed::exchange(&error)),
                }
            };
            let (parts, ()) = response.into_parts();
            let body = Body3 {
                stream: recv,
                reading: Reading::Data,
                _upload: upload,
                _held: (shared.sender, InUse(shared.usage)),
            };
            return Ok(Response::from_parts(parts, Incoming::Http3(Box::new(body))));
        }
    }

    /// A new HTTP/3 connection, or the one another request made while this one waited.
    async fn connect_quic(&self, server: &Server) -> Result<Shared3, Failed> {
        let link = &server.link;
        let sharing = self.keepalive.is_some();
        let _turn = if sharing {
            let seen = link.failures.load(Ordering::Relaxed);
            let turn = link.dialing.lock().await;
            if let Some(shared) = link.shared3() {
                return Ok(shared);
            }
            if link.failures.load(Ordering::Relaxed) != seen {
                return Err(Failed::connect(
                    "the connection this request waited for could not be made",
                ));
            }
            Some(turn)
        } else {
            None
        };
        let made = self.dial_quic(server).await;
        match &made {
            Err(_) => {
                link.failures.fetch_add(1, Ordering::Relaxed);
            }
            Ok(shared) if sharing => *locked(&link.http3) = Some(shared.clone()),
            Ok(_) => {}
        }
        made
    }

    async fn dial_quic(&self, server: &Server) -> Result<Shared3, Failed> {
        let (Some(quic), Some(tls)) = (&self.quic, &self.tls) else {
            return Err(Failed::connect("this proxy has no QUIC"));
        };
        let endpoint = quic.endpoint(server.addr.is_ipv6()).map_err(Failed::connect)?;
        let name = tls.name_for(server.name.host()).map_err(Failed::connect)?;
        let connecting = endpoint
            .connect_with(quic.config.clone(), server.addr, &name.to_str())
            .map_err(Failed::connect)?;
        // One handshake makes the connection and its TLS: both limits bound it.
        let limit = self.dial_timeout + tls.timeout().unwrap_or_default();
        let connection = match tokio::time::timeout(limit, connecting).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => return Err(Failed::connect(format_args!("QUIC: {error}"))),
            Err(_) => return Err(Failed::connect("connection timed out")),
        };
        let mut builder = h3::client::builder();
        builder.max_field_section_size(u64::from(MAX_HEAD));
        let (mut driver, sender) = builder
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(Failed::connect)?;
        let usage = Usage::new();
        let idle = idle(Arc::downgrade(&usage), self.keepalive);
        let quic = connection.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = std::future::poll_fn(|cx| driver.poll_close(cx)) => {}
                () = idle => quic.close(H3_NO_ERROR, b"idle"),
            }
        });
        Ok(Shared3 {
            sender,
            quic: connection,
            usage,
        })
    }
}

async fn send1(mut sender: http1::SendRequest<Body>, home: Weak<Mutex<Vec<Idle1>>>, out: Outgoing) -> Sent {
    match sender.try_send_request(out.http1()).await {
        Ok(response) => Sent::Answered(response.map(|body| {
            Incoming::Kept(Kept {
                body,
                sender: Some(sender),
                home,
                ended: false,
            })
        })),
        Err(mut error) => match error.take_message() {
            Some(request) => Sent::Unsent(Outgoing::unsent(request)),
            None => Sent::Failed(Failed::exchange(error.error())),
        },
    }
}

async fn send2(shared: Shared2, scheme: Scheme, server: &Server, out: Outgoing) -> Sent {
    let Shared2 { mut sender, usage } = shared;
    usage.touch();
    let in_use = InUse(usage);
    match sender.try_send_request(out.http2(scheme, server)).await {
        Ok(response) => Sent::Answered(response.map(|body| Incoming::Http2 {
            body,
            _held: (sender, in_use),
        })),
        Err(mut error) => match error.take_message() {
            Some(request) => Sent::Unsent(Outgoing::unsent(request)),
            None if refused2(error.error()) => Sent::Refused(Failed::exchange(error.error())),
            None => Sent::Failed(Failed::exchange(error.error())),
        },
    }
}

/// The request's body, sent on its HTTP/3 stream as it comes; `fault`: told when the body fails
/// by the client's doing (it stalled, or went over its limit).
async fn upload(
    mut send: h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    mut body: Body,
    fault: tokio::sync::oneshot::Sender<StatusCode>,
) {
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
                send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                if let Some(status) = body_fault(error.as_ref()) {
                    let _ = fault.send(status);
                }
                return;
            }
        };
        match frame.into_data() {
            Ok(data) => {
                if !data.is_empty() && send.send_data(data).await.is_err() {
                    return;
                }
            }
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers()
                    && send.send_trailers(trailers).await.is_err()
                {
                    return;
                }
            }
        }
    }
    let _ = send.finish().await;
}

/// The task that sends a request's body: stopped with the response it belongs to.
struct Upload(tokio::task::JoinHandle<()>);

impl Drop for Upload {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The body of an upstream's response.
pub enum Incoming {
    /// The pooled client's.
    Pooled(hyper::body::Incoming),
    /// HTTP/1.1 on a connection of a link: kept for the next request when read to its end.
    Kept(Kept),
    /// One stream of an HTTP/2 connection, which lives while its streams do.
    Http2 {
        body: hyper::body::Incoming,
        _held: (http2::SendRequest<Body>, InUse),
    },
    Http3(Box<Body3>),
}

impl http_body::Body for Incoming {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match self.get_mut() {
            Incoming::Pooled(body) | Incoming::Http2 { body, .. } => Pin::new(body).poll_frame(cx).map_err(Into::into),
            Incoming::Kept(kept) => {
                let polled = Pin::new(&mut kept.body).poll_frame(cx);
                if matches!(polled, Poll::Ready(None)) {
                    kept.ended = true;
                }
                polled.map_err(Into::into)
            }
            Incoming::Http3(body) => body.poll(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Incoming::Pooled(body) | Incoming::Http2 { body, .. } => body.is_end_stream(),
            Incoming::Kept(kept) => kept.body.is_end_stream(),
            Incoming::Http3(body) => matches!(body.reading, Reading::Done),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            Incoming::Pooled(body) | Incoming::Http2 { body, .. } => body.size_hint(),
            Incoming::Kept(kept) => kept.body.size_hint(),
            Incoming::Http3(_) => http_body::SizeHint::default(),
        }
    }
}

/// A response over HTTP/1.1 on a connection of a link.
pub struct Kept {
    body: hyper::body::Incoming,
    /// The connection: back to the link when the response has been read to its end, closed
    /// otherwise.
    sender: Option<http1::SendRequest<Body>>,
    home: Weak<Mutex<Vec<Idle1>>>,
    ended: bool,
}

impl Drop for Kept {
    fn drop(&mut self) {
        let Some(mut sender) = self.sender.take() else {
            return;
        };
        if !(self.ended || self.body.is_end_stream()) || sender.is_closed() {
            return;
        }
        let home = std::mem::take(&mut self.home);
        let keep = move |sender: http1::SendRequest<Body>| {
            if let Some(home) = home.upgrade() {
                locked(&home).push(Idle1 {
                    sender,
                    since: now_ms(),
                });
            }
        };
        if sender.is_ready() {
            keep(sender);
        } else if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            // The connection has yet to see the response's end: kept once it has.
            runtime.spawn(async move {
                if sender.ready().await.is_ok() {
                    keep(sender);
                }
            });
        }
    }
}

enum Reading {
    Data,
    Trailers,
    Done,
}

/// A response's body as it arrives on its HTTP/3 stream.
pub struct Body3 {
    stream: h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    reading: Reading,
    _upload: Option<Upload>,
    /// The connection closes when the last handle to it goes: one stays with every response.
    _held: (Sender3, InUse),
}

impl Body3 {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        loop {
            match self.reading {
                Reading::Data => match ready!(self.stream.poll_recv_data(cx)) {
                    Ok(Some(mut data)) => {
                        let bytes = data.copy_to_bytes(data.remaining());
                        return Poll::Ready(Some(Ok(Frame::data(bytes))));
                    }
                    Ok(None) => self.reading = Reading::Trailers,
                    Err(error) => {
                        self.reading = Reading::Done;
                        return Poll::Ready(Some(Err(Box::new(error))));
                    }
                },
                Reading::Trailers => {
                    let trailers = ready!(self.stream.poll_recv_trailers(cx));
                    self.reading = Reading::Done;
                    return match trailers {
                        Ok(Some(trailers)) => Poll::Ready(Some(Ok(Frame::trailers(trailers)))),
                        Ok(None) => Poll::Ready(None),
                        Err(error) => Poll::Ready(Some(Err(Box::new(error)))),
                    };
                }
                Reading::Done => return Poll::Ready(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_versions_as_caddy_reads_them() {
        assert_eq!(Versions::parse(["1.1", "2"]).unwrap(), Versions::default());
        assert_eq!(Versions::parse(["h2c", "2"]).unwrap(), Versions::H2C);
        let only = Versions::parse(["1.1"]).unwrap();
        assert!(only.http1 && !only.http2 && !only.h2c && !only.http3);
        assert!(Versions::parse(["3"]).unwrap().http3);
        for (words, says) in [
            (vec![], "versions takes"),
            (vec!["1.0"], "is not one of"),
            (vec!["3", "2"], "3 goes alone"),
            (vec!["1.1", "3"], "3 goes alone"),
        ] {
            let error = Versions::parse(words.iter().copied()).unwrap_err();
            assert!(error.contains(says), "{words:?}: {error}");
        }
    }

    #[test]
    fn what_reaches_an_upstream_how() {
        let links = |tls: bool, versions: Versions, except: Vec<u16>| {
            let tls = tls.then(|| {
                Arc::new(
                    UpstreamTls::new(&crate::upstream_tls::Settings {
                        except_ports: except,
                        ..Default::default()
                    })
                    .unwrap(),
                )
            });
            Links::new(tls, versions, Duration::from_secs(3), Some(Duration::from_secs(120))).unwrap()
        };
        // Plain HTTP/1.1 needs none of this, whatever is said of HTTP/2 over TLS.
        assert!(links(false, Versions::default(), vec![]).is_none());
        // Over TLS: HTTP/2 offered unless `versions 1.1`; an excepted port stays plain.
        let tls = links(true, Versions::default(), vec![8080]).unwrap();
        assert_eq!(tls.via(443), Via::Tls { http2: true });
        assert_eq!(tls.via(8080), Via::Pooled);
        let only = links(true, Versions::parse(["1.1"]).unwrap(), vec![]).unwrap();
        assert_eq!(only.via(443), Via::Tls { http2: false });
        // h2c: without TLS; with TLS, HTTP/2 inside it.
        assert_eq!(links(false, Versions::H2C, vec![]).unwrap().via(80), Via::H2c);
        let both = links(true, Versions::H2C, vec![8080]).unwrap();
        assert_eq!(both.via(443), Via::Tls { http2: true });
        assert_eq!(both.via(8080), Via::H2c);
        // HTTP/3 needs TLS, and is all there is then.
        let three = Versions::parse(["3"]).unwrap();
        assert_eq!(links(true, three, vec![]).unwrap().via(443), Via::Http3);
        let tls = None;
        assert!(Links::new(tls, three, Duration::from_secs(3), None).is_err());
    }

    #[test]
    fn the_target_of_a_request_takes_the_host_out_of_the_headers() {
        let name = crate::upstreams::Name::new("backend.test:8443".parse().unwrap(), 1);
        let server = Server::new(&name, "10.0.0.5".parse().unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("example.test"));
        headers.insert("x-kept", HeaderValue::from_static("1"));
        let uri = target(
            &mut headers,
            Scheme::HTTPS,
            PathAndQuery::from_static("/a?b=1"),
            &server,
        );
        assert_eq!(uri.to_string(), "https://example.test/a?b=1");
        assert!(!headers.contains_key(HOST) && headers.contains_key("x-kept"));
        // No Host, or one that is no authority: the upstream as written.
        let uri = target(&mut headers, Scheme::HTTP, PathAndQuery::from_static("/"), &server);
        assert_eq!(uri.to_string(), "http://backend.test:8443/");
        headers.insert(HOST, HeaderValue::from_static("not a host"));
        let uri = target(&mut headers, Scheme::HTTP, PathAndQuery::from_static("/"), &server);
        assert_eq!(uri.authority().unwrap().as_str(), "backend.test:8443");

        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("te", "gzip"),
            ("upgrade", "h2c"),
            ("accept", "*/*"),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }
        let headers = without_connection_fields(headers);
        assert_eq!(headers.len(), 1, "{headers:?}");
        let mut headers = HeaderMap::new();
        headers.insert(TE, HeaderValue::from_static("trailers"));
        assert_eq!(without_connection_fields(headers).len(), 1);
    }
}
