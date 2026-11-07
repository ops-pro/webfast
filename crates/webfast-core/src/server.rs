//! Listeners and connections: one TCP listener per port (HTTP/1.1, HTTP/2 over TLS, h2c when
//! enabled) and, for TLS ports with h3, a QUIC endpoint on the same port number. A request is
//! routed to the site whose host matches (exact, wildcard, catch-all), runs its handler chain and
//! is logged when its body ends. HTTPS responses over TCP advertise HTTP/3 (`Alt-Svc`).
//!
//! Client IP as in Caddy: for a peer in `trusted_proxies`, the left-most valid address of the
//! `client_ip_headers` (right-most untrusted with `trusted_proxies_strict`); otherwise the peer.

use crate::accesslog::{Logged, RequestInfo};
use crate::body::{Body, boxed};
use crate::config::{Config, Limits, Protocols, ReloadMode, ServerConfig, Site};
use crate::extensions::{At, Client, ErrorPage, Hooks, RequestCheck};
use crate::guard::{Activity, Admission, Place, Tracked};
use crate::handler::{ConnInfo, Ctx, Failed, Handler, Next, Route, SentRequest, hostport_of, strip_port};
use crate::tls::{self, CertResolver};
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Version};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use ipnet::IpNet;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

/// What a request needs from its server (port). The routing is replaced whole when the
/// configuration is reloaded (`Running::reload`); the rest is the port's own.
pub struct ServerState {
    routing: ArcSwap<Routing>,
    /// WEB_RELOAD: with `lazy` and `drain` a connection keeps the routing it was accepted with
    /// (`ConnState`); with `drain` it is also asked to close after a reload (src/guard.rs `Retire`).
    mode: ReloadMode,
    /// The routing's generation, sent by each reload (to the connections `drain` retires).
    reloads: watch::Sender<u64>,
    /// With `lazy` and `drain`, the routings a reload replaced, while connections still use them:
    /// when files change their ready answers are forgotten too (src/watch.rs), so that those
    /// connections serve the files as they are now.
    retired: Mutex<Vec<Weak<Routing>>>,
    tls: bool,
    /// The `Alt-Svc` value with HTTP/3 on; a static string, so that a response's copy of it counts
    /// no reference every core shares.
    alt_svc: Option<&'static str>,
    /// TLS with the Host check on (`strict_sni_host`, on unless `insecure_off`): the certificates,
    /// to tell whether a request's Host is served with the connection's one.
    host_check: Option<Arc<CertResolver>>,
    /// `max_header_size`: HTTP/2 and HTTP/3 refuse more themselves (431), HTTP/1.1 in `handle`.
    max_header: usize,
    /// The extensions' hooks (src/extensions.rs): the checks before the routes, and those bound to
    /// upstreams for the proxies.
    hooks: &'static Hooks,
}

/// A port's sites, and whose word on the client's address is taken.
pub struct Routing {
    sites: Vec<Site>,
    /// The sites' host patterns, by name (`select`).
    index: crate::matcher::HostIndex,
    trusted: Vec<IpNet>,
    strict: bool,
    client_ip_headers: Vec<HeaderName>,
    /// Counts the reloads: a connection that outlives the routing it was accepted with works out
    /// again whether its peer is trusted.
    generation: u64,
    /// A site's routes may send Early Hints (`respond 103`): HTTP/3 then gives each request the
    /// channel they go through (src/h3.rs), and not otherwise.
    early_hints: bool,
}

/// What the requests of one connection share: the port, the connection's facts, and — with
/// WEB_RELOAD=lazy or drain — the routing it was accepted with, which it keeps while it is open.
/// One per connection, so that its requests count references on it, not on the port that every
/// connection shares.
pub struct ConnState {
    state: Arc<ServerState>,
    info: Arc<ConnInfo>,
    pinned: Option<Arc<Routing>>,
    /// The routing's generation `info.trusted` was worked out with.
    generation: u64,
}

impl ConnState {
    pub fn info(&self) -> &Arc<ConnInfo> {
        &self.info
    }

    /// The connection's facts under `routing`: the same unless a reload changed whether its peer
    /// is trusted.
    fn info_under(&self, routing: &Routing) -> Arc<ConnInfo> {
        let trusted = routing.trusts(self.info.remote.ip());
        if trusted == self.info.trusted {
            return self.info.clone();
        }
        Arc::new(ConnInfo {
            remote: self.info.remote,
            tls: self.info.tls,
            trusted,
            sni: self.info.sni.clone(),
        })
    }

    /// Whether a route of the routing this connection's requests take may send Early Hints.
    pub(crate) fn may_hint(&self) -> bool {
        match &self.pinned {
            Some(pinned) => pinned.early_hints,
            None => self.state.routing.load().early_hints,
        }
    }
}

impl ServerState {
    /// The routing in use, counted: for work that outlives a request (src/watch.rs).
    pub(crate) fn routing(&self) -> Arc<Routing> {
        self.routing.load_full()
    }

    /// The routings that connections use: the current one, and with WEB_RELOAD=lazy or drain
    /// those that connections accepted before a reload still keep.
    pub(crate) fn routings(&self) -> Vec<Arc<Routing>> {
        let mut all = vec![self.routing.load_full()];
        let mut retired = self.retired.lock().unwrap_or_else(PoisonError::into_inner);
        retired.retain(|routing| routing.strong_count() > 0);
        all.extend(retired.iter().filter_map(Weak::upgrade));
        all
    }

    /// A request on this TLS connection for a host served with another certificate than the one
    /// the connection was opened for (RFC 9110 §15.5.20: answered 421, the client asks again on a
    /// connection of its own).
    fn misdirected(&self, conn: &ConnInfo, parts: &http::request::Parts) -> bool {
        match &self.host_check {
            Some(certificates) if conn.tls => {
                !certificates.same_certificate(conn.sni.as_deref(), strip_port(hostport_of(parts)))
            }
            _ => false,
        }
    }

    pub(crate) fn tls(&self) -> bool {
        self.tls
    }

    /// Whether `peer` is a trusted proxy under the routing in use now (what admission needs of a
    /// connection before anything else is known of it).
    pub(crate) fn trusts(&self, peer: IpAddr) -> bool {
        self.routing.load().trusts(peer)
    }

    /// A new connection with no TLS name: `connection_named` without one.
    pub fn connection(self: &Arc<Self>, remote: SocketAddr) -> Arc<ConnState> {
        self.connection_named(remote, None)
    }

    /// A new connection, once its TLS handshake named `sni` (for the Host check; `None`: none, or
    /// plain HTTP): its facts, worked out with the routing in use now — which it keeps with
    /// WEB_RELOAD=lazy or drain. Made once per connection, after the handshake.
    pub fn connection_named(self: &Arc<Self>, remote: SocketAddr, sni: Option<&str>) -> Arc<ConnState> {
        let current = self.routing.load();
        let info = Arc::new(
            ConnInfo {
                remote,
                tls: self.tls,
                trusted: current.trusts(remote.ip()),
                sni: None,
            }
            .with_sni(sni),
        );
        let generation = current.generation;
        let pinned = self.mode.pins().then(|| arc_swap::Guard::into_inner(current));
        Arc::new(ConnState {
            state: self.clone(),
            info,
            pinned,
            generation,
        })
    }

    /// With WEB_RELOAD=drain, when `conn` is to close after a reload (src/guard.rs `Retire`).
    pub(crate) fn retire(&self, conn: &ConnState) -> Option<crate::guard::Retire> {
        match self.mode {
            ReloadMode::Drain(window) => Some(crate::guard::Retire {
                reloads: self.reloads.subscribe(),
                generation: conn.generation,
                window,
            }),
            _ => None,
        }
    }
}

impl Routing {
    fn new(
        sites: Vec<Site>,
        trusted: Vec<IpNet>,
        strict: bool,
        client_ip_headers: Vec<HeaderName>,
        generation: u64,
    ) -> Routing {
        let index = crate::matcher::HostIndex::new(sites.iter().map(|site| site.hosts.as_slice()));
        let early_hints = sites
            .iter()
            .any(|site| emits_hints(&site.routes) || site.errors.as_deref().is_some_and(emits_hints));
        Routing {
            sites,
            index,
            trusted,
            strict,
            client_ip_headers,
            generation,
            early_hints,
        }
    }

    pub(crate) fn sites(&self) -> &[Site] {
        &self.sites
    }

    fn trusts(&self, peer: IpAddr) -> bool {
        self.trusted.iter().any(|n| n.contains(&peer))
    }

    /// The site for the request's host: the first, in order, that takes any host or names this
    /// one (exactly or by a wildcard). The host is looked at only when the first site names hosts.
    fn select(&self, parts: &http::request::Parts) -> Option<&Site> {
        let any = self.index.any().first().copied();
        if any == Some(0) {
            return self.sites.first();
        }
        let host = strip_port(hostport_of(parts));
        let named = self.index.lookup(host, |exact, wildcard| {
            exact.first().into_iter().chain(wildcard.first()).min().copied()
        });
        let first = any.into_iter().chain(named).min()?;
        self.sites.get(first as usize)
    }

    fn client_ip(&self, headers: &HeaderMap, peer: IpAddr) -> IpAddr {
        for field in &self.client_ip_headers {
            let mut values = headers.get_all(field).iter().filter_map(|v| v.to_str().ok()).peekable();
            if values.peek().is_none() {
                continue;
            }
            if self.strict {
                // From the last value back (the nearest proxy's), with no list of them made.
                for value in headers.get_all(field).iter().rev().filter_map(|v| v.to_str().ok()) {
                    for part in value.rsplit(',') {
                        if let Some(ip) = parse_ip(part)
                            && !self.trusted.iter().any(|n| n.contains(&ip))
                        {
                            return ip;
                        }
                    }
                }
            } else if let Some(ip) = values.flat_map(|v| v.split(',')).find_map(parse_ip) {
                return ip;
            }
        }
        peer
    }
}

/// A `respond 103` among `routes`, subroutes included.
fn emits_hints(routes: &[Route]) -> bool {
    routes.iter().any(|route| match &route.handler {
        Handler::Respond {
            status: Some(StatusCode::EARLY_HINTS),
            ..
        } => true,
        Handler::Subroute(routes) => emits_hints(routes),
        _ => false,
    })
}

/// An address from a client IP header: bare, with a port, bracketed IPv6, with a zone.
fn parse_ip(part: &str) -> Option<IpAddr> {
    let part = part.trim();
    if let Ok(ip) = part.parse::<IpAddr>() {
        return Some(ip.to_canonical());
    }
    if let Ok(addr) = part.parse::<SocketAddr>() {
        return Some(addr.ip().to_canonical());
    }
    let host = part.trim_start_matches('[');
    let host = host.split(']').next().unwrap_or(host);
    host.split('%')
        .next()?
        .parse::<IpAddr>()
        .ok()
        .map(|ip| ip.to_canonical())
}

/// How a request is answered.
enum Way {
    /// A file's ready answer (src/memo.rs).
    Ready(Response<Body>),
    /// The handler chain, and the site's `handle_errors` routes.
    Chain(Arc<[Route]>, Option<Arc<[Route]>>),
}

/// A request check's refusal, with the site's `handle_errors` routes when it is to go through them.
type Refusal = (Response<Body>, Option<Arc<[Route]>>);

/// The `handle_errors` routes of the site a request is for, looked up again: for a request a
/// check refused when a ready answer had been found, which carries no routes.
fn errors_of(connection: &ConnState, parts: &http::request::Parts) -> Option<Arc<[Route]>> {
    let current;
    let routing: &Routing = match &connection.pinned {
        Some(pinned) => pinned,
        None => {
            current = connection.state.routing.load();
            &current
        }
    };
    routing.select(parts).and_then(|site| site.errors.clone())
}

/// Marks a request the server makes of its own routes (an API spec given as a path, src/apifw):
/// the request checks and the Host check pass it by. Only set in the process; a client cannot.
#[derive(Debug, Clone, Copy)]
pub struct InternalRequest;

/// Handles one request on any protocol, with its log line bound to the response body (for a
/// request the server makes of itself, src/extensions.rs; the protocols take `handle_with_log`).
pub async fn handle(connection: Arc<ConnState>, request: Request<Body>) -> Response<Body> {
    let (response, log) = handle_with_log(connection, request).await;
    match log {
        Some(log) => response.map(|body| boxed(Tracked::new(body, None, Some(log)))),
        None => response,
    }
}

/// Handles one request on any protocol. With it, when the site logs, what writes the access log
/// line once the response body has been sent: the caller puts it in the body's wrapper it makes
/// anyway (src/guard.rs `Tracked`), so no body is boxed for logging.
pub async fn handle_with_log(connection: Arc<ConnState>, request: Request<Body>) -> (Response<Body>, Option<Logged>) {
    let started = Instant::now();
    let (mut parts, body) = request.into_parts();
    let remote = connection.info.remote;
    let version = parts.version;
    // A request the server makes of itself (src/apifw: a spec given as a path) passes the Host
    // checks by.
    let internal = parts.extensions.get::<InternalRequest>().is_some();
    // HTTP/1.1 heads are only bounded by hyper's buffer (~400 KiB); HTTP/2 and HTTP/3 refused
    // more than this before (431), by the same count.
    if field_section_size(&parts.headers) > connection.state.max_header {
        return (
            refused(&connection.state, version, StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE),
            None,
        );
    }
    // A host that is no name or address, or a Host and an authority that differ: 400 before
    // anything reads it (Caddy 2.11.8 and 2.11.9).
    if !internal && crate::handler::bad_host(&parts) {
        return (refused(&connection.state, version, StatusCode::BAD_REQUEST), None);
    }
    // A Host served with another certificate than the connection's gets 421 (RFC 9110 §15.5.20).
    let misdirected = !internal && connection.state.misdirected(&connection.info, &parts);
    // The site, in the connection's routing (WEB_RELOAD=lazy, drain) or in the port's as it is now; what
    // the request needs of it is taken out, so that nothing holds the routing across an await.
    let picked = {
        let current;
        let routing: &Routing = match &connection.pinned {
            Some(pinned) => pinned,
            None => {
                current = connection.state.routing.load();
                &current
            }
        };
        let conn = if routing.generation == connection.generation {
            connection.info.clone()
        } else {
            connection.info_under(routing)
        };
        let client_ip = if conn.trusted {
            routing.client_ip(&parts.headers, remote.ip())
        } else {
            remote.ip()
        };
        routing.select(&parts).map(|site| {
            let way = match site.answers.load().as_ref().and_then(|answers| answers.answer(&parts)) {
                Some(response) => Way::Ready(response),
                None => Way::Chain(site.routes.clone(), site.errors.clone()),
            };
            // The log's two enums by value: no count on the site touched.
            (conn, client_ip, site.log.as_deref().copied(), way)
        })
    };
    let state = &connection.state;
    let Some((conn, client_ip, log, way)) = picked else {
        // Like Caddy: a host no site serves gets an empty 200.
        let mut response = Response::new(crate::body::empty());
        if misdirected {
            *response.status_mut() = StatusCode::MISDIRECTED_REQUEST;
        }
        common_headers(state, version, &mut response);
        return (response, None);
    };
    // What the access log needs, as cheap copies, and only when the site logs.
    let info = log.as_ref().map(|_| RequestInfo {
        remote,
        client_ip,
        proto: proto_name(version),
        method: parts.method.clone(),
        host: parts.headers.get(http::header::HOST).cloned(),
        uri: parts.uri.clone(),
        started,
    });
    // Refused before the routes and ready answers: a Host of another certificate (421), then by
    // the request checks. A refusal that asks for the site's error page (`ErrorPage`) goes
    // through its `handle_errors` routes, as a handler's own failure does; the others go out as
    // they are.
    let mut refused: Option<Refusal> = None;
    let (way, body) = if misdirected {
        let mut response = Response::new(crate::body::empty());
        *response.status_mut() = StatusCode::MISDIRECTED_REQUEST;
        (Way::Ready(response), crate::body::empty())
    } else if !internal {
        let client = Client {
            ip: client_ip,
            conn: &conn,
            at: At::Routes,
        };
        match state.hooks.request.check(&mut parts, body, client).await {
            Ok(body) => (way, body),
            Err(response) => {
                let errors = match &way {
                    _ if response.extensions().get::<ErrorPage>().is_none() => None,
                    Way::Chain(_, errors) => errors.clone(),
                    // A ready answer carries no error routes: the site is looked up again, on a
                    // refusal only.
                    Way::Ready(_) => errors_of(&connection, &parts),
                };
                refused = Some((response, errors));
                (way, crate::body::empty())
            }
        }
    } else {
        (way, body)
    };
    let mut response = match refused {
        Some((response, Some(errors))) => {
            // Through the site's error routes, as a handler's failure: the request as sent goes
            // with it.
            let mut ctx = Ctx::new(conn.clone(), parts, crate::body::empty(), client_ip);
            ctx.for_errors = true;
            let response = ctx.respond(response);
            let mut response = ctx.failed(response, None);
            let sent = response.extensions_mut().remove::<SentRequest>();
            match (response.extensions().get::<Failed>(), sent) {
                (Some(Failed(error)), Some(SentRequest(original))) => {
                    let error = error.clone();
                    crate::handler::handle_error(&errors, conn, *original, client_ip, error, response).await
                }
                _ => response,
            }
        }
        Some((response, None)) => response,
        None => match way {
            Way::Ready(response) => response,
            Way::Chain(routes, errors) => {
                // With `handle_errors`, a failure brings the request as sent back with it.
                let kept = errors.map(|errors| (errors, conn.clone()));
                let mut ctx = Ctx::new(conn, parts, body, client_ip);
                ctx.for_errors = kept.is_some();
                if !internal {
                    ctx.upstream_hooks = state.hooks.upstream.as_ref();
                    ctx.server_hooks = Some(state.hooks);
                }
                let mut response = Next::start(routes).walk(ctx).await;
                let sent = response.extensions_mut().remove::<SentRequest>();
                match (kept, response.extensions().get::<Failed>(), sent) {
                    (Some((errors, conn)), Some(Failed(error)), Some(SentRequest(original))) => {
                        let error = error.clone();
                        crate::handler::handle_error(&errors, conn, *original, client_ip, error, response).await
                    }
                    _ => response,
                }
            }
        },
    };
    common_headers(state, version, &mut response);
    let status = response.status().as_u16();
    let log = match (log, info) {
        (Some(log), Some(info)) => Some(Logged::new(log, info, status)),
        _ => None,
    };
    (response, log)
}

/// The request with its body under the stall limit: a client that stops sending it for `stall`
/// ends the body with an error, and the handler reading it (the proxy) answers 408
/// (src/guard.rs `StalledBody`).
pub fn stall_limited(request: Request<Body>, stall: Duration) -> Request<Body> {
    // A body already complete (none: most requests) never stalls: left as it is, nothing marked.
    if http_body::Body::is_end_stream(request.body()) {
        return request;
    }
    request.map(|body| boxed(crate::guard::StalledBody::new(body, stall)))
}

/// What every response gets: `Date` from the shared clock (a proxied response keeps the upstream's,
/// as in Caddy; hyper's own date is left for the error responses it writes itself) and, with
/// HTTP/3 on, `Alt-Svc` over TCP.
/// A request refused before the routes, for what its head is: empty, and on HTTP/1.x the last
/// on its connection (what else the client sent cannot be trusted to frame the next one).
fn refused(state: &ServerState, version: Version, status: StatusCode) -> Response<Body> {
    let mut response = Response::new(crate::body::empty());
    *response.status_mut() = status;
    if version <= Version::HTTP_11 {
        response
            .headers_mut()
            .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
    }
    common_headers(state, version, &mut response);
    response
}

/// The size of a request's header fields as HTTP/2 and HTTP/3 count it: name, value and 32 bytes
/// of each (RFC 9113 §6.5.2).
fn field_section_size(headers: &http::HeaderMap) -> usize {
    headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len() + 32)
        .sum()
}

fn common_headers(state: &ServerState, version: Version, response: &mut Response<Body>) {
    let headers = response.headers_mut();
    headers.entry(http::header::DATE).or_insert_with(crate::date::now);
    if version != Version::HTTP_3
        && let Some(alt_svc) = state.alt_svc
    {
        headers.insert(http::header::ALT_SVC, HeaderValue::from_static(alt_svc));
    }
}

fn proto_name(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

/// A started server: its bound addresses, how to reload and how to stop it.
pub struct Running {
    /// Configured port → bound TCP address (and the QUIC one when HTTP/3 is on).
    pub bound: Vec<(u16, SocketAddr, Option<SocketAddr>)>,
    /// Ready answers prepared, over every site (src/memo.rs).
    pub ready: Ready,
    stop: watch::Sender<bool>,
    /// Open connections per port: shutdown waits for them.
    admissions: Vec<Arc<Admission>>,
    tasks: Vec<JoinHandle<()>>,
    quic: Vec<quinn::Endpoint>,
    /// Each port as started: what a reload may change (its routing, its certificates) and what it
    /// may not (`Shape`).
    ports: Vec<Port>,
    /// The site roots in memory, which a reload takes over (src/files.rs `Loader::reusing`).
    stores: Vec<Arc<crate::files::FileStore>>,
    watcher: Option<crate::watch::Watcher>,
}

struct Port {
    shape: Shape,
    state: Arc<ServerState>,
    resolver: Option<Arc<CertResolver>>,
}

/// What a port was started with that only a restart can change: its listening sockets, TLS or
/// not, its protocols (and so its QUIC endpoint), limits, threads and reload mode.
#[derive(Debug, Clone, PartialEq)]
struct Shape {
    port: u16,
    tls: bool,
    /// `strict_sni_host`: the Host check is set up with the port's certificates.
    strict_host: bool,
    protocols: Protocols,
    limits: Limits,
    per_core: bool,
    workers: Option<usize>,
    reload: ReloadMode,
}

impl Shape {
    fn of(server: &ServerConfig) -> Shape {
        Shape {
            port: server.port,
            tls: server.tls.is_some(),
            strict_host: server.strict_host,
            protocols: server.protocols,
            limits: server.limits,
            per_core: server.per_core,
            workers: server.workers,
            reload: server.reload,
        }
    }

    /// What differs from `new`, for the refusal.
    fn differences(&self, new: &Shape) -> Vec<&'static str> {
        let mut what = Vec::new();
        if self.tls != new.tls {
            what.push("TLS on or off");
        }
        if self.strict_host != new.strict_host {
            what.push("strict_sni_host");
        }
        if self.protocols != new.protocols {
            what.push("protocols");
        }
        if self.limits != new.limits {
            what.push("timeouts or limits");
        }
        if self.per_core != new.per_core || self.workers != new.workers {
            what.push("threads");
        }
        if self.reload != new.reload {
            what.push("WEB_RELOAD");
        }
        what
    }
}

/// What preparing the ready answers gave and cost.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ready {
    /// Paths answered without the handler chain.
    pub paths: usize,
    /// Distinct answers held.
    pub answers: usize,
    /// Memory they hold (src/memo.rs `Answers::bytes`; the bodies are the files').
    pub bytes: u64,
    pub millis: u64,
}

impl Running {
    /// The certificate resolvers of the TLS ports (the ACME thread tells them of new files).
    #[cfg(feature = "acme")]
    pub(crate) fn resolvers(&self) -> Vec<Arc<CertResolver>> {
        self.ports.iter().filter_map(|p| p.resolver.clone()).collect()
    }

    /// The site roots in memory (for loading a new configuration that takes them over).
    pub fn stores(&self) -> Vec<Arc<crate::files::FileStore>> {
        self.stores.clone()
    }

    /// Puts a new configuration in place without dropping a connection: each port's sites, trusted
    /// proxies and client IP headers are replaced whole, its certificates read again, and the files
    /// watched are the new configuration's. Requests under way finish with the configuration they
    /// started with. The ports must stay as they are (`Shape`): what only a restart can change is
    /// refused, and the running configuration stays — as it does when anything else fails.
    pub async fn reload(&mut self, config: Config) -> Result<Ready> {
        // The request checks stay as they started: the new routes must still send to the upstreams
        // they are bound to.
        if let Some(port) = self.ports.first() {
            port.state.hooks.bound_within(&config.upstreams())?;
        }
        // The new configuration's upstream names, resolved before it is taken (src/dns.rs).
        crate::dns::begin(&config)?;
        #[cfg(feature = "acme")]
        let acme = config.acme.clone();
        let Config {
            servers,
            stores,
            watch,
            max_memory,
            ..
        } = config;
        let ports: Vec<u16> = self.ports.iter().map(|p| p.shape.port).collect();
        let mut new_ports: Vec<u16> = servers.iter().map(|s| s.port).collect();
        new_ports.sort_unstable();
        let mut old_ports = ports.clone();
        old_ports.sort_unstable();
        if new_ports != old_ports {
            anyhow::bail!("the ports changed ({old_ports:?} to {new_ports:?}); restart to listen on others");
        }
        let mut placed = Vec::new();
        for server in servers {
            let i = ports.iter().position(|p| *p == server.port).expect("the same ports");
            let what = self.ports[i].shape.differences(&Shape::of(&server));
            if !what.is_empty() {
                anyhow::bail!("port {}: {} changed; restart to apply", server.port, what.join(", "));
            }
            // Read now, installed with the rest: a certificate that cannot be read stops the reload.
            let certificates = match (&server.tls, &self.ports[i].resolver) {
                (Some(specs), Some(_)) => Some(CertResolver::read(specs, &tls::provider())?),
                _ => None,
            };
            placed.push((i, server, certificates));
        }
        // The ready answers of the new sites, worked out on every CPU before anything changes.
        let tls_of: Vec<bool> = placed.iter().map(|(i, ..)| self.ports[*i].shape.tls).collect();
        let (placed, ready) = tokio::task::spawn_blocking(move || {
            let mut ready = Ready::default();
            for ((_, server, _), tls) in placed.iter_mut().zip(tls_of) {
                for site in &mut server.sites {
                    prepare_answers(server.port, site, tls, &mut ready);
                }
            }
            (placed, ready)
        })
        .await
        .context("preparing the ready answers")?;
        for (i, server, certificates) in placed {
            let port = &self.ports[i];
            let state = &port.state;
            let generation = state.routing.load().generation + 1;
            let old = state.routing.swap(Arc::new(Routing::new(
                server.sites,
                server.trusted_proxies,
                server.trusted_strict,
                server.client_ip_headers,
                generation,
            )));
            // WEB_RELOAD=lazy or drain: connections keep the old routing while they are open (also
            // one being accepted right now, which may not hold it yet: kept whatever its count).
            if state.mode.pins() {
                let mut retired = state.retired.lock().unwrap_or_else(PoisonError::into_inner);
                retired.retain(|routing| routing.strong_count() > 0);
                retired.push(Arc::downgrade(&old));
            }
            if let (Some(resolver), Some(certificates)) = (&port.resolver, certificates) {
                resolver.install(certificates);
            }
            // With drain, the connections on older routings now draw their moment to close.
            state.reloads.send_replace(generation);
        }
        // The files watched are the new configuration's (the roots it kept are looked at again at
        // once, as at startup).
        if let Some(watcher) = self.watcher.take() {
            watcher.stop();
        }
        let states: Vec<Arc<ServerState>> = self.ports.iter().map(|p| p.state.clone()).collect();
        self.watcher = crate::watch::start(watch, &stores, &states, max_memory);
        self.stores = stores;
        self.ready = ready;
        #[cfg(feature = "acme")]
        if let Some(settings) = acme {
            crate::acme::start(settings, self.resolvers());
        }
        Ok(ready)
    }

    /// Stops accepting, lets open requests finish (up to `grace`), then closes everything.
    pub async fn shutdown(self, grace: Duration) {
        if let Some(watcher) = &self.watcher {
            watcher.stop();
        }
        let _ = self.stop.send(true);
        // The accept loops stop at once; open connections are asked to finish (GOAWAY).
        for task in self.tasks {
            let _ = task.await;
        }
        let admissions = self.admissions;
        let quic = self.quic;
        let wait = async move {
            for admission in &admissions {
                admission.all_closed().await;
            }
            for endpoint in &quic {
                endpoint.wait_idle().await;
            }
        };
        if tokio::time::timeout(grace, wait).await.is_err() {
            tracing::warn!(
                grace_secs = grace.as_secs(),
                "connections still open after the grace period; closing them"
            );
        }
    }
}

pub async fn start(config: Config) -> Result<Running> {
    crate::date::start();
    let (stop, _) = watch::channel(false);
    let mut running = Running {
        bound: Vec::new(),
        ready: Ready::default(),
        stop,
        admissions: Vec::new(),
        tasks: Vec::new(),
        quic: Vec::new(),
        ports: Vec::new(),
        stores: Vec::new(),
        watcher: None,
    };
    crate::extensions::check_bindings(&config)?;
    let hooks = Hooks::new(&config);
    // What the extensions do once the server runs (src/extensions.rs): begun before the servers
    // take the configuration, finished with their states.
    let started = crate::extensions::Started::begin(&config)?;
    for server in config.servers {
        start_server(server, &mut running, hooks).await?;
    }
    let states: Vec<Arc<ServerState>> = running.ports.iter().map(|p| p.state.clone()).collect();
    started.finish(&states)?;
    #[cfg(feature = "acme")]
    if let Some(settings) = config.acme.clone() {
        crate::acme::start(settings, running.resolvers());
    }
    running.watcher = crate::watch::start(config.watch, &config.stores, &states, config.max_memory);
    running.stores = config.stores;
    Ok(running)
}

/// Works out a site's ready answers (src/memo.rs; it blocks until done), counted in `ready`.
fn prepare_answers(port: u16, site: &mut Site, tls: bool, ready: &mut Ready) {
    let started = Instant::now();
    if let Some(answers) = crate::memo::Answers::prepare(&site.routes, tls) {
        let millis = started.elapsed().as_millis() as u64;
        let bytes = answers.bytes();
        tracing::info!(
            port,
            hosts = ?site.hosts,
            paths = answers.paths(),
            answers = answers.answers(),
            memory_kib = bytes / 1024,
            ms = millis,
            "ready answers for the site's files"
        );
        ready.paths += answers.paths();
        ready.answers += answers.answers();
        ready.bytes += bytes;
        ready.millis += millis;
        site.answers.store(Some(Arc::new(answers)));
    } else {
        tracing::info!(
            port,
            hosts = ?site.hosts,
            "no ready answers: the site's routes look at more than the path"
        );
    }
}

/// Listening sockets for a port: on Unix `workers` of them (`None`: one per CPU, at most 64) with
/// SO_REUSEPORT, each with its own accept loop — the kernel spreads new connections over them, and
/// another process can bind the port while this one finishes (restarts without a gap). Dual-stack
/// `[::]` when available, else `0.0.0.0`. Also returns the socket options the system refused
/// (src/sockets.rs).
fn bind_tcp(port: u16, limits: &Limits, workers: Option<usize>) -> Result<(Vec<TcpListener>, Vec<String>)> {
    let count = if cfg!(unix) {
        workers.unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()).min(64))
    } else {
        1
    };
    let listen = |address: SocketAddr| crate::sockets::tcp_listener(address, limits);
    let ((first, refused), family) = match listen(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)) {
        Ok(listener) => (listener, IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        Err(_) => (
            listen(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
                .with_context(|| format!("cannot listen on port {port}"))?,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        ),
    };
    // Port 0 (tests): the others join the port the first one got.
    let port = first.local_addr()?.port();
    let mut listeners = vec![first];
    for _ in 1..count {
        let (listener, _) =
            listen(SocketAddr::new(family, port)).with_context(|| format!("cannot listen on port {port}"))?;
        listeners.push(listener);
    }
    Ok((listeners, refused))
}

fn bind_quic(port: u16, config: quinn::ServerConfig) -> Result<quinn::Endpoint> {
    let bound = crate::sockets::udp_socket(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port))
        .or_else(|_| crate::sockets::udp_socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)));
    let (socket, receive, send) = bound.with_context(|| format!("cannot listen on UDP port {port} (HTTP/3)"))?;
    tracing::info!(port, receive_buffer = receive, send_buffer = send, "HTTP/3 socket");
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .with_context(|| format!("cannot serve HTTP/3 on UDP port {port}"))
}

async fn start_server(server: ServerConfig, running: &mut Running, hooks: &'static Hooks) -> Result<()> {
    let shape = Shape::of(&server);
    let ServerConfig {
        port,
        tls,
        strict_sni,
        ticket_keys,
        strict_host,
        protocols,
        trusted_proxies,
        trusted_strict,
        client_ip_headers,
        limits,
        per_core,
        workers,
        reload,
        mut sites,
    } = server;
    let admission = Admission::new(&limits);
    for site in &mut sites {
        prepare_answers(port, site, tls.is_some(), &mut running.ready);
    }
    running.admissions.push(admission.clone());
    let (listeners, refused) = bind_tcp(port, &limits, workers)?;
    for option in &refused {
        tracing::warn!(port, option = %option, "socket option not available; the system's default stays");
    }
    let tcp_addr = listeners[0].local_addr()?;
    let bound_port = tcp_addr.port();

    let mut acceptor = None;
    let mut quic_resolver = None;
    let mut port_resolver = None;
    let mut host_check = None;
    if let Some(specs) = tls {
        let resolver = Arc::new(CertResolver::new(specs, strict_sni, &tls::provider())?);
        tls::watch(resolver.clone());
        port_resolver = Some(resolver.clone());
        if strict_host {
            host_check = Some(resolver.clone());
        }
        let mut alpn: Vec<&[u8]> = Vec::new();
        if protocols.h2 {
            alpn.push(b"h2");
        }
        if protocols.h1 {
            alpn.push(b"http/1.1");
        }
        // TLS-ALPN-01 (src/acme): offered so that a validation handshake can ask for it; the
        // resolver answers it only for a host with a challenge up.
        #[cfg(feature = "acme")]
        alpn.push(crate::acme::challenge::ALPN);
        let config = tls::server_config(resolver.clone(), &alpn, false, ticket_keys.clone())?;
        // For the life of the process (a reload changes the certificates through the resolver, not
        // this): borrowed by every connection, cloned by none.
        let leaked: &'static TlsAcceptor = Box::leak(Box::new(TlsAcceptor::from(Arc::new(config))));
        acceptor = Some(leaked);
        if protocols.h3 {
            quic_resolver = Some(resolver);
        }
    }
    let state_tls = acceptor.is_some();
    let mut state = ServerState {
        routing: ArcSwap::from_pointee(Routing::new(
            sites,
            trusted_proxies,
            trusted_strict,
            client_ip_headers,
            0,
        )),
        mode: reload,
        reloads: watch::channel(0).0,
        retired: Mutex::new(Vec::new()),
        tls: state_tls,
        alt_svc: None,
        host_check,
        max_header: limits.max_header,
        hooks,
    };
    let mut quic_endpoint = None;
    if let Some(resolver) = quic_resolver {
        let tls_config = tls::server_config(resolver, &[b"h3"], true, None)?;
        let quic_crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).context("QUIC TLS configuration")?;
        let mut quic_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
        // Handshakes waiting to be accepted, and the packets they may buffer (quinn: 65536, 100 MB).
        quic_config.max_incoming(4096).incoming_buffer_size_total(32 << 20);
        if let Some(transport) = Arc::get_mut(&mut quic_config.transport) {
            transport.max_concurrent_bidi_streams(250u32.into());
            transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().expect("small duration")));
        }
        let endpoint = bind_quic(bound_port, quic_config)?;
        state.alt_svc = Some(String::leak(format!("h3=\":{bound_port}\"; ma=2592000")));
        quic_endpoint = Some(endpoint);
    }
    let state = Arc::new(state);
    let mut quic_addr = None;
    if let Some(endpoint) = quic_endpoint {
        quic_addr = Some(endpoint.local_addr()?);
        let task = tokio::spawn(crate::h3::serve(
            endpoint.clone(),
            state.clone(),
            running.stop.subscribe(),
            limits,
            admission.clone(),
        ));
        running.tasks.push(task);
        running.quic.push(endpoint);
    }

    tracing::info!(
        port,
        address = %tcp_addr,
        sockets = listeners.len(),
        congestion = crate::sockets::congestion_of(&listeners[0]).unwrap_or_default(),
        tls = state_tls,
        strict_sni = state_tls && strict_sni,
        h1 = protocols.h1,
        h2 = protocols.h2 && state_tls,
        h2c = protocols.h2c && !state_tls,
        h3 = quic_addr.is_some(),
        runtime = if per_core { "per-core" } else { "shared" },
        "listening"
    );
    for listener in listeners {
        let (state, admission, stop) = (state.clone(), admission.clone(), running.stop.subscribe());
        if !per_core {
            let task = tokio::spawn(accept_loop(
                listener, state, acceptor, protocols, limits, admission, stop,
            ));
            running.tasks.push(task);
            continue;
        }
        // A thread with a single-threaded runtime for this listener: the connections it accepts are
        // polled by that thread alone, on its own epoll — no handing work between threads, as with
        // nginx's worker processes. The kernel spreads new connections over the listeners.
        let listener = listener.into_std()?;
        std::thread::Builder::new()
            .name(format!("web-{bound_port}"))
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(runtime) => runtime,
                    Err(e) => {
                        tracing::error!(error = %e, "cannot start a connection thread's runtime");
                        return;
                    }
                };
                runtime.block_on(async move {
                    let listener = match TcpListener::from_std(listener) {
                        Ok(listener) => listener,
                        Err(e) => {
                            tracing::error!(error = %e, "cannot take over a listening socket");
                            return;
                        }
                    };
                    accept_loop(listener, state, acceptor, protocols, limits, admission.clone(), stop).await;
                    // After the stop, this thread's connections run on until all are closed (the
                    // shutdown bounds that wait; when the process ends, so does the thread).
                    admission.all_closed().await;
                });
            })
            .context("cannot start a connection thread")?;
    }
    running.bound.push((port, tcp_addr, quic_addr));
    running.ports.push(Port {
        shape,
        state,
        resolver: port_resolver,
    });
    Ok(())
}

#[derive(Clone, Copy)]
enum Mode {
    Http1,
    Http2,
    Auto,
}

/// hyper's connection builders, one set per listener for the life of the process: each connection
/// borrows the one for its protocol, none is cloned per connection.
struct Builders {
    auto: auto::Builder<TokioExecutor>,
    h1: auto::Builder<TokioExecutor>,
    h2: auto::Builder<TokioExecutor>,
}

impl Builders {
    fn new(limits: &Limits) -> Builders {
        let mut builder = auto::Builder::new(TokioExecutor::new());
        // No header read timeout of hyper's own (it would make a timer per request; with none set
        // hyper needs no timer for HTTP/1 at all): the connection's `Activity` bounds the heads
        // instead, with one timer per connection (src/guard.rs).
        builder.http1().header_read_timeout(None);
        builder
            .http2()
            .timer(TokioTimer::new())
            .max_header_list_size(u32::try_from(limits.max_header).unwrap_or(u32::MAX))
            .max_concurrent_streams(250)
            .keep_alive_interval(Some(Duration::from_secs(60)));
        Builders {
            h1: builder.clone().http1_only(),
            h2: builder.clone().http2_only(),
            auto: builder,
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    state: Arc<ServerState>,
    acceptor: Option<&'static TlsAcceptor>,
    protocols: Protocols,
    limits: Limits,
    admission: Arc<Admission>,
    stop: watch::Receiver<bool>,
) {
    let builders: &'static Builders = Box::leak(Box::new(Builders::new(&limits)));
    // The server's stop is watched once here, and passed on to this listener's connections through
    // a channel of their own: what every core shares is touched once per stop, not per connection.
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
        let (stream, remote) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = &mut stopped => {
                local_stop.send_replace(true);
                break;
            }
        };
        let remote = SocketAddr::new(remote.ip().to_canonical(), remote.port());
        let Some(permit) = admission.admit(remote.ip(), state.trusts(remote.ip())) else {
            tracing::debug!(%remote, "connection refused: too many open");
            continue;
        };
        // Linux: inherited from the listening socket (src/sockets.rs); elsewhere set here.
        #[cfg(not(target_os = "linux"))]
        let _ = stream.set_nodelay(true);
        let activity = Activity::new();
        let stream = crate::guard::Io::new(stream, activity.clone());
        let stop = local_stop.subscribe();
        let state = state.clone();
        tokio::spawn(async move {
            // The connection's place: its requests carry it, and a WebSocket tunnel keeps it.
            let place = Place::new(permit, stop.clone());
            // The connection's requests, once what the connection is (its SNI) is known.
            let service = |conn: Arc<ConnState>| {
                let activity = activity.clone();
                let place = place.clone();
                // Per request only this connection's own reference counts change.
                service_fn(move |mut request: Request<Incoming>| {
                    // The request counts as in progress until its response body ends.
                    let flight = activity.begin(request.version());
                    let conn = conn.clone();
                    let cut = activity.clone();
                    // Only a request that can switch protocols (hyper's `OnUpgrade`) can become a
                    // tunnel, the one that keeps the place: no extension map made for the others.
                    if request.extensions().get::<hyper::upgrade::OnUpgrade>().is_some() {
                        request.extensions_mut().insert(place.clone());
                    }
                    async move {
                        // A body already complete (none: most requests) is replaced by the empty one,
                        // which takes no allocation — on HTTP/2 too: the stream's state stays with
                        // hyper's sender, not with the `Incoming` it hands over.
                        let request = if http_body::Body::is_end_stream(request.body()) {
                            request.map(|_| crate::body::empty())
                        } else {
                            request.map(boxed)
                        };
                        let request = stall_limited(request, limits.stall);
                        let (response, log) = handle_with_log(conn, request).await;
                        // 444 (the request filter): nothing goes out, the connection is cut.
                        if response.status().as_u16() == 444 {
                            cut.cut();
                        }
                        // Not boxed again: hyper takes the tracking body as it is.
                        Ok::<_, Infallible>(response.map(|body| Tracked::new(body, Some(flight), log)))
                    }
                })
            };
            // What may end the connection besides itself, once its facts are known (made once, after
            // the handshake: admission needed only its address).
            let ends = |conn: &ConnState| crate::guard::Ends {
                stop,
                retire: state.retire(conn),
            };
            match acceptor {
                Some(acceptor) => {
                    let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await
                    else {
                        return;
                    };
                    let mode = match stream.get_ref().1.alpn_protocol() {
                        Some(b"h2") => Mode::Http2,
                        _ if protocols.h1 => Mode::Http1,
                        _ => return,
                    };
                    let conn = state.connection_named(remote, stream.get_ref().1.server_name());
                    let ends = ends(&conn);
                    serve_connection(
                        builders,
                        TokioIo::new(stream),
                        service(conn),
                        mode,
                        &activity,
                        &limits,
                        ends,
                    )
                    .await;
                }
                None => {
                    let mode = match (protocols.h1, protocols.h2c) {
                        (true, true) => Mode::Auto,
                        (false, true) => Mode::Http2,
                        _ => Mode::Http1,
                    };
                    let conn = state.connection(remote);
                    let ends = ends(&conn);
                    serve_connection(
                        builders,
                        TokioIo::new(stream),
                        service(conn),
                        mode,
                        &activity,
                        &limits,
                        ends,
                    )
                    .await;
                }
            }
        });
    }
}

async fn serve_connection<I, S>(
    builders: &'static Builders,
    io: I,
    service: S,
    mode: Mode,
    activity: &Activity,
    limits: &Limits,
    ends: crate::guard::Ends,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    S: hyper::service::Service<Request<Incoming>, Response = Response<Tracked>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    let builder = match mode {
        Mode::Http1 => &builders.h1,
        Mode::Http2 => &builders.h2,
        Mode::Auto => &builders.auto,
    };
    // With upgrades: a request that switches protocols (WebSocket) hands the connection over. The
    // builder is borrowed: the connection is driven here, in place.
    let connection = builder.serve_connection_with_upgrades(io, service);
    crate::guard::drive(connection, |c| c.graceful_shutdown(), activity, limits, ends).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routing(strict: bool) -> Routing {
        Routing::new(
            Vec::new(),
            vec!["10.0.0.0/8".parse().unwrap(), "172.16.0.0/12".parse().unwrap()],
            strict,
            vec![HeaderName::from_static("x-forwarded-for")],
            0,
        )
    }

    #[test]
    fn strict_mode_takes_the_right_most_untrusted_forwarded_address() {
        let mut headers = HeaderMap::new();
        // The client sent "6.6.6.6"; its proxy (10.0.0.5) appended the real address and itself.
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("6.6.6.6, 203.0.113.7, 10.0.0.5"),
        );
        let peer: IpAddr = "172.18.0.3".parse().unwrap();
        assert_eq!(
            routing(true).client_ip(&headers, peer),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
        // Caddy's default: the left-most, whatever the client wrote there.
        assert_eq!(
            routing(false).client_ip(&headers, peer),
            "6.6.6.6".parse::<IpAddr>().unwrap()
        );
        // Every entry a proxy: the peer.
        headers.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.9"));
        assert_eq!(routing(true).client_ip(&headers, peer), peer);
        // Several field lines: the last line's entries first, then the line before.
        headers.insert("x-forwarded-for", HeaderValue::from_static("6.6.6.6, 198.51.100.4"));
        headers.append("x-forwarded-for", HeaderValue::from_static("10.0.0.7"));
        headers.append("x-forwarded-for", HeaderValue::from_static("172.16.1.1, 10.0.0.5"));
        assert_eq!(
            routing(true).client_ip(&headers, peer),
            "198.51.100.4".parse::<IpAddr>().unwrap()
        );
        headers.append("x-forwarded-for", HeaderValue::from_static("203.0.113.8"));
        assert_eq!(
            routing(true).client_ip(&headers, peer),
            "203.0.113.8".parse::<IpAddr>().unwrap()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn workers_set_the_listening_sockets() {
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get()).min(64);
        let (listeners, _) = bind_tcp(0, &Limits::default(), None).unwrap();
        assert_eq!(listeners.len(), cpus);
        let (listeners, _) = bind_tcp(0, &Limits::default(), Some(3)).unwrap();
        assert_eq!(listeners.len(), 3);
        let port = listeners[0].local_addr().unwrap().port();
        assert!(listeners.iter().all(|l| l.local_addr().unwrap().port() == port));
    }
}
