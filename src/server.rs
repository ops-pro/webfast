//! Listeners and connections: one TCP listener per port (HTTP/1.1, HTTP/2 over TLS, h2c when
//! enabled) and, for TLS ports with h3, a QUIC endpoint on the same port number. A request is
//! routed to the site whose host matches (exact, wildcard, catch-all), runs its handler chain and
//! is logged when its body ends. HTTPS responses over TCP advertise HTTP/3 (`Alt-Svc`).
//!
//! Client IP as in Caddy: for a peer in `trusted_proxies`, the left-most valid address of the
//! `client_ip_headers` (right-most untrusted with `trusted_proxies_strict`); otherwise the peer.

use crate::accesslog::{LoggedBody, RequestInfo};
use crate::body::{Body, boxed};
use crate::config::{Config, Protocols, ServerConfig, Site};
use crate::handler::{ConnInfo, Ctx, Next, hostport_of, strip_port};
use crate::matcher::host_matches;
use crate::tls::{self, CertResolver};
use anyhow::{Context, Result};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, Version};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use ipnet::IpNet;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

/// What a request needs from its server (port).
pub struct ServerState {
    sites: Vec<Site>,
    trusted: Vec<IpNet>,
    strict: bool,
    client_ip_headers: Vec<HeaderName>,
    tls: bool,
    alt_svc: Option<HeaderValue>,
}

impl ServerState {
    /// Connection facts shared by all its requests.
    pub fn conn_info(&self, remote: SocketAddr) -> Arc<ConnInfo> {
        Arc::new(ConnInfo {
            remote,
            tls: self.tls,
            trusted: self.trusted.iter().any(|n| n.contains(&remote.ip())),
        })
    }

    /// The site for the request's host; the host is looked at only when a site names hosts.
    fn select(&self, parts: &http::request::Parts) -> Option<&Site> {
        let mut host: Option<String> = None;
        for site in &self.sites {
            if site.hosts.is_empty() {
                return Some(site);
            }
            let host = host.get_or_insert_with(|| strip_port(hostport_of(parts)).to_ascii_lowercase());
            if site.hosts.iter().any(|h| host_matches(h, host)) {
                return Some(site);
            }
        }
        None
    }

    fn client_ip(&self, headers: &HeaderMap, peer: IpAddr) -> IpAddr {
        for field in &self.client_ip_headers {
            let mut values = headers.get_all(field).iter().filter_map(|v| v.to_str().ok()).peekable();
            if values.peek().is_none() {
                continue;
            }
            if self.strict {
                let values: Vec<&str> = values.collect();
                for value in values.iter().rev() {
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

/// Handles one request on any protocol.
pub async fn handle(state: Arc<ServerState>, conn: Arc<ConnInfo>, request: Request<Body>) -> Response<Body> {
    let started = Instant::now();
    let (parts, body) = request.into_parts();
    let remote = conn.remote;
    let client_ip = if conn.trusted {
        state.client_ip(&parts.headers, remote.ip())
    } else {
        remote.ip()
    };
    let version = parts.version;
    let Some(site) = state.select(&parts) else {
        // Like Caddy: a host no site serves gets an empty 200.
        let mut response = Response::new(crate::body::empty());
        add_alt_svc(&state, version, &mut response);
        return response;
    };
    // What the access log needs, as cheap copies, and only when the site logs.
    let info = site.log.as_ref().map(|_| RequestInfo {
        remote,
        client_ip,
        proto: proto_name(version),
        method: parts.method.clone(),
        host: parts.headers.get(http::header::HOST).cloned(),
        uri: parts.uri.clone(),
        started,
    });
    let ctx = Ctx::new(conn, parts, body, client_ip);
    let mut response = Next::start(site.routes.clone()).run(ctx).await;
    add_alt_svc(&state, version, &mut response);
    match (&site.log, info) {
        (Some(log), Some(info)) => {
            let status = response.status().as_u16();
            let log = log.clone();
            response.map(|b| boxed(LoggedBody::new(b, log, info, status)))
        }
        _ => response,
    }
}

fn add_alt_svc(state: &ServerState, version: Version, response: &mut Response<Body>) {
    if version != Version::HTTP_3
        && let Some(alt_svc) = &state.alt_svc
    {
        response.headers_mut().insert(http::header::ALT_SVC, alt_svc.clone());
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

/// A started server: its bound addresses and how to stop it.
pub struct Running {
    /// Configured port → bound TCP address (and the QUIC one when HTTP/3 is on).
    pub bound: Vec<(u16, SocketAddr, Option<SocketAddr>)>,
    stop: watch::Sender<bool>,
    graceful: Arc<GracefulShutdown>,
    tasks: Vec<JoinHandle<()>>,
    quic: Vec<quinn::Endpoint>,
}

impl Running {
    /// Stops accepting, lets open requests finish (up to `grace`), then closes everything.
    pub async fn shutdown(self, grace: Duration) {
        let _ = self.stop.send(true);
        // The accept loops stop at once and drop their handle on the connection tracker.
        for task in self.tasks {
            let _ = task.await;
        }
        let graceful = self.graceful;
        let quic = self.quic;
        let wait = async move {
            if let Ok(graceful) = Arc::try_unwrap(graceful) {
                graceful.shutdown().await;
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
    let (stop, _) = watch::channel(false);
    let graceful = Arc::new(GracefulShutdown::new());
    let mut running = Running {
        bound: Vec::new(),
        stop,
        graceful,
        tasks: Vec::new(),
        quic: Vec::new(),
    };
    for server in config.servers {
        start_server(server, &mut running).await?;
    }
    Ok(running)
}

/// Listening sockets for a port: on Unix one per CPU with SO_REUSEPORT, each with its own accept
/// loop — the kernel spreads new connections over them, and another process can bind the port while
/// this one finishes (restarts without a gap). Dual-stack `[::]` when available, else `0.0.0.0`.
fn bind_tcp(port: u16) -> Result<Vec<TcpListener>> {
    let count = if cfg!(unix) {
        std::thread::available_parallelism().map_or(1, |n| n.get()).min(64)
    } else {
        1
    };
    let (first, family) = match listen(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)) {
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
        listeners.push(listen(SocketAddr::new(family, port)).with_context(|| format!("cannot listen on port {port}"))?);
    }
    Ok(listeners)
}

fn listen(address: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = if address.is_ipv6() {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };
    socket.set_reuseaddr(true)?;
    #[cfg(unix)]
    socket.set_reuseport(true)?;
    socket.set_nodelay(true)?;
    socket.bind(address)?;
    socket.listen(1024)
}

fn bind_quic(port: u16, config: quinn::ServerConfig) -> Result<quinn::Endpoint> {
    match quinn::Endpoint::server(config.clone(), SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)) {
        Ok(endpoint) => Ok(endpoint),
        Err(_) => quinn::Endpoint::server(config, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
            .with_context(|| format!("cannot listen on UDP port {port} (HTTP/3)")),
    }
}

async fn start_server(server: ServerConfig, running: &mut Running) -> Result<()> {
    let ServerConfig {
        port,
        tls,
        protocols,
        trusted_proxies,
        trusted_strict,
        client_ip_headers,
        read_header_timeout,
        sites,
    } = server;
    let listeners = bind_tcp(port)?;
    let tcp_addr = listeners[0].local_addr()?;
    let bound_port = tcp_addr.port();

    let mut acceptor = None;
    let mut quic_resolver = None;
    if let Some(specs) = tls {
        let resolver = Arc::new(CertResolver::new(specs, &tls::provider())?);
        tls::watch(resolver.clone());
        let mut alpn: Vec<&[u8]> = Vec::new();
        if protocols.h2 {
            alpn.push(b"h2");
        }
        if protocols.h1 {
            alpn.push(b"http/1.1");
        }
        let config = tls::server_config(resolver.clone(), &alpn, false)?;
        acceptor = Some(TlsAcceptor::from(Arc::new(config)));
        if protocols.h3 {
            quic_resolver = Some(resolver);
        }
    }
    let state_tls = acceptor.is_some();
    let mut state = ServerState {
        sites,
        trusted: trusted_proxies,
        strict: trusted_strict,
        client_ip_headers,
        tls: state_tls,
        alt_svc: None,
    };
    let mut quic_endpoint = None;
    if let Some(resolver) = quic_resolver {
        let tls_config = tls::server_config(resolver, &[b"h3"], true)?;
        let quic_crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).context("QUIC TLS configuration")?;
        let mut quic_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
        if let Some(transport) = Arc::get_mut(&mut quic_config.transport) {
            transport.max_concurrent_bidi_streams(250u32.into());
            transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().expect("small duration")));
        }
        let endpoint = bind_quic(bound_port, quic_config)?;
        state.alt_svc = HeaderValue::from_str(&format!("h3=\":{bound_port}\"; ma=2592000")).ok();
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
        ));
        running.tasks.push(task);
        running.quic.push(endpoint);
    }

    tracing::info!(
        port,
        address = %tcp_addr,
        sockets = listeners.len(),
        tls = state_tls,
        h1 = protocols.h1,
        h2 = protocols.h2 && state_tls,
        h2c = protocols.h2c && !state_tls,
        h3 = quic_addr.is_some(),
        "listening"
    );
    for listener in listeners {
        let task = tokio::spawn(accept_loop(
            listener,
            state.clone(),
            acceptor.clone(),
            protocols,
            read_header_timeout,
            running.graceful.clone(),
            running.stop.subscribe(),
        ));
        running.tasks.push(task);
    }
    running.bound.push((port, tcp_addr, quic_addr));
    Ok(())
}

#[derive(Clone, Copy)]
enum Mode {
    Http1,
    Http2,
    Auto,
}

async fn accept_loop(
    listener: TcpListener,
    state: Arc<ServerState>,
    acceptor: Option<TlsAcceptor>,
    protocols: Protocols,
    read_header_timeout: Option<Duration>,
    graceful: Arc<GracefulShutdown>,
    mut stop: watch::Receiver<bool>,
) {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(read_header_timeout.unwrap_or(Duration::from_secs(30)));
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(250)
        .keep_alive_interval(Some(Duration::from_secs(60)));
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
            _ = stop.changed() => break,
        };
        let _ = stream.set_nodelay(true);
        let remote = SocketAddr::new(remote.ip().to_canonical(), remote.port());
        let conn = state.conn_info(remote);
        let state = state.clone();
        let acceptor = acceptor.clone();
        let watcher = graceful.watcher();
        let builder = builder.clone();
        tokio::spawn(async move {
            let service = {
                let state = state.clone();
                service_fn(move |request: Request<Incoming>| {
                    let state = state.clone();
                    let conn = conn.clone();
                    async move { Ok::<_, Infallible>(handle(state, conn, request.map(boxed)).await) }
                })
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
                    serve_connection(builder, TokioIo::new(stream), service, mode, watcher).await;
                }
                None => {
                    let mode = match (protocols.h1, protocols.h2c) {
                        (true, true) => Mode::Auto,
                        (false, true) => Mode::Http2,
                        _ => Mode::Http1,
                    };
                    serve_connection(builder, TokioIo::new(stream), service, mode, watcher).await;
                }
            }
        });
    }
}

async fn serve_connection<I, S>(
    builder: auto::Builder<TokioExecutor>,
    io: I,
    service: S,
    mode: Mode,
    watcher: hyper_util::server::graceful::Watcher,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    S: hyper::service::Service<Request<Incoming>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    let builder = match mode {
        Mode::Http1 => builder.http1_only(),
        Mode::Http2 => builder.http2_only(),
        Mode::Auto => builder,
    };
    let connection = builder.serve_connection(io, service).into_owned();
    if let Err(e) = watcher.watch(connection).await {
        tracing::debug!(error = %e, "connection ended with an error");
    }
}
