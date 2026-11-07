//! `reverse_proxy` to plain-HTTP upstreams over HTTP/1.1, bodies streamed both ways (SSE reaches
//! the client event by event). As in Caddy: the client's Host is passed through, X-Forwarded-For /
//! -Proto / -Host are set (kept and extended only for trusted proxies), hop-by-hop headers are
//! dropped, a failed connection answers 502 and a response-header timeout 504. Upstream response
//! headers are added to those an earlier (not deferred) `header` set, as Caddy does.
//!
//! Unlike Caddy: the other headers that name a client — `X-Real-IP`, `CF-Connecting-IP`,
//! `CF-IPCountry`, `Forwarded`, … (`CLIENT_IDENTITY_HEADERS`) — are dropped unless the peer is a
//! trusted proxy, so an upstream that reads them cannot be fed a made-up address or country; a
//! request body the client stops sending (src/guard.rs `StalledBody`) answers 408, one over its
//! `request_body` limit 413 (at once when its length says so: the upstream is not called); and
//! `response_header_timeout` has a default (src/config.rs).
//!
//! WebSocket (any `Connection: upgrade` over HTTP/1.1): the handshake goes to the upstream on a
//! connection of its own, and when it answers 101 the client's and the upstream's connections are
//! joined into a tunnel that copies bytes both ways until either side closes. The tunnel keeps the
//! client connection's place (src/guard.rs `Place`), so it counts against the connection limits.
//!
//! Request checks bound to an upstream (`upstreams` in src/jwt and src/apifw) run here, on the
//! request as it goes to that upstream, before anything is sent.

use crate::body::{Body, boxed};
use crate::extensions::{Held, PROXY, ProxyObserver, Sent, UpstreamCheck, UpstreamHeld};
use crate::guard::{BodyStalled, BodyTooLarge, Place};
use crate::handler::{Ctx, HeaderOp, RenderedOp, apply_ops};
use crate::upstreams::{NoServer, Upstreams};
use http::header::{CONNECTION, HOST, SET_COOKIE, UPGRADE};
use http::uri::{Authority, Scheme};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri};
use hyper::upgrade::OnUpgrade;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub type HttpClient = Client<HttpConnector, Body>;

pub fn client(dial_timeout: Duration, keepalive: Option<Duration>) -> HttpClient {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(dial_timeout));
    connector.set_nodelay(true);
    connector.enforce_http(true);
    let mut builder = Client::builder(TokioExecutor::new());
    // Host is always in the headers sent (`ReverseProxy::upstream_headers`, and the cache's
    // requests reuse those): the client need not look for it and make one.
    builder.set_host(false);
    builder.pool_idle_timeout(keepalive.unwrap_or(Duration::from_secs(120)));
    if keepalive.is_none() {
        builder.pool_max_idle_per_host(0);
    }
    builder.build(connector)
}

pub struct ReverseProxy {
    /// The upstreams as named (the request checks are bound to them); `servers` is what is sent
    /// to (src/upstreams.rs).
    pub upstreams: Vec<Authority>,
    pub servers: Upstreams,
    /// `lb_retries`, `lb_try_duration`, `lb_try_interval`: a request that reached no upstream
    /// (the connection failed) and has no body to send again is tried again while both allow
    /// (one that is 0 does not bound; both 0: no retry), `lb_try_interval` apart.
    pub retries: u32,
    pub try_duration: Duration,
    pub try_interval: Duration,
    pub header_up: Vec<HeaderOp>,
    pub header_down: Vec<HeaderOp>,
    pub response_header_timeout: Option<Duration>,
    /// For the connections of WebSocket handshakes (the pooled client has its own).
    pub dial_timeout: Duration,
    pub client: HttpClient,
}

/// Whether a (lowercase) field name is hop-by-hop (Caddy's list): never forwarded in either
/// direction. A match on the text: a length check and a compare, no name parsed or hashed.
fn is_hop(name: &str) -> bool {
    matches!(
        name,
        "alt-svc"
            | "connection"
            | "proxy-connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Whether the Connection field(s) list `name` (a lowercase field name): such a field is this
/// hop's too (RFC 9110 §7.6.1). Tokens are compared where they are: no name made of them.
fn connection_lists(connection: &http::header::GetAll<'_, HeaderValue>, name: &str) -> bool {
    connection
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case(name))
}

/// Headers that name the client or where it comes from, which proxies and CDNs set and upstreams
/// trust; from a peer that is not a trusted proxy they are the client's own invention.
/// (X-Forwarded-For / -Proto / -Host are handled in `forwarded_headers`.)
pub const CLIENT_IDENTITY_HEADERS: &[&str] = &[
    "cf-connecting-ip",
    "cf-connecting-ipv6",
    "cf-ipcountry",
    "cf-ray",
    "cf-visitor",
    "fastly-client-ip",
    "forwarded",
    "true-client-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "x-forwarded-port",
    "x-original-forwarded-for",
    "x-real-ip",
];

/// The headers the proxy writes itself (`forwarded_headers`).
const FORWARDED_HEADERS: &[&str] = &["x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"];

/// Whether a (lowercase) request field is not copied to the upstream: hop-by-hop, listed by the
/// Connection field, one the proxy writes itself (`FORWARDED_HEADERS`), a client-identity header
/// from a peer that is no trusted proxy, or a look-alike of one of those from anyone (no proxy
/// writes `X_Real_IP`).
fn is_withheld(name: &str, connection: &http::header::GetAll<'_, HeaderValue>, trusted: bool) -> bool {
    if is_hop(name) || FORWARDED_HEADERS.contains(&name) {
        return true;
    }
    if !trusted && CLIENT_IDENTITY_HEADERS.contains(&name) {
        return true;
    }
    if name.bytes().any(|c| c == b'_' || c == b'.')
        && CLIENT_IDENTITY_HEADERS
            .iter()
            .chain(FORWARDED_HEADERS)
            .any(|real| same_cgi_name(name, real))
    {
        return true;
    }
    connection_lists(connection, name)
}

/// The request's fields as they go to the upstream, without those `is_withheld` names, in one
/// pass: no copy of the map pruned afterwards, no probe for each name that could be there. The
/// map has room for `spare` more fields (X-Forwarded-*, Host, `header_up`) without growing; hyper
/// reuses the sent map for the response's headers, so spare room serves there too.
fn forwardable_headers(ctx: &Ctx, spare: usize) -> HeaderMap {
    let from = &ctx.req.headers;
    let connection = from.get_all(CONNECTION);
    let trusted = ctx.conn.trusted;
    let mut headers = HeaderMap::with_capacity(from.len() + spare);
    // `iter` gives a multi-valued field one value at a time: `append` keeps them all.
    for (name, value) in from.iter() {
        if !is_withheld(name.as_str(), &connection, trusted) {
            headers.append(name.clone(), value.clone());
        }
    }
    headers
}

// Inserted by a name of its own: one given as text is copied into a new name on every insert.
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");

/// Whether CGI, PHP, WSGI and Rack read the two (lowercase) field names as one variable: they turn
/// `-` into `_`, so `X_User`, `X.User` and `X-User` are all `HTTP_X_USER` there.
fn same_cgi_name(a: &str, b: &str) -> bool {
    let fold = |c: u8| if c == b'_' || c == b'.' { b'-' } else { c };
    a.len() == b.len() && a.bytes().zip(b.bytes()).all(|(x, y)| fold(x) == fold(y))
}

/// Takes off the fields spelled as one of `names` with `_` or `.` for a `-` (the names themselves
/// stay): an upstream that reads headers as CGI variables would take such a field for the real one,
/// one the server sets or only a trusted proxy may (Caddy drops every field with `_` or `.`).
/// The proxy's own look-alikes go in `is_withheld`; this is for the JWT claim headers.
#[cfg(any(feature = "jwt", test))]
pub(crate) fn remove_lookalikes<S: AsRef<str>>(headers: &mut HeaderMap, names: &[S]) {
    let lookalikes: Vec<HeaderName> = headers
        .keys()
        .filter(|field| {
            let field = field.as_str();
            field.bytes().any(|c| c == b'_' || c == b'.')
                && names
                    .iter()
                    .any(|name| name.as_ref() != field && same_cgi_name(field, name.as_ref()))
        })
        .cloned()
        .collect();
    for field in lookalikes {
        headers.remove(field);
    }
}

/// Takes the hop-by-hop fields and those the Connection field lists off a response. One pass over
/// the names present (a response has 5–10, with none or two of them: `Connection: keep-alive` and
/// its `Keep-Alive`) instead of a probe for each name that could be there; the names found are
/// kept on the stack, and only a response that lists more than fit takes a `Vec`.
pub(crate) fn remove_hop_headers(headers: &mut HeaderMap) {
    const FIT: usize = 8;
    let mut found: [Option<HeaderName>; FIT] = [const { None }; FIT];
    let mut n = 0;
    let mut more: Vec<HeaderName> = Vec::new();
    {
        let connection = headers.get_all(CONNECTION);
        for name in headers.keys() {
            if is_hop(name.as_str()) || connection_lists(&connection, name.as_str()) {
                if n < FIT {
                    found[n] = Some(name.clone());
                    n += 1;
                } else {
                    more.push(name.clone());
                }
            }
        }
    }
    for name in found.iter_mut().take(n) {
        if let Some(name) = name.take() {
            headers.remove(name);
        }
    }
    for name in more {
        headers.remove(name);
    }
}

/// The protocol a request asks to switch to (`Connection: upgrade` and an `Upgrade` field), e.g.
/// `websocket`.
fn upgrade_of(headers: &HeaderMap) -> Option<HeaderValue> {
    if connection_lists(&headers.get_all(CONNECTION), "upgrade") {
        headers.get(UPGRADE).cloned()
    } else {
        None
    }
}

impl ReverseProxy {
    pub async fn serve(self: &Arc<Self>, mut ctx: Ctx) -> Response<Body> {
        // Preparing ready answers (src/memo.rs): never kept from a proxy, so no upstream is called.
        if ctx.req.extensions.get::<crate::memo::Preparing>().is_some() {
            return ctx.status(StatusCode::BAD_GATEWAY);
        }
        // `request_body`: a body whose length is over the limit is not sent anywhere.
        let too_large = ctx.req.extensions.get::<BodyTooLarge>().cloned();
        if too_large.as_ref().is_some_and(BodyTooLarge::happened) {
            return ctx.status(StatusCode::PAYLOAD_TOO_LARGE);
        }
        // The checks bound to these upstreams (src/extensions.rs), on the request as it goes there,
        // and what they keep for the response's life (the client's slot at the upstreams).
        let held = match ctx.upstream_hooks.take() {
            Some(hooks) => {
                let body = ctx.body.take().unwrap_or_else(crate::body::empty);
                let client = crate::extensions::Client {
                    ip: ctx.client_ip,
                    conn: &ctx.conn,
                    at: crate::extensions::At::Upstream,
                };
                match hooks.check(&mut ctx.req, body, client, &self.upstreams).await {
                    Ok((body, held)) => {
                        ctx.body = Some(body);
                        held
                    }
                    Err(response) => return refusal(&mut ctx, response),
                }
            }
            None => UpstreamHeld::nothing(),
        };
        // What the observers take from the request before the upstream is called (a cache miss).
        let mut pending = PROXY.begin(&mut ctx);
        // A WebSocket handshake on a connection that can be handed over (HTTP/1.1); anything else
        // goes on as an ordinary request, its Upgrade dropped as hop-by-hop.
        if let Some(protocol) = upgrade_of(&ctx.req.headers)
            && let Some(client) = ctx.req.extensions.remove::<OnUpgrade>()
        {
            return self.tunnel(ctx, protocol, client, held).await;
        }
        // The headers go with the request, not copied; a retry (after a failed connection) makes
        // them again. Kept only for an observer that looks at them (a cache miss).
        let mut headers = Some(self.upstream_headers(&ctx));
        let keep = PROXY.wants_sent(&pending);
        let mut kept: Option<HeaderMap> = None;
        // `header_down` with placeholders is filled in now, from the request; one without is
        // applied as it is after the response. An observer that keeps what was sent (a cache
        // miss) gets it filled in either way, to apply to the upstream's later answers.
        let rendered_down: Vec<RenderedOp> = if keep {
            self.header_down.iter().map(|op| op.render(&ctx)).collect()
        } else {
            self.render_down(&ctx)
        };
        let path_and_query = ctx.req.uri.path_and_query().cloned();
        let method = ctx.req.method.clone();
        let body_stalled = ctx.req.extensions.get::<BodyStalled>().cloned();
        let mut body = ctx.body.take();
        // Without a body the request can be retried on another upstream (lb_try_duration).
        let replayable = body.as_ref().is_none_or(http_body::Body::is_end_stream);
        // The clock is read only for what reads it: `lb_try_duration` bounds the retries from
        // here, `unhealthy_latency` times each attempt.
        let started = (!self.try_duration.is_zero()).then(Instant::now);
        // The servers as they are now, kept for the request; `tried`: those it tried, by bit.
        let loaded = self.servers.load();
        let passive = self.servers.passive();
        let timed = passive.is_some_and(|p| p.unhealthy_latency.is_some());
        let mut tried: u64 = 0;
        let mut attempt: u32 = 0;
        let outcome = loop {
            let picked = match loaded.pick(&ctx, tried) {
                Ok(picked) => picked,
                // Every server up was tried: from the start again, as Caddy retries.
                Err(NoServer::AllTried) => {
                    tried = 0;
                    match loaded.pick(&ctx, 0) {
                        Ok(picked) => picked,
                        Err(_) => break Err(StatusCode::SERVICE_UNAVAILABLE),
                    }
                }
                Err(NoServer::AllDown) => {
                    tracing::warn!("no upstream is available");
                    break Err(StatusCode::SERVICE_UNAVAILABLE);
                }
                // The name has not resolved (yet): what a failed connection answers.
                Err(NoServer::NoAddress) => {
                    tracing::warn!(upstreams = ?self.upstreams, "no upstream address: the name does not resolve");
                    break Err(StatusCode::BAD_GATEWAY);
                }
            };
            tried |= 1 << picked.index;
            let (server, lease, set_cookie) = (picked.server, picked.lease, picked.set_cookie);
            let mut parts = Uri::builder().scheme(Scheme::HTTP).authority(server.authority.clone());
            if let Some(pq) = &path_and_query {
                parts = parts.path_and_query(pq.clone());
            }
            let uri = match parts.build() {
                Ok(uri) => uri,
                Err(_) => break Err(StatusCode::BAD_GATEWAY),
            };
            let request_body = if replayable {
                crate::body::empty()
            } else {
                body.take().unwrap_or_else(crate::body::empty)
            };
            let mut request = Request::new(request_body);
            *request.method_mut() = method.clone();
            *request.uri_mut() = uri;
            *request.version_mut() = http::Version::HTTP_11;
            let sending = headers.take().unwrap_or_else(|| self.upstream_headers(&ctx));
            if keep && kept.is_none() {
                kept = Some(sending.clone());
            }
            *request.headers_mut() = sending;
            let sent_at = timed.then(Instant::now);
            let sent = self.client.request(request);
            let result = match self.response_header_timeout {
                Some(limit) => match tokio::time::timeout(limit, sent).await {
                    Ok(r) => r.map_err(|e| (e.is_connect(), false)),
                    Err(_) => Err((false, true)),
                },
                None => sent.await.map_err(|e| (e.is_connect(), false)),
            };
            match result {
                Ok(response) => {
                    if let Some(passive) = passive {
                        let took = sent_at.map_or(Duration::ZERO, |at| at.elapsed());
                        if passive.faults(response.status().as_u16(), took) {
                            server.failed(passive);
                        } else {
                            server.succeeded();
                        }
                    }
                    break Ok((response, lease, set_cookie.then_some(server)));
                }
                Err((connect, timed_out)) => {
                    // The body went over its `request_body` limit while it was being sent.
                    if too_large.as_ref().is_some_and(BodyTooLarge::happened) {
                        tracing::debug!(upstream = %server.name, "the request body went over its limit");
                        break Err(StatusCode::PAYLOAD_TOO_LARGE);
                    }
                    // The client stopped sending its body: its fault, not the upstream's.
                    if body_stalled.as_ref().is_some_and(BodyStalled::happened) {
                        tracing::debug!(upstream = %server.name, "the client stopped sending the request body");
                        break Err(StatusCode::REQUEST_TIMEOUT);
                    }
                    tracing::warn!(upstream = %server.name, address = %server.addr, connect, timed_out, "upstream request failed");
                    if let Some(passive) = passive {
                        server.failed(passive);
                    }
                    if timed_out {
                        break Err(StatusCode::GATEWAY_TIMEOUT);
                    }
                    attempt += 1;
                    let allowed = (self.retries > 0 || !self.try_duration.is_zero())
                        && (self.retries == 0 || attempt <= self.retries)
                        && started.is_none_or(|at| at.elapsed() + self.try_interval < self.try_duration);
                    if !(connect && replayable && allowed) {
                        break Err(StatusCode::BAD_GATEWAY);
                    }
                    tokio::time::sleep(self.try_interval).await;
                }
            }
        };
        match outcome {
            Ok((response, lease, chosen)) => {
                let (mut parts, incoming) = response.into_parts();
                remove_hop_headers(&mut parts.headers);
                self.apply_down(&rendered_down, &mut parts.headers);
                // `lb_policy cookie`: the response that chose a server names it to the client.
                if let Some(server) = chosen
                    && let Some(cookie) = self.servers.cookie_for(server, ctx.conn.tls)
                {
                    parts.headers.append(SET_COOKIE, cookie);
                }
                if parts.status.is_server_error()
                    && let Some(stale) = PROXY.fallback(&mut pending, &mut ctx, parts.status)
                {
                    return stale;
                }
                let none = HeaderMap::new();
                let sent = Sent {
                    proxy: self,
                    path_and_query: path_and_query.as_ref().map_or("/", |pq| pq.as_str()),
                    headers: kept.as_ref().unwrap_or(&none),
                    header_down: &rendered_down,
                };
                // What is held wraps the upstream's body before it is boxed: one box, one
                // indirection per frame, whether or not anything is held.
                let body = PROXY.observe(pending, sent, &mut parts, holding(incoming, (held, lease)));
                ctx.respond_appending(Response::from_parts(parts, body))
            }
            Err(status) => {
                if let Some(stale) = PROXY.fallback(&mut pending, &mut ctx, status) {
                    return stale;
                }
                ctx.fail(status, None)
            }
        }
    }

    /// A request of the server's own to an upstream (src/cache.rs: revalidations, and the
    /// upstream's own encodings of a response).
    #[cfg(feature = "proxy-cache")]
    pub(crate) async fn fetch(
        &self,
        path_and_query: &str,
        headers: HeaderMap,
    ) -> Result<Response<hyper::body::Incoming>, String> {
        let Some(server) = self.servers.any() else {
            return Err("no upstream is available".to_string());
        };
        let uri = Uri::builder()
            .scheme(Scheme::HTTP)
            .authority(server.authority.clone())
            .path_and_query(path_and_query)
            .build()
            .map_err(|e| e.to_string())?;
        let mut request = Request::new(crate::body::empty());
        *request.uri_mut() = uri;
        *request.version_mut() = http::Version::HTTP_11;
        *request.headers_mut() = headers;
        let sent = self.client.request(request);
        match self.response_header_timeout {
            Some(limit) => match tokio::time::timeout(limit, sent).await {
                Ok(result) => result.map_err(|e| e.to_string()),
                Err(_) => Err("no answer in time".to_string()),
            },
            None => sent.await.map_err(|e| e.to_string()),
        }
    }

    /// `header_down` on a response: as rendered for the request when it was (`rendered`), else the
    /// operations as they stand, which need no request (the deferred `header` of src/handler.rs).
    fn apply_down(&self, rendered: &[RenderedOp], headers: &mut HeaderMap) {
        if rendered.is_empty() {
            for op in &self.header_down {
                op.apply(None, headers);
            }
        } else {
            for op in rendered {
                op.apply(headers);
            }
        }
    }

    /// `header_down` filled in from the request, when any of it has placeholders; else nothing
    /// (`apply_down` applies the operations as they stand).
    fn render_down(&self, ctx: &Ctx) -> Vec<RenderedOp> {
        if self.header_down.iter().any(HeaderOp::is_dynamic) {
            self.header_down.iter().map(|op| op.render(ctx)).collect()
        } else {
            Vec::new()
        }
    }

    /// The request's headers as the upstream gets them. Host is always among them (the client's,
    /// else the authority), so the client is built not to set it (`client`).
    fn upstream_headers(&self, ctx: &Ctx) -> HeaderMap {
        // Room for X-Forwarded-For / -Proto / -Host, Host, and what `header_up` adds.
        let mut headers = forwardable_headers(ctx, 4 + self.header_up.len());
        forwarded_headers(ctx, &mut headers);
        if !headers.contains_key(HOST)
            && let Ok(value) = HeaderValue::from_str(ctx.hostport())
        {
            headers.insert(HOST, value);
        }
        apply_ops(&self.header_up, ctx, &mut headers);
        headers
    }

    /// A protocol switch (WebSocket): the handshake goes to the upstream on a connection of its own;
    /// when it answers 101, the client's connection and that one become a tunnel, copied both ways
    /// until either side closes. Any other answer is passed on as it is, with no tunnel.
    async fn tunnel(
        &self,
        mut ctx: Ctx,
        protocol: HeaderValue,
        client: OnUpgrade,
        held: UpstreamHeld,
    ) -> Response<Body> {
        let mut headers = self.upstream_headers(&ctx);
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(UPGRADE, protocol);
        let rendered_down = self.render_down(&ctx);
        let place = ctx.req.extensions.get::<Place>().cloned();
        let loaded = self.servers.load();
        let picked = match loaded.pick(&ctx, 0) {
            Ok(picked) => picked,
            Err(_) => {
                tracing::warn!("no upstream is available");
                return ctx.fail(StatusCode::SERVICE_UNAVAILABLE, None);
            }
        };
        let (server, lease) = (picked.server, picked.lease);
        let upstream = server.name.clone();
        let target = ctx.req.uri.path_and_query().map_or("/", |pq| pq.as_str());
        let mut request = Request::new(crate::body::empty());
        *request.method_mut() = ctx.req.method.clone();
        *request.uri_mut() = target.parse().unwrap_or_else(|_| Uri::from_static("/"));
        *request.headers_mut() = headers;
        let (dial_timeout, address) = (self.dial_timeout, server.addr);
        let exchange = async move {
            let tcp = tokio::time::timeout(dial_timeout, tokio::net::TcpStream::connect(address))
                .await
                .map_err(|_| "connection timed out".to_string())?
                .map_err(|e| e.to_string())?;
            let _ = tcp.set_nodelay(true);
            let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
                .await
                .map_err(|e| e.to_string())?;
            // Drives the connection, and hands it over when the upstream switches protocols.
            tokio::spawn(connection.with_upgrades());
            sender.send_request(request).await.map_err(|e| e.to_string())
        };
        let answered = match self.response_header_timeout {
            Some(limit) => match tokio::time::timeout(limit, exchange).await {
                Ok(result) => result.map_err(|e| (StatusCode::BAD_GATEWAY, e)),
                Err(_) => Err((StatusCode::GATEWAY_TIMEOUT, "no answer in time".to_string())),
            },
            None => exchange.await.map_err(|e| (StatusCode::BAD_GATEWAY, e)),
        };
        let mut response = match answered {
            Ok(response) => response,
            Err((status, error)) => {
                tracing::warn!(upstream = %upstream, address = %server.addr, %error, "upstream WebSocket handshake failed");
                if let Some(passive) = self.servers.passive() {
                    server.failed(passive);
                }
                return ctx.fail(status, None);
            }
        };
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            let (mut parts, incoming) = response.into_parts();
            remove_hop_headers(&mut parts.headers);
            self.apply_down(&rendered_down, &mut parts.headers);
            return ctx.respond_appending(Response::from_parts(parts, holding(incoming, (held, lease))));
        }
        // A tunnel counts as the connection it came from (src/guard.rs), not as a request: its
        // slot is given back with this answer.
        let upstream_io = hyper::upgrade::on(&mut response);
        let (mut parts, _) = response.into_parts();
        let switched_to = parts.headers.get(UPGRADE).cloned();
        remove_hop_headers(&mut parts.headers);
        parts.headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        if let Some(protocol) = switched_to {
            parts.headers.insert(UPGRADE, protocol);
        }
        self.apply_down(&rendered_down, &mut parts.headers);
        tokio::spawn(async move {
            // The tunnel counts at its server until it closes.
            let _lease = lease;
            let (Ok(client), Ok(upstream)) = tokio::join!(client, upstream_io) else {
                return;
            };
            let (mut client, mut upstream) = (TokioIo::new(client), TokioIo::new(upstream));
            let copied = tokio::io::copy_bidirectional(&mut client, &mut upstream);
            // The client connection's place is held until the tunnel closes: either side closing
            // it, or the server stopping.
            match place {
                Some(place) => {
                    tokio::select! {
                        _ = copied => {}
                        _ = place.clone().stopped() => {}
                    }
                    drop(place);
                }
                None => {
                    let _ = copied.await;
                }
            }
        });
        ctx.respond_appending(Response::from_parts(parts, crate::body::empty()))
    }
}

/// A hook's refusal: through the site's error routes when it says so (`ErrorPage`), else as it is.
fn refusal(ctx: &mut Ctx, response: Response<Body>) -> Response<Body> {
    if response.extensions().get::<crate::extensions::ErrorPage>().is_some() {
        let response = ctx.respond(response);
        ctx.failed(response, None)
    } else {
        ctx.respond(response)
    }
}

/// The upstream's response body, boxed once: with what the upstream checks hold (a slot at the
/// upstreams, a lease on the server's count) kept until it ends or is dropped, or as it is when
/// there is nothing to keep.
fn holding<B, H>(body: B, held: H) -> Body
where
    B: http_body::Body<Data = bytes::Bytes> + Send + Unpin + 'static,
    B::Error: Into<crate::body::BoxError>,
    H: Held,
{
    if held.is_empty() {
        boxed(body)
    } else {
        boxed(Holding { body, held: Some(held) })
    }
}

struct Holding<B, H> {
    body: B,
    held: Option<H>,
}

impl<B, H> http_body::Body for Holding<B, H>
where
    B: http_body::Body<Data = bytes::Bytes> + Unpin,
    H: Held,
{
    type Data = bytes::Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<bytes::Bytes>, Self::Error>>> {
        let polled = std::pin::Pin::new(&mut self.body).poll_frame(cx);
        if matches!(polled, std::task::Poll::Ready(None | Some(Err(_)))) {
            self.held = None;
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }
}

/// Writes X-Forwarded-For / -Proto / -Host into `headers` (a map `forwardable_headers` made: the
/// client's own are not in it, the identity headers only a trusted proxy's).
fn forwarded_headers(ctx: &Ctx, headers: &mut HeaderMap) {
    let peer = ctx.conn.remote.ip();
    let trusted = ctx.conn.trusted;
    // The trusted proxy's entries, then the peer, written into the value at once.
    let mut xff = crate::handler::HeaderText::new();
    if trusted {
        let prior = ctx.req.headers.get_all("x-forwarded-for");
        for value in prior.iter().filter_map(|v| v.to_str().ok()) {
            xff.push_str(value);
            xff.push_str(", ");
        }
    }
    {
        use std::fmt::Write as _;
        let _ = write!(xff, "{peer}");
    }
    if let Some(value) = xff.value() {
        headers.insert(X_FORWARDED_FOR, value);
    }
    // A trusted proxy's last value as it came (the same bytes: no string made of it).
    let last = |name: &str| {
        ctx.req
            .headers
            .get_all(name)
            .iter()
            .next_back()
            .filter(|v| v.to_str().is_ok_and(|v| !v.is_empty()))
    };
    let proto = match last("x-forwarded-proto") {
        Some(prior) if trusted => prior.clone(),
        _ => HeaderValue::from_static(if ctx.conn.tls { "https" } else { "http" }),
    };
    headers.insert(X_FORWARDED_PROTO, proto);
    // The Host field itself when it is the host (a reference count, no copy); the HTTP/2 and
    // HTTP/3 authority is copied.
    let host = match last("x-forwarded-host") {
        Some(prior) if trusted => Some(prior.clone()),
        _ => match ctx.req.headers.get(http::header::HOST) {
            Some(field) if field.as_bytes() == ctx.hostport().as_bytes() => Some(field.clone()),
            _ => HeaderValue::from_str(ctx.hostport()).ok(),
        },
    };
    if let Some(host) = host {
        headers.insert(X_FORWARDED_HOST, host);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_headers_and_connection_listed_fields_are_removed() {
        let mut h = HeaderMap::new();
        h.insert(CONNECTION, HeaderValue::from_static("keep-alive, X-Secret"));
        h.insert("x-secret", HeaderValue::from_static("1"));
        h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        h.insert("x-kept", HeaderValue::from_static("1"));
        remove_hop_headers(&mut h);
        assert_eq!(h.len(), 1);
        assert!(h.contains_key("x-kept"));
    }

    #[test]
    fn a_response_loses_its_hop_headers_and_keeps_the_rest() {
        // What a Node upstream answers: Connection and its Keep-Alive, among ordinary fields.
        let mut h = HeaderMap::new();
        h.insert("content-type", HeaderValue::from_static("text/plain"));
        h.insert("content-length", HeaderValue::from_static("5"));
        h.insert(CONNECTION, HeaderValue::from_static("Keep-Alive"));
        h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        h.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        h.insert("alt-svc", HeaderValue::from_static("h3=\":443\""));
        h.insert(UPGRADE, HeaderValue::from_static("h2c"));
        h.append("set-cookie", HeaderValue::from_static("a=1"));
        h.append("set-cookie", HeaderValue::from_static("b=2"));
        remove_hop_headers(&mut h);
        assert_eq!(h.len(), 4, "{h:?}");
        assert_eq!(h["content-type"], "text/plain");
        assert_eq!(h["content-length"], "5");
        assert_eq!(h.get_all("set-cookie").iter().count(), 2);
        // Several Connection fields, listing more names than fit on the stack: all of them go.
        let mut h = HeaderMap::new();
        h.append(CONNECTION, HeaderValue::from_static("a, b, c"));
        h.append(CONNECTION, HeaderValue::from_static("d,e ,f, g, h, i, close"));
        for name in ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"] {
            h.insert(name, HeaderValue::from_static("1"));
        }
        remove_hop_headers(&mut h);
        assert_eq!(h.len(), 1, "{h:?}");
        assert!(h.contains_key("j"));
    }

    fn ctx_from(peer: &str, trusted: bool, headers: &[(&'static str, &str)]) -> Ctx {
        let conn = std::sync::Arc::new(crate::handler::ConnInfo {
            remote: peer.parse().unwrap(),
            tls: false,
            trusted,
            sni: None,
        });
        let mut builder = Request::get("/api/x").header("host", "example.test");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let (parts, body) = builder.body(crate::body::empty()).unwrap().into_parts();
        let ip = conn.remote.ip();
        Ctx::new(conn, parts, body, ip)
    }

    #[test]
    fn client_identity_headers_come_only_from_trusted_proxies() {
        let sent = [
            ("cf-ipcountry", "NL"),
            ("x-real-ip", "6.6.6.6"),
            ("forwarded", "for=6.6.6.6"),
            ("x-forwarded-for", "6.6.6.6"),
            ("x-forwarded-proto", "https"),
            ("x-custom", "kept"),
        ];
        let ctx = ctx_from("203.0.113.9:4000", false, &sent);
        let headers = to_upstream(&ctx);
        assert!(headers.get("cf-ipcountry").is_none());
        assert!(headers.get("x-real-ip").is_none());
        assert!(headers.get("forwarded").is_none());
        assert_eq!(headers["x-forwarded-for"], "203.0.113.9");
        assert_eq!(headers["x-forwarded-proto"], "http");
        assert_eq!(headers["x-forwarded-host"], "example.test");
        assert_eq!(headers["x-custom"], "kept");
        assert_eq!(headers["host"], "example.test");
        assert_eq!(headers.len(), 5, "{headers:?}");

        let ctx = ctx_from("10.0.0.5:4000", true, &sent);
        let headers = to_upstream(&ctx);
        assert_eq!(headers["cf-ipcountry"], "NL");
        assert_eq!(headers["x-real-ip"], "6.6.6.6");
        assert_eq!(headers["x-forwarded-for"], "6.6.6.6, 10.0.0.5");
        assert_eq!(headers["x-forwarded-proto"], "https");
        assert_eq!(
            headers.get_all("x-forwarded-for").iter().count(),
            1,
            "one value, extended"
        );
    }

    /// The request's headers as `upstream_headers` makes them, short of `header_up`.
    fn to_upstream(ctx: &Ctx) -> HeaderMap {
        let mut headers = forwardable_headers(ctx, 4);
        forwarded_headers(ctx, &mut headers);
        headers
    }

    #[test]
    fn the_request_loses_hop_and_connection_listed_fields_and_keeps_every_value() {
        let sent = [
            ("connection", "keep-alive, X-Session"),
            ("keep-alive", "timeout=5"),
            ("x-session", "secret"),
            ("te", "trailers"),
            ("proxy-authorization", "Basic xyz"),
            ("accept", "text/html"),
            ("accept", "application/json"),
            ("cookie", "a=1"),
            ("cookie", "b=2"),
            ("x-forwarded-host", "forged.test"),
            ("x-forwarded-for", "6.6.6.6"),
        ];
        let ctx = ctx_from("203.0.113.9:4000", false, &sent);
        let headers = to_upstream(&ctx);
        for gone in ["connection", "keep-alive", "x-session", "te", "proxy-authorization"] {
            assert!(headers.get(gone).is_none(), "{gone} in {headers:?}");
        }
        let values = |name: &str| -> Vec<String> {
            headers
                .get_all(name)
                .iter()
                .map(|v| v.to_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(values("accept"), ["text/html", "application/json"]);
        assert_eq!(values("cookie"), ["a=1", "b=2"]);
        assert_eq!(
            values("x-forwarded-for"),
            ["203.0.113.9"],
            "the client's own is not kept"
        );
        assert_eq!(values("x-forwarded-host"), ["example.test"]);
        assert_eq!(values("x-forwarded-proto"), ["http"]);
        assert_eq!(headers["host"], "example.test");
        // The request's own map is untouched: a retry, the cookie policy and the error routes
        // read it.
        assert_eq!(ctx.req.headers.get_all("connection").iter().count(), 1);
        assert_eq!(ctx.req.headers["x-session"], "secret");
        // Room for X-Forwarded-* and Host was there from the start: nothing grew.
        assert!(headers.capacity() >= sent.len() + 1 + 4);
    }

    #[test]
    fn look_alikes_of_identity_headers_come_from_no_one() {
        let sent = [
            ("x_real_ip", "6.6.6.6"),
            ("x.forwarded.for", "6.6.6.6"),
            ("x_forwarded_host", "admin.test"),
            ("cf_connecting.ip", "6.6.6.6"),
            ("x_custom", "kept"),
            ("x-real_ip-x", "kept"),
        ];
        for (peer, trusted) in [("203.0.113.9:4000", false), ("10.0.0.5:4000", true)] {
            let ctx = ctx_from(peer, trusted, &sent);
            let headers = to_upstream(&ctx);
            for gone in ["x_real_ip", "x.forwarded.for", "x_forwarded_host", "cf_connecting.ip"] {
                assert!(headers.get(gone).is_none(), "{gone} from {peer}");
            }
            assert_eq!(headers["x_custom"], "kept");
            assert_eq!(headers["x-real_ip-x"], "kept");
            assert_eq!(headers["x-forwarded-host"], "example.test");
        }
    }

    #[test]
    fn cgi_names_fold_underscores_and_dots_only() {
        assert!(same_cgi_name("x_user", "x-user"));
        assert!(same_cgi_name("x.user", "x-user"));
        assert!(same_cgi_name("x_user", "x.user"));
        assert!(!same_cgi_name("x_users", "x-user"));
        assert!(!same_cgi_name("xauser", "x-user"));
        let mut h = HeaderMap::new();
        h.insert("x-user", HeaderValue::from_static("real"));
        h.insert("x_user", HeaderValue::from_static("forged"));
        remove_lookalikes(&mut h, &["x-user"]);
        assert_eq!(h.len(), 1);
        assert_eq!(h["x-user"], "real");
    }
}
