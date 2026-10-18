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
use crate::extensions::UpstreamCheck;
use crate::guard::{BodyStalled, BodyTooLarge, Place};
use crate::handler::{Ctx, HeaderOp, RenderedOp, apply_ops};
use http::header::{CONNECTION, HOST, UPGRADE};
use http::uri::{Authority, Scheme};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri};
use hyper::upgrade::OnUpgrade;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub type HttpClient = Client<HttpConnector, Body>;

pub fn client(dial_timeout: Duration, keepalive: Option<Duration>) -> HttpClient {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(dial_timeout));
    connector.set_nodelay(true);
    connector.enforce_http(true);
    let mut builder = Client::builder(TokioExecutor::new());
    builder.pool_idle_timeout(keepalive.unwrap_or(Duration::from_secs(120)));
    if keepalive.is_none() {
        builder.pool_max_idle_per_host(0);
    }
    builder.build(connector)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbPolicy {
    Random,
    First,
    RoundRobin,
}

pub struct ReverseProxy {
    pub upstreams: Vec<Authority>,
    pub policy: LbPolicy,
    pub try_duration: Duration,
    pub try_interval: Duration,
    pub header_up: Vec<HeaderOp>,
    pub header_down: Vec<HeaderOp>,
    pub response_header_timeout: Option<Duration>,
    /// For the connections of WebSocket handshakes (the pooled client has its own).
    pub dial_timeout: Duration,
    pub client: HttpClient,
    pub counter: AtomicUsize,
}

/// Hop-by-hop fields (Caddy's list) never forwarded in either direction.
const HOP_HEADERS: &[&str] = &[
    "alt-svc",
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

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

pub(crate) fn remove_hop_headers(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in listed {
        headers.remove(name);
    }
    for name in HOP_HEADERS {
        headers.remove(*name);
    }
}

/// The protocol a request asks to switch to (`Connection: upgrade` and an `Upgrade` field), e.g.
/// `websocket`.
fn upgrade_of(headers: &HeaderMap) -> Option<HeaderValue> {
    let wanted = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
    if wanted { headers.get(UPGRADE).cloned() } else { None }
}

impl ReverseProxy {
    fn pick(&self, attempt: usize) -> &Authority {
        let n = self.upstreams.len();
        let index = match self.policy {
            LbPolicy::First => attempt.min(n - 1),
            LbPolicy::RoundRobin => self.counter.fetch_add(1, Ordering::Relaxed) % n,
            LbPolicy::Random => {
                if n == 1 {
                    0
                } else {
                    let nanos = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.subsec_nanos() as usize)
                        .unwrap_or(0);
                    (nanos ^ self.counter.fetch_add(1, Ordering::Relaxed)) % n
                }
            }
        };
        &self.upstreams[index]
    }

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
        // Request checks bound to these upstreams (src/jwt, src/apifw: `upstreams`), on the request
        // as it goes there.
        if let Some(hooks) = ctx.upstream_hooks.take() {
            let body = ctx.body.take().unwrap_or_else(crate::body::empty);
            match hooks
                .check(
                    &mut ctx.req,
                    body,
                    crate::extensions::Client { ip: ctx.client_ip },
                    &self.upstreams,
                )
                .await
            {
                Ok(body) => ctx.body = Some(body),
                Err(response) => return ctx.respond(response),
            }
        }
        // The client's slot at the upstreams (WEB_MAX_UPSTREAM_REQUESTS_PER_IP), held until the
        // response ends.
        #[cfg(feature = "rate-limit")]
        let slot = match crate::ratelimit::upstream_slot(&ctx) {
            Ok(slot) => slot,
            Err(_) => return ctx.fail(StatusCode::TOO_MANY_REQUESTS, None),
        };
        #[cfg(not(feature = "rate-limit"))]
        let slot: Slot = None;
        // A `cache` the request passed: the response may be kept (src/cache.rs).
        #[cfg(feature = "proxy-cache")]
        let mut miss = ctx.req.extensions.remove::<crate::cache::PendingMiss>().map(|m| m.0);
        #[cfg(feature = "proxy-cache")]
        if let Some(miss) = miss.as_mut() {
            // The site's `encode` the request passed: what a kept answer is compressed with.
            miss.encode = ctx.encode.clone();
        }
        #[cfg(feature = "proxy-cache")]
        if let Some(miss) = miss.as_mut()
            && ctx.req.extensions.get::<crate::handler::Credentialed>().is_some()
        {
            miss.credentialed = true;
        }
        // A WebSocket handshake on a connection that can be handed over (HTTP/1.1); anything else
        // goes on as an ordinary request, its Upgrade dropped as hop-by-hop.
        if let Some(protocol) = upgrade_of(&ctx.req.headers)
            && let Some(client) = ctx.req.extensions.remove::<OnUpgrade>()
        {
            return self.tunnel(ctx, protocol, client, slot).await;
        }
        let headers = self.upstream_headers(&ctx);
        let rendered_down: Vec<_> = self.header_down.iter().map(|op| op.render(&ctx)).collect();
        let path_and_query = ctx.req.uri.path_and_query().cloned();
        let method = ctx.req.method.clone();
        let body_stalled = ctx.req.extensions.get::<BodyStalled>().cloned();
        let mut body = ctx.body.take();
        // Without a body the request can be retried on another upstream (lb_try_duration).
        let replayable = body.as_ref().is_none_or(http_body::Body::is_end_stream);
        let started = Instant::now();
        let mut attempt = 0;
        let outcome = loop {
            let upstream = self.pick(attempt).clone();
            let mut parts = Uri::builder().scheme(Scheme::HTTP).authority(upstream.clone());
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
            *request.headers_mut() = headers.clone();
            let sent = self.client.request(request);
            let result = match self.response_header_timeout {
                Some(limit) => match tokio::time::timeout(limit, sent).await {
                    Ok(r) => r.map_err(|e| (e.is_connect(), false)),
                    Err(_) => Err((false, true)),
                },
                None => sent.await.map_err(|e| (e.is_connect(), false)),
            };
            match result {
                Ok(response) => break Ok(response),
                Err((connect, timed_out)) => {
                    // The body went over its `request_body` limit while it was being sent.
                    if too_large.as_ref().is_some_and(BodyTooLarge::happened) {
                        tracing::debug!(upstream = %upstream, "the request body went over its limit");
                        break Err(StatusCode::PAYLOAD_TOO_LARGE);
                    }
                    // The client stopped sending its body: its fault, not the upstream's.
                    if body_stalled.as_ref().is_some_and(BodyStalled::happened) {
                        tracing::debug!(upstream = %upstream, "the client stopped sending the request body");
                        break Err(StatusCode::REQUEST_TIMEOUT);
                    }
                    tracing::warn!(upstream = %upstream, connect, timed_out, "upstream request failed");
                    if timed_out {
                        break Err(StatusCode::GATEWAY_TIMEOUT);
                    }
                    let can_retry = connect && replayable && started.elapsed() + self.try_interval < self.try_duration;
                    if !can_retry {
                        break Err(StatusCode::BAD_GATEWAY);
                    }
                    attempt += 1;
                    tokio::time::sleep(self.try_interval).await;
                }
            }
        };
        match outcome {
            Ok(response) => {
                let (mut parts, incoming) = response.into_parts();
                remove_hop_headers(&mut parts.headers);
                for op in &rendered_down {
                    op.apply(&mut parts.headers);
                }
                #[cfg(feature = "proxy-cache")]
                if let Some(mut miss) = miss {
                    if parts.status.is_server_error()
                        && let Some(stale) = miss.fallback(&mut ctx, parts.status)
                    {
                        return stale;
                    }
                    let pq = path_and_query.as_ref().map_or("/", |pq| pq.as_str());
                    let body = miss.tee(self, pq, &headers, &rendered_down, &mut parts, boxed(incoming));
                    return ctx.respond_appending(Response::from_parts(parts, holding(body, slot)));
                }
                ctx.respond_appending(Response::from_parts(parts, holding(boxed(incoming), slot)))
            }
            Err(status) => {
                #[cfg(feature = "proxy-cache")]
                if let Some(stale) = miss.as_mut().and_then(|miss| miss.fallback(&mut ctx, status)) {
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
        let uri = Uri::builder()
            .scheme(Scheme::HTTP)
            .authority(self.pick(0).clone())
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

    /// The request's headers as the upstream gets them.
    fn upstream_headers(&self, ctx: &Ctx) -> HeaderMap {
        let mut headers = ctx.req.headers.clone();
        remove_hop_headers(&mut headers);
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
    async fn tunnel(&self, mut ctx: Ctx, protocol: HeaderValue, client: OnUpgrade, slot: Slot) -> Response<Body> {
        let mut headers = self.upstream_headers(&ctx);
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(UPGRADE, protocol);
        let rendered_down: Vec<RenderedOp> = self.header_down.iter().map(|op| op.render(&ctx)).collect();
        let place = ctx.req.extensions.get::<Place>().cloned();
        let upstream = self.pick(0).clone();
        let target = ctx.req.uri.path_and_query().map_or("/", |pq| pq.as_str());
        let mut request = Request::new(crate::body::empty());
        *request.method_mut() = ctx.req.method.clone();
        *request.uri_mut() = target.parse().unwrap_or_else(|_| Uri::from_static("/"));
        *request.headers_mut() = headers;
        let (dial_timeout, address) = (self.dial_timeout, upstream.clone());
        let exchange = async move {
            let tcp = tokio::time::timeout(dial_timeout, tokio::net::TcpStream::connect(address.as_str()))
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
                tracing::warn!(upstream = %upstream, %error, "upstream WebSocket handshake failed");
                return ctx.fail(status, None);
            }
        };
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            let (mut parts, incoming) = response.into_parts();
            remove_hop_headers(&mut parts.headers);
            for op in &rendered_down {
                op.apply(&mut parts.headers);
            }
            return ctx.respond_appending(Response::from_parts(parts, holding(boxed(incoming), slot)));
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
        for op in &rendered_down {
            op.apply(&mut parts.headers);
        }
        tokio::spawn(async move {
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

/// A request's slot at the upstreams (src/ratelimit.rs, WEB_MAX_UPSTREAM_REQUESTS_PER_IP).
#[cfg(feature = "rate-limit")]
type Slot = Option<crate::ratelimit::UpstreamSlot>;
#[cfg(not(feature = "rate-limit"))]
type Slot = Option<std::convert::Infallible>;

/// A response body that holds the request's slot at the upstreams until it ends (or is dropped).
#[cfg(feature = "rate-limit")]
fn holding(body: Body, slot: Slot) -> Body {
    match slot {
        Some(slot) => crate::body::boxed(Holding { body, slot: Some(slot) }),
        None => body,
    }
}

#[cfg(not(feature = "rate-limit"))]
fn holding(body: Body, _: Slot) -> Body {
    body
}

#[cfg(feature = "rate-limit")]
struct Holding {
    body: Body,
    slot: Option<crate::ratelimit::UpstreamSlot>,
}

#[cfg(feature = "rate-limit")]
impl http_body::Body for Holding {
    type Data = bytes::Bytes;
    type Error = crate::body::BoxError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<bytes::Bytes>, Self::Error>>> {
        let polled = std::pin::Pin::new(&mut self.body).poll_frame(cx);
        if matches!(polled, std::task::Poll::Ready(None | Some(Err(_)))) {
            self.slot = None;
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

fn forwarded_headers(ctx: &Ctx, headers: &mut HeaderMap) {
    let peer = ctx.conn.remote.ip().to_string();
    let trusted = ctx.conn.trusted;
    if !trusted {
        for name in CLIENT_IDENTITY_HEADERS {
            headers.remove(*name);
        }
    }
    let prior: Vec<&str> = ctx
        .req
        .headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let xff = if trusted && !prior.is_empty() {
        format!("{}, {peer}", prior.join(", "))
    } else {
        peer
    };
    if let Ok(value) = HeaderValue::from_str(&xff) {
        headers.insert("x-forwarded-for", value);
    }
    let last = |name: &str| {
        ctx.req
            .headers
            .get_all(name)
            .iter()
            .next_back()
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
    };
    let proto = match last("x-forwarded-proto") {
        Some(prior) if trusted => prior.to_string(),
        _ => (if ctx.conn.tls { "https" } else { "http" }).to_string(),
    };
    if let Ok(value) = HeaderValue::from_str(&proto) {
        headers.insert("x-forwarded-proto", value);
    }
    let host = match last("x-forwarded-host") {
        Some(prior) if trusted => prior.to_string(),
        _ => ctx.hostport().to_string(),
    };
    if let Ok(value) = HeaderValue::from_str(&host) {
        headers.insert("x-forwarded-host", value);
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
        let mut headers = ctx.req.headers.clone();
        forwarded_headers(&ctx, &mut headers);
        assert!(headers.get("cf-ipcountry").is_none());
        assert!(headers.get("x-real-ip").is_none());
        assert!(headers.get("forwarded").is_none());
        assert_eq!(headers["x-forwarded-for"], "203.0.113.9");
        assert_eq!(headers["x-forwarded-proto"], "http");
        assert_eq!(headers["x-forwarded-host"], "example.test");
        assert_eq!(headers["x-custom"], "kept");

        let ctx = ctx_from("10.0.0.5:4000", true, &sent);
        let mut headers = ctx.req.headers.clone();
        forwarded_headers(&ctx, &mut headers);
        assert_eq!(headers["cf-ipcountry"], "NL");
        assert_eq!(headers["x-real-ip"], "6.6.6.6");
        assert_eq!(headers["x-forwarded-for"], "6.6.6.6, 10.0.0.5");
        assert_eq!(headers["x-forwarded-proto"], "https");
    }
}
