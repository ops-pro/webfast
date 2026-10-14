//! `reverse_proxy` to plain-HTTP upstreams over HTTP/1.1, bodies streamed both ways (SSE reaches
//! the client event by event). As in Caddy: the client's Host is passed through, X-Forwarded-For /
//! -Proto / -Host are set (kept and extended only for trusted proxies), hop-by-hop headers are
//! dropped, a failed connection answers 502 and a response-header timeout 504. Upstream response
//! headers are added to those an earlier (not deferred) `header` set, as Caddy does.

use crate::body::{Body, boxed};
use crate::handler::{Ctx, HeaderOp, apply_ops};
use http::header::{CONNECTION, HOST};
use http::uri::{Authority, Scheme};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
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

fn remove_hop_headers(headers: &mut HeaderMap) {
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

    pub async fn serve(&self, mut ctx: Ctx) -> Response<Body> {
        let mut headers = ctx.req.headers.clone();
        remove_hop_headers(&mut headers);
        forwarded_headers(&ctx, &mut headers);
        if !headers.contains_key(HOST)
            && let Ok(value) = HeaderValue::from_str(ctx.hostport())
        {
            headers.insert(HOST, value);
        }
        apply_ops(&self.header_up, &ctx, &mut headers);
        let rendered_down: Vec<_> = self.header_down.iter().map(|op| op.render(&ctx)).collect();
        let path_and_query = ctx.req.uri.path_and_query().cloned();
        let method = ctx.req.method.clone();
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
                ctx.respond_appending(Response::from_parts(parts, boxed(incoming)))
            }
            Err(status) => ctx.status(status),
        }
    }
}

fn forwarded_headers(ctx: &Ctx, headers: &mut HeaderMap) {
    let peer = ctx.conn.remote.ip().to_string();
    let trusted = ctx.conn.trusted;
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
}
