//! `cache` (feature `proxy-cache`): proxied responses kept in memory and answered from there, in
//! every encoding the site's `encode` lists; what may not be stored goes to the upstream each
//! time; stale answers while one conditional request revalidates, and when the upstream fails; an
//! upstream that encodes is asked for its own other encodings.
#![cfg(feature = "proxy-cache")]

use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use webfast::server::{self, Running};

/// What the upstream was asked: per path, the requests' headers.
#[derive(Default)]
struct Seen {
    requests: Mutex<HashMap<String, Vec<HeaderMap>>>,
    failing: AtomicBool,
}

impl Seen {
    fn count(&self, path: &str) -> usize {
        self.requests.lock().unwrap().get(path).map_or(0, Vec::len)
    }

    fn headers(&self, path: &str, i: usize) -> HeaderMap {
        self.requests.lock().unwrap()[path][i].clone()
    }
}

/// A page of text long enough to be compressed.
fn page(name: &str) -> String {
    format!(
        "<!doctype html><title>{name}</title>{}",
        "<p>Some words of the page.</p>\n".repeat(80)
    )
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn brotli(data: &[u8], quality: u32) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut out, 4096, quality, 22);
        writer.write_all(data).unwrap();
    }
    out
}

/// The upstream: each path answers in its own way (see the match).
async fn upstream(seen: Arc<Seen>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                    let seen = seen.clone();
                    async move { Ok::<_, std::convert::Infallible>(answer(&seen, request)) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    addr
}

fn answer(seen: &Seen, request: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    let path = request.uri().path().to_string();
    let headers = request.headers().clone();
    seen.requests
        .lock()
        .unwrap()
        .entry(path.clone())
        .or_default()
        .push(headers.clone());
    let mut response = Response::builder();
    let accept = headers
        .get("accept-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body: Vec<u8> = match path.as_str() {
        "/api/private" => {
            response = response.header("cache-control", "private, max-age=60");
            page(&path).into()
        }
        "/api/cookie" => {
            response = response
                .header("cache-control", "max-age=60")
                .header("set-cookie", "a=1");
            page(&path).into()
        }
        "/api/vary" => {
            response = response.header("cache-control", "max-age=60").header("vary", "Cookie");
            page(&path).into()
        }
        "/api/missing" => {
            response = response.status(404).header("cache-control", "max-age=60");
            page(&path).into()
        }
        "/api/events" => {
            response = response
                .header("content-type", "text/event-stream")
                .header("cache-control", "max-age=60");
            b"data: one\n\n".to_vec()
        }
        "/api/big" => {
            response = response.header("cache-control", "max-age=60");
            "x".repeat(300_000).into()
        }
        "/api/ttl" => page(&path).into(),
        "/api/default" => page(&path).into(),
        "/api/stale" | "/api/flaky" => {
            if seen.failing.load(Ordering::SeqCst) {
                response = response.status(503);
                b"down".to_vec()
            } else if headers.get("if-none-match").is_some_and(|v| v == "\"s1\"") {
                return Response::builder()
                    .status(304)
                    .header("etag", "\"s1\"")
                    .header("cache-control", "max-age=60")
                    .body(Full::new(Bytes::new()))
                    .unwrap();
            } else {
                response = response.header("cache-control", "max-age=1").header("etag", "\"s1\"");
                page(&path).into()
            }
        }
        // Encodes what it is asked for, but has no zstd of its own.
        "/api/encoded" => {
            response = response
                .header("cache-control", "max-age=60")
                .header("vary", "Accept-Encoding");
            let text = page(&path);
            if accept == "br" {
                response = response.header("content-encoding", "br");
                brotli(text.as_bytes(), 5)
            } else if accept.contains("gzip") {
                response = response.header("content-encoding", "gzip");
                gzip(text.as_bytes())
            } else {
                text.into()
            }
        }
        _ => {
            response = response.header("cache-control", "max-age=60").header("etag", "\"p1\"");
            page(&path).into()
        }
    };
    if !response.headers_ref().is_some_and(|h| h.contains_key("content-type")) {
        response = response.header("content-type", "text/html; charset=utf-8");
    }
    response.body(Full::new(Bytes::from(body))).unwrap()
}

fn load(text: &str) -> anyhow::Result<webfast::config::Config> {
    let file = webfast::caddyfile::parse_str(text, Path::new("Caddyfile"))?;
    webfast::load_parsed_reusing(&file, 1 << 24, None, None, webfast::watch::Watch::default(), &[])
}

async fn start(seen: &Arc<Seen>, cache: &str) -> (Running, u16) {
    let addr = upstream(seen.clone()).await;
    let text = format!(
        "{{
	cache {{
		stale 30s
		max_cacheable_body_bytes 100000
	}}
}}
:0 {{
	encode zstd br gzip
	{cache}
	reverse_proxy /api/* {addr}
	respond /page \"not proxied\"
}}
"
    );
    let running = server::start(load(&text).unwrap()).await.unwrap();
    let port = running.bound[0].1.port();
    (running, port)
}

struct Got {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Got {
    fn header(&self, name: &str) -> &str {
        self.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
    }

    /// The body decoded from its Content-Encoding.
    fn text(&self) -> String {
        let mut out = Vec::new();
        match self.header("content-encoding") {
            "" => out = self.body.to_vec(),
            "gzip" => {
                flate2::read::GzDecoder::new(&self.body[..])
                    .read_to_end(&mut out)
                    .unwrap();
            }
            "br" => {
                brotli::Decompressor::new(&self.body[..], 4096)
                    .read_to_end(&mut out)
                    .unwrap();
            }
            "zstd" => out = zstd::decode_all(&self.body[..]).unwrap(),
            other => panic!("unexpected encoding {other}"),
        }
        String::from_utf8(out).unwrap()
    }
}

async fn send(port: u16, method: Method, path: &str, headers: &[(&str, &str)]) -> Got {
    let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let mut request = Request::builder()
        .method(method)
        .uri(format!("http://127.0.0.1:{port}{path}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = client
        .request(request.body(Full::new(Bytes::new())).unwrap())
        .await
        .unwrap();
    let (status, headers) = (response.status(), response.headers().clone());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Got { status, headers, body }
}

async fn get(port: u16, path: &str, headers: &[(&str, &str)]) -> Got {
    send(port, Method::GET, path, headers).await
}

/// Waits until the worker has stored the path (or the condition holds).
async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let started = Instant::now();
    while !done() {
        assert!(started.elapsed() < Duration::from_secs(10), "{what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn until_stored(port: u16, path: &str) {
    let hostport = format!("127.0.0.1:{port}");
    until(&format!("{path} stored"), || webfast::cache::is_stored(&hostport, path)).await;
}

#[tokio::test]
async fn a_stored_response_answers_from_memory_in_every_encoding() {
    let seen = Arc::new(Seen::default());
    let (running, port) = start(&seen, "cache").await;
    let text = page("/api/page");

    let first = get(port, "/api/page", &[("accept-encoding", "br")]).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.header("cache-status"), "webfast; fwd=uri-miss; stored");
    assert_eq!(first.text(), text);
    until_stored(port, "/api/page").await;

    for (accept, encoding) in [
        ("br", "br"),
        ("zstd", "zstd"),
        ("gzip, deflate", "gzip"),
        ("gzip, deflate, br, zstd", "zstd"),
        ("identity", ""),
    ] {
        let hit = get(port, "/api/page", &[("accept-encoding", accept)]).await;
        assert_eq!(hit.status, StatusCode::OK, "{accept}");
        assert!(hit.header("cache-status").starts_with("webfast; hit; ttl="), "{accept}");
        assert_eq!(hit.header("content-encoding"), encoding, "{accept}");
        assert_eq!(hit.header("content-length"), hit.body.len().to_string());
        assert!(hit.headers.contains_key("age"));
        assert_eq!(hit.header("vary"), "Accept-Encoding");
        assert_eq!(hit.text(), text, "{accept}");
        let etag = if encoding.is_empty() {
            "\"p1\"".to_string()
        } else {
            format!("\"p1-{encoding}\"")
        };
        assert_eq!(hit.header("etag"), etag);
        // Its validator gives a 304.
        let again = get(
            port,
            "/api/page",
            &[("accept-encoding", accept), ("if-none-match", &etag)],
        )
        .await;
        assert_eq!(again.status, StatusCode::NOT_MODIFIED, "{accept}");
        assert!(again.body.is_empty());
    }
    let head = send(port, Method::HEAD, "/api/page", &[]).await;
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(head.header("content-length"), text.len().to_string());
    assert!(head.body.is_empty());
    assert_eq!(seen.count("/api/page"), 1, "every answer but the first from memory");

    // A request that may change it: what was stored is dropped.
    assert_eq!(send(port, Method::POST, "/api/page", &[]).await.status, StatusCode::OK);
    let after = get(port, "/api/page", &[]).await;
    assert_eq!(after.header("cache-status"), "webfast; fwd=uri-miss; stored");
    assert_eq!(seen.count("/api/page"), 3);

    // The client's no-cache goes to the upstream, and stores what it brings.
    until_stored(port, "/api/page").await;
    let forced = get(port, "/api/page", &[("cache-control", "no-cache")]).await;
    assert_eq!(forced.header("cache-status"), "webfast; fwd=request; stored");
    assert_eq!(seen.count("/api/page"), 4);
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn what_may_not_be_stored_goes_to_the_upstream_each_time() {
    let seen = Arc::new(Seen::default());
    let (running, port) = start(&seen, "cache {\n\t\tregex {\n\t\t\texclude ^/api/excluded\n\t\t}\n\t}").await;
    let hostport = format!("127.0.0.1:{port}");
    for (path, headers) in [
        ("/api/private", &[][..]),
        ("/api/cookie", &[]),
        ("/api/vary", &[]),
        ("/api/missing", &[]),
        ("/api/events", &[]),
        ("/api/big", &[]),
        ("/api/excluded", &[]),
        ("/api/ranged", &[("range", "bytes=0-10")]),
        ("/api/unstored", &[("cache-control", "no-store")]),
    ] {
        for _ in 0..2 {
            let got = get(port, path, headers).await;
            assert!(!got.header("cache-status").contains("hit"), "{path}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(seen.count(path), 2, "{path}");
        assert!(!webfast::cache::is_stored(&hostport, path), "{path}");
    }
    // What is not proxied is not stored either.
    assert_eq!(&get(port, "/page", &[]).await.body[..], b"not proxied");
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn ttl_and_default_cache_control_for_responses_without_a_lifetime() {
    let seen = Arc::new(Seen::default());
    let (running, port) = start(
        &seen,
        "cache /api/ttl {\n\t\tttl 1s\n\t\tstale 0\n\t}\n\tcache /api/default {\n\t\tdefault_cache_control \"public, max-age=30\"\n\t}",
    )
    .await;
    get(port, "/api/ttl", &[]).await;
    until_stored(port, "/api/ttl").await;
    assert!(get(port, "/api/ttl", &[]).await.header("cache-status").contains("hit"));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(
        !get(port, "/api/ttl", &[]).await.header("cache-status").contains("hit"),
        "past its ttl"
    );
    assert_eq!(seen.count("/api/ttl"), 2);

    let first = get(port, "/api/default", &[]).await;
    assert_eq!(
        first.header("cache-control"),
        "public, max-age=30",
        "the client gets it too"
    );
    until_stored(port, "/api/default").await;
    let hit = get(port, "/api/default", &[]).await;
    assert!(hit.header("cache-status").starts_with("webfast; hit; ttl=3"));
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn stale_answers_while_one_request_revalidates_and_when_the_upstream_fails() {
    let seen = Arc::new(Seen::default());
    let (running, port) = start(&seen, "cache").await;
    let text = page("/api/stale");
    get(port, "/api/stale", &[]).await;
    until_stored(port, "/api/stale").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Past max-age=1: answered as stored, and revalidated once with its ETag.
    let stale = get(port, "/api/stale", &[]).await;
    assert!(
        stale.header("cache-status").ends_with("; fwd=stale"),
        "{}",
        stale.header("cache-status")
    );
    assert_eq!(stale.text(), text);
    until("revalidated", || seen.count("/api/stale") == 2).await;
    assert_eq!(seen.headers("/api/stale", 1)["if-none-match"], "\"s1\"");
    // The 304 made it fresh for a minute.
    let mut fresh = get(port, "/api/stale", &[]).await;
    for _ in 0..100 {
        if !fresh.header("cache-status").contains("stale") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        fresh = get(port, "/api/stale", &[]).await;
    }
    let ttl: i64 = fresh
        .header("cache-status")
        .strip_prefix("webfast; hit; ttl=")
        .unwrap()
        .parse()
        .unwrap();
    assert!(ttl > 50, "{}", fresh.header("cache-status"));
    assert_eq!(fresh.text(), text);
    assert_eq!(seen.count("/api/stale"), 2);

    // The upstream fails: within the stale window the stored response answers in its place.
    get(port, "/api/flaky", &[]).await;
    until_stored(port, "/api/flaky").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    seen.failing.store(true, Ordering::SeqCst);
    let fallback = get(port, "/api/flaky", &[("cache-control", "no-cache")]).await;
    assert_eq!(fallback.status, StatusCode::OK);
    assert!(
        fallback.header("cache-status").ends_with("fwd=stale; fwd-status=503"),
        "{}",
        fallback.header("cache-status")
    );
    assert_eq!(fallback.text(), page("/api/flaky"));
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn an_upstream_that_encodes_is_asked_for_its_own_other_encodings() {
    let seen = Arc::new(Seen::default());
    let (running, port) = start(&seen, "cache").await;
    let text = page("/api/encoded");
    let first = get(port, "/api/encoded", &[("accept-encoding", "gzip")]).await;
    assert_eq!(first.header("content-encoding"), "gzip");
    until_stored(port, "/api/encoded").await;
    // Asked for br and zstd: br is the upstream's own, zstd it does not have.
    assert_eq!(seen.count("/api/encoded"), 3);
    let br = get(port, "/api/encoded", &[("accept-encoding", "br")]).await;
    assert!(br.header("cache-status").contains("hit"));
    assert_eq!(&br.body[..], &brotli(text.as_bytes(), 5)[..], "the upstream's own br");
    let zstd = get(port, "/api/encoded", &[("accept-encoding", "zstd")]).await;
    assert_eq!(zstd.header("content-encoding"), "zstd");
    assert_eq!(zstd.text(), text);
    let gzip_hit = get(port, "/api/encoded", &[("accept-encoding", "gzip")]).await;
    assert_eq!(&gzip_hit.body[..], &first.body[..], "the upstream's gzip as it came");
    let plain = get(port, "/api/encoded", &[]).await;
    assert_eq!(plain.header("content-encoding"), "");
    assert_eq!(plain.text(), text);
    assert_eq!(seen.count("/api/encoded"), 3);
    running.shutdown(Duration::from_secs(1)).await;
}

#[test]
fn what_the_plugin_has_and_webfast_does_not_is_refused() {
    for (options, message) in [
        ("redis {\n\t\t\turl 127.0.0.1:6379\n\t\t}", "kept in memory"),
        ("cdn {\n\t\t\tprovider fastly\n\t\t}", "cdn is not supported"),
        ("mode bypass", "only `mode strict`"),
        ("key {\n\t\t\tdisable_body\n\t\t}", "unsupported option"),
    ] {
        let text = format!("{{\n\tcache {{\n\t\t{options}\n\t}}\n}}\n:0 {{\n\tcache\n\trespond ok\n}}\n");
        let error = load(&text).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(error.contains(message), "{options}: {error}");
        let in_site = format!(":0 {{\n\tcache {{\n\t\t{options}\n\t}}\n\trespond ok\n}}\n");
        let error = load(&in_site).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(error.contains(message), "{options} in a site: {error}");
    }
}
