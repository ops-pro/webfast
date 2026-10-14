//! The workload a profile-guided build learns from (pgo/train.sh): many kinds of requests over every
//! protocol the server speaks, so that no path it serves is left looking cold to the optimiser.
//!
//!   train cert <dir>     self-signed certificate for "localhost"
//!   train site <dir>     a stand-in for the built site; prints the paths to request
//!   train run <plain addr> <tls addr> <cert.pem> <upstream addr> <seconds> <path>...
//!
//! For each path: GET with a browser's, other and no Accept-Encoding, revalidation (304), HEAD, a
//! range, a query; besides: redirects, 404, 405, paths to clean, and the answers of the app and the
//! streaming service (compressed on the fly, streamed), which `run` plays itself on the upstream address.
//! HTTP/1.1 on the plain address (connections kept and new), HTTP/2 and HTTP/1.1 over TLS and HTTP/3
//! on the TLS one, each with new connections now and then (handshakes, resumption). Responses are
//! read whole.

use bytes::{Buf, Bytes};
use http::{HeaderValue, Method, Request, Response};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::fmt::Write as _;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const ACCEPT: &[&str] = &[
    "gzip, deflate, br, zstd",
    "gzip, deflate, br",
    "gzip",
    "zstd;q=0.5, br",
    "",
];

/// Answered by the app behind the server (the streaming service's paths are among the posts).
const APP: &[&str] = &[
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/api/health",
    "/api/export",
    "/api/stream/quota",
    "/en/",
    "/old-page/",
    "/nope",
];

#[derive(Clone)]
struct Probe {
    method: Method,
    path: String,
    headers: Vec<(&'static str, String)>,
    body: &'static str,
}

fn probes(paths: &[String]) -> Vec<Probe> {
    let get = |path: &str, headers: Vec<(&'static str, String)>| Probe {
        method: Method::GET,
        path: path.to_string(),
        headers,
        body: "",
    };
    let browser = || vec![("accept-encoding", ACCEPT[0].to_string())];
    let mut out = Vec::new();
    for path in paths.iter().map(String::as_str).chain(APP.iter().copied()) {
        for accept in ACCEPT {
            let headers = if accept.is_empty() {
                Vec::new()
            } else {
                vec![("accept-encoding", accept.to_string())]
            };
            out.push(get(path, headers));
        }
        out.push(Probe {
            method: Method::HEAD,
            ..get(path, browser())
        });
        out.push(get(path, vec![("range", "bytes=0-99".into())]));
        out.push(get(path, vec![("range", "bytes=0-9,20-29".into())]));
        out.push(get(&format!("{path}?v=1"), browser()));
        out.push(get(path, vec![("if-match", "\"other\"".into())]));
    }
    for path in [
        "/en",
        "/en/services",
        "/en/contact.html",
        "/en//contact",
        "/EN/contact",
        "/healthz",
        "/%65n/",
        "/_headers",
        "/api/stream/internal",
    ] {
        out.push(get(path, browser()));
    }
    for (path, body) in [
        (
            "/api/form",
            r#"{"name":"Train","email":"train@example.com","message":"PGO"}"#,
        ),
        (
            "/api/stream/chat",
            r#"{"messages":[{"role":"user","content":"What do you offer?"}]}"#,
        ),
        ("/en/contact", ""),
    ] {
        out.push(Probe {
            method: Method::POST,
            headers: vec![
                ("accept-encoding", ACCEPT[0].to_string()),
                ("content-type", "application/json".into()),
            ],
            body,
            ..get(path, Vec::new())
        });
    }
    out
}

/// The ETag of each path's browser response, for revalidations.
fn revalidations(paths: &[String], etags: &[Option<HeaderValue>]) -> Vec<Probe> {
    paths
        .iter()
        .zip(etags)
        .filter_map(|(path, etag)| {
            Some(Probe {
                method: Method::GET,
                path: path.clone(),
                headers: vec![
                    ("accept-encoding", ACCEPT[0].to_string()),
                    ("if-none-match", etag.as_ref()?.to_str().ok()?.to_string()),
                ],
                body: "",
            })
        })
        .collect()
}

fn request(authority: &str, scheme: &str, probe: &Probe) -> Request<Full<Bytes>> {
    let mut builder = Request::builder()
        .method(probe.method.clone())
        .uri(format!("{scheme}://{authority}{}", probe.path));
    for (name, value) in &probe.headers {
        builder = builder.header(*name, value);
    }
    builder
        .body(Full::new(Bytes::from_static(probe.body.as_bytes())))
        .expect("request")
}

fn tls(cert: &[u8], alpn: &[&[u8]], early: bool) -> rustls::ClientConfig {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for der in CertificateDer::pem_slice_iter(cert) {
        roots.add(der.expect("pem")).expect("root");
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.enable_early_data = early;
    config
}

/// HTTP/1.1 on the plain address: `workers` connections, each replaced every `per_connection`.
async fn plain(addr: SocketAddr, probes: Arc<Vec<Probe>>, until: Instant, done: Arc<AtomicU64>) {
    let authority = addr.to_string();
    let mut tasks = Vec::new();
    for worker in 0..16usize {
        let (probes, done, authority) = (probes.clone(), done.clone(), authority.clone());
        tasks.push(tokio::spawn(async move {
            let mut i = worker;
            while Instant::now() < until {
                let Ok(tcp) = tokio::net::TcpStream::connect(addr).await else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let Ok((mut sender, conn)) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await else {
                    continue;
                };
                tokio::spawn(conn);
                // Most connections carry many requests, some only one.
                let per_connection = if worker % 4 == 0 { 1 } else { 200 };
                for _ in 0..per_connection {
                    if Instant::now() >= until || sender.ready().await.is_err() {
                        break;
                    }
                    let probe = &probes[i % probes.len()];
                    i += 7;
                    if let Ok(response) = sender.send_request(request(&authority, "http", probe)).await {
                        let _ = response.into_body().collect().await;
                        done.fetch_add(1, Ordering::Relaxed);
                    } else {
                        break;
                    }
                }
            }
        }));
    }
    for task in tasks {
        let _ = task.await;
    }
}

/// HTTP/2 (and some HTTP/1.1) over TLS: new connections now and then, streams in parallel.
async fn over_tls(addr: SocketAddr, cert: Vec<u8>, probes: Arc<Vec<Probe>>, until: Instant, done: Arc<AtomicU64>) {
    let h2 = tokio_rustls::TlsConnector::from(Arc::new(tls(&cert, &[b"h2"], false)));
    let h1 = tokio_rustls::TlsConnector::from(Arc::new(tls(&cert, &[b"http/1.1"], false)));
    let mut tasks = Vec::new();
    for worker in 0..6usize {
        let (h2, h1, probes, done) = (h2.clone(), h1.clone(), probes.clone(), done.clone());
        tasks.push(tokio::spawn(async move {
            let mut i = worker;
            while Instant::now() < until {
                let Ok(tcp) = tokio::net::TcpStream::connect(addr).await else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let name = "localhost".try_into().expect("name");
                if worker == 0 {
                    let Ok(stream) = h1.connect(name, tcp).await else {
                        continue;
                    };
                    let Ok((mut sender, conn)) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await
                    else {
                        continue;
                    };
                    tokio::spawn(conn);
                    for _ in 0..50 {
                        if Instant::now() >= until || sender.ready().await.is_err() {
                            break;
                        }
                        let probe = &probes[i % probes.len()];
                        i += 5;
                        if let Ok(response) = sender.send_request(request("localhost", "https", probe)).await {
                            let _ = response.into_body().collect().await;
                            done.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    continue;
                }
                let Ok(stream) = h2.connect(name, tcp).await else {
                    continue;
                };
                let Ok((sender, conn)) =
                    hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)).await
                else {
                    continue;
                };
                tokio::spawn(conn);
                // 8 streams at a time, 400 requests per connection.
                let mut streams = Vec::new();
                for s in 0..8usize {
                    let (mut sender, probes, done) = (sender.clone(), probes.clone(), done.clone());
                    streams.push(tokio::spawn(async move {
                        let mut j = i + s * 3;
                        for _ in 0..50 {
                            if Instant::now() >= until || sender.ready().await.is_err() {
                                break;
                            }
                            let probe = &probes[j % probes.len()];
                            j += 11;
                            if let Ok(response) = sender.send_request(request("localhost", "https", probe)).await {
                                let _ = response.into_body().collect().await;
                                done.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }));
                }
                for stream in streams {
                    let _ = stream.await;
                }
                i += 13;
            }
        }));
    }
    for task in tasks {
        let _ = task.await;
    }
}

/// HTTP/3: a few connections at once, each replaced after a while (resumption, 0-RTT).
async fn quic(addr: SocketAddr, cert: Vec<u8>, probes: Arc<Vec<Probe>>, until: Instant, done: Arc<AtomicU64>) {
    let config = quinn::crypto::rustls::QuicClientConfig::try_from(tls(&cert, &[b"h3"], true)).expect("quic tls");
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().expect("bind")).expect("endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(config)));
    let mut tasks = Vec::new();
    for worker in 0..3usize {
        let (endpoint, probes, done) = (endpoint.clone(), probes.clone(), done.clone());
        tasks.push(tokio::spawn(async move {
            let mut i = worker;
            while Instant::now() < until {
                let Ok(connecting) = endpoint.connect(addr, "localhost") else {
                    break;
                };
                let conn = match connecting.into_0rtt() {
                    Ok((conn, _)) => conn,
                    Err(connecting) => match connecting.await {
                        Ok(conn) => conn,
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    },
                };
                let Ok((mut driver, mut send_request)) = h3::client::new(h3_quinn::Connection::new(conn.clone())).await
                else {
                    continue;
                };
                let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
                for _ in 0..150 {
                    if Instant::now() >= until {
                        break;
                    }
                    let probe = &probes[i % probes.len()];
                    i += 3;
                    let mut builder = Request::builder()
                        .method(probe.method.clone())
                        .uri(format!("https://localhost{}", probe.path));
                    for (name, value) in &probe.headers {
                        builder = builder.header(*name, value);
                    }
                    let Ok(mut stream) = send_request.send_request(builder.body(()).expect("request")).await else {
                        break;
                    };
                    if !probe.body.is_empty()
                        && stream
                            .send_data(Bytes::from_static(probe.body.as_bytes()))
                            .await
                            .is_err()
                    {
                        break;
                    }
                    if stream.finish().await.is_err() || stream.recv_response().await.is_err() {
                        break;
                    }
                    while let Ok(Some(mut chunk)) = stream.recv_data().await {
                        chunk.advance(chunk.remaining());
                    }
                    done.fetch_add(1, Ordering::Relaxed);
                }
                // Let the session tickets arrive before closing, for the next connection's 0-RTT.
                tokio::time::sleep(Duration::from_millis(20)).await;
                drop(send_request);
                drive.abort();
                conn.close(0u32.into(), b"next");
            }
        }));
    }
    for task in tasks {
        let _ = task.await;
    }
    endpoint.wait_idle().await;
}

/// The browser response's ETag of each path, over plain HTTP/1.1.
async fn etags(addr: SocketAddr, paths: &[String]) -> Vec<Option<HeaderValue>> {
    let mut out = Vec::new();
    for path in paths {
        let mut etag = None;
        if let Ok(tcp) = tokio::net::TcpStream::connect(addr).await
            && let Ok((mut sender, conn)) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await
        {
            tokio::spawn(conn);
            let probe = Probe {
                method: Method::GET,
                path: path.clone(),
                headers: vec![("accept-encoding", ACCEPT[0].to_string())],
                body: "",
            };
            if let Ok(response) = sender.send_request(request(&addr.to_string(), "http", &probe)).await {
                etag = response.headers().get("etag").cloned();
                let _ = response.into_body().collect().await;
            }
        }
        out.push(etag);
    }
    out
}

/// Waits until something answers on `addr`.
async fn ready(addr: SocketAddr) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("nothing listens on {addr}");
}

/// The app and the streaming service behind the server, on one address: an event stream for the streaming service,
/// JSON for the API (one streamed), a redirect, plain text, XML, and HTML 404 pages for the rest.
async fn upstream(addr: SocketAddr) {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let json = Bytes::from(format!(
        r#"{{"ok":true,"items":["{}"]}}"#,
        prose(&mut rng, 200).replace(' ', "\",\"")
    ));
    let sitemap = Bytes::from({
        let mut xml = String::from(
            r#"<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">"#,
        );
        // Over 64 KiB: compressed on the blocking pool.
        for n in 0..1500 {
            let _ = write!(
                xml,
                "<url><loc>https://example.com/en/{}-{n}</loc></url>",
                prose(&mut rng, 2).replace(' ', "-")
            );
        }
        xml + "</urlset>"
    });
    let not_found = Bytes::from(page(&mut rng, "en", 14_000));
    let events: Arc<Vec<Bytes>> = Arc::new(
        (0..30)
            .map(|_| Bytes::from(format!("data: {{\"delta\":\"{}\"}}\n\n", prose(&mut rng, 12))))
            .collect(),
    );
    let listener = tokio::net::TcpListener::bind(addr).await.expect("upstream address");
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            continue;
        };
        let (json, sitemap, not_found, events) = (json.clone(), sitemap.clone(), not_found.clone(), events.clone());
        let service = hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
            let (json, sitemap, not_found, events) = (json.clone(), sitemap.clone(), not_found.clone(), events.clone());
            async move {
                let path = request.uri().path().to_string();
                let _ = request.into_body().collect().await;
                let full = |status: u16, kind: &str, body: Bytes| {
                    Response::builder()
                        .status(status)
                        .header("content-type", kind)
                        .header("cache-control", "no-store")
                        .body(Full::new(body).boxed())
                        .expect("response")
                };
                // Of unknown length: an event stream (not compressed), JSON compressed frame by frame.
                let stream = |kind: &str| {
                    let frames = events
                        .iter()
                        .cloned()
                        .map(|event| Ok::<_, Infallible>(Frame::data(event)))
                        .collect::<Vec<_>>();
                    Response::builder()
                        .header("content-type", kind)
                        .body(BoxBody::new(StreamBody::new(tokio_stream::iter(frames))))
                        .expect("response")
                };
                let response = if path.starts_with("/api/stream/") || path.starts_with("/stream") {
                    stream("text/event-stream")
                } else if path == "/api/export" {
                    stream("application/json")
                } else if path.starts_with("/api/") {
                    full(200, "application/json", json)
                } else if path == "/" {
                    let mut response = full(302, "text/plain", Bytes::new());
                    response
                        .headers_mut()
                        .insert("location", HeaderValue::from_static("/en/"));
                    response
                } else if path == "/robots.txt" {
                    full(
                        200,
                        "text/plain; charset=utf-8",
                        Bytes::from_static(b"User-agent: *\nAllow: /\nSitemap: https://example.com/sitemap.xml\n"),
                    )
                } else if path == "/sitemap.xml" {
                    full(200, "application/xml", sitemap)
                } else {
                    full(404, "text/html; charset=utf-8", not_found)
                };
                Ok::<_, Infallible>(response)
            }
        });
        tokio::spawn(hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tcp), service));
    }
}

/// xorshift64: the stand-in site and the upstream's answers are the same on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const WORDS: &[&str] = &[
    "river",
    "garden",
    "window",
    "meadow",
    "summer",
    "morning",
    "journey",
    "story",
    "harbour",
    "lantern",
    "orchard",
    "compass",
    "pebble",
    "moment",
    "kettle",
    "upland",
    "été",
    "forêt",
    "château",
    "fenêtre",
    "naïve",
    "garçon",
    "größe",
    "straße",
    "müde",
    "schön",
    "über",
    "река",
    "сад",
    "окно",
    "утро",
    "лето",
    "луг",
    "гавань",
    "компас",
    "камень",
];

fn prose(rng: &mut Rng, words: usize) -> String {
    let mut out = String::new();
    for i in 0..words {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(WORDS[rng.below(WORDS.len())]);
    }
    out
}

/// A page about `size` bytes long, shaped as the built ones: head with the build's assets, sections
/// of text with links, a footer.
fn page(rng: &mut Rng, lang: &str, size: usize) -> String {
    let mut html = format!(
        r#"<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{}</title><link rel="stylesheet" href="/assets/main-PgoTrain.css"><script type="module" src="/assets/main-PgoTrain.js"></script></head><body><header class="site-header"><nav><a href="/{lang}/">Example</a> <a href="/{lang}/services/">{}</a> <a href="/{lang}/contact">{}</a></nav></header><main>"#,
        prose(rng, 4),
        prose(rng, 1),
        prose(rng, 1)
    );
    while html.len() < size {
        let words = 40 + rng.below(80);
        let _ = write!(
            html,
            r#"<section class="block block-{}"><h2>{}</h2><p>{}</p><a class="button" href="/{lang}/services/overview">{}</a></section>"#,
            rng.below(9),
            prose(rng, 3),
            prose(rng, words),
            prose(rng, 2)
        );
        html.push('\n');
    }
    html + r#"</main><footer class="site-footer"><p>© Example</p></footer></body></html>"#
}

fn script(rng: &mut Rng, size: usize) -> String {
    let mut js = String::new();
    while js.len() < size {
        let (n, word) = (rng.below(10_000), WORDS[rng.below(16)]);
        let _ = writeln!(
            js,
            r#"function f{n}(a,b){{const c=a.{word}+b*{};return c>{n}?"{word}":f{}(c,b)}}"#,
            rng.below(99),
            rng.below(10_000)
        );
    }
    js
}

fn styles(rng: &mut Rng, size: usize) -> String {
    let mut css = String::new();
    while css.len() < size {
        let _ = writeln!(
            css,
            ".{}-{}{{margin:{}px {}px;color:#{:06x};display:flex;gap:{}rem}}",
            WORDS[rng.below(16)],
            rng.below(1000),
            rng.below(48),
            rng.below(48),
            rng.next() & 0xff_ffff,
            rng.below(4)
        );
    }
    css
}

fn drawing(rng: &mut Rng, size: usize) -> String {
    let mut svg = String::from(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><path d="M0 0"#);
    while svg.len() < size {
        let _ = write!(svg, "L{} {}", rng.below(512), rng.below(512));
    }
    svg + r#""/></svg>"#
}

fn noise(rng: &mut Rng, size: usize) -> Vec<u8> {
    (0..size).map(|_| rng.next() as u8).collect()
}

/// Writes `bytes` to `dir/path`, and for text its .br, .zst and .gz siblings, as the build does.
fn put(dir: &Path, path: &str, bytes: &[u8], siblings: bool) -> std::io::Result<()> {
    let file = dir.join(path);
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&file, bytes)?;
    if siblings {
        let sibling = |extension: &str| {
            let mut name = file.clone().into_os_string();
            name.push(".");
            name.push(extension);
            PathBuf::from(name)
        };
        let mut br = brotli::CompressorWriter::new(Vec::new(), 4096, 9, 22);
        br.write_all(bytes)?;
        std::fs::write(sibling("br"), br.into_inner())?;
        std::fs::write(sibling("zst"), zstd::bulk::compress(bytes, 15)?)?;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        gz.write_all(bytes)?;
        std::fs::write(sibling("gz"), gz.finish()?)?;
    }
    Ok(())
}

/// A stand-in for the built site (dist/client) in `dir`, the same on every run: pages in four
/// languages, one with a section of its own, the build's assets, fonts, images, the service worker
/// and its manifest. Returns the paths to request.
fn site(dir: &Path) -> std::io::Result<Vec<String>> {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut paths = Vec::new();
    for lang in ["en", "fr", "ru", "de"] {
        for (name, size) in [
            ("index", 30_000),
            ("contact", 12_000),
            ("pricing", 25_000),
            ("about", 18_000),
            ("services/index", 20_000),
            ("services/overview", 60_000),
        ] {
            put(
                dir,
                &format!("{lang}/{name}.html"),
                page(&mut rng, lang, size).as_bytes(),
                true,
            )?;
            paths.push(format!("/{lang}/{}", name.strip_suffix("index").unwrap_or(name)));
        }
    }
    let text = [
        ("assets/main-PgoTrain.js", script(&mut rng, 150_000)),
        ("assets/Form-PgoTrain.js", script(&mut rng, 9_000)),
        ("assets/Quiz-PgoTrain.js", script(&mut rng, 25_000)),
        ("assets/main-PgoTrain.css", styles(&mut rng, 40_000)),
        ("sw.js", script(&mut rng, 6_000)),
        ("v.json", r#"{"version":"pgo-train"}"#.to_string()),
        (
            "site.webmanifest",
            r#"{"name":"Example","icons":[{"src":"/images/icon.png","sizes":"192x192"}]}"#.to_string(),
        ),
        ("llms.txt", prose(&mut rng, 1_200)),
        ("favicon.svg", drawing(&mut rng, 1_500)),
        ("images/logo.svg", drawing(&mut rng, 7_000)),
    ];
    for (path, body) in &text {
        put(dir, path, body.as_bytes(), true)?;
        paths.push(format!("/{path}"));
    }
    for (path, size) in [
        ("fonts/sans-latin.woff2", 48_000),
        ("fonts/sans-cyrillic.woff2", 30_000),
        ("fonts/display-latin.woff2", 25_000),
        ("images/hero.webp", 90_000),
        ("images/team.avif", 40_000),
        ("images/og.jpg", 120_000),
        ("images/icon.png", 9_000),
        ("favicon.ico", 4_000),
    ] {
        put(dir, path, &noise(&mut rng, size), false)?;
        paths.push(format!("/{path}"));
    }
    Ok(paths)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("cert") => {
            let dir = Path::new(args.get(1).expect("dir"));
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("certificate");
            std::fs::write(dir.join("cert.pem"), certified.cert.pem()).expect("cert.pem");
            std::fs::write(dir.join("key.pem"), certified.signing_key.serialize_pem()).expect("key.pem");
        }
        Some("site") => {
            for path in site(Path::new(args.get(1).expect("dir"))).expect("site") {
                println!("{path}");
            }
        }
        Some("run") if args.len() >= 7 => {
            let plain_addr: SocketAddr = args[1].parse().expect("plain address");
            let tls_addr: SocketAddr = args[2].parse().expect("tls address");
            let cert = std::fs::read(&args[3]).expect("cert");
            let upstream_addr: SocketAddr = args[4].parse().expect("upstream address");
            let seconds: u64 = args[5].parse().expect("seconds");
            let paths: Vec<String> = args[6..].to_vec();
            let runtime = tokio::runtime::Runtime::new().expect("runtime");
            runtime.block_on(async move {
                tokio::spawn(upstream(upstream_addr));
                ready(upstream_addr).await;
                ready(plain_addr).await;
                ready(tls_addr).await;
                let mut all = probes(&paths);
                all.extend(revalidations(&paths, &etags(plain_addr, &paths).await));
                let probes = Arc::new(all);
                let done = Arc::new(AtomicU64::new(0));
                let until = Instant::now() + Duration::from_secs(seconds);
                tokio::join!(
                    plain(plain_addr, probes.clone(), until, done.clone()),
                    over_tls(tls_addr, cert.clone(), probes.clone(), until, done.clone()),
                    quic(tls_addr, cert, probes.clone(), until, done.clone()),
                );
                println!(
                    "{} requests of {} kinds in {seconds} s",
                    done.load(Ordering::Relaxed),
                    probes.len()
                );
            });
        }
        _ => {
            eprintln!(
                "usage: train cert <dir> | train site <dir> | \
                 train run <plain addr> <tls addr> <cert.pem> <upstream addr> <seconds> <path>..."
            );
            std::process::exit(2);
        }
    }
}
