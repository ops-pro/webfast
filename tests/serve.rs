//! End to end: the server started from a Caddyfile shaped like sample/Caddyfile, a stub upstream
//! for the proxied paths, and real HTTP/1.1, HTTP/2 (TLS) and HTTP/3 clients.

use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use webfast::server::{self, Running};

fn compress(encoding: &str, data: &[u8]) -> Vec<u8> {
    match encoding {
        "br" => {
            let mut out = Vec::new();
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 9, 22);
            w.write_all(data).unwrap();
            drop(w);
            out
        }
        "zst" => zstd::stream::encode_all(data, 3).unwrap(),
        _ => {
            let mut w = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            w.write_all(data).unwrap();
            w.finish().unwrap()
        }
    }
}

fn write(root: &Path, path: &str, body: &[u8]) {
    let file = root.join(path.trim_start_matches('/'));
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(file, body).unwrap();
}

const HOME: &str = "<!doctype html><title>Home</title><p>en home page</p>";

fn site() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let home = HOME.repeat(20);
    write(root, "/en/index.html", home.as_bytes());
    for ext in ["br", "zst", "gz"] {
        write(root, &format!("/en/index.html.{ext}"), &compress(ext, home.as_bytes()));
    }
    write(root, "/en/contact.html", b"<!doctype html><title>Contact</title>");
    write(root, "/en/blog/index.html", b"<!doctype html><title>Blog</title>");
    write(root, "/assets/app-abc.js", b"console.log(1)");
    write(root, "/sw.js", b"self.addEventListener('fetch', () => {})");
    write(root, "/_headers", b"internal");
    write(root, "/.well-known/catalog.json", b"{\"catalog\":true}");
    dir
}

/// Upstream stub: SSE on /api/stream/chat, a JSON echo of the request everywhere else.
async fn upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let service = hyper::service::service_fn(|req: Request<Incoming>| async move {
                    // Reads the whole request body before answering (a stalled client is seen here).
                    if req.uri().path().starts_with("/api/slurp") {
                        let size = match req.into_body().collect().await {
                            Ok(collected) => collected.to_bytes().len().to_string(),
                            Err(e) => format!("error: {e}"),
                        };
                        let response = http::Response::builder()
                            .header("content-type", "text/plain")
                            .body(
                                Full::new(Bytes::from(size))
                                    .map_err(|never| match never {})
                                    .boxed_unsync(),
                            )
                            .unwrap();
                        return Ok::<_, Infallible>(response);
                    }
                    if req.uri().path() == "/api/stream/chat" {
                        let (tx, rx) = tokio::sync::mpsc::channel::<Result<http_body::Frame<Bytes>, Infallible>>(4);
                        tokio::spawn(async move {
                            let _ = tx.send(Ok(http_body::Frame::data(Bytes::from("data: 1\n\n")))).await;
                            tokio::time::sleep(Duration::from_millis(400)).await;
                            let _ = tx.send(Ok(http_body::Frame::data(Bytes::from("data: 2\n\n")))).await;
                        });
                        let body = http_body_util::StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx));
                        let response = http::Response::builder()
                            .header("content-type", "text/event-stream")
                            .header("cache-control", "no-cache")
                            .body(body.boxed_unsync())
                            .unwrap();
                        return Ok::<_, Infallible>(response);
                    }
                    let header = |name: &str| {
                        req.headers()
                            .get(name)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string()
                    };
                    let echo = serde_json::json!({
                        "method": req.method().as_str(),
                        "uri": req.uri().to_string(),
                        "host": header("host"),
                        "xff": header("x-forwarded-for"),
                        "xfp": header("x-forwarded-proto"),
                        "xfh": header("x-forwarded-host"),
                        "country": header("cf-ipcountry"),
                        "real_ip": header("x-real-ip"),
                        // /api/big: past the size compressed on the blocking pool (64 KiB).
                        "padding": "x".repeat(if req.uri().path() == "/api/big" { 300_000 } else { 600 }),
                    });
                    let response = http::Response::builder()
                        .header("content-type", "application/json")
                        .header("x-upstream", "1")
                        .body(
                            Full::new(Bytes::from(echo.to_string()))
                                .map_err(|never| match never {})
                                .boxed_unsync(),
                        )
                        .unwrap();
                    Ok(response)
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    addr
}

fn caddyfile(root: &Path, app: SocketAddr, ai: SocketAddr) -> String {
    format!(
        r#"{{
	auto_https off
	admin off
	servers {{
		trusted_proxies static private_ranges
		client_ip_headers X-Forwarded-For X-Real-IP
	}}
}}

(site_headers) {{
	header {{
		Content-Security-Policy "default-src 'self'"
		X-Frame-Options "DENY"
		-Server
	}}
	@hashed path /assets/*
	header @hashed Cache-Control "public, max-age=31536000, immutable"
	@sw path /sw.js
	header @sw Cache-Control "max-age=300"
	@catalog path /.well-known/catalog.json
	header @catalog {{
		Content-Type "application/x-catalog+json"
		Access-Control-Allow-Origin "*"
		defer
	}}
	@html_en path /en/*
	header @html_en Cache-Control "public, max-age=0, must-revalidate"
	header @html_en Link "</assets/app.css>; rel=preload; as=style, <f.woff2>; rel=preload; type=\"font/woff2\""
}}

:0 {{
	root * {root}
	import site_headers

	route {{
		respond /healthz "ok" 200

		@internal path /_headers /.buildignore /_internal/* /.cache/*
		respond @internal 404

		@stream path /api/stream/chat /stream
		reverse_proxy @stream {ai} {{
			flush_interval -1
		}}
		respond /api/stream/* 404

		request_body /api/slurp-limited {{
			max_size 1KB
		}}

		encode zstd br gzip

		reverse_proxy /api/* {app}

		@html_suffix path_regexp html ^(.*)\.html$
		redir @html_suffix {{re.html.1}} 308

		@dir_without_slash {{
			not path */
			file {{
				try_files {{path}}/index.html
			}}
		}}
		redir @dir_without_slash {{path}}/ 308

		@static file {{
			try_files {{path}} {{path}}.html {{path}}index.html
		}}
		handle @static {{
			rewrite * {{file_match.relative}}
			file_server {{
				precompressed br zstd gzip
			}}
		}}

		reverse_proxy {app}
	}}

	log {{
		output discard
	}}
}}
"#,
        root = root.display()
    )
}

struct Harness {
    _site: tempfile::TempDir,
    running: Running,
    base: String,
    client: Client<HttpConnector, Full<Bytes>>,
}

async fn start() -> Harness {
    let site = site();
    let app = upstream().await;
    let ai = upstream().await;
    let text = caddyfile(site.path(), app, ai);
    let file = webfast::caddyfile::parse_str(&text, Path::new("Caddyfile")).unwrap();
    let config = webfast::load_parsed(&file, 1 << 24).unwrap();
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();
    let client = Client::builder(TokioExecutor::new()).build_http();
    Harness {
        _site: site,
        running,
        base: format!("http://127.0.0.1:{port}"),
        client,
    }
}

struct Got {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Harness {
    async fn request(&self, method: Method, path: &str, headers: &[(&str, &str)]) -> Got {
        let mut builder = Request::builder().method(method).uri(format!("{}{path}", self.base));
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let response = self
            .client
            .request(builder.body(Full::new(Bytes::new())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        Got { status, headers, body }
    }

    async fn get(&self, path: &str, headers: &[(&str, &str)]) -> Got {
        self.request(Method::GET, path, headers).await
    }
}

fn header<'a>(got: &'a Got, name: &str) -> &'a str {
    got.headers.get(name).map(|v| v.to_str().unwrap()).unwrap_or("")
}

#[tokio::test]
async fn static_site_behaves_like_the_caddy_config() {
    let h = start().await;

    let health = h.get("/healthz", &[]).await;
    assert_eq!(health.status, 200);
    assert_eq!(&health.body[..], b"ok");
    assert_eq!(header(&health, "content-type"), "text/plain; charset=utf-8");
    assert_eq!(
        header(&health, "content-security-policy"),
        "default-src 'self'",
        "deferred site headers apply"
    );
    assert!(health.headers.get("server").is_none());
    let date = httpdate::parse_http_date(header(&health, "date")).expect("an HTTP date");
    let age = std::time::SystemTime::now().duration_since(date).unwrap_or_default();
    assert!(age < Duration::from_secs(3), "the shared Date is current: {age:?}");

    assert_eq!(h.get("/_headers", &[]).await.status, 404);

    let home = h.get("/en/", &[]).await;
    assert_eq!(home.status, 200);
    assert_eq!(&home.body[..], HOME.repeat(20).as_bytes());
    assert_eq!(header(&home, "content-type"), "text/html; charset=utf-8");
    assert_eq!(header(&home, "cache-control"), "public, max-age=0, must-revalidate");
    assert!(header(&home, "link").contains("type=\"font/woff2\""));
    assert_eq!(header(&home, "vary"), "Accept-Encoding");
    assert_eq!(header(&home, "content-length"), home.body.len().to_string());
    assert_eq!(
        header(&home, "etag"),
        webfast::files::etag_of(HOME.repeat(20).as_bytes())
    );
    assert!(home.headers.get("last-modified").is_none());

    let redirect = h.get("/en", &[]).await;
    assert_eq!(redirect.status, 308);
    assert_eq!(header(&redirect, "location"), "/en/");
    let blog = h.get("/en/blog?x=1", &[]).await;
    assert_eq!(
        (blog.status, header(&blog, "location")),
        (StatusCode::PERMANENT_REDIRECT, "/en/blog/")
    );
    let suffix = h.get("/en/contact.html", &[]).await;
    assert_eq!(
        (suffix.status, header(&suffix, "location")),
        (StatusCode::PERMANENT_REDIRECT, "/en/contact")
    );
    let contact = h.get("/en/contact", &[]).await;
    assert_eq!(contact.status, 200);
    assert_eq!(&contact.body[..], b"<!doctype html><title>Contact</title>");
    // No open redirect through the path: `//host` and `/\host` (a browser reads `\` as `/`) in
    // {re.html.1} and in the canonical trailing-slash redirect stay on the site — also with a tab
    // or newline between the slashes, which a browser drops ("/%09/host" would be "//host").
    for (path, location) in [
        ("/%5Cevil.example/x.html", "/evil.example/x"),
        ("//evil.example/x.html", "/evil.example/x"),
        ("/%5C%5Cevil.example/x.html", "/evil.example/x"),
        ("/%09/evil.example/x.html", "/evil.example/x"),
        ("/%09%5Cevil.example/x.html", "/evil.example/x"),
        ("/%0D/evil.example/x.html", "/evil.example/x"),
        ("/%09/evil.example/../../en", "/evil.example/../../en/"),
        ("/%09page.html", "/%09page"),
    ] {
        let got = h.get(path, &[]).await;
        assert_eq!(
            (got.status, header(&got, "location")),
            (StatusCode::PERMANENT_REDIRECT, location),
            "{path}"
        );
    }

    // Precompressed: the browser's usual header picks br (config order breaks the q=1 tie).
    let br = h.get("/en/", &[("accept-encoding", "gzip, deflate, br, zstd")]).await;
    assert_eq!(header(&br, "content-encoding"), "br");
    assert_eq!(&br.body[..], &compress("br", HOME.repeat(20).as_bytes())[..]);
    assert_ne!(header(&br, "etag"), header(&home, "etag"));
    let gz = h.get("/en/", &[("accept-encoding", "gzip")]).await;
    let mut plain = String::new();
    flate2::read::GzDecoder::new(&gz.body[..])
        .read_to_string(&mut plain)
        .unwrap();
    assert_eq!(plain, HOME.repeat(20));

    // Conditional and range requests.
    let etag = header(&home, "etag").to_string();
    let not_modified = h.get("/en/", &[("if-none-match", &etag)]).await;
    assert_eq!(not_modified.status, 304);
    assert!(not_modified.body.is_empty());
    assert_eq!(header(&not_modified, "etag"), etag);
    assert!(not_modified.headers.get("content-type").is_none());
    // The br sibling's ETag, weak and in a list: 304 without Content-Encoding.
    let br_listed = format!("\"other\", W/{}", header(&br, "etag"));
    let listed = h
        .get("/en/", &[("accept-encoding", "br"), ("if-none-match", &br_listed)])
        .await;
    assert_eq!(listed.status, 304);
    assert_eq!(header(&listed, "etag"), header(&br, "etag"));
    assert!(listed.headers.get("content-encoding").is_none());
    // If-Match first: 412, with the representation's headers.
    let failed = h
        .get("/en/", &[("if-match", "\"other\""), ("if-none-match", &etag)])
        .await;
    assert_eq!(failed.status, 412);
    assert_eq!(header(&failed, "content-type"), "text/html; charset=utf-8");
    let partial = h.get("/en/contact", &[("range", "bytes=0-8")]).await;
    assert_eq!(partial.status, 206);
    assert_eq!(&partial.body[..], b"<!doctype");
    assert_eq!(header(&partial, "content-range"), "bytes 0-8/37");
    // /en/index.html is kept in LZ4 (repeated text): whole, ranged and HEAD all as stored.
    let tail = h.get("/en/", &[("range", "bytes=-10")]).await;
    assert_eq!(tail.status, 206);
    assert_eq!(&tail.body[..], &HOME.repeat(20).as_bytes()[HOME.len() * 20 - 10..]);
    let head_lz4 = h.request(Method::HEAD, "/en/", &[]).await;
    assert_eq!(header(&head_lz4, "content-length"), (HOME.len() * 20).to_string());

    // Several ranges: multipart/byteranges; overlapping or too many ranges: the whole file (200),
    // as for ranges adding up to more than the file.
    let two = h.get("/en/contact", &[("range", "bytes=0-1,4-5")]).await;
    assert_eq!(two.status, 206);
    assert!(header(&two, "content-type").starts_with("multipart/byteranges; boundary="));
    assert!(two.body.windows(2).any(|w| w == b"<!"));
    let too_many = format!("bytes={}", (0..65).map(|_| "0-0").collect::<Vec<_>>().join(","));
    for range in ["bytes=0-1,1-2", "bytes=0-0,0-0", too_many.as_str()] {
        let got = h.get("/en/contact", &[("range", range)]).await;
        assert_eq!(got.status, 200, "{range}");
        assert_eq!(&got.body[..], b"<!doctype html><title>Contact</title>");
        assert!(got.headers.get("content-range").is_none());
    }
    let many_ok = format!(
        "bytes={}",
        (0..32).map(|i| format!("{i}-{i}")).collect::<Vec<_>>().join(",")
    );
    assert_eq!(h.get("/en/contact", &[("range", &many_ok)]).await.status, 206);

    let head = h.request(Method::HEAD, "/en/contact", &[]).await;
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());
    assert_eq!(header(&head, "content-length"), "37");

    let post = h.request(Method::POST, "/en/contact", &[]).await;
    assert_eq!(post.status, 405);
    assert_eq!(header(&post, "allow"), "GET, HEAD");

    let catalog = h.get("/.well-known/catalog.json", &[]).await;
    assert_eq!(header(&catalog, "content-type"), "application/x-catalog+json");
    assert_eq!(header(&catalog, "access-control-allow-origin"), "*");
    assert_eq!(header(&h.get("/sw.js", &[]).await, "cache-control"), "max-age=300");
    assert_eq!(
        header(&h.get("/assets/app-abc.js", &[]).await, "cache-control"),
        "public, max-age=31536000, immutable"
    );

    h.running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn proxied_paths_stream_and_compress() {
    let h = start().await;

    let echo = h
        .get(
            "/api/echo?q=1",
            &[
                ("x-forwarded-for", "203.0.113.9"),
                ("cf-ipcountry", "NL"),
                ("x-real-ip", "6.6.6.6"),
            ],
        )
        .await;
    assert_eq!(echo.status, 200);
    assert_eq!(header(&echo, "x-upstream"), "1");
    let json: serde_json::Value = serde_json::from_slice(&echo.body).unwrap();
    assert_eq!(json["uri"], "/api/echo?q=1");
    assert_eq!(json["host"], h.base.trim_start_matches("http://"));
    assert_eq!(json["xff"], "203.0.113.9, 127.0.0.1", "127.0.0.1 is a trusted proxy");
    assert_eq!(json["xfp"], "http");
    assert_eq!(json["country"], "NL", "a trusted proxy's client headers pass");
    assert_eq!(json["real_ip"], "6.6.6.6");

    // A request body is sent on as it arrives; one the client stops sending ends with 408 after
    // the stall limit instead of holding this connection and the upstream's.
    let whole = h.request(Method::POST, "/api/slurp", &[]).await;
    assert_eq!((whole.status, &whole.body[..]), (StatusCode::OK, &b"0"[..]));

    for (encoding, accept) in [
        ("zstd", "gzip, deflate, br, zstd"),
        ("br", "gzip, br"),
        ("gzip", "gzip"),
    ] {
        let got = h.get("/api/echo", &[("accept-encoding", accept)]).await;
        assert_eq!(header(&got, "content-encoding"), encoding, "{accept}");
        assert!(header(&got, "vary").contains("Accept-Encoding"));
        let mut plain = Vec::new();
        match encoding {
            "zstd" => plain = zstd::stream::decode_all(&got.body[..]).unwrap(),
            "br" => {
                brotli::Decompressor::new(&got.body[..], 4096)
                    .read_to_end(&mut plain)
                    .unwrap();
            }
            _ => {
                flate2::read::GzDecoder::new(&got.body[..])
                    .read_to_end(&mut plain)
                    .unwrap();
            }
        }
        assert!(serde_json::from_slice::<serde_json::Value>(&plain).is_ok());
    }
    // A large body is compressed off the worker thread, whole, with its length.
    let big = h.get("/api/big", &[("accept-encoding", "br")]).await;
    assert_eq!(header(&big, "content-encoding"), "br");
    assert_eq!(header(&big, "content-length"), big.body.len().to_string());
    let mut plain = Vec::new();
    brotli::Decompressor::new(&big.body[..], 4096)
        .read_to_end(&mut plain)
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(json["padding"].as_str().unwrap().len(), 300_000);

    // Unknown pages go to the app as well.
    let fallback = h.get("/robots.txt", &[]).await;
    assert_eq!(header(&fallback, "x-upstream"), "1");
    assert_eq!(h.get("/api/stream/other", &[]).await.status, 404);

    // SSE: the first event arrives long before the stream ends, uncompressed.
    let started = Instant::now();
    let request = Request::get(format!("{}/api/stream/chat", h.base))
        .header("accept-encoding", "gzip, br, zstd")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = h.client.request(request).await.unwrap();
    assert!(response.headers().get("content-encoding").is_none());
    let mut body = response.into_body();
    let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
    let first_at = started.elapsed();
    assert_eq!(&first[..], b"data: 1\n\n");
    let second = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(&second[..], b"data: 2\n\n");
    assert!(first_at < Duration::from_millis(300), "first event after {first_at:?}");
    assert!(started.elapsed() >= Duration::from_millis(390));

    h.running.shutdown(Duration::from_secs(1)).await;
}

fn self_signed() -> (rcgen::CertifiedKey<rcgen::KeyPair>, tempfile::TempDir) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("cert.pem"), certified.cert.pem()).unwrap();
    std::fs::write(dir.path().join("key.pem"), certified.signing_key.serialize_pem()).unwrap();
    (certified, dir)
}

fn client_tls(cert: &rcgen::Certificate, alpn: &[u8]) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    config
}

#[tokio::test]
async fn https_over_http2_and_http3() {
    let (certified, dir) = self_signed();
    let text = format!(
        "localhost:0 {{\n\ttls {cert} {key}\n\trespond \"hello {{scheme}}\"\n}}\n",
        cert = dir.path().join("cert.pem").display(),
        key = dir.path().join("key.pem").display()
    );
    let file = webfast::caddyfile::parse_str(&text, Path::new("Caddyfile")).unwrap();
    let config = webfast::load_parsed(&file, 1 << 20).unwrap();
    let running = server::start(config).await.unwrap();
    let (_, tcp, udp) = running.bound[0];
    let port = tcp.port();
    let udp = udp.expect("HTTP/3 is on for TLS sites");
    assert_eq!(udp.port(), port);

    // HTTP/2 over TLS.
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls(&certified.cert, b"h2")));
    let tcp_stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let tls_stream = connector
        .connect("localhost".try_into().unwrap(), tcp_stream)
        .await
        .unwrap();
    assert_eq!(tls_stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls_stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let response = sender
        .send_request(
            Request::get(format!("https://localhost:{port}/"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.version(), http::Version::HTTP_2);
    assert_eq!(
        response.headers()["alt-svc"],
        format!("h3=\":{port}\"; ma=2592000").as_str()
    );
    assert!(response.headers().contains_key("date"));
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"hello https");

    // HTTP/3.
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls(&certified.cert, b"h3")).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
    let conn = endpoint
        .connect(SocketAddr::from(([127, 0, 0, 1], port)), "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
    let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    let mut stream = send_request
        .send_request(Request::get(format!("https://localhost:{port}/")).body(()).unwrap())
        .await
        .unwrap();
    stream.finish().await.unwrap();
    let response = stream.recv_response().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.version(), http::Version::HTTP_3);
    assert!(response.headers().get("alt-svc").is_none());
    assert!(response.headers().contains_key("date"));
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        use bytes::Buf;
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        body.extend_from_slice(&bytes);
    }
    assert_eq!(body, b"hello https");
    drop(send_request);
    drive.abort();
    endpoint.close(0u32.into(), b"done");

    running.shutdown(Duration::from_secs(1)).await;
}

/// A client whose handshake offers only these signature schemes (it verifies nothing else).
fn client_offering(roots: &[&rcgen::Certificate], schemes: &[rustls::SignatureScheme]) -> rustls::ClientConfig {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    let all = provider.signature_verification_algorithms;
    let mapping: Vec<_> = all
        .mapping
        .iter()
        .filter(|(s, _)| schemes.contains(s))
        .copied()
        .collect();
    provider.signature_verification_algorithms = rustls::crypto::WebPkiSupportedAlgorithms {
        all: all.all,
        mapping: Box::leak(mapping.into_boxed_slice()),
    };
    let mut store = rustls::RootCertStore::empty();
    for cert in roots {
        store.add(cert.der().clone()).unwrap();
    }
    rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(store)
        .with_no_client_auth()
}

#[tokio::test]
async fn a_site_with_several_certificates_gives_each_client_one_it_can_verify() {
    let dir = tempfile::tempdir().unwrap();
    let mut certs = Vec::new();
    for (name, algorithm) in [("ec", &rcgen::PKCS_ECDSA_P256_SHA256), ("rsa", &rcgen::PKCS_RSA_SHA256)] {
        let key = rcgen::KeyPair::generate_for(algorithm).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        std::fs::write(dir.path().join(format!("{name}.pem")), cert.pem()).unwrap();
        std::fs::write(dir.path().join(format!("{name}.key")), key.serialize_pem()).unwrap();
        certs.push(cert);
    }
    let text = format!(
        "localhost:0 {{\n\ttls {d}/ec.pem {d}/ec.key\n\ttls {d}/rsa.pem {d}/rsa.key\n\trespond \"ok\"\n}}\n",
        d = dir.path().display()
    );
    let file = webfast::caddyfile::parse_str(&text, Path::new("Caddyfile")).unwrap();
    let config = webfast::load_parsed(&file, 1 << 20).unwrap();
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();

    use rustls::SignatureScheme::{ECDSA_NISTP256_SHA256 as EC, RSA_PSS_SHA256 as RSA};
    for (offered, expected) in [(vec![EC, RSA], 0), (vec![RSA], 1), (vec![EC], 0)] {
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_offering(&[&certs[0], &certs[1]], &offered)));
        let tcp_stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let tls_stream = connector
            .connect("localhost".try_into().unwrap(), tcp_stream)
            .await
            .unwrap();
        let peer = &tls_stream.get_ref().1.peer_certificates().unwrap()[0];
        assert_eq!(peer, certs[expected].der(), "offered {offered:?}");
    }

    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn request_bodies_over_their_limit_get_413() {
    let h = start().await;
    type Boxed = http_body_util::combinators::BoxBody<Bytes, Infallible>;
    let client: Client<HttpConnector, Boxed> = Client::builder(TokioExecutor::new()).build_http();
    let post = |path: &str, body: Boxed| {
        let request = Request::post(format!("{}{path}", h.base)).body(body).unwrap();
        let sent = client.request(request);
        async move {
            let response = sent.await.unwrap();
            let status = response.status();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            (status, String::from_utf8_lossy(&body).into_owned())
        }
    };
    let sized = |n: usize| Full::new(Bytes::from(vec![b'x'; n])).boxed();
    // Without a length: chunked over HTTP/1.1.
    let streamed = |chunks: usize, size: usize| {
        let frames: Vec<Result<http_body::Frame<Bytes>, Infallible>> = (0..chunks)
            .map(|_| Ok(http_body::Frame::data(Bytes::from(vec![b'x'; size]))))
            .collect();
        http_body_util::StreamBody::new(tokio_stream::iter(frames)).boxed()
    };
    // `max_size 1KB` is 1000 bytes, as Caddy reads it.
    assert_eq!(
        post("/api/slurp-limited", sized(1000)).await,
        (StatusCode::OK, "1000".into())
    );
    assert_eq!(
        post("/api/slurp-limited", sized(1001)).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        post("/api/slurp-limited", streamed(2, 500)).await,
        (StatusCode::OK, "1000".into())
    );
    assert_eq!(
        post("/api/slurp-limited", streamed(3, 600)).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    // Paths without a limit take any size.
    assert_eq!(post("/api/slurp", sized(5000)).await, (StatusCode::OK, "5000".into()));
    h.running.shutdown(Duration::from_secs(1)).await;
}

/// A self-signed certificate for `names`, written as `<file>.pem` / `<file>.key` into `dir`.
fn certificate_for(dir: &Path, file: &str, names: &[&str]) -> rcgen::Certificate {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
        .unwrap()
        .self_signed(&key)
        .unwrap();
    std::fs::write(dir.join(format!("{file}.pem")), cert.pem()).unwrap();
    std::fs::write(dir.join(format!("{file}.key")), key.serialize_pem()).unwrap();
    cert
}

#[tokio::test]
async fn a_host_served_with_another_certificate_gets_421() {
    let dir = tempfile::tempdir().unwrap();
    let a = certificate_for(dir.path(), "a", &["a.test", "c.test"]);
    let b = certificate_for(dir.path(), "b", &["b.test"]);
    let d = dir.path().display();
    let sites = format!(
        "a.test:0, c.test:0 {{\n\ttls {d}/a.pem {d}/a.key\n\trespond \"site {{host}}\"\n}}\nb.test:0 {{\n\ttls {d}/b.pem {d}/b.key\n\trespond \"site {{host}}\"\n}}\n"
    );
    for check in ["", "{\n\tservers {\n\t\tstrict_sni_host insecure_off\n\t}\n}\n"] {
        let file = webfast::caddyfile::parse_str(&format!("{check}{sites}"), Path::new("Caddyfile")).unwrap();
        let running = server::start(webfast::load_parsed(&file, 1 << 20).unwrap())
            .await
            .unwrap();
        let port = running.bound[0].1.port();
        // One HTTP/2 connection opened for a.test, as a browser would, then requests for each host.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(a.der().clone()).unwrap();
        roots.add(b.der().clone()).unwrap();
        let mut config =
            rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let tcp_stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let tls_stream = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect("a.test".try_into().unwrap(), tcp_stream)
            .await
            .unwrap();
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls_stream))
            .await
            .unwrap();
        tokio::spawn(conn);
        let mut got = Vec::new();
        for host in ["a.test", "c.test", "b.test"] {
            let request = Request::get(format!("https://{host}:{port}/"))
                .body(Full::new(Bytes::new()))
                .unwrap();
            let response = sender.send_request(request).await.unwrap();
            let status = response.status();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            got.push((status.as_u16(), String::from_utf8_lossy(&body).into_owned()));
        }
        let expected_b = if check.is_empty() {
            (421, String::new())
        } else {
            (200, "site b.test".to_string())
        };
        assert_eq!(
            got,
            [
                (200, "site a.test".to_string()),
                (200, "site c.test".to_string()),
                expected_b
            ],
            "{check:?}"
        );
        running.shutdown(Duration::from_secs(1)).await;
    }
}

/// How a TLS handshake with `server_name` (`None`: no SNI) ended: Ok, or the rustls error.
async fn handshake(
    port: u16,
    mut config: rustls::ClientConfig,
    server_name: Option<&str>,
) -> Result<(), rustls::Error> {
    config.enable_sni = server_name.is_some();
    let name = server_name.unwrap_or("localhost").to_string();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp_stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    match connector.connect(name.try_into().unwrap(), tcp_stream).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
            .cloned()
            .unwrap_or_else(|| panic!("not a TLS error: {e}"))),
    }
}

#[tokio::test]
async fn with_strict_sni_only_the_names_of_the_sites_get_a_certificate() {
    let (certified, dir) = self_signed();
    let tls = format!(
        "tls {} {}",
        dir.path().join("cert.pem").display(),
        dir.path().join("key.pem").display()
    );
    // A named site and a site for any host, both with a certificate.
    let text = format!("localhost:0 {{\n\t{tls}\n\trespond \"named\"\n}}\n:0 {{\n\t{tls}\n\trespond \"any\"\n}}\n");
    let file = webfast::caddyfile::parse_str(&text, Path::new("Caddyfile")).unwrap();

    for strict in [true, false] {
        let mut config = webfast::load_parsed(&file, 1 << 20).unwrap();
        config.servers[0].strict_sni = strict;
        let running = server::start(config).await.unwrap();
        let port = running.bound[0].1.port();
        let client = || client_tls(&certified.cert, b"h2");

        assert_eq!(
            handshake(port, client(), Some("localhost")).await,
            Ok(()),
            "strict {strict}"
        );
        let other = handshake(port, client(), Some("other.test")).await;
        let no_sni = handshake(port, client(), None).await;
        if strict {
            // The server ends the handshake: no certificate reached the client.
            assert!(matches!(other, Err(rustls::Error::AlertReceived(_))), "{other:?}");
            assert!(matches!(no_sni, Err(rustls::Error::AlertReceived(_))), "{no_sni:?}");
        } else {
            // The site for any host gives its certificate, which the client finds not to be for
            // that name; without SNI the client checks it against "localhost" and takes it.
            assert!(matches!(other, Err(rustls::Error::InvalidCertificate(_))), "{other:?}");
            assert_eq!(no_sni, Ok(()));
        }
        running.shutdown(Duration::from_secs(1)).await;
    }
}

/// One HTTP/3 request on a QUIC connection: status and body.
async fn h3_request(conn: quinn::Connection, method: Method, port: u16) -> (StatusCode, String) {
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
    let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    let request = Request::builder()
        .method(method)
        .uri(format!("https://localhost:{port}/"))
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(request).await.unwrap();
    stream.finish().await.unwrap();
    let response = stream.recv_response().await.unwrap();
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        use bytes::Buf;
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        body.extend_from_slice(&bytes);
    }
    drop(send_request);
    drive.abort();
    (response.status(), String::from_utf8(body).unwrap())
}

#[tokio::test]
async fn http3_resumes_with_zero_rtt() {
    let (certified, dir) = self_signed();
    let text = format!(
        "localhost:0 {{\n\ttls {cert} {key}\n\trespond \"{{method}} early={{header.early-data}}\"\n}}\n",
        cert = dir.path().join("cert.pem").display(),
        key = dir.path().join("key.pem").display()
    );
    let file = webfast::caddyfile::parse_str(&text, Path::new("Caddyfile")).unwrap();
    let config = webfast::load_parsed(&file, 1 << 20).unwrap();
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let mut tls = client_tls(&certified.cert, b"h3");
    tls.enable_early_data = true;
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));

    // A full handshake: the server hands out session tickets.
    let conn = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    let (status, body) = h3_request(conn.clone(), Method::GET, port).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "GET early="));
    // The tickets come after the handshake; give the client a moment to take them.
    tokio::time::sleep(Duration::from_millis(100)).await;
    conn.close(0u32.into(), b"done");

    // Resumed: the request leaves together with the ClientHello, as early data.
    let (conn, accepted) = endpoint
        .connect(addr, "localhost")
        .unwrap()
        .into_0rtt()
        .unwrap_or_else(|_| panic!("a session ticket allows 0-RTT"));
    let (status, body) = h3_request(conn.clone(), Method::GET, port).await;
    assert!(accepted.await, "the server accepted the early data");
    assert_eq!(status, StatusCode::OK);
    // On localhost the handshake may complete before the request is taken: early or not, a GET is answered.
    assert!(body == "GET early=1" || body == "GET early=", "{body}");
    eprintln!("0-RTT request answered as {body:?}");
    conn.close(0u32.into(), b"done");
    endpoint.close(0u32.into(), b"done");
    running.shutdown(Duration::from_secs(1)).await;
}

fn load(text: &str) -> webfast::config::Config {
    let file = webfast::caddyfile::parse_str(text, Path::new("Caddyfile")).unwrap();
    webfast::load_parsed(&file, 1 << 27).unwrap()
}

fn request_head(method: &Method, path: &str, headers: &[(&str, &str)]) -> (http::request::Parts, webfast::body::Body) {
    let mut builder = Request::builder().method(method.clone()).uri(path);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    builder.body(webfast::body::empty()).unwrap().into_parts()
}

async fn collected(response: http::Response<webfast::body::Body>) -> (StatusCode, HeaderMap, Bytes) {
    let (parts, body) = response.into_parts();
    (parts.status, parts.headers, body.collect().await.unwrap().to_bytes())
}

async fn through_chain(
    routes: &Arc<[webfast::handler::Route]>,
    method: &Method,
    path: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Bytes) {
    let conn = Arc::new(webfast::handler::ConnInfo {
        remote: "127.0.0.1:5000".parse().unwrap(),
        tls: false,
        trusted: false,
        sni: None,
    });
    let (parts, body) = request_head(method, path, headers);
    let ctx = webfast::handler::Ctx::new(conn.clone(), parts, body, conn.remote.ip());
    collected(webfast::handler::Next::start(routes.clone()).run(ctx).await).await
}

#[tokio::test]
async fn ready_answers_are_what_the_chain_answers() {
    let site = site();
    // Compressible, above encode's minimum and without precompressed siblings: compressed on the
    // fly for clients that accept it, so only its plain answer can be prepared.
    write(site.path(), "/notes.txt", &[b'a'; 2000]);
    let app = upstream().await;
    let ai = upstream().await;
    let config = load(&caddyfile(site.path(), app, ai));
    let routes = config.servers[0].sites[0].routes.clone();
    let answers = webfast::memo::Answers::prepare(&routes, false).expect("this site decides by the path");
    // /en/, contact, blog/, the asset, sw.js, the catalog — and /en/index, /en/blog/index,
    // which the chain serves too ({path}.html), as Caddy does.
    assert_eq!(answers.paths(), 8);

    let accepts = [
        "gzip, deflate, br, zstd",
        "gzip, deflate, br",
        "gzip, deflate",
        "",
        "br",
        "zstd",
        "br;q=0.5, gzip",
        "zstd;q=0.1, br;q=0.9, gzip;q=0.9",
        "*",
    ];
    let paths = [
        "/en/",
        "/en/contact",
        "/en/contact?utm_source=x",
        "/en/blog/",
        "/assets/app-abc.js",
        "/sw.js",
        "/.well-known/catalog.json",
    ];
    for path in paths {
        for accept in accepts {
            let mut base: Vec<(&str, &str)> = Vec::new();
            if !accept.is_empty() {
                base.push(("accept-encoding", accept));
            }
            let first = through_chain(&routes, &Method::GET, path, &base).await;
            assert_eq!(first.0, StatusCode::OK, "{path}");
            let etag = first.1["etag"].to_str().unwrap().to_string();
            for (method, if_none_match) in [
                (Method::GET, None),
                (Method::HEAD, None),
                (Method::GET, Some(etag.as_str())),
            ] {
                let mut headers = base.clone();
                if let Some(etag) = if_none_match {
                    headers.push(("if-none-match", etag));
                }
                let (parts, _) = request_head(&method, path, &headers);
                let ready = answers
                    .answer(&parts)
                    .unwrap_or_else(|| panic!("no ready answer for {method} {path} {accept:?} {if_none_match:?}"));
                let ready = collected(ready).await;
                let expected = through_chain(&routes, &method, path, &headers).await;
                assert_eq!(
                    ready, expected,
                    "{method} {path} accept={accept:?} if-none-match={if_none_match:?}"
                );
            }
        }
    }

    // The long way: no ready answer.
    type Case<'a> = (Method, &'a str, &'a [(&'a str, &'a str)]);
    let compressible = [("accept-encoding", "gzip")];
    let cases: &[Case] = &[
        (Method::GET, "/en", &[]),
        (Method::GET, "/en/contact.html", &[]),
        (Method::GET, "/healthz", &[]),
        (Method::GET, "/api/forms", &[]),
        (Method::GET, "/EN/contact", &[]),
        (Method::GET, "/en//contact", &[]),
        (Method::GET, "/en/contact", &[("range", "bytes=0-3")]),
        (Method::GET, "/en/contact", &[("if-match", "\"x\"")]),
        (Method::GET, "/en/contact", &[("if-none-match", "\"other\"")]),
        (Method::POST, "/en/contact", &[]),
        (Method::GET, "/notes.txt", &compressible),
        (
            Method::GET,
            "/notes.txt",
            &[("accept-encoding", "gzip, deflate, br, zstd")],
        ),
    ];
    for (method, path, headers) in cases {
        let (parts, _) = request_head(method, path, headers);
        assert!(answers.answer(&parts).is_none(), "{method} {path} {headers:?}");
    }
    // Not compressed for a client that takes no encoding: that answer is ready.
    let (parts, _) = request_head(&Method::GET, "/notes.txt", &[]);
    let ready = collected(answers.answer(&parts).expect("plain notes.txt")).await;
    assert_eq!(ready, through_chain(&routes, &Method::GET, "/notes.txt", &[]).await);
}

#[tokio::test]
async fn sites_that_look_beyond_the_path_get_no_ready_answers() {
    let site = site();
    let root = site.path().display();
    for extra in [
        "header X-Client {client_ip}",
        "header X-Host {host}",
        "@get method GET\n\theader @get X-Get 1",
        "@ua header User-Agent *bot*\n\theader @ua X-Bot 1",
        "request_header X-A 1",
    ] {
        let config = load(&format!(":0 {{\n\troot * {root}\n\t{extra}\n\tfile_server\n}}\n"));
        let routes = config.servers[0].sites[0].routes.clone();
        assert!(webfast::memo::Answers::prepare(&routes, false).is_none(), "{extra}");
    }
    let config = load(&format!(
        ":0 {{\n\troot * {root}\n\theader X-Path {{path}}\n\tfile_server\n}}\n"
    ));
    let routes = config.servers[0].sites[0].routes.clone();
    let answers = webfast::memo::Answers::prepare(&routes, false).expect("path placeholders are fine");
    let (parts, _) = request_head(&Method::GET, "/sw.js", &[]);
    let ready = collected(answers.answer(&parts).unwrap()).await;
    assert_eq!(ready.1["x-path"], "/sw.js");
}

#[tokio::test]
async fn a_client_that_stops_sending_its_body_gets_408() {
    let site = site();
    let app = upstream().await;
    let ai = upstream().await;
    let mut config = load(&caddyfile(site.path(), app, ai));
    config.servers[0].limits.stall = Duration::from_millis(500);
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<http_body::Frame<Bytes>, Infallible>>(4);
    tx.send(Ok(http_body::Frame::data(Bytes::from("first chunk"))))
        .await
        .unwrap();
    let body = http_body_util::StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx)).boxed();
    let client: Client<HttpConnector, http_body_util::combinators::BoxBody<Bytes, Infallible>> =
        Client::builder(TokioExecutor::new()).build_http();
    let request = Request::post(format!("http://127.0.0.1:{port}/api/slurp"))
        .body(body)
        .unwrap();
    let started = Instant::now();
    // `tx` stays open and silent: the body never ends.
    let response = tokio::time::timeout(Duration::from_secs(5), client.request(request))
        .await
        .expect("answered before the test's own timeout")
        .unwrap();
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(
        started.elapsed() >= Duration::from_millis(450),
        "{:?}",
        started.elapsed()
    );
    drop(tx);
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn a_client_that_stops_reading_is_cut_off() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const SIZE: usize = 48 << 20;
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "/big.bin", &vec![7u8; SIZE]);
    // Kept as it is (no LZ4): this test is about the socket, not about decompressing 48 MB.
    let text = format!(":0 {{\n\troot * {}\n\tfile_server\n}}\n", dir.path().display());
    let file = webfast::caddyfile::parse_str(&text, Path::new("Caddyfile")).unwrap();
    let mut config = webfast::load_parsed_with(&file, 1 << 27, None).unwrap();
    config.servers[0].limits.stall = Duration::from_secs(1);
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();

    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    let mut stream = socket.connect(SocketAddr::from(([127, 0, 0, 1], port))).await.unwrap();
    stream
        .write_all(b"GET /big.bin HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    // Not reading: the server's writes stop moving.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let mut received = 0usize;
    let mut buf = vec![0u8; 1 << 16];
    loop {
        match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => received += n,
            Err(_) => panic!("the server did not close the connection"),
        }
    }
    assert!(
        received < SIZE,
        "the whole file arrived ({received} bytes): the reader was not cut off"
    );
    assert!(received > 0, "the response had started");
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn idle_http2_connections_are_closed() {
    let mut config = load("{\n\tservers {\n\t\tprotocols h1 h2c\n\t}\n}\n:0 {\n\trespond \"ok\"\n}\n");
    config.servers[0].limits.idle = Duration::from_millis(600);
    config.servers[0].limits.read_header = Duration::from_millis(600);
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();

    // One request, then nothing: GOAWAY after `idle`.
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
        .await
        .unwrap();
    let conn = tokio::spawn(conn);
    let response = sender
        .send_request(Request::get("http://localhost/").body(Full::new(Bytes::new())).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(&response.into_body().collect().await.unwrap().to_bytes()[..], b"ok");
    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(5), conn)
        .await
        .expect("the server closed the idle connection")
        .unwrap()
        .unwrap();
    let after = started.elapsed();
    assert!(
        after >= Duration::from_millis(400),
        "closed after {after:?}, before it was idle"
    );
    drop(sender);

    // A connection that never sends a request: closed after `read_header`.
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (_sender, conn) =
        hyper::client::conn::http2::handshake::<_, _, Full<Bytes>>(TokioExecutor::new(), TokioIo::new(tcp))
            .await
            .unwrap();
    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(5), conn)
        .await
        .expect("the server closed the silent connection")
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn connections_over_the_per_address_limit_are_refused() {
    use tokio::io::AsyncReadExt;
    let mut config = load(":0 {\n\trespond \"ok\"\n}\n");
    config.servers[0].limits.max_per_ip = 2;
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();
    use tokio::io::AsyncWriteExt;
    // Each sends the start of a request: a connection that sends nothing never reaches the server
    // (TCP_DEFER_ACCEPT).
    let open = || async move {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(
                b"GET / HTTP/1.1
",
            )
            .await
            .unwrap();
        stream
    };
    let _first = open().await;
    let _second = open().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut third = open().await;
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(2), third.read(&mut buf))
        .await
        .expect("the third connection was closed at once");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn http3_stops_a_stream_with_an_oversized_header_frame() {
    let (certified, dir) = self_signed();
    let text = format!(
        "localhost:0 {{\n\ttls {cert} {key}\n\trespond \"ok\"\n}}\n",
        cert = dir.path().join("cert.pem").display(),
        key = dir.path().join("key.pem").display()
    );
    let running = server::start(load(&text)).await.unwrap();
    let port = running.bound[0].1.port();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls(&certified.cert, b"h3")).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
    let endpoint_ref = &endpoint;
    let connect = || async move {
        endpoint_ref
            .connect(SocketAddr::from(([127, 0, 0, 1], port)), "localhost")
            .unwrap()
            .await
            .unwrap()
    };

    // A request stream written by hand: HEADERS (type 0x01) announcing 1 MiB, more than the 64 KiB
    // the server takes.
    let conn = connect().await;
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    let mut frame = vec![0x01];
    frame.extend_from_slice(&(0x8000_0000u32 | (1 << 20)).to_be_bytes());
    frame.extend_from_slice(&[b'x'; 16 * 1024]);
    send.write_all(&frame).await.unwrap();
    let stopped = tokio::time::timeout(Duration::from_secs(5), send.stopped())
        .await
        .expect("the server stopped the stream")
        .unwrap();
    assert_eq!(stopped.map(|code| code.into_inner()), Some(0x0107), "H3_EXCESSIVE_LOAD");

    // Requests of the usual size are served.
    let (status, body) = h3_request(connect().await, Method::GET, port).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "ok"));
    endpoint.close(0u32.into(), b"done");
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn both_runtimes_serve_and_shut_down() {
    for (per_core, workers) in [(true, None), (true, Some(1)), (false, None)] {
        let mut config = load(
            ":0 {
	respond \"ok {method}\"
}
",
        );
        config.servers[0].per_core = per_core;
        config.servers[0].workers = workers;
        let running = server::start(config).await.unwrap();
        let port = running.bound[0].1.port();
        let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        // Many connections at once: per core, the kernel spreads them over the listeners' threads.
        let requests: Vec<_> = (0..64)
            .map(|_| {
                let client = client.clone();
                tokio::spawn(async move {
                    let response = client
                        .request(
                            Request::get(format!("http://127.0.0.1:{port}/"))
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.status(), 200);
                    response.into_body().collect().await.unwrap().to_bytes()
                })
            })
            .collect();
        for request in requests {
            assert_eq!(&request.await.unwrap()[..], b"ok GET");
        }
        drop(client);
        let started = Instant::now();
        running.shutdown(Duration::from_secs(2)).await;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "per_core={per_core}, workers={workers:?}: the connections closed at the stop"
        );
    }
}

/// GETs `url` (with `accept` as Accept-Encoding, if any) until `done` holds, for up to 10 s.
async fn eventually(
    client: &Client<HttpConnector, Full<Bytes>>,
    url: &str,
    accept: Option<&str>,
    done: impl Fn(StatusCode, &HeaderMap, &[u8]) -> bool,
) -> (StatusCode, HeaderMap, Bytes) {
    let started = Instant::now();
    loop {
        let mut request = Request::get(url);
        if let Some(accept) = accept {
            request = request.header("accept-encoding", accept);
        }
        let response = client
            .request(request.body(Full::new(Bytes::new())).unwrap())
            .await
            .unwrap();
        let (status, headers) = (response.status(), response.headers().clone());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        if done(status, &headers, &body) {
            return (status, headers, body);
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{url}: still {status} {body:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn changed_files_are_picked_up() {
    use webfast::watch::{Mode, Watch};
    for mode in [Mode::Inotify, Mode::Poll] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "/page.html", b"one");
        write(root, "/page.html.br", &compress("br", b"one"));
        write(root, "/keep.txt", b"kept");
        let text = format!(
            ":0 {{\n\troot * {}\n\tfile_server {{\n\t\tprecompressed br\n\t}}\n}}\n",
            root.display()
        );
        let file = webfast::caddyfile::parse_str(&text, Path::new("Caddyfile")).unwrap();
        let watch = Watch {
            mode,
            poll: Duration::from_millis(100),
        };
        let config = webfast::load_parsed_watching(&file, 1 << 20, None, watch).unwrap();
        let running = server::start(config).await.unwrap();
        let base = format!("http://127.0.0.1:{}", running.bound[0].1.port());
        let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        let page = format!("{base}/page.html");
        let any = |_: StatusCode, _: &HeaderMap, _: &[u8]| true;
        let (_, before, body) = eventually(&client, &page, Some("br"), any).await;
        assert_eq!(decompress("br", &body), b"one");

        // The page and its sibling changed, a file added in a new directory, one removed.
        write(root, "/page.html", b"two!");
        write(root, "/page.html.br", &compress("br", b"two!"));
        write(root, "/new/added.txt", b"added");
        std::fs::remove_file(root.join("keep.txt")).unwrap();
        let (_, _, body) = eventually(&client, &page, None, |_, _, body| body == b"two!").await;
        assert_eq!(&body[..], b"two!", "{mode:?}");
        let (_, after, body) = eventually(&client, &page, Some("br"), |_, headers, _| {
            headers.get("etag") != before.get("etag")
        })
        .await;
        assert_eq!(decompress("br", &body), b"two!", "{mode:?}: the sibling too");
        assert_eq!(after.get("content-length").unwrap(), &body.len().to_string());
        let added = format!("{base}/new/added.txt");
        let (status, _, body) = eventually(&client, &added, None, |status, _, _| status == 200).await;
        assert_eq!((status, &body[..]), (StatusCode::OK, &b"added"[..]));
        let keep = format!("{base}/keep.txt");
        eventually(&client, &keep, None, |status, _, _| status == 404).await;

        // A file made later in the directory that came: watched too.
        write(root, "/new/later.txt", b"later");
        let later = format!("{base}/new/later.txt");
        let (_, _, body) = eventually(&client, &later, None, |status, _, _| status == 200).await;
        assert_eq!(&body[..], b"later", "{mode:?}");
        running.shutdown(Duration::from_secs(1)).await;
    }
}

fn decompress(encoding: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    match encoding {
        "br" => brotli::Decompressor::new(data, 4096).read_to_end(&mut out).unwrap(),
        _ => unreachable!(),
    };
    out
}
