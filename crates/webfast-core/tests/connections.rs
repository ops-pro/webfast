//! What a connection pays and when it closes: the head timeout between keep-alive requests, idle
//! HTTP/2 connections, bodiless HTTP/2 requests, and the access log line a response leaves.

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use webfast_core::server;

fn load(text: &str) -> webfast_core::config::Config {
    let file = webfast_core::caddyfile::parse_str(text, Path::new("Caddyfile")).unwrap();
    webfast_core::load_parsed(&file, 1 << 24).unwrap()
}

/// Sends `head` and reads one HTTP/1.1 response (`Content-Length` and no body beyond it).
async fn ask(stream: &mut TcpStream, head: &str) -> String {
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let mut text = String::new();
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("a response")
            .unwrap();
        assert!(n > 0, "closed before the response was complete: {text:?}");
        text.push_str(&String::from_utf8_lossy(&buf[..n]));
        if let Some(end) = text.find("\r\n\r\n") {
            let length: usize = text[..end]
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .map_or(0, |v| v.trim().parse().unwrap());
            if text.len() >= end + 4 + length {
                return text;
            }
        }
    }
}

/// Reads until the server closes the connection; how long that took, or `None` after `limit`.
async fn closed_within(stream: &mut TcpStream, limit: Duration) -> Option<Duration> {
    let started = Instant::now();
    let mut buf = [0u8; 256];
    loop {
        match tokio::time::timeout(limit, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return Some(started.elapsed()),
            Ok(Ok(_)) => continue,
            Err(_) => return None,
        }
    }
}

#[tokio::test]
async fn a_keep_alive_request_whose_head_stalls_closes_the_connection() {
    let mut config = load(":0 {\n\trespond \"ok\"\n}\n");
    config.servers[0].limits.read_header = Duration::from_millis(600);
    config.servers[0].limits.idle = Duration::from_secs(30);
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();

    // A complete request, then the start of a second whose head never ends: closed within
    // `read_header` of the first response, long before `idle`.
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let first = ask(&mut stream, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    assert!(first.starts_with("HTTP/1.1 200"), "{first}");
    assert!(first.ends_with("ok"), "{first}");
    stream.write_all(b"GET /second HTTP/1.1\r\nHost: loc").await.unwrap();
    let after = closed_within(&mut stream, Duration::from_secs(5))
        .await
        .expect("the connection was closed");
    assert!(
        after >= Duration::from_millis(400) && after < Duration::from_secs(3),
        "closed after {after:?}"
    );

    // A second request within the limit is served on the same connection.
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    ask(&mut stream, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let second = ask(&mut stream, "GET /again HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    assert!(second.starts_with("HTTP/1.1 200"), "{second}");
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn between_requests_http1_waits_the_shorter_of_idle_and_read_header() {
    // `idle` the shorter: a keep-alive connection closes after it.
    let mut config = load(":0 {\n\trespond \"ok\"\n}\n");
    config.servers[0].limits.read_header = Duration::from_secs(30);
    config.servers[0].limits.idle = Duration::from_millis(600);
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    ask(&mut stream, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    let after = closed_within(&mut stream, Duration::from_secs(5))
        .await
        .expect("closed when idle");
    assert!(
        after >= Duration::from_millis(400) && after < Duration::from_secs(3),
        "closed after {after:?}"
    );
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn http2_connections_keep_the_idle_timeout_between_requests() {
    // `read_header` short, `idle` long: HTTP/2 frames its heads, so only `idle` applies after the
    // first request — the connection outlives `read_header`, then closes at `idle`.
    let mut config = load("{\n\tservers {\n\t\tprotocols h1 h2c\n\t}\n}\n:0 {\n\trespond \"ok\"\n}\n");
    config.servers[0].limits.read_header = Duration::from_millis(400);
    config.servers[0].limits.idle = Duration::from_millis(1500);
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
        .await
        .unwrap();
    let conn = tokio::spawn(conn);
    let get = |sender: &mut hyper::client::conn::http2::SendRequest<Full<Bytes>>| {
        sender.send_request(Request::get("http://localhost/").body(Full::new(Bytes::new())).unwrap())
    };
    assert_eq!(get(&mut sender).await.unwrap().status(), 200);
    let started = Instant::now();
    tokio::time::sleep(Duration::from_millis(800)).await;
    // Past `read_header`, within `idle`: still open and serving.
    assert_eq!(get(&mut sender).await.unwrap().status(), 200);
    let closed = tokio::time::timeout(Duration::from_secs(5), conn)
        .await
        .expect("the server closed the idle connection")
        .unwrap();
    assert!(closed.is_ok(), "{closed:?}");
    let after = started.elapsed();
    assert!(after >= Duration::from_millis(1800), "closed after {after:?}");
    drop(sender);
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn http2_requests_without_a_body_are_served_without_stream_errors() {
    let mut config = load("{\n\tservers {\n\t\tprotocols h1 h2c\n\t}\n}\n:0 {\n\trespond \"ok {method} {path}\"\n}\n");
    config.servers[0].limits.idle = Duration::from_secs(5);
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
        .await
        .unwrap();
    let conn = tokio::spawn(conn);
    // Several GETs, one after the other and at once: each is answered; a stream reset or a
    // connection error would fail the request or end `conn` with an error.
    for i in 0..5 {
        let response = sender
            .send_request(
                Request::get(format!("http://localhost/one/{i}"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, format!("ok GET /one/{i}").as_bytes());
    }
    let at_once: Vec<_> = (0..8)
        .map(|i| {
            sender.send_request(
                Request::get(format!("http://localhost/many/{i}"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
        })
        .collect();
    for (i, pending) in at_once.into_iter().enumerate() {
        let response = pending.await.unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, format!("ok GET /many/{i}").as_bytes());
    }
    // A POST with a body still arrives whole.
    let response = sender
        .send_request(
            Request::post("http://localhost/post")
                .body(Full::new(Bytes::from_static(b"payload")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    drop(sender);
    let closed = tokio::time::timeout(Duration::from_secs(5), conn)
        .await
        .expect("the connection ended once the client was done")
        .unwrap();
    assert!(closed.is_ok(), "{closed:?}");
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn a_response_leaves_its_access_log_line_when_its_body_ends() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("access.log");
    let mut config = load(":0 {\n\tlog {\n\t\tformat console\n\t}\n\trespond \"hello there\"\n}\n");
    // The Caddyfile takes `output stdout|stderr|discard`; a file is set here.
    config.servers[0].sites[0].log = Some(std::sync::Arc::new(webfast_core::accesslog::AccessLog {
        output: webfast_core::accesslog::Output::parse("access.log", dir.path()),
        format: webfast_core::accesslog::Format::Console,
        privacy: Default::default(),
    }));
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let response = ask(&mut stream, "GET /logged?x=1 HTTP/1.1\r\nHost: example.test\r\n\r\n").await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    // The line is queued when the body has been sent; the writer thread takes it within its tick.
    let mut lines = String::new();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        webfast_core::accesslog::flush_all(Duration::from_secs(1));
        lines = std::fs::read_to_string(&log).unwrap_or_default();
        if !lines.is_empty() {
            break;
        }
    }
    let line = lines
        .lines()
        .next()
        .unwrap_or_else(|| panic!("no log line in {lines:?}"));
    assert!(
        line.contains(" HTTP/1.1 GET example.test /logged?x=1 200 11 "),
        "{line}"
    );
    running.shutdown(Duration::from_secs(1)).await;
}

/// `{http.request.id}` sent to the upstream is the id of the request's access log line; a client
/// that is no trusted proxy cannot give its own.
#[tokio::test]
async fn the_upstream_and_the_access_log_share_the_request_id() {
    // An upstream that answers with the `X-Request-Id` it was sent.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 4096];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
                let id = head
                    .lines()
                    .find_map(|l| l.strip_prefix("x-request-id: "))
                    .unwrap_or("")
                    .to_string();
                let answer = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{id}", id.len());
                let _ = stream.write_all(answer.as_bytes()).await;
            });
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("access.log");
    let mut config = load(&format!(
        ":0 {{\n\tlog\n\treverse_proxy {echo} {{\n\t\theader_up X-Request-Id {{http.request.id}}\n\t}}\n}}\n"
    ));
    config.servers[0].sites[0].log = Some(std::sync::Arc::new(webfast_core::accesslog::AccessLog {
        output: webfast_core::accesslog::Output::parse("access.log", dir.path()),
        format: webfast_core::accesslog::Format::Json,
        privacy: Default::default(),
    }));
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let response = ask(
        &mut stream,
        "GET /up HTTP/1.1\r\nHost: example.test\r\nX-Request-Id: chosen-by-the-client\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let sent = response.split("\r\n\r\n").nth(1).unwrap().to_string();
    assert_eq!(sent.len(), 32, "{sent:?}: the server's own id, not the client's");
    let mut lines = String::new();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        webfast_core::accesslog::flush_all(Duration::from_secs(1));
        lines = std::fs::read_to_string(&log).unwrap_or_default();
        if !lines.is_empty() {
            break;
        }
    }
    let line: serde_json::Value = serde_json::from_str(lines.lines().next().expect("a log line")).unwrap();
    assert_eq!(line["request"]["id"], sent.as_str(), "{line}");
    running.shutdown(Duration::from_secs(1)).await;
}
