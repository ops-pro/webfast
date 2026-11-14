//! WebSocket through `reverse_proxy`: the handshake reaches the upstream (another one when the
//! connection fails), a 101 joins the two connections into a tunnel, any other answer passes as it
//! is; tunnels count against the connection limits; the server ends them with a Close frame when
//! it stops, when `stream_timeout` runs out and after a reload with `stream_close_delay`; a
//! tunnel's close leaves a line in the access log; and WebSocket over HTTP/2 (RFC 8441) is the
//! same tunnel on a stream.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use webfast_core::server;

/// Reads up to the end of a message head; returns it and whatever came after it, or `None` when
/// the connection closes first.
async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> Option<(String, Vec<u8>)> {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = data.split_off(end + 4);
            return Some((String::from_utf8(data).unwrap(), rest));
        }
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
    }
}

/// A head's first line and its fields (names lowercased; a repeated field's values joined).
fn parse_head(head: &str) -> (String, HashMap<String, String>) {
    let mut lines = head.trim_end().split("\r\n");
    let first = lines.next().unwrap().to_string();
    let mut fields: HashMap<String, String> = HashMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').unwrap();
        fields
            .entry(name.trim().to_ascii_lowercase())
            .and_modify(|v| {
                v.push_str(", ");
                v.push_str(value.trim());
            })
            .or_insert_with(|| value.trim().to_string());
    }
    (first, fields)
}

/// An upstream written by hand: on /ws it switches protocols, telling what it was sent in
/// `X-Got-*` fields, then echoes every byte until the other side closes; on any other path it
/// refuses with 403.
async fn upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Some((head, rest)) = read_head(&mut stream).await else {
                    return;
                };
                let (line, fields) = parse_head(&head);
                let got = |name: &str| fields.get(name).cloned().unwrap_or_default();
                if !line.starts_with("GET /ws") {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\nnope",
                        )
                        .await;
                    return;
                }
                let answer = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
                     Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nX-Got-Line: {line}\r\n\
                     X-Got-Connection: {}\r\nX-Got-Upgrade: {}\r\nX-Got-Key: {}\r\nX-Got-Host: {}\r\n\
                     X-Got-Xff: {}\r\nX-Got-Up: {}\r\n\r\n",
                    got("connection"),
                    got("upgrade"),
                    got("sec-websocket-key"),
                    got("host"),
                    got("x-forwarded-for"),
                    got("x-up"),
                );
                stream.write_all(answer.as_bytes()).await.unwrap();
                stream.write_all(&rest).await.unwrap();
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    addr
}

fn load(text: &str) -> webfast_core::config::Config {
    let file = webfast_core::caddyfile::parse_str(text, Path::new("Caddyfile")).unwrap();
    webfast_core::load_parsed(&file, 1 << 24).unwrap()
}

fn caddyfile(upstream: SocketAddr) -> String {
    format!(
        ":0 {{
	header X-Site 1
	route {{
		respond /plain \"plain\"
		encode zstd gzip
		@proxied path /ws* /other*
		reverse_proxy @proxied {upstream} {{
			header_up X-Up yes
			header_down X-Down yes
		}}
	}}
}}
"
    )
}

const HANDSHAKE: &str = "Connection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\
                         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
                         Accept-Encoding: gzip, zstd\r\n";

/// Status line, fields, the connection, and what came after the head.
type Answer = (String, HashMap<String, String>, TcpStream, Vec<u8>);

/// Opens a connection and sends a handshake for `path`; returns the answer, or `None` when the
/// server closes the connection instead.
async fn try_handshake(port: u16, path: &str) -> Option<Answer> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: example.test\r\n{HANDSHAKE}\r\n");
    stream.write_all(request.as_bytes()).await.ok()?;
    let (head, rest) = tokio::time::timeout(Duration::from_secs(5), read_head(&mut stream))
        .await
        .expect("an answer to the handshake, or the connection closed")?;
    let (line, fields) = parse_head(&head);
    Some((line, fields, stream, rest))
}

/// Reads a body of `length` bytes, `rest` being what came with the head.
async fn body(stream: &mut TcpStream, mut rest: Vec<u8>, length: usize) -> Vec<u8> {
    let mut more = vec![0u8; length - rest.len()];
    stream.read_exact(&mut more).await.unwrap();
    rest.extend_from_slice(&more);
    rest
}

async fn handshake(port: u16, path: &str) -> Answer {
    try_handshake(port, path).await.expect("an answer to the handshake")
}

async fn echoed(stream: &mut (impl AsyncRead + tokio::io::AsyncWrite + Unpin), message: &[u8]) {
    stream.write_all(message).await.unwrap();
    let mut back = vec![0u8; message.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut back))
        .await
        .expect("the echo came back")
        .unwrap();
    assert_eq!(back, message);
}

/// Whether the server closes `stream` (rather than leaving it open) within `within`.
async fn closed(stream: &mut TcpStream, within: Duration) -> bool {
    let mut buf = [0u8; 64];
    matches!(
        tokio::time::timeout(within, stream.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

#[tokio::test]
async fn a_websocket_handshake_becomes_a_tunnel() {
    let running = server::start(load(&caddyfile(upstream().await))).await.unwrap();
    let port = running.bound[0].1.port();

    let (line, fields, mut stream, rest) = handshake(port, "/ws/chat?room=1").await;
    assert_eq!(line, "HTTP/1.1 101 Switching Protocols");
    assert!(rest.is_empty(), "nothing before the first message: {rest:?}");
    let field = |name: &str| fields.get(name).map(String::as_str).unwrap_or("");
    // The upstream's handshake answer reaches the client, and the switch is announced again.
    assert_eq!(field("upgrade"), "websocket");
    assert!(field("connection").eq_ignore_ascii_case("upgrade"));
    assert_eq!(field("sec-websocket-accept"), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    assert_eq!((field("x-site"), field("x-down")), ("1", "yes"));
    assert!(!fields.contains_key("content-encoding"), "a switch is not compressed");
    // What the upstream was sent: the switch alone (keep-alive is this hop's), the key, the
    // client's Host, the forwarded address, header_up.
    assert_eq!(field("x-got-line"), "GET /ws/chat?room=1 HTTP/1.1");
    assert_eq!(field("x-got-connection"), "upgrade");
    assert_eq!(field("x-got-upgrade"), "websocket");
    assert_eq!(field("x-got-key"), "dGhlIHNhbXBsZSBub25jZQ==");
    assert_eq!(field("x-got-host"), "example.test");
    assert_eq!(field("x-got-xff"), "127.0.0.1");
    assert_eq!(field("x-got-up"), "yes");

    // Bytes go both ways, as they are, however they are cut.
    echoed(&mut stream, b"\x81\x05hello").await;
    let large: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
    echoed(&mut stream, &large).await;

    // The client closes its side: the upstream sees it, and the tunnel ends.
    stream.shutdown().await.unwrap();
    assert!(closed(&mut stream, Duration::from_secs(5)).await);
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn an_upstream_that_does_not_switch_is_answered_as_usual() {
    let running = server::start(load(&caddyfile(upstream().await))).await.unwrap();
    let port = running.bound[0].1.port();

    let (line, fields, mut stream, rest) = handshake(port, "/other").await;
    assert_eq!(line, "HTTP/1.1 403 Forbidden");
    assert_eq!(fields.get("x-down").map(String::as_str), Some("yes"));
    assert_eq!(fields.get("content-length").map(String::as_str), Some("4"));
    assert_eq!(body(&mut stream, rest, 4).await, b"nope");

    // A handshake for a path that is not proxied is an ordinary request; the connection stays
    // HTTP and takes the next one.
    let (line, _, mut stream, rest) = handshake(port, "/plain").await;
    assert_eq!(line, "HTTP/1.1 200 OK");
    assert_eq!(body(&mut stream, rest, 5).await, b"plain");
    stream
        .write_all(b"GET /plain HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = read_head(&mut stream).await.expect("an answer on the same connection");
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");

    // An upstream that cannot be reached: 502.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    running.shutdown(Duration::from_secs(1)).await;
    let running = server::start(load(&caddyfile(dead_addr))).await.unwrap();
    let (line, ..) = handshake(running.bound[0].1.port(), "/ws").await;
    assert_eq!(line, "HTTP/1.1 502 Bad Gateway");
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn tunnels_keep_their_connection_place_and_close_when_the_server_stops() {
    let mut config = load(&caddyfile(upstream().await));
    config.servers[0].limits.max_per_ip = 1;
    // Far shorter than a tunnel may stay quiet: tunnels have no idle limit.
    config.servers[0].limits.idle = Duration::from_millis(300);
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();

    let (line, _, mut tunnel, _) = handshake(port, "/ws").await;
    assert_eq!(line, "HTTP/1.1 101 Switching Protocols");
    tokio::time::sleep(Duration::from_millis(600)).await;
    echoed(&mut tunnel, b"still here").await;

    // The tunnel holds this address's one place: another connection is refused.
    let mut second = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    second.write_all(b"GET /plain HTTP/1.1\r\n").await.unwrap();
    assert!(closed(&mut second, Duration::from_secs(2)).await, "refused");

    // Closed, it gives the place back.
    tunnel.shutdown().await.unwrap();
    assert!(closed(&mut tunnel, Duration::from_secs(5)).await);
    drop(tunnel);
    let started = Instant::now();
    let mut tunnel = loop {
        if let Some((line, _, stream, _)) = try_handshake(port, "/ws").await {
            assert_eq!(line, "HTTP/1.1 101 Switching Protocols");
            break stream;
        }
        assert!(started.elapsed() < Duration::from_secs(5), "the place came back");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    echoed(&mut tunnel, b"again").await;

    // The server stops: the tunnel is closed at once, not waited for until the grace ends.
    let started = Instant::now();
    running.shutdown(Duration::from_secs(10)).await;
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    assert!(closed(&mut tunnel, Duration::from_secs(2)).await);
}

/// The Close frame the server ends a tunnel with: 1001, going away.
const GOING_AWAY: &[u8] = &[0x88, 0x02, 0x03, 0xe9];

/// A text frame from a client (masked with a key of zeros, so the payload reads as it is).
fn client_frame(text: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x81, 0x80 | text.len() as u8, 0, 0, 0, 0];
    frame.extend_from_slice(text);
    frame
}

/// A site that proxies everything to `upstreams` with `options` in the `reverse_proxy` block.
fn proxying(upstreams: &str, options: &str) -> String {
    format!(":0 {{\n\treverse_proxy {upstreams} {{\n{options}\n\t}}\n}}\n")
}

/// An upstream that switches protocols on any path, sends `greeting` and then only listens: what
/// it was sent after the handshake comes on the channel when the other side closes.
async fn listening_upstream(greeting: &'static [u8]) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (heard, hearing) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let heard = heard.clone();
            tokio::spawn(async move {
                let Some((_, mut got)) = read_head(&mut stream).await else {
                    return;
                };
                let answer = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
                              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
                stream.write_all(answer.as_bytes()).await.unwrap();
                stream.write_all(greeting).await.unwrap();
                let _ = stream.read_to_end(&mut got).await;
                let _ = heard.send(got);
            });
        }
    });
    (addr, hearing)
}

/// Reads to the end of the stream (or for 5 s).
async fn rest_of(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut all = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut all))
        .await
        .expect("the stream ended")
        .unwrap();
    all
}

#[tokio::test]
async fn a_handshake_is_tried_on_another_upstream_when_the_connection_fails() {
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let live = upstream().await;
    let upstreams = format!("{dead_addr} {live}");

    // `first` always starts at the dead one; with retries the handshake goes on to the next.
    let options = "\t\tlb_policy first\n\t\tlb_retries 2\n\t\tlb_try_interval 10ms";
    let running = server::start(load(&proxying(&upstreams, options))).await.unwrap();
    let (line, _, mut stream, _) = handshake(running.bound[0].1.port(), "/ws").await;
    assert_eq!(line, "HTTP/1.1 101 Switching Protocols");
    echoed(&mut stream, b"\x81\x05hello").await;
    assert!(webfast_core::tunnel::open() >= 1, "the tunnel is counted while open");
    drop(stream);
    running.shutdown(Duration::from_secs(1)).await;

    // Without them it is answered 502, as a request is.
    let running = server::start(load(&proxying(&upstreams, "\t\tlb_policy first")))
        .await
        .unwrap();
    let (line, ..) = handshake(running.bound[0].1.port(), "/ws").await;
    assert_eq!(line, "HTTP/1.1 502 Bad Gateway");
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn a_stopping_server_says_going_away_to_both_sides() {
    let (addr, mut hearing) = listening_upstream(b"\x81\x02hi").await;
    let running = server::start(load(&proxying(&addr.to_string(), ""))).await.unwrap();
    let (line, _, mut stream, mut got) = handshake(running.bound[0].1.port(), "/ws").await;
    assert_eq!(line, "HTTP/1.1 101 Switching Protocols");
    // A whole frame each way: both sides are between frames.
    while got.len() < 4 {
        let mut more = [0u8; 4];
        let n = stream.read(&mut more).await.unwrap();
        assert!(n > 0, "the greeting");
        got.extend_from_slice(&more[..n]);
    }
    assert_eq!(got, b"\x81\x02hi");
    let said = client_frame(b"hello");
    stream.write_all(&said).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let started = Instant::now();
    let stopping = tokio::spawn(running.shutdown(Duration::from_secs(10)));
    // The client: a Close frame (1001), then the end.
    assert_eq!(rest_of(&mut stream).await, GOING_AWAY);
    drop(stream);
    stopping.await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    // The upstream: what the client said, then a Close frame masked as a client's are.
    let heard = hearing.recv().await.unwrap();
    assert_eq!(heard[..said.len()], said[..]);
    let close = &heard[said.len()..];
    assert_eq!(close.len(), 8, "{close:?}");
    assert_eq!(close[..2], [0x88, 0x82]);
    assert_eq!([close[6] ^ close[2], close[7] ^ close[3]], [0x03, 0xe9]);
}

#[tokio::test]
async fn stream_timeout_ends_a_tunnel() {
    let addr = upstream().await;
    let running = server::start(load(&proxying(&addr.to_string(), "\t\tstream_timeout 500ms")))
        .await
        .unwrap();
    let started = Instant::now();
    let (line, _, mut stream, _) = handshake(running.bound[0].1.port(), "/ws").await;
    assert_eq!(line, "HTTP/1.1 101 Switching Protocols");
    echoed(&mut stream, &client_frame(b"hello")).await;
    assert_eq!(rest_of(&mut stream).await, GOING_AWAY);
    let after = started.elapsed();
    assert!(
        after >= Duration::from_millis(450) && after < Duration::from_secs(4),
        "{after:?}"
    );
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn a_reload_closes_tunnels_only_with_stream_close_delay() {
    let addr = upstream().await;
    // Without it a tunnel outlives the reloads.
    let text = proxying(&addr.to_string(), "");
    let mut running = server::start(load(&text)).await.unwrap();
    let (_, _, mut stream, _) = handshake(running.bound[0].1.port(), "/ws").await;
    echoed(&mut stream, &client_frame(b"before")).await;
    running.reload(load(&text)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    echoed(&mut stream, &client_frame(b"after")).await;
    drop(stream);
    running.shutdown(Duration::from_secs(1)).await;

    // With it the tunnels of the configuration that was replaced are told to go, within the
    // delay; one opened after the reload stays.
    let text = proxying(&addr.to_string(), "\t\tstream_close_delay 300ms");
    let mut running = server::start(load(&text)).await.unwrap();
    let port = running.bound[0].1.port();
    let (_, _, mut old, _) = handshake(port, "/ws").await;
    echoed(&mut old, &client_frame(b"before")).await;
    running.reload(load(&text)).await.unwrap();
    let started = Instant::now();
    let (_, _, mut new, _) = handshake(port, "/ws").await;
    assert_eq!(rest_of(&mut old).await, GOING_AWAY);
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    tokio::time::sleep(Duration::from_millis(400)).await;
    echoed(&mut new, &client_frame(b"still here")).await;
    drop(new);
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn a_tunnel_leaves_a_second_access_log_line_when_it_closes() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("access.log");
    let mut config = load(&caddyfile(upstream().await));
    config.servers[0].sites[0].log = Some(std::sync::Arc::new(webfast_core::accesslog::AccessLog {
        output: webfast_core::accesslog::Output::parse("access.log", dir.path()),
        format: webfast_core::accesslog::Format::Json,
        privacy: Default::default(),
    }));
    let running = server::start(config).await.unwrap();
    let (line, _, mut stream, _) = handshake(running.bound[0].1.port(), "/ws/chat?room=1").await;
    assert_eq!(line, "HTTP/1.1 101 Switching Protocols");
    echoed(&mut stream, b"\x81\x05hello").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    stream.shutdown().await.unwrap();
    assert!(closed(&mut stream, Duration::from_secs(5)).await);

    let mut lines: Vec<serde_json::Value> = Vec::new();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        webfast_core::accesslog::flush_all(Duration::from_secs(1));
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        lines = text.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
        if lines.len() >= 2 {
            break;
        }
    }
    assert_eq!(lines.len(), 2, "{lines:?}");
    // The handshake, when it was answered; then the tunnel, when it closed.
    let (shake, tunnel) = (&lines[0], &lines[1]);
    assert_eq!(shake["msg"], "handled request");
    assert_eq!(shake["status"], 101);
    assert!(shake.get("closed_by").is_none());
    assert_eq!(tunnel["msg"], "closed tunnel");
    assert_eq!(tunnel["status"], 101);
    assert_eq!(tunnel["closed_by"], "client");
    assert_eq!(tunnel["bytes_read"], 7);
    assert_eq!(tunnel["size"], 7);
    assert_eq!(tunnel["request"]["uri"], "/ws/chat?room=1");
    assert_eq!(tunnel["request"]["id"], shake["request"]["id"], "the same request");
    let life = tunnel["duration"].as_f64().unwrap();
    assert!((0.25..10.0).contains(&life), "the tunnel's life: {life}");
    running.shutdown(Duration::from_secs(1)).await;
}

/// An upstream that answers every handshake with a switch to `protocol`.
async fn switching_to(protocol: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                if read_head(&mut stream).await.is_none() {
                    return;
                }
                let answer =
                    format!("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: {protocol}\r\n\r\n");
                let _ = stream.write_all(answer.as_bytes()).await;
                let mut rest = Vec::new();
                let _ = stream.read_to_end(&mut rest).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn a_switch_to_another_protocol_than_asked_for_is_refused() {
    // The protocol's name is compared without its case; another one is a bad gateway's answer.
    for (protocol, line) in [
        ("WebSocket", "HTTP/1.1 101 Switching Protocols"),
        ("h2c", "HTTP/1.1 502 Bad Gateway"),
        ("websocket, h2c", "HTTP/1.1 502 Bad Gateway"),
    ] {
        let addr = switching_to(protocol).await;
        let running = server::start(load(&proxying(&addr.to_string(), ""))).await.unwrap();
        let (answered, ..) = handshake(running.bound[0].1.port(), "/ws").await;
        assert_eq!(answered, line, "{protocol}");
        running.shutdown(Duration::from_secs(1)).await;
    }
}

#[tokio::test]
async fn a_reload_that_takes_an_upstream_out_closes_its_tunnels() {
    let (out, staying) = (upstream().await, upstream().await);
    let both = proxying(&format!("{out} {staying}"), "\t\tlb_policy first");
    let mut running = server::start(load(&both)).await.unwrap();
    let port = running.bound[0].1.port();
    // `first`: the tunnel is to the first upstream.
    let (_, _, mut tunnel, _) = handshake(port, "/ws").await;
    echoed(&mut tunnel, &client_frame(b"before")).await;

    // A reload that still names it leaves the tunnel alone, whatever else changes.
    let reordered = proxying(&format!("{staying} {out}"), "\t\tlb_policy first");
    running.reload(load(&reordered)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    echoed(&mut tunnel, &client_frame(b"still named")).await;
    let (_, _, mut other, _) = handshake(port, "/ws").await;
    echoed(&mut other, &client_frame(b"to the one that stays")).await;

    // One that no longer names it: told to go at once; the tunnel to the other stays.
    let started = Instant::now();
    running.reload(load(&proxying(&staying.to_string(), ""))).await.unwrap();
    assert_eq!(rest_of(&mut tunnel).await, GOING_AWAY);
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    echoed(&mut other, &client_frame(b"untouched")).await;
    drop(other);
    running.shutdown(Duration::from_secs(1)).await;
}

/// A site whose sockets only its own pages may open (recipes/websocket): a handshake that names
/// another origin is refused, one that names none (no browser) passes.
fn own_origin_only(upstream: SocketAddr) -> String {
    format!(
        ":0 {{
	@foreign {{
		header Upgrade *
		header Origin *
		not header Origin https://app.example.com https://www.example.com
	}}
	route {{
		respond @foreign 403
		reverse_proxy {upstream}
	}}
}}
"
    )
}

/// The status line of the answer to a handshake for /ws with `fields` added.
async fn handshake_with(port: u16, fields: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let request = format!("GET /ws HTTP/1.1\r\nHost: example.test\r\n{HANDSHAKE}{fields}\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let (head, _) = tokio::time::timeout(Duration::from_secs(5), read_head(&mut stream))
        .await
        .expect("an answer to the handshake")
        .expect("an answer, not a closed connection");
    parse_head(&head).0
}

#[tokio::test]
async fn a_handshake_from_another_origin_is_refused() {
    let running = server::start(load(&own_origin_only(upstream().await))).await.unwrap();
    let port = running.bound[0].1.port();
    let switched = "HTTP/1.1 101 Switching Protocols";
    assert_eq!(
        handshake_with(port, "Origin: https://app.example.com\r\n").await,
        switched
    );
    assert_eq!(
        handshake_with(port, "Origin: https://www.example.com\r\n").await,
        switched
    );
    assert_eq!(handshake_with(port, "").await, switched, "no browser: no Origin");
    for foreign in ["https://evil.example", "https://app.example.com.evil.example", "null"] {
        let line = handshake_with(port, &format!("Origin: {foreign}\r\n")).await;
        assert_eq!(line, "HTTP/1.1 403 Forbidden", "{foreign}");
    }
    running.shutdown(Duration::from_secs(1)).await;
}

/// `unhealthy_request_count` counts a tunnel until it closes: it bounds the tunnels (and the
/// requests) an upstream address holds at once.
#[tokio::test]
async fn an_upstream_takes_no_more_tunnels_than_its_request_count() {
    let addr = upstream().await;
    let options = "\t\tfail_duration 1s\n\t\tunhealthy_request_count 1";
    let running = server::start(load(&proxying(&addr.to_string(), options)))
        .await
        .unwrap();
    let port = running.bound[0].1.port();
    let (line, _, mut first, _) = handshake(port, "/ws").await;
    assert_eq!(line, "HTTP/1.1 101 Switching Protocols");
    echoed(&mut first, &client_frame(b"hello")).await;
    let (line, ..) = handshake(port, "/ws").await;
    assert_eq!(line, "HTTP/1.1 503 Service Unavailable");
    // Closed, the first one gives its count back.
    first.shutdown().await.unwrap();
    assert!(closed(&mut first, Duration::from_secs(5)).await);
    let started = Instant::now();
    loop {
        let (line, ..) = handshake(port, "/ws").await;
        if line == "HTTP/1.1 101 Switching Protocols" {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(5), "{line}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    running.shutdown(Duration::from_secs(1)).await;
}

mod over_http2 {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty};
    use hyper::client::conn::http2::SendRequest;
    use hyper::ext::Protocol;
    use hyper::{Method, Request, Response, StatusCode};
    use hyper_util::rt::{TokioExecutor, TokioIo};

    fn h2c(text: &str) -> String {
        format!("{{\n\tservers {{\n\t\tprotocols h1 h2c\n\t}}\n}}\n{text}")
    }

    /// CONNECT with `:protocol` (RFC 8441 §4).
    async fn connect(
        sender: &mut SendRequest<Empty<Bytes>>,
        path: &str,
        protocol: &'static str,
    ) -> Response<hyper::body::Incoming> {
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("http://example.test{path}"))
            .extension(Protocol::from_static(protocol))
            .body(Empty::new())
            .unwrap();
        sender.send_request(request).await.unwrap()
    }

    async fn get(sender: &mut SendRequest<Empty<Bytes>>, path: &str) -> (StatusCode, Bytes) {
        let request = Request::get(format!("http://example.test{path}"))
            .body(Empty::new())
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        let status = response.status();
        (status, response.into_body().collect().await.unwrap().to_bytes())
    }

    #[tokio::test]
    async fn websocket_is_a_stream_of_the_connection() {
        let mut config = load(&h2c(&caddyfile(upstream().await)));
        // Far shorter than the tunnel stays quiet: a connection with a tunnel is not idle.
        config.servers[0].limits.idle = Duration::from_millis(300);
        let running = server::start(config).await.unwrap();
        let tcp = TcpStream::connect(("127.0.0.1", running.bound[0].1.port()))
            .await
            .unwrap();
        let (mut sender, connection) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
            .await
            .unwrap();
        let connection = tokio::spawn(connection);
        // A request first: with its answer the server's settings (the offer) have arrived.
        assert_eq!(get(&mut sender, "/plain").await, (StatusCode::OK, Bytes::from("plain")));

        let response = connect(&mut sender, "/ws/chat?room=1", "websocket").await;
        // The switch as HTTP/2 says it: 200, and none of the HTTP/1.1 handshake's fields.
        assert_eq!(response.status(), StatusCode::OK);
        let field = |name: &str| {
            response
                .headers()
                .get(name)
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default()
        };
        for gone in ["connection", "upgrade", "sec-websocket-accept"] {
            assert!(!response.headers().contains_key(gone), "{gone}");
        }
        assert_eq!((field("x-site"), field("x-down")), ("1".to_string(), "yes".to_string()));
        // The upstream got the handshake it knows, with a key made here.
        assert_eq!(field("x-got-line"), "GET /ws/chat?room=1 HTTP/1.1");
        assert_eq!(field("x-got-connection"), "upgrade");
        assert_eq!(field("x-got-upgrade"), "websocket");
        assert_eq!(field("x-got-key").len(), 24, "{:?}", field("x-got-key"));
        assert_eq!(field("x-got-host"), "example.test");
        assert_eq!(field("x-got-up"), "yes");
        let mut tunnel = TokioIo::new(hyper::upgrade::on(response).await.unwrap());
        echoed(&mut tunnel, &client_frame(b"hello")).await;
        let large: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let mut frame = vec![0x82, 0x80 | 127];
        frame.extend_from_slice(&(large.len() as u64).to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame.extend_from_slice(&large);
        echoed(&mut tunnel, &frame).await;

        // Quiet for longer than `idle`: the connection stays, for the tunnel and for requests.
        tokio::time::sleep(Duration::from_millis(900)).await;
        echoed(&mut tunnel, &client_frame(b"still here")).await;
        assert_eq!(get(&mut sender, "/plain").await.0, StatusCode::OK);

        // What is no WebSocket is not answered as an open tunnel: a path that answers 200 is 501,
        // a refusal is the refusal, another protocol is not spoken.
        assert_eq!(connect(&mut sender, "/plain", "websocket").await.status(), 501);
        assert_eq!(connect(&mut sender, "/other", "websocket").await.status(), 403);
        assert_eq!(connect(&mut sender, "/ws", "connect-udp").await.status(), 501);
        echoed(&mut tunnel, &client_frame(b"and still")).await;

        // The server stops: the tunnel is told to go, and the connection ends.
        let started = Instant::now();
        let stopping = tokio::spawn(running.shutdown(Duration::from_secs(10)));
        assert_eq!(rest_of(&mut tunnel).await, GOING_AWAY);
        drop((tunnel, sender));
        stopping.await.unwrap();
        assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
        let _ = tokio::time::timeout(Duration::from_secs(2), connection).await;
    }

    /// WEB_RELOAD=drain closes the connections a reload left on the old configuration, and cuts
    /// what is still open on them after the grace; a tunnel is not a request under way: it stays,
    /// as a tunnel that took its whole connection does.
    #[tokio::test]
    async fn a_connection_a_reload_retires_keeps_its_tunnel() {
        let text = h2c(&caddyfile(upstream().await));
        let config = || {
            let mut config = load(&text);
            config.servers[0].reload = webfast_core::config::ReloadMode::Drain(Duration::from_millis(100));
            config.servers[0].limits.grace = Duration::from_millis(200);
            config
        };
        let mut running = server::start(config()).await.unwrap();
        let tcp = TcpStream::connect(("127.0.0.1", running.bound[0].1.port()))
            .await
            .unwrap();
        let (mut sender, connection) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
            .await
            .unwrap();
        tokio::spawn(connection);
        assert_eq!(get(&mut sender, "/plain").await.0, StatusCode::OK);
        let response = connect(&mut sender, "/ws", "websocket").await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut tunnel = TokioIo::new(hyper::upgrade::on(response).await.unwrap());
        echoed(&mut tunnel, &client_frame(b"before")).await;

        running.reload(config()).await.unwrap();
        // Past the window and the grace: the connection was asked to close, the tunnel goes on.
        tokio::time::sleep(Duration::from_millis(900)).await;
        echoed(&mut tunnel, &client_frame(b"after")).await;
        drop((tunnel, sender));
        running.shutdown(Duration::from_secs(1)).await;
    }

    async fn client(port: u16) -> SendRequest<Empty<Bytes>> {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (mut sender, connection) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
            .await
            .unwrap();
        tokio::spawn(connection);
        // A request first: with its answer the server's settings (the offer) have arrived.
        assert_eq!(get(&mut sender, "/plain").await.0, StatusCode::OK);
        sender
    }

    /// A tunnel is a connection of the limits whichever way it was opened: on a stream it takes
    /// a place next to its connection's, and gives it back when it closes.
    #[tokio::test]
    async fn a_tunnel_takes_a_connection_s_place() {
        let mut config = load(&h2c(&caddyfile(upstream().await)));
        config.servers[0].limits.max_per_ip = 3;
        let running = server::start(config).await.unwrap();
        let port = running.bound[0].1.port();
        let mut sender = client(port).await;
        // The connection, and two tunnels on it: the address's three places.
        let mut tunnels = Vec::new();
        for _ in 0..2 {
            let response = connect(&mut sender, "/ws", "websocket").await;
            assert_eq!(response.status(), StatusCode::OK);
            let mut tunnel = TokioIo::new(hyper::upgrade::on(response).await.unwrap());
            echoed(&mut tunnel, &client_frame(b"hello")).await;
            tunnels.push(tunnel);
        }
        // A third tunnel is refused, before any upstream is asked; so is another connection.
        assert_eq!(
            connect(&mut sender, "/ws", "websocket").await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        let mut other = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        other.write_all(b"GET /plain HTTP/1.1\r\n").await.unwrap();
        assert!(closed(&mut other, Duration::from_secs(2)).await, "refused");
        // Requests on the connection are not tunnels: they go on.
        assert_eq!(get(&mut sender, "/plain").await.0, StatusCode::OK);
        echoed(&mut tunnels[0], &client_frame(b"still here")).await;

        // A tunnel closed gives its place back.
        drop(tunnels.pop());
        let started = Instant::now();
        let response = loop {
            let response = connect(&mut sender, "/ws", "websocket").await;
            if response.status() == StatusCode::OK {
                break response;
            }
            assert!(started.elapsed() < Duration::from_secs(5), "{}", response.status());
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let mut tunnel = TokioIo::new(hyper::upgrade::on(response).await.unwrap());
        echoed(&mut tunnel, &client_frame(b"again")).await;
        drop((tunnel, tunnels, sender));
        running.shutdown(Duration::from_secs(1)).await;
    }

    /// The matchers see the handshake a CONNECT stands for: the origin check of an HTTP/1.1
    /// handshake holds for a WebSocket opened over HTTP/2.
    #[tokio::test]
    async fn the_origin_check_holds_over_http2() {
        let text = h2c(&own_origin_only(upstream().await))
            .replace("reverse_proxy", "respond /plain \"plain\"\n\t\treverse_proxy");
        let running = server::start(load(&text)).await.unwrap();
        let mut sender = client(running.bound[0].1.port()).await;
        let from = |origin: Option<&'static str>| {
            let mut request = Request::builder()
                .method(Method::CONNECT)
                .uri("http://example.test/ws")
                .extension(Protocol::from_static("websocket"));
            if let Some(origin) = origin {
                request = request.header("origin", origin);
            }
            request.body(Empty::<Bytes>::new()).unwrap()
        };
        let own = sender
            .send_request(from(Some("https://app.example.com")))
            .await
            .unwrap();
        assert_eq!(own.status(), StatusCode::OK);
        let none = sender.send_request(from(None)).await.unwrap();
        assert_eq!(none.status(), StatusCode::OK);
        let foreign = sender.send_request(from(Some("https://evil.example"))).await.unwrap();
        assert_eq!(foreign.status(), StatusCode::FORBIDDEN);
        drop((own, none, sender));
        running.shutdown(Duration::from_secs(1)).await;
    }
}
