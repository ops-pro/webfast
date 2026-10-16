//! WebSocket through `reverse_proxy`: the handshake reaches the upstream, a 101 joins the two
//! connections into a tunnel, any other answer passes as it is; tunnels count against the
//! connection limits and close when the server stops.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use webfast::server;

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

fn load(text: &str) -> webfast::config::Config {
    let file = webfast::caddyfile::parse_str(text, Path::new("Caddyfile")).unwrap();
    webfast::load_parsed(&file, 1 << 24).unwrap()
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

async fn echoed(stream: &mut TcpStream, message: &[u8]) {
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
