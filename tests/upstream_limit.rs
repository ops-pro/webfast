//! WEB_MAX_UPSTREAM_REQUESTS_PER_IP (feature `rate-limit`): a client's requests at the upstreams
//! at once. The next is refused with 429 (through `handle_errors`) until one of them ends; files
//! are not counted; a trusted proxy's own requests are not limited, the clients it names are.
#![cfg(feature = "rate-limit")]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::watch;
use webfast::server;

/// Reads up to the end of a message head, or `None` when the connection closes first.
async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> Option<String> {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            data.truncate(end);
            return Some(String::from_utf8(data).unwrap());
        }
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
    }
}

/// An upstream written by hand: /api/hold answers once `release` is set (counting the requests
/// it holds in `held`), anything else at once.
struct Upstream {
    addr: SocketAddr,
    held: Arc<AtomicUsize>,
    release: watch::Sender<bool>,
}

async fn upstream() -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let held = Arc::new(AtomicUsize::new(0));
    let (release, released) = watch::channel(false);
    let counter = held.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let (counter, mut released) = (counter.clone(), released.clone());
            tokio::spawn(async move {
                let Some(head) = read_head(&mut stream).await else {
                    return;
                };
                let body = if head.starts_with("GET /api/hold") {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let _ = released.wait_for(|go| *go).await;
                    "held"
                } else {
                    "quick"
                };
                let answer = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(answer.as_bytes()).await;
            });
        }
    });
    Upstream { addr, held, release }
}

/// One request on a connection of its own from the loopback address `from`: the status and body.
async fn get(from: &str, port: u16, path: &str, forwarded_for: Option<&str>) -> (u16, String) {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(format!("{from}:0").parse().unwrap()).unwrap();
    let mut stream = socket
        .connect(format!("127.0.0.1:{port}").parse().unwrap())
        .await
        .unwrap();
    let xff = forwarded_for
        .map(|ip| format!("X-Forwarded-For: {ip}\r\n"))
        .unwrap_or_default();
    let request = format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n{xff}\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();
    let text = String::from_utf8_lossy(&answer).into_owned();
    let status = text[9..12].parse().unwrap();
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

async fn until_held(upstream: &Upstream, n: usize) {
    let started = Instant::now();
    while upstream.held.load(Ordering::SeqCst) < n {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the upstream got {n} requests"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn a_client_has_so_many_requests_at_the_upstreams_at_once() {
    webfast::ratelimit::set_max_upstream_requests_per_ip(2);
    let upstream = upstream().await;
    let text = format!(
        "{{
	servers {{
		trusted_proxies static 127.0.0.2/32
	}}
}}
:0 {{
	reverse_proxy /api/* {}
	respond /page \"page\"
	handle_errors 429 {{
		respond \"busy ({{err.status_code}})\"
	}}
}}
",
        upstream.addr
    );
    let file = webfast::caddyfile::parse_str(&text, Path::new("Caddyfile")).unwrap();
    let config =
        webfast::load_parsed_reusing(&file, 1 << 24, None, None, webfast::watch::Watch::default(), &[]).unwrap();
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();
    let hold = |from: &'static str, xff: Option<&'static str>| tokio::spawn(get(from, port, "/api/hold", xff));

    assert_eq!(get("127.0.0.1", port, "/api/quick", None).await, (200, "quick".into()));
    // A client with two requests held at the upstream: the third is refused, a page is not.
    let mut holding = vec![hold("127.0.0.1", None), hold("127.0.0.1", None)];
    until_held(&upstream, 2).await;
    assert_eq!(
        get("127.0.0.1", port, "/api/quick", None).await,
        (429, "busy (429)".into())
    );
    assert_eq!(get("127.0.0.1", port, "/page", None).await, (200, "page".into()));

    // A trusted proxy's own requests are not limited; the clients it names each are.
    holding.push(hold("127.0.0.2", None));
    holding.push(hold("127.0.0.2", None));
    until_held(&upstream, 4).await;
    assert_eq!(get("127.0.0.2", port, "/api/quick", None).await, (200, "quick".into()));
    holding.push(hold("127.0.0.2", Some("203.0.113.5")));
    holding.push(hold("127.0.0.2", Some("203.0.113.5")));
    until_held(&upstream, 6).await;
    assert_eq!(get("127.0.0.2", port, "/api/quick", Some("203.0.113.5")).await.0, 429);
    assert_eq!(get("127.0.0.2", port, "/api/quick", Some("203.0.113.6")).await.0, 200);

    // Once the held responses end, their slots are free again.
    upstream.release.send(true).unwrap();
    for held in holding {
        assert_eq!(held.await.unwrap(), (200, "held".into()));
    }
    assert_eq!(get("127.0.0.1", port, "/api/quick", None).await, (200, "quick".into()));
    running.shutdown(Duration::from_secs(1)).await;
}
