//! `reverse_proxy` with several upstreams: the policies, the passive health settings, the
//! retries, and names resolved through `resolvers` (src/upstreams.rs, src/dns.rs).

use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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

/// An upstream that answers with its own port; `/hold` waits until released, `/fail` answers 500.
struct Upstream {
    addr: SocketAddr,
    release: watch::Sender<bool>,
}

async fn upstream() -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (release, released) = watch::channel(false);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut released = released.clone();
            tokio::spawn(async move {
                loop {
                    let Some(head) = read_head(&mut stream).await else {
                        return;
                    };
                    let (status, body) = if head.starts_with("GET /hold") {
                        let _ = released.wait_for(|go| *go).await;
                        ("200 OK", format!("port:{}", addr.port()))
                    } else if head.starts_with("GET /fail") {
                        ("500 Internal Server Error", format!("port:{}", addr.port()))
                    } else {
                        ("200 OK", format!("port:{}", addr.port()))
                    };
                    let answer = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if stream.write_all(answer.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Upstream { addr, release }
}

struct Answer {
    status: u16,
    headers: String,
    body: String,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.lines().find_map(|l| {
            l.split_once(':')
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim())
        })
    }

    fn port(&self) -> u16 {
        self.body
            .strip_prefix("port:")
            .unwrap_or_else(|| panic!("{} {}", self.status, self.body))
            .parse()
            .unwrap()
    }
}

/// One request on a connection of its own.
async fn get(port: u16, path: &str, headers: &[(&str, &str)]) -> Answer {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let extra: String = headers.iter().map(|(k, v)| format!("{k}: {v}\r\n")).collect();
    let request = format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n{extra}\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();
    let text = String::from_utf8_lossy(&answer).into_owned();
    let status = text[9..12].parse().unwrap();
    let (headers, body) = text.split_once("\r\n\r\n").unwrap();
    Answer {
        status,
        headers: headers.to_string(),
        body: body.to_string(),
    }
}

fn load(text: &str) -> webfast::config::Config {
    let file = webfast::caddyfile::parse_str(text, Path::new("Caddyfile")).unwrap();
    webfast::load_parsed(&file, 1 << 27).unwrap()
}

async fn start(text: &str) -> (server::Running, u16) {
    let running = server::start(load(text)).await.unwrap();
    let port = running.bound[0].1.port();
    (running, port)
}

#[tokio::test]
async fn round_robin_takes_turns_and_weights_give_shares() {
    let (a, b) = (upstream().await, upstream().await);
    let (running, port) = start(&format!(
        ":0 {{\n\treverse_proxy {} {} {{\n\t\tlb_policy round_robin\n\t}}\n}}\n",
        a.addr, b.addr
    ))
    .await;
    let mut ports = Vec::new();
    for _ in 0..4 {
        ports.push(get(port, "/", &[]).await.port());
    }
    assert_eq!(ports, vec![a.addr.port(), b.addr.port(), a.addr.port(), b.addr.port()]);
    running.shutdown(Duration::from_secs(1)).await;

    let (running, port) = start(&format!(
        ":0 {{\n\treverse_proxy {} {} {{\n\t\tlb_policy weighted_round_robin 3 1\n\t}}\n}}\n",
        a.addr, b.addr
    ))
    .await;
    let mut ports = Vec::new();
    for _ in 0..4 {
        ports.push(get(port, "/", &[]).await.port());
    }
    assert_eq!(ports, vec![a.addr.port(), a.addr.port(), a.addr.port(), b.addr.port()]);
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn a_dead_upstream_is_retried_past_and_then_marked_down() {
    let live = upstream().await;
    // A port nothing listens on: the connection is refused at once.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    // No retries: `first` sends to the dead one and answers 502.
    let (running, port) = start(&format!(
        ":0 {{\n\treverse_proxy {dead} {} {{\n\t\tlb_policy first\n\t}}\n}}\n",
        live.addr
    ))
    .await;
    assert_eq!(get(port, "/", &[]).await.status, 502);
    running.shutdown(Duration::from_secs(1)).await;

    // `lb_retries 1`: the next server is tried; the dead one is marked down after `max_fails`
    // failures, so later requests go to the live one without a retry.
    let (running, port) = start(&format!(
        ":0 {{\n\treverse_proxy {dead} {} {{\n\t\tlb_policy first\n\t\tlb_retries 1\n\t\tlb_try_interval 1ms\n\t\tfail_duration 30s\n\t\tmax_fails 1\n\t}}\n}}\n",
        live.addr
    ))
    .await;
    for _ in 0..3 {
        let answer = get(port, "/", &[]).await;
        assert_eq!(answer.status, 200);
        assert_eq!(answer.port(), live.addr.port());
    }
    running.shutdown(Duration::from_secs(1)).await;

    // Without retries, the first request fails and marks the server down; the rest go on.
    let (running, port) = start(&format!(
        ":0 {{\n\treverse_proxy {dead} {} {{\n\t\tlb_policy first\n\t\tfail_duration 30s\n\t}}\n}}\n",
        live.addr
    ))
    .await;
    assert_eq!(get(port, "/", &[]).await.status, 502);
    assert_eq!(get(port, "/", &[]).await.port(), live.addr.port());
    running.shutdown(Duration::from_secs(1)).await;

    // Every server down: 503.
    let (running, port) = start(&format!(
        ":0 {{\n\treverse_proxy {dead} {{\n\t\tfail_duration 30s\n\t}}\n}}\n"
    ))
    .await;
    assert_eq!(get(port, "/", &[]).await.status, 502);
    assert_eq!(get(port, "/", &[]).await.status, 503);
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn an_unhealthy_status_marks_a_server_down() {
    let (a, b) = (upstream().await, upstream().await);
    let (running, port) = start(&format!(
        ":0 {{\n\treverse_proxy {} {} {{\n\t\tlb_policy first\n\t\tfail_duration 30s\n\t\tunhealthy_status 5xx\n\t}}\n}}\n",
        a.addr, b.addr
    ))
    .await;
    let failed = get(port, "/fail", &[]).await;
    assert_eq!(
        (failed.status, failed.port()),
        (500, a.addr.port()),
        "passed on as it is"
    );
    assert_eq!(get(port, "/", &[]).await.port(), b.addr.port(), "the first is down");
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn least_conn_goes_where_fewer_requests_are_under_way() {
    let (a, b) = (upstream().await, upstream().await);
    let (running, port) = start(&format!(
        ":0 {{\n\treverse_proxy {} {} {{\n\t\tlb_policy least_conn\n\t}}\n}}\n",
        a.addr, b.addr
    ))
    .await;
    let holding = tokio::spawn(get(port, "/hold", &[]));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let busy = if a.release.is_closed() {
        unreachable!()
    } else {
        a.addr.port()
    };
    // Which one holds is random; the next four all go to the other.
    let first = get(port, "/", &[]).await.port();
    for _ in 0..3 {
        assert_eq!(get(port, "/", &[]).await.port(), first);
    }
    let _ = busy;
    a.release.send_replace(true);
    b.release.send_replace(true);
    let held = holding.await.unwrap();
    assert_eq!(held.status, 200);
    assert_ne!(held.port(), first, "the held request was at the other server");
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn a_cookie_keeps_a_client_on_its_server() {
    let (a, b) = (upstream().await, upstream().await);
    let (running, port) = start(&format!(
        ":0 {{\n\treverse_proxy {} {} {{\n\t\tlb_policy cookie sticky s3cret\n\t}}\n}}\n",
        a.addr, b.addr
    ))
    .await;
    let first = get(port, "/", &[]).await;
    let cookie = first
        .header("set-cookie")
        .expect("Set-Cookie on the response that chose");
    assert!(
        cookie.starts_with("sticky=") && cookie.ends_with("; Path=/; HttpOnly"),
        "{cookie}"
    );
    let pair = cookie.split(';').next().unwrap();
    for _ in 0..5 {
        let again = get(port, "/", &[("Cookie", pair)]).await;
        assert_eq!(again.port(), first.port());
        assert!(again.header("set-cookie").is_none(), "known: not set again");
    }
    running.shutdown(Duration::from_secs(1)).await;
}

/// A nameserver of the test's own, answering every A query with `ip` while `known` is set, and
/// SERVFAIL otherwise (a container that is not up yet).
fn nameserver(ip: [u8; 4], known: Arc<AtomicBool>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            let question = &buf[12..n];
            let qtype = u16::from_be_bytes([buf[n - 4], buf[n - 3]]);
            let answers = qtype == 1 && known.load(Ordering::SeqCst);
            let flags: u16 = if known.load(Ordering::SeqCst) { 0x8180 } else { 0x8182 };
            let mut msg = Vec::new();
            msg.extend_from_slice(&buf[..2]);
            msg.extend_from_slice(&flags.to_be_bytes());
            msg.extend_from_slice(&1u16.to_be_bytes());
            msg.extend_from_slice(&u16::from(answers).to_be_bytes());
            msg.extend_from_slice(&[0; 4]);
            msg.extend_from_slice(question);
            if answers {
                msg.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
                msg.extend_from_slice(&ip);
            }
            let _ = socket.send_to(&msg, from);
        }
    });
    addr
}

#[tokio::test]
async fn a_name_is_resolved_through_the_resolvers_before_the_start() {
    let live = upstream().await;
    let ns = nameserver([127, 0, 0, 1], Arc::new(AtomicBool::new(true)));
    let (running, port) = start(&format!(
        ":0 {{\n\treverse_proxy app.test:{} {{\n\t\ttransport http {{\n\t\t\tresolvers {ns}\n\t\t}}\n\t}}\n}}\n",
        live.addr.port()
    ))
    .await;
    assert_eq!(get(port, "/", &[]).await.port(), live.addr.port());
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn a_name_that_does_not_resolve_yet_gets_502_until_it_does() {
    let live = upstream().await;
    let known = Arc::new(AtomicBool::new(false));
    let ns = nameserver([127, 0, 0, 1], known.clone());
    // The start goes on without the name (a Compose stack where the container is not up yet).
    let (running, port) = start(&format!(
        ":0 {{\n\treverse_proxy /api/* app.test:{} {{\n\t\ttransport http {{\n\t\t\tresolvers {ns}\n\t\t}}\n\t}}\n\trespond /site \"site\"\n}}\n",
        live.addr.port()
    ))
    .await;
    let first = get(port, "/api/x", &[]).await;
    assert_eq!(first.status, 502, "body: {}", first.body);
    assert_eq!(
        get(port, "/site", &[]).await.body,
        "site",
        "the rest of the site serves"
    );
    // The name appears: the DNS thread finds it on one of its tries (1 s, then 2, then 4…).
    known.store(true, Ordering::SeqCst);
    let started = Instant::now();
    loop {
        let answer = get(port, "/api/x", &[]).await;
        if answer.status == 200 {
            assert_eq!(answer.port(), live.addr.port());
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "still 502 after the name resolves"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    running.shutdown(Duration::from_secs(1)).await;
}
