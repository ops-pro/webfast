//! The test harness (cargo feature `test-harness`): a server booted from a Caddyfile text with a
//! composition of modules, and raw HTTP/1.1 to it on a TCP connection — what the integration
//! tests of a module crate need (docs/modules.md, "Testing"; the tests of webfast-modules' crates,
//! https://github.com/ops-pro/webfast-modules, are written on it).
//!
//! The server listens on `:0` ports of the loopback (the Caddyfile says `:0`); the composition is
//! registered once per process, so every test of a binary composes the same set, as the server
//! binary does.

use crate::config::Config;
use crate::module::{Checks, Composition, Inspectors};
use crate::server::{self, Running};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A running server of a test.
pub struct Server {
    pub running: Running,
    /// Where to reach the first port (TCP): the IPv4 loopback when it listens on every address.
    pub addr: SocketAddr,
}

impl Server {
    /// The address to connect to for the configured `port` (`:0` ports are bound to a free one):
    /// the IPv4 loopback for a port bound on every address, so the client is `127.0.0.1`.
    pub fn addr_of(&self, port: u16) -> Option<SocketAddr> {
        self.running
            .bound
            .iter()
            .find(|(p, _, _)| *p == port)
            .map(|(_, a, _)| loopback(*a))
    }

    /// A request on a new connection to the first port (`request`).
    pub async fn send(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Response {
        request(self.addr, method, path, headers, body).await
    }

    /// A GET on a new connection to the first port.
    pub async fn get(&self, path: &str, headers: &[(&str, &str)]) -> Response {
        self.send("GET", path, headers, b"").await
    }

    /// Stops the server, giving the connections a second.
    pub async fn shutdown(self) {
        self.running.shutdown(Duration::from_secs(1)).await;
    }
}

/// Boots a server from `caddyfile` with the modules of `composition` (registered once per
/// process: a second composition is ignored, so one binary's tests compose alike), after `prepare`
/// saw the loaded configuration — where a test puts a module's state into `config.modules`, as
/// `Module::load` would from its file.
pub async fn start<C: Checks, I: Inspectors>(
    composition: Composition<C, I>,
    caddyfile: &str,
    prepare: impl FnOnce(&mut Config),
) -> Server {
    crate::module::install(composition).expect("a composition the core accepts");
    let file = crate::caddyfile::parse_str(caddyfile, Path::new("Caddyfile")).expect("a Caddyfile that parses");
    let mut config = crate::load_parsed(&file, 1 << 24).expect("a configuration that loads");
    prepare(&mut config);
    let running = server::start(config).await.expect("a server that starts");
    let addr = loopback(running.bound[0].1);
    Server { running, addr }
}

/// `addr` with the IPv4 loopback for an unspecified address (`[::]`, `0.0.0.0`): what the tests
/// connect to, so the server sees the client as `127.0.0.1`.
fn loopback(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, addr.port()))
    } else {
        addr
    }
}

/// A site directory with `files` (`path` relative to the root, and the content), kept until
/// dropped.
pub fn site(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("a temporary directory");
    for (path, content) in files {
        let path = dir.path().join(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("the file's directory");
        }
        std::fs::write(path, content).expect("the file written");
    }
    dir
}

/// A response as read off the connection.
#[derive(Debug)]
pub struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Response {
    /// A header's value, `""` when absent.
    pub fn header(&self, name: &str) -> &str {
        self.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
    }

    /// The body as text (lossily).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// One HTTP/1.1 request on a new connection to `addr`, `Connection: close`, and its response read
/// to the end. `Host: 127.0.0.1` unless `headers` set one; a `Content-Length` for the body.
pub async fn request(addr: SocketAddr, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Response {
    let mut text = format!("{method} {path} HTTP/1.1\r\n");
    if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) {
        text.push_str("Host: 127.0.0.1\r\n");
    }
    for (name, value) in headers {
        text.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty() || method == "POST" || method == "PUT" {
        text.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    text.push_str("Connection: close\r\n\r\n");
    let mut bytes = text.into_bytes();
    bytes.extend_from_slice(body);
    let got = raw(addr, &bytes).await;
    parse(&got).unwrap_or_else(|| panic!("not an HTTP/1.1 response: {:?}", String::from_utf8_lossy(&got)))
}

/// `bytes` written to a new connection to `addr`, and everything the server sends until it closes
/// the connection (within 5 s): empty when it answered nothing (a 444).
pub async fn raw(addr: SocketAddr, bytes: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).await.expect("a connection to the server");
    stream.write_all(bytes).await.expect("the request written");
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut got))
        .await
        .expect("the server closes the connection")
        .expect("the response read");
    got
}

/// The status line, the headers and the body of an HTTP/1.1 response; the body as the bytes after
/// the head (the connection was closed after it), chunked transfer decoded.
fn parse(bytes: &[u8]) -> Option<Response> {
    let head_end = bytes.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&bytes[..head_end]).ok()?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next()?;
    let status = status_line.strip_prefix("HTTP/1.1 ")?.get(..3)?.parse::<u16>().ok()?;
    let status = StatusCode::from_u16(status).ok()?;
    let mut headers = HeaderMap::new();
    let mut chunked = false;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        let name = HeaderName::from_bytes(name.trim().as_bytes()).ok()?;
        let value = HeaderValue::from_str(value.trim()).ok()?;
        if name == http::header::TRANSFER_ENCODING && value.as_bytes().eq_ignore_ascii_case(b"chunked") {
            chunked = true;
        }
        headers.append(name, value);
    }
    let rest = &bytes[head_end + 4..];
    let body = if chunked { dechunk(rest)? } else { rest.to_vec() };
    Some(Response { status, headers, body })
}

fn dechunk(mut rest: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = rest.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&rest[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Some(body);
        }
        body.extend_from_slice(rest.get(..size)?);
        rest = rest.get(size + 2..)?;
    }
}

/// The first line of the file at `path` that `matches`, within `within` (a log writer batches its
/// lines); panics with the file's contents when none comes.
pub async fn wait_for_line(path: &Path, within: Duration, matches: impl Fn(&str) -> bool) -> String {
    let started = Instant::now();
    loop {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Some(line) = text.lines().find(|l| matches(l))
        {
            return line.to_string();
        }
        assert!(
            started.elapsed() < within,
            "no matching line in {}: {:?}",
            path.display(),
            std::fs::read_to_string(path)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
