//! `reverse_proxy` to upstreams over TLS (src/upstream_tls.rs): `https://` upstreams and
//! `transport http { tls… }`, against an upstream of the test's own with a certificate from a CA
//! made here — what is verified and for which name, the Host the upstream gets, the client's
//! certificate, `tls_except_ports`, the pool, and WebSocket through the same TLS. And `versions`
//! (src/upstream_link.rs): HTTP/2 when the upstream takes it in the handshake, HTTP/2 without TLS
//! (`h2c`), and HTTP/3, against upstreams that speak them.

use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use webfast_core::server;

/// A certificate authority of the test's own, a server certificate for `backend.test` and
/// 127.0.0.1, and a client certificate; `dir` holds `ca.pem`, `client.pem` and `client.key`.
struct Pki {
    dir: tempfile::TempDir,
    server: Arc<rustls::ServerConfig>,
}

impl Pki {
    fn new() -> Pki {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca, ca_key);

        let server_key = KeyPair::generate().unwrap();
        let server_cert = CertificateParams::new(vec!["backend.test".to_string(), "127.0.0.1".to_string()])
            .unwrap()
            .signed_by(&server_key, &issuer)
            .unwrap();
        let client_key = KeyPair::generate().unwrap();
        let client_cert = CertificateParams::new(vec!["webfast.test".to_string()])
            .unwrap()
            .signed_by(&client_key, &issuer)
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ca.pem"), ca_cert.pem()).unwrap();
        std::fs::write(dir.path().join("client.pem"), client_cert.pem()).unwrap();
        std::fs::write(dir.path().join("client.key"), client_key.serialize_pem()).unwrap();

        // The upstream asks for a client certificate and goes on without one: it tells which.
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_cert.der().clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .allow_unauthenticated()
            .build()
            .unwrap();
        let chain: Vec<CertificateDer<'static>> = vec![server_cert.der().clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));
        let server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)
            .unwrap();
        Pki {
            dir,
            server: Arc::new(server),
        }
    }

    /// The upstream's TLS, offering `protocols` in the handshake (ALPN).
    fn offering(&self, protocols: &[&[u8]]) -> rustls::ServerConfig {
        let mut config = (*self.server).clone();
        config.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
        config
    }

    /// A file of `dir`, as a Caddyfile takes a path.
    fn file(&self, name: &str) -> String {
        self.dir.path().join(name).display().to_string().replace('\\', "/")
    }
}

/// Reads up to the end of a message head; `None` when the connection closes first.
async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> Option<String> {
    let mut data = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        if data.ends_with(b"\r\n\r\n") {
            return Some(String::from_utf8(data).unwrap());
        }
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(_) => data.push(buf[0]),
        }
    }
}

fn field<'h>(head: &'h str, name: &str) -> &'h str {
    head.lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim())
        })
        .unwrap_or("")
}

/// An upstream over TLS, or in plain HTTP without `tls`. It answers every request with what it
/// saw — the name the handshake asked for, whether the client showed a certificate, the Host,
/// X-Forwarded-Host, and how many connections it has accepted — and on `/ws` switches protocols
/// and echoes. Connections are kept for the next request.
async fn upstream(tls: Option<Arc<rustls::ServerConfig>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (tls, connections) = (tls.clone(), connections.clone());
            tokio::spawn(async move {
                let nth = connections.fetch_add(1, Ordering::SeqCst) + 1;
                match tls {
                    Some(config) => {
                        let Ok(stream) = tokio_rustls::TlsAcceptor::from(config).accept(tcp).await else {
                            return;
                        };
                        let (_, session) = stream.get_ref();
                        let sni = session.server_name().unwrap_or("-").to_string();
                        let cert = if session.peer_certificates().is_some_and(|c| !c.is_empty()) {
                            "yes"
                        } else {
                            "no"
                        };
                        serve(stream, format!("tls=yes sni={sni} cert={cert}"), nth).await;
                    }
                    None => serve(tcp, "tls=no".to_string(), nth).await,
                }
            });
        }
    });
    addr
}

async fn serve(mut stream: impl AsyncRead + tokio::io::AsyncWrite + Unpin, seen: String, nth: usize) {
    while let Some(head) = read_head(&mut stream).await {
        if head.starts_with("GET /ws") {
            let answer = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
            stream.write_all(answer.as_bytes()).await.unwrap();
            let (mut reader, mut writer) = tokio::io::split(stream);
            let _ = tokio::io::copy(&mut reader, &mut writer).await;
            return;
        }
        let body = format!(
            "{seen} host={} xfh={} connection={nth}",
            field(&head, "host"),
            field(&head, "x-forwarded-host")
        );
        let answer = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        if stream.write_all(answer.as_bytes()).await.is_err() {
            return;
        }
    }
}

fn try_load(text: &str) -> Result<webfast_core::config::Config, String> {
    let file = webfast_core::caddyfile::parse_str(text, Path::new("Caddyfile")).map_err(|e| format!("{e:#}"))?;
    webfast_core::load_parsed(&file, 1 << 24).map_err(|e| format!("{e:#}"))
}

/// A site that proxies everything to `upstreams` with `options` in the `reverse_proxy` block.
fn proxying(upstreams: &str, options: &str) -> String {
    format!(":0 {{\n\treverse_proxy {upstreams} {{\n{options}\n\t}}\n}}\n")
}

async fn start(text: &str) -> (server::Running, u16) {
    let running = server::start(try_load(text).unwrap_or_else(|e| panic!("{e}\n{text}")))
        .await
        .unwrap();
    let port = running.bound[0].1.port();
    (running, port)
}

/// One request on a connection of its own: the status and the body.
async fn get(port: u16, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();
    let text = String::from_utf8_lossy(&answer).into_owned();
    let (_, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    (text[9..12].parse().unwrap(), body.to_string())
}

/// A nameserver of the test's own: every A query is answered with 127.0.0.1.
fn nameserver() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            let question = &buf[12..n];
            let answers = u16::from_be_bytes([buf[n - 4], buf[n - 3]]) == 1;
            let mut msg = Vec::new();
            msg.extend_from_slice(&buf[..2]);
            msg.extend_from_slice(&0x8180u16.to_be_bytes());
            msg.extend_from_slice(&1u16.to_be_bytes());
            msg.extend_from_slice(&u16::from(answers).to_be_bytes());
            msg.extend_from_slice(&[0; 4]);
            msg.extend_from_slice(question);
            if answers {
                msg.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1]);
            }
            let _ = socket.send_to(&msg, from);
        }
    });
    addr
}

#[tokio::test]
async fn an_https_upstream_is_verified_and_named_as_its_host() {
    let pki = Pki::new();
    let addr = upstream(Some(pki.server.clone())).await;
    let trusted = format!(
        "\t\ttransport http {{\n\t\t\ttls_trusted_ca_certs {}\n\t\t}}",
        pki.file("ca.pem")
    );

    // Verified against the authority given, for the address it is written with (no name asked
    // for: an address is not one); the Host is the upstream as written, the client's is in
    // X-Forwarded-Host; the next request takes the connection the first one made.
    let (running, port) = start(&proxying(&format!("https://{addr}"), &trusted)).await;
    let (status, body) = get(port, "/").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        format!("tls=yes sni=- cert=no host={addr} xfh=example.test connection=1")
    );
    let (_, again) = get(port, "/again").await;
    assert!(again.ends_with("connection=1"), "the pooled connection: {again}");
    running.shutdown(Duration::from_secs(1)).await;

    // `tls` in the transport, without a scheme: the same.
    let options = format!(
        "\t\ttransport http {{\n\t\t\ttls\n\t\t\ttls_trust_pool file {}\n\t\t}}",
        pki.file("ca.pem")
    );
    let (running, port) = start(&proxying(&addr.to_string(), &options)).await;
    let (status, body) = get(port, "/").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("tls=yes "), "{body}");
    running.shutdown(Duration::from_secs(1)).await;

    // An authority nobody trusts here (the built-in roots do not know the test's): 502.
    let (running, port) = start(&proxying(&format!("https://{addr}"), "")).await;
    assert_eq!(get(port, "/").await.0, 502);
    running.shutdown(Duration::from_secs(1)).await;

    // … unless told not to look.
    let insecure = "\t\ttransport http {\n\t\t\ttls_insecure_skip_verify\n\t\t}";
    let (running, port) = start(&proxying(&format!("https://{addr}"), insecure)).await;
    let (status, body) = get(port, "/").await;
    assert_eq!(status, 200, "{body}");
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn the_name_asked_for_and_the_host_can_be_set() {
    let pki = Pki::new();
    let addr = upstream(Some(pki.server.clone())).await;
    let with = |more: &str| {
        format!(
            "{more}\t\ttransport http {{\n\t\t\ttls_trusted_ca_certs {}\n\t\t\ttls_server_name NAME\n\t\t}}",
            pki.file("ca.pem")
        )
    };
    // `tls_server_name`: asked for in the handshake, and what the certificate is verified for.
    let named = with("").replace("NAME", "backend.test");
    let (running, port) = start(&proxying(&format!("https://{addr}"), &named)).await;
    let (status, body) = get(port, "/").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("tls=yes sni=backend.test "), "{body}");
    running.shutdown(Duration::from_secs(1)).await;

    // A name the certificate is not for: refused.
    let other = with("").replace("NAME", "other.test");
    let (running, port) = start(&proxying(&format!("https://{addr}"), &other)).await;
    assert_eq!(get(port, "/").await.0, 502);
    running.shutdown(Duration::from_secs(1)).await;

    // `header_up` comes after the Host the proxy sets: the client's own back, or any other.
    let kept = with("\t\theader_up Host {hostport}\n").replace("NAME", "backend.test");
    let (running, port) = start(&proxying(&format!("https://{addr}"), &kept)).await;
    let (_, body) = get(port, "/").await;
    assert!(body.contains(" host=example.test xfh=example.test "), "{body}");
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn an_upstream_written_by_name_is_asked_for_by_that_name() {
    let pki = Pki::new();
    let addr = upstream(Some(pki.server.clone())).await;
    let options = format!(
        "\t\ttransport http {{\n\t\t\tresolvers {}\n\t\t\ttls_trusted_ca_certs {}\n\t\t}}",
        nameserver(),
        pki.file("ca.pem")
    );
    let upstream = format!("https://backend.test:{}", addr.port());
    let (running, port) = start(&proxying(&upstream, &options)).await;
    // The name resolves in the background: until it has, 502.
    let mut answer = (0, String::new());
    for _ in 0..100 {
        answer = get(port, "/").await;
        if answer.0 == 200 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        answer.1,
        format!(
            "tls=yes sni=backend.test cert=no host=backend.test:{} xfh=example.test connection=1",
            addr.port()
        )
    );
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn a_client_certificate_is_shown_and_some_ports_stay_plain() {
    let pki = Pki::new();
    let secure = upstream(Some(pki.server.clone())).await;
    let plain = upstream(None).await;
    let options = format!(
        "\t\tlb_policy first\n\t\ttransport http {{\n\t\t\ttls_trusted_ca_certs {}\n\t\t\ttls_client_auth {} {}\n\t\t\ttls_except_ports {}\n\t\t}}",
        pki.file("ca.pem"),
        pki.file("client.pem"),
        pki.file("client.key"),
        plain.port()
    );
    // The first upstream: over TLS, with the certificate.
    let (running, port) = start(&proxying(&format!("{secure} {plain}"), &options)).await;
    let (status, body) = get(port, "/").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("tls=yes sni=- cert=yes "), "{body}");
    running.shutdown(Duration::from_secs(1)).await;

    // The one on the excepted port: plain HTTP, though the transport has TLS; its Host is still
    // the upstream as written.
    let (running, port) = start(&proxying(&format!("{plain} {secure}"), &options)).await;
    let (status, body) = get(port, "/").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, format!("tls=no host={plain} xfh=example.test connection=1"));
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn websocket_goes_through_the_same_tls() {
    let pki = Pki::new();
    let addr = upstream(Some(pki.server.clone())).await;
    let options = format!(
        "\t\ttransport http {{\n\t\t\ttls_trusted_ca_certs {}\n\t\t}}",
        pki.file("ca.pem")
    );
    let handshake = |port: u16| async move {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let request = "GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
                       Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        stream.write_all(request.as_bytes()).await.unwrap();
        let head = tokio::time::timeout(Duration::from_secs(5), read_head(&mut stream))
            .await
            .expect("an answer to the handshake")
            .expect("an answer, not a closed connection");
        (head, stream)
    };
    let (running, port) = start(&proxying(&format!("https://{addr}"), &options)).await;
    let (head, mut stream) = handshake(port).await;
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    let message: Vec<u8> = (0..50_000u32).map(|i| i as u8).collect();
    stream.write_all(&message).await.unwrap();
    let mut back = vec![0u8; message.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut back))
        .await
        .expect("the echo came back")
        .unwrap();
    assert_eq!(back, message);
    drop(stream);
    running.shutdown(Duration::from_secs(1)).await;

    // An upstream whose certificate is not trusted: no tunnel.
    let (running, port) = start(&proxying(&format!("https://{addr}"), "")).await;
    let (head, _) = handshake(port).await;
    assert!(head.starts_with("HTTP/1.1 502 "), "{head}");
    running.shutdown(Duration::from_secs(1)).await;
}

#[test]
fn what_the_caddyfile_may_say_of_tls_to_an_upstream() {
    let loads = |upstreams: &str, options: &str| try_load(&proxying(upstreams, options)).map(|_| ());
    let transport = |lines: &str| format!("\t\ttransport http {{\n{lines}\n\t\t}}");
    // `https://` with and without a port (443), a name or an address; `http://` as none.
    for upstreams in [
        "https://backend.test",
        "https://backend.test:8443",
        "https://10.0.0.5:8443 https://10.0.0.6:8443",
        "https://backend.test 10.0.0.5:8443",
    ] {
        loads(upstreams, "").unwrap_or_else(|e| panic!("{upstreams}: {e}"));
    }
    // The schemes of one proxy cannot differ: the scheme sets the transport of them all.
    let mixed = loads("https://backend.test http://10.0.0.5:8080", "").unwrap_err();
    assert!(mixed.contains("cannot be mixed"), "{mixed}");
    let other = loads("ftp://10.0.0.5:8080", "").unwrap_err();
    assert!(other.contains("ftp:// upstreams are not supported"), "{other}");
    let browsers = loads("wss://10.0.0.5:8080", "").unwrap_err();
    assert!(browsers.contains("use https://"), "{browsers}");
    // A scheme without TLS and a transport with it contradict each other.
    let plain = loads("http://10.0.0.5:8080", &transport("\t\t\ttls")).unwrap_err();
    assert!(plain.contains("written without TLS"), "{plain}");
    // The options are read, their files too: one that is not there stops the start.
    loads(
        "10.0.0.5:8443",
        &transport(
            "\t\t\ttls\n\t\t\ttls_server_name backend.test\n\t\t\ttls_timeout 5s\n\t\t\ttls_except_ports 8080 8081",
        ),
    )
    .unwrap();
    let missing = loads(
        "10.0.0.5:8443",
        &transport("\t\t\ttls_trusted_ca_certs /nonexistent/ca.pem"),
    )
    .unwrap_err();
    assert!(missing.contains("/nonexistent/ca.pem"), "{missing}");
    for (lines, says) in [
        ("\t\t\ttls yes", "tls takes no arguments"),
        (
            "\t\t\ttls_server_name {http.request.host}",
            "placeholders are not allowed",
        ),
        (
            "\t\t\ttls_client_auth backend.test",
            "a certificate file and its key file",
        ),
        ("\t\t\ttls_trust_pool inline abc", "only `file <pem files…>`"),
        ("\t\t\ttls_except_ports https", "port numbers"),
        ("\t\t\ttls_curves x25519", "unsupported option"),
        ("\t\t\ttls_renegotiation once", "unsupported option"),
    ] {
        let error = loads("10.0.0.5:8443", &transport(lines)).unwrap_err();
        assert!(error.contains(says), "{lines}: {error}");
    }
}

// ---------------------------------------------------------------------------------------------
// `versions`: HTTP/2 over TLS, HTTP/2 without it (h2c), HTTP/3.

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};

/// What an upstream of the tests below answers: the request's body back on `/echo`, else what it
/// saw of the request.
fn seen(
    how: &str,
    version: http::Version,
    uri: &http::Uri,
    headers: &http::HeaderMap,
    body: Bytes,
    nth: usize,
) -> Bytes {
    if uri.path() == "/echo" {
        return body;
    }
    let field = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("-");
    // The host a request is for: its `:authority` over HTTP/2 and HTTP/3, its Host before them.
    let host = uri
        .authority()
        .map_or_else(|| field("host").to_string(), ToString::to_string);
    format!(
        "{how} version={version:?} host={host} xfh={} body={} connection={nth}",
        field("x-forwarded-host"),
        body.len()
    )
    .into()
}

/// An upstream that speaks HTTP/1.1 and HTTP/2 (hyper), over TLS with `tls`, else without (HTTP/2
/// from the first byte, as h2c is). `once`: every connection is told to finish after its first
/// answer, as an upstream that restarts does.
async fn upstream_h2(tls: Option<rustls::ServerConfig>, once: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let tls = tls.map(|config| tokio_rustls::TlsAcceptor::from(Arc::new(config)));
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let nth = connections.fetch_add(1, Ordering::SeqCst) + 1;
            let tls = tls.clone();
            tokio::spawn(async move {
                match tls {
                    Some(acceptor) => {
                        if let Ok(stream) = acceptor.accept(tcp).await {
                            let sni = stream.get_ref().1.server_name().unwrap_or("-").to_string();
                            serve_h2(TokioIo::new(stream), format!("tls=yes sni={sni}"), nth, once).await;
                        }
                    }
                    None => serve_h2(TokioIo::new(tcp), "tls=no".to_string(), nth, once).await,
                }
            });
        }
    });
    addr
}

async fn serve_h2<T>(io: T, how: String, nth: usize, once: bool)
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let answered = Arc::new(tokio::sync::Notify::new());
    let said = answered.clone();
    let service = hyper::service::service_fn(move |request: http::Request<hyper::body::Incoming>| {
        let (how, said) = (how.clone(), said.clone());
        async move {
            let (parts, body) = request.into_parts();
            let body = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
            let text = seen(&how, parts.version, &parts.uri, &parts.headers, body, nth);
            if once {
                said.notify_one();
            }
            Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(text)))
        }
    });
    let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    let connection = builder.serve_connection(io, service);
    tokio::pin!(connection);
    let mut finishing = false;
    loop {
        tokio::select! {
            _ = connection.as_mut() => return,
            () = answered.notified(), if once && !finishing => {
                finishing = true;
                connection.as_mut().graceful_shutdown();
            }
        }
    }
}

/// An upstream that speaks HTTP/3 only.
async fn upstream_h3(pki: &Pki) -> SocketAddr {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(pki.offering(&[b"h3"])).unwrap();
    let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let nth = connections.fetch_add(1, Ordering::SeqCst) + 1;
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let sni = connection
                    .handshake_data()
                    .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                    .and_then(|data| data.server_name)
                    .unwrap_or_else(|| "-".to_string());
                let Ok(mut h3) = h3::server::builder()
                    .build::<_, Bytes>(h3_quinn::Connection::new(connection))
                    .await
                else {
                    return;
                };
                while let Ok(Some(resolver)) = h3.accept().await {
                    let how = format!("tls=yes sni={sni}");
                    tokio::spawn(async move {
                        let Ok((request, mut stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        let mut body = Vec::new();
                        while let Ok(Some(mut data)) = stream.recv_data().await {
                            body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                        }
                        let text = seen(
                            &how,
                            request.version(),
                            request.uri(),
                            request.headers(),
                            body.into(),
                            nth,
                        );
                        let head = http::Response::builder()
                            .header("content-length", text.len())
                            .body(())
                            .unwrap();
                        let _ = stream.send_response(head).await;
                        let _ = stream.send_data(text).await;
                        let _ = stream.finish().await;
                    });
                }
            });
        }
    });
    addr
}

/// One request with a body, on a connection of its own: the status and the body as sent (a
/// chunked one put together).
async fn send(port: u16, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();
    let end = answer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("the end of a head");
    let head = String::from_utf8_lossy(&answer[..end]).into_owned();
    let status = head[9..12].parse().unwrap();
    let mut rest = &answer[end + 4..];
    if !field(&head, "transfer-encoding").eq_ignore_ascii_case("chunked") {
        return (status, rest.to_vec());
    }
    let mut whole = Vec::new();
    loop {
        let line = rest.windows(2).position(|w| w == b"\r\n").expect("a chunk's size");
        let size = usize::from_str_radix(std::str::from_utf8(&rest[..line]).unwrap().trim(), 16).unwrap();
        if size == 0 {
            return (status, whole);
        }
        whole.extend_from_slice(&rest[line + 2..line + 2 + size]);
        rest = &rest[line + 2 + size + 2..];
    }
}

async fn text(port: u16, path: &str) -> (u16, String) {
    let (status, body) = send(port, "GET", path, b"").await;
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// `transport http { tls_trusted_ca_certs <the test's> … }` with more lines.
fn trusting(pki: &Pki, more: &str) -> String {
    format!(
        "\t\ttransport http {{\n\t\t\ttls_trusted_ca_certs {}\n{more}\t\t}}",
        pki.file("ca.pem")
    )
}

#[tokio::test]
async fn http2_is_spoken_to_an_upstream_that_takes_it() {
    let pki = Pki::new();
    let addr = upstream_h2(Some(pki.offering(&[b"h2", b"http/1.1"])), false).await;

    // The default versions are `1.1 2`: HTTP/2 is offered, and taken. The request is for the
    // upstream as written (its `:authority`), the client's host is in X-Forwarded-Host.
    let (running, port) = start(&proxying(&format!("https://{addr}"), &trusting(&pki, ""))).await;
    let (status, body) = text(port, "/").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        format!("tls=yes sni=- version=HTTP/2.0 host={addr} xfh=example.test body=0 connection=1")
    );
    // The requests share the one connection, side by side too; a body goes and comes whole.
    let several = (0..16).map(|_| text(port, "/")).collect::<Vec<_>>();
    for handle in several.into_iter().map(tokio::spawn).collect::<Vec<_>>() {
        let (status, body) = handle.await.unwrap();
        assert_eq!(status, 200, "{body}");
        assert!(body.ends_with("connection=1"), "{body}");
    }
    let sent: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let (status, back) = send(port, "POST", "/echo", &sent).await;
    assert_eq!(status, 200);
    assert!(back == sent, "{} bytes came back of {}", back.len(), sent.len());
    running.shutdown(Duration::from_secs(1)).await;

    // `header_up Host` is the `:authority` then.
    let kept = trusting(&pki, "") + "\n\t\theader_up Host {hostport}";
    let (running, port) = start(&proxying(&format!("https://{addr}"), &kept)).await;
    let (_, body) = text(port, "/").await;
    assert!(body.contains(" version=HTTP/2.0 host=example.test "), "{body}");
    running.shutdown(Duration::from_secs(1)).await;

    // `versions 1.1`: HTTP/2 is not offered; the connection is kept for the next request.
    let only = trusting(&pki, "\t\t\tversions 1.1\n");
    let (running, port) = start(&proxying(&format!("https://{addr}"), &only)).await;
    let (status, body) = text(port, "/").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(" version=HTTP/1.1 "), "{body}");
    let (_, again) = text(port, "/").await;
    assert!(again.contains(" version=HTTP/1.1 "), "{again}");
    assert_eq!(
        body.rsplit_once(' ').unwrap().1,
        again.rsplit_once(' ').unwrap().1,
        "the kept connection"
    );
    running.shutdown(Duration::from_secs(1)).await;

    // An upstream that offers HTTP/1.1 alone is spoken to in it, whatever is offered to it.
    let old = upstream_h2(Some(pki.offering(&[b"http/1.1"])), false).await;
    let (running, port) = start(&proxying(&format!("https://{old}"), &trusting(&pki, ""))).await;
    let (status, body) = text(port, "/").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(" version=HTTP/1.1 "), "{body}");
    let (status, back) = send(port, "POST", "/echo", &sent).await;
    assert_eq!(status, 200);
    assert!(back == sent, "{} bytes came back of {}", back.len(), sent.len());
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn a_shared_connection_that_closed_is_made_again() {
    let pki = Pki::new();
    // The upstream finishes every connection after one answer.
    let addr = upstream_h2(Some(pki.offering(&[b"h2", b"http/1.1"])), true).await;
    let (running, port) = start(&proxying(&format!("https://{addr}"), &trusting(&pki, ""))).await;
    for nth in 1..=4 {
        let (status, body) = text(port, "/").await;
        assert_eq!(status, 200, "request {nth}: {body}");
        assert!(body.contains(" version=HTTP/2.0 "), "{body}");
        assert!(body.ends_with(&format!("connection={nth}")), "request {nth}: {body}");
        // The upstream's goodbye is on its way.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Without the wait a request may find the connection still open and be refused by it, or
    // find it closing: either way it is answered, on a new one.
    for nth in 0..40 {
        let (status, body) = text(port, "/").await;
        assert_eq!(status, 200, "request {nth} in a row: {body}");
    }
    let several = (0..24).map(|_| tokio::spawn(text(port, "/"))).collect::<Vec<_>>();
    for handle in several {
        let (status, body) = handle.await.unwrap();
        assert_eq!(status, 200, "side by side: {body}");
    }
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn h2c_is_http2_without_tls() {
    let addr = upstream_h2(None, false).await;
    // `h2c://`: HTTP/2 from the first byte; without TLS the Host stays the client's.
    for (upstreams, options) in [
        (format!("h2c://{addr}"), ""),
        (addr.to_string(), "\t\ttransport http {\n\t\t\tversions h2c\n\t\t}"),
    ] {
        let (running, port) = start(&proxying(&upstreams, options)).await;
        let (status, body) = text(port, "/").await;
        assert_eq!(status, 200, "{upstreams}: {body}");
        let (seen, connection) = body.rsplit_once(' ').unwrap();
        assert_eq!(
            seen,
            "tls=no version=HTTP/2.0 host=example.test xfh=example.test body=0"
        );
        let (_, again) = text(port, "/again").await;
        assert!(again.ends_with(connection), "the shared connection: {again}");
        let sent = vec![7u8; 100_000];
        let (status, back) = send(port, "PUT", "/echo", &sent).await;
        assert_eq!(status, 200);
        assert!(back == sent, "{} bytes came back", back.len());
        running.shutdown(Duration::from_secs(1)).await;
    }
    // Plain upstreams with the default versions stay on HTTP/1.1: HTTP/2 is a matter of the TLS
    // handshake, or of h2c.
    let (running, port) = start(&proxying(&addr.to_string(), "")).await;
    let (_, body) = text(port, "/").await;
    assert!(body.contains(" version=HTTP/1.1 "), "{body}");
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn http3_is_spoken_when_asked_for() {
    let pki = Pki::new();
    let addr = upstream_h3(&pki).await;
    let three = trusting(&pki, "\t\t\tversions 3\n");
    let (running, port) = start(&proxying(&format!("https://{addr}"), &three)).await;
    let (status, body) = text(port, "/").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        format!("tls=yes sni=- version=HTTP/3.0 host={addr} xfh=example.test body=0 connection=1")
    );
    // One connection for the requests, side by side too; bodies whole both ways.
    let several = (0..16).map(|_| text(port, "/")).collect::<Vec<_>>();
    for handle in several.into_iter().map(tokio::spawn).collect::<Vec<_>>() {
        let (status, body) = handle.await.unwrap();
        assert_eq!(status, 200, "{body}");
        assert!(body.ends_with("connection=1"), "{body}");
    }
    let sent: Vec<u8> = (0..300_000u32).map(|i| (i % 241) as u8).collect();
    let (status, back) = send(port, "POST", "/echo", &sent).await;
    assert_eq!(status, 200);
    assert!(back == sent, "{} bytes came back of {}", back.len(), sent.len());
    running.shutdown(Duration::from_secs(1)).await;

    // The name asked for, and the certificate verified, as over TCP.
    let named = trusting(&pki, "\t\t\tversions 3\n\t\t\ttls_server_name backend.test\n");
    let (running, port) = start(&proxying(&format!("https://{addr}"), &named)).await;
    let (status, body) = text(port, "/").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("tls=yes sni=backend.test version=HTTP/3.0 "), "{body}");
    running.shutdown(Duration::from_secs(1)).await;
    let untrusted = "\t\ttransport http {\n\t\t\tversions 3\n\t\t}";
    let (running, port) = start(&proxying(&format!("https://{addr}"), untrusted)).await;
    assert_eq!(text(port, "/").await.0, 502);
    running.shutdown(Duration::from_secs(1)).await;

    // No fall back: an upstream that speaks HTTP/3 only is not reached by the versions over TCP,
    // nor one over TCP by `versions 3`.
    let (running, port) = start(&proxying(&format!("https://{addr}"), &trusting(&pki, ""))).await;
    assert_eq!(text(port, "/").await.0, 502);
    running.shutdown(Duration::from_secs(1)).await;
    let tcp = upstream_h2(Some(pki.offering(&[b"h2", b"http/1.1"])), false).await;
    let (running, port) = start(&proxying(&format!("https://{tcp}"), &three)).await;
    assert_eq!(text(port, "/").await.0, 502);
    running.shutdown(Duration::from_secs(1)).await;
}

#[test]
fn what_the_caddyfile_may_say_of_versions() {
    let loads = |upstreams: &str, options: &str| try_load(&proxying(upstreams, options)).map(|_| ());
    let versions = |words: &str| format!("\t\ttransport http {{\n\t\t\tversions {words}\n\t\t}}");
    for (upstreams, words) in [
        ("10.0.0.5:8080", "1.1"),
        ("10.0.0.5:8080", "1.1 2"),
        ("10.0.0.5:8080", "h2c"),
        ("h2c://10.0.0.5:8080", "h2c 2"),
        ("https://backend.test", "2"),
        ("https://backend.test", "3"),
    ] {
        loads(upstreams, &versions(words)).unwrap_or_else(|e| panic!("{upstreams} {words}: {e}"));
    }
    loads("h2c://10.0.0.5:8080", "").unwrap();
    for (upstreams, words, says) in [
        ("10.0.0.5:8080", "", "versions takes"),
        ("10.0.0.5:8080", "1.0", "is not one of"),
        ("https://backend.test", "2 3", "3 goes alone"),
        ("10.0.0.5:8080", "3", "versions 3 needs TLS"),
        ("h2c://10.0.0.5:8080", "1.1", "`versions` without h2c"),
    ] {
        let error = loads(upstreams, &versions(words)).unwrap_err();
        assert!(error.contains(says), "{upstreams} {words}: {error}");
    }
    let mixed = loads("h2c://10.0.0.5:8080 https://backend.test", "").unwrap_err();
    assert!(mixed.contains("cannot be mixed"), "{mixed}");
    let excepted = "\t\ttransport http {\n\t\t\tversions 3\n\t\t\ttls_except_ports 8080\n\t\t}";
    let error = loads("https://backend.test", excepted).unwrap_err();
    assert!(error.contains("cannot be combined"), "{error}");
}
