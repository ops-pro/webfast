//! Time to the first response from a new connection, over whatever delay the network has (the
//! bench script adds one with `tc netem`):
//!   - HTTP/2 over TCP + TLS 1.3, TLS session resumed (TCP handshake, TLS handshake, request);
//!   - HTTP/3, full handshake (QUIC handshake, request);
//!   - HTTP/3 resumed with 0-RTT (the request travels with the handshake).
//!
//!   rtt cert <dir>                          writes a self-signed certificate for "localhost"
//!   rtt run <host> <port> <cert.pem> <n>    n connections per variant, prints the median ms

use http::Request;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("cert") => {
            let dir = std::path::Path::new(args.get(1).expect("dir"));
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("certificate");
            std::fs::write(dir.join("cert.pem"), certified.cert.pem()).expect("cert.pem");
            std::fs::write(dir.join("key.pem"), certified.signing_key.serialize_pem()).expect("key.pem");
        }
        Some("run") => {
            let host = &args[1];
            let port: u16 = args[2].parse().expect("port");
            let cert = std::fs::read(&args[3]).expect("cert");
            let n: usize = args[4].parse().expect("n");
            let addr = (host.as_str(), port)
                .to_socket_addrs()
                .expect("address")
                .next()
                .expect("address");
            let runtime = tokio::runtime::Runtime::new().expect("runtime");
            runtime.block_on(run(addr, port, &cert, n));
        }
        _ => {
            eprintln!("usage: rtt cert <dir> | rtt run <host> <port> <cert.pem> <n>");
            std::process::exit(2);
        }
    }
}

fn tls(cert: &[u8], alpn: &[u8], resume: bool, early: bool) -> rustls::ClientConfig {
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
    config.alpn_protocols = vec![alpn.to_vec()];
    config.enable_early_data = early;
    if !resume {
        config.resumption = rustls::client::Resumption::disabled();
    }
    config
}

fn median(mut ms: Vec<f64>) -> f64 {
    ms.sort_by(f64::total_cmp);
    ms[ms.len() / 2]
}

async fn h2_once(addr: SocketAddr, port: u16, connector: &tokio_rustls::TlsConnector) -> f64 {
    let started = Instant::now();
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("tcp");
    tcp.set_nodelay(true).ok();
    let stream = connector
        .connect("localhost".try_into().expect("name"), tcp)
        .await
        .expect("tls");
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
        .await
        .expect("h2");
    tokio::spawn(conn);
    let request = Request::get(format!("https://localhost:{port}/"))
        .body(Empty::<bytes::Bytes>::new())
        .expect("request");
    let response = sender.send_request(request).await.expect("response");
    let elapsed = started.elapsed().as_secs_f64() * 1000.0;
    let _ = response.into_body().collect().await;
    elapsed
}

/// One request over QUIC; with `zero_rtt` the request is sent before the handshake completes.
async fn h3_once(endpoint: &quinn::Endpoint, addr: SocketAddr, port: u16, zero_rtt: bool) -> (f64, bool) {
    let started = Instant::now();
    let connecting = endpoint.connect(addr, "localhost").expect("connect");
    let (conn, early) = if zero_rtt {
        match connecting.into_0rtt() {
            Ok((conn, accepted)) => (conn, Some(accepted)),
            Err(connecting) => (connecting.await.expect("quic"), None),
        }
    } else {
        (connecting.await.expect("quic"), None)
    };
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
        .await
        .expect("h3");
    let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    let request = Request::get(format!("https://localhost:{port}/"))
        .body(())
        .expect("request");
    let mut stream = send_request.send_request(request).await.expect("send");
    stream.finish().await.expect("finish");
    let _response = stream.recv_response().await.expect("response");
    let elapsed = started.elapsed().as_secs_f64() * 1000.0;
    while stream.recv_data().await.expect("data").is_some() {}
    let accepted = match early {
        Some(accepted) => accepted.await,
        None => false,
    };
    // Let the session tickets of this connection arrive before it closes.
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(send_request);
    drive.abort();
    conn.close(0u32.into(), b"done");
    (elapsed, accepted)
}

async fn run(addr: SocketAddr, port: u16, cert: &[u8], n: usize) {
    // HTTP/2: a new TCP + TLS connection per request; sessions resumed after the first.
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls(cert, b"h2", true, false)));
    h2_once(addr, port, &connector).await;
    let mut h2 = Vec::new();
    for _ in 0..n {
        h2.push(h2_once(addr, port, &connector).await);
    }

    let endpoint = |config: rustls::ClientConfig| {
        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(config).expect("quic tls");
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().expect("bind")).expect("endpoint");
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
        endpoint
    };
    // HTTP/3 without resumption: every connection does the full handshake.
    let full = endpoint(tls(cert, b"h3", false, false));
    let mut h3_full = Vec::new();
    for _ in 0..n {
        h3_full.push(h3_once(&full, addr, port, false).await.0);
    }
    // HTTP/3 with 0-RTT: a first connection fetches a ticket, each next one uses the newest.
    let resumed = endpoint(tls(cert, b"h3", true, true));
    h3_once(&resumed, addr, port, false).await;
    let mut h3_0rtt = Vec::new();
    let mut accepted = 0;
    for _ in 0..n {
        let (ms, ok) = h3_once(&resumed, addr, port, true).await;
        h3_0rtt.push(ms);
        accepted += usize::from(ok);
    }
    println!("connections per variant: {n}");
    println!("HTTP/2 over TCP+TLS (resumed)  {:>8.1} ms", median(h2));
    println!("HTTP/3, full handshake         {:>8.1} ms", median(h3_full));
    println!(
        "HTTP/3, 0-RTT                  {:>8.1} ms   (0-RTT accepted {accepted}/{n})",
        median(h3_0rtt)
    );
}
