//! `respond 103` (Early Hints), as in Caddy: the headers set before it go out as an interim
//! response and the chain goes on. Sent over HTTP/3; over HTTP/1.1 and HTTP/2 hyper sends no
//! interim responses, and the same headers come with the final response.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use webfast::server;

const LINK: &str = "</app.css>; rel=preload; as=style";

fn caddyfile(dir: &Path) -> String {
    format!(
        "localhost:0 {{
	tls {d}/cert.pem {d}/key.pem
	route {{
		header Link \"{LINK}\"
		respond /page 103
		respond /page \"the page\"
		respond \"other\"
	}}
}}
",
        d = dir.display()
    )
}

fn self_signed(dir: &Path) -> rcgen::Certificate {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    std::fs::write(dir.join("cert.pem"), certified.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), certified.signing_key.serialize_pem()).unwrap();
    certified.cert
}

fn client_tls(cert: &rcgen::Certificate, alpn: &[u8]) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let mut config =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    config
}

fn load(text: &str) -> webfast::config::Config {
    let file = webfast::caddyfile::parse_str(text, Path::new("Caddyfile")).unwrap();
    webfast::load_parsed(&file, 1 << 20).unwrap()
}

#[tokio::test]
async fn early_hints_go_out_over_http3_before_the_answer() {
    let dir = tempfile::tempdir().unwrap();
    let cert = self_signed(dir.path());
    let running = server::start(load(&caddyfile(dir.path()))).await.unwrap();
    let port = running.bound[0].1.port();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls(&cert, b"h3")).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
    let conn = endpoint
        .connect(std::net::SocketAddr::from(([127, 0, 0, 1], port)), "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
    let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

    let ask = |path: &'static str| {
        http::Request::get(format!("https://localhost:{port}{path}"))
            .body(())
            .unwrap()
    };
    let mut stream = send_request.send_request(ask("/page")).await.unwrap();
    stream.finish().await.unwrap();
    let hints = stream.recv_response().await.unwrap();
    assert_eq!(hints.status(), http::StatusCode::EARLY_HINTS);
    assert_eq!(hints.headers()["link"], LINK);
    let response = stream.recv_response().await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(response.headers()["link"], LINK, "kept for the final response");
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        use bytes::Buf;
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    assert_eq!(body, b"the page");

    // A path without `respond 103`: no interim response.
    let mut stream = send_request.send_request(ask("/other")).await.unwrap();
    stream.finish().await.unwrap();
    assert_eq!(stream.recv_response().await.unwrap().status(), http::StatusCode::OK);

    drop(send_request);
    drive.abort();
    endpoint.close(0u32.into(), b"done");
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn over_http1_the_hints_come_with_the_final_response() {
    let dir = tempfile::tempdir().unwrap();
    let cert = self_signed(dir.path());
    let running = server::start(load(&caddyfile(dir.path()))).await.unwrap();
    let port = running.bound[0].1.port();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls(&cert, b"http/1.1")));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut tls = connector.connect("localhost".try_into().unwrap(), tcp).await.unwrap();
    tls.write_all(b"GET /page HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut answer = String::new();
    tls.read_to_string(&mut answer).await.unwrap();
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    assert!(answer.contains(&format!("link: {LINK}\r\n")), "{answer}");
    assert!(answer.ends_with("the page"));
    running.shutdown(Duration::from_secs(1)).await;
}

#[test]
fn the_documented_example_loads() {
    // docs/configuration.md, Early Hints.
    let text = ":0 {\n\t@pages not path /api/* /assets/*\n\theader @pages Link \"</assets/app.css>; rel=preload; as=style\"\n\trespond @pages 103\n\treverse_proxy app:8080\n}\n";
    let file = webfast::caddyfile::parse_str(text, Path::new("Caddyfile")).unwrap();
    webfast::load_parsed(&file, 1 << 20).unwrap();
}

#[test]
fn only_103_of_the_informational_statuses() {
    for (text, message) in [
        (":0 {\n\trespond 100\n}\n", "only 103"),
        (":0 {\n\trespond \"hints\" 103\n}\n", "headers only"),
    ] {
        let file = webfast::caddyfile::parse_str(text, Path::new("Caddyfile")).unwrap();
        let error = webfast::load_parsed(&file, 1 << 20)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(error.contains(message), "{text:?}: {error}");
    }
}
