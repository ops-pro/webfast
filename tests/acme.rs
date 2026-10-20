//! Automatic certificates against Pebble, Let's Encrypt's test CA (docs/acme.md): run when
//! WEBFAST_PEBBLE_ROOT names Pebble's `pebble.minica.pem` (its own HTTPS root) and Pebble
//! listens at WEBFAST_PEBBLE_DIRECTORY (`https://localhost:14000/dir` unless set) with
//! PEBBLE_VA_ALWAYS_VALID=1, so that no challenge has to reach this test's server. Never against
//! a real CA.
#![cfg(feature = "acme")]

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use webfast::server;

/// Trusts any certificate: the test looks at what was presented, not at who signed it.
#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// The certificate the server presents for `name`, or `None` when the handshake fails.
async fn presented(port: u16, name: &str) -> Option<CertificateDer<'static>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.ok()?;
    let stream = connector
        .connect(name.to_string().try_into().unwrap(), tcp)
        .await
        .ok()?;
    let (_, connection) = stream.get_ref();
    connection.peer_certificates().and_then(|c| c.first().cloned())
}

fn load(text: &str) -> webfast::config::Config {
    let file = webfast::caddyfile::parse_str(text, Path::new("Caddyfile")).unwrap();
    webfast::load_parsed(&file, 1 << 20).unwrap()
}

#[tokio::test]
async fn a_certificate_is_obtained_from_the_test_ca_and_kept() {
    let Ok(root) = std::env::var("WEBFAST_PEBBLE_ROOT") else {
        eprintln!("WEBFAST_PEBBLE_ROOT is not set: no Pebble, the test does nothing");
        return;
    };
    let directory =
        std::env::var("WEBFAST_PEBBLE_DIRECTORY").unwrap_or_else(|_| "https://localhost:14000/dir".to_string());
    let dir = tempfile::tempdir().unwrap();
    // SAFETY: the one test of this binary that reads the variable, set before the server starts.
    unsafe { std::env::set_var("WEB_ACME_DIR", dir.path()) };
    let text = format!(
        "{{\n\tacme_ca {directory}\n\tacme_ca_root {root}\n\temail test@example.test\n\tauto_https disable_redirects\n\thttps_port 0\n}}\nexample.test {{\n\trespond \"secure\"\n}}\n"
    );
    let running = server::start(load(&text)).await.unwrap();
    let port = running.bound[0].1.port();
    assert!(
        presented(port, "example.test").await.is_none(),
        "no certificate yet: the handshake ends"
    );

    let started = Instant::now();
    let certificate = loop {
        if let Some(cert) = presented(port, "example.test").await {
            break cert;
        }
        assert!(
            started.elapsed() < Duration::from_secs(90),
            "no certificate within 90 s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert!(
        certificate.as_ref().windows(12).any(|w| w == b"example.test"),
        "the certificate names the host"
    );
    let ca_dir = std::fs::read_dir(dir.path()).unwrap().next().unwrap().unwrap().path();
    assert!(ca_dir.join("account.json").is_file());
    let certs = ca_dir.join("certs").join("example.test");
    assert!(certs.join("cert.pem").is_file() && certs.join("key.pem").is_file() && certs.join("record.json").is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(certs.join("key.pem")).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    running.shutdown(Duration::from_secs(1)).await;

    // Started again with the same directory: the certificate on disk serves at once, not ordered
    // again (the record says it is not due).
    let again = server::start(load(&text)).await.unwrap();
    let port = again.bound[0].1.port();
    let on_disk = presented(port, "example.test")
        .await
        .expect("the certificate from disk");
    assert_eq!(on_disk, certificate);
    again.shutdown(Duration::from_secs(1)).await;
}
