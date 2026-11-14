//! TLS to the upstreams of `reverse_proxy`: `https://` upstreams and `transport http { tls … }`,
//! as Caddy reads them.
//!
//! One client configuration per `reverse_proxy` (rustls on aws-lc-rs): the upstream's certificate
//! is verified against the Mozilla roots built in (the image has no CA store of its own; Caddy
//! takes the system's) or against `tls_trusted_ca_certs`, for the name the upstream is written
//! with unless `tls_server_name` gives another; `tls_client_auth` presents a certificate;
//! `tls_insecure_skip_verify` verifies nothing but the handshake's signature; `tls_except_ports`
//! leaves the upstreams on those ports on plain HTTP.
//!
//! The same configuration is kept three times, for what a handshake offers (ALPN): HTTP/1.1
//! alone (`versions 1.1`, and every WebSocket handshake), HTTP/2 before HTTP/1.1 (`versions`
//! with `2`, the default), and `h3` for QUIC (`versions 3`). The connections themselves are made
//! and kept in src/upstream_link.rs.

use anyhow::{Context, Result, anyhow, bail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// `transport http { tls… }` as written.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    /// `tls_server_name`: the name asked for and verified, in place of the upstream's own.
    pub server_name: Option<String>,
    /// `tls_trusted_ca_certs` / `tls_trust_pool file`: PEM files of the authorities trusted, in
    /// place of the built-in roots.
    pub trusted_ca: Vec<PathBuf>,
    /// `tls_client_auth <cert> <key>`.
    pub client_auth: Option<(PathBuf, PathBuf)>,
    /// `tls_insecure_skip_verify`.
    pub insecure: bool,
    /// `tls_except_ports`: upstreams on these ports are spoken to in plain HTTP.
    pub except_ports: Vec<u16>,
    /// `tls_timeout`: a handshake at most this long (unset: the request's own timeouts bound it).
    pub timeout: Option<Duration>,
}

/// TLS to the upstreams of one `reverse_proxy`.
pub struct UpstreamTls {
    /// What a handshake offers: HTTP/1.1 alone.
    http1: TlsConnector,
    /// HTTP/2 first, HTTP/1.1 after it.
    http2: TlsConnector,
    /// `h3`, for QUIC.
    quic: Arc<ClientConfig>,
    server_name: Option<ServerName<'static>>,
    except_ports: Vec<u16>,
    timeout: Option<Duration>,
}

impl std::fmt::Debug for UpstreamTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamTls")
            .field("server_name", &self.server_name)
            .field("except_ports", &self.except_ports)
            .finish_non_exhaustive()
    }
}

impl UpstreamTls {
    /// Reads the files the settings name and makes the client configuration.
    pub fn new(settings: &Settings) -> Result<UpstreamTls> {
        let provider = crate::tls::provider();
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .context("TLS to the upstream")?;
        let builder = if settings.insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(Unverified(provider)))
        } else {
            let mut roots = RootCertStore::empty();
            if settings.trusted_ca.is_empty() {
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
            for file in &settings.trusted_ca {
                let mut found = 0;
                for certificate in CertificateDer::pem_file_iter(file)
                    .with_context(|| format!("reading the trusted certificates {}", file.display()))?
                {
                    let certificate =
                        certificate.with_context(|| format!("reading the trusted certificates {}", file.display()))?;
                    roots
                        .add(certificate)
                        .with_context(|| format!("a certificate of {} is not an authority's", file.display()))?;
                    found += 1;
                }
                if found == 0 {
                    bail!("no certificate in {}", file.display());
                }
            }
            builder.with_root_certificates(roots)
        };
        let config: ClientConfig = match &settings.client_auth {
            Some((certificate, key)) => {
                let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(certificate)
                    .with_context(|| format!("reading the client certificate {}", certificate.display()))?
                    .collect::<std::result::Result<_, _>>()
                    .with_context(|| format!("reading the client certificate {}", certificate.display()))?;
                if chain.is_empty() {
                    bail!("no certificate in {}", certificate.display());
                }
                let key = PrivateKeyDer::from_pem_file(key)
                    .with_context(|| format!("reading the client key {}", key.display()))?;
                builder
                    .with_client_auth_cert(chain, key)
                    .context("the client certificate and its key")?
            }
            None => builder.with_no_client_auth(),
        };
        let offering = |protocols: &[&[u8]]| {
            let mut config = config.clone();
            config.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
            Arc::new(config)
        };
        let (http1, http2, quic) = (
            offering(&[b"http/1.1"]),
            offering(&[b"h2", b"http/1.1"]),
            offering(&[b"h3"]),
        );
        let server_name = match &settings.server_name {
            Some(name) => Some(
                ServerName::try_from(name.clone())
                    .map_err(|_| anyhow!("tls_server_name: {name:?} is not a host name or an address"))?,
            ),
            None => None,
        };
        Ok(UpstreamTls {
            http1: TlsConnector::from(http1),
            http2: TlsConnector::from(http2),
            quic,
            server_name,
            except_ports: settings.except_ports.clone(),
            timeout: settings.timeout,
        })
    }

    /// Whether an upstream on `port` is spoken to over TLS (`tls_except_ports`).
    pub fn applies(&self, port: u16) -> bool {
        !self.except_ports.contains(&port)
    }

    /// The name a handshake with the upstream written as `host` asks for and verifies:
    /// `tls_server_name`, else that host (a name or an address).
    pub fn name_for(&self, host: &str) -> std::io::Result<ServerName<'static>> {
        if let Some(name) = &self.server_name {
            return Ok(name.clone());
        }
        ServerName::try_from(host.trim_matches(['[', ']']).to_string()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{host:?} is not a name a certificate can be verified for"),
            )
        })
    }

    /// The handshake, on a connection already made; `http2`: HTTP/2 is offered before HTTP/1.1
    /// (what was chosen: `TlsStream::get_ref().1.alpn_protocol()`), else HTTP/1.1 alone.
    pub async fn handshake(
        &self,
        name: ServerName<'static>,
        tcp: TcpStream,
        http2: bool,
    ) -> std::io::Result<TlsStream<TcpStream>> {
        let connector = if http2 { &self.http2 } else { &self.http1 };
        let handshake = connector.connect(name, tcp);
        match self.timeout {
            Some(limit) => tokio::time::timeout(limit, handshake).await.unwrap_or_else(|_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TLS handshake timed out",
                ))
            }),
            None => handshake.await,
        }
    }
}

impl UpstreamTls {
    /// The same configuration for QUIC, offering `h3` (`versions 3`).
    pub fn quic(&self) -> Result<quinn::ClientConfig> {
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(self.quic.clone())
            .map_err(|e| anyhow!("TLS to the upstream over QUIC: {e}"))?;
        Ok(quinn::ClientConfig::new(Arc::new(crypto)))
    }

    /// `tls_timeout`.
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
}

/// `tls_insecure_skip_verify`: any certificate, for any name. The handshake's signature is still
/// checked with the key of the certificate shown (as Go's `InsecureSkipVerify` does).
#[derive(Debug)]
struct Unverified(Arc<CryptoProvider>);

impl ServerCertVerifier for Unverified {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_verified_is_the_upstream_s_unless_one_is_given() {
        let tls = UpstreamTls::new(&Settings::default()).unwrap();
        assert!(
            matches!(tls.name_for("app.internal").unwrap(), ServerName::DnsName(n) if n.as_ref() == "app.internal")
        );
        assert!(matches!(tls.name_for("10.0.0.5").unwrap(), ServerName::IpAddress(_)));
        assert!(matches!(
            tls.name_for("[2001:db8::5]").unwrap(),
            ServerName::IpAddress(_)
        ));
        assert!(tls.name_for("not a name").is_err());
        let named = UpstreamTls::new(&Settings {
            server_name: Some("backend.example".into()),
            except_ports: vec![8080],
            ..Settings::default()
        })
        .unwrap();
        assert!(
            matches!(named.name_for("10.0.0.5").unwrap(), ServerName::DnsName(n) if n.as_ref() == "backend.example")
        );
        assert!(named.applies(443) && !named.applies(8080));
        assert!(
            UpstreamTls::new(&Settings {
                server_name: Some("not a name".into()),
                ..Settings::default()
            })
            .is_err()
        );
        let missing = UpstreamTls::new(&Settings {
            trusted_ca: vec![PathBuf::from("/nonexistent/ca.pem")],
            ..Settings::default()
        })
        .unwrap_err();
        assert!(format!("{missing:#}").contains("ca.pem"), "{missing:#}");
    }
}
