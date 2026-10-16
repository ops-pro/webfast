//! TLS with rustls on aws-lc-rs: TLS 1.3 and 1.2, the hybrid post-quantum key exchange
//! X25519MLKEM768 preferred, ML-DSA certificates accepted. Certificates come from PEM files
//! (`tls <cert> <key>`), are chosen by SNI and are re-read when the files change (renewals) and
//! when the configuration is reloaded.
//!
//! Resumption, kept in this process (a restart or another replica means a full handshake):
//!   - TCP: stateless session tickets for TLS 1.3 (keys rotated by the ticketer), the session cache
//!     for TLS 1.2 session IDs; no early data.
//!   - QUIC: tickets are single-use entries of the session cache — rustls accepts 0-RTT only with
//!     those (RFC 8446 §8.1: a replayed ClientHello cannot resume twice); src/h3.rs decides what is
//!     answered from early data.

use crate::config::CertSpec;
use crate::matcher::host_matches;
use anyhow::{Context, Result};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

/// Sessions remembered for resumption: TLS 1.2 session IDs over TCP, single-use tickets over QUIC
/// (rustls keeps 256 by default); a few MB at most.
const SESSION_CACHE: usize = 16_384;

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Picks the certificate for the SNI name: exact or wildcard host, else a certificate without
/// hosts, else the first one.
#[derive(Debug)]
pub struct CertResolver {
    loaded: RwLock<Vec<LoadedEntry>>,
}

#[derive(Debug, Clone)]
struct LoadedEntry {
    spec: CertSpec,
    key: Arc<CertifiedKey>,
    stamp: Stamp,
}

/// Certificates read for a configuration, not yet in use (`CertResolver::install`).
#[derive(Debug)]
pub struct Certificates(Vec<LoadedEntry>);

/// The certificate and key files' sizes and modification times: changed when renewed.
type Stamp = Vec<(u64, Option<SystemTime>)>;

fn stamp(spec: &CertSpec) -> Stamp {
    [&spec.cert, &spec.key]
        .iter()
        .map(|p| {
            std::fs::metadata(p)
                .map(|m| (m.len(), m.modified().ok()))
                .unwrap_or((0, None))
        })
        .collect()
}

fn load(spec: &CertSpec, provider: &CryptoProvider) -> Result<LoadedEntry> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&spec.cert)
        .with_context(|| format!("reading certificate {}", spec.cert.display()))?
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("parsing certificate {}", spec.cert.display()))?;
    if certs.is_empty() {
        anyhow::bail!("no certificate in {}", spec.cert.display());
    }
    let key = PrivateKeyDer::from_pem_file(&spec.key).with_context(|| format!("reading key {}", spec.key.display()))?;
    let signing = provider
        .key_provider
        .load_private_key(key)
        .with_context(|| format!("unsupported private key {}", spec.key.display()))?;
    Ok(LoadedEntry {
        spec: spec.clone(),
        key: Arc::new(CertifiedKey::new(certs, signing)),
        stamp: stamp(spec),
    })
}

impl CertResolver {
    pub fn new(specs: Vec<CertSpec>, provider: &CryptoProvider) -> Result<CertResolver> {
        Ok(CertResolver {
            loaded: RwLock::new(CertResolver::read(&specs, provider)?.0),
        })
    }

    /// Reads every certificate of `specs` (a reload: they are installed once the rest of the new
    /// configuration is ready too).
    pub fn read(specs: &[CertSpec], provider: &CryptoProvider) -> Result<Certificates> {
        specs
            .iter()
            .map(|spec| load(spec, provider))
            .collect::<Result<_>>()
            .map(Certificates)
    }

    /// The certificates of a reloaded configuration, in place of the current ones; handshakes
    /// under way keep the certificate they chose.
    pub fn install(&self, certificates: Certificates) {
        if let Ok(mut loaded) = self.loaded.write() {
            *loaded = certificates.0;
        }
    }

    /// Re-reads certificates whose files changed; a broken new file keeps the old certificate.
    pub fn reload_changed(&self, provider: &CryptoProvider) {
        let current: Vec<(CertSpec, Stamp)> = self
            .loaded
            .read()
            .map(|l| l.iter().map(|e| (e.spec.clone(), e.stamp.clone())).collect())
            .unwrap_or_default();
        for (i, (spec, current)) in current.iter().enumerate() {
            if stamp(spec) == *current {
                continue;
            }
            match load(spec, provider) {
                Ok(fresh) => {
                    if let Ok(mut loaded) = self.loaded.write()
                        // Unless a reload installed other certificates meanwhile.
                        && loaded.get(i).is_some_and(|e| e.spec == *spec)
                    {
                        loaded[i] = fresh;
                    }
                    tracing::info!(cert = %spec.cert.display(), "certificate reloaded");
                }
                Err(e) => {
                    tracing::error!(cert = %spec.cert.display(), error = %e, "certificate reload failed; keeping the old one")
                }
            }
        }
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let loaded = self.loaded.read().ok()?;
        if let Some(name) = hello.server_name() {
            let name = name.to_ascii_lowercase();
            if let Some(e) = loaded
                .iter()
                .find(|e| e.spec.hosts.iter().any(|h| host_matches(h, &name)))
            {
                return Some(e.key.clone());
            }
        }
        loaded
            .iter()
            .find(|e| e.spec.hosts.is_empty())
            .or_else(|| loaded.first())
            .map(|e| e.key.clone())
    }
}

/// Server configuration for TCP (ALPN h2 / http/1.1) or QUIC (ALPN h3, TLS 1.3 only).
pub fn server_config(resolver: Arc<CertResolver>, alpn: &[&[u8]], quic: bool) -> Result<rustls::ServerConfig> {
    let builder = rustls::ServerConfig::builder_with_provider(provider());
    let builder = if quic {
        builder.with_protocol_versions(&[&rustls::version::TLS13])?
    } else {
        builder.with_safe_default_protocol_versions()?
    };
    let mut config = builder.with_no_client_auth().with_cert_resolver(resolver);
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(SESSION_CACHE);
    if quic {
        // Stateful tickets (the default: no ticketer) allow 0-RTT; quinn takes exactly this value.
        config.max_early_data_size = u32::MAX;
    } else {
        config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new()?;
    }
    Ok(config)
}

/// Checks the certificate files once a minute.
pub fn watch(resolver: Arc<CertResolver>) {
    tokio::spawn(async move {
        let provider = provider();
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await;
        loop {
            tick.tick().await;
            let r = resolver.clone();
            let p = provider.clone();
            let _ = tokio::task::spawn_blocking(move || r.reload_changed(&p)).await;
        }
    });
}
