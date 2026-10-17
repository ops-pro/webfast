//! TLS with rustls on aws-lc-rs: TLS 1.3 and 1.2, the hybrid post-quantum key exchange
//! X25519MLKEM768 preferred, ML-DSA certificates accepted. Certificates come from PEM files
//! (`tls <cert> <key>`) and are re-read when the files change (renewals) and when the configuration
//! is reloaded.
//!
//! A site may have several (`tls` repeated: an ECDSA and an RSA certificate, say). A handshake gets
//! one for its SNI name — the sites that name it exactly, else by a wildcard, else the site for any
//! host — and of those the first, in Caddyfile order, whose key signs with a scheme the client
//! offers; as Caddy chooses, so the same file serves the same certificates in both.
//!
//! Certificate compression (RFC 8879, TLS 1.3 over TCP and QUIC): a client that offers brotli or
//! zlib gets the chain compressed, a shorter server flight. Each chain is compressed once, at the
//! slow and small level, and kept; the cache has room for every certificate in both algorithms
//! (rustls keeps 4 by default: with more certificates every handshake would compress again).
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
use rustls::SignatureScheme;
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

/// Picks the certificate for a handshake (see the module documentation).
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
            .map(|spec| {
                let entry = load(spec, provider)?;
                tracing::info!(
                    cert = %spec.cert.display(),
                    hosts = ?spec.hosts,
                    key = ?entry.key.key.algorithm(),
                    "certificate loaded"
                );
                Ok(entry)
            })
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
        let name = hello.server_name().map(str::to_ascii_lowercase);
        choose(&loaded, name.as_deref(), hello.signature_schemes()).map(|e| e.key.clone())
    }
}

/// The certificate for a handshake: of the entries that fit the SNI `name` best — exactly, else by
/// a wildcard, else an entry for any host, else (none fits) all of them — the first whose key can
/// sign with one of the client's `schemes`; when none can, the first of them (the handshake then
/// fails as it would have).
fn choose<'a>(loaded: &'a [LoadedEntry], name: Option<&str>, schemes: &[SignatureScheme]) -> Option<&'a LoadedEntry> {
    // How well an entry fits the name: 0 exactly, 1 by a wildcard, 2 as an entry for any host.
    let fit = |entry: &LoadedEntry| -> Option<u8> {
        if entry.spec.hosts.is_empty() {
            return Some(2);
        }
        let name = name?;
        let mut by = entry.spec.hosts.iter().filter(|h| host_matches(h, name));
        by.clone()
            .any(|h| !h.starts_with("*."))
            .then_some(0)
            .or_else(|| by.next().map(|_| 1))
    };
    let best = loaded.iter().filter_map(fit).min();
    let candidates = || loaded.iter().filter(move |e| best.is_none() || fit(e) == best);
    candidates()
        .find(|e| e.key.key.choose_scheme(schemes).is_some())
        .or_else(|| candidates().next())
}

/// Server configuration for TCP (ALPN h2 / http/1.1) or QUIC (ALPN h3, TLS 1.3 only).
pub fn server_config(resolver: Arc<CertResolver>, alpn: &[&[u8]], quic: bool) -> Result<rustls::ServerConfig> {
    let builder = rustls::ServerConfig::builder_with_provider(provider());
    let builder = if quic {
        builder.with_protocol_versions(&[&rustls::version::TLS13])?
    } else {
        builder.with_safe_default_protocol_versions()?
    };
    let certificates = resolver.specs.len();
    let mut config = builder.with_no_client_auth().with_cert_resolver(resolver);
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    // Compressed chains: one per certificate and algorithm, never evicted while those are in use.
    let compressions = certificates * config.cert_compressors.len();
    config.cert_compression_cache = Arc::new(rustls::compress::CompressionCache::new(compressions.max(4)));
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::SignatureAlgorithm;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use std::path::PathBuf;

    /// A certificate for `hosts` (empty: any host) with a new key of `algorithm`.
    fn entry(hosts: &[&str], algorithm: &'static rcgen::SignatureAlgorithm) -> LoadedEntry {
        let key_pair = rcgen::KeyPair::generate_for(algorithm).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let signing = provider().key_provider.load_private_key(key).unwrap();
        LoadedEntry {
            spec: CertSpec {
                hosts: hosts.iter().map(|h| h.to_string()).collect(),
                cert: PathBuf::new(),
                key: PathBuf::new(),
            },
            key: Arc::new(CertifiedKey::new(vec![cert.der().clone()], signing)),
            stamp: Vec::new(),
        }
    }

    fn chosen(loaded: &[LoadedEntry], name: &str, schemes: &[SignatureScheme]) -> usize {
        let entry = choose(loaded, Some(name), schemes).expect("a certificate");
        loaded.iter().position(|e| std::ptr::eq(e, entry)).unwrap()
    }

    const EC: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;
    const RSA: SignatureScheme = SignatureScheme::RSA_PSS_SHA256;

    #[test]
    fn the_first_certificate_the_client_can_verify_is_chosen() {
        let loaded = [
            entry(&["example.test"], &rcgen::PKCS_ECDSA_P256_SHA256),
            entry(&["example.test"], &rcgen::PKCS_RSA_SHA256),
        ];
        assert_eq!(loaded[0].key.key.algorithm(), SignatureAlgorithm::ECDSA);
        assert_eq!(loaded[1].key.key.algorithm(), SignatureAlgorithm::RSA);
        assert_eq!(chosen(&loaded, "example.test", &[EC, RSA]), 0, "both: the first listed");
        assert_eq!(
            chosen(&loaded, "example.test", &[RSA, EC]),
            0,
            "the client's order does not matter"
        );
        assert_eq!(chosen(&loaded, "example.test", &[RSA]), 1, "RSA only");
        assert_eq!(chosen(&loaded, "example.test", &[EC]), 0, "ECDSA only");
        assert_eq!(
            chosen(&loaded, "example.test", &[SignatureScheme::ED25519]),
            0,
            "none fits: the first, and the handshake fails"
        );
        // Listed the other way round, a client that takes both gets RSA (as from Caddy).
        let reversed = [loaded[1].clone(), loaded[0].clone()];
        assert_eq!(chosen(&reversed, "example.test", &[EC, RSA]), 0);
        assert_eq!(chosen(&reversed, "example.test", &[EC]), 1);
    }

    #[test]
    fn an_exact_name_comes_before_a_wildcard_and_the_site_for_any_host() {
        let loaded = [
            entry(&[], &rcgen::PKCS_ECDSA_P256_SHA256),
            entry(&["*.example.test"], &rcgen::PKCS_ECDSA_P256_SHA256),
            entry(&["www.example.test"], &rcgen::PKCS_RSA_SHA256),
        ];
        assert_eq!(
            chosen(&loaded, "www.example.test", &[EC, RSA]),
            2,
            "exact, though listed last"
        );
        assert_eq!(
            chosen(&loaded, "www.example.test", &[EC]),
            2,
            "the exact name's certificate, even when the client cannot verify it"
        );
        assert_eq!(chosen(&loaded, "api.example.test", &[EC]), 1, "by the wildcard");
        assert_eq!(
            chosen(&loaded, "a.b.example.test", &[EC]),
            0,
            "a wildcard covers one label"
        );
        assert_eq!(chosen(&loaded, "other.test", &[EC]), 0, "the site for any host");
        assert!(
            std::ptr::eq(choose(&loaded, None, &[EC]).unwrap(), &loaded[0]),
            "no SNI"
        );
        // No site for any host and no name that fits: the first certificate the client can verify.
        let named = [loaded[2].clone(), loaded[1].clone()];
        assert_eq!(chosen(&named, "other.test", &[EC]), 1);
        assert_eq!(chosen(&named, "other.test", &[RSA]), 0);
    }

    /// Bytes the server sends until a handshake between these two is complete.
    fn server_flight(server: Arc<rustls::ServerConfig>, client: rustls::ClientConfig) -> usize {
        let mut server = rustls::ServerConnection::new(server).unwrap();
        let mut client = rustls::ClientConnection::new(Arc::new(client), "localhost".try_into().unwrap()).unwrap();
        let mut sent = 0;
        while client.is_handshaking() || server.is_handshaking() {
            let mut bytes = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut bytes).unwrap();
            }
            let mut rest = &bytes[..];
            while !rest.is_empty() {
                server.read_tls(&mut rest).unwrap();
                server.process_new_packets().unwrap();
            }
            let mut bytes = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut bytes).unwrap();
            }
            sent += bytes.len();
            let mut rest = &bytes[..];
            while !rest.is_empty() {
                client.read_tls(&mut rest).unwrap();
                client.process_new_packets().unwrap();
            }
        }
        sent
    }

    #[test]
    fn certificates_go_compressed_to_clients_that_offer_it() {
        // A certificate with many names, as a site with many hosts would have.
        let mut names = vec!["localhost".to_string()];
        names.extend((0..60).map(|i| format!("service-{i}.example.test")));
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(names)
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let signing = provider().key_provider.load_private_key(key).unwrap();
        let resolver = Arc::new(CertResolver {
            specs: Vec::new(),
            loaded: RwLock::new(vec![LoadedEntry {
                hosts: Vec::new(),
                key: Arc::new(CertifiedKey::new(vec![cert.der().clone()], signing)),
                stamp: Vec::new(),
            }]),
        });
        let server = Arc::new(server_config(resolver, &[b"h2"], false).unwrap());
        assert_eq!(server.cert_compressors.len(), 2, "brotli and zlib");

        let client = |decompressors: Vec<&'static dyn rustls::compress::CertDecompressor>| {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert.der().clone()).unwrap();
            let mut config = rustls::ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.cert_decompressors = decompressors;
            config
        };
        let plain = server_flight(server.clone(), client(Vec::new()));
        let brotli = server_flight(server.clone(), client(vec![rustls::compress::BROTLI_DECOMPRESSOR]));
        let zlib = server_flight(server.clone(), client(vec![rustls::compress::ZLIB_DECOMPRESSOR]));
        assert!(cert.der().len() > 1500, "{}", cert.der().len());
        assert!(brotli + 1000 < plain, "brotli {brotli}, uncompressed {plain}");
        assert!(zlib + 1000 < plain, "zlib {zlib}, uncompressed {plain}");
        // The next handshake takes the compressed chain from the cache (the flight differs only by
        // the ECDSA signature, whose DER length varies by a byte or two).
        let again = server_flight(server, client(vec![rustls::compress::BROTLI_DECOMPRESSOR]));
        assert!(again.abs_diff(brotli) <= 4, "brotli {brotli}, then {again}");
    }
}
