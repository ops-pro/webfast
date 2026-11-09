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
//! With WEB_TLS_STRICT_SNI=on a certificate goes only to a name a site names, exactly or by a
//! wildcard: a handshake without SNI (a scanner trying the address) or for another name ends with
//! an alert before any certificate is sent, as Cloudflare does — the certificates' names, the
//! sites served, are not given away. The site for any host then serves no TLS handshake.
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
    loaded: RwLock<Loaded>,
    /// Certificates only for the names the sites name (WEB_TLS_STRICT_SNI).
    strict_sni: bool,
}

#[derive(Debug, Clone)]
struct LoadedEntry {
    spec: CertSpec,
    /// `None`: a managed certificate (src/acme) whose files are not there yet.
    key: Option<Arc<CertifiedKey>>,
    stamp: Stamp,
}

/// Certificates read for a configuration, not yet in use (`CertResolver::install`).
#[derive(Debug)]
pub struct Certificates(Vec<LoadedEntry>);

/// The certificates in use, their names indexed: a handshake (and a request's Host check) finds
/// those that fit a name in one or two lookups, however many certificates there are.
#[derive(Debug)]
struct Loaded {
    entries: Vec<LoadedEntry>,
    index: crate::matcher::HostIndex,
}

impl Loaded {
    fn new(entries: Vec<LoadedEntry>) -> Loaded {
        let index = crate::matcher::HostIndex::new(entries.iter().map(|e| e.spec.hosts.as_slice()));
        Loaded { entries, index }
    }

    /// `f` of the entries that fit `name` best (as `fit` ranks them): those naming it exactly,
    /// else by a wildcard, else those for any host; `None` when none fits, and with `strict` SNI
    /// also when only one for any host would.
    fn best<R>(&self, name: Option<&str>, strict: bool, f: impl FnOnce(Option<&[u32]>) -> R) -> R {
        let any = if strict || self.index.any().is_empty() {
            None
        } else {
            Some(self.index.any())
        };
        match name {
            Some(name) => self.index.lookup(name, |exact, wildcard| {
                if !exact.is_empty() {
                    f(Some(exact))
                } else if !wildcard.is_empty() {
                    f(Some(wildcard))
                } else {
                    f(any)
                }
            }),
            None => f(any),
        }
    }
}

impl std::ops::Deref for Loaded {
    type Target = [LoadedEntry];

    fn deref(&self) -> &[LoadedEntry] {
        &self.entries
    }
}

/// In place only: an entry re-read from its files keeps its names, so the index stays right.
impl std::ops::DerefMut for Loaded {
    fn deref_mut(&mut self) -> &mut [LoadedEntry] {
        &mut self.entries
    }
}

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
    if spec.managed && !spec.cert.exists() {
        return Ok(LoadedEntry {
            spec: spec.clone(),
            key: None,
            stamp: stamp(spec),
        });
    }
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
        key: Some(Arc::new(CertifiedKey::new(certs, signing))),
        stamp: stamp(spec),
    })
}

impl CertResolver {
    /// `strict_sni`: a handshake without SNI, or for a name no site names exactly or by a wildcard,
    /// gets no certificate and ends (the site for any host gives none either).
    pub fn new(specs: Vec<CertSpec>, strict_sni: bool, provider: &CryptoProvider) -> Result<CertResolver> {
        Ok(CertResolver {
            loaded: RwLock::new(Loaded::new(CertResolver::read(&specs, provider)?.0)),
            strict_sni,
        })
    }

    /// Reads every certificate of `specs` (a reload: they are installed once the rest of the new
    /// configuration is ready too).
    pub fn read(specs: &[CertSpec], provider: &CryptoProvider) -> Result<Certificates> {
        specs
            .iter()
            .map(|spec| {
                let entry = load(spec, provider)?;
                match &entry.key {
                    Some(key) => tracing::info!(
                        cert = %spec.cert.display(),
                        hosts = ?spec.hosts,
                        key = ?key.key.algorithm(),
                        "certificate loaded"
                    ),
                    None => tracing::info!(
                        cert = %spec.cert.display(),
                        hosts = ?spec.hosts,
                        "certificate to be obtained: none for the host until then"
                    ),
                }
                Ok(entry)
            })
            .collect::<Result<_>>()
            .map(Certificates)
    }

    /// The certificates of a reloaded configuration, in place of the current ones; handshakes
    /// under way keep the certificate they chose.
    pub fn install(&self, certificates: Certificates) {
        // Built before the lock: handshakes and host checks wait only for the swap.
        let new = Loaded::new(certificates.0);
        if let Ok(mut loaded) = self.loaded.write() {
            *loaded = new;
        }
    }

    /// Whether a request for `host` may be answered on a connection whose handshake named `sni`
    /// (RFC 9110 §15.5.20; otherwise 421 Misdirected Request): the sites that fit the host best
    /// share a certificate with those that fit the SNI name best. A browser that coalesced HTTP/2
    /// connections for names of one certificate is answered; a client that opened the connection
    /// for one site and asks another, served with another certificate, is not. When neither
    /// fits any site the request goes to no site anyway and is let through.
    pub fn same_certificate(&self, sni: Option<&str>, host: &str) -> bool {
        if sni.is_some_and(|sni| sni.eq_ignore_ascii_case(host)) {
            return true;
        }
        let Ok(loaded) = self.loaded.read() else {
            return true;
        };
        // The certificates by their files: those that fit each name best share one.
        let files = |i: &u32| {
            let spec = &loaded[*i as usize].spec;
            (spec.cert.as_path(), spec.key.as_path())
        };
        loaded.best(sni, self.strict_sni, |by_sni| {
            loaded.best(Some(host), self.strict_sni, |by_host| match (by_sni, by_host) {
                (None, None) => true,
                (Some(by_sni), Some(by_host)) => by_sni.iter().any(|a| by_host.iter().any(|b| files(a) == files(b))),
                _ => false,
            })
        })
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
        // Compared in any case where it is looked up: no lowercase copy for an ordinary handshake.
        let name = hello.server_name();
        // TLS-ALPN-01 (src/acme): the challenge certificate for a handshake that asks for it.
        #[cfg(feature = "acme")]
        if let Some(name) = name
            && hello.alpn().is_some_and(crate::acme::challenge::offers_challenge)
        {
            return crate::acme::challenge::alpn_certificate(&name.to_ascii_lowercase());
        }
        let loaded = self.loaded.read().ok()?;
        let chosen = choose(&loaded, name, hello.signature_schemes(), self.strict_sni);
        if chosen.is_none() {
            // Scanners do this all the time: debug, not to flood the log.
            tracing::debug!(sni = name.unwrap_or(""), "TLS handshake refused: no site for this name");
        }
        chosen.and_then(|e| e.key.clone())
    }
}

/// How well a site's `hosts` fit `name`: 0 exactly, 1 by a wildcard, 2 as the site for any host;
/// `None`: not at all. What `Loaded::best` finds by its index; kept to check it against.
#[cfg(test)]
fn fit(hosts: &[String], name: Option<&str>) -> Option<u8> {
    use crate::matcher::host_matches;
    if hosts.is_empty() {
        return Some(2);
    }
    let name = name?;
    let mut by = hosts.iter().filter(|h| host_matches(h, name));
    by.clone()
        .any(|h| !h.starts_with("*."))
        .then_some(0)
        .or_else(|| by.next().map(|_| 1))
}

/// The certificate for a handshake: of the entries that fit the SNI `name` best — exactly, else by
/// a wildcard, else an entry for any host, else (none fits) all of them — the first whose key can
/// sign with one of the client's `schemes`; when none can, the first of them (the handshake then
/// fails as it would have). With `strict_sni` only an exact or wildcard fit counts: no name, or
/// one that only the site for any host would take, gets none (rustls then ends the handshake with
/// an alert, before any certificate is sent).
fn choose<'a>(
    loaded: &'a Loaded,
    name: Option<&str>,
    schemes: &[SignatureScheme],
    strict_sni: bool,
) -> Option<&'a LoadedEntry> {
    loaded.best(name, strict_sni, |best| match best {
        Some(best) => first_signing(best.iter().map(|i| &loaded[*i as usize]), schemes),
        None if strict_sni => None,
        // None fits: any of them.
        None => first_signing(loaded.iter(), schemes),
    })
}

/// Of `candidates`, the first with a key that can sign with one of `schemes`, else the first with
/// a key (an entry whose certificate is still to be obtained has none to give).
fn first_signing<'a>(
    candidates: impl Iterator<Item = &'a LoadedEntry> + Clone,
    schemes: &[SignatureScheme],
) -> Option<&'a LoadedEntry> {
    let candidates = candidates.filter(|e| e.key.is_some());
    candidates
        .clone()
        .find(|e| e.key.as_ref().is_some_and(|k| k.key.choose_scheme(schemes).is_some()))
        .or_else(|| candidates.clone().next())
}

/// `choose` entry by entry, as it was before the index: kept to check the index against.
#[cfg(test)]
fn choose_linear<'a>(
    loaded: &'a [LoadedEntry],
    name: Option<&str>,
    schemes: &[SignatureScheme],
    strict_sni: bool,
) -> Option<&'a LoadedEntry> {
    let fits = |entry: &LoadedEntry| fit(&entry.spec.hosts, name);
    let best = loaded.iter().filter_map(fits).min();
    if strict_sni && !matches!(best, Some(0 | 1)) {
        return None;
    }
    // An entry whose certificate is still to be obtained has none to give.
    let candidates = || {
        loaded
            .iter()
            .filter(move |e| best.is_none() || fits(e) == best)
            .filter(|e| e.key.is_some())
    };
    candidates()
        .find(|e| e.key.as_ref().is_some_and(|k| k.key.choose_scheme(schemes).is_some()))
        .or_else(|| candidates().next())
}

/// Server configuration for TCP (ALPN h2 / http/1.1) or QUIC (ALPN h3, TLS 1.3 only). `tickets`:
/// TCP session tickets sealed with keys from a shared seed (src/tickets.rs), else with keys of
/// this process; QUIC keeps its single-use tickets (0-RTT) whatever it is given.
pub fn server_config(
    resolver: Arc<CertResolver>,
    alpn: &[&[u8]],
    quic: bool,
    tickets: Option<Arc<crate::tickets::TicketKeys>>,
) -> Result<rustls::ServerConfig> {
    let builder = rustls::ServerConfig::builder_with_provider(provider());
    let builder = if quic {
        builder.with_protocol_versions(&[&rustls::version::TLS13])?
    } else {
        builder.with_safe_default_protocol_versions()?
    };
    let certificates = resolver.loaded.read().map_or(1, |l| l.len());
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
        config.ticketer = match tickets {
            Some(keys) => keys,
            None => rustls::crypto::aws_lc_rs::Ticketer::new()?,
        };
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
                managed: false,
            },
            key: Some(Arc::new(CertifiedKey::new(vec![cert.der().clone()], signing))),
            stamp: Vec::new(),
        }
    }

    /// `super::choose` on these entries, checked against the entry-by-entry `choose_linear`.
    fn choose<'a>(
        loaded: &'a [LoadedEntry],
        name: Option<&str>,
        schemes: &[SignatureScheme],
        strict: bool,
    ) -> Option<&'a LoadedEntry> {
        let indexed = Loaded::new(loaded.to_vec());
        let position = |entries: &[LoadedEntry], e: &LoadedEntry| entries.iter().position(|l| std::ptr::eq(l, e));
        let by_index = super::choose(&indexed, name, schemes, strict).and_then(|e| position(&indexed, e));
        let by_entry = choose_linear(loaded, name, schemes, strict).and_then(|e| position(loaded, e));
        assert_eq!(by_index, by_entry, "{name:?} {schemes:?} strict {strict}");
        by_entry.map(|i| &loaded[i])
    }

    #[test]
    fn the_index_chooses_as_entry_by_entry() {
        let p256 = &rcgen::PKCS_ECDSA_P256_SHA256;
        let loaded = [
            entry(&["a.test", "b.test"], p256),
            entry(&["*.w.test"], &rcgen::PKCS_RSA_SHA256),
            entry(&["*.w.test", "x.w.test"], p256),
            entry(&[], &rcgen::PKCS_RSA_SHA256),
            entry(&["b.test"], &rcgen::PKCS_RSA_SHA256),
            entry(&[], p256),
        ];
        let names = [
            None,
            Some("a.test"),
            Some("B.Test"),
            Some("x.w.test"),
            Some("y.W.test"),
            Some("a.y.w.test"),
            Some("w.test"),
            Some("other.test"),
            Some(""),
        ];
        for strict in [false, true] {
            for entries in [&loaded[..], &loaded[..3], &loaded[3..], &loaded[1..2]] {
                for name in names {
                    for schemes in [&[EC][..], &[RSA], &[EC, RSA], &[]] {
                        choose(entries, name, schemes, strict);
                    }
                }
            }
        }
    }

    fn chosen(loaded: &[LoadedEntry], name: &str, schemes: &[SignatureScheme]) -> usize {
        let entry = choose(loaded, Some(name), schemes, false).expect("a certificate");
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
        assert_eq!(
            loaded[0].key.as_ref().unwrap().key.algorithm(),
            SignatureAlgorithm::ECDSA
        );
        assert_eq!(loaded[1].key.as_ref().unwrap().key.algorithm(), SignatureAlgorithm::RSA);
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
            std::ptr::eq(choose(&loaded, None, &[EC], false).unwrap(), &loaded[0]),
            "no SNI"
        );
        // No site for any host and no name that fits: the first certificate the client can verify.
        let named = [loaded[2].clone(), loaded[1].clone()];
        assert_eq!(chosen(&named, "other.test", &[EC]), 1);
        assert_eq!(chosen(&named, "other.test", &[RSA]), 0);
    }

    #[test]
    fn strict_sni_gives_certificates_only_to_the_names_of_the_sites() {
        let loaded = [
            entry(&[], &rcgen::PKCS_ECDSA_P256_SHA256),
            entry(&["*.example.test"], &rcgen::PKCS_ECDSA_P256_SHA256),
            entry(&["www.example.test"], &rcgen::PKCS_ECDSA_P256_SHA256),
        ];
        let strict = |name: Option<&str>| {
            choose(&loaded, name, &[EC], true).map(|e| loaded.iter().position(|l| std::ptr::eq(l, e)).unwrap())
        };
        assert_eq!(strict(Some("www.example.test")), Some(2), "exact");
        assert_eq!(strict(Some("api.example.test")), Some(1), "wildcard");
        assert_eq!(
            strict(None),
            None,
            "no SNI: no certificate, even with a site for any host"
        );
        assert_eq!(strict(Some("other.test")), None, "a name no site names");
        assert_eq!(strict(Some("a.b.example.test")), None, "a wildcard covers one label");
        let named = [loaded[2].clone()];
        assert!(choose(&named, None, &[EC], true).is_none());
        assert!(choose(&named, Some("other.test"), &[EC], true).is_none());
        assert!(
            choose(&named, Some("other.test"), &[EC], false).is_some(),
            "not strict: the first"
        );
    }

    /// A resolver over `entries`, `files[i]` naming entry i's certificate files.
    fn resolver(mut entries: Vec<LoadedEntry>, files: Vec<usize>, strict_sni: bool) -> CertResolver {
        for (entry, file) in entries.iter_mut().zip(files) {
            entry.spec.cert = PathBuf::from(format!("cert-{file}.pem"));
            entry.spec.key = PathBuf::from(format!("cert-{file}.key"));
        }
        CertResolver {
            loaded: RwLock::new(Loaded::new(entries)),
            strict_sni,
        }
    }

    #[test]
    fn a_host_served_with_another_certificate_is_misdirected() {
        let a = entry(&["a.test"], &rcgen::PKCS_ECDSA_P256_SHA256);
        let b = entry(&["b.test"], &rcgen::PKCS_ECDSA_P256_SHA256);
        // c.test: a site of its own, with a.test's certificate files.
        let c = entry(&["c.test"], &rcgen::PKCS_ECDSA_P256_SHA256);
        let wild = entry(&["*.w.test"], &rcgen::PKCS_ECDSA_P256_SHA256);
        let any = entry(&[], &rcgen::PKCS_ECDSA_P256_SHA256);
        let r = resolver(
            vec![a.clone(), b.clone(), c.clone(), wild.clone(), any.clone()],
            vec![0, 1, 0, 3, 4],
            false,
        );
        assert!(r.same_certificate(Some("a.test"), "a.test"));
        assert!(r.same_certificate(Some("a.test"), "A.TEST"), "case");
        assert!(
            !r.same_certificate(Some("a.test"), "b.test"),
            "another site, another certificate"
        );
        assert!(
            r.same_certificate(Some("a.test"), "c.test"),
            "coalesced: the same certificate"
        );
        assert!(
            r.same_certificate(Some("x.w.test"), "y.w.test"),
            "one wildcard certificate"
        );
        assert!(!r.same_certificate(Some("x.w.test"), "a.test"));
        assert!(
            !r.same_certificate(Some("other.test"), "a.test"),
            "the site for any host is not a.test"
        );
        assert!(
            r.same_certificate(Some("other.test"), "else.test"),
            "both for the site for any host"
        );
        assert!(
            !r.same_certificate(None, "a.test"),
            "no SNI: the site for any host's certificate"
        );

        // No site for any host: names no site serves go nowhere and pass; a site's name does not.
        let r = resolver(vec![a.clone(), b.clone()], vec![0, 1], false);
        assert!(r.same_certificate(Some("other.test"), "else.test"));
        assert!(!r.same_certificate(Some("other.test"), "a.test"));
        assert!(!r.same_certificate(None, "b.test"));

        // Strict SNI: a host no site names is misdirected on any connection.
        let r = resolver(vec![a, b, any], vec![0, 1, 2], true);
        assert!(r.same_certificate(Some("a.test"), "a.test"));
        assert!(!r.same_certificate(Some("a.test"), "else.test"));
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
            strict_sni: false,
            loaded: RwLock::new(Loaded::new(vec![LoadedEntry {
                spec: CertSpec {
                    hosts: Vec::new(),
                    cert: std::path::PathBuf::new(),
                    key: std::path::PathBuf::new(),
                    managed: false,
                },
                key: Some(Arc::new(CertifiedKey::new(vec![cert.der().clone()], signing))),
                stamp: Vec::new(),
            }])),
        });
        let server = Arc::new(server_config(resolver, &[b"h2"], false, None).unwrap());
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

    /// One handshake of `client` (which keeps its tickets) with `server`: how it went.
    fn handshake(server: Arc<rustls::ServerConfig>, client: &Arc<rustls::ClientConfig>) -> rustls::HandshakeKind {
        let mut server = rustls::ServerConnection::new(server).unwrap();
        let mut client = rustls::ClientConnection::new(client.clone(), "localhost".try_into().unwrap()).unwrap();
        while client.is_handshaking() || server.is_handshaking() || server.wants_write() {
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
            let mut rest = &bytes[..];
            while !rest.is_empty() {
                client.read_tls(&mut rest).unwrap();
                client.process_new_packets().unwrap();
            }
        }
        client.handshake_kind().unwrap()
    }

    #[test]
    fn replicas_with_one_ticket_seed_resume_each_others_sessions() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let resolver = || {
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
            let signing = provider().key_provider.load_private_key(key).unwrap();
            Arc::new(CertResolver {
                strict_sni: false,
                loaded: RwLock::new(Loaded::new(vec![LoadedEntry {
                    spec: CertSpec {
                        hosts: Vec::new(),
                        cert: std::path::PathBuf::new(),
                        key: std::path::PathBuf::new(),
                        managed: false,
                    },
                    key: Some(Arc::new(CertifiedKey::new(vec![cert.der().clone()], signing))),
                    stamp: Vec::new(),
                }])),
            })
        };
        let client = || {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert.der().clone()).unwrap();
            Arc::new(
                rustls::ClientConfig::builder_with_provider(provider())
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        };
        let seed = b"a seed every replica is given, 32+ bytes";
        // Two replicas: their own configurations and keys, made from one seed.
        let replica = |seed: Option<&[u8]>| {
            let keys = seed.map(|seed| Arc::new(crate::tickets::TicketKeys::new(seed).unwrap()));
            Arc::new(server_config(resolver(), &[b"h2"], false, keys).unwrap())
        };
        let (a, b) = (replica(Some(seed)), replica(Some(seed)));
        let browser = client();
        assert_eq!(handshake(a.clone(), &browser), rustls::HandshakeKind::Full);
        assert_eq!(
            handshake(b, &browser),
            rustls::HandshakeKind::Resumed,
            "the ticket of A, on B"
        );
        assert_eq!(handshake(a, &browser), rustls::HandshakeKind::Resumed, "and of B on A");
        // Another seed (or none, the keys of each process): a full handshake there.
        let browser = client();
        assert_eq!(handshake(replica(Some(seed)), &browser), rustls::HandshakeKind::Full);
        assert_eq!(
            handshake(replica(Some(b"another seed, quite unlike the first one")), &browser),
            rustls::HandshakeKind::Full
        );
        let browser = client();
        assert_eq!(handshake(replica(None), &browser), rustls::HandshakeKind::Full);
        assert_eq!(handshake(replica(None), &browser), rustls::HandshakeKind::Full);
    }
}
