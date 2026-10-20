//! Automatic certificates (docs/acme.md; cargo feature `acme`). A site with a host name on the
//! HTTPS port and no `tls` files is managed: its certificate is ordered from the ACME CA
//! (`acme_ca`, Let's Encrypt unless set) and renewed at two thirds of its life, by one background
//! thread. The site is a `tls` site whose files this module writes (`WEB_ACME_DIR`); the resolver
//! (src/tls.rs) serves them as soon as they are there, and none for the host until then.
//!
//! The challenges are answered without touching the site: HTTP-01 by a request check that runs
//! before the routes (`Http01`, src/extensions.rs), TLS-ALPN-01 by the resolver for a handshake
//! that offers `acme-tls/1` (src/acme/challenge.rs). Validation is not watched: the order is
//! polled at the CA.
//!
//! A failure keeps what is on disk and is tried again with a back-off (a minute doubling to a
//! day): a valid certificate is never ordered again, and never within a minute, which is what
//! the CA's rate limits ask for.

pub mod challenge;

pub use challenge::Http01;

use crate::background::Worker;
use crate::tls::CertResolver;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// The default of WEB_ACME_DIR.
pub const DEFAULT_DIR: &str = "/data/acme";

/// A host whose certificate this module obtains.
#[derive(Debug, Clone)]
pub struct Managed {
    pub host: String,
    /// `tls <email>` of the site, over the global `email`.
    pub email: Option<String>,
    /// The server listens on `http_port` for this host: HTTP-01, else TLS-ALPN-01.
    pub http01: bool,
}

/// What the configuration asks of this module.
#[derive(Debug, Clone)]
pub struct Settings {
    /// `acme_ca`: the directory URL.
    pub directory: String,
    /// `acme_ca_root`: a PEM file with the root to trust for the CA's own HTTPS (a test CA).
    pub root: Option<PathBuf>,
    /// The global `email`.
    pub email: Option<String>,
    /// WEB_ACME_DIR.
    pub dir: PathBuf,
    pub hosts: Vec<Managed>,
}

/// WEB_ACME_DIR, or its default.
pub fn dir_from_env() -> PathBuf {
    match std::env::var_os("WEB_ACME_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(DEFAULT_DIR),
    }
}

pub fn configure_from_env() -> Result<(), String> {
    if let Some(dir) = std::env::var_os("WEB_ACME_DIR")
        && dir.is_empty()
    {
        return Err("WEB_ACME_DIR: empty".into());
    }
    Ok(())
}

/// The CA's directory under `dir`, named after the directory URL's host (as Caddy names it), so
/// that a change of CA does not mix accounts or certificates.
pub fn ca_dir(dir: &Path, directory: &str) -> PathBuf {
    let host = directory
        .split("://")
        .nth(1)
        .unwrap_or(directory)
        .split('/')
        .next()
        .unwrap_or("ca");
    let slug: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    dir.join(slug)
}

/// The certificate and key files of `host`: what the site's `tls` points at.
pub fn cert_paths(dir: &Path, directory: &str, host: &str) -> (PathBuf, PathBuf) {
    let base = ca_dir(dir, directory).join("certs").join(host);
    (base.join("cert.pem"), base.join("key.pem"))
}

// --- The background thread ---

struct Plan {
    settings: Arc<Settings>,
    /// The resolvers to tell when a certificate is written (the ports' own, which a reload keeps).
    resolvers: Vec<Weak<CertResolver>>,
}

struct HostState {
    due: Instant,
    failures: u32,
}

#[derive(Default)]
struct Shared {
    plan: Option<Arc<Plan>>,
    hosts: HashMap<String, HostState>,
    /// A check is under way (one at a time).
    running: bool,
}

type State = Arc<Mutex<Shared>>;

static WORKER: LazyLock<Worker<Plan>> = LazyLock::new(|| {
    let state: State = Arc::new(Mutex::new(Shared::default()));
    let on_plan = state.clone();
    Worker::start(
        "webfast-acme",
        4,
        5,
        Duration::from_secs(60),
        move |plan: Plan| {
            {
                let mut shared = on_plan.lock().unwrap_or_else(|e| e.into_inner());
                let now = Instant::now();
                // Every host of the new plan is looked at now; the states of hosts that stay
                // keep their back-off.
                for host in &plan.settings.hosts {
                    shared
                        .hosts
                        .entry(host.host.clone())
                        .or_insert(HostState { due: now, failures: 0 });
                }
                shared
                    .hosts
                    .retain(|name, _| plan.settings.hosts.iter().any(|h| h.host == *name));
                shared.plan = Some(Arc::new(plan));
            }
            kick(on_plan.clone());
            async {}
        },
        move |_| kick(state.clone()),
    )
});

/// Has the certificates of `settings`' hosts obtained and renewed; called at start and at a reload
/// (the plan is replaced whole).
pub fn start(settings: Arc<Settings>, resolvers: Vec<Arc<CertResolver>>) {
    if settings.hosts.is_empty() {
        return;
    }
    let plan = Plan {
        settings,
        resolvers: resolvers.iter().map(Arc::downgrade).collect(),
    };
    if WORKER.submit(plan).is_err() {
        tracing::error!("the ACME thread takes no plan: no certificate is obtained");
    }
}

/// Runs a check on the worker's runtime unless one is under way.
fn kick(state: State) {
    {
        let mut shared = state.lock().unwrap_or_else(|e| e.into_inner());
        if shared.running || shared.plan.is_none() {
            return;
        }
        shared.running = true;
    }
    tokio::spawn(async move {
        check(&state).await;
        state.lock().unwrap_or_else(|e| e.into_inner()).running = false;
    });
}

/// Orders or renews what is due, one host at a time.
async fn check(state: &State) {
    loop {
        let (plan, host) = {
            let shared = state.lock().unwrap_or_else(|e| e.into_inner());
            let Some(plan) = shared.plan.clone() else {
                return;
            };
            let now = Instant::now();
            let due = plan
                .settings
                .hosts
                .iter()
                .find(|h| shared.hosts.get(&h.host).is_some_and(|s| s.due <= now))
                .cloned();
            match due {
                Some(host) => (plan, host),
                None => return,
            }
        };
        let outcome = handle(&plan, &host).await;
        let mut shared = state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = shared.hosts.get_mut(&host.host) else {
            continue;
        };
        match outcome {
            Ok(renew_at) => {
                entry.failures = 0;
                entry.due = renew_at;
            }
            Err(error) => {
                entry.failures = entry.failures.saturating_add(1);
                let wait = Duration::from_secs(60u64 << entry.failures.min(11).saturating_sub(1))
                    .min(Duration::from_secs(86_400));
                if entry.failures == 1 {
                    tracing::warn!(host = %host.host, %error, retry_in = ?wait, "no certificate obtained; the one on disk, if any, stays in use");
                } else {
                    tracing::debug!(host = %host.host, %error, failures = entry.failures, retry_in = ?wait, "still no certificate");
                }
                entry.due = Instant::now() + wait;
            }
        }
    }
}

/// What is written next to a certificate: when it was obtained and when to renew it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub not_before: u64,
    pub not_after: u64,
    pub renew_at: u64,
}

impl Record {
    /// Renewal at two thirds of the certificate's life.
    pub fn new(not_before: u64, not_after: u64) -> Record {
        let life = not_after.saturating_sub(not_before);
        Record {
            not_before,
            not_after,
            renew_at: not_before + life / 3 * 2,
        }
    }

    fn write(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::json!({
            "not_before": self.not_before,
            "not_after": self.not_after,
            "renew_at": self.renew_at,
        });
        write_atomically(path, json.to_string().as_bytes(), false)
    }

    fn read(path: &Path) -> Option<Record> {
        let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
        Some(Record {
            not_before: json.get("not_before")?.as_u64()?,
            not_after: json.get("not_after")?.as_u64()?,
            renew_at: json.get("renew_at")?.as_u64()?,
        })
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The instant `at` (unix seconds) falls on, now when it is past.
fn instant_of(at: u64) -> Instant {
    Instant::now() + Duration::from_secs(at.saturating_sub(unix_now()))
}

/// Obtains the host's certificate unless the one on disk is not due; `Ok`: when to look again.
async fn handle(plan: &Plan, host: &Managed) -> Result<Instant, String> {
    let settings = &plan.settings;
    let (cert, _) = cert_paths(&settings.dir, &settings.directory, &host.host);
    let record_path = cert.with_file_name("record.json");
    if cert.is_file()
        && let Some(record) = Record::read(&record_path)
        && unix_now() < record.renew_at
    {
        tracing::debug!(host = %host.host, renew_at = record.renew_at, "certificate on disk, not due");
        return Ok(instant_of(record.renew_at));
    }
    let record = obtain(settings, host).await?;
    tracing::info!(host = %host.host, not_after = record.not_after, renew_at = record.renew_at, "certificate obtained");
    let provider = crate::tls::provider();
    for resolver in plan.resolvers.iter().filter_map(Weak::upgrade) {
        resolver.reload_changed(&provider);
    }
    Ok(instant_of(record.renew_at))
}

static ACCOUNT: Mutex<Option<(String, Account)>> = Mutex::new(None);

/// The HTTP client the ACME client talks through: the Mozilla roots built in (the image has no
/// CA store), or `acme_ca_root` alone for a test CA.
fn http_client(root: Option<&Path>) -> Result<Box<dyn instant_acme::HttpClient>, String> {
    let builder = hyper_rustls::HttpsConnectorBuilder::new();
    let builder = match root {
        Some(path) => {
            let mut roots = rustls::RootCertStore::empty();
            for cert in
                CertificateDer::pem_file_iter(path).map_err(|e| format!("acme_ca_root {}: {e}", path.display()))?
            {
                let cert = cert.map_err(|e| format!("acme_ca_root {}: {e}", path.display()))?;
                roots
                    .add(cert)
                    .map_err(|e| format!("acme_ca_root {}: {e}", path.display()))?;
            }
            let config = rustls::ClientConfig::builder_with_provider(crate::tls::provider())
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .with_root_certificates(roots)
                .with_no_client_auth();
            builder.with_tls_config(config)
        }
        None => builder
            .with_provider_and_webpki_roots(crate::tls::provider())
            .map_err(|e| e.to_string())?,
    };
    let connector = builder.https_only().enable_http1().build();
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(connector);
    Ok(Box::new(AcmeHttp(client)))
}

/// The server's HTTPS client as the ACME client asks for one.
struct AcmeHttp(
    hyper_util::client::legacy::Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        instant_acme::BodyWrapper<bytes::Bytes>,
    >,
);

impl instant_acme::HttpClient for AcmeHttp {
    fn request(
        &self,
        request: http::Request<instant_acme::BodyWrapper<bytes::Bytes>>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<instant_acme::BytesResponse, instant_acme::Error>> + Send>> {
        let sent = self.0.request(request);
        Box::pin(async move {
            match sent.await {
                Ok(response) => Ok(instant_acme::BytesResponse::from(response)),
                Err(e) => Err(instant_acme::Error::Other(Box::new(e))),
            }
        })
    }
}

/// The account at the CA: restored from `account.json`, or created and written there.
async fn account(settings: &Settings, email: Option<&str>) -> Result<Account, String> {
    if let Some((directory, account)) = ACCOUNT.lock().unwrap_or_else(|e| e.into_inner()).as_ref()
        && *directory == settings.directory
    {
        return Ok(account.clone());
    }
    let ca = ca_dir(&settings.dir, &settings.directory);
    let path = ca.join("account.json");
    let builder = Account::builder_with_http(http_client(settings.root.as_deref())?);
    let account = match std::fs::read(&path) {
        Ok(json) => {
            let credentials: AccountCredentials =
                serde_json::from_slice(&json).map_err(|e| format!("{}: {e}", path.display()))?;
            builder
                .from_credentials(credentials)
                .await
                .map_err(|e| format!("the account of {}: {e}", path.display()))?
        }
        Err(_) => {
            let contact: Vec<String> = email.map(|e| format!("mailto:{e}")).into_iter().collect();
            let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
            let (account, credentials) = builder
                .create(
                    &NewAccount {
                        contact: &contact,
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    settings.directory.clone(),
                    None,
                )
                .await
                .map_err(|e| format!("creating the account at {}: {e}", settings.directory))?;
            let json = serde_json::to_vec(&credentials).map_err(|e| e.to_string())?;
            std::fs::create_dir_all(&ca).map_err(|e| format!("{}: {e}", ca.display()))?;
            write_atomically(&path, &json, true).map_err(|e| format!("{}: {e}", path.display()))?;
            tracing::info!(directory = %settings.directory, "ACME account created");
            account
        }
    };
    *ACCOUNT.lock().unwrap_or_else(|e| e.into_inner()) = Some((settings.directory.clone(), account.clone()));
    Ok(account)
}

/// Orders the certificate, answers the challenge, writes the files.
async fn obtain(settings: &Settings, host: &Managed) -> Result<Record, String> {
    let email = host.email.as_deref().or(settings.email.as_deref());
    let account = account(settings, email).await?;
    let identifiers = [Identifier::Dns(host.host.clone())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|e| format!("ordering: {e}"))?;
    // What was put up for the challenges, taken down whatever the outcome.
    let mut put_up: Vec<Answer> = Vec::new();
    let outcome = answer_challenges(&mut order, host, &mut put_up).await;
    let outcome = match outcome {
        Ok(()) => finish(&mut order, settings, host).await,
        Err(e) => Err(e),
    };
    for answer in put_up {
        answer.take_down();
    }
    outcome
}

/// A challenge answer in place: HTTP-01 by token, TLS-ALPN-01 by host.
enum Answer {
    Http01(String),
    TlsAlpn01(String),
}

impl Answer {
    fn take_down(&self) {
        match self {
            Answer::Http01(token) => challenge::http01_clear(token),
            Answer::TlsAlpn01(host) => challenge::alpn_clear(host),
        }
    }
}

async fn answer_challenges(
    order: &mut instant_acme::Order,
    host: &Managed,
    put_up: &mut Vec<Answer>,
) -> Result<(), String> {
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authorization = result.map_err(|e| format!("authorization: {e}"))?;
        match authorization.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            status => return Err(format!("authorization {status:?}")),
        }
        let preferred = if host.http01 {
            ChallengeType::Http01
        } else {
            ChallengeType::TlsAlpn01
        };
        let other = if host.http01 {
            ChallengeType::TlsAlpn01
        } else {
            ChallengeType::Http01
        };
        let offered: Vec<ChallengeType> = authorization.challenges.iter().map(|c| c.r#type.clone()).collect();
        let kind = [preferred, other]
            .into_iter()
            .find(|kind| offered.contains(kind))
            .ok_or_else(|| format!("the CA offers none of HTTP-01 and TLS-ALPN-01 for {}", host.host))?;
        let mut challenge = authorization
            .challenge(kind.clone())
            .ok_or_else(|| "the challenge went away".to_string())?;
        let key_authorization = challenge.key_authorization();
        match kind {
            ChallengeType::Http01 => {
                let token = challenge.token.clone();
                challenge::http01_set(&token, key_authorization.as_str());
                put_up.push(Answer::Http01(token));
            }
            _ => {
                let key = challenge::alpn_key(&host.host, key_authorization.digest().as_ref())?;
                challenge::alpn_set(&host.host, key);
                put_up.push(Answer::TlsAlpn01(host.host.clone()));
            }
        }
        tracing::debug!(host = %host.host, challenge = ?kind, "challenge answer put up");
        challenge.set_ready().await.map_err(|e| format!("challenge: {e}"))?;
    }
    Ok(())
}

/// Waits for the order, finalizes it with a new key, writes the certificate, the key and the
/// record.
async fn finish(order: &mut instant_acme::Order, settings: &Settings, host: &Managed) -> Result<Record, String> {
    // Validation takes the CA a few seconds; a minute is long for it.
    let policy = RetryPolicy::default().timeout(Duration::from_secs(120));
    let status = order
        .poll_ready(&policy)
        .await
        .map_err(|e| format!("waiting for validation: {e}"))?;
    if status != OrderStatus::Ready {
        let detail = order
            .state()
            .authorizations
            .iter()
            .filter_map(|a| a.state.as_ref())
            .flat_map(|s| s.challenges.iter())
            .filter_map(|c| c.error.as_ref())
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!("validation failed ({status:?}): {detail}"));
    }
    let key_pem = order.finalize().await.map_err(|e| format!("finalizing: {e}"))?;
    let chain_pem = order
        .poll_certificate(&policy)
        .await
        .map_err(|e| format!("the certificate: {e}"))?;
    let leaf = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .next()
        .and_then(Result::ok)
        .ok_or("the CA sent no certificate")?;
    let (not_before, not_after) = validity(&leaf).ok_or("the certificate's validity cannot be read")?;
    let record = Record::new(not_before, not_after);
    let (cert, key) = cert_paths(&settings.dir, &settings.directory, &host.host);
    let dir = cert.parent().ok_or("no directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    write_atomically(&key, key_pem.as_bytes(), true).map_err(|e| format!("{}: {e}", key.display()))?;
    write_atomically(&cert, chain_pem.as_bytes(), false).map_err(|e| format!("{}: {e}", cert.display()))?;
    record
        .write(&cert.with_file_name("record.json"))
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(record)
}

/// Writes `path` whole or not at all (a temporary file next to it, renamed); `private`: 0600.
fn write_atomically(path: &Path, data: &[u8], private: bool) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(not(unix))]
        let _ = private;
        use std::io::Write;
        let mut file = options.open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

// --- The validity of a certificate, read from its DER ---

/// One DER element at `at`: its tag, and the bounds of its content.
fn element(der: &[u8], at: usize) -> Option<(u8, usize, usize)> {
    let tag = *der.get(at)?;
    let first = *der.get(at + 1)?;
    let (len, start) = if first < 0x80 {
        (usize::from(first), at + 2)
    } else {
        let n = usize::from(first & 0x7F);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(*der.get(at + 2 + i)?);
        }
        (len, at + 2 + n)
    };
    let end = start.checked_add(len)?;
    (end <= der.len()).then_some((tag, start, end))
}

/// `notBefore` and `notAfter` of a certificate, unix seconds (RFC 5280 §4.1: the validity is the
/// fifth element of the TBSCertificate, after an optional version, the serial, the signature
/// algorithm and the issuer).
pub fn validity(der: &[u8]) -> Option<(u64, u64)> {
    let (_, tbs_start, _) = element(der, 0)?; // Certificate
    let (_, mut at, tbs_end) = element(der, tbs_start)?; // TBSCertificate
    if let Some((0xA0, _, end)) = element(der, at) {
        at = end; // version
    }
    for _ in 0..3 {
        let (_, _, end) = element(der, at)?; // serial, signature algorithm, issuer
        at = end;
    }
    let (0x30, start, end) = element(der, at)? else {
        return None;
    };
    if end > tbs_end {
        return None;
    }
    let (tag_a, a_start, a_end) = element(der, start)?;
    let (tag_b, b_start, _) = element(der, a_end)?;
    Some((time(tag_a, &der[a_start..a_end])?, time(tag_b, &der[b_start..])?))
}

/// A UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`) as unix seconds.
fn time(tag: u8, text: &[u8]) -> Option<u64> {
    let digits = |s: &[u8]| -> Option<u64> { std::str::from_utf8(s).ok()?.parse().ok() };
    let (year, rest) = match tag {
        0x17 => {
            let yy = digits(text.get(..2)?)?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, text.get(2..)?)
        }
        0x18 => (digits(text.get(..4)?)?, text.get(4..)?),
        _ => return None,
    };
    let month = digits(rest.get(..2)?)?;
    let day = digits(rest.get(2..4)?)?;
    let hour = digits(rest.get(4..6)?)?;
    let minute = digits(rest.get(6..8)?)?;
    let second = digits(rest.get(8..10)?)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    // Days from 1970-01-01 (Howard Hinnant's days_from_civil).
    let (y, m) = if month <= 2 {
        (year as i64 - 1, month as i64 + 12)
    } else {
        (year as i64, month as i64)
    };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m - 3) + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + (hour * 3600 + minute * 60 + second) as i64).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_directory_names_the_ca() {
        let dir = Path::new("/data/acme");
        assert_eq!(
            ca_dir(dir, LETS_ENCRYPT),
            PathBuf::from("/data/acme/acme-v02.api.letsencrypt.org")
        );
        assert_eq!(
            cert_paths(dir, "https://localhost:14000/dir", "example.test").0,
            PathBuf::from("/data/acme/localhost_14000/certs/example.test/cert.pem")
        );
    }

    #[test]
    fn times_are_read_as_unix_seconds() {
        assert_eq!(time(0x17, b"700101000000Z"), Some(0));
        assert_eq!(time(0x18, b"20260301120000Z"), Some(1_772_366_400));
        assert_eq!(time(0x17, b"491231235959Z"), Some(2_524_607_999), "49 is 2049");
        assert!(
            time(0x17, b"500101000000Z").is_none(),
            "50 is 1950: before 1970, not a unix time"
        );
        assert!(time(0x17, b"261301000000Z").is_none(), "month 13");
        assert!(time(0x19, b"20260301120000Z").is_none(), "another tag");
    }

    #[test]
    fn a_certificates_validity_is_read() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["example.test".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2026, 3, 1);
        params.not_after = rcgen::date_time_ymd(2026, 5, 30);
        let cert = params.self_signed(&key).unwrap();
        let (not_before, not_after) = validity(cert.der()).unwrap();
        assert_eq!(not_before, time(0x18, b"20260301000000Z").unwrap());
        assert_eq!(not_after, time(0x18, b"20260530000000Z").unwrap());
        let record = Record::new(not_before, not_after);
        assert_eq!(
            record.renew_at,
            not_before + (not_after - not_before) / 3 * 2,
            "two thirds in"
        );
        assert!(validity(&cert.der()[..40]).is_none(), "a cut certificate");
    }

    #[test]
    fn a_record_is_written_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.json");
        let record = Record::new(1_000, 7_000);
        record.write(&path).unwrap();
        assert_eq!(Record::read(&path), Some(record));
        assert_eq!(record.renew_at, 5_000);
        assert!(Record::read(&dir.path().join("none.json")).is_none());
        write_atomically(&path, b"{}", true).unwrap();
        assert!(Record::read(&path).is_none(), "a record without its fields");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
