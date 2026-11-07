//! `cache` (cargo feature `proxy-cache`): responses of `reverse_proxy` kept in memory and answered
//! from there, in the Caddyfile syntax of Caddy's cache-handler (Souin) — the global `cache` option
//! and the `cache` directive, with `ttl`, `stale`, `default_cache_control`,
//! `max_cacheable_body_bytes`, `cache_name`, `regex { exclude }` and `mode strict`.
//!
//! The client is answered first. On a miss the upstream's body goes to the client as it comes,
//! and its frames (`Bytes`: shared, not copied) are kept on the side before `encode` sees them;
//! once the body has ended whole, the response goes to the worker thread through a bounded queue
//! (full: it is not stored). Whether it may be stored is decided from its headers on the way
//! (RFC 9111 for a shared cache, and stricter: GET, 200, no Set-Cookie, no `Vary` but on
//! Accept-Encoding, never an event stream). The worker decodes a body the upstream encoded
//! (bounded, against bombs), prepares each encoding the site's `encode` lists at the highest
//! level — first asking the upstream for those it may have itself, when it sent one encoded — and
//! puts the entry in place whole.
//!
//! A hit is answered from memory with `Age` and `Cache-Status`, in the best encoding the client
//! takes, and 304 for its validators. Past its freshness, within its stale window (`stale`, or the
//! response's own stale-while-revalidate), a response is answered as it is while one conditional
//! request refreshes it in the background; within `stale` (or stale-if-error) it also answers when
//! the upstream fails. Misses are not collapsed: concurrent misses each go to the upstream.
//!
//! WEB_PROXY_CACHE_MEMORY (64 MiB) bounds what the entries take; past it, the entries not asked
//! for since the last round go first (CLOCK). The store outlives a reload.

use crate::background::{Budget, Seen, Worker};
use crate::body::{Body, BoxError};
use crate::encode::{Encode, Encoding, contains_ignore_case, has_vary, starts_with_ignore_case, types_match};
use crate::extensions::UpstreamCheck;
use crate::handler::{Ctx, RenderedOp};
use crate::proxy::ReverseProxy;
use bytes::{Bytes, BytesMut};
use http::header::{
    ACCEPT, ACCEPT_ENCODING, AGE, AUTHORIZATION, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE,
    CONTENT_TYPE, COOKIE, DATE, ETAG, EXPIRES, HOST, IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE,
    IF_UNMODIFIED_SINCE, LAST_MODIFIED, RANGE, SET_COOKIE, TRANSFER_ENCODING, UPGRADE, VARY,
};
use http::uri::{Authority, PathAndQuery};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
use http_body::{Frame, SizeHint};
use http_body_util::BodyExt;
use regex::Regex;
use rustc_hash::FxHashMap;
use std::hash::{BuildHasher, Hasher};
use std::io::Read;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};

/// The default of WEB_PROXY_CACHE_MEMORY.
pub const DEFAULT_MEMORY: usize = 64 << 20;
/// WEB_PROXY_CACHE_MEMORY: what the entries may take; 0: nothing is stored.
static MAX_MEMORY: AtomicUsize = AtomicUsize::new(DEFAULT_MEMORY);
/// Responses waiting for the worker; more are not stored.
const QUEUE: usize = 64;
const SHARDS: usize = 64;
/// `Cache-Status` names this cache unless `cache_name` says otherwise.
pub const DEFAULT_NAME: &str = "webfast";
static CACHE_STATUS: HeaderName = HeaderName::from_static("cache-status");

/// WEB_PROXY_CACHE_MEMORY: a size (`64MiB`), or `off`.
pub fn configure_from_env() -> Result<(), String> {
    if let Ok(value) = std::env::var("WEB_PROXY_CACHE_MEMORY") {
        let bytes = if value.trim().eq_ignore_ascii_case("off") {
            0
        } else {
            crate::parse_size(&value)
                .ok_or_else(|| format!("WEB_PROXY_CACHE_MEMORY: a size (e.g. 64MiB) or off, not {value:?}"))?
        };
        MAX_MEMORY.store(usize::try_from(bytes).unwrap_or(usize::MAX), Ordering::Relaxed);
    }
    Ok(())
}

/// The options of the global `cache` and of a `cache` directive (which starts from the global's).
#[derive(Debug, Clone)]
pub struct Settings {
    /// How long a response with no lifetime of its own (no max-age, s-maxage or Expires) is fresh.
    pub ttl: Duration,
    /// How long past its freshness a response may still answer (stale-while-revalidate, and
    /// stale-if-error).
    pub stale: Duration,
    /// The Cache-Control of a response that has none (the client gets it too).
    pub default_cache_control: Option<HeaderValue>,
    /// `max_cacheable_body_bytes`; `None`: a sixteenth of WEB_PROXY_CACHE_MEMORY.
    pub max_body: Option<usize>,
    /// The name in `Cache-Status`.
    pub name: Arc<str>,
    /// `regex { exclude }`: request URIs (path and query) never answered from or kept in the cache.
    pub exclude: Option<Regex>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            ttl: Duration::from_secs(120),
            stale: Duration::ZERO,
            default_cache_control: None,
            max_body: None,
            name: Arc::from(DEFAULT_NAME),
            exclude: None,
        }
    }
}

impl Settings {
    fn max_body(&self) -> usize {
        self.max_body.unwrap_or(MAX_MEMORY.load(Ordering::Relaxed) / 16)
    }
}

/// A directive's settings and what every miss derives from them: its `Cache-Status`, in its four
/// forms, made once here and shared with each answer.
struct Configured {
    settings: Settings,
    /// By `forced` (bit 0) and `stored` (bit 1); `None` when `name` is no header value.
    miss_status: [Option<HeaderValue>; 4],
}

impl Configured {
    fn new(settings: Settings) -> Configured {
        let status = |forced: bool, stored: bool| {
            let fwd = if forced { "request" } else { "uri-miss" };
            let stored = if stored { "; stored" } else { "" };
            HeaderValue::from_str(&format!("{}; fwd={fwd}{stored}", settings.name)).ok()
        };
        Configured {
            miss_status: [
                status(false, false),
                status(true, false),
                status(false, true),
                status(true, true),
            ],
            settings,
        }
    }

    /// Appends the `Cache-Status` of a miss: `forced` by the client (`fwd=request`), `stored` on
    /// its way to the client.
    fn add_miss_status(&self, headers: &mut HeaderMap, forced: bool, stored: bool) {
        if let Some(value) = &self.miss_status[usize::from(forced) | (usize::from(stored) << 1)] {
            headers.append(CACHE_STATUS.clone(), value.clone());
        }
    }
}

impl Deref for Configured {
    type Target = Settings;

    fn deref(&self) -> &Settings {
        &self.settings
    }
}

/// One `cache` directive.
pub struct Cache {
    settings: Arc<Configured>,
}

/// A `Miss` on the request (`http::Extensions`), from the `cache` directive to the `reverse_proxy`
/// that takes it; `Clone` is required of extensions, never used (a miss is taken, not copied).
pub struct PendingMiss(pub Miss);

impl Clone for PendingMiss {
    fn clone(&self) -> Self {
        unreachable!("a pending cache miss is taken by the proxy, never cloned")
    }
}

/// A request the cache did not answer, on its way to `reverse_proxy` (src/proxy.rs `tee`).
pub struct Miss {
    key: Keyed,
    settings: Arc<Configured>,
    /// The response may be kept: a GET without Range, and without the client's no-store.
    store: bool,
    /// The client asked for the upstream's answer (no-cache, max-age): `Cache-Status: fwd=request`.
    forced: bool,
    /// Its credentials were checked here (src/handler.rs `Credentialed`): kept only when shared.
    pub(crate) credentialed: bool,
    /// The site's `encode` on the way to the proxy (src/handler.rs sets it): which encodings to
    /// keep, in its order.
    pub encode: Option<Arc<Encode>>,
    /// What may answer if the upstream fails (within the stale-if-error window).
    fallback: Option<Arc<Entry>>,
}

/// Where a stored response comes from: the entry's own texts (copies made on the worker; a
/// request's would keep its connection's buffers alive for as long as the entry).
#[derive(Debug, Clone)]
struct Key {
    hash: u64,
    https: bool,
    hostport: Box<str>,
    uri: Box<str>,
}

impl Key {
    fn is(&self, https: bool, hostport: &str, uri: &str) -> bool {
        self.https == https && self.hostport.eq_ignore_ascii_case(hostport) && &*self.uri == uri
    }
}

/// The key of a response on its way to the store.
enum Keyed {
    /// A miss: the request's texts, shared with it, nothing copied on the connection's thread.
    Asked {
        hash: u64,
        https: bool,
        hostport: HostPort,
        /// `None`: `/`.
        uri: Option<PathAndQuery>,
    },
    /// A revalidation: the entry's.
    Known(Key),
}

impl Keyed {
    fn hostport(&self) -> &str {
        match self {
            Keyed::Asked { hostport, .. } => hostport.as_str(),
            Keyed::Known(key) => &key.hostport,
        }
    }

    fn uri(&self) -> &str {
        match self {
            Keyed::Asked { uri, .. } => uri.as_ref().map_or("/", PathAndQuery::as_str),
            Keyed::Known(key) => &key.uri,
        }
    }

    fn into_key(self) -> Key {
        match self {
            Keyed::Asked { hash, https, .. } => Key {
                hash,
                https,
                hostport: self.hostport().into(),
                uri: self.uri().into(),
            },
            Keyed::Known(key) => key,
        }
    }
}

/// The host and port a request names, as src/handler.rs `hostport_of` reads them: its URI's
/// authority, or else its Host.
#[derive(Debug, Clone)]
enum HostPort {
    Authority(Authority),
    /// Visible ASCII, checked when taken.
    Header(HeaderValue),
    None,
}

impl HostPort {
    fn of(parts: &http::request::Parts) -> HostPort {
        if let Some(authority) = parts.uri.authority() {
            return HostPort::Authority(authority.clone());
        }
        match parts.headers.get(HOST) {
            Some(value) if value.to_str().is_ok() => HostPort::Header(value.clone()),
            _ => HostPort::None,
        }
    }

    fn as_str(&self) -> &str {
        match self {
            HostPort::Authority(authority) => authority.as_str(),
            HostPort::Header(value) => value.to_str().unwrap_or(""),
            HostPort::None => "",
        }
    }
}

/// A stored response.
pub struct Entry {
    key: Key,
    status: StatusCode,
    /// The upstream's headers without those of the representation: Content-Length,
    /// Content-Encoding, ETag and Age are set for each answer.
    headers: HeaderMap,
    /// The upstream's ETag, for its revalidation.
    etag: Option<HeaderValue>,
    last_modified: Option<HeaderValue>,
    /// The encoding the upstream's body came in; `None`: identity.
    origin: Option<Encoding>,
    identity: Variant,
    encoded: [Option<Variant>; 3],
    /// The encodings to offer, best first among equals (the site's `encode` order).
    offer: Vec<Encoding>,
    /// An answer says `Vary: Accept-Encoding`: encodings are offered and the headers do not say it.
    vary: bool,
    /// The site's `encode`, for a revalidation that brings a new body.
    encode: Option<Arc<Encode>>,
    received: Instant,
    freshness: Freshness,
    size: usize,
    /// Asked for since the eviction last passed it.
    touched: AtomicBool,
    /// One background revalidation at a time.
    revalidating: AtomicBool,
    fetch: Arc<Fetch>,
    settings: Arc<Configured>,
}

/// One representation of a stored response, with the header values of its own made once: an
/// answer takes a copy of each (shared bytes).
#[derive(Clone)]
struct Variant {
    body: Bytes,
    /// The upstream's ETag for the encoding it sent (and when weak), otherwise with the encoding's
    /// letter appended to it (src/encode.rs `etag_with`; `i`: identity).
    etag: Option<HeaderValue>,
    content_length: HeaderValue,
}

impl Variant {
    fn new(body: Bytes, etag: Option<&HeaderValue>, origin: Option<Encoding>, encoding: Option<Encoding>) -> Variant {
        Variant {
            etag: etag_of(etag, origin, encoding),
            content_length: header_small(body.len() as u64),
            body,
        }
    }
}

/// The ETag of the representation in `encoding`, from the upstream's `etag` (sent in `origin`).
fn etag_of(etag: Option<&HeaderValue>, origin: Option<Encoding>, encoding: Option<Encoding>) -> Option<HeaderValue> {
    let etag = etag?;
    if encoding == origin || etag.as_bytes().starts_with(b"W/") {
        return Some(etag.clone());
    }
    let text = etag.to_str().ok()?;
    let letter = encoding.map_or('i', Encoding::letter);
    crate::encode::etag_with(text, letter)
}

/// Numbers up to this have a header value ready (`Age`, `Content-Length`).
const SMALL: usize = 4096;

/// The digits of `0..=SMALL` in a row, for header values that point into them.
static DIGITS: [u8; small_digits_len()] = small_digits();

const fn small_digits_len() -> usize {
    let mut len = 0;
    let mut n = 0;
    while n <= SMALL {
        len += digits_of(n);
        n += 1;
    }
    len
}

const fn digits_of(n: usize) -> usize {
    let mut digits = 1;
    let mut rest = n / 10;
    while rest > 0 {
        digits += 1;
        rest /= 10;
    }
    digits
}

const fn small_digits() -> [u8; small_digits_len()] {
    let mut out = [0u8; small_digits_len()];
    let mut at = 0;
    let mut n = 0;
    while n <= SMALL {
        let digits = digits_of(n);
        let mut rest = n;
        let mut i = digits;
        while i > 0 {
            i -= 1;
            out[at + i] = b'0' + (rest % 10) as u8;
            rest /= 10;
        }
        at += digits;
        n += 1;
    }
    out
}

/// A header value for each number up to `SMALL`, each a view of `DIGITS` (static bytes: a copy of
/// one is a pointer, with nothing counted or allocated).
static SMALL_NUMBERS: LazyLock<Vec<HeaderValue>> = LazyLock::new(|| {
    let digits = Bytes::from_static(&DIGITS);
    let mut at = 0;
    (0..=SMALL)
        .map(|n| {
            let len = digits_of(n);
            at += len;
            HeaderValue::from_maybe_shared(digits.slice(at - len..at)).expect("digits")
        })
        .collect()
});

/// A number as a header value: ready for a small one, written for the rest.
fn header_small(n: u64) -> HeaderValue {
    match usize::try_from(n).ok().and_then(|n| SMALL_NUMBERS.get(n)) {
        Some(value) => value.clone(),
        None => crate::handler::header_number(n),
    }
}

/// How a background request reaches the upstream again: the proxy, and the request as it was sent
/// without the client's identity, credentials, cookies and conditions.
struct Fetch {
    proxy: Arc<ReverseProxy>,
    path_and_query: Box<str>,
    headers: HeaderMap,
    /// The proxy's `header_down`, as it was filled in for that request.
    header_down: Vec<RenderedOp>,
}

#[derive(Debug, Clone, Copy)]
struct Freshness {
    /// How long from `received` the response is fresh (its lifetime less its Age on arrival).
    fresh: Duration,
    /// How old it was on arrival (its Age).
    initial_age: Duration,
    /// Past `fresh`: answered while revalidated (stale-while-revalidate) …
    while_revalidating: Duration,
    /// … and when the upstream fails (stale-if-error).
    if_error: Duration,
}

/// The cache's own `Cache-Control` reading.
#[derive(Debug, Default)]
struct Directives {
    no_store: bool,
    no_cache: bool,
    private: bool,
    public: bool,
    must_revalidate: bool,
    only_if_cached: bool,
    max_age: Option<u64>,
    s_maxage: Option<u64>,
    stale_while_revalidate: Option<u64>,
    stale_if_error: Option<u64>,
}

impl Directives {
    fn of(headers: &HeaderMap) -> Directives {
        let mut d = Directives::default();
        for value in headers.get_all(CACHE_CONTROL) {
            let Ok(value) = value.to_str() else { continue };
            for item in value.split(',') {
                let (name, argument) = match item.split_once('=') {
                    Some((name, argument)) => (name.trim(), Some(argument.trim().trim_matches('"'))),
                    None => (item.trim(), None),
                };
                let seconds = argument.and_then(|a| a.parse::<u64>().ok());
                // Compared in place, in any case: no lowercase copy of the name.
                let is = |directive: &str| name.eq_ignore_ascii_case(directive);
                if is("no-store") {
                    d.no_store = true;
                } else if is("no-cache") {
                    d.no_cache = true;
                } else if is("private") {
                    d.private = true;
                } else if is("public") {
                    d.public = true;
                } else if is("must-revalidate") || is("proxy-revalidate") {
                    d.must_revalidate = true;
                } else if is("only-if-cached") {
                    d.only_if_cached = true;
                } else if is("max-age") {
                    d.max_age = seconds.or(Some(0));
                } else if is("s-maxage") {
                    d.s_maxage = seconds.or(Some(0));
                } else if is("stale-while-revalidate") {
                    d.stale_while_revalidate = seconds;
                } else if is("stale-if-error") {
                    d.stale_if_error = seconds;
                }
            }
        }
        d
    }
}

/// A shard's lock on a cache line of its own: a hit on one shard does not bounce the line that
/// holds its neighbours' locks.
#[repr(align(128))]
struct Padded<T>(T);

/// One shard of the store, on cache lines of its own.
type Shard = Padded<Mutex<FxHashMap<u64, Arc<Entry>>>>;

/// The entries, by a hash of their key (ahash, keyed by the process: a client cannot aim keys at one
/// shard), in shards.
struct Store {
    hasher: ahash::RandomState,
    shards: Vec<Shard>,
    /// The order entries came in and what they take (src/background.rs: CLOCK eviction).
    budget: Mutex<Budget<Weak<Entry>>>,
}

static STORE: LazyLock<Store> = LazyLock::new(|| Store {
    hasher: ahash::RandomState::new(),
    shards: (0..SHARDS).map(|_| Padded(Mutex::new(FxHashMap::default()))).collect(),
    budget: Mutex::new(Budget::new()),
});

/// What the worker does.
enum Job {
    Store(Box<Pending>, Vec<Bytes>),
    Revalidate(Arc<Entry>),
}

/// A response on its way to the store: what was decided from its headers.
struct Pending {
    miss: Miss,
    status: StatusCode,
    headers: HeaderMap,
    freshness: Freshness,
    received: Instant,
    fetch: Fetching,
}

/// How the entry will reach the upstream again: what a revalidation's entry has already, or what
/// the proxy sent on the miss, to be made into a `Fetch` on the worker, not the connection's thread.
enum Fetching {
    Ready(Arc<Fetch>),
    Sent {
        proxy: Arc<ReverseProxy>,
        /// The path and query the proxy sent, when another than the one asked for (`Miss::key`:
        /// rewritten on the way).
        path_and_query: Option<Box<str>>,
        headers: HeaderMap,
        header_down: Vec<RenderedOp>,
    },
}

impl Fetching {
    fn into_fetch(self, key: &Key) -> Arc<Fetch> {
        match self {
            Fetching::Ready(fetch) => fetch,
            Fetching::Sent {
                proxy,
                path_and_query,
                headers,
                header_down,
            } => Arc::new(Fetch {
                proxy,
                path_and_query: path_and_query.unwrap_or_else(|| key.uri.clone()),
                headers: background_headers(headers),
                header_down,
            }),
        }
    }
}

/// The worker (src/background.rs): stores answers and revalidates entries, and once a minute
/// drops the entries past every window and says how many jobs its queue could not take.
static WORKER: LazyLock<Worker<Job>> = LazyLock::new(|| {
    Worker::start(
        "web-cache",
        QUEUE,
        0,
        Duration::from_secs(60),
        |job| async move {
            match job {
                Job::Store(pending, pieces) => store(*pending, pieces).await,
                Job::Revalidate(entry) => revalidate(entry).await,
            }
        },
        |dropped| {
            STORE.sweep(Instant::now());
            if dropped > 0 {
                tracing::warn!(
                    dropped,
                    "proxy cache: answers not stored or revalidated, its queue was full"
                );
            }
        },
    )
});

fn submit(job: Job) {
    let _ = WORKER.submit(job);
}

impl Cache {
    pub fn new(settings: Settings) -> Cache {
        LazyLock::force(&WORKER);
        Cache {
            settings: Arc::new(Configured::new(settings)),
        }
    }

    /// The directive's step: `Some` answers from the cache; `None` lets the request go on, marked
    /// for the proxy when its response may be kept.
    pub async fn check(&self, ctx: &mut Ctx) -> Option<Response<Body>> {
        if ctx.req.extensions.get::<crate::memo::Preparing>().is_some() || MAX_MEMORY.load(Ordering::Relaxed) == 0 {
            return None;
        }
        // A cheap copy (shared bytes): the checks on a hit borrow the request mutably.
        let path_and_query = ctx.req.uri.path_and_query().cloned();
        let uri = path_and_query.as_ref().map_or("/", |pq| pq.as_str());
        if self.settings.exclude.as_ref().is_some_and(|re| re.is_match(uri)) {
            return None;
        }
        let https = ctx.conn.tls;
        let hash = STORE.hash(https, ctx.hostport(), uri);
        let method = ctx.req.method.clone();
        if method != Method::GET && method != Method::HEAD {
            // A request that may change the resource: what is stored for it is no longer to be
            // trusted (RFC 9111 §4.4).
            if !matches!(method, Method::OPTIONS | Method::TRACE) {
                STORE.remove(hash, https, ctx.hostport(), uri);
            }
            return None;
        }
        let headers = &ctx.req.headers;
        // Event streams and protocol switches are never kept (as Souin); ranges are the
        // upstream's to answer.
        if headers.contains_key(UPGRADE)
            || headers.contains_key(RANGE)
            || headers
                .get(ACCEPT)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("text/event-stream"))
        {
            return None;
        }
        let asked = Directives::of(headers);
        let now = Instant::now();
        let mut forced = asked.no_cache;
        let mut fallback = None;
        if let Some(entry) = STORE.get(hash, https, ctx.hostport(), uri) {
            let age = entry.age(now);
            if asked.max_age.is_some_and(|max| age.as_secs() > max) {
                forced = true;
            }
            let fresh = entry.freshness.fresh;
            if !forced
                && age < fresh + entry.freshness.while_revalidating
                && let Some(refusal) = refused(ctx, &entry).await
            {
                return Some(refusal);
            }
            if !forced && age < fresh {
                return Some(entry.answer(ctx, now, None));
            }
            if !forced && age < fresh + entry.freshness.while_revalidating {
                entry.revalidate();
                return Some(entry.answer(ctx, now, Some(None)));
            }
            if age < fresh + entry.freshness.if_error {
                fallback = Some(entry);
            }
        }
        if asked.only_if_cached {
            return Some(ctx.status(StatusCode::GATEWAY_TIMEOUT));
        }
        let store = method == Method::GET && !asked.no_store;
        let credentialed = ctx.req.extensions.get::<crate::handler::Credentialed>().is_some();
        // The miss is boxed once, by the extensions; its key shares the request's texts.
        ctx.req.extensions.insert(PendingMiss(Miss {
            key: Keyed::Asked {
                hash,
                https,
                hostport: HostPort::of(&ctx.req),
                uri: path_and_query,
            },
            settings: self.settings.clone(),
            store,
            forced,
            credentialed,
            encode: None,
            fallback,
        }));
        None
    }
}

/// The request checks bound to the upstream a stored response came from (src/jwt, src/apifw:
/// `upstreams`): a stored answer goes only to a request that would have passed them on its way
/// there. `Some`: the refusal to answer with.
async fn refused(ctx: &mut Ctx, entry: &Entry) -> Option<Response<Body>> {
    let hooks = ctx.upstream_hooks?;
    let body = ctx.body.take().unwrap_or_else(crate::body::empty);
    let client = crate::extensions::Client {
        ip: ctx.client_ip,
        conn: &ctx.conn,
        at: crate::extensions::At::Hit,
    };
    match hooks
        .check(&mut ctx.req, body, client, &entry.fetch.proxy.upstreams)
        .await
    {
        Ok((body, _held)) => {
            ctx.body = Some(body);
            None
        }
        Err(response) => Some(ctx.respond(response)),
    }
}

impl Miss {
    /// The upstream answered: `Cache-Status` and `default_cache_control` on its response, and when
    /// it may be kept, its body passes through a tee that hands it to the worker once whole.
    pub fn tee(
        self,
        proxy: &Arc<ReverseProxy>,
        path_and_query: &str,
        sent: &HeaderMap,
        header_down: &[RenderedOp],
        parts: &mut http::response::Parts,
        body: Body,
    ) -> Body {
        if !parts.headers.contains_key(CACHE_CONTROL)
            && let Some(value) = &self.settings.default_cache_control
        {
            parts.headers.insert(CACHE_CONTROL, value.clone());
        }
        // A request whose credentials were checked here, its token perhaps taken off before the
        // upstream: kept only when the response says it may be shared (RFC 9111 §3.5).
        let shared = || {
            let cc = Directives::of(&parts.headers);
            cc.public || cc.s_maxage.is_some() || cc.must_revalidate
        };
        let decided = if self.store && (!self.credentialed || shared()) {
            storable(parts.status, &parts.headers, sent, &self.settings)
        } else {
            None
        };
        let Some(freshness) = decided else {
            self.settings.add_miss_status(&mut parts.headers, self.forced, false);
            return body;
        };
        self.settings.add_miss_status(&mut parts.headers, self.forced, true);
        // What the worker needs and the proxy lends: copied here (the response's headers go on to
        // the client; the sent ones and `header_down` are the proxy's). The path is most often the
        // one asked for, shared in the key already.
        let pending = Pending {
            status: parts.status,
            headers: parts.headers.clone(),
            freshness,
            received: Instant::now(),
            fetch: Fetching::Sent {
                proxy: proxy.clone(),
                path_and_query: (path_and_query != self.key.uri()).then(|| path_and_query.into()),
                headers: sent.clone(),
                header_down: header_down.to_vec(),
            },
            miss: self,
        };
        let cap = pending.miss.settings.max_body();
        crate::body::boxed(Tee {
            inner: body,
            pieces: Vec::new(),
            size: 0,
            cap,
            pending: Some(pending),
        })
    }

    /// The upstream failed (or answered 5xx): a stored response within its stale-if-error window
    /// answers instead.
    pub fn fallback(&mut self, ctx: &mut Ctx, upstream: StatusCode) -> Option<Response<Body>> {
        let entry = self.fallback.take()?;
        Some(entry.answer(ctx, Instant::now(), Some(Some(upstream))))
    }
}

/// Whether a response may be kept, and for how long: from its headers and the request's.
fn storable(status: StatusCode, headers: &HeaderMap, sent: &HeaderMap, settings: &Settings) -> Option<Freshness> {
    if status != StatusCode::OK || headers.contains_key(SET_COOKIE) || headers.contains_key(CONTENT_RANGE) {
        return None;
    }
    // Only Accept-Encoding may vary: the encodings are the cache's own.
    let vary_ok = headers.get_all(VARY).iter().all(|v| {
        v.to_str().is_ok_and(|v| {
            v.split(',')
                .all(|f| f.trim().eq_ignore_ascii_case("accept-encoding") || f.trim().is_empty())
        })
    });
    if !vary_ok {
        return None;
    }
    if headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| starts_with_ignore_case(v.trim_start(), "text/event-stream"))
        || crate::encode::incremental(headers)
    {
        return None;
    }
    match headers.get(CONTENT_ENCODING).map(|v| v.to_str().unwrap_or("?").trim()) {
        None => {}
        Some(coding) if coding.eq_ignore_ascii_case("identity") || Encoding::parse_ignore_case(coding).is_some() => {}
        Some(_) => return None,
    }
    let max_body = settings.max_body();
    if headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|len| len > max_body as u64)
    {
        return None;
    }
    let cc = Directives::of(headers);
    if cc.no_store || cc.private || cc.no_cache {
        return None;
    }
    // A response to a request with credentials only when it says it may be shared (RFC 9111 §3.5).
    if sent.contains_key(AUTHORIZATION) && !(cc.public || cc.s_maxage.is_some() || cc.must_revalidate) {
        return None;
    }
    let lifetime = match (cc.s_maxage, cc.max_age) {
        (Some(s), _) => Duration::from_secs(s),
        (None, Some(m)) => Duration::from_secs(m),
        (None, None) => match headers.get(EXPIRES) {
            Some(expires) => {
                let date = headers
                    .get(DATE)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| httpdate::parse_http_date(v).ok())
                    .unwrap_or_else(SystemTime::now);
                expires
                    .to_str()
                    .ok()
                    .and_then(|v| httpdate::parse_http_date(v).ok())
                    .and_then(|at| at.duration_since(date).ok())
                    .unwrap_or(Duration::ZERO)
            }
            None => settings.ttl,
        },
    };
    let initial_age = Duration::from_secs(
        headers
            .get(AGE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0),
    );
    let (while_revalidating, if_error) = if cc.must_revalidate {
        (Duration::ZERO, Duration::ZERO)
    } else {
        let window = |own: Option<u64>| settings.stale.max(Duration::from_secs(own.unwrap_or(0)));
        (window(cc.stale_while_revalidate), window(cc.stale_if_error))
    };
    let fresh = lifetime.saturating_sub(initial_age);
    if fresh.is_zero() && while_revalidating.is_zero() && if_error.is_zero() {
        return None;
    }
    Some(Freshness {
        fresh,
        initial_age,
        while_revalidating,
        if_error,
    })
}

/// The request headers background requests send: those of the request that filled the entry,
/// without its client's address, credentials, cookies, conditions and range.
fn background_headers(mut headers: HeaderMap) -> HeaderMap {
    for name in [
        AUTHORIZATION,
        COOKIE,
        IF_MATCH,
        IF_NONE_MATCH,
        IF_MODIFIED_SINCE,
        IF_UNMODIFIED_SINCE,
        IF_RANGE,
        RANGE,
        CACHE_CONTROL,
    ] {
        headers.remove(name);
    }
    for name in ["x-forwarded-for", "x-real-ip", "forwarded"] {
        headers.remove(name);
    }
    headers
}

/// The upstream's body on its way to the client, its frames kept on the side up to the cap.
struct Tee {
    inner: Body,
    /// Room is made at the first frame: a body that fails before one costs none.
    pieces: Vec<Bytes>,
    size: usize,
    cap: usize,
    pending: Option<Pending>,
}

impl Tee {
    fn give_up(&mut self) {
        self.pending = None;
        self.pieces = Vec::new();
    }

    fn keep(&mut self, data: &Bytes) {
        if self.pieces.capacity() == 0 {
            // Most bodies come in one or two frames.
            self.pieces.reserve_exact(2);
        }
        self.pieces.push(data.clone());
    }

    fn hand_over(&mut self) {
        if let Some(pending) = self.pending.take() {
            submit(Job::Store(Box::new(pending), std::mem::take(&mut self.pieces)));
        }
    }
}

impl http_body::Body for Tee {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) if this.pending.is_some() => match frame.data_ref() {
                Some(data) => {
                    this.size += data.len();
                    if this.size > this.cap {
                        this.give_up();
                    } else {
                        if !data.is_empty() {
                            this.keep(data);
                        }
                        // hyper stops polling a body that says it has ended.
                        if this.inner.is_end_stream() {
                            this.hand_over();
                        }
                    }
                }
                // Trailers: not kept.
                None => this.give_up(),
            },
            Poll::Ready(Some(Err(_))) => this.give_up(),
            Poll::Ready(None) => this.hand_over(),
            _ => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for Tee {
    fn drop(&mut self) {
        // Dropped after its last frame without being polled again: whole all the same.
        if http_body::Body::is_end_stream(&self.inner) {
            self.hand_over();
        }
    }
}

impl Store {
    /// The hash of a key: the host in any ASCII case.
    fn hash(&self, https: bool, hostport: &str, uri: &str) -> u64 {
        let mut hasher = self.hasher.build_hasher();
        hasher.write_u8(u8::from(https));
        // The host lowercased on the stack and written at once: a write is a mixing round, one per
        // byte would be as many. A host longer than the buffer (not one that resolves) goes byte
        // by byte.
        let mut lower = [0u8; 256];
        if let Some(lower) = lower.get_mut(..hostport.len()) {
            for (to, from) in lower.iter_mut().zip(hostport.bytes()) {
                *to = from.to_ascii_lowercase();
            }
            hasher.write(lower);
        } else {
            for b in hostport.bytes() {
                hasher.write_u8(b.to_ascii_lowercase());
            }
        }
        hasher.write_u8(0xff);
        hasher.write(uri.as_bytes());
        hasher.finish()
    }

    fn shard(&self, hash: u64) -> std::sync::MutexGuard<'_, FxHashMap<u64, Arc<Entry>>> {
        self.shards[(hash as usize) % SHARDS]
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn get(&self, hash: u64, https: bool, hostport: &str, uri: &str) -> Option<Arc<Entry>> {
        let shard = self.shard(hash);
        let entry = shard.get(&hash).filter(|e| e.key.is(https, hostport, uri))?;
        // Written once per round, not on every hit: a store dirties the line for every thread.
        if !entry.touched.load(Ordering::Relaxed) {
            entry.touched.store(true, Ordering::Relaxed);
        }
        Some(entry.clone())
    }

    fn remove(&self, hash: u64, https: bool, hostport: &str, uri: &str) {
        let removed = {
            let mut shard = self.shard(hash);
            if shard.get(&hash).is_some_and(|e| e.key.is(https, hostport, uri)) {
                shard.remove(&hash)
            } else {
                None
            }
        };
        if let Some(old) = removed {
            self.release(old.size);
        }
    }

    /// Takes `entry` out, when it is still the one in place.
    fn evict(&self, entry: &Arc<Entry>) {
        if self.take(entry) {
            self.release(entry.size);
        }
    }

    /// Removes `entry` from its shard when it is still the one in place; the budget is told by
    /// the caller (never under the shard's lock: the budget's pass takes shards itself).
    fn take(&self, entry: &Arc<Entry>) -> bool {
        let mut shard = self.shard(entry.key.hash);
        if shard.get(&entry.key.hash).is_some_and(|e| Arc::ptr_eq(e, entry)) {
            shard.remove(&entry.key.hash);
            true
        } else {
            false
        }
    }

    fn release(&self, size: usize) {
        self.budget.lock().unwrap_or_else(PoisonError::into_inner).release(size);
    }

    /// Puts an entry in place (replacing its key's), then evicts until the entries fit
    /// (src/background.rs `Budget`: CLOCK, an entry asked for since the last pass gets another
    /// round).
    fn insert(&self, entry: Arc<Entry>) {
        let max = MAX_MEMORY.load(Ordering::Relaxed);
        if entry.size > max {
            return;
        }
        let replaced = self.shard(entry.key.hash).insert(entry.key.hash, entry.clone());
        let mut budget = self.budget.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(old) = replaced {
            budget.release(old.size);
        }
        budget.add(Arc::downgrade(&entry), entry.size);
        budget.evict(max, |weak| match weak.upgrade() {
            None => Seen::Gone,
            Some(candidate) if candidate.touched.swap(false, Ordering::Relaxed) => Seen::Marked,
            Some(candidate) => {
                if self.take(&candidate) {
                    Seen::Evicted(candidate.size)
                } else {
                    Seen::Gone
                }
            }
        });
    }

    /// Drops the entries past every window, and the order's dead references.
    fn sweep(&self, now: Instant) {
        let mut released = 0;
        for shard in &self.shards {
            let mut shard = shard.0.lock().unwrap_or_else(PoisonError::into_inner);
            shard.retain(|_, entry| {
                let keep = entry.age(now)
                    < entry.freshness.fresh + entry.freshness.while_revalidating.max(entry.freshness.if_error);
                if !keep {
                    released += entry.size;
                }
                keep
            });
        }
        let mut budget = self.budget.lock().unwrap_or_else(PoisonError::into_inner);
        budget.release(released);
        budget.retain(|weak| weak.strong_count() > 0);
    }
}

/// Whether the response at `hostport` + `path_and_query` (plain HTTP) is in the cache — for tests
/// and diagnostics.
pub fn is_stored(hostport: &str, path_and_query: &str) -> bool {
    STORE
        .get(
            STORE.hash(false, hostport, path_and_query),
            false,
            hostport,
            path_and_query,
        )
        .is_some()
}

impl Entry {
    fn age(&self, now: Instant) -> Duration {
        self.freshness.initial_age + now.saturating_duration_since(self.received)
    }

    /// The answer from the entry. `stale`: `None` when fresh; `Some(None)` while it is
    /// revalidated; `Some(Some(status))` in place of the upstream's failure.
    fn answer(&self, ctx: &mut Ctx, now: Instant, stale: Option<Option<StatusCode>>) -> Response<Body> {
        let age = self.age(now);
        let accept = ctx.accept_encoding();
        let encoding = accept.ranked(&self.offer).find(|e| self.encoded[*e as usize].is_some());
        let variant = encoding
            .and_then(|e| self.encoded[e as usize].as_ref())
            .unwrap_or(&self.identity);
        // With room for the fields added below (ETag, Vary, Age, Cache-Status, Content-Length,
        // Content-Encoding): a clone has none, and would grow on the way. The values of the
        // variant's own are ready (`Variant`), as is a small Age.
        let mut headers = HeaderMap::with_capacity(self.headers.len() + 6);
        headers.extend(self.headers.iter().map(|(name, value)| (name.clone(), value.clone())));
        let etag = variant.etag.as_ref();
        if let Some(etag) = etag {
            headers.insert(ETAG, etag.clone());
        }
        if self.vary {
            headers.append(VARY, HeaderValue::from_static("Accept-Encoding"));
        }
        headers.insert(AGE, header_small(age.as_secs()));
        let ttl = self.freshness.fresh.as_secs() as i64 - age.as_secs() as i64;
        let mut status = crate::handler::HeaderText::new();
        {
            use std::fmt::Write as _;
            let name = &self.settings.name;
            let _ = match stale {
                None => write!(status, "{name}; hit; ttl={ttl}"),
                Some(None) => write!(status, "{name}; hit; ttl={ttl}; fwd=stale"),
                Some(Some(upstream)) => {
                    write!(
                        status,
                        "{name}; hit; ttl={ttl}; fwd=stale; fwd-status={}",
                        upstream.as_u16()
                    )
                }
            };
        }
        if let Some(value) = status.value() {
            headers.append(CACHE_STATUS.clone(), value);
        }
        let request = &ctx.req.headers;
        let not_modified = match request.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
            Some(list) => etag.is_some_and(|etag| crate::static_files::etag_list_matches(list, etag, false)),
            None => match (
                request.get(IF_MODIFIED_SINCE).and_then(|v| v.to_str().ok()),
                self.last_modified.as_ref().and_then(|v| v.to_str().ok()),
            ) {
                (Some(since), Some(modified)) => {
                    match (httpdate::parse_http_date(since), httpdate::parse_http_date(modified)) {
                        (Ok(since), Ok(modified)) => modified <= since,
                        _ => false,
                    }
                }
                _ => false,
            },
        };
        let mut response = if not_modified {
            let mut response = Response::new(crate::body::empty());
            *response.status_mut() = StatusCode::NOT_MODIFIED;
            response
        } else {
            headers.insert(CONTENT_LENGTH, variant.content_length.clone());
            if let Some(encoding) = encoding {
                headers.insert(CONTENT_ENCODING, HeaderValue::from_static(encoding.name()));
            }
            let mut response = Response::new(if ctx.req.method == Method::HEAD {
                crate::body::empty()
            } else {
                crate::body::full(variant.body.clone())
            });
            *response.status_mut() = self.status;
            response
        };
        *response.headers_mut() = headers;
        ctx.respond_appending(response)
    }

    /// Starts a background revalidation unless one is under way (or the queue is full: then a
    /// later request tries again).
    fn revalidate(self: &Arc<Self>) {
        if !self.revalidating.swap(true, Ordering::AcqRel) && WORKER.submit(Job::Revalidate(self.clone())).is_err() {
            self.revalidating.store(false, Ordering::Release);
        }
    }
}

/// The worker: a thread with a runtime of its own, storing and revalidating one job at a time.
/// A whole response from the tee: decoded, encoded as the site's `encode` lists, stored.
async fn store(pending: Pending, pieces: Vec<Bytes>) {
    let raw = join(pieces);
    if let Some(entry) = build(pending, raw).await {
        STORE.insert(Arc::new(entry));
    }
}

fn join(mut pieces: Vec<Bytes>) -> Bytes {
    if pieces.len() == 1 {
        return pieces.pop().unwrap_or_default();
    }
    let mut joined = BytesMut::with_capacity(pieces.iter().map(Bytes::len).sum());
    for piece in pieces {
        joined.extend_from_slice(&piece);
    }
    joined.freeze()
}

async fn build(pending: Pending, raw: Bytes) -> Option<Entry> {
    let Pending {
        miss,
        status,
        mut headers,
        freshness,
        received,
        fetch,
    } = pending;
    let Miss {
        key, settings, encode, ..
    } = miss;
    // The entry's own copies of the key's texts and of how to fetch it again, made here and not
    // on the connection's thread.
    let key = key.into_key();
    let fetch = fetch.into_fetch(&key);
    let cap = settings.max_body();
    let origin = headers
        .get(CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| Encoding::parse_ignore_case(v.trim()));
    let identity = match origin {
        Some(encoding) => match decode(encoding, &raw, cap, 0) {
            Some(identity) => identity,
            None => {
                tracing::debug!(uri = %key.uri, "not stored: its body does not decode within max_cacheable_body_bytes");
                return None;
            }
        },
        None => raw.clone(),
    };
    let offer: Vec<Encoding> = match &encode {
        Some(encode) if encodes(encode, status, &headers, identity.len()) => encode.formats.clone(),
        _ => origin.into_iter().collect(),
    };
    let etag = headers.remove(ETAG);
    let mut encoded: [Option<Variant>; 3] = [None, None, None];
    for &encoding in &offer {
        let variant = if Some(encoding) == origin {
            Some(raw.clone())
        } else {
            let theirs = if origin.is_some() {
                fetch_encoded(&fetch, encoding, &identity, cap).await
            } else {
                None
            };
            match theirs {
                Some(theirs) => Some(theirs),
                None => {
                    let input = identity.clone();
                    tokio::task::spawn_blocking(move || crate::encode::compress_best(encoding, &input))
                        .await
                        .ok()
                        .and_then(Result::ok)
                }
            }
        };
        // Only an encoding that saves something is offered.
        encoded[encoding as usize] = variant
            .filter(|v| v.len() < identity.len() || Some(encoding) == origin)
            .map(|body| Variant::new(body, etag.as_ref(), origin, Some(encoding)));
    }
    let last_modified = headers.get(LAST_MODIFIED).cloned();
    for name in [CONTENT_LENGTH, CONTENT_ENCODING, TRANSFER_ENCODING, AGE] {
        headers.remove(name);
    }
    headers.remove(&CACHE_STATUS);
    let header_bytes: usize = headers.iter().map(|(n, v)| n.as_str().len() + v.len() + 32).sum();
    let size = identity.len()
        + encoded.iter().flatten().map(|v| v.body.len()).sum::<usize>()
        + header_bytes
        + key.hostport.len()
        + key.uri.len()
        + 512;
    let vary = !offer.is_empty() && !has_vary(&headers, "accept-encoding");
    Some(Entry {
        key,
        status,
        headers,
        identity: Variant::new(identity, etag.as_ref(), origin, None),
        etag,
        last_modified,
        origin,
        encoded,
        offer,
        vary,
        encode,
        received,
        freshness,
        size,
        touched: AtomicBool::new(false),
        revalidating: AtomicBool::new(false),
        fetch,
        settings,
    })
}

/// Whether `encode` would compress this response (its types, its minimum length, its statuses).
fn encodes(encode: &Encode, status: StatusCode, headers: &HeaderMap, len: usize) -> bool {
    if (len as u64) < encode.minimum_length {
        return false;
    }
    if !encode.statuses.is_empty()
        && !encode
            .statuses
            .iter()
            .any(|(lo, hi)| (*lo..=*hi).contains(&status.as_u16()))
    {
        return false;
    }
    if headers
        .get_all(CACHE_CONTROL)
        .iter()
        .any(|v| contains_ignore_case(v.as_bytes(), b"no-transform"))
    {
        return false;
    }
    let Some(content_type) = headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    types_match(encode.types.iter().map(String::as_str), content_type)
}

/// Decodes a body, giving up past `cap` bytes; `expected`: the length it should have, when known
/// (0: not known), for a buffer of that size at once. The bytes may be kept in the cache: they hold
/// no more memory than their length (`exact`).
fn decode(encoding: Encoding, data: &[u8], cap: usize, expected: usize) -> Option<Bytes> {
    let mut out = Vec::with_capacity(expected.min(cap));
    let limit = cap as u64 + 1;
    let read = match encoding {
        Encoding::Gzip => flate2::read::MultiGzDecoder::new(data)
            .take(limit)
            .read_to_end(&mut out),
        Encoding::Br => brotli::Decompressor::new(data, 4096).take(limit).read_to_end(&mut out),
        Encoding::Zstd => zstd::stream::read::Decoder::new(data).and_then(|d| d.take(limit).read_to_end(&mut out)),
    };
    (read.is_ok() && out.len() <= cap).then(|| crate::encode::exact(out))
}

/// The upstream's own body in `encoding`, when it has one that decodes to the same content.
async fn fetch_encoded(fetch: &Fetch, encoding: Encoding, identity: &Bytes, cap: usize) -> Option<Bytes> {
    let mut headers = fetch.headers.clone();
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static(encoding.name()));
    let response = fetch.proxy.fetch(&fetch.path_and_query, headers).await.ok()?;
    let theirs = response
        .headers()
        .get(CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case(encoding.name()));
    if response.status() != StatusCode::OK || !theirs {
        return None;
    }
    let body = collect(response.into_body(), cap).await?;
    // The same content is the identity's length: decoded into a buffer of that size, and given up
    // as soon as it is longer (not at `cap`: a small identity's look-alike cannot expand to it).
    let same = decode(encoding, &body, identity.len(), identity.len()).is_some_and(|decoded| decoded == *identity);
    same.then_some(body)
}

/// A body whole, or `None` past `cap` bytes or on an error.
async fn collect<B>(mut body: B, cap: usize) -> Option<Bytes>
where
    B: http_body::Body<Data = Bytes> + Unpin,
{
    let mut pieces = Vec::new();
    let mut size = 0;
    while let Some(frame) = body.frame().await {
        let frame = frame.ok()?;
        if let Some(data) = frame.data_ref() {
            size += data.len();
            if size > cap {
                return None;
            }
            pieces.push(data.clone());
        }
    }
    Some(join(pieces))
}

/// A conditional request for a stale entry: 304 refreshes it, 200 replaces it, an answer that may
/// not be stored removes it; a failure leaves it (stale-if-error) and is tried again after a while.
async fn revalidate(entry: Arc<Entry>) {
    let fetch = &entry.fetch;
    let mut headers = fetch.headers.clone();
    if let Some(etag) = &entry.etag {
        headers.insert(IF_NONE_MATCH, etag.clone());
    }
    if let Some(modified) = &entry.last_modified {
        headers.insert(IF_MODIFIED_SINCE, modified.clone());
    }
    let retry_later = |entry: Arc<Entry>| {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            entry.revalidating.store(false, Ordering::Release);
        });
    };
    let response = match fetch.proxy.fetch(&fetch.path_and_query, headers).await {
        Ok(response) => response,
        Err(error) => {
            tracing::debug!(uri = %entry.key.uri, %error, "revalidation failed; the stored response stays");
            retry_later(entry);
            return;
        }
    };
    let received = Instant::now();
    // The answer's headers as the proxy gives them to clients.
    let (mut parts, body) = response.into_parts();
    crate::proxy::remove_hop_headers(&mut parts.headers);
    for op in &fetch.header_down {
        op.apply(&mut parts.headers);
    }
    match parts.status {
        StatusCode::NOT_MODIFIED => {
            // The stored headers, updated with the 304's (RFC 9111 §4.3.4).
            let mut merged = entry.headers.clone();
            for name in parts.headers.keys() {
                if [CONTENT_LENGTH, CONTENT_ENCODING, TRANSFER_ENCODING, ETAG, VARY].contains(name)
                    || *name == CACHE_STATUS
                {
                    continue;
                }
                merged.remove(name);
                for value in parts.headers.get_all(name) {
                    merged.append(name.clone(), value.clone());
                }
            }
            let Some(freshness) = storable(entry.status, &merged, &fetch.headers, &entry.settings) else {
                STORE.evict(&entry);
                return;
            };
            STORE.insert(Arc::new(Entry {
                key: entry.key.clone(),
                status: entry.status,
                headers: merged,
                etag: entry.etag.clone(),
                last_modified: entry.last_modified.clone(),
                origin: entry.origin,
                identity: entry.identity.clone(),
                encoded: entry.encoded.clone(),
                offer: entry.offer.clone(),
                // Vary is kept as it was (not merged above).
                vary: entry.vary,
                encode: entry.encode.clone(),
                received,
                freshness,
                size: entry.size,
                touched: AtomicBool::new(true),
                revalidating: AtomicBool::new(false),
                fetch: entry.fetch.clone(),
                settings: entry.settings.clone(),
            }));
        }
        status if status.is_server_error() => {
            retry_later(entry);
        }
        status => {
            if !parts.headers.contains_key(CACHE_CONTROL)
                && let Some(value) = &entry.settings.default_cache_control
            {
                parts.headers.insert(CACHE_CONTROL, value.clone());
            }
            let Some(freshness) = storable(status, &parts.headers, &fetch.headers, &entry.settings) else {
                STORE.evict(&entry);
                return;
            };
            let Some(raw) = collect(body, entry.settings.max_body()).await else {
                STORE.evict(&entry);
                return;
            };
            let pending = Pending {
                miss: Miss {
                    key: Keyed::Known(entry.key.clone()),
                    settings: entry.settings.clone(),
                    store: true,
                    forced: false,
                    // Stored before as shared, or the request had no credentials.
                    credentialed: false,
                    encode: entry.encode.clone(),
                    fallback: None,
                },
                status,
                headers: parts.headers,
                freshness,
                received,
                fetch: Fetching::Ready(entry.fetch.clone()),
            };
            match build(pending, raw).await {
                Some(fresh) => STORE.insert(Arc::new(fresh)),
                None => STORE.evict(&entry),
            }
        }
    }
}

/// The cache at a `reverse_proxy` (src/extensions.rs `ProxyObserver`): takes the miss the `cache`
/// directive left on the request, answers stale for a failing upstream, and keeps the response.
pub struct Observer;

impl crate::extensions::ProxyObserver for Observer {
    type Pending = Option<Miss>;

    fn begin(&self, ctx: &mut Ctx) -> Self::Pending {
        let mut miss = ctx.req.extensions.remove::<PendingMiss>().map(|m| m.0);
        if let Some(miss) = miss.as_mut() {
            // The site's `encode` the request passed: what a kept answer is compressed with.
            miss.encode = ctx.encode.clone();
            if ctx.req.extensions.get::<crate::handler::Credentialed>().is_some() {
                miss.credentialed = true;
            }
        }
        miss
    }

    fn fallback(&self, pending: &mut Self::Pending, ctx: &mut Ctx, status: StatusCode) -> Option<Response<Body>> {
        pending.as_mut().and_then(|miss| miss.fallback(ctx, status))
    }

    /// A miss stores what the upstream answered, by the headers it was asked with.
    fn wants_sent(&self, pending: &Self::Pending) -> bool {
        pending.is_some()
    }

    fn observe(
        &self,
        pending: Self::Pending,
        sent: crate::extensions::Sent<'_>,
        parts: &mut http::response::Parts,
        body: Body,
    ) -> Body {
        match pending {
            Some(miss) => miss.tee(
                sent.proxy,
                sent.path_and_query,
                sent.headers,
                sent.header_down,
                parts,
                body,
            ),
            None => body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn what_may_be_stored_and_for_how_long() {
        let settings = Settings::default();
        let none = HeaderMap::new();
        let fresh = |pairs: &[(&'static str, &str)]| storable(StatusCode::OK, &headers(pairs), &none, &settings);
        assert_eq!(
            fresh(&[("cache-control", "max-age=60")]).unwrap().fresh,
            Duration::from_secs(60)
        );
        assert_eq!(
            fresh(&[("cache-control", "max-age=60, s-maxage=30")]).unwrap().fresh,
            Duration::from_secs(30)
        );
        assert_eq!(
            fresh(&[("cache-control", "max-age=60"), ("age", "50")]).unwrap().fresh,
            Duration::from_secs(10)
        );
        assert_eq!(
            fresh(&[]).unwrap().fresh,
            Duration::from_secs(120),
            "no lifetime: the ttl"
        );
        for refused in [
            &[("cache-control", "private, max-age=60")][..],
            &[("cache-control", "no-store")],
            &[("cache-control", "no-cache")],
            &[("set-cookie", "a=1")],
            &[("vary", "Cookie")],
            &[("vary", "*")],
            &[("content-type", "text/event-stream")],
            &[("incremental", "?1")],
            &[("content-encoding", "deflate")],
            &[("cache-control", "max-age=0")],
        ] {
            assert!(fresh(refused).is_none(), "{refused:?}");
        }
        assert!(fresh(&[("vary", "accept-encoding")]).is_some());
        assert!(storable(StatusCode::NOT_FOUND, &none, &none, &settings).is_none());
        // Credentials: only what says it may be shared.
        let auth = headers(&[("authorization", "Bearer x")]);
        assert!(
            storable(
                StatusCode::OK,
                &headers(&[("cache-control", "max-age=60")]),
                &auth,
                &settings
            )
            .is_none()
        );
        assert!(
            storable(
                StatusCode::OK,
                &headers(&[("cache-control", "public, max-age=60")]),
                &auth,
                &settings
            )
            .is_some()
        );
        // The stale windows: the setting, or the response's own; none after must-revalidate.
        let stale = Settings {
            stale: Duration::from_secs(30),
            ..Settings::default()
        };
        let windows = storable(
            StatusCode::OK,
            &headers(&[("cache-control", "max-age=1, stale-if-error=600")]),
            &none,
            &stale,
        )
        .unwrap();
        assert_eq!(windows.while_revalidating, Duration::from_secs(30));
        assert_eq!(windows.if_error, Duration::from_secs(600));
        let strict = storable(
            StatusCode::OK,
            &headers(&[("cache-control", "max-age=1, must-revalidate")]),
            &none,
            &stale,
        )
        .unwrap();
        assert!(strict.while_revalidating.is_zero() && strict.if_error.is_zero());
    }

    #[test]
    fn directives_are_read_in_any_case_without_a_copy() {
        let d = Directives::of(&headers(&[
            ("cache-control", "No-Store, MAX-AGE=\"5\" , Public"),
            ("cache-control", "s-maxage, Stale-While-Revalidate=7, Proxy-Revalidate"),
        ]));
        assert!(d.no_store && d.public && d.must_revalidate);
        assert!(!d.no_cache && !d.private && !d.only_if_cached);
        assert_eq!(d.max_age, Some(5));
        assert_eq!(d.s_maxage, Some(0), "no argument: 0");
        assert_eq!(d.stale_while_revalidate, Some(7));
        assert_eq!(d.stale_if_error, None);
    }

    #[test]
    fn the_cache_status_of_a_miss_is_made_once() {
        let configured = Configured::new(Settings::default());
        let status = |forced, stored| {
            let mut map = HeaderMap::new();
            configured.add_miss_status(&mut map, forced, stored);
            map.get(&CACHE_STATUS).unwrap().to_str().unwrap().to_string()
        };
        assert_eq!(status(false, false), "webfast; fwd=uri-miss");
        assert_eq!(status(true, false), "webfast; fwd=request");
        assert_eq!(status(false, true), "webfast; fwd=uri-miss; stored");
        assert_eq!(status(true, true), "webfast; fwd=request; stored");
        // A name no header value can hold: no Cache-Status, rather than a wrong one.
        let odd = Configured::new(Settings {
            name: Arc::from("two\nlines"),
            ..Settings::default()
        });
        let mut map = HeaderMap::new();
        odd.add_miss_status(&mut map, false, true);
        assert!(map.is_empty());
    }

    #[test]
    fn small_numbers_are_ready_as_header_values() {
        for n in [0, 1, 9, 10, 99, 100, 999, 1000, 4095, 4096, 4097, 65536, u64::MAX] {
            assert_eq!(header_small(n), crate::handler::header_number(n), "{n}");
        }
        assert_eq!(DIGITS.len(), SMALL_NUMBERS.iter().map(HeaderValue::len).sum::<usize>());
    }

    #[test]
    fn the_hash_takes_the_host_in_any_case_at_any_length() {
        let store = Store {
            hasher: ahash::RandomState::new(),
            shards: Vec::new(),
            budget: Mutex::new(Budget::new()),
        };
        assert_eq!(
            store.hash(false, "Example.COM:8080", "/a"),
            store.hash(false, "example.com:8080", "/a")
        );
        assert_ne!(
            store.hash(false, "example.com", "/a"),
            store.hash(false, "example.org", "/a")
        );
        assert_ne!(
            store.hash(false, "example.com", "/a"),
            store.hash(true, "example.com", "/a")
        );
        assert_ne!(
            store.hash(false, "example.com", "/a"),
            store.hash(false, "example.com", "/b")
        );
        // Past the stack buffer: the same host still hashes alike, in either case.
        let long = "a".repeat(300);
        assert_eq!(
            store.hash(false, &long, "/"),
            store.hash(false, &long.to_ascii_uppercase(), "/")
        );
        assert_ne!(store.hash(false, &long, "/"), store.hash(false, &long[1..], "/"));
    }

    #[test]
    fn a_key_shares_the_requests_texts() {
        let mut parts = http::Request::builder()
            .uri("/p?q=1")
            .header("host", "Example.com")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let asked = Keyed::Asked {
            hash: 7,
            https: false,
            hostport: HostPort::of(&parts),
            uri: parts.uri.path_and_query().cloned(),
        };
        assert_eq!(asked.hostport(), "Example.com");
        assert_eq!(asked.uri(), "/p?q=1");
        // The entry's key: the same texts, its own.
        let key = asked.into_key();
        assert_eq!((key.hash, &*key.hostport, &*key.uri), (7, "Example.com", "/p?q=1"));
        assert!(key.is(false, "example.com", "/p?q=1"));
        assert!(!key.is(true, "example.com", "/p?q=1"));
        assert!(!key.is(false, "example.com", "/p"));
        let known = Keyed::Known(key.clone());
        assert_eq!((known.hostport(), known.uri()), ("Example.com", "/p?q=1"));
        assert_eq!(known.into_key().uri, key.uri);
        // An absolute-form URI names the host itself; no URI (`None`) is `/`.
        parts.uri = "http://Other.net".parse().unwrap();
        assert_eq!(HostPort::of(&parts).as_str(), "Other.net");
        assert_eq!(crate::handler::hostport_of(&parts), "Other.net");
        let root = Keyed::Asked {
            hash: 0,
            https: true,
            hostport: HostPort::of(&parts),
            uri: parts.uri.path_and_query().cloned(),
        };
        assert_eq!(root.uri(), "/");
        parts.headers.remove(HOST);
        parts.uri = "/".parse().unwrap();
        assert_eq!(HostPort::of(&parts).as_str(), "");
    }

    #[test]
    fn each_variant_has_its_own_etag() {
        let strong = HeaderValue::from_static("\"abc\"");
        let weak = HeaderValue::from_static("W/\"abc\"");
        let tag = |etag: &HeaderValue, origin, encoding| {
            etag_of(Some(etag), origin, encoding)
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap()
        };
        assert_eq!(tag(&strong, None, None), "\"abc\"", "the upstream's own representation");
        assert_eq!(tag(&strong, None, Some(Encoding::Gzip)), "\"abc.g\"");
        assert_eq!(tag(&strong, Some(Encoding::Br), Some(Encoding::Br)), "\"abc\"");
        assert_eq!(tag(&strong, Some(Encoding::Br), None), "\"abc.i\"");
        assert_eq!(tag(&weak, None, Some(Encoding::Zstd)), "W/\"abc\"", "weak: as it is");
        assert!(etag_of(None, None, None).is_none());
        let variant = Variant::new(Bytes::from_static(b"hello"), Some(&strong), None, Some(Encoding::Zstd));
        assert_eq!(variant.content_length, "5");
        assert_eq!(variant.etag.unwrap(), "\"abc.z\"");
    }

    #[test]
    fn bodies_decode_within_the_cap() {
        let text = "hello ".repeat(1000);
        for encoding in [Encoding::Gzip, Encoding::Br, Encoding::Zstd] {
            let packed = crate::encode::compress_best(encoding, text.as_bytes()).unwrap();
            assert!(packed.len() < text.len());
            assert_eq!(decode(encoding, &packed, 1 << 20, 0).unwrap(), text.as_bytes());
            assert_eq!(
                decode(encoding, &packed, text.len(), text.len()).unwrap(),
                text.as_bytes()
            );
            assert!(decode(encoding, &packed, 100, 0).is_none(), "{encoding:?} past the cap");
            assert!(
                decode(encoding, &packed, text.len() - 1, text.len() - 1).is_none(),
                "{encoding:?} longer"
            );
        }
    }
}
