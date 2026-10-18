//! Where the optional pieces (cargo features) plug into the request path: one trait per hook
//! point, and the hooks of a point composed at compile time from the features that are on
//! (docs/extensions.md).
//!
//! A point's hooks are a type, not a list: `()` where a feature is off (the call compiles to
//! nothing), `Option<T>` for a feature that is built but not configured (one test), and nested
//! pairs `(A, (B, ()))` for the order, which the core fixes here. No trait object, no boxed future:
//! a configured hook is a direct call, as the hand-written one was. The composed values are
//! `&'static` (one per process) or zero-sized constants, so a request copies a pointer at most.
//!
//! The `cfg` knowledge of the request path lives in this file; the hook points call the composed
//! types and know no extension by name.

use crate::body::Body;
use crate::config::Config;
use crate::encode::Encoding;
use crate::files::{FileEntry, FileStore};
use crate::handler::{ConnInfo, Ctx, RenderedOp};
use crate::proxy::ReverseProxy;
use anyhow::Result;
use http::uri::Authority;
use http::{HeaderMap, Response, StatusCode};
use std::net::IpAddr;
use std::sync::Arc;

/// What a hook learns of the client and of the moment it runs at.
#[derive(Debug, Clone, Copy)]
pub struct Client<'a> {
    pub ip: IpAddr,
    pub conn: &'a ConnInfo,
    pub at: At,
}

/// Where in the request's way a hook runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum At {
    /// Before the site's routes and ready answers.
    Routes,
    /// At a `reverse_proxy`, about to send the request to an upstream.
    Upstream,
    /// At a `cache` about to answer from memory: no upstream is called.
    Hit,
}

/// The body to go on with (the same bytes, when a check read it), or the answer that refuses.
pub type Checked = std::result::Result<Body, Response<Body>>;

/// On a refusing response: answered through the site's `handle_errors` routes, as a handler's
/// own failure is (a `reverse_proxy`'s 502, say); without it the response goes out as it is.
#[derive(Debug, Clone, Copy)]
pub struct ErrorPage;

/// Before the site's routes and ready answers: refuse, or let through (perhaps changed).
pub trait RequestCheck: Send + Sync {
    fn check(
        &self,
        req: &mut http::request::Parts,
        body: Body,
        client: Client<'_>,
    ) -> impl Future<Output = Checked> + Send;
}

/// Something a hook keeps for as long as the response lasts (a slot at the upstreams), composed
/// like the hooks; `is_empty`: nothing to keep, so the response body is not wrapped.
pub trait Held: Send + Unpin + 'static {
    fn nothing() -> Self;
    fn is_empty(&self) -> bool;
}

/// At a `reverse_proxy` (`At::Upstream`) or a `cache` hit (`At::Hit`), on the request as it goes
/// to one of `upstreams`.
pub trait UpstreamCheck: Send + Sync {
    type Held: Held;

    fn check(
        &self,
        req: &mut http::request::Parts,
        body: Body,
        client: Client<'_>,
        upstreams: &[Authority],
    ) -> impl Future<Output = std::result::Result<(Body, Self::Held), Response<Body>>> + Send;

    /// Whether this check has anything to do at a proxy at all (none: the proxies skip the call).
    fn bound(&self) -> bool;

    /// The upstreams it is bound to: each must be one a `reverse_proxy` sends to.
    fn upstreams(&self, out: &mut Vec<(Authority, &'static str)>);
}

/// What a `reverse_proxy` sent, for an observer that may ask the upstream again.
pub struct Sent<'a> {
    pub proxy: &'a Arc<ReverseProxy>,
    pub path_and_query: &'a str,
    pub headers: &'a HeaderMap,
    pub header_down: &'a [RenderedOp],
}

/// Sees a proxied response on its way to the client (the proxy cache keeps it).
pub trait ProxyObserver: Send + Sync {
    /// What the request carries for this observer, taken before the upstream is called.
    type Pending: Send;

    fn begin(&self, ctx: &mut Ctx) -> Self::Pending;

    /// The upstream answered a server error, or failed, with `status`: an answer to give instead
    /// (a stale one), or none.
    fn fallback(&self, pending: &mut Self::Pending, ctx: &mut Ctx, status: StatusCode) -> Option<Response<Body>>;

    /// The response as it goes out: its body, perhaps wrapped.
    fn observe(
        &self,
        pending: Self::Pending,
        sent: Sent<'_>,
        parts: &mut http::response::Parts,
        body: Body,
    ) -> Body;
}

/// What `file_server` has of a file in an encoding, when there is no precompressed sibling.
pub enum Lookup {
    Have(Arc<FileEntry>),
    /// None yet; one can be made (`wanted`).
    Missing,
    /// None, and none will be.
    No,
}

/// Decides what `file_server` answers when a file has no precompressed sibling.
pub trait Representation: Send + Sync {
    fn lookup(&self, file: &FileEntry, encoding: Encoding) -> Lookup;

    /// Asked for `file` in `encodings`, which the client preferred and no one had.
    fn wanted(&self, file: &Arc<FileEntry>, store: &Arc<FileStore>, encodings: &[Encoding]);
}

// The empty hook: nothing, compiled away.

impl RequestCheck for () {
    async fn check(&self, _: &mut http::request::Parts, body: Body, _: Client<'_>) -> Checked {
        Ok(body)
    }
}

impl Held for () {
    fn nothing() -> Self {}

    fn is_empty(&self) -> bool {
        true
    }
}

impl UpstreamCheck for () {
    type Held = ();

    async fn check(
        &self,
        _: &mut http::request::Parts,
        body: Body,
        _: Client<'_>,
        _: &[Authority],
    ) -> std::result::Result<(Body, ()), Response<Body>> {
        Ok((body, ()))
    }

    fn bound(&self) -> bool {
        false
    }

    fn upstreams(&self, _: &mut Vec<(Authority, &'static str)>) {}
}

impl ProxyObserver for () {
    type Pending = ();

    fn begin(&self, _: &mut Ctx) {}

    fn fallback(&self, _: &mut (), _: &mut Ctx, _: StatusCode) -> Option<Response<Body>> {
        None
    }

    fn observe(&self, _: (), _: Sent<'_>, _: &mut http::response::Parts, body: Body) -> Body {
        body
    }
}

impl Representation for () {
    fn lookup(&self, _: &FileEntry, _: Encoding) -> Lookup {
        Lookup::No
    }

    fn wanted(&self, _: &Arc<FileEntry>, _: &Arc<FileStore>, _: &[Encoding]) {}
}

// A pair: the first, then the second.

impl<A: RequestCheck, B: RequestCheck> RequestCheck for (A, B) {
    async fn check(&self, req: &mut http::request::Parts, body: Body, client: Client<'_>) -> Checked {
        let body = self.0.check(req, body, client).await?;
        self.1.check(req, body, client).await
    }
}

impl<A: Held, B: Held> Held for (A, B) {
    fn nothing() -> Self {
        (A::nothing(), B::nothing())
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty() && self.1.is_empty()
    }
}

impl<A: UpstreamCheck, B: UpstreamCheck> UpstreamCheck for (A, B) {
    type Held = (A::Held, B::Held);

    async fn check(
        &self,
        req: &mut http::request::Parts,
        body: Body,
        client: Client<'_>,
        up: &[Authority],
    ) -> std::result::Result<(Body, Self::Held), Response<Body>> {
        let (body, a) = self.0.check(req, body, client, up).await?;
        let (body, b) = self.1.check(req, body, client, up).await?;
        Ok((body, (a, b)))
    }

    fn bound(&self) -> bool {
        self.0.bound() || self.1.bound()
    }

    fn upstreams(&self, out: &mut Vec<(Authority, &'static str)>) {
        self.0.upstreams(out);
        self.1.upstreams(out);
    }
}

impl<A: ProxyObserver, B: ProxyObserver> ProxyObserver for (A, B) {
    type Pending = (A::Pending, B::Pending);

    fn begin(&self, ctx: &mut Ctx) -> Self::Pending {
        (self.0.begin(ctx), self.1.begin(ctx))
    }

    fn fallback(&self, pending: &mut Self::Pending, ctx: &mut Ctx, status: StatusCode) -> Option<Response<Body>> {
        self.0
            .fallback(&mut pending.0, ctx, status)
            .or_else(|| self.1.fallback(&mut pending.1, ctx, status))
    }

    fn observe(&self, pending: Self::Pending, sent: Sent<'_>, parts: &mut http::response::Parts, body: Body) -> Body {
        let again = Sent {
            proxy: sent.proxy,
            path_and_query: sent.path_and_query,
            headers: sent.headers,
            header_down: sent.header_down,
        };
        let body = self.0.observe(pending.0, sent, parts, body);
        self.1.observe(pending.1, again, parts, body)
    }
}

impl<A: Representation, B: Representation> Representation for (A, B) {
    fn lookup(&self, file: &FileEntry, encoding: Encoding) -> Lookup {
        match self.0.lookup(file, encoding) {
            Lookup::No => self.1.lookup(file, encoding),
            Lookup::Missing => match self.1.lookup(file, encoding) {
                Lookup::Have(entry) => Lookup::Have(entry),
                _ => Lookup::Missing,
            },
            have => have,
        }
    }

    fn wanted(&self, file: &Arc<FileEntry>, store: &Arc<FileStore>, encodings: &[Encoding]) {
        self.0.wanted(file, store, encodings);
        self.1.wanted(file, store, encodings);
    }
}

// Built, but perhaps not configured.

impl<T: RequestCheck> RequestCheck for Option<T> {
    async fn check(&self, req: &mut http::request::Parts, body: Body, client: Client<'_>) -> Checked {
        match self {
            Some(check) => check.check(req, body, client).await,
            None => Ok(body),
        }
    }
}

impl<T: Held> Held for Option<T> {
    fn nothing() -> Self {
        None
    }

    fn is_empty(&self) -> bool {
        self.as_ref().is_none_or(Held::is_empty)
    }
}

impl<T: UpstreamCheck> UpstreamCheck for Option<T> {
    type Held = Option<T::Held>;

    async fn check(
        &self,
        req: &mut http::request::Parts,
        body: Body,
        client: Client<'_>,
        up: &[Authority],
    ) -> std::result::Result<(Body, Self::Held), Response<Body>> {
        match self {
            Some(check) => {
                let (body, held) = check.check(req, body, client, up).await?;
                Ok((body, Some(held)))
            }
            None => Ok((body, None)),
        }
    }

    fn bound(&self) -> bool {
        self.as_ref().is_some_and(UpstreamCheck::bound)
    }

    fn upstreams(&self, out: &mut Vec<(Authority, &'static str)>) {
        if let Some(check) = self {
            check.upstreams(out);
        }
    }
}

// Shared.

impl<T: RequestCheck> RequestCheck for Arc<T> {
    async fn check(&self, req: &mut http::request::Parts, body: Body, client: Client<'_>) -> Checked {
        (**self).check(req, body, client).await
    }
}

impl<T: UpstreamCheck> UpstreamCheck for Arc<T> {
    type Held = T::Held;

    async fn check(
        &self,
        req: &mut http::request::Parts,
        body: Body,
        client: Client<'_>,
        up: &[Authority],
    ) -> std::result::Result<(Body, Self::Held), Response<Body>> {
        (**self).check(req, body, client, up).await
    }

    fn bound(&self) -> bool {
        (**self).bound()
    }

    fn upstreams(&self, out: &mut Vec<(Authority, &'static str)>) {
        (**self).upstreams(out);
    }
}

// The slots: a feature's type where it is on, `()` where it is off.

#[cfg(feature = "jwt")]
type Jwt = Option<Arc<crate::jwt::JwtAuth>>;
#[cfg(not(feature = "jwt"))]
type Jwt = ();

#[cfg(feature = "api-firewall")]
type ApiFirewall = Option<Arc<crate::apifw::ApiFirewall>>;
#[cfg(not(feature = "api-firewall"))]
type ApiFirewall = ();

#[cfg(feature = "rate-limit")]
type UpstreamLimit = crate::ratelimit::UpstreamLimit;
#[cfg(not(feature = "rate-limit"))]
type UpstreamLimit = ();

#[cfg(feature = "proxy-cache")]
type CacheObserver = crate::cache::Observer;
#[cfg(not(feature = "proxy-cache"))]
type CacheObserver = ();

#[cfg(feature = "compress-files")]
type Variants = crate::variants::Hook;
#[cfg(not(feature = "compress-files"))]
type Variants = ();

/// The checks before the routes, in order: the JWT first (the API firewall sees the claim headers
/// it set, and the query parameters it hides from the event log).
pub type RequestChecks = (Jwt, (ApiFirewall, ()));
/// The checks at a proxy, in the same order, then the client's slot at the upstreams (taken only
/// for a request the checks let through).
pub type UpstreamChecks = (Jwt, (ApiFirewall, (UpstreamLimit, ())));
/// What the upstream checks keep for the response's life.
pub type UpstreamHeld = <UpstreamChecks as UpstreamCheck>::Held;
/// The observers of proxied responses.
pub type ProxyObservers = (CacheObserver, ());
/// Where `file_server` asks for a representation it has no sibling for.
pub type Representations = (Variants, ());

/// The proxy observers: zero-sized, one constant for every proxy.
pub const PROXY: ProxyObservers = (
    #[cfg(feature = "proxy-cache")]
    crate::cache::Observer,
    #[cfg(not(feature = "proxy-cache"))]
    (),
    (),
);

/// The representations: zero-sized, one constant for every file server.
pub const REPRESENTATIONS: Representations = (
    #[cfg(feature = "compress-files")]
    crate::variants::Hook,
    #[cfg(not(feature = "compress-files"))]
    (),
    (),
);

/// The hooks of a server, composed from the configuration; one per process, `&'static` (a reload
/// keeps them), so a request copies a pointer at most.
pub struct Hooks {
    pub request: RequestChecks,
    /// `None` when no check has anything to do at a proxy: requests carry nothing for them.
    pub upstream: Option<UpstreamChecks>,
}

impl Hooks {
    pub fn new(config: &Config) -> &'static Hooks {
        let upstream = compose_upstream(config);
        Box::leak(Box::new(Hooks {
            request: compose_request(config),
            upstream: upstream.bound().then_some(upstream),
        }))
    }

    /// `Ok` when every upstream the checks are bound to is one of `known` (the upstreams the
    /// `reverse_proxy`s send to): at startup, and for a reloaded Caddyfile, which keeps the hooks.
    pub fn bound_within(&self, known: &[Authority]) -> Result<()> {
        let mut bound = Vec::new();
        if let Some(upstream) = &self.upstream {
            upstream.upstreams(&mut bound);
        }
        within(&bound, known)
    }
}

fn within(bound: &[(Authority, &'static str)], known: &[Authority]) -> Result<()> {
    let mut missing: Vec<String> = bound
        .iter()
        .filter(|(u, _)| !known.contains(u))
        .map(|(u, who)| format!("{u} ({who})"))
        .collect();
    missing.dedup();
    if missing.is_empty() {
        return Ok(());
    }
    let known: Vec<String> = known.iter().map(|u| u.to_string()).collect();
    anyhow::bail!(
        "request checks bound to upstreams no reverse_proxy sends to: {}; the Caddyfile's are: {}",
        missing.join(", "),
        if known.is_empty() {
            "none".to_string()
        } else {
            known.join(", ")
        }
    )
}

fn compose_request(config: &Config) -> RequestChecks {
    let _ = config;
    (
        #[cfg(feature = "jwt")]
        config.jwt.clone(),
        #[cfg(not(feature = "jwt"))]
        (),
        (
            #[cfg(feature = "api-firewall")]
            config.api_firewall.clone(),
            #[cfg(not(feature = "api-firewall"))]
            (),
            (),
        ),
    )
}

fn compose_upstream(config: &Config) -> UpstreamChecks {
    let _ = config;
    (
        #[cfg(feature = "jwt")]
        config.jwt.clone(),
        #[cfg(not(feature = "jwt"))]
        (),
        (
            #[cfg(feature = "api-firewall")]
            config.api_firewall.clone(),
            #[cfg(not(feature = "api-firewall"))]
            (),
            (
                #[cfg(feature = "rate-limit")]
                crate::ratelimit::UpstreamLimit,
                #[cfg(not(feature = "rate-limit"))]
                (),
                (),
            ),
        ),
    )
}

/// Refuses request checks bound to an upstream no `reverse_proxy` of `config` sends to: a typo,
/// or routes changed since, would otherwise leave the requests going there unchecked.
pub fn check_bindings(config: &Config) -> Result<()> {
    let mut bound = Vec::new();
    compose_upstream(config).upstreams(&mut bound);
    within(&bound, &config.upstreams())
}


// Startup: the environment, the files, and what runs once the server does.

/// The extensions' environment (WEB_*), read before the configuration: each built extension's
/// own, and a variable of one that is not built stops the start, as a misspelt one would.
pub fn configure_from_env() -> std::result::Result<(), String> {
    #[cfg(feature = "rate-limit")]
    crate::ratelimit::configure_from_env()?;
    #[cfg(not(feature = "rate-limit"))]
    unbuilt(
        "rate limits",
        "rate-limit",
        &["WEB_RATE_LIMIT_KEYS", "WEB_RATE_LIMIT_DRY_RUN", "WEB_MAX_UPSTREAM_REQUESTS_PER_IP"],
    )?;
    #[cfg(feature = "proxy-cache")]
    crate::cache::configure_from_env()?;
    #[cfg(not(feature = "proxy-cache"))]
    unbuilt("the proxy cache", "proxy-cache", &["WEB_PROXY_CACHE_MEMORY"])?;
    #[cfg(feature = "compress-files")]
    crate::variants::configure_from_env()?;
    #[cfg(not(feature = "compress-files"))]
    unbuilt("compressed variants", "compress-files", &["WEB_COMPRESSED_FILES_MEMORY"])?;
    #[cfg(not(feature = "jwt"))]
    unbuilt("JWT validation", "jwt", &["WEB_JWT_CONFIG"])?;
    #[cfg(not(feature = "api-firewall"))]
    unbuilt("the API firewall", "api-firewall", &["WEB_API_FIREWALL_CONFIG"])?;
    Ok(())
}

#[allow(dead_code)]
fn unbuilt(what: &str, feature: &str, variables: &[&str]) -> std::result::Result<(), String> {
    match variables.iter().find(|name| std::env::var_os(name).is_some()) {
        Some(name) => Err(format!("{name}: this webfast was built without {what} (cargo feature {feature})")),
        None => Ok(()),
    }
}

/// The request checks the environment names (WEB_JWT_CONFIG, WEB_API_FIREWALL_CONFIG), loaded
/// into `config`; what was loaded, one line each, for the startup log and `validate`.
pub fn load_checks(config: &mut Config) -> std::result::Result<Vec<String>, String> {
    let _ = &config;
    #[allow(unused_mut)]
    let mut loaded = Vec::new();
    #[allow(unused_variables)]
    let file = |name: &str| {
        std::env::var(name)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    #[cfg(feature = "jwt")]
    if let Some(path) = file("WEB_JWT_CONFIG") {
        let jwt = crate::jwt::JwtAuth::load(std::path::Path::new(&path)).map_err(|e| format!("{e:#}"))?;
        let (providers, rules) = jwt.counts();
        let bound = bound_to(jwt.upstreams());
        loaded.push(format!("JWT: {path}, {providers} provider(s), {rules} rule(s){bound}"));
        config.jwt = Some(Arc::new(jwt));
    }
    #[cfg(feature = "api-firewall")]
    if let Some(path) = file("WEB_API_FIREWALL_CONFIG") {
        let firewall = crate::apifw::ApiFirewall::load(std::path::Path::new(&path)).map_err(|e| format!("{e:#}"))?;
        let (apis, operations, later) = firewall.counts();
        let later = if later > 0 {
            format!(", {later} spec(s) read once the server runs")
        } else {
            String::new()
        };
        loaded.push(format!(
            "API firewall: {path}, {apis} API(s), {operations} operation(s){later}{}",
            bound_to(firewall.upstreams())
        ));
        config.api_firewall = Some(Arc::new(firewall));
    }
    check_bindings(config).map_err(|e| format!("{e:#}"))?;
    Ok(loaded)
}

/// ", checked at the proxies to a:80, b:8787" for the upstreams a check is bound to; "": none.
#[allow(dead_code)]
fn bound_to<'a>(upstreams: impl Iterator<Item = &'a Authority>) -> String {
    let mut names: Vec<String> = Vec::new();
    for upstream in upstreams {
        if !names.iter().any(|n| n == upstream.as_str()) {
            names.push(upstream.to_string());
        }
    }
    if names.is_empty() {
        String::new()
    } else {
        format!(", checked at the proxies to {}", names.join(", "))
    }
}

/// What the extensions do once the server runs: `begin` before the servers take the
/// configuration (the JWT keys start being read), `finish` with the ports' states (API specs
/// given as a path are read through the first port's routes; compressed variants redo the ready
/// answers of the sites reading their files).
pub struct Started {
    #[cfg(feature = "jwt")]
    jwt: Option<Arc<crate::jwt::JwtAuth>>,
    #[cfg(feature = "api-firewall")]
    firewall: Option<Arc<crate::apifw::ApiFirewall>>,
}

impl Started {
    pub fn begin(config: &Config) -> Result<Started> {
        let _ = config;
        #[cfg(feature = "jwt")]
        if let Some(jwt) = &config.jwt {
            jwt.start()?;
        }
        Ok(Started {
            #[cfg(feature = "jwt")]
            jwt: config.jwt.clone(),
            #[cfg(feature = "api-firewall")]
            firewall: config.api_firewall.clone(),
        })
    }

    pub fn finish(self, states: &[Arc<crate::server::ServerState>]) -> Result<()> {
        let _ = states;
        #[cfg(feature = "api-firewall")]
        if let Some(firewall) = &self.firewall {
            firewall.start(states.first().cloned().map(local_fetch))?;
        }
        #[cfg(feature = "compress-files")]
        {
            let states: Vec<std::sync::Weak<crate::server::ServerState>> = states.iter().map(Arc::downgrade).collect();
            crate::variants::on_change(Arc::new(move |changed| crate::watch::prepare_answers(&states, changed)));
        }
        #[cfg(feature = "jwt")]
        let _ = &self.jwt;
        Ok(())
    }
}

/// Requests to this server's own routes, as a client on the loopback would make them, marked so
/// that the Host check and the request checks pass them by (src/server.rs `InternalRequest`).
#[cfg(feature = "api-firewall")]
fn local_fetch(state: Arc<crate::server::ServerState>) -> crate::apifw::LocalFetch {
    Arc::new(move |mut request: http::Request<Body>| {
        let state = state.clone();
        Box::pin(async move {
            request.extensions_mut().insert(crate::server::InternalRequest);
            let conn = state.connection(std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)));
            crate::server::handle(conn, request).await
        })
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A check that counts its calls and refuses when told to.
    struct Counting {
        calls: AtomicUsize,
        refuse: bool,
    }

    impl RequestCheck for Counting {
        async fn check(&self, _: &mut http::request::Parts, body: Body, _: Client<'_>) -> Checked {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.refuse {
                let mut response = Response::new(crate::body::empty());
                *response.status_mut() = http::StatusCode::FORBIDDEN;
                return Err(response);
            }
            Ok(body)
        }
    }

    fn counting(refuse: bool) -> Counting {
        Counting {
            calls: AtomicUsize::new(0),
            refuse,
        }
    }

    #[tokio::test]
    async fn hooks_compose_in_order_and_stop_at_a_refusal() {
        let conn = ConnInfo {
            remote: "203.0.113.7:4000".parse().unwrap(),
            tls: false,
            trusted: false,
            sni: None,
        };
        let client = Client {
            ip: conn.remote.ip(),
            conn: &conn,
            at: At::Routes,
        };
        let (mut parts, ()) = http::Request::get("/").body(()).unwrap().into_parts();
        let empty: ((), ((), ())) = ((), ((), ()));
        assert!(
            RequestCheck::check(&empty, &mut parts, crate::body::empty(), client)
                .await
                .is_ok()
        );

        let pass_then_refuse = (Some(counting(false)), (counting(true), (counting(false), ())));
        let refused = RequestCheck::check(&pass_then_refuse, &mut parts, crate::body::empty(), client)
            .await
            .expect_err("refused");
        assert_eq!(refused.status(), http::StatusCode::FORBIDDEN);
        assert_eq!(pass_then_refuse.0.as_ref().unwrap().calls.load(Ordering::Relaxed), 1);
        assert_eq!((pass_then_refuse.1).0.calls.load(Ordering::Relaxed), 1);
        assert_eq!(((pass_then_refuse.1).1).0.calls.load(Ordering::Relaxed), 0, "not reached");

        let unconfigured: Option<Counting> = None;
        assert!(
            RequestCheck::check(&unconfigured, &mut parts, crate::body::empty(), client)
                .await
                .is_ok()
        );
    }

    /// Something a test hook holds.
    struct Slot;

    impl Held for Slot {
        fn nothing() -> Self {
            unreachable!()
        }

        fn is_empty(&self) -> bool {
            false
        }
    }

    #[test]
    fn what_hooks_hold_is_empty_unless_something_is_in_it() {
        assert!(<((), (Option<()>, ())) as Held>::nothing().is_empty());
        assert!(((), (Some(()), ())).is_empty(), "a configured check that holds nothing");
        assert!(!(Some(Slot), ()).is_empty());
        assert!(<Option<Slot> as Held>::nothing().is_none());
    }
}
