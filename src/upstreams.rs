//! The upstreams of a `reverse_proxy` and how one is chosen for a request. The unit is an address:
//! a name with several (src/dns.rs) is as many servers, each with its own health and count of
//! requests under way, as HAProxy and nginx have it (Caddy balances over the names). The servers
//! are a snapshot (`ArcSwap`) that the DNS thread replaces; a request loads it once and keeps
//! what it chose for its life.
//!
//! `Upstreams::Fixed` is the common case — one upstream, a literal address, no health settings —
//! and costs a request nothing: no snapshot, no policy, no counters. `Upstreams::Set` is the
//! rest; it maintains only what its policy and health settings read (the count of requests under
//! way only for `least_conn`, `random_choose` and `unhealthy_request_count`).
//!
//! Passive health as Caddy has it: `fail_duration` remembers a failure (a connection refused or
//! timed out, a status among `unhealthy_status`, a response slower than `unhealthy_latency`) for
//! that long; `max_fails` of them within it mark the server down for `fail_duration`; a server
//! with `unhealthy_request_count` requests under way is not chosen. Down servers are passed by;
//! with every server down the request is refused (503).

use crate::handler::Ctx;
use arc_swap::ArcSwap;
use http::header::HeaderName;
use http::uri::Authority;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

/// Servers per `reverse_proxy` at most: a request's bookkeeping is one `u64` of bits.
pub const MAX_SERVERS: usize = 64;

/// An upstream as the directive names it.
#[derive(Debug, Clone)]
pub struct Name {
    /// As written (`app:8080`): the logs, the bindings of the request checks.
    pub text: Authority,
    pub host: String,
    pub port: u16,
    /// `weighted_round_robin`: this name's weight, each of its addresses' too.
    pub weight: u32,
    /// A literal address: nothing to resolve.
    pub literal: Option<IpAddr>,
}

impl Name {
    pub fn new(text: Authority, weight: u32) -> Name {
        let host = text.host().trim_matches(['[', ']']).to_string();
        let port = text.port_u16().unwrap_or(80);
        let literal = host.parse::<IpAddr>().ok();
        Name {
            text,
            host,
            port,
            weight,
            literal,
        }
    }

    /// The host to resolve; `None` for a literal address.
    pub fn to_resolve(&self) -> Option<&str> {
        match self.literal {
            Some(_) => None,
            None => Some(&self.host),
        }
    }
}

static START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Milliseconds since the process started: what the health marks are kept in.
fn now_ms() -> u64 {
    START.elapsed().as_millis() as u64
}

/// One address a proxy sends to.
pub struct Server {
    /// The name it came from, as written.
    pub name: Authority,
    pub addr: SocketAddr,
    /// `ip:port`, what the request's URI gets.
    pub authority: Authority,
    pub weight: u32,
    /// Requests under way, kept only when the set counts (`Set::counting`).
    pub in_flight: AtomicUsize,
    fails: AtomicU32,
    last_fail: AtomicU64,
    down_until: AtomicU64,
    /// `lb_policy cookie`: the value that names this server, made once.
    cookie: std::sync::OnceLock<String>,
}

impl Server {
    fn new(name: &Name, ip: IpAddr) -> Server {
        let addr = SocketAddr::new(ip, name.port);
        let authority = match ip {
            IpAddr::V4(_) => format!("{ip}:{}", name.port),
            IpAddr::V6(_) => format!("[{ip}]:{}", name.port),
        };
        Server {
            name: name.text.clone(),
            addr,
            authority: authority.parse().expect("an address and a port are an authority"),
            weight: name.weight,
            in_flight: AtomicUsize::new(0),
            fails: AtomicU32::new(0),
            last_fail: AtomicU64::new(0),
            down_until: AtomicU64::new(0),
            cookie: std::sync::OnceLock::new(),
        }
    }

    /// The cookie value that names this server: an HMAC of its address with `secret`, hex.
    pub fn cookie_value(&self, secret: &[u8]) -> &str {
        self.cookie.get_or_init(|| {
            let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, secret);
            let tag = aws_lc_rs::hmac::sign(&key, self.addr.to_string().as_bytes());
            tag.as_ref().iter().map(|b| format!("{b:02x}")).collect()
        })
    }

    pub fn is_down(&self) -> bool {
        self.is_down_at(now_ms())
    }

    /// `now`: `now_ms()`, read once for every server of a pick (a clock read costs more than the
    /// pick itself).
    fn is_down_at(&self, now: u64) -> bool {
        self.down_until.load(Ordering::Relaxed) > now
    }

    /// A failure as the passive health settings count it.
    pub fn failed(&self, passive: &Passive) {
        let now = now_ms();
        let window = passive.fail_duration.as_millis() as u64;
        let last = self.last_fail.swap(now, Ordering::Relaxed);
        let fails = if now.saturating_sub(last) > window {
            self.fails.store(1, Ordering::Relaxed);
            1
        } else {
            self.fails.fetch_add(1, Ordering::Relaxed) + 1
        };
        if fails >= passive.max_fails {
            let was_down = self.down_until.swap(now + window, Ordering::Relaxed) > now;
            if !was_down {
                tracing::warn!(upstream = %self.name, address = %self.addr, fails, "upstream marked down for fail_duration");
            }
        }
    }

    /// A response the health settings do not fault: the failures before it are forgotten.
    pub fn succeeded(&self) {
        self.fails.store(0, Ordering::Relaxed);
    }
}

/// `lb_policy`.
#[derive(Debug, Clone)]
pub enum Policy {
    Random,
    /// `random_choose <n>`: `n` at random, the one with the fewest requests under way.
    RandomChoose(u32),
    First,
    RoundRobin,
    WeightedRoundRobin,
    LeastConn,
    /// The peer's address (`ip_hash`).
    IpHash,
    /// The client's address, as the trusted proxies name it (`client_ip_hash`).
    ClientIpHash,
    UriHash,
    Query(String),
    Header(HeaderName),
    /// Sticky: the cookie names the server (an HMAC of its address with `secret`), set on the
    /// response that chose it.
    Cookie {
        name: String,
        secret: Arc<[u8]>,
    },
}

impl Policy {
    /// Whether the policy reads the count of requests under way.
    fn counts(&self) -> bool {
        matches!(self, Policy::RandomChoose(_) | Policy::LeastConn)
    }
}

/// Passive health settings; `None` when `fail_duration` is not set.
#[derive(Debug, Clone)]
pub struct Passive {
    pub fail_duration: Duration,
    pub max_fails: u32,
    /// Status ranges, inclusive (`5xx` is 500–599).
    pub unhealthy_status: Vec<(u16, u16)>,
    pub unhealthy_latency: Option<Duration>,
    /// Requests under way at which a server is not chosen (0: no limit).
    pub unhealthy_request_count: usize,
}

impl Passive {
    /// Whether a response faults the server.
    pub fn faults(&self, status: u16, took: Duration) -> bool {
        self.unhealthy_status
            .iter()
            .any(|&(lo, hi)| (lo..=hi).contains(&status))
            || self.unhealthy_latency.is_some_and(|limit| took > limit)
    }
}

/// The servers of a `reverse_proxy` with more than one, or a name, or health settings.
pub struct Set {
    names: Vec<Name>,
    /// The current addresses of each name (the DNS thread's), the servers rebuilt from them.
    addresses: Mutex<Vec<Vec<IpAddr>>>,
    servers: ArcSwap<Vec<Arc<Server>>>,
    policy: Policy,
    passive: Option<Passive>,
    counter: AtomicUsize,
    /// `transport http { resolvers … }`, or the system's.
    nameservers: Arc<[SocketAddr]>,
    refresh: Option<Duration>,
    /// Requests under way are counted (the policy or `unhealthy_request_count` reads them).
    counting: bool,
}

impl Set {
    pub fn names(&self) -> &[Name] {
        &self.names
    }

    pub fn nameservers(&self) -> Arc<[SocketAddr]> {
        self.nameservers.clone()
    }

    pub fn refresh(&self) -> Option<Duration> {
        self.refresh
    }

    /// The servers as they are now.
    pub fn servers(&self) -> Arc<Vec<Arc<Server>>> {
        self.servers.load_full()
    }

    /// A name's addresses as resolved now: the servers are rebuilt, those whose address stays
    /// kept with their counts and health.
    pub fn addresses(&self, index: usize, mut addrs: Vec<IpAddr>) {
        let mut addresses = self.addresses.lock().unwrap_or_else(|e| e.into_inner());
        addrs.sort_unstable();
        addrs.dedup();
        if addresses[index] == addrs {
            return;
        }
        addresses[index] = addrs;
        let current = self.servers.load();
        let mut servers = Vec::with_capacity(current.len());
        for (name, addrs) in self.names.iter().zip(addresses.iter()) {
            for &ip in addrs {
                if servers.len() == MAX_SERVERS {
                    tracing::warn!(upstream = %name.text, "more than {MAX_SERVERS} addresses: the rest are not used");
                    break;
                }
                let addr = SocketAddr::new(ip, name.port);
                let server = match current.iter().find(|s| s.addr == addr) {
                    Some(kept) => kept.clone(),
                    None => Arc::new(Server::new(name, ip)),
                };
                servers.push(server);
            }
        }
        tracing::debug!(upstream = %self.names[index].text, servers = servers.len(), "upstream addresses changed");
        self.servers.store(Arc::new(servers));
    }
}

/// What a `reverse_proxy` sends to.
pub enum Upstreams {
    /// One literal address, no health settings: nothing to choose.
    Fixed(Arc<Server>),
    Set(Arc<Set>),
}

impl Upstreams {
    /// `nameservers`: `None` for the system's.
    pub fn new(
        names: Vec<Name>,
        policy: Policy,
        passive: Option<Passive>,
        nameservers: Option<Vec<SocketAddr>>,
        refresh: Option<Duration>,
    ) -> Upstreams {
        if let ([name], None, Some(ip)) = (names.as_slice(), &passive, names.first().and_then(|n| n.literal)) {
            return Upstreams::Fixed(Arc::new(Server::new(name, ip)));
        }
        let counting = policy.counts() || passive.as_ref().is_some_and(|p| p.unhealthy_request_count > 0);
        let nameservers: Arc<[SocketAddr]> = match nameservers {
            Some(list) => list.into(),
            None => crate::dns::system_nameservers().into(),
        };
        let set = Arc::new(Set {
            addresses: Mutex::new(vec![Vec::new(); names.len()]),
            names,
            servers: ArcSwap::from_pointee(Vec::new()),
            policy,
            passive,
            counter: AtomicUsize::new(0),
            nameservers,
            refresh,
            counting,
        });
        // The literal addresses are there from the start; the names once resolved (src/dns.rs).
        for (index, ip) in set.names.iter().map(|n| n.literal).enumerate() {
            if let Some(ip) = ip {
                set.addresses(index, vec![ip]);
            }
        }
        Upstreams::Set(set)
    }

    /// The set, for the DNS thread; `None` for a fixed upstream.
    pub fn set(&self) -> Option<&Arc<Set>> {
        match self {
            Upstreams::Fixed(_) => None,
            Upstreams::Set(set) => Some(set),
        }
    }

    /// The servers as they are now, for a request.
    pub fn load(&self) -> Loaded<'_> {
        match self {
            Upstreams::Fixed(server) => Loaded::Fixed(server),
            Upstreams::Set(set) => Loaded::Set(set, set.servers.load()),
        }
    }

    /// Any server that is up, for the server's own requests (src/cache.rs); `None` with every
    /// one down.
    pub fn any(&self) -> Option<Arc<Server>> {
        match self {
            Upstreams::Fixed(server) => Some(server.clone()),
            Upstreams::Set(set) => {
                let servers = set.servers.load();
                let now = now_ms();
                let up: Vec<&Arc<Server>> = servers.iter().filter(|s| !s.is_down_at(now)).collect();
                if up.is_empty() {
                    return None;
                }
                let index = set.counter.fetch_add(1, Ordering::Relaxed) % up.len();
                Some(up[index].clone())
            }
        }
    }

    pub fn passive(&self) -> Option<&Passive> {
        match self {
            Upstreams::Fixed(_) => None,
            Upstreams::Set(set) => set.passive.as_ref(),
        }
    }

    /// `lb_policy cookie`: the Set-Cookie that names `server` (`Secure` over TLS).
    pub fn cookie_for(&self, server: &Server, secure: bool) -> Option<http::HeaderValue> {
        let Upstreams::Set(set) = self else {
            return None;
        };
        let Policy::Cookie { name, secret } = &set.policy else {
            return None;
        };
        let value = server.cookie_value(secret);
        let flags = if secure { "; Secure" } else { "" };
        http::HeaderValue::from_str(&format!("{name}={value}; Path=/; HttpOnly{flags}")).ok()
    }
}

/// A request's view of the upstreams.
pub enum Loaded<'a> {
    Fixed(&'a Arc<Server>),
    /// The snapshot held, not cloned: no reference count touched on the way in or out.
    Set(&'a Set, arc_swap::Guard<Arc<Vec<Arc<Server>>>>),
}

/// The server chosen for one attempt.
pub struct Picked<'a> {
    pub server: &'a Arc<Server>,
    /// Its bit in the request's `tried`.
    pub index: usize,
    /// `cookie`: the response is to set the cookie that names this server.
    pub set_cookie: bool,
    /// Counting a request under way until its response ends.
    pub lease: Option<Lease>,
}

/// A request under way at a server, until dropped.
pub struct Lease(Arc<Server>);

impl Drop for Lease {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

impl crate::extensions::Held for Option<Lease> {
    fn nothing() -> Self {
        None
    }

    fn is_empty(&self) -> bool {
        self.is_none()
    }
}

impl std::fmt::Debug for Picked<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Picked({}, #{})", self.server.addr, self.index)
    }
}

/// Why no server was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoServer {
    /// None is up (or there is none yet): 503.
    AllDown,
    /// Every one that is up was tried by this request already.
    AllTried,
}

impl Loaded<'_> {
    /// The server for an attempt; `tried`: the bits of those this request tried before. With
    /// every server up already tried, `AllTried`: the caller may start over (Caddy tries one
    /// again; the retry settings bound that).
    pub fn pick(&self, ctx: &Ctx, tried: u64) -> Result<Picked<'_>, NoServer> {
        match self {
            Loaded::Fixed(server) => Ok(Picked {
                server,
                index: 0,
                set_cookie: false,
                lease: None,
            }),
            Loaded::Set(set, servers) => {
                let n = servers.len().min(MAX_SERVERS);
                // Without health settings no server is ever down: the clock is not read.
                let mut up: u64 = if n == MAX_SERVERS { u64::MAX } else { (1u64 << n) - 1 };
                if let Some(passive) = &set.passive {
                    let (limit, now) = (passive.unhealthy_request_count, now_ms());
                    for (i, server) in servers[..n].iter().enumerate() {
                        let busy = limit > 0 && server.in_flight.load(Ordering::Relaxed) >= limit;
                        if busy || server.is_down_at(now) {
                            up &= !(1 << i);
                        }
                    }
                }
                if up == 0 {
                    return Err(NoServer::AllDown);
                }
                let pool = if up & !tried == 0 {
                    if tried == 0 {
                        up
                    } else {
                        return Err(NoServer::AllTried);
                    }
                } else {
                    up & !tried
                };
                let (index, set_cookie) = choose(set, servers, pool, ctx);
                let server = &servers[index];
                let lease = set.counting.then(|| {
                    server.in_flight.fetch_add(1, Ordering::Relaxed);
                    Lease(server.clone())
                });
                Ok(Picked {
                    server,
                    index,
                    set_cookie,
                    lease,
                })
            }
        }
    }
}

thread_local! {
    static RNG: std::cell::Cell<u64> = std::cell::Cell::new({
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E3779B97F4A7C15);
        (nanos ^ (&nanos as *const u64 as u64)) | 1
    });
}

/// A number from a per-thread xorshift: a choice at random, nothing more.
fn random() -> u64 {
    RNG.with(|cell| {
        let mut x = cell.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        cell.set(x);
        x
    })
}

/// The `k`-th set bit of `pool`.
fn nth_set(pool: u64, k: u32) -> usize {
    let mut rest = pool;
    for _ in 0..k {
        rest &= rest - 1;
    }
    rest.trailing_zeros() as usize
}

/// The set bit of `pool` at or after `from`, cyclically.
fn next_set(pool: u64, from: usize) -> usize {
    let masked = pool & (u64::MAX << from);
    if masked != 0 {
        masked.trailing_zeros() as usize
    } else {
        pool.trailing_zeros() as usize
    }
}

/// Rendezvous hashing: the server with the highest hash of (key, address), the same for a key as
/// long as that server is up, and only the keys of a server that went change hands.
static HRW: LazyLock<ahash::RandomState> =
    LazyLock::new(|| ahash::RandomState::with_seeds(0x4c62, 0x6c6f, 0x6164, 0x6572));

fn by_hash(servers: &[Arc<Server>], pool: u64, key: &[u8]) -> usize {
    let mut best = (0u64, 0usize);
    let mut rest = pool;
    while rest != 0 {
        let i = rest.trailing_zeros() as usize;
        rest &= rest - 1;
        let mut hasher = HRW.build_hasher();
        hasher.write(key);
        servers[i].addr.hash(&mut hasher);
        let h = hasher.finish();
        if h >= best.0 {
            best = (h, i);
        }
    }
    best.1
}

fn fewest_in_flight(servers: &[Arc<Server>], pool: u64) -> usize {
    let (mut best, mut fewest, mut ties) = (0usize, usize::MAX, 0u64);
    let mut rest = pool;
    while rest != 0 {
        let i = rest.trailing_zeros() as usize;
        rest &= rest - 1;
        let n = servers[i].in_flight.load(Ordering::Relaxed);
        if n < fewest {
            (best, fewest, ties) = (i, n, 1);
        } else if n == fewest {
            // Among equals one at random (reservoir of one), as Caddy does.
            ties += 1;
            if random().is_multiple_of(ties) {
                best = i;
            }
        }
    }
    best
}

fn cookie_of<'h>(ctx: &'h Ctx, name: &str) -> Option<&'h str> {
    ctx.req
        .headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .map(str::trim)
        .find_map(|pair| pair.strip_prefix(name).and_then(|rest| rest.strip_prefix('=')))
}

/// The index chosen from `pool` by the policy, and whether the response is to set the cookie.
fn choose(set: &Set, servers: &[Arc<Server>], pool: u64, ctx: &Ctx) -> (usize, bool) {
    let count = pool.count_ones();
    if count == 1 {
        return (
            pool.trailing_zeros() as usize,
            matches!(set.policy, Policy::Cookie { .. }),
        );
    }
    let at_random = || nth_set(pool, (random() % u64::from(count)) as u32);
    let index = match &set.policy {
        Policy::Random => at_random(),
        Policy::RandomChoose(k) => {
            let mut chosen = 0u64;
            for _ in 0..(*k).min(count) {
                chosen |= 1 << nth_set(pool, (random() % u64::from(count)) as u32);
            }
            fewest_in_flight(servers, chosen)
        }
        Policy::First => pool.trailing_zeros() as usize,
        Policy::RoundRobin => {
            let turn = set.counter.fetch_add(1, Ordering::Relaxed) % servers.len();
            next_set(pool, turn)
        }
        Policy::WeightedRoundRobin => {
            let mut total: u64 = 0;
            let mut rest = pool;
            while rest != 0 {
                let i = rest.trailing_zeros() as usize;
                rest &= rest - 1;
                total += u64::from(servers[i].weight);
            }
            if total == 0 {
                at_random()
            } else {
                let mut turn = (set.counter.fetch_add(1, Ordering::Relaxed) as u64) % total;
                let mut rest = pool;
                loop {
                    let i = rest.trailing_zeros() as usize;
                    let weight = u64::from(servers[i].weight);
                    if turn < weight || rest & (rest - 1) == 0 {
                        break i;
                    }
                    turn -= weight;
                    rest &= rest - 1;
                }
            }
        }
        Policy::LeastConn => fewest_in_flight(servers, pool),
        Policy::IpHash => by_hash(servers, pool, &ip_bytes(ctx.conn.remote.ip())),
        Policy::ClientIpHash => by_hash(servers, pool, &ip_bytes(ctx.client_ip)),
        Policy::UriHash => by_hash(
            servers,
            pool,
            ctx.req.uri.path_and_query().map_or("/", |pq| pq.as_str()).as_bytes(),
        ),
        Policy::Query(key) => match query_value(ctx, key) {
            Some(value) => by_hash(servers, pool, value.as_bytes()),
            None => at_random(),
        },
        Policy::Header(name) => match ctx.req.headers.get(name) {
            Some(value) => by_hash(servers, pool, value.as_bytes()),
            None => at_random(),
        },
        Policy::Cookie { name, secret } => {
            if let Some(value) = cookie_of(ctx, name) {
                let mut rest = pool;
                while rest != 0 {
                    let i = rest.trailing_zeros() as usize;
                    rest &= rest - 1;
                    if servers[i].cookie_value(secret) == value {
                        return (i, false);
                    }
                }
            }
            return (at_random(), true);
        }
    };
    (index, false)
}

fn ip_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn query_value<'q>(ctx: &'q Ctx, key: &str) -> Option<&'q str> {
    ctx.req.uri.query()?.split('&').find_map(|pair| {
        let rest = pair.strip_prefix(key)?;
        match rest.strip_prefix('=') {
            Some(value) => Some(value),
            None if rest.is_empty() => Some(""),
            None => None,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::empty;
    use crate::handler::ConnInfo;
    use http::Request;

    fn name(text: &str, weight: u32) -> Name {
        Name::new(text.parse().unwrap(), weight)
    }

    fn ctx(remote: &str, uri: &str, cookie: Option<&str>) -> Ctx {
        let remote: SocketAddr = remote.parse().unwrap();
        let mut request = Request::builder().uri(uri).header("host", "example.test");
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        let (parts, _) = request.body(()).unwrap().into_parts();
        let conn = Arc::new(ConnInfo {
            remote,
            tls: false,
            trusted: false,
            sni: None,
        });
        Ctx::new(conn, parts, empty(), remote.ip())
    }

    fn set(names: &[&str], policy: Policy, passive: Option<Passive>) -> Upstreams {
        Upstreams::new(names.iter().map(|n| name(n, 1)).collect(), policy, passive, None, None)
    }

    fn picks(upstreams: &Upstreams, ctx: &Ctx, n: usize) -> Vec<u16> {
        let loaded = upstreams.load();
        (0..n)
            .map(|_| loaded.pick(ctx, 0).unwrap().server.addr.port())
            .collect()
    }

    #[test]
    fn one_literal_upstream_is_fixed() {
        assert!(matches!(
            set(&["127.0.0.1:8080"], Policy::Random, None),
            Upstreams::Fixed(_)
        ));
        assert!(
            matches!(set(&["app:8080"], Policy::Random, None), Upstreams::Set(_)),
            "a name"
        );
        assert!(matches!(
            set(&["127.0.0.1:8080", "127.0.0.1:8081"], Policy::Random, None),
            Upstreams::Set(_)
        ));
        let fixed = set(&["127.0.0.1:8080"], Policy::Random, None);
        let c = ctx("10.0.0.2:4000", "/", None);
        let loaded = fixed.load();
        let picked = loaded.pick(&c, 0).unwrap();
        assert_eq!(picked.server.authority.as_str(), "127.0.0.1:8080");
        assert!(picked.lease.is_none() && !picked.set_cookie);
    }

    #[test]
    fn round_robin_and_first() {
        let c = ctx("10.0.0.2:4000", "/", None);
        let rr = set(&["127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3"], Policy::RoundRobin, None);
        assert_eq!(picks(&rr, &c, 6), vec![1, 2, 3, 1, 2, 3]);
        let first = set(&["127.0.0.1:1", "127.0.0.1:2"], Policy::First, None);
        assert_eq!(picks(&first, &c, 3), vec![1, 1, 1]);
        // A tried server is passed by; with every one tried, one again.
        let loaded = first.load();
        assert_eq!(loaded.pick(&c, 0b01).unwrap().server.addr.port(), 2);
        assert_eq!(loaded.pick(&c, 0b11).unwrap_err(), NoServer::AllTried);
    }

    #[test]
    fn weights_give_each_its_share() {
        let c = ctx("10.0.0.2:4000", "/", None);
        let weighted = Upstreams::new(
            vec![name("127.0.0.1:1", 3), name("127.0.0.1:2", 1)],
            Policy::WeightedRoundRobin,
            None,
            None,
            None,
        );
        assert_eq!(picks(&weighted, &c, 8), vec![1, 1, 1, 2, 1, 1, 1, 2]);
    }

    #[test]
    fn hashes_keep_a_key_on_its_server() {
        let names = ["127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3", "127.0.0.1:4"];
        let by_ip = set(&names, Policy::IpHash, None);
        let a = picks(&by_ip, &ctx("10.0.0.2:4000", "/", None), 5);
        assert!(a.iter().all(|&p| p == a[0]), "the same server every time: {a:?}");
        let spread: std::collections::BTreeSet<u16> = (0..64)
            .map(|i| picks(&by_ip, &ctx(&format!("10.0.{i}.2:4000"), "/", None), 1)[0])
            .collect();
        assert_eq!(spread.len(), 4, "every server gets keys");
        let by_uri = set(&names, Policy::UriHash, None);
        let u = picks(&by_uri, &ctx("10.0.0.2:4000", "/a/b?c=1", None), 1)[0];
        assert_eq!(picks(&by_uri, &ctx("10.0.0.9:1", "/a/b?c=1", None), 1)[0], u);
        // Only the keys of a server that is gone move: the rest stay put.
        let loaded = by_uri.load();
        let without = loaded
            .pick(&ctx("10.0.0.2:4000", "/a/b?c=1", None), 1 << (u - 1))
            .unwrap();
        assert_ne!(without.server.addr.port(), u);
        let by_query = set(&names, Policy::Query("user".into()), None);
        let q = picks(&by_query, &ctx("10.0.0.2:4000", "/x?user=ann&y=1", None), 1)[0];
        assert_eq!(picks(&by_query, &ctx("10.0.0.2:4000", "/z?user=ann", None), 1)[0], q);
    }

    #[test]
    fn least_conn_counts_requests_under_way() {
        let c = ctx("10.0.0.2:4000", "/", None);
        let lc = set(&["127.0.0.1:1", "127.0.0.1:2"], Policy::LeastConn, None);
        let loaded = lc.load();
        let first = loaded.pick(&c, 0).unwrap();
        let held = first.server.addr.port();
        assert!(first.lease.is_some(), "counted while the lease lives");
        let second = loaded.pick(&c, 0).unwrap();
        assert_ne!(second.server.addr.port(), held, "the other has fewer under way");
        drop(first);
        let third = loaded.pick(&c, 0).unwrap();
        assert_eq!(third.server.addr.port(), held, "released: the fewest again");
    }

    #[test]
    fn passive_health_marks_a_server_down_and_lets_it_back() {
        let passive = Passive {
            fail_duration: Duration::from_millis(200),
            max_fails: 2,
            unhealthy_status: vec![(500, 599)],
            unhealthy_latency: Some(Duration::from_secs(1)),
            unhealthy_request_count: 0,
        };
        assert!(passive.faults(502, Duration::ZERO));
        assert!(passive.faults(200, Duration::from_secs(2)));
        assert!(!passive.faults(404, Duration::ZERO));
        let c = ctx("10.0.0.2:4000", "/", None);
        let two = set(&["127.0.0.1:1", "127.0.0.1:2"], Policy::First, Some(passive.clone()));
        let loaded = two.load();
        let server = loaded.pick(&c, 0).unwrap().server.clone();
        assert_eq!(server.addr.port(), 1);
        server.failed(&passive);
        assert!(!server.is_down(), "one failure of two");
        server.failed(&passive);
        assert!(server.is_down());
        assert_eq!(
            loaded.pick(&c, 0).unwrap().server.addr.port(),
            2,
            "the down one passed by"
        );
        std::thread::sleep(Duration::from_millis(250));
        assert!(!server.is_down(), "back after fail_duration");
        let one = set(&["127.0.0.1:1"], Policy::First, Some(passive.clone()));
        let loaded = one.load();
        let only = loaded.pick(&c, 0).unwrap().server.clone();
        only.failed(&passive);
        only.failed(&passive);
        assert_eq!(loaded.pick(&c, 0).unwrap_err(), NoServer::AllDown);
        assert!(one.any().is_none());
    }

    #[test]
    fn a_cookie_names_the_server() {
        let secret: Arc<[u8]> = b"s3cret".as_slice().into();
        let sticky = set(
            &["127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3"],
            Policy::Cookie {
                name: "lb".into(),
                secret: secret.clone(),
            },
            None,
        );
        let loaded = sticky.load();
        let first = loaded.pick(&ctx("10.0.0.2:4000", "/", None), 0).unwrap();
        assert!(first.set_cookie, "no cookie yet: the response sets one");
        let value = first.server.cookie_value(&secret).to_string();
        let again = loaded
            .pick(&ctx("10.0.0.9:1", "/", Some(&format!("a=b; lb={value}"))), 0)
            .unwrap();
        assert_eq!(again.server.addr, first.server.addr);
        assert!(!again.set_cookie);
        let unknown = loaded.pick(&ctx("10.0.0.9:1", "/", Some("lb=nonsense")), 0).unwrap();
        assert!(unknown.set_cookie, "a cookie naming no server: chosen anew, set anew");
    }

    #[test]
    fn addresses_of_a_name_become_servers_and_keep_their_state() {
        let names = vec![name("app:8080", 2), name("127.0.0.1:9", 1)];
        let Upstreams::Set(set) = Upstreams::new(names, Policy::RoundRobin, None, Some(vec![]), None) else {
            panic!("a name is a set");
        };
        assert_eq!(set.servers().len(), 1, "the literal from the start");
        set.addresses(0, vec![IpAddr::from([10, 0, 0, 2]), IpAddr::from([10, 0, 0, 1])]);
        let servers = set.servers();
        assert_eq!(servers.len(), 3);
        assert_eq!(servers[0].authority.as_str(), "10.0.0.1:8080", "sorted");
        assert_eq!(servers[0].weight, 2);
        servers[0].in_flight.fetch_add(5, Ordering::Relaxed);
        set.addresses(0, vec![IpAddr::from([10, 0, 0, 1]), IpAddr::from([10, 0, 0, 3])]);
        let servers = set.servers();
        assert_eq!(servers.len(), 3);
        assert_eq!(
            servers[0].in_flight.load(Ordering::Relaxed),
            5,
            "the kept server with its count"
        );
        assert_eq!(servers[1].authority.as_str(), "10.0.0.3:8080");
        set.addresses(0, Vec::new());
        assert_eq!(set.servers().len(), 1, "a name with no address leaves the literal");
        let v6 = name("[2001:db8::1]:8080", 1);
        assert_eq!(v6.host, "2001:db8::1");
        assert!(v6.literal.is_some());
    }

    #[test]
    fn bit_helpers() {
        assert_eq!(nth_set(0b1011, 0), 0);
        assert_eq!(nth_set(0b1011, 2), 3);
        assert_eq!(next_set(0b1011, 2), 3);
        assert_eq!(next_set(0b1011, 4), 0);
    }
}

#[cfg(test)]
mod cost {
    //! `cargo test --release --lib -- --ignored cost:: --nocapture`: what a pick costs.
    use super::*;
    use crate::handler::ConnInfo;
    use http::Request;
    use std::hint::black_box;

    fn ctx() -> Ctx {
        let remote: SocketAddr = "10.0.0.2:4000".parse().unwrap();
        let (parts, _) = Request::builder()
            .uri("/a/b?c=1")
            .header("host", "example.test")
            .body(())
            .unwrap()
            .into_parts();
        let conn = Arc::new(ConnInfo {
            remote,
            tls: false,
            trusted: false,
            sni: None,
        });
        Ctx::new(conn, parts, crate::body::empty(), remote.ip())
    }

    fn time(label: &str, upstreams: &Upstreams) {
        let c = ctx();
        let n = 2_000_000u32;
        let started = Instant::now();
        for _ in 0..n {
            let loaded = upstreams.load();
            let picked = loaded.pick(&c, 0).unwrap();
            black_box(picked.server.addr);
        }
        let took = started.elapsed();
        println!("{label:<28} {:>6.1} ns per pick", took.as_nanos() as f64 / f64::from(n));
    }

    #[test]
    #[ignore]
    fn of_a_pick() {
        let names = |n: usize| -> Vec<Name> {
            (1..=n)
                .map(|i| Name::new(format!("127.0.0.1:{i}").parse().unwrap(), 1))
                .collect()
        };
        let passive = Passive {
            fail_duration: Duration::from_secs(30),
            max_fails: 1,
            unhealthy_status: vec![(500, 599)],
            unhealthy_latency: None,
            unhealthy_request_count: 0,
        };
        time("fixed", &Upstreams::new(names(1), Policy::Random, None, None, None));
        time(
            "one, fail_duration",
            &Upstreams::new(names(1), Policy::First, Some(passive.clone()), None, None),
        );
        time(
            "4 round_robin",
            &Upstreams::new(names(4), Policy::RoundRobin, None, None, None),
        );
        time("4 random", &Upstreams::new(names(4), Policy::Random, None, None, None));
        time(
            "4 least_conn",
            &Upstreams::new(names(4), Policy::LeastConn, None, None, None),
        );
        time(
            "4 uri_hash",
            &Upstreams::new(names(4), Policy::UriHash, None, None, None),
        );
        time(
            "4 client_ip_hash, health",
            &Upstreams::new(names(4), Policy::ClientIpHash, Some(passive), None, None),
        );
    }
}
