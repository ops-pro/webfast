//! Upstream names (docs/dns.md). The addresses of a `reverse_proxy` upstream given by name are a
//! snapshot the requests read (src/upstreams.rs); this module fills it. A name is resolved at
//! start and at reload, synchronously (`begin`: one that does not resolve stops either), and from
//! then on by one background thread (`Worker`), at the proxy's `refresh` or at the answer's TTL,
//! the current addresses kept while a refresh fails. Nothing of it runs on a request.
//!
//! The queries are the module's own: A and AAAA over UDP, TCP when the answer is truncated, to
//! the nameservers of /etc/resolv.conf or the proxy's `transport http { resolvers … }`;
//! /etc/hosts is read first (Docker mounts both into every container, the scratch image too).
//!
//! WEB_DNS_TTL_MIN (5s) and WEB_DNS_TTL_MAX (1h) clamp a TTL, WEB_DNS_TIMEOUT (5s) bounds one
//! query, WEB_DNS_IPV6=off leaves AAAA out.

use crate::background::Worker;
use crate::upstreams::Set;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub ttl_min: Duration,
    pub ttl_max: Duration,
    pub timeout: Duration,
    pub ipv6: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            ttl_min: Duration::from_secs(5),
            ttl_max: Duration::from_secs(3600),
            timeout: Duration::from_secs(5),
            ipv6: true,
        }
    }
}

static OPTIONS: OnceLock<Options> = OnceLock::new();

pub fn options() -> Options {
    OPTIONS.get().copied().unwrap_or_default()
}

/// WEB_DNS_TTL_MIN, WEB_DNS_TTL_MAX, WEB_DNS_TIMEOUT (durations as the Caddyfile writes them),
/// WEB_DNS_IPV6 (`on` / `off`).
pub fn configure_from_env() -> Result<(), String> {
    let mut options = Options::default();
    let duration = |name: &str, into: &mut Duration| -> Result<(), String> {
        if let Ok(value) = std::env::var(name) {
            *into = crate::config::parse_duration(&value).map_err(|e| format!("{name}: {e}"))?;
            if into.is_zero() {
                return Err(format!("{name}: must be above zero"));
            }
        }
        Ok(())
    };
    duration("WEB_DNS_TTL_MIN", &mut options.ttl_min)?;
    duration("WEB_DNS_TTL_MAX", &mut options.ttl_max)?;
    duration("WEB_DNS_TIMEOUT", &mut options.timeout)?;
    if options.ttl_min > options.ttl_max {
        return Err("WEB_DNS_TTL_MIN is above WEB_DNS_TTL_MAX".into());
    }
    if let Ok(value) = std::env::var("WEB_DNS_IPV6") {
        options.ipv6 = match value.as_str() {
            "on" | "true" | "1" => true,
            "off" | "false" | "0" => false,
            other => return Err(format!("WEB_DNS_IPV6: {other:?} (on or off)")),
        };
    }
    let _ = OPTIONS.set(options);
    Ok(())
}

// --- The system's files ---

static SYSTEM: LazyLock<Vec<SocketAddr>> =
    LazyLock::new(|| parse_resolv_conf(&std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default()));

/// The nameservers of /etc/resolv.conf (port 53), in its order; empty without the file.
pub fn system_nameservers() -> &'static [SocketAddr] {
    &SYSTEM
}

fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    text.lines()
        .map(|line| line.split(['#', ';']).next().unwrap_or("").trim())
        .filter_map(|line| line.strip_prefix("nameserver"))
        .filter_map(|rest| rest.split_whitespace().next())
        // A link-local scope (`fe80::1%eth0`) is not an address this parser takes: left out.
        .filter_map(|address| address.parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
}

static HOSTS: LazyLock<Vec<(Box<str>, IpAddr)>> =
    LazyLock::new(|| parse_hosts(&std::fs::read_to_string("/etc/hosts").unwrap_or_default()));

fn parse_hosts(text: &str) -> Vec<(Box<str>, IpAddr)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut fields = line.split_whitespace();
        let Some(ip) = fields.next().and_then(|f| f.parse::<IpAddr>().ok()) else {
            continue;
        };
        for name in fields {
            out.push((name.to_ascii_lowercase().into_boxed_str(), ip));
        }
    }
    out
}

fn in_hosts(name: &str) -> Vec<IpAddr> {
    HOSTS
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, ip)| *ip)
        .collect()
}

// --- The wire format (RFC 1035): one question, A or AAAA answers ---

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
/// A UDP answer without EDNS is at most 512 bytes; the buffer takes any that is sent anyway.
const UDP_BUFFER: usize = 4096;

fn query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return Err(format!("{name:?} is not a name to resolve"));
    }
    let mut out = Vec::with_capacity(17 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // a query, recursion desired
    out.extend_from_slice(&1u16.to_be_bytes()); // one question
    out.extend_from_slice(&[0; 6]); // no answers, authorities, additionals
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("{name:?} is not a name to resolve"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// What an answer says: the addresses of the type asked for and the smallest TTL among them.
#[derive(Debug, Default, PartialEq, Eq)]
struct Records {
    addrs: Vec<IpAddr>,
    ttl: Option<u32>,
    /// The answer was cut (UDP): ask again over TCP.
    truncated: bool,
}

fn skip_name(msg: &[u8], mut at: usize) -> Result<usize, String> {
    loop {
        let len = *msg.get(at).ok_or("a cut name")?;
        if len == 0 {
            return Ok(at + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Ok(at + 2);
        }
        at += 1 + usize::from(len);
    }
}

fn u16_at(msg: &[u8], at: usize) -> Result<u16, String> {
    let bytes: [u8; 2] = msg
        .get(at..at + 2)
        .ok_or("a cut message")?
        .try_into()
        .map_err(|_| "a cut message")?;
    Ok(u16::from_be_bytes(bytes))
}

fn parse_answer(msg: &[u8], id: u16, qtype: u16) -> Result<Records, String> {
    if msg.len() < 12 {
        return Err("a cut message".into());
    }
    if u16_at(msg, 0)? != id {
        return Err("an answer to another query".into());
    }
    let flags = u16_at(msg, 2)?;
    if flags & 0x8000 == 0 {
        return Err("not an answer".into());
    }
    match flags & 0x000F {
        0 => {}
        3 => return Err("no such name".into()),
        2 => return Err("the nameserver failed".into()),
        5 => return Err("the nameserver refused".into()),
        code => return Err(format!("the nameserver answered with code {code}")),
    }
    let mut records = Records {
        truncated: flags & 0x0200 != 0,
        ..Records::default()
    };
    let questions = u16_at(msg, 4)?;
    let answers = u16_at(msg, 6)?;
    let mut at = 12;
    for _ in 0..questions {
        at = skip_name(msg, at)? + 4;
    }
    for _ in 0..answers {
        at = skip_name(msg, at)?;
        let rtype = u16_at(msg, at)?;
        let class = u16_at(msg, at + 2)?;
        let ttl = u32::from(u16_at(msg, at + 4)?) << 16 | u32::from(u16_at(msg, at + 6)?);
        let len = usize::from(u16_at(msg, at + 8)?);
        let data = msg.get(at + 10..at + 10 + len).ok_or("a cut record")?;
        at += 10 + len;
        if class != CLASS_IN || rtype != qtype {
            continue;
        }
        let ip = match (rtype, len) {
            (TYPE_A, 4) => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data).map_err(|_| "a cut record")?)),
            (TYPE_AAAA, 16) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).map_err(|_| "a cut record")?)),
            _ => continue,
        };
        records.addrs.push(ip);
        records.ttl = Some(records.ttl.map_or(ttl, |t| t.min(ttl)));
    }
    Ok(records)
}

// --- Asking a nameserver ---

static NEXT_ID: AtomicU32 = AtomicU32::new(0);

fn next_id() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (NEXT_ID.fetch_add(0x9E37, Ordering::Relaxed) ^ nanos) as u16
}

fn exchange_udp(server: SocketAddr, packet: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let bind: SocketAddr = match server {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    socket.connect(server).map_err(|e| e.to_string())?;
    socket.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    socket.send(packet).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; UDP_BUFFER];
    let deadline = Instant::now() + timeout;
    loop {
        let n = socket.recv(&mut buf).map_err(|e| e.to_string())?;
        // An answer with another id (a late one to an earlier query) is passed by.
        if n >= 2 && buf[..2] == packet[..2] {
            buf.truncate(n);
            return Ok(buf);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("timed out".into());
        }
        socket.set_read_timeout(Some(left)).map_err(|e| e.to_string())?;
    }
}

fn exchange_tcp(server: SocketAddr, packet: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let mut stream = TcpStream::connect_timeout(&server, timeout).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    let len = u16::try_from(packet.len()).map_err(|_| "a query too long")?;
    stream.write_all(&len.to_be_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(packet).map_err(|e| e.to_string())?;
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).map_err(|e| e.to_string())?;
    let mut msg = vec![0u8; usize::from(u16::from_be_bytes(head))];
    stream.read_exact(&mut msg).map_err(|e| e.to_string())?;
    Ok(msg)
}

fn ask(server: SocketAddr, name: &str, qtype: u16, timeout: Duration) -> Result<Records, String> {
    let id = next_id();
    let packet = query(id, name, qtype)?;
    let answer = exchange_udp(server, &packet, timeout)?;
    let records = parse_answer(&answer, id, qtype)?;
    if !records.truncated {
        return Ok(records);
    }
    let answer = exchange_tcp(server, &packet, timeout)?;
    parse_answer(&answer, id, qtype)
}

/// What a name resolves to and for how long the answer holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub addrs: Vec<IpAddr>,
    pub ttl: Duration,
}

/// Resolves `name`, blocking: /etc/hosts, then the nameservers in their order (the next on a
/// failure), A and, with `ipv6`, AAAA. IPv4 addresses come first.
pub fn lookup(name: &str, nameservers: &[SocketAddr], options: Options) -> Result<Answer, String> {
    if let Ok(ip) = name.parse::<IpAddr>() {
        return Ok(Answer {
            addrs: vec![ip],
            ttl: options.ttl_max,
        });
    }
    let hosts = in_hosts(name);
    if !hosts.is_empty() {
        return Ok(Answer {
            addrs: hosts,
            ttl: options.ttl_max,
        });
    }
    if name.eq_ignore_ascii_case("localhost") {
        return Ok(Answer {
            addrs: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            ttl: options.ttl_max,
        });
    }
    if nameservers.is_empty() {
        return Err("no nameserver: /etc/resolv.conf names none and the proxy has no `resolvers`".into());
    }
    let mut last_error = String::new();
    for &server in nameservers {
        let a = match ask(server, name, TYPE_A, options.timeout) {
            Ok(records) => records,
            Err(e) => {
                last_error = format!("{server}: {e}");
                continue;
            }
        };
        let mut addrs = a.addrs;
        let mut ttl = a.ttl;
        if options.ipv6 {
            // Without an AAAA answer the A records serve; a failure here is not one of the name.
            if let Ok(aaaa) = ask(server, name, TYPE_AAAA, options.timeout) {
                addrs.extend(aaaa.addrs);
                ttl = match (ttl, aaaa.ttl) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
            }
        }
        if addrs.is_empty() {
            return Err(format!("{server}: no address for {name}"));
        }
        let ttl = Duration::from_secs(u64::from(ttl.unwrap_or(0))).clamp(options.ttl_min, options.ttl_max);
        return Ok(Answer { addrs, ttl });
    }
    Err(last_error)
}

// --- Keeping the snapshots current ---

/// A name of a set of upstreams, refreshed in the background while the set lives.
pub struct Watch {
    name: Box<str>,
    /// Which name of the set's this is.
    index: usize,
    nameservers: Arc<[SocketAddr]>,
    /// `refresh` of the directive; without it the answer's TTL.
    refresh: Option<Duration>,
    set: Weak<Set>,
    state: Mutex<State>,
}

struct State {
    due: Instant,
    /// Refreshes failed in a row (the next waits longer for each).
    failures: u32,
    /// The current term, the back-off's ceiling.
    term: Duration,
}

impl Watch {
    /// The term of an answer: `refresh`, or its TTL. The next refresh is due at 90% of it, so
    /// that the addresses are never past their term while the nameserver answers.
    fn next_term(&self, ttl: Duration) -> Duration {
        self.refresh.unwrap_or(ttl)
    }

    fn refresh(&self, set: &Set, now: Instant) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match lookup(&self.name, &self.nameservers, options()) {
            Ok(answer) => {
                let term = self.next_term(answer.ttl);
                if state.failures > 0 {
                    tracing::info!(name = %self.name, "the name resolves again");
                }
                set.addresses(self.index, answer.addrs);
                state.failures = 0;
                state.term = term;
                state.due = now + term.mul_f32(0.9);
            }
            Err(error) => {
                state.failures = state.failures.saturating_add(1);
                let wait = Duration::from_secs(1u64 << state.failures.min(16))
                    .min(state.term)
                    .max(Duration::from_secs(1));
                if state.failures == 1 {
                    tracing::warn!(name = %self.name, %error, "the name does not resolve: its addresses are kept as they are");
                } else {
                    tracing::debug!(name = %self.name, %error, failures = state.failures, "the name still does not resolve");
                }
                state.due = now + wait;
            }
        }
    }
}

type Watches = Arc<Mutex<Vec<Arc<Watch>>>>;

static REFRESHER: LazyLock<Worker<Arc<Watch>>> = LazyLock::new(|| {
    let watches: Watches = Arc::new(Mutex::new(Vec::new()));
    let taken = watches.clone();
    Worker::start(
        "webfast-dns",
        1024,
        5,
        Duration::from_secs(1),
        move |watch| {
            taken.lock().unwrap_or_else(|e| e.into_inner()).push(watch);
            async {}
        },
        move |_| tick(&watches),
    )
});

fn tick(watches: &Watches) {
    let now = Instant::now();
    let mut watches = watches.lock().unwrap_or_else(|e| e.into_inner());
    // A set that is gone (its configuration replaced) takes its watches with it.
    watches.retain(|w| w.set.strong_count() > 0);
    for watch in watches.iter() {
        let due = watch.state.lock().unwrap_or_else(|e| e.into_inner()).due;
        if due > now {
            continue;
        }
        if let Some(set) = watch.set.upgrade() {
            watch.refresh(&set, now);
        }
    }
}

/// The term a name that has not resolved yet is tried on: the back-off doubles from a second up
/// to this (a container that is not up yet, in Compose, comes within it).
const UNRESOLVED_TERM: Duration = Duration::from_secs(60);

/// Resolves every name of every `reverse_proxy` of `config`, now, and has them refreshed from
/// then on. A name that does not resolve is not an error: the start (or the reload) goes on, a
/// request to that upstream gets 502 until the name resolves, and the DNS thread keeps trying
/// (as Caddy serves, and as Compose brings containers up in its own order).
pub fn begin(config: &crate::config::Config) -> anyhow::Result<()> {
    let options = options();
    for set in config.upstream_sets() {
        for (index, name) in set.names().iter().enumerate() {
            let Some(host) = name.to_resolve() else {
                continue;
            };
            let nameservers = set.nameservers();
            let (due, failures, term) = match lookup(host, &nameservers, options) {
                Ok(answer) => {
                    let term = set.refresh().unwrap_or(answer.ttl);
                    set.addresses(index, answer.addrs);
                    (Instant::now() + term.mul_f32(0.9), 0, term)
                }
                Err(error) => {
                    tracing::warn!(
                        upstream = %name.text,
                        %error,
                        "the upstream name does not resolve yet: requests to it get 502 until it does"
                    );
                    (Instant::now() + Duration::from_secs(1), 1, UNRESOLVED_TERM)
                }
            };
            let watch = Arc::new(Watch {
                name: host.into(),
                index,
                nameservers,
                refresh: set.refresh(),
                set: Arc::downgrade(&set),
                state: Mutex::new(State { due, failures, term }),
            });
            if REFRESHER.submit(watch).is_err() {
                tracing::error!(name = %host, "the DNS thread takes no more names: this one is resolved once only");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf_gives_the_nameservers_in_order() {
        let text = "# comment\nsearch example.test\nnameserver 10.0.0.2\nnameserver 2001:db8::1 ; trailing\nnameserver fe80::1%eth0\noptions ndots:1\n";
        assert_eq!(
            parse_resolv_conf(text),
            vec![
                SocketAddr::from(([10, 0, 0, 2], 53)),
                SocketAddr::new("2001:db8::1".parse().unwrap(), 53)
            ]
        );
        assert!(parse_resolv_conf("").is_empty());
    }

    #[test]
    fn hosts_are_read_by_name() {
        let hosts =
            parse_hosts("127.0.0.1 localhost\n10.0.0.5 App app.internal # note\n\n::1 ip6-localhost\nbad line\n");
        assert_eq!(hosts.len(), 4);
        assert_eq!(hosts[1], ("app".into(), IpAddr::from([10, 0, 0, 5])));
        assert_eq!(hosts[2], ("app.internal".into(), IpAddr::from([10, 0, 0, 5])));
    }

    #[test]
    fn a_query_is_one_question() {
        let packet = query(0x1234, "app.internal.", TYPE_A).unwrap();
        assert_eq!(&packet[..12], &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&packet[12..], b"\x03app\x08internal\x00\x00\x01\x00\x01");
        assert!(query(1, "", TYPE_A).is_err());
        assert!(query(1, "a..b", TYPE_A).is_err());
        assert!(query(1, &"x".repeat(64), TYPE_A).is_err());
    }

    /// An answer as a nameserver writes it: the question echoed, the answers' names compressed.
    fn answer(id: u16, flags: u16, records: &[(u16, u32, &[u8])]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(&flags.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&(records.len() as u16).to_be_bytes());
        msg.extend_from_slice(&[0; 4]);
        msg.extend_from_slice(b"\x03app\x08internal\x00\x00\x01\x00\x01");
        for (rtype, ttl, data) in records {
            msg.extend_from_slice(&[0xC0, 12]); // a pointer to the question's name
            msg.extend_from_slice(&rtype.to_be_bytes());
            msg.extend_from_slice(&CLASS_IN.to_be_bytes());
            msg.extend_from_slice(&ttl.to_be_bytes());
            msg.extend_from_slice(&(data.len() as u16).to_be_bytes());
            msg.extend_from_slice(data);
        }
        msg
    }

    #[test]
    fn an_answer_gives_the_addresses_of_its_type_and_the_smallest_ttl() {
        let msg = answer(
            7,
            0x8180,
            &[
                (5, 300, b"\x03cdn\x08internal\x00"), // a CNAME: passed by
                (TYPE_A, 120, &[10, 0, 0, 1]),
                (TYPE_A, 30, &[10, 0, 0, 2]),
            ],
        );
        let records = parse_answer(&msg, 7, TYPE_A).unwrap();
        assert_eq!(
            records.addrs,
            vec![IpAddr::from([10, 0, 0, 1]), IpAddr::from([10, 0, 0, 2])]
        );
        assert_eq!(records.ttl, Some(30));
        assert!(!records.truncated);
        assert_eq!(parse_answer(&msg, 8, TYPE_A).unwrap_err(), "an answer to another query");
        assert_eq!(
            parse_answer(&answer(7, 0x8183, &[]), 7, TYPE_A).unwrap_err(),
            "no such name"
        );
        assert!(parse_answer(&answer(7, 0x8380, &[]), 7, TYPE_A).unwrap().truncated);
        let aaaa = answer(
            7,
            0x8180,
            &[(
                TYPE_AAAA,
                60,
                &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            )],
        );
        assert_eq!(
            parse_answer(&aaaa, 7, TYPE_AAAA).unwrap().addrs,
            vec!["2001:db8::1".parse::<IpAddr>().unwrap()]
        );
        assert!(parse_answer(&msg[..20], 7, TYPE_A).is_err(), "a cut message");
    }

    #[test]
    fn literals_and_localhost_need_no_nameserver() {
        let options = Options::default();
        assert_eq!(
            lookup("10.1.2.3", &[], options).unwrap().addrs,
            vec![IpAddr::from([10, 1, 2, 3])]
        );
        let local = lookup("localhost", &[], options).unwrap().addrs;
        assert!(
            !local.is_empty() && local.iter().all(|ip| ip.is_loopback()),
            "{local:?}"
        );
        assert!(
            lookup("app.internal", &[], options)
                .unwrap_err()
                .starts_with("no nameserver")
        );
    }

    /// A nameserver of the test's own on the loopback, answering every A query with `addrs`.
    fn nameserver(addrs: Vec<[u8; 4]>, ttl: u32) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = socket.recv_from(&mut buf) {
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                let qtype = u16::from_be_bytes([buf[n - 4], buf[n - 3]]);
                let records: Vec<(u16, u32, &[u8])> = if qtype == TYPE_A {
                    addrs.iter().map(|a| (TYPE_A, ttl, &a[..])).collect()
                } else {
                    Vec::new()
                };
                let _ = socket.send_to(&answer(id, 0x8180, &records), from);
            }
        });
        addr
    }

    #[test]
    fn a_name_is_asked_of_the_nameservers_in_turn() {
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let live = nameserver(vec![[10, 0, 0, 1], [10, 0, 0, 2]], 20);
        let options = Options {
            timeout: Duration::from_millis(500),
            ..Options::default()
        };
        let answer = lookup("app.internal", &[dead, live], options).unwrap();
        assert_eq!(
            answer.addrs,
            vec![IpAddr::from([10, 0, 0, 1]), IpAddr::from([10, 0, 0, 2])]
        );
        assert_eq!(answer.ttl, Duration::from_secs(20));
        let clamped = lookup(
            "app.internal",
            &[live],
            Options {
                ttl_min: Duration::from_secs(60),
                ..options
            },
        )
        .unwrap();
        assert_eq!(
            clamped.ttl,
            Duration::from_secs(60),
            "the TTL clamped to WEB_DNS_TTL_MIN"
        );
        let none = nameserver(Vec::new(), 20);
        assert!(
            lookup("app.internal", &[none], options)
                .unwrap_err()
                .ends_with("no address for app.internal")
        );
    }
}
