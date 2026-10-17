//! `rate_limit` (cargo feature `rate-limit`): requests per key and window, in the Caddyfile syntax
//! of the caddy-ratelimit plugin.
//!
//! ```caddyfile
//! rate_limit {
//!     zone api {
//!         match {
//!             path /api/*
//!         }
//!         key {client_ip}
//!         events 120
//!         window 1m
//!     }
//! }
//! ```
//!
//! Each zone is a GCRA (generic cell rate algorithm, the leaky bucket of nginx's `limit_req`): per
//! key one number, the time at which the key is fully rested again; `events` requests may come at
//! once, then one more every `window / events`. The plugin keeps every event of the window instead
//! (never more than `events` in any window, at the price of `events` timestamps per key); here a
//! key takes some 16 bytes whatever its limits, and after a pause up to twice `events` may pass in
//! one window.
//!
//! Zones are checked from the tightest to the most permissive, and the first exceeded ends the
//! check, as in the plugin; the request then fails with 429 and `Retry-After` (src/handler.rs
//! `HandlerError`: `handle_errors 429` can answer it). Keys are hashed with a key of the process's
//! own, kept in 64 shards each under its own lock; a sweeper thread drops the keys that are fully
//! rested again and logs, once per `sweep_interval`, how many requests each zone limited.
//! WEB_RATE_LIMIT_KEYS bounds the keys of a zone (when full, new keys are limited, as nginx does),
//! WEB_RATE_LIMIT_DRY_RUN only logs. The state of a zone outlives a reload when its name, limits
//! and key stay.

use crate::handler::Ctx;
use crate::matcher::{Matcher, MatcherSet};
use crate::placeholder::{Sole, Template};
use http::{HeaderValue, Method};
use rustc_hash::FxHashMap;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

/// The default of WEB_RATE_LIMIT_KEYS.
pub const DEFAULT_KEYS: usize = 1_000_000;

const SHARDS: usize = 64;

/// WEB_RATE_LIMIT_KEYS, the keys a zone remembers at most.
static MAX_KEYS: AtomicUsize = AtomicUsize::new(DEFAULT_KEYS);
/// WEB_RATE_LIMIT_DRY_RUN: limited requests are only counted and logged.
static DRY_RUN: AtomicBool = AtomicBool::new(false);

/// WEB_RATE_LIMIT_KEYS (a count) and WEB_RATE_LIMIT_DRY_RUN (`on` / `off`).
pub fn configure_from_env() -> Result<(), String> {
    if let Ok(value) = std::env::var("WEB_RATE_LIMIT_KEYS") {
        match value.trim().parse::<usize>() {
            Ok(n) if n >= SHARDS => MAX_KEYS.store(n, Ordering::Relaxed),
            _ => {
                return Err(format!(
                    "WEB_RATE_LIMIT_KEYS: a number of keys (at least {SHARDS}), not {value:?}"
                ));
            }
        }
    }
    if let Ok(value) = std::env::var("WEB_RATE_LIMIT_DRY_RUN") {
        let on = match value.trim().to_ascii_lowercase().as_str() {
            "on" | "1" | "true" => true,
            "off" | "0" | "false" => false,
            _ => return Err(format!("WEB_RATE_LIMIT_DRY_RUN: on or off, not {value:?}")),
        };
        DRY_RUN.store(on, Ordering::Relaxed);
    }
    Ok(())
}

/// Monotonic nanoseconds since the first use (the zones' clock).
fn now_nanos() -> u64 {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    START.elapsed().as_nanos() as u64
}

/// One `rate_limit` directive: its zones, tightest first.
pub struct RateLimit {
    zones: Vec<Zone>,
    jitter: f64,
}

/// A zone as configured, over its state.
struct Zone {
    matcher: Option<MatcherSet>,
    key: Key,
    state: Arc<ZoneState>,
}

/// How a request's key is found.
enum Key {
    /// One limiter for the whole zone.
    Static,
    /// The client's address (`{client_ip}`, `{remote_host}`), without making a string of it.
    Address(Sole),
    /// Any other template, rendered.
    Template(Template),
}

/// What a zone counts, shared by the configurations that have it.
struct ZoneState {
    name: Arc<str>,
    /// `window / events`, and the burst a rested key may make: `window - interval`.
    interval: u64,
    tolerance: u64,
    ipv4_prefix: u8,
    ipv6_prefix: u8,
    hasher: std::hash::RandomState,
    /// Key hash → the time (`now_nanos`) at which the key is fully rested.
    shards: Vec<Mutex<FxHashMap<u64, u64>>>,
    /// Since the last summary: requests limited, and up to a few of their keys (with `log_key`).
    limited: AtomicU64,
    keys_seen: Mutex<Vec<String>>,
    log_key: bool,
    sweep_every: Duration,
    /// What identifies the zone across reloads.
    identity: String,
}

/// The zones alive, for the sweeper and for reloads to take over.
static ZONES: Mutex<Vec<Weak<ZoneState>>> = Mutex::new(Vec::new());

/// A zone as parsed from the Caddyfile.
pub struct ZoneSpec {
    pub name: String,
    pub matcher: Option<MatcherSet>,
    pub key: Template,
    pub events: u64,
    pub window: Duration,
    pub ipv4_prefix: u8,
    pub ipv6_prefix: u8,
}

/// The directive's settings besides its zones.
pub struct Options {
    pub jitter: f64,
    pub sweep_interval: Duration,
    pub log_key: bool,
}

impl RateLimit {
    pub fn new(specs: Vec<ZoneSpec>, options: Options) -> RateLimit {
        let mut zones: Vec<Zone> = specs.into_iter().map(|spec| Zone::new(spec, &options)).collect();
        // Tightest first (the fewest events per unit of time), as the plugin orders them.
        zones.sort_by_key(|zone| std::cmp::Reverse(zone.state.interval));
        start_sweeper();
        RateLimit {
            zones,
            jitter: options.jitter,
        }
    }

    /// Whether ready answers stay right with this directive in front of them: every zone either
    /// never takes a GET or HEAD, or decides by the path alone (src/memo.rs).
    pub fn decided_by_path(&self) -> bool {
        self.zones.iter().all(|zone| match &zone.matcher {
            None => true,
            Some(set) => ready_safe(set),
        })
    }

    /// Counts the request in each zone it matches; the first zone exceeded gives its name and how
    /// long until the key may ask again. Preparing ready answers (src/memo.rs), nothing is counted:
    /// a path that some zone takes is only marked so that it gets no ready answer.
    pub fn check(&self, ctx: &mut Ctx) -> Option<(Arc<str>, Duration)> {
        let preparing = ctx.req.extensions.get::<crate::memo::Preparing>().is_some();
        let now = now_nanos();
        for zone in &self.zones {
            if !zone.matcher.as_ref().is_none_or(|m| m.matches(ctx)) {
                continue;
            }
            if preparing {
                ctx.req.extensions.insert(crate::memo::Unkept);
                return None;
            }
            let (hash, shown) = zone.key_of(ctx);
            if let Some(wait) = zone.state.take(hash, now) {
                zone.state.limited.fetch_add(1, Ordering::Relaxed);
                if zone.state.log_key {
                    zone.state.remember(shown.unwrap_or_else(|| zone.shown_key(ctx)));
                }
                if DRY_RUN.load(Ordering::Relaxed) {
                    continue;
                }
                let mut wait = Duration::from_nanos(wait);
                if self.jitter > 0.0 {
                    wait += wait.mul_f64(self.jitter * random_fraction());
                }
                return Some((zone.state.name.clone(), wait));
            }
        }
        None
    }
}

/// `Retry-After` for a wait: whole seconds, rounded up, at least one (the plugin means the same
/// with `wait + 0.5` rounded).
pub fn retry_after(wait: Duration) -> HeaderValue {
    HeaderValue::from(wait.as_secs_f64().ceil().max(1.0) as u64)
}

/// A zone's matcher set leaves ready answers right: it never takes a GET or HEAD, or it decides
/// by the path (a `method` matcher counts as the path when it takes both GET and HEAD).
fn ready_safe(set: &MatcherSet) -> bool {
    let takes = |methods: &[Method]| (methods.contains(&Method::GET), methods.contains(&Method::HEAD));
    if set
        .matchers
        .iter()
        .any(|m| matches!(m, Matcher::Method(methods) if takes(methods) == (false, false)))
    {
        return true;
    }
    set.matchers.iter().all(|m| match m {
        Matcher::Method(methods) => takes(methods) == (true, true),
        other => other.depends_on_path_only(),
    })
}

impl Zone {
    fn new(spec: ZoneSpec, options: &Options) -> Zone {
        let key = match spec.key.sole_address() {
            Some(sole) => Key::Address(sole),
            None if spec.key.as_static().is_some() => Key::Static,
            None => Key::Template(spec.key.clone()),
        };
        let events = spec.events.max(1);
        let window = spec.window.as_nanos().min(u128::from(u64::MAX / 4)) as u64;
        let interval = (window / events).max(1);
        let identity = format!(
            "{}|{events}|{window}|{}|{}|{}",
            spec.name,
            spec.key.source(),
            spec.ipv4_prefix,
            spec.ipv6_prefix
        );
        let state = ZoneState::find_or_make(identity, || ZoneState {
            name: Arc::from(spec.name.as_str()),
            interval,
            tolerance: window.saturating_sub(interval),
            ipv4_prefix: spec.ipv4_prefix,
            ipv6_prefix: spec.ipv6_prefix,
            hasher: std::hash::RandomState::new(),
            shards: (0..SHARDS).map(|_| Mutex::new(FxHashMap::default())).collect(),
            limited: AtomicU64::new(0),
            keys_seen: Mutex::new(Vec::new()),
            log_key: options.log_key,
            sweep_every: options.sweep_interval,
            identity: String::new(),
        });
        Zone {
            matcher: spec.matcher,
            key,
            state,
        }
    }

    /// The request's key hash, and the key as text when it was rendered anyway.
    fn key_of(&self, ctx: &Ctx) -> (u64, Option<String>) {
        let state = &self.state;
        match &self.key {
            Key::Static => (0, None),
            Key::Address(sole) => (state.hash_address(address(sole, ctx)), None),
            Key::Template(template) => {
                let text = template.render(ctx);
                let hash = match text.parse::<IpAddr>() {
                    Ok(ip) if state.ipv4_prefix > 0 || state.ipv6_prefix > 0 => state.hash_address(ip),
                    _ => state.hasher.hash_one(text.as_bytes()),
                };
                (hash, Some(text))
            }
        }
    }

    fn shown_key(&self, ctx: &Ctx) -> String {
        match &self.key {
            Key::Static => "static".to_string(),
            Key::Address(sole) => address(sole, ctx).to_string(),
            Key::Template(template) => template.render(ctx),
        }
    }
}

fn address(sole: &Sole, ctx: &Ctx) -> IpAddr {
    match sole {
        Sole::ClientIp => ctx.client_ip,
        Sole::RemoteHost => ctx.conn.remote.ip(),
    }
}

impl ZoneState {
    /// The zone's state from a configuration before this one (a reload), or a new one.
    fn find_or_make(identity: String, make: impl FnOnce() -> ZoneState) -> Arc<ZoneState> {
        let mut zones = ZONES.lock().unwrap_or_else(PoisonError::into_inner);
        zones.retain(|zone| zone.strong_count() > 0);
        if let Some(found) = zones
            .iter()
            .filter_map(Weak::upgrade)
            .find(|zone| zone.identity == identity)
        {
            return found;
        }
        let mut state = make();
        state.identity = identity;
        let state = Arc::new(state);
        zones.push(Arc::downgrade(&state));
        state
    }

    /// An address's hash, masked to the zone's prefixes.
    fn hash_address(&self, ip: IpAddr) -> u64 {
        let masked = match ip.to_canonical() {
            IpAddr::V4(v4) if self.ipv4_prefix > 0 => {
                let bits = u32::from(v4)
                    & (u32::MAX
                        .checked_shl(32 - u32::from(self.ipv4_prefix.min(32)))
                        .unwrap_or(0));
                IpAddr::V4(bits.into())
            }
            IpAddr::V6(v6) if self.ipv6_prefix > 0 => {
                let bits = u128::from(v6)
                    & (u128::MAX
                        .checked_shl(128 - u32::from(self.ipv6_prefix.min(128)))
                        .unwrap_or(0));
                IpAddr::V6(bits.into())
            }
            other => other,
        };
        self.hasher.hash_one(masked)
    }

    /// One request of the key at `now`: `None` when it may pass (and is counted), otherwise how
    /// many nanoseconds until it may.
    fn take(&self, hash: u64, now: u64) -> Option<u64> {
        let mut shard = self.shards[(hash as usize) % SHARDS]
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let full = shard.len() >= MAX_KEYS.load(Ordering::Relaxed) / SHARDS;
        if full && !shard.contains_key(&hash) {
            // As nginx when its zone is full: the rested keys go first, and if none did, the new
            // key is limited (for one interval) rather than let through uncounted.
            shard.retain(|_, rested_at| *rested_at > now);
            if shard.len() >= MAX_KEYS.load(Ordering::Relaxed) / SHARDS {
                return Some(self.interval);
            }
        }
        let rested_at = shard.entry(hash).or_insert(now);
        let at = (*rested_at).max(now);
        let ahead = at - now;
        if ahead > self.tolerance {
            return Some(ahead - self.tolerance);
        }
        *rested_at = at + self.interval;
        None
    }

    fn remember(&self, key: String) {
        let mut seen = self.keys_seen.lock().unwrap_or_else(PoisonError::into_inner);
        if seen.len() < 10 && !seen.contains(&key) {
            seen.push(key);
        }
    }

    /// Drops the keys fully rested again; how many keys remain.
    fn sweep(&self, now: u64) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                let mut shard = shard.lock().unwrap_or_else(PoisonError::into_inner);
                shard.retain(|_, rested_at| *rested_at > now);
                shard.len()
            })
            .sum()
    }
}

/// The thread that sweeps the zones and logs what they limited, each at its `sweep_interval`.
fn start_sweeper() {
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(|| {
        let spawned = std::thread::Builder::new().name("web-ratelimit".into()).spawn(|| {
            let mut last: FxHashMap<usize, Instant> = FxHashMap::default();
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let zones: Vec<Arc<ZoneState>> = {
                    let mut zones = ZONES.lock().unwrap_or_else(PoisonError::into_inner);
                    zones.retain(|zone| zone.strong_count() > 0);
                    zones.iter().filter_map(Weak::upgrade).collect()
                };
                for zone in zones {
                    let id = Arc::as_ptr(&zone) as usize;
                    let due = last.get(&id).is_none_or(|at| at.elapsed() >= zone.sweep_every);
                    if !due {
                        continue;
                    }
                    last.insert(id, Instant::now());
                    let keys = zone.sweep(now_nanos());
                    let limited = zone.limited.swap(0, Ordering::Relaxed);
                    if limited > 0 {
                        let seen = std::mem::take(&mut *zone.keys_seen.lock().unwrap_or_else(PoisonError::into_inner));
                        let message = if DRY_RUN.load(Ordering::Relaxed) {
                            "requests would be limited (WEB_RATE_LIMIT_DRY_RUN)"
                        } else {
                            "requests limited"
                        };
                        if zone.log_key {
                            tracing::warn!(zone = %zone.name, limited, keys, ?seen, "{message}");
                        } else {
                            tracing::warn!(zone = %zone.name, limited, keys, "{message}");
                        }
                    }
                }
            }
        });
        if let Err(e) = spawned {
            tracing::error!(error = %e, "cannot start the rate limit sweeper; keys are swept when a zone is full");
        }
    });
}

/// A number in [0, 1), different on every call.
fn random_fraction() -> f64 {
    let bits = std::hash::RandomState::new().hash_one(Instant::now());
    (bits >> 11) as f64 / (1u64 << 53) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(events: u64, window: Duration) -> ZoneState {
        let window = window.as_nanos() as u64;
        let interval = window / events;
        ZoneState {
            name: Arc::from("test"),
            interval,
            tolerance: window - interval,
            ipv4_prefix: 0,
            ipv6_prefix: 0,
            hasher: std::hash::RandomState::new(),
            shards: (0..SHARDS).map(|_| Mutex::new(FxHashMap::default())).collect(),
            limited: AtomicU64::new(0),
            keys_seen: Mutex::new(Vec::new()),
            log_key: false,
            sweep_every: Duration::from_secs(60),
            identity: String::new(),
        }
    }

    #[test]
    fn events_at_once_then_one_per_interval() {
        let zone = state(3, Duration::from_secs(3));
        let second = 1_000_000_000;
        for _ in 0..3 {
            assert_eq!(zone.take(7, 0), None);
        }
        assert_eq!(zone.take(7, 0), Some(second), "the fourth waits one interval");
        assert_eq!(zone.take(8, 0), None, "another key has its own");
        assert_eq!(zone.take(7, second - 1), Some(1));
        assert_eq!(zone.take(7, second), None);
        assert_eq!(zone.take(7, second), Some(second));
        // Rested again after the window: swept.
        assert_eq!(zone.sweep(10 * second), 0);
        for _ in 0..3 {
            assert_eq!(zone.take(7, 10 * second), None);
        }
    }

    #[test]
    fn prefixes_group_addresses() {
        let mut zone = state(1, Duration::from_secs(60));
        zone.ipv6_prefix = 64;
        zone.ipv4_prefix = 24;
        let a = zone.hash_address("2001:db8:1:2::1".parse().unwrap());
        let b = zone.hash_address("2001:db8:1:2:ffff::9".parse().unwrap());
        let c = zone.hash_address("2001:db8:1:3::1".parse().unwrap());
        assert_eq!(a, b);
        assert_ne!(a, c);
        let d = zone.hash_address("203.0.113.7".parse().unwrap());
        let e = zone.hash_address("203.0.113.200".parse().unwrap());
        assert_eq!(d, e);
    }

    #[test]
    fn retry_after_rounds_up() {
        assert_eq!(retry_after(Duration::from_millis(1)), "1");
        assert_eq!(retry_after(Duration::from_millis(1500)), "2");
        assert_eq!(retry_after(Duration::from_secs(20)), "20");
    }
}
