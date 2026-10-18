# Extensions

How the optional pieces of webfast plug into the core, so that the next one is written
against a small, named set of hook points instead of edits scattered through the request path.
Extensions are cargo features: an extension that is not built costs nothing, not even a branch
on the request path. This document says where it started, what the design is, and how the
migration to it was done.

## Where it started

Before the migration (October 2026), every extension gated its own module
(`#[cfg(feature = …)] pub mod …` in `src/lib.rs`), read its environment in a `configure_from_env`,
and ran its background work on a thread of its own. Those were conventions; the ways they reached
the request path were not:

| Extension        | How it took part                                                                                                                          |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `rate-limit`     | a `Handler` variant made by the Caddyfile parser; a call inside `reverse_proxy` for the per-client slot                                    |
| `proxy-cache`    | a `Handler` variant; a field on `Ctx` (`cache_miss`) the proxy took; calls at three points of `reverse_proxy`                               |
| `jwt`            | a field on `Checks` in `server.rs`, called before the routes; a call inside `reverse_proxy` (`check_upstream`) and inside `cache` on a hit |
| `api-firewall`   | the same as `jwt`, with the body passed through; `local_fetch` and `InternalRequest` in `server.rs` for specs read from the server itself  |
| `compress-files` | calls inside `file_server`; a callback the server installed so variants could redo ready answers                                          |

Seventy-six `#[cfg]` sites in the core. Each extension knew the core, and the core knew each
extension by name: `Checks` had a field per check and `cfg`-paired branches in five methods, the
proxy a `Slot` type alias with a `cfg` on each arm, `Ctx` carried one extension's state as a named
field. Adding an extension meant finding each of those places again.

## The target

### One trait per hook point, not one trait for everything

An extension is not one object that implements every possible hook. It implements the traits of
the points it needs. Small traits keep each one honest (interface segregation): the proxy cache
needs the response as it streams, the JWT check does not; nothing implements methods it does not
use.

```rust
/// Before the site's routes and ready answers: refuse, or let through (perhaps changed).
pub trait RequestCheck: Send + Sync {
    async fn check(&self, req: &mut Head, body: Body, client: Client<'_>) -> Result<Body, Response<Body>>;
}

/// At a reverse_proxy, on the request as it goes to one of `upstreams`.
pub trait UpstreamCheck: Send + Sync {
    async fn check(&self, req: &mut Head, body: Body, client: Client<'_>, upstreams: &[Authority]) -> Result<Body, Response<Body>>;
}

/// Decides what a file_server answers when a file has no precompressed sibling.
pub trait Representation: Send + Sync {
    fn choose(&self, file: &Arc<FileEntry>, store: &Arc<FileStore>, accept: Ranked<'_>) -> Chosen;
}

/// Sees a proxied response on its way to the client; may keep it.
pub trait ResponseObserver: Send + Sync {
    fn observe(&self, req: &Head, res: &mut http::response::Parts, body: Body) -> Body;
}
```

`Result<Body, Response<Body>>` is the body to go on with, or the answer that refuses: exactly what
`Checks::check` returns today; the trait only names it. The methods are `async fn` in traits
(Rust 1.75; the MSRV is 1.88), so no future is boxed.

### Hooks are composed at compile time, not listed at run time

The set of extensions is known when the binary is built, so the hooks of a point are a type, not
a vector of trait objects. Each trait is implemented for the empty tuple (nothing to do), for a
pair (first one, then the other) and for `Option` (built, but not configured):

```rust
impl RequestCheck for () {
    async fn check(&self, _: &mut Head, body: Body, _: Client<'_>) -> Result<Body, Response<Body>> {
        Ok(body)
    }
}

impl<A: RequestCheck, B: RequestCheck> RequestCheck for (A, B) {
    async fn check(&self, req: &mut Head, body: Body, client: Client<'_>) -> Result<Body, Response<Body>> {
        let body = self.0.check(req, body, client).await?;
        self.1.check(req, body, client).await
    }
}

impl<T: RequestCheck> RequestCheck for Option<T> {
    async fn check(&self, req: &mut Head, body: Body, client: Client<'_>) -> Result<Body, Response<Body>> {
        match self {
            Some(check) => check.check(req, body, client).await,
            None => Ok(body),
        }
    }
}
```

What this costs on the request path, for each hook point:

- **No extension built:** the hooks are `()`. The call compiles to nothing: no branch, no load.
- **Built, not configured:** one test of an `Option`, as `checks.any()` is today.
- **Configured:** a direct call, inlined where the compiler sees fit; the future lives on the
  caller's stack. The same cost as today's hand-written call.

The order of the hooks is the order in the type, fixed by the core: JWT before the API firewall,
because the firewall sees the claim headers the JWT check set. An extension cannot put itself
first, and the order cannot drift at run time.

### Composition in one place

The `cfg` knowledge lives in a single file. Each extension occupies a slot of a nested pair, and
`()` fills the slot when the feature is off, so the number of `cfg` arms grows with the extensions
and not with their combinations:

```rust
// src/extensions.rs
#[cfg(feature = "jwt")]
type Jwt = Option<Arc<crate::jwt::JwtAuth>>;
#[cfg(not(feature = "jwt"))]
type Jwt = ();

#[cfg(feature = "api-firewall")]
type ApiFirewall = Option<Arc<crate::apifw::ApiFirewall>>;
#[cfg(not(feature = "api-firewall"))]
type ApiFirewall = ();

/// The checks before the routes, in order; `()` where a feature is off.
pub type RequestChecks = (Jwt, (ApiFirewall, ()));

pub fn request_checks(config: &Config) -> RequestChecks {
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
```

`ServerState` holds a `Hooks { request: RequestChecks, upstream: UpstreamChecks, … }` and gives
`Ctx` a reference to what the chain needs. Every hook point in the core is one call, written once:

```rust
let body = state.hooks.request.check(&mut parts, body, client).await?;
```

Startup goes through the same file. `extensions::configure_from_env()` reads each built
extension's `WEB_*` variables and stops the start on a variable of one that is not built (so
`WEB_PROXY_CACHE_MEMORY` on a build without `proxy-cache` is an error, as a misspelt variable
would be). `extensions::load_checks(&mut config)` loads the files `WEB_JWT_CONFIG` and
`WEB_API_FIREWALL_CONFIG` name and gives back one line per extension for the startup log and
`validate`. `extensions::Started` does what runs once the server does: `begin` before the servers
take the configuration (the JWT keys start being read), `finish` with the ports' states (API specs
given as a path are read through the first port's routes; the variants get the callback that redoes
ready answers). `server.rs` and `main.rs` call these four and name no extension.

When a hook must be chosen at run time — extensions configured per site, say — the same traits
take a `Vec<Arc<dyn …>>` behind an object-safe wrapper; nothing in the core needs that today, and
the static form stays the default.

### Request-scoped state through typed extensions

An extension that needs to leave something on the request for a later hook (the JWT check marks
`Credentialed`; the cache marks a miss) puts a type of its own into `http::Extensions` and reads
it back there. The core defines no field for it, and two extensions cannot collide: the type is
the key. `Preparing`, `Unkept`, `FromFile` and `InternalRequest` already work this way; the rule
is that everything does.

### What a hook may touch

Each trait's signature says what the hook sees and may change, and nothing else: a
`RequestCheck` gets the request head mutably and the body by value, and gives a body back or an
answer. It cannot reach the routes, the site, other hooks or the connection beyond `Client`
(address, trusted, TLS, SNI). This is the open/closed line: the core can be extended at these
points without being modified, and an extension cannot do more than the point allows. A new need
means a new hook point, added to the core deliberately, with its own trait.

### Directives stay the parser's

`rate_limit` and `cache` are Caddyfile directives and that is right: they belong in the chain,
where the user puts them. The `Handler` enum keeps a variant per directive, and the parser keeps
its `cfg`-gated arms. That is the one place `cfg` stays in the core besides `extensions.rs`, and
it is where a reader expects to find a directive. A directive that needs a hook elsewhere (the
cache in the proxy) registers it through `extensions.rs` like any other, instead of being called
by name from `reverse_proxy`.

### Background work through one worker shape

Three extensions run a thread: the cache's `web-cache`, the variants' `webfast-compress`, the rate
limit's `web-ratelimit`; the JWKS and spec refreshers run on the tokio runtime. The threads share
a shape, and the code, in `src/background.rs`:

```rust
pub struct Worker<J> { … }
impl<J: Send + 'static> Worker<J> {
    /// A thread `name` with a current-thread runtime: `run` on each job, `tick` every `every`
    /// with the jobs not taken since the last; `nice` below the requests' threads (Linux).
    pub fn start(name: &'static str, queue: usize, nice: i32, every: Duration, run: R, tick: T) -> Worker<J>;
    /// A full queue (or a worker that could not start) gives the job back and counts it.
    pub fn submit(&self, job: J) -> Result<(), J>;
}
```

Each is a `static WORKER: LazyLock<Worker<Job>>` in its module; the rate limit's has no jobs
(`Worker<Infallible>`) and only ticks. The same for bounded memory with CLOCK eviction, which the
cache and the variants each had a copy of:

```rust
pub struct Budget<K> { … }              // the order entries came in, and the sum of their sizes
pub enum Seen { Gone, Marked, Evicted(usize) }
impl<K> Budget<K> {
    pub fn add(&mut self, key: K, size: usize);
    pub fn release(&mut self, size: usize);  // removed by the owner (replaced, swept)
    pub fn evict(&mut self, max: usize, look: impl FnMut(&K) -> Seen);  // the CLOCK pass
    pub fn retain(&mut self, keep: impl FnMut(&K) -> bool);
}
```

The budget keeps the order and the sum; the owner keeps the entries and their marks however its
readers need them (the cache in sharded maps read lock-free of the budget, the variants under one
`RwLock`), and answers for each entry when its turn comes. Nothing of either is on the request
path but a `try_send` and an atomic mark.

### What stays as it is

- Cargo features gate whole modules, and the default build turns every extension on.
- An extension's configuration is its own: a YAML file for the checks, directive options for the
  directives, environment variables for memory bounds. Nothing moves into the Caddyfile that Caddy
  could not read.
- Performance rules hold for hooks as for the core: no allocation on the request path for a request
  the hook does not act on, decisions on the request head only, bodies passed through by value.

## The patterns, and why these

- **Traits per hook point** (not one `Extension` trait with optional methods): a trait with one
  method is implemented in ten lines, and a hook point's signature says exactly what a hook may
  touch. `Send + Sync` on each because hooks run on every worker.
- **Static composition over trait objects:** the set of extensions is fixed at build time, so
  `()`, pairs and `Option` compose it with no dynamic dispatch, no boxed future and nothing at all
  for a feature that is off. A `Vec<Arc<dyn …>>` would cost a vtable call and a heap allocation per
  hook, and could not be optimised away.
- **Composition in the core, by the core:** inventory-style self-registration (`linkme`,
  `inventory`) was considered and rejected. It hides the order, needs link-time tricks, and buys
  nothing here: the set of extensions is known at build time.
- **Typed request extensions instead of fields on `Ctx`:** `http::Extensions` is the crate's own
  mechanism for exactly this, and keeps `Ctx` ignorant of extensions.
- **Generic worker and budget instead of traits:** the queue, the thread and the eviction do not
  vary in behaviour, only in the job type, so generics (monomorphised, no dynamic dispatch) fit,
  and the extension supplies a closure.
- **No `cfg` outside `extensions.rs`, the parser and the modules themselves:** the request path
  reads as one thing. A reviewer sees one call per hook point, not five extensions' branches.

## Writing an extension, then

1. Add the feature in `Cargo.toml` and the gated module in `src/lib.rs`.
2. Give the module a config type and `configure_from_env` / `load`; its startup line goes in
   `load_checks`, its variables in `configure_from_env`.
3. Implement the trait of each hook point it needs; put request-scoped state in a type of its own.
4. Give it a slot in `src/extensions.rs`: its type alias with the `cfg` pair, its place in the
   tuple, its value in the constructor; name the environment variables it reads.
5. Background work: `Worker::start`; bounded memory: `Budget`.
6. Tests: the module's own, one end-to-end test through the server, and the feature alone under
   clippy (`scripts/check.sh` runs each feature by itself).
7. Docs: a section in `docs/configuration.md` or `docs/operations.md`, a row in the features table
   of `docs/overview.md`, a CHANGELOG line.

## How it was done

In five commits, each leaving the tests green and measured with `examples/bench.rs` before and
after (release, the chain in process; with no extension built the numbers did not move, with
every extension built they stayed within the run-to-run noise, and the allocations per request
were the same at every step):

1. `src/extensions.rs` with `RequestCheck` and `UpstreamCheck`, composed as types; `Checks`
   became `Hooks`. The API firewall stopped knowing the JWT module: the query parameters the
   event log hides are left on the request by the JWT check (`eventlog::HiddenParams`).
2. The cache miss became a typed request extension (`cache::PendingMiss`); `Ctx::cache_miss`
   went. The site's `encode` a request passed is a plain field on `Ctx` (a core directive): a
   first try through `http::Extensions` cost three allocations per request and was taken back.
3. `ProxyObserver` (the cache in the proxy), `Representation` (the variants in `file_server`), and
   the rate limit's slot as an `UpstreamCheck` with a `Held` guard; hooks `&'static`, one per
   process, so a request copies a pointer and touches no `Arc`.
4. `Worker` and `Budget`, with the three threads and the two evictions moved onto them.
5. `configure_from_env`, `load_checks` and `Started` in `extensions.rs`; `server.rs` and
   `main.rs` lost their last extension branches.

`#[cfg]` sites in the core went from 76 to 24: the Caddyfile parser's directive arms and the two
fields on `Config` (`config.rs`, 13), the `Handler` variants of the two directives and their
dispatch (`handler.rs`, 7, and `memo.rs`, 2), one proxy method only the cache calls, the module
list in `lib.rs` and the allocator in `main.rs`. `extensions.rs` holds the rest (43), which is the
point.
