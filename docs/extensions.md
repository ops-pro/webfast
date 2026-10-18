# Extensions

A design for how optional pieces of webfast plug into the core, so that the next one is written
against a small, named set of hook points instead of edits scattered through the request path.
Extensions stay cargo features: an extension that is not built costs nothing, not even a branch
on the request path. This document says what exists today, what the target looks like, and how to
get there without a rewrite.

## Today

Every extension gates its own module (`#[cfg(feature = …)] pub mod …` in `src/lib.rs`), reads its
environment in a `configure_from_env`, and runs its background work on a thread of its own. Those
are conventions; the ways they reach the request path are not:

| Extension        | How it takes part                                                                                                                         |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `rate-limit`     | a `Handler` variant made by the Caddyfile parser; a call inside `reverse_proxy` for the per-client slot                                    |
| `proxy-cache`    | a `Handler` variant; a field on `Ctx` (`cache_miss`) the proxy takes; calls at three points of `reverse_proxy`                              |
| `jwt`            | a field on `Checks` in `server.rs`, called before the routes; a call inside `reverse_proxy` (`check_upstream`) and inside `cache` on a hit |
| `api-firewall`   | the same as `jwt`, with the body passed through; `local_fetch` and `InternalRequest` in `server.rs` for specs read from the server itself  |
| `compress-files` | calls inside `file_server`; a callback the server installs so variants can redo ready answers                                             |

Some seventy `#[cfg]` sites in five core files. Each extension knows the core, and the core knows
each extension by name: `Checks` has a field per check and `cfg`-paired branches in five methods,
the proxy has a `Slot` type alias with a `cfg` on each arm, `Ctx` carries one extension's state as
a named field. Adding an extension means finding each of those places again.

## The target

### One trait per hook point, not one trait for everything

An extension is not one object that implements every possible hook. It implements the traits of
the points it needs, and registers an object for each. Small traits keep each one honest
(interface segregation): the proxy cache needs the response as it streams, the JWT check does not;
nothing implements methods it does not use.

```rust
/// Before the site's routes and ready answers: refuse, or let through (perhaps changed).
pub trait RequestCheck: Send + Sync {
    fn check<'a>(&'a self, req: &'a mut Head, body: Body, client: Client<'a>) -> Checked<'a>;
}

/// At a reverse_proxy, on the request as it goes to one of `upstreams`.
pub trait UpstreamCheck: Send + Sync {
    fn check<'a>(&'a self, req: &'a mut Head, body: Body, client: Client<'a>, upstreams: &'a [Authority]) -> Checked<'a>;
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

`Checked<'a>` is a boxed future of `Result<Body, Response<Body>>`: the body to go on with, or the
answer that refuses. That is exactly what `Checks::check` returns today; the trait only names it.

### Hooks are owned by the place they run

The core keeps a registry per hook point, not one global list:

```rust
pub struct Hooks {
    pub request: Vec<Arc<dyn RequestCheck>>,
    pub upstream: Vec<Arc<dyn UpstreamCheck>>,
    pub representation: Vec<Arc<dyn Representation>>,
    pub response: Vec<Arc<dyn ResponseObserver>>,
}
```

`ServerState` holds one `Arc<Hooks>` and gives `Ctx` the parts it needs (`Ctx::upstream_hooks`
replaces `Ctx::upstream_checks` and `Ctx::cache_miss`: one field, any extension). Every hook point
in the core is one loop over its list, written once:

```rust
for check in &hooks.request {
    body = check.check(&mut parts, body, client).await?;
}
```

With no extension built the lists are empty and the loop is skipped by one length test. That is
the cost of the design on the request path: one branch per hook point, the same as today's
`checks.any()`. Nothing is dispatched through a trait object unless an extension is registered,
and an extension that is built but not configured registers nothing.

Order within a list is the registration order, and registration order is fixed by the core
(`src/extensions.rs`), not by the extensions: JWT before the API firewall, because the firewall
sees the claim headers the JWT check set. An extension cannot put itself first.

### Registration in one place

The `cfg` knowledge lives in a single file:

```rust
// src/extensions.rs
pub fn register(config: &Config, hooks: &mut Hooks) -> Result<()> {
    #[cfg(feature = "jwt")]
    if let Some(jwt) = &config.jwt {
        hooks.request.push(jwt.clone());
        hooks.upstream.push(jwt.clone());
    }
    #[cfg(feature = "api-firewall")]
    if let Some(fw) = &config.api_firewall {
        hooks.request.push(fw.clone());
        hooks.upstream.push(fw.clone());
    }
    #[cfg(feature = "compress-files")]
    hooks.representation.push(Arc::new(crate::variants::Variants));
    Ok(())
}
```

`main.rs` keeps the environment the same way: one `extensions::configure_from_env()` that calls
each extension's, and one list of the variables an unbuilt extension would have read, so that
`WEB_PROXY_CACHE_MEMORY` on a build without `proxy-cache` still stops the start. Startup logging
of what an extension loaded goes through one `Describe` trait (`fn describe(&self) -> String`),
so `validate` and the `started` line print every extension the same way.

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

Three extensions run a thread: the cache's `web-cache`, the variants' `webfast-compress`, the
JWKS and spec refreshers on the tokio runtime. They share a shape — a bounded queue, a job type,
a drop counter, a periodic sweep, a summary line — and should share the code:

```rust
pub struct Worker<J> { … }
impl<J: Send + 'static> Worker<J> {
    pub fn start(name: &'static str, queue: usize, nice: i32, run: impl FnMut(J) + Send + 'static) -> Worker<J>;
    pub fn submit(&self, job: J) -> bool;   // false: the queue was full, counted
    pub fn every(&self, period: Duration, tick: impl FnMut() + Send + 'static);
}
```

The same for bounded memory with CLOCK eviction, which the cache and the variants each have a
copy of today (`Store` and `Variants`): one `Budget<K, V>` with `insert`, `touch`, `evict_to`,
`sweep`, and the counters the summary line prints.

### What stays as it is

- Cargo features gate whole modules, and the default build turns every extension on.
- An extension's configuration is its own: a YAML file for the checks, directive options for the
  directives, environment variables for memory bounds. Nothing moves into the Caddyfile that Caddy
  could not read.
- Performance rules hold for hooks as for the core: no allocation on the request path for a request
  the hook does not act on, decisions on the request head only, bodies passed through by value.

## The patterns, and why these

- **Traits per hook point** (not one `Extension` trait with optional methods): Rust's trait
  objects cost a dynamic call per hook, so the fewer and more specific the better, and a trait with
  one method is implemented in ten lines. `Send + Sync` on each because hooks run on every worker.
- **Registration in the core, by the core:** inventory-style self-registration (`linkme`,
  `inventory`) was considered and rejected. It hides the order, needs link-time tricks, and buys
  nothing here: the set of extensions is known at build time.
- **Typed request extensions instead of fields on `Ctx`:** `http::Extensions` is the crate's own
  mechanism for exactly this, and keeps `Ctx` ignorant of extensions.
- **Generic worker and budget instead of traits:** the queue, the thread and the eviction do not
  vary in behaviour, only in the job type, so generics (monomorphised, no dynamic dispatch) fit,
  and the extension supplies a closure.
- **No `cfg` outside `extensions.rs`, the parser and the modules themselves:** the request path
  reads as one thing. A reviewer sees the hook loop, not five extensions' branches.

## Writing an extension, then

1. Add the feature in `Cargo.toml` and the gated module in `src/lib.rs`.
2. Give the module a config type and `configure_from_env` / `load`, and a `describe`.
3. Implement the trait of each hook point it needs; put request-scoped state in a type of its own.
4. Register it in `src/extensions.rs`, in order, and name the environment variables it reads.
5. Background work: `Worker::start`; bounded memory: `Budget`.
6. Tests: the module's own, one end-to-end test through the server, and the feature alone under
   clippy (`scripts/check.sh` runs each feature by itself).
7. Docs: a section in `docs/configuration.md` or `docs/operations.md`, a row in the features table
   of `docs/overview.md`, a CHANGELOG line.

## Getting there

In steps that each leave the tests green, roughly in this order:

1. `src/extensions.rs` with `Hooks`, the four traits and `register`; `Checks` becomes the
   `request` and `upstream` lists; `Ctx::upstream_checks` becomes `Ctx::hooks`. The behaviour is
   the same; `server.rs` and `proxy.rs` lose their `jwt` / `api-firewall` branches.
2. `Credentialed` and the cache miss move to `http::Extensions`; `Ctx::cache_miss` goes.
3. The cache's three calls in `reverse_proxy` become one `ResponseObserver` and one
   `RequestCheck`-shaped hit check; the rate limit's upstream slot becomes an `UpstreamCheck`
   whose body is a guard dropped with the response.
4. `Worker` and `Budget`, with the cache and the variants moved onto them.
5. `Describe` and one `configure_from_env` in `main.rs`.

Each step is a commit of its own with the `cfg` count in the core going down; the end state is
`cfg` in `extensions.rs`, `config.rs` (directive arms), `lib.rs` and `main.rs` only.
