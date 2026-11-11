# Modules

How to write a module for webfast as a crate of its own, against the core's public API
(`webfast_core`, crates/webfast-core), and how the binary composes the modules it is built with.
The two modules of [webfast-modules](https://github.com/ops-pro/webfast-modules) — the request
filter (`crates/webfast-ngfw`, its docs/ngfw.md) and the browser challenge
(`crates/webfast-challenge`, its docs/challenge.md) — are written this way and serve as the worked
example below: they reach the core only through `webfast_core::` paths, as any external crate
does, and the core names neither.

The extensions that stay in the core (the JWT check, the API firewall, the rate limit, the proxy
cache, compressed variants, ACME) are composed as docs/extensions.md describes; this document is
about what lives outside it.

## The shape

```
crates/webfast-core      the library: the server, the Caddyfile, the hook traits, `module`, `run`
crates/webfast           the binary: main.rs, compose.rs (which modules, in what order)
webfast-modules          another repository: crates/webfast-ngfw, crates/webfast-challenge, each
                         with its integration tests on the core's harness
```

A module is a crate that depends on `webfast-core` and provides:

- a `Module` (`webfast_core::module::Module`): one static the binary registers;
- the directives it adds to the Caddyfile, each a `Directive` with a parser and a place in the
  directive order, whose routes run a `RouteHandler`;
- its hooks on the request path: a `Check` (before the routes) and/or an `Inspect` (on proxied
  responses), which the binary puts in its composed tuples;
- its state, loaded from its own files (the environment names them) into `Config::modules`.

The binary (`crates/webfast/src/compose.rs`) names the modules and the order of their hooks, and
`main.rs` is three lines: the allocator, the vDSO shim, and
`webfast_core::run::main(webfast::compose::composition())`.

## What the request path costs

Nothing more than when the modules were `cfg`s of the core. The core calls the composed set of
checks through one `&'static dyn module::Checks` and the set of inspectors through one
`&'static dyn module::Inspectors` — one vtable call per request for the whole set — and the
protocol is synchronous first:

- `Check::head(&self, &mut Parts, Client) -> Head<Self::Pending>` sees the request's head and
  answers `Pass`, `Refuse(response)` or `Body(pending)`. A clean GET is `Pass` from every head:
  no future, no allocation.
- `Body(pending)` hands the body phase what the head found, by value (`Check::Pending`: the
  request filter's state and evaluation so far; `()` for the challenge's endpoint) — nothing goes
  through the request's extensions. `Check::body(pending, …)` returns `impl Future`, unboxed.
- The whole set costs one boxed future for a request whose body some check asked for, and none
  otherwise: `Checks::check` runs the heads and returns `Checking::Done(checked)`, or
  `Checking::Body(future)` — one box over the body of the check that asked and the heads (and
  bodies) of the checks after it, however many there are.
- `Inspect::covers(&self, &Ctx, &response::Parts) -> bool` is a plain call; the set boxes one
  future for a response some inspector covers (over every inspector that covers it,
  `Inspect::inspect` returning `impl Future`), none for the others.

The sets themselves are tuples the binary writes — `(ChallengeEndpoint, (Option<Arc<Ngfw>>, ()))`
— so the order is a type fixed at compile time, and `()` is a module that is not built. The core
keeps the pairs' bookkeeping in two traits per kind: the generic `module::CheckSet` and
`module::InspectSet` (implemented for every leaf, for `()`, `Option<T>`, `Arc<T>` and pairs; a
pair's `Pending` is `Stage::First(a)` or `Stage::Second(b)`), whose futures are not boxed, and the
object-safe `module::Checks` and `module::Inspectors` the core calls through `&'static dyn`
(implemented for every generic set, and boxing once). A module implements `Check` or `Inspect`
alone.

`Handler::Extension(Arc<dyn RouteHandler>)` is a vtable call where `Handler::Challenge` was a
match arm; `RouteHandler::run` is synchronous, as the directive handlers of the core are.

## The `Module` trait

```rust
pub trait Module: Sync + Send + 'static {
    fn name(&self) -> &'static str;
    fn directives(&self) -> &'static [Directive] { &[] }
    fn configure_from_env(&self) -> Result<(), String> { Ok(()) }
    fn seed(&self, seed: Option<&[u8]>) {}
    fn load(&self, config: &mut Config) -> anyhow::Result<Vec<String>> { Ok(Vec::new()) }
    fn start(&self, config: &Config) -> anyhow::Result<()> { Ok(()) }
    fn reload(&self) -> Vec<String> { Vec::new() }
    fn validate(&self, config: &Config) -> Vec<String> { /* the routes of its directives */ }
}
```

In the order the binary calls them:

1. `directives()` — registered by `module::install` before the Caddyfile is read. A name the
   core or another module has, or an `Order` relative to a directive no one has, is an error at
   start.
2. `configure_from_env()` — the module's WEB_* variables, before the configuration; an error is
   fatal, as the core's own are. A module whose cargo feature is off should still refuse its
   variables: register a `module::Unbuilt { what, feature, variables }` in its place (compose.rs
   does for a module whose feature is off), so a variable of an unbuilt module stops the start
   instead of being ignored.
3. `seed(Some(bytes))` — the TLS ticket seed (WEB_TLS_TICKET_SEED), before the configuration is
   loaded. The challenge derives its cookie keys from it, so every replica given the seed
   accepts the others' cookies.
4. `load(&mut config)` — after the Caddyfile is compiled and the core's checks (JWT, API
   firewall) are loaded. The module reads its file, puts its state into `config.modules`
   (`TypeMap::insert(Arc<T>)`), and returns one line per thing loaded, for the startup log and
   `webfast validate`. `config.hidden_params` holds the query parameters the core's checks hide
   from their logs; a module that logs requests before them hides them too (the request filter
   does).
5. `validate(&config)` — `webfast validate` prints its lines after the loaded checks'. The default
   lists every route of the module's directives: `challenge example.com: level js, valid 604800s,
   bind ip`.
6. `start(&config)` — on the runtime, as the server is about to take the configuration: background
   work starts here (the request filter's feeds and sweeps). Not called by `validate`.
7. `reload()` — SIGHUP. The hooks are `&'static` (a reload keeps them), so a module that reads
   its own file again swaps its state in place (`ArcSwap`) and keeps the old one when the new does
   not load; it says what happened, one line each.

## Directives

```rust
pub struct Directive { pub name: &'static str, pub parse: DirectiveParser, pub order: Order }
pub type DirectiveParser = fn(&Line, &Scope, &mut Cx, &mut SiteCx) -> anyhow::Result<Vec<Entry>>;
pub enum Order { Before(&'static str), After(&'static str) }
```

The parser gets the Caddyfile line (`caddyfile::Line`: its `tokens`, its `block`, its `at`), the
named matchers in scope, and the compilation contexts (`config::Cx`, `config::SiteCx`: opaque,
passed on). What it needs from `webfast_core::config`:

- `matcher_token(line, scope)` — the matcher after the directive name (`*`, `/path`, `@name`) and
  where the arguments start;
- `add_matcher(set, kind, args, block, at, def_name, cx, site)` — a matcher line into a
  `MatcherSet` (the challenge's `except { … }` block is a matcher block);
- `parse_duration`, `parse_size` (`webfast_core::parse_size`), `placeholder::Template::parse`;
- `at_err(at, message)`, `token_err(token, message)` — errors that name the file and line;
- `entry(name, matcher, Handler::Extension(Arc::new(handler)))` — the route.

`Order::Before("rate_limit")` puts the directive where Caddy's order has `rate_limit`, so a site's
directives outside `route` blocks are sorted with it in its place.

```rust
pub trait RouteHandler: Any + Send + Sync {
    fn directive(&self) -> &'static str;
    fn run(&self, ctx: &mut Ctx) -> Option<Response<Body>>;   // None: the chain goes on
    fn decided_by_path(&self) -> bool;
    fn describe(&self) -> String;
}
```

`run` is where the handler stands in the chain, like `rate_limit`: it may change the request
(`ctx.req`), set response headers (`ctx.pre_headers`), or answer. `decided_by_path` is for the
ready answers (src/memo.rs): a site whose routes decide by the request path alone has its files'
answers worked out in advance, and a handler in front of them must say whether that still holds —
and, while answers are prepared (`ctx.req.extensions` holds `memo::Preparing`), mark the requests
it would decide on `memo::Unkept` so no ready answer stands where it decides. `describe` is the
line `validate` prints. `dyn RouteHandler::downcast_ref::<T>()` gives the handler back as its own
type, for a module looking at the routes it installed.

## Hooks

```rust
pub trait Check: Any + Send + Sync {
    /// What the head phase hands the body phase, by value.
    type Pending: Send + 'static;
    fn head(&self, req: &mut http::request::Parts, client: Client<'_>) -> Head<Self::Pending>;
    fn body<'a>(&'a self, pending: Self::Pending, req: &'a mut http::request::Parts, body: Body, client: Client<'a>)
        -> impl Future<Output = Checked> + Send + 'a;
}
pub enum Head<P = ()> { Pass, Refuse(Response<Body>), Body(P) }

pub trait Inspect: Any + Send + Sync {
    fn covers(&self, ctx: &Ctx, parts: &http::response::Parts) -> bool;
    fn inspect<'a>(&'a self, ctx: &'a mut Ctx, parts: &'a mut http::response::Parts, body: Body)
        -> impl Future<Output = Result<Body, Response<Body>>> + Send + 'a;
}

// What the core calls, through `&'static dyn`: implemented for every composed set.
pub trait Checks: Send + Sync + 'static {
    fn check<'a>(&'a self, req: &'a mut http::request::Parts, body: Body, client: Client<'a>) -> Checking<'a>;
    fn find(&self, id: TypeId) -> Option<&dyn Any>;
}
pub enum Checking<'a> { Done(Checked), Body(BoxFuture<'a, Checked>) }
```

A check that needs the body, written with `async fn` (the trait's `impl Future + Send` accepts
it):

```rust
pub struct Endpoint;

impl Check for Endpoint {
    type Pending = ();   // the head decided by the path; nothing to hand on

    fn head(&self, req: &mut http::request::Parts, _: Client<'_>) -> Head {
        if req.method == Method::POST && req.uri.path() == "/.well-known/endpoint" {
            Head::Body(())
        } else {
            Head::Pass
        }
    }

    async fn body<'a>(&'a self, _: (), req: &'a mut http::request::Parts, body: Body, _: Client<'a>) -> Checked {
        let form = Limited::new(body, 4096).collect().await.map_err(|_| bad_request())?.to_bytes();
        Err(answer(req, &form))   // the endpoint's answer is the response
    }
}
```

A `Check` runs before the site's routes and ready answers, after the core's ACME answer and before
its JWT and API firewall checks, with `extensions::Client` (the client's address, the connection's
`ConnInfo`: TLS, SNI, trusted, and over TLS on TCP the client's JA4 fingerprint, `ja4`, `None` when
it could not be read). A refusal marked `extensions::ErrorPage` goes through the site's
`handle_errors` routes, as a handler's own failure does; one without the mark goes out as it is
(the challenge page is the answer, not an error). `head` may change the request — the request
filter takes the headers of its `header` actions off every request and sets the geo header — and
what it must carry over to `body` is its `Pending`, handed back by value (the filter's `Pending`:
the state it ran with, its evaluation so far, the body's kind), so the hand-over allocates nothing.

An `Inspect` sees a `reverse_proxy`'s response before the proxy cache keeps it and before the
client gets it. It is zero-sized and composed as a constant for every proxy; it finds its module's
state through `ctx.hook::<T>()` (`Hooks::get`: the leaf of type `T` among the composed checks and
inspectors — `Option<Arc<Ngfw>>` in the checks answers `&Ngfw`). `inspect` is called only for a
response its `covers` took; it may read the start of the body and must give back a body that yields
the same bytes (`webfast_ngfw::body::read_prefix` chains the frames read with the rest), or wrap the
body (the filter's response phase scans a 200 as it streams, and ends the body with an error on a
leak); an `Err` replaces the response.

The upstream checks (`UpstreamCheck`, at a `reverse_proxy` and a `cache` hit, with a slot held for
the response's life) stay the core's for now: the JWT and API firewall use them, and when those
move out the same synchronous-first protocol will carry them.

## Configuration state and the environment

`Config::modules` is a `TypeMap`: `insert(Arc<T>)` in `Module::load`, `get::<T>() -> Option<Arc<T>>`
in the binary's composition and in `Module::start`. One value per type; the type is the key, as
with `http::Extensions` on a request, so two modules cannot collide and the core defines no field.

A module's environment is its own (WEB_NGFW_CONFIG, WEB_CHALLENGE_PASSED), read in
`configure_from_env` and `load`. Nothing moves into the Caddyfile that Caddy could not read: a
module's directive is one Caddy would accept from a plugin of the same name, and its file is YAML
read through `webfast_core::yaml::from_str` (pure Rust, with limits on what a document may expand
to).

What else the core makes available (all documented in the source):

| Need | Where |
| --- | --- |
| the body type, `empty()`, `full()`, `boxed()` | `webfast_core::body` |
| the request context, `ConnInfo`, `hostport_of`, `strip_port` | `webfast_core::handler` |
| the client's TLS fingerprint (`Ja4`, its parts, JA4_r from a parsed hello) | `webfast_core::ja4` |
| matchers, `PathPattern`, `host_matches`, `clean_path` | `webfast_core::matcher` |
| placeholders (`Template`, `Sole`) | `webfast_core::placeholder` |
| an event log in the checks' JSON format: `EventKind`, `Field`, `EventLog::event` and `event_with` (a module's fields inside `request` too), `Fields` (`str`, `u64`, `value` with its source, `strs`, `numbers`, `object`, `list`), `CheckLog` (an output with its `privacy`), `record_with` (fields as JSON, until step 4 of docs/logging.md), `HiddenParams` | `webfast_core::eventlog` |
| the log policy: classes, sources, actions (`Class`, `Source`, `Policy`; a composite value's part by `query_class`, `path_class`, `uri_class`), `Overrides` for a module's `log.privacy` | `webfast_core::privacy` |
| the request's id (`RequestId`, in the request's extensions) | `webfast_core::reqid` |
| HTTPS fetches with the built-in roots (`get`, `post_form`; cargo feature `fetch`) | `webfast_core::fetch` |
| a worker thread with a current-thread runtime, a memory budget | `webfast_core::background` |
| the client key the connection limits count by (`/64` for IPv6) | `webfast_core::guard::address_key` |
| the look-alike header fields an upstream would read as the real one | `webfast_core::proxy::remove_lookalikes` |
| JSON escaping as the access log does it | `webfast_core::accesslog::json_escape` |
| `Preparing`, `Unkept` | `webfast_core::memo` |

## The composition

```rust
// crates/webfast/src/compose.rs, with the two crates of webfast-modules as dependencies
use webfast_challenge::ChallengeEndpoint;
use webfast_ngfw::{Ngfw, response::NgfwResponses};

pub type Checks = (ChallengeEndpoint, (Option<Arc<Ngfw>>, ()));
pub type Inspectors = (NgfwResponses, ());

pub static MODULES: &[&dyn Module] = &[&webfast_challenge::MODULE, &webfast_ngfw::MODULE];

fn hooks(config: &Config) -> (Checks, Inspectors) {
    ((ChallengeEndpoint, (config.modules.get::<Ngfw>(), ())), (NgfwResponses, ()))
}

pub fn composition() -> Composition<Checks, Inspectors> {
    Composition { modules: MODULES, hooks }
}
```

An empty composition — this repository's, until the modules' crates are added — is `Checks = ()`,
`Inspectors = ()`, `MODULES = &[]` and `hooks` answering `((), ())`.

Each slot is a type alias with a `cfg` pair — the module's type when its feature is on, `()`
when it is off — so the number of arms grows with the modules and not with their combinations.
`hooks` is called once per process when the server starts (a reload keeps the hooks); the core
leaks each set and calls it through `&'static dyn`.

`webfast_core::module::install(composition)` registers it: once per process; a second
installation is ignored, so every test of a binary composes alike. `run::main` does it first
thing; the test harness does it for a test.

## Testing

`webfast_core::harness` (cargo feature `test-harness`, a dev-dependency of a module crate) boots
a server from a Caddyfile text with a composition and speaks raw HTTP/1.1 to it on a TCP
connection:

```rust
let server = harness::start(webfast::compose::composition(), CADDYFILE, |config| {
    config.modules.insert(Arc::new(ngfw));          // as Module::load would from its file
}).await;
let got = server.get("/api/echo?q=1", &[("user-agent", UA)]).await;   // harness::Response
assert_eq!(got.status, 200);
assert_eq!(got.header("x-upstream"), "1");
let bytes = harness::raw(server.addr, b"GET /en/ HTTP/1.1\r\nHost: x\r\n\r\n").await;  // a 444: empty
let line = harness::wait_for_line(&log, Duration::from_secs(3), |l| l.contains("\"decision\"")).await;
server.shutdown().await;
```

`harness::site(&[("en/index.html", "…")])` makes a site directory; `Server::addr_of(port)` is
the bound address of a configured port. The two modules' integration tests
(`crates/webfast-ngfw/tests`, `crates/webfast-challenge/tests` in webfast-modules) are written on
it, with their own upstream stubs where they need one.

A module's unit tests that parse a Caddyfile with its directive call the composition's `install`
first (`crate::compose::install()`), as the challenge's `directive.rs` tests do.

## A module's crate

The two modules were written in the binary's crate, as the proving ground of this API, and moved
to webfast-modules without a change in the core: a module's directory is the crate's `src/`, its
features and dependencies are its own `Cargo.toml`'s, the binary depends on the crate, and
compose.rs names `webfast_ngfw::MODULE`. The request filter's use of the challenge
(`action: challenge`) is a dependency of the one crate on the other, not on the core.
