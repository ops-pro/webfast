//! The module API: what a crate outside the core implements to take part in the server, and what
//! the binary registers (docs/modules.md). The core knows no module by name: it calls the
//! [`Module`]s the binary composed (`Composition`), parses the directives they registered
//! (`Directive`), runs the route handlers their directives installed (`RouteHandler`,
//! `Handler::Extension`), and calls their request checks (`Check`) and proxied-response inspectors
//! (`Inspect`) through one `&'static dyn` object per kind — the composed set, a tuple the binary
//! writes (`(A, (B, ()))`), resolved at compile time there.
//!
//! The checks decide synchronously where they can: `Check::head` sees the request's head and
//! answers `Pass`, `Refuse` or `Body(pending)`, handing the body phase what it found by value;
//! only `Body` costs a boxed future — one for the whole set, made by `Checks::check` over the
//! bodies and the heads after them — and a clean GET never gets there. The same for a proxied
//! response: `Inspect::covers` is a plain call, and the set's one boxed future is made only for a
//! response some inspector covers. So the request path allocates nothing for a module that has
//! nothing to say, as it did when the modules were `cfg`s of the core.

use crate::body::Body;
use crate::caddyfile::Line;
use crate::config::{Config, Cx, Entry, Scope, SiteCx};
use crate::extensions::{Checked, Client};
use crate::handler::{BoxFuture, Ctx, Handler};
use http::Response;
use std::any::{Any, TypeId};
use std::sync::{Arc, OnceLock};

/// A module: what the binary registers (`Composition::modules`). Every method has a default, so a
/// module implements the ones it takes part in; `name` alone is required.
pub trait Module: Sync + Send + 'static {
    /// Its name in the logs and in `webfast validate`.
    fn name(&self) -> &'static str;

    /// The Caddyfile directives the module adds: each with its parser and its place in the
    /// directive order (`Order`), registered before the Caddyfile is read.
    fn directives(&self) -> &'static [Directive] {
        &[]
    }

    /// Its WEB_* environment, read at start before the configuration (errors are fatal, as the
    /// core's own `limits_from_env` are). A variable of a module that is not built should stop
    /// the start too: `Unbuilt`.
    fn configure_from_env(&self) -> Result<(), String> {
        Ok(())
    }

    /// The TLS ticket seed (WEB_TLS_TICKET_SEED), when there is one, before the configuration is
    /// loaded: a module that signs things derives its keys from it, so that every replica given the
    /// seed accepts the others' (the browser challenge's cookies).
    fn seed(&self, seed: Option<&[u8]>) {
        let _ = seed;
    }

    /// After the Caddyfile is loaded and the core's own checks (JWT, API firewall) with it: the
    /// module reads its own files (the environment names them), puts its state into
    /// `config.modules` (a typed map the hooks take it from), and says what it loaded, one line
    /// each, for the startup log and `webfast validate`. An error stops the start.
    fn load(&self, config: &mut Config) -> anyhow::Result<Vec<String>> {
        let _ = config;
        Ok(Vec::new())
    }

    /// The server is about to take the configuration, on the runtime: background work starts here
    /// (feeds, sweeps). Not called by `webfast validate`.
    fn start(&self, config: &Config) -> anyhow::Result<()> {
        let _ = config;
        Ok(())
    }

    /// SIGHUP: the module's own files read again (the hooks are `&'static`, so it swaps its state
    /// in place); what happened, one line each. A file that does not load is a line, not a failed
    /// reload of the Caddyfile.
    fn reload(&self) -> Vec<String> {
        Vec::new()
    }

    /// `webfast validate`: lines to print after the loaded configuration's. The default lists
    /// every route of the module's directives: `challenge example.com: level js, …`.
    fn validate(&self, config: &Config) -> Vec<String> {
        let directives = self.directives();
        let mut out = Vec::new();
        config.each_route(&mut |hosts, route| {
            if let Handler::Extension(handler) = &route.handler
                && directives.iter().any(|d| d.name == handler.directive())
            {
                out.push(format!("{} {hosts}: {}", handler.directive(), handler.describe()));
            }
        });
        out
    }
}

/// A Caddyfile directive a module adds.
pub struct Directive {
    /// Its name (`challenge`): what the Caddyfile line starts with.
    pub name: &'static str,
    /// Reads the line (and its block) into routes.
    pub parse: DirectiveParser,
    /// Where it stands in Caddy's directive order, by which the directives of a site are sorted.
    pub order: Order,
}

/// A directive's parser: the line, the named matchers in scope, the compilation context and the
/// site's; the routes it adds (`config::entry`), usually one.
pub type DirectiveParser = fn(&Line, &Scope, &mut Cx, &mut SiteCx) -> anyhow::Result<Vec<Entry>>;

/// Where a module's directive goes in the directive order, relative to one the core knows
/// (`rate_limit`, `encode`, `reverse_proxy`, …; src/config.rs `DIRECTIVE_ORDER`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    Before(&'static str),
    After(&'static str),
}

/// A route handler a module's directive installs (`Handler::Extension`): run in the chain where it
/// stands, like `rate_limit`, before the handler that answers.
pub trait RouteHandler: Any + Send + Sync {
    /// The directive that installed it.
    fn directive(&self) -> &'static str;

    /// `None`: the chain goes on; `Some`: this is the answer. Synchronous: a handler that must
    /// wait answers with a response, or arranges the wait elsewhere.
    fn run(&self, ctx: &mut Ctx) -> Option<Response<Body>>;

    /// Whether the ready answers of the site stay right with this handler in front of them
    /// (src/memo.rs): it decides by the request path alone, and while answers are prepared
    /// (`memo::Preparing`) it marks the paths it would decide on `memo::Unkept`.
    fn decided_by_path(&self) -> bool;

    /// Its settings in a few words, for `webfast validate`.
    fn describe(&self) -> String;
}

impl dyn RouteHandler {
    /// The handler as its own type, for a module looking at the routes it installed.
    pub fn downcast_ref<T: RouteHandler>(&self) -> Option<&T> {
        (self as &dyn Any).downcast_ref()
    }
}

/// A request check of a module: before the site's routes and ready answers, after the ACME answer
/// and before the core's JWT and API firewall checks. The head first, synchronously; the body only
/// when the head could not decide, with what the head handed it (`Head::Body`).
pub trait Check: Any + Send + Sync {
    /// What the head phase hands the body phase, by value (`()` when it needs nothing).
    type Pending: Send + 'static;

    /// The request's head: let it through (perhaps changed), refuse it, or ask for the body.
    fn head(&self, req: &mut http::request::Parts, client: Client<'_>) -> Head<Self::Pending>;

    /// After `Head::Body(pending)`: the check with the body — what `head` could not decide, not
    /// the head's work again. The body given back is the one the routes read (the same bytes,
    /// when the check read some). Not boxed here: the set boxes once for all its checks.
    fn body<'a>(
        &'a self,
        pending: Self::Pending,
        req: &'a mut http::request::Parts,
        body: Body,
        client: Client<'a>,
    ) -> impl Future<Output = Checked> + Send + 'a;
}

/// What `Check::head` decided.
pub enum Head<P = ()> {
    /// The routes next (the core's own checks first).
    Pass,
    /// This is the answer; marked `extensions::ErrorPage` to go through the site's
    /// `handle_errors`.
    Refuse(Response<Body>),
    /// `Check::body` decides, given this.
    Body(P),
}

/// An inspector of proxied responses: sees a `reverse_proxy`'s response before the proxy cache
/// keeps it and before the client gets it, and may replace it (the request filter's response
/// phase). `covers` first, a plain call; `inspect` only for a response it covers.
pub trait Inspect: Any + Send + Sync {
    /// Whether `inspect` has anything to do with this response (its status and headers, the
    /// request in `ctx`).
    fn covers(&self, ctx: &Ctx, parts: &http::response::Parts) -> bool;

    /// A response `covers` took, as the upstream gave it: may read the start of the body (giving
    /// back a body that yields the same bytes), wrap the body, and replace the response; `Err` is
    /// sent in its place, through the site's `handle_errors` when marked `extensions::ErrorPage`.
    /// Not boxed here: the set boxes once for all its inspectors.
    fn inspect<'a>(
        &'a self,
        ctx: &'a mut Ctx,
        parts: &'a mut http::response::Parts,
        body: Body,
    ) -> impl Future<Output = Result<Body, Response<Body>>> + Send + 'a;
}

// The composed sets: `()` for none, a leaf, `Option<T>` for a module that is built but not
// configured, `Arc<T>` for a shared one, and nested pairs `(A, (B, ()))` for the order. Two traits
// each: the generic one the tuple recursion is written in (`CheckSet`, `InspectSet`: what a head
// hands on is a type, the futures are not boxed), and the object-safe one the core calls through
// `&'static dyn` (`Checks`, `Inspectors`), implemented for every generic set: one vtable call per
// request for the whole set, and one boxed future at most — for a request whose body a check asked
// for, for a response an inspector covers — however many modules there are.

/// A composed set of request checks, generically: what the object-safe `Checks` is made of.
/// Implemented for every `Check`, for `()`, `Option<T>`, `Arc<T>` and pairs `(A, B)`; nothing else
/// implements it.
pub trait CheckSet: Send + Sync + 'static {
    /// What the heads hand the bodies: for a pair, which of the two asked, and its leaf's.
    type Pending: Send + 'static;

    /// The heads in order, until one refuses or asks for the body.
    fn head(&self, req: &mut http::request::Parts, client: Client<'_>) -> Head<Self::Pending>;

    /// From the leaf that asked for the body on: its `body`, then the rest's heads and bodies —
    /// one future for all of them.
    fn body<'a>(
        &'a self,
        pending: Self::Pending,
        req: &'a mut http::request::Parts,
        body: Body,
        client: Client<'a>,
    ) -> impl Future<Output = Checked> + Send + 'a;

    /// The leaf of type `id`, for `Hooks::get`.
    fn find(&self, id: TypeId) -> Option<&dyn Any>;
}

/// Which side of a pair asked for the body, and what its head handed on.
pub enum Stage<A, B> {
    /// The first: its body, then the second's head (and perhaps body).
    First(A),
    /// The second (the first passed).
    Second(B),
}

impl<T: Check> CheckSet for T {
    type Pending = T::Pending;

    fn head(&self, req: &mut http::request::Parts, client: Client<'_>) -> Head<T::Pending> {
        Check::head(self, req, client)
    }

    fn body<'a>(
        &'a self,
        pending: T::Pending,
        req: &'a mut http::request::Parts,
        body: Body,
        client: Client<'a>,
    ) -> impl Future<Output = Checked> + Send + 'a {
        Check::body(self, pending, req, body, client)
    }

    fn find(&self, id: TypeId) -> Option<&dyn Any> {
        (self.type_id() == id).then_some(self)
    }
}

impl CheckSet for () {
    type Pending = std::convert::Infallible;

    fn head(&self, _: &mut http::request::Parts, _: Client<'_>) -> Head<Self::Pending> {
        Head::Pass
    }

    fn body<'a>(
        &'a self,
        pending: Self::Pending,
        _: &'a mut http::request::Parts,
        body: Body,
        _: Client<'a>,
    ) -> impl Future<Output = Checked> + Send + 'a {
        // Not reached: no head of `()` asks for the body (`Infallible` has no value).
        let _: std::convert::Infallible = pending;
        std::future::ready(Ok(body))
    }

    fn find(&self, _: TypeId) -> Option<&dyn Any> {
        None
    }
}

impl<T: CheckSet> CheckSet for Option<T> {
    type Pending = T::Pending;

    fn head(&self, req: &mut http::request::Parts, client: Client<'_>) -> Head<T::Pending> {
        match self {
            Some(check) => check.head(req, client),
            None => Head::Pass,
        }
    }

    async fn body<'a>(
        &'a self,
        pending: T::Pending,
        req: &'a mut http::request::Parts,
        body: Body,
        client: Client<'a>,
    ) -> Checked {
        match self {
            Some(check) => check.body(pending, req, body, client).await,
            // Not reached: a `None` asks for no body.
            None => Ok(body),
        }
    }

    fn find(&self, id: TypeId) -> Option<&dyn Any> {
        self.as_ref().and_then(|check| check.find(id))
    }
}

impl<T: CheckSet> CheckSet for Arc<T> {
    type Pending = T::Pending;

    fn head(&self, req: &mut http::request::Parts, client: Client<'_>) -> Head<T::Pending> {
        (**self).head(req, client)
    }

    fn body<'a>(
        &'a self,
        pending: T::Pending,
        req: &'a mut http::request::Parts,
        body: Body,
        client: Client<'a>,
    ) -> impl Future<Output = Checked> + Send + 'a {
        (**self).body(pending, req, body, client)
    }

    fn find(&self, id: TypeId) -> Option<&dyn Any> {
        (**self).find(id)
    }
}

impl<A: CheckSet, B: CheckSet> CheckSet for (A, B) {
    type Pending = Stage<A::Pending, B::Pending>;

    fn head(&self, req: &mut http::request::Parts, client: Client<'_>) -> Head<Self::Pending> {
        match self.0.head(req, client) {
            Head::Pass => match self.1.head(req, client) {
                Head::Pass => Head::Pass,
                Head::Refuse(response) => Head::Refuse(response),
                Head::Body(pending) => Head::Body(Stage::Second(pending)),
            },
            Head::Refuse(response) => Head::Refuse(response),
            // The second's head runs after the first's body: what the first changes, it sees.
            Head::Body(pending) => Head::Body(Stage::First(pending)),
        }
    }

    async fn body<'a>(
        &'a self,
        pending: Self::Pending,
        req: &'a mut http::request::Parts,
        body: Body,
        client: Client<'a>,
    ) -> Checked {
        match pending {
            Stage::First(pending) => {
                let body = self.0.body(pending, req, body, client).await?;
                match self.1.head(req, client) {
                    Head::Pass => Ok(body),
                    Head::Refuse(response) => Err(response),
                    Head::Body(pending) => self.1.body(pending, req, body, client).await,
                }
            }
            Stage::Second(pending) => self.1.body(pending, req, body, client).await,
        }
    }

    fn find(&self, id: TypeId) -> Option<&dyn Any> {
        self.0.find(id).or_else(|| self.1.find(id))
    }
}

/// A composed set of request checks, as the core calls it (`extensions::Modules`): implemented for
/// every `CheckSet`.
pub trait Checks: Send + Sync + 'static {
    /// The heads in order, synchronously; `Checking::Body` when a check asked for the body: the
    /// one boxed future, for its body and the rest of the set.
    fn check<'a>(&'a self, req: &'a mut http::request::Parts, body: Body, client: Client<'a>) -> Checking<'a>;

    /// The leaf of type `id`, for `Hooks::get`.
    fn find(&self, id: TypeId) -> Option<&dyn Any>;
}

/// What a set of checks decided from the heads alone, or the rest of its work.
pub enum Checking<'a> {
    /// Decided: the body to go on with (untouched), or the refusal.
    Done(Checked),
    /// A check wants the body: this future decides.
    Body(BoxFuture<'a, Checked>),
}

impl<T: CheckSet> Checks for T {
    fn check<'a>(&'a self, req: &'a mut http::request::Parts, body: Body, client: Client<'a>) -> Checking<'a> {
        match CheckSet::head(self, req, client) {
            Head::Pass => Checking::Done(Ok(body)),
            Head::Refuse(response) => Checking::Done(Err(response)),
            Head::Body(pending) => Checking::Body(Box::pin(CheckSet::body(self, pending, req, body, client))),
        }
    }

    fn find(&self, id: TypeId) -> Option<&dyn Any> {
        CheckSet::find(self, id)
    }
}

/// A composed set of inspectors, generically: what the object-safe `Inspectors` is made of.
/// Implemented for every `Inspect`, for `()`, `Option<T>`, `Arc<T>` and pairs `(A, B)`.
pub trait InspectSet: Send + Sync + 'static {
    /// Whether any inspector covers the response.
    fn covers(&self, ctx: &Ctx, parts: &http::response::Parts) -> bool;

    /// For a response the set covers: every inspector that covers it, in order, each on the body
    /// the one before gave back — one future for all of them.
    fn inspect<'a>(
        &'a self,
        ctx: &'a mut Ctx,
        parts: &'a mut http::response::Parts,
        body: Body,
    ) -> impl Future<Output = Result<Body, Response<Body>>> + Send + 'a;

    /// The leaf of type `id`, for `Hooks::get`.
    fn find(&self, id: TypeId) -> Option<&dyn Any>;
}

impl<T: Inspect> InspectSet for T {
    fn covers(&self, ctx: &Ctx, parts: &http::response::Parts) -> bool {
        Inspect::covers(self, ctx, parts)
    }

    fn inspect<'a>(
        &'a self,
        ctx: &'a mut Ctx,
        parts: &'a mut http::response::Parts,
        body: Body,
    ) -> impl Future<Output = Result<Body, Response<Body>>> + Send + 'a {
        Inspect::inspect(self, ctx, parts, body)
    }

    fn find(&self, id: TypeId) -> Option<&dyn Any> {
        (self.type_id() == id).then_some(self)
    }
}

impl InspectSet for () {
    fn covers(&self, _: &Ctx, _: &http::response::Parts) -> bool {
        false
    }

    fn inspect<'a>(
        &'a self,
        _: &'a mut Ctx,
        _: &'a mut http::response::Parts,
        body: Body,
    ) -> impl Future<Output = Result<Body, Response<Body>>> + Send + 'a {
        std::future::ready(Ok(body))
    }

    fn find(&self, _: TypeId) -> Option<&dyn Any> {
        None
    }
}

impl<T: InspectSet> InspectSet for Option<T> {
    fn covers(&self, ctx: &Ctx, parts: &http::response::Parts) -> bool {
        self.as_ref().is_some_and(|inspector| inspector.covers(ctx, parts))
    }

    async fn inspect<'a>(
        &'a self,
        ctx: &'a mut Ctx,
        parts: &'a mut http::response::Parts,
        body: Body,
    ) -> Result<Body, Response<Body>> {
        match self {
            Some(inspector) => inspector.inspect(ctx, parts, body).await,
            None => Ok(body),
        }
    }

    fn find(&self, id: TypeId) -> Option<&dyn Any> {
        self.as_ref().and_then(|inspector| inspector.find(id))
    }
}

impl<T: InspectSet> InspectSet for Arc<T> {
    fn covers(&self, ctx: &Ctx, parts: &http::response::Parts) -> bool {
        (**self).covers(ctx, parts)
    }

    fn inspect<'a>(
        &'a self,
        ctx: &'a mut Ctx,
        parts: &'a mut http::response::Parts,
        body: Body,
    ) -> impl Future<Output = Result<Body, Response<Body>>> + Send + 'a {
        (**self).inspect(ctx, parts, body)
    }

    fn find(&self, id: TypeId) -> Option<&dyn Any> {
        (**self).find(id)
    }
}

impl<A: InspectSet, B: InspectSet> InspectSet for (A, B) {
    fn covers(&self, ctx: &Ctx, parts: &http::response::Parts) -> bool {
        self.0.covers(ctx, parts) || self.1.covers(ctx, parts)
    }

    async fn inspect<'a>(
        &'a self,
        ctx: &'a mut Ctx,
        parts: &'a mut http::response::Parts,
        body: Body,
    ) -> Result<Body, Response<Body>> {
        // Each side only for what it covers (as the first left the response).
        let body = if self.0.covers(ctx, parts) {
            self.0.inspect(ctx, parts, body).await?
        } else {
            body
        };
        if self.1.covers(ctx, parts) {
            self.1.inspect(ctx, parts, body).await
        } else {
            Ok(body)
        }
    }

    fn find(&self, id: TypeId) -> Option<&dyn Any> {
        self.0.find(id).or_else(|| self.1.find(id))
    }
}

/// A composed set of inspectors, as the core calls it (`extensions::ModuleInspectors`):
/// implemented for every `InspectSet`.
pub trait Inspectors: Send + Sync + 'static {
    /// Whether any inspector covers the response: if not, `inspect` is not called (nothing boxed).
    fn covers(&self, ctx: &Ctx, parts: &http::response::Parts) -> bool;

    /// For a response the set covers: the inspectors that cover it in order, in one boxed future.
    fn inspect<'a>(
        &'a self,
        ctx: &'a mut Ctx,
        parts: &'a mut http::response::Parts,
        body: Body,
    ) -> BoxFuture<'a, Result<Body, Response<Body>>>;

    /// The leaf of type `id`, for `Hooks::get`.
    fn find(&self, id: TypeId) -> Option<&dyn Any>;
}

impl<T: InspectSet> Inspectors for T {
    fn covers(&self, ctx: &Ctx, parts: &http::response::Parts) -> bool {
        InspectSet::covers(self, ctx, parts)
    }

    fn inspect<'a>(
        &'a self,
        ctx: &'a mut Ctx,
        parts: &'a mut http::response::Parts,
        body: Body,
    ) -> BoxFuture<'a, Result<Body, Response<Body>>> {
        Box::pin(InspectSet::inspect(self, ctx, parts, body))
    }

    fn find(&self, id: TypeId) -> Option<&dyn Any> {
        InspectSet::find(self, id)
    }
}

/// What the binary composes: the modules, and how their hooks are made from the loaded
/// configuration — the checks in order and the inspectors in order, as tuples
/// (`(ChallengeEndpoint, (Option<Arc<Ngfw>>, ()))`), so that the composition is a type.
pub struct Composition<C: Checks = (), I: Inspectors = ()> {
    pub modules: &'static [&'static dyn Module],
    /// Called once per process, when the server starts (a reload keeps the hooks).
    pub hooks: fn(&Config) -> (C, I),
}

/// The modules' hooks as the core holds them: one object per kind, `&'static` (leaked once).
#[derive(Clone, Copy)]
pub struct ModuleHooks {
    pub checks: &'static dyn Checks,
    pub inspectors: &'static dyn Inspectors,
}

/// What `install` keeps of a `Composition`, whatever its types.
trait Composer: Sync + Send {
    fn hooks(&self, config: &Config) -> ModuleHooks;
}

impl<C: Checks, I: Inspectors> Composer for Composition<C, I> {
    fn hooks(&self, config: &Config) -> ModuleHooks {
        let (checks, inspectors) = (self.hooks)(config);
        ModuleHooks {
            checks: Box::leak(Box::new(checks)),
            inspectors: Box::leak(Box::new(inspectors)),
        }
    }
}

/// The installed composition: the modules, their directives, the directive order with them in
/// it. One per process, set by `install` before the Caddyfile is read.
pub struct Registry {
    modules: &'static [&'static dyn Module],
    directives: Vec<&'static Directive>,
    order: Vec<&'static str>,
    composer: Option<&'static dyn Composer>,
}

static REGISTRY: OnceLock<Registry> = OnceLock::new();

/// Registers the composition: the modules' directives become known to the Caddyfile parser, and
/// `server::start` takes their hooks. Once per process (`run` and the test harness do it); a
/// second installation is ignored, so tests in one binary compose once. An error names a
/// directive the core has (or another module registered) or an `Order` relative to one no one has.
pub fn install<C: Checks, I: Inspectors>(composition: Composition<C, I>) -> Result<(), String> {
    let modules = composition.modules;
    let composer: &'static dyn Composer = Box::leak(Box::new(composition));
    let mut registry = Registry {
        modules,
        directives: Vec::new(),
        order: crate::config::DIRECTIVE_ORDER.to_vec(),
        composer: Some(composer),
    };
    for module in modules {
        for directive in module.directives() {
            if registry.order.contains(&directive.name) {
                return Err(format!(
                    "module {}: directive {:?} exists already",
                    module.name(),
                    directive.name
                ));
            }
            let (anchor, offset) = match directive.order {
                Order::Before(name) => (name, 0),
                Order::After(name) => (name, 1),
            };
            let Some(at) = registry.order.iter().position(|d| *d == anchor) else {
                return Err(format!(
                    "module {}: directive {:?} is ordered relative to {anchor:?}, which no one has",
                    module.name(),
                    directive.name
                ));
            };
            registry.order.insert(at + offset, directive.name);
            registry.directives.push(directive);
        }
    }
    let _ = REGISTRY.set(registry);
    Ok(())
}

static EMPTY: Registry = Registry {
    modules: &[],
    directives: Vec::new(),
    order: Vec::new(),
    composer: None,
};

/// The installed composition; without one (the core alone, its own tests): no modules.
pub fn registry() -> &'static Registry {
    REGISTRY.get().unwrap_or(&EMPTY)
}

impl Registry {
    pub fn modules(&self) -> &'static [&'static dyn Module] {
        self.modules
    }

    /// A module's directive by name.
    pub fn directive(&self, name: &str) -> Option<&'static Directive> {
        self.directives.iter().copied().find(|d| d.name == name)
    }

    /// Caddy's directive order with the modules' directives in it.
    pub fn directive_order(&self) -> &[&'static str] {
        if self.order.is_empty() {
            crate::config::DIRECTIVE_ORDER
        } else {
            &self.order
        }
    }

    /// The modules' hooks for this configuration (`server::start`).
    pub(crate) fn hooks(&self, config: &Config) -> ModuleHooks {
        match self.composer {
            Some(composer) => composer.hooks(config),
            None => ModuleHooks {
                checks: &(),
                inspectors: &(),
            },
        }
    }
}

/// A placeholder for a module that is not built (its cargo feature off): a variable of its
/// environment stops the start, as a misspelt one would, instead of being ignored.
pub struct Unbuilt {
    /// What it is ("the request filter").
    pub what: &'static str,
    /// The cargo feature that builds it.
    pub feature: &'static str,
    /// Its WEB_* variables.
    pub variables: &'static [&'static str],
}

impl Module for Unbuilt {
    fn name(&self) -> &'static str {
        self.feature
    }

    fn configure_from_env(&self) -> Result<(), String> {
        unbuilt(self.what, self.feature, self.variables)
    }
}

/// An error naming the first of `variables` that is set: "this webfast was built without `what`".
pub fn unbuilt(what: &str, feature: &str, variables: &[&str]) -> Result<(), String> {
    match variables.iter().find(|name| std::env::var_os(name).is_some()) {
        Some(name) => Err(format!(
            "{name}: this webfast was built without {what} (cargo feature {feature})"
        )),
        None => Ok(()),
    }
}

/// The modules' state the configuration carries (`Config::modules`): one value per type, put
/// there by `Module::load`, taken by the binary's `Composition::hooks`.
#[derive(Default)]
pub struct TypeMap(Vec<(TypeId, Arc<dyn Any + Send + Sync>)>);

impl TypeMap {
    /// Puts `value` in, replacing one of the same type.
    pub fn insert<T: Any + Send + Sync>(&mut self, value: Arc<T>) {
        let id = TypeId::of::<T>();
        self.0.retain(|(k, _)| *k != id);
        self.0.push((id, value));
    }

    pub fn get<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        let id = TypeId::of::<T>();
        self.0
            .iter()
            .find(|(k, _)| *k == id)
            .and_then(|(_, v)| Arc::clone(v).downcast().ok())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::At;
    use crate::handler::ConnInfo;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A check that counts its heads and bodies, passes, refuses, or asks for the body — handing
    /// its body phase a token it checks.
    struct Leaf {
        heads: AtomicUsize,
        bodies: AtomicUsize,
        answer: &'static str,
    }

    fn leaf(answer: &'static str) -> Leaf {
        Leaf {
            heads: AtomicUsize::new(0),
            bodies: AtomicUsize::new(0),
            answer,
        }
    }

    impl Check for Leaf {
        type Pending = (usize, &'static str);

        fn head(&self, _: &mut http::request::Parts, _: Client<'_>) -> Head<Self::Pending> {
            let n = self.heads.fetch_add(1, Ordering::Relaxed);
            match self.answer {
                "pass" => Head::Pass,
                "body" => Head::Body((n, self.answer)),
                _ => {
                    let mut response = Response::new(crate::body::empty());
                    *response.status_mut() = http::StatusCode::FORBIDDEN;
                    Head::Refuse(response)
                }
            }
        }

        async fn body<'a>(
            &'a self,
            pending: Self::Pending,
            _: &'a mut http::request::Parts,
            body: Body,
            _: Client<'a>,
        ) -> Checked {
            assert_eq!(pending, (0, "body"), "what the head handed on");
            self.bodies.fetch_add(1, Ordering::Relaxed);
            Ok(body)
        }
    }

    /// The whole set as the core runs it (`extensions::Modules`), and whether it boxed.
    #[allow(clippy::result_large_err)]
    async fn run(set: &dyn Checks) -> (Checked, bool) {
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
        match set.check(&mut parts, crate::body::empty(), client) {
            Checking::Done(checked) => (checked, false),
            Checking::Body(checking) => (checking.await, true),
        }
    }

    #[tokio::test]
    async fn the_heads_decide_and_only_the_leaf_that_asked_reads_the_body() {
        let set = (leaf("pass"), (Some(leaf("body")), (Arc::new(leaf("pass")), ())));
        let (checked, boxed) = run(&set).await;
        assert!(checked.is_ok());
        assert!(boxed, "the body: one future");
        let (a, b, c) = (&set.0, set.1.0.as_ref().unwrap(), &set.1.1.0);
        assert_eq!(
            (a.heads.load(Ordering::Relaxed), a.bodies.load(Ordering::Relaxed)),
            (1, 0)
        );
        assert_eq!(
            (b.heads.load(Ordering::Relaxed), b.bodies.load(Ordering::Relaxed)),
            (1, 1)
        );
        assert_eq!(
            (c.heads.load(Ordering::Relaxed), c.bodies.load(Ordering::Relaxed)),
            (1, 0),
            "the rest's head runs after the body"
        );

        let refusing = (leaf("pass"), (leaf("refuse"), (leaf("pass"), ())));
        let (refused, boxed) = run(&refusing).await;
        assert_eq!(refused.expect_err("refused").status(), http::StatusCode::FORBIDDEN);
        assert!(!boxed, "decided by the heads: nothing boxed");
        assert_eq!(refusing.1.1.0.heads.load(Ordering::Relaxed), 0, "not reached");

        let after_body = (leaf("body"), (leaf("refuse"), ()));
        assert!(run(&after_body).await.0.is_err(), "a refusal after a body read");
        assert_eq!(after_body.0.bodies.load(Ordering::Relaxed), 1);

        let two_bodies = (leaf("body"), (leaf("pass"), (leaf("body"), ())));
        assert!(run(&two_bodies).await.0.is_ok());
        assert_eq!(two_bodies.0.bodies.load(Ordering::Relaxed), 1);
        assert_eq!(
            two_bodies.1.1.0.bodies.load(Ordering::Relaxed),
            1,
            "the second body in the same future"
        );

        let none: Option<Leaf> = None;
        assert!(!run(&(none, ())).await.1);
        assert!(run(&()).await.0.is_ok());
        assert!(!run(&(leaf("pass"), ())).await.1, "a pass: nothing boxed");
    }

    #[test]
    fn a_leaf_is_found_by_its_type() {
        let set = (leaf("pass"), (Some(Arc::new(leaf("body"))), ()));
        let found = Checks::find(&set, TypeId::of::<Leaf>()).and_then(|a| a.downcast_ref::<Leaf>());
        assert_eq!(found.map(|l| l.answer), Some("pass"));
        assert!(Checks::find(&set, TypeId::of::<String>()).is_none());
        let empty: (Option<Leaf>, ()) = (None, ());
        assert!(Checks::find(&empty, TypeId::of::<Leaf>()).is_none());
    }

    /// An inspector that covers a status, and counts what it inspected.
    struct Covering {
        status: u16,
        inspected: AtomicUsize,
    }

    impl Inspect for Covering {
        fn covers(&self, _: &Ctx, parts: &http::response::Parts) -> bool {
            parts.status.as_u16() == self.status
        }

        async fn inspect<'a>(
            &'a self,
            _: &'a mut Ctx,
            _: &'a mut http::response::Parts,
            body: Body,
        ) -> Result<Body, Response<Body>> {
            self.inspected.fetch_add(1, Ordering::Relaxed);
            Ok(body)
        }
    }

    #[tokio::test]
    async fn only_the_inspectors_that_cover_a_response_inspect_it() {
        let covering = |status| Covering {
            status,
            inspected: AtomicUsize::new(0),
        };
        let set = (covering(200), (Some(covering(500)), (Arc::new(covering(200)), ())));
        let conn = Arc::new(ConnInfo {
            remote: "203.0.113.7:4000".parse().unwrap(),
            tls: false,
            trusted: false,
            sni: None,
        });
        let (req, body) = http::Request::get("/").body(crate::body::empty()).unwrap().into_parts();
        let mut ctx = Ctx::new(conn.clone(), req, body, conn.remote.ip());
        let (mut parts, ()) = Response::new(()).into_parts();
        let inspectors: &dyn Inspectors = &set;
        assert!(inspectors.covers(&ctx, &parts));
        assert!(
            inspectors
                .inspect(&mut ctx, &mut parts, crate::body::empty())
                .await
                .is_ok()
        );
        let counts = (
            set.0.inspected.load(Ordering::Relaxed),
            set.1.0.as_ref().unwrap().inspected.load(Ordering::Relaxed),
            set.1.1.0.inspected.load(Ordering::Relaxed),
        );
        assert_eq!(counts, (1, 0, 1));
        parts.status = http::StatusCode::NOT_FOUND;
        assert!(
            !inspectors.covers(&ctx, &parts),
            "none covers it: the core does not call inspect"
        );
        assert!(!Inspectors::covers(&(), &ctx, &parts));
    }

    #[test]
    fn the_type_map_holds_one_value_per_type() {
        let mut map = TypeMap::default();
        assert!(map.is_empty());
        map.insert(Arc::new(1u32));
        map.insert(Arc::new(String::from("a")));
        map.insert(Arc::new(2u32));
        assert_eq!(map.get::<u32>().as_deref(), Some(&2));
        assert_eq!(map.get::<String>().as_deref().map(String::as_str), Some("a"));
        assert!(map.get::<u8>().is_none());
    }
}
