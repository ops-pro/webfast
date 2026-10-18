//! Where the optional pieces (cargo features) plug into the request path: one trait per hook
//! point, and the hooks of a point composed at compile time from the features that are on
//! (docs/extensions.md).
//!
//! A point's hooks are a type, not a list: `()` where a feature is off (the call compiles to
//! nothing), `Option<T>` for a feature that is built but not configured (one test), and nested
//! pairs `(A, (B, ()))` for the order, which the core fixes here. No trait object, no boxed future:
//! a configured hook is a direct call, as the hand-written one was.
//!
//! The `cfg` knowledge of the request path lives in this file; the hook points call `Hooks`'s
//! fields and know no extension by name.

use crate::body::Body;
use crate::config::Config;
use anyhow::Result;
use http::Response;
use http::uri::Authority;
use std::net::IpAddr;
use std::sync::Arc;

/// What a hook learns of the client.
#[derive(Debug, Clone, Copy)]
pub struct Client {
    pub ip: IpAddr,
}

/// The body to go on with (the same bytes, when a check read it), or the answer that refuses.
pub type Checked = std::result::Result<Body, Response<Body>>;

/// Before the site's routes and ready answers: refuse, or let through (perhaps changed).
pub trait RequestCheck: Send + Sync {
    fn check(&self, req: &mut http::request::Parts, body: Body, client: Client)
    -> impl Future<Output = Checked> + Send;
}

/// At a `reverse_proxy` (and a `cache` hit), on the request as it goes to one of `upstreams`.
pub trait UpstreamCheck: Send + Sync {
    fn check(
        &self,
        req: &mut http::request::Parts,
        body: Body,
        client: Client,
        upstreams: &[Authority],
    ) -> impl Future<Output = Checked> + Send;

    /// Whether this check is bound to any upstream at all (none: the proxies skip the call).
    fn bound(&self) -> bool;

    /// The upstreams it is bound to: each must be one a `reverse_proxy` sends to.
    fn upstreams(&self, out: &mut Vec<(Authority, &'static str)>);
}

impl RequestCheck for () {
    async fn check(&self, _: &mut http::request::Parts, body: Body, _: Client) -> Checked {
        Ok(body)
    }
}

impl UpstreamCheck for () {
    async fn check(&self, _: &mut http::request::Parts, body: Body, _: Client, _: &[Authority]) -> Checked {
        Ok(body)
    }

    fn bound(&self) -> bool {
        false
    }

    fn upstreams(&self, _: &mut Vec<(Authority, &'static str)>) {}
}

impl<A: RequestCheck, B: RequestCheck> RequestCheck for (A, B) {
    async fn check(&self, req: &mut http::request::Parts, body: Body, client: Client) -> Checked {
        let body = self.0.check(req, body, client).await?;
        self.1.check(req, body, client).await
    }
}

impl<A: UpstreamCheck, B: UpstreamCheck> UpstreamCheck for (A, B) {
    async fn check(&self, req: &mut http::request::Parts, body: Body, client: Client, up: &[Authority]) -> Checked {
        let body = self.0.check(req, body, client, up).await?;
        self.1.check(req, body, client, up).await
    }

    fn bound(&self) -> bool {
        self.0.bound() || self.1.bound()
    }

    fn upstreams(&self, out: &mut Vec<(Authority, &'static str)>) {
        self.0.upstreams(out);
        self.1.upstreams(out);
    }
}

impl<T: RequestCheck> RequestCheck for Option<T> {
    async fn check(&self, req: &mut http::request::Parts, body: Body, client: Client) -> Checked {
        match self {
            Some(check) => check.check(req, body, client).await,
            None => Ok(body),
        }
    }
}

impl<T: UpstreamCheck> UpstreamCheck for Option<T> {
    async fn check(&self, req: &mut http::request::Parts, body: Body, client: Client, up: &[Authority]) -> Checked {
        match self {
            Some(check) => check.check(req, body, client, up).await,
            None => Ok(body),
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

impl<T: RequestCheck> RequestCheck for Arc<T> {
    async fn check(&self, req: &mut http::request::Parts, body: Body, client: Client) -> Checked {
        (**self).check(req, body, client).await
    }
}

impl<T: UpstreamCheck> UpstreamCheck for Arc<T> {
    async fn check(&self, req: &mut http::request::Parts, body: Body, client: Client, up: &[Authority]) -> Checked {
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

/// The checks before the routes, in order: the JWT first (the API firewall sees the claim headers
/// it set, and the query parameters it hides from the event log).
pub type RequestChecks = (Jwt, (ApiFirewall, ()));
/// The checks at a proxy, in the same order.
pub type UpstreamChecks = (Jwt, (ApiFirewall, ()));

/// The hooks of a server, composed from the configuration.
#[derive(Clone)]
pub struct Hooks {
    pub request: RequestChecks,
    /// `None` when no check is bound to an upstream: requests carry nothing for the proxies.
    pub upstream: Option<Arc<UpstreamChecks>>,
}

impl Hooks {
    pub fn new(config: &Config) -> Hooks {
        let request = compose(config);
        let upstream = request.bound().then(|| Arc::new(compose(config)));
        Hooks { request, upstream }
    }

    /// The hooks of a configuration with no extension configured (tests).
    pub fn none() -> Hooks {
        Hooks {
            request: Default::default(),
            upstream: None,
        }
    }

    /// `Ok` when every upstream the checks are bound to is one of `known` (the upstreams the
    /// `reverse_proxy`s send to): at startup, and for a reloaded Caddyfile, which keeps the hooks.
    pub fn bound_within(&self, known: &[Authority]) -> Result<()> {
        let mut bound = Vec::new();
        if let Some(upstream) = &self.upstream {
            upstream.upstreams(&mut bound);
        }
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
}

/// The checks of `config` in their slots (cheap: `Arc`s cloned, `()` where a feature is off).
fn compose(config: &Config) -> (Jwt, (ApiFirewall, ())) {
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
/// Refuses request checks bound to an upstream no `reverse_proxy` of `config` sends to: a typo,
/// or routes changed since, would otherwise leave the requests going there unchecked.
pub fn check_bindings(config: &Config) -> Result<()> {
    Hooks::new(config).bound_within(&config.upstreams())
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
        async fn check(&self, _: &mut http::request::Parts, body: Body, _: Client) -> Checked {
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

    fn client() -> Client {
        Client {
            ip: "203.0.113.7".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn hooks_compose_in_order_and_stop_at_a_refusal() {
        let (mut parts, ()) = http::Request::get("/").body(()).unwrap().into_parts();
        let empty: ((), ((), ())) = ((), ((), ()));
        assert!(
            RequestCheck::check(&empty, &mut parts, crate::body::empty(), client())
                .await
                .is_ok()
        );

        let pass_then_refuse = (Some(counting(false)), (counting(true), (counting(false), ())));
        let refused = RequestCheck::check(&pass_then_refuse, &mut parts, crate::body::empty(), client())
            .await
            .expect_err("refused");
        assert_eq!(refused.status(), http::StatusCode::FORBIDDEN);
        assert_eq!(pass_then_refuse.0.as_ref().unwrap().calls.load(Ordering::Relaxed), 1);
        assert_eq!((pass_then_refuse.1).0.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            ((pass_then_refuse.1).1).0.calls.load(Ordering::Relaxed),
            0,
            "not reached"
        );

        let unconfigured: Option<Counting> = None;
        assert!(
            RequestCheck::check(&unconfigured, &mut parts, crate::body::empty(), client())
                .await
                .is_ok()
        );
    }

    #[test]
    fn the_hooks_of_a_configuration_without_extensions_are_empty() {
        assert!(Hooks::none().upstream.is_none());
        assert!(Hooks::none().bound_within(&[]).is_ok());
    }
}
