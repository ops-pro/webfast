//! The handler chain: routes (an optional matcher set and one handler) run in order, each handler
//! either answers or passes the request on, as in Caddy.
//!
//! The chain is walked in one loop, in one future: handlers that only change the request or its
//! context (`root`, `header` without defer, `request_header`, `rewrite`, `handle_path`'s prefix) and
//! entering `route` / `handle` blocks are applied in place; handlers that change the response of
//! everything after them (deferred `header`, `encode`) are recorded as hooks and applied, innermost
//! first, to the response once a handler answers — the order wrapping would give.
//!
//! - `header` without `defer` (and with no deletions) sets response headers now; a later handler's
//!   own value for the same field wins. Deferred operations apply to the final response.
//! - `handle` blocks of one level are mutually exclusive: after one ran, the others are skipped.
//! - The end of the chain answers 200 with an empty body.
//! - A handler that fails (Caddy: returns an error) answers with the bare status, marked `Failed`;
//!   the site's `handle_errors` routes then get their turn (`handle_error`).

use crate::body::{Body, empty, full};
use crate::encode::{AcceptEncoding, Encode, Encoding};
use crate::files::FileStore;
use crate::matcher::{MatcherSet, clean_path, needs_clean};
use crate::placeholder::Template;
use crate::proxy::ReverseProxy;
use crate::static_files::FileServer;
use bytes::Bytes;
use http::header::{CONTENT_TYPE, LOCATION};
use http::uri::PathAndQuery;
use http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode, Uri};
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use std::borrow::Cow;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Marks a request whose credentials were checked here (src/jwt): a cache keeps the response to
/// it only when the response says it may be shared, as for a request with Authorization (the
/// token may have been taken off before the upstream).
#[derive(Debug, Clone, Copy)]
pub struct Credentialed;

/// What the connection tells about a request.
#[derive(Debug)]
pub struct ConnInfo {
    pub remote: SocketAddr,
    pub tls: bool,
    /// Requests from this peer may set the client IP and X-Forwarded-* (trusted_proxies).
    pub trusted: bool,
    /// TLS: the name the handshake asked for (SNI), lowercase; `None`: none, or plain HTTP.
    pub sni: Option<Box<str>>,
    /// TLS over TCP: the client's JA4 fingerprint, read from its ClientHello (src/ja4.rs);
    /// `None`: plain HTTP, HTTP/3, or a hello that could not be read — never a signal by itself.
    pub ja4: Option<crate::ja4::Ja4>,
}

impl ConnInfo {
    /// The same connection once its TLS handshake named `sni`.
    pub fn with_sni(&self, sni: Option<&str>) -> ConnInfo {
        ConnInfo {
            remote: self.remote,
            tls: self.tls,
            trusted: self.trusted,
            sni: sni.map(|name| name.to_ascii_lowercase().into_boxed_str()),
            ja4: self.ja4,
        }
    }
}

/// Groups of a `path_regexp` match: byte ranges into the matched path.
#[derive(Debug, Clone)]
pub struct RegexCaptures {
    /// The path matched; `None`: the request's cleaned path as it is now (no copy), made a copy
    /// of its own before a rewrite changes the path (`Ctx::set_path_and_query`).
    pub text: Option<String>,
    /// One slot per group of the regexp, sized at config load (`captures_len`).
    pub groups: Box<[Option<(usize, usize)>]>,
    pub names: Arc<[(String, usize)]>,
}

#[derive(Debug, Clone)]
pub struct FileMatch {
    pub relative: String,
    pub root: Arc<FileStore>,
    pub kind: &'static str,
}

impl FileMatch {
    pub fn absolute(&self) -> String {
        format!("{}{}", self.root.root.display(), self.relative)
    }
}

/// A form of the path derived once per request (and again after a rewrite).
#[derive(Debug)]
enum Derived {
    Unset,
    SameAsPath,
    Own(String),
}

/// A handler's failure, as Caddy's handlers return errors: `file_server`'s 404 and 405, the proxy's
/// 502, 504 and 408, the `error` directive. The failed handler answers with the bare status, marked
/// with this (`Failed`), and a site's `handle_errors` routes may answer instead (`handle_error`).
#[derive(Debug)]
pub struct HandlerError {
    pub status: StatusCode,
    /// `{err.message}`: what `error` was given; otherwise the status text (Caddy has the error's own
    /// text where there is one, such as a proxy's network error). Borrowed for the status text:
    /// a 404 costs no string.
    pub message: Cow<'static, str>,
    /// The site root the request had when it failed: the error routes start with it (in Caddy
    /// `root` is a request variable, which they see).
    pub root: Option<Arc<FileStore>>,
    /// The `rate_limit` zone that refused the request (`{http.rate_limit.exceeded.name}`).
    pub zone: Option<Arc<str>>,
}

/// Where `respond 103` sends Early Hints for a request: the protocol that can send an interim
/// response puts it in the request's extensions (src/h3.rs; hyper sends none over HTTP/1.1 and
/// HTTP/2, so there the hints only reach the client with the final response).
#[derive(Debug, Clone)]
pub struct EarlyHints(pub tokio::sync::mpsc::Sender<HeaderMap>);

/// The mark on the response of a handler that failed.
#[derive(Debug, Clone)]
pub struct Failed(pub Arc<HandlerError>);

/// One request on its way through the chain.
pub struct Ctx {
    pub conn: Arc<ConnInfo>,
    /// The current request head; `rewrite` changes its URI.
    pub req: http::request::Parts,
    pub body: Option<Body>,
    pub orig_uri: Uri,
    /// The decoded path when it differs from the URI's (percent-escapes, a rewrite); otherwise the
    /// URI's own path is used, without a copy.
    decoded: Option<String>,
    /// Lowercased and cleaned: what `path` matchers compare against.
    match_path: Derived,
    /// Cleaned, case kept: what `path_regexp` matches.
    clean_path: Derived,
    /// Accept-Encoding, parsed on first use (`encode` and precompressed files share it).
    accept: Option<AcceptEncoding>,
    pub client_ip: IpAddr,
    pub root: Option<Arc<FileStore>>,
    regexps: Vec<(Arc<str>, RegexCaptures)>,
    pub file_match: Option<FileMatch>,
    /// Response headers set by `header` before the handler that answers.
    pub pre_headers: HeaderMap,
    /// What deferred `header` and `encode` will do to the response, outermost first.
    hooks: Hooks,
    /// The site's `encode` the request passed, if any: what a kept proxied answer is compressed
    /// with (src/proxy.rs, src/cache.rs). An `Arc` clone: no allocation.
    pub encode: Option<Arc<Encode>>,
    /// In `handle_errors` routes: the failure they answer for.
    pub error: Option<Arc<HandlerError>>,
    /// The extensions' checks bound to upstreams (src/extensions.rs), for the proxy to run before it
    /// sends the request on; `None`: there are none, or the server asks itself.
    pub(crate) upstream_hooks: Option<&'static crate::extensions::UpstreamChecks>,
    /// The server's composed hooks (src/extensions.rs), for a hook that finds another by its type
    /// (`hook`: a zero-sized proxy observer finds its module); `None` for a request the server
    /// makes of itself or sends through the chain to prepare answers.
    pub server_hooks: Option<&'static crate::extensions::Hooks>,
    /// The site has `handle_errors`: a failure carries the request as sent (`SentRequest`).
    pub(crate) for_errors: bool,
    /// The request body's announced length is over a `request_body` limit: the proxy answers 413
    /// without sending anything on.
    pub body_too_large: bool,
    /// The request's headers as sent, kept before the routes first change them (`request_header`,
    /// `encode`'s If-None-Match), only when `for_errors`; unchanged, they are `req.headers`.
    /// Boxed: the `Ctx` is in every future of the chain, the map is rarely there.
    sent_headers: Option<Box<HeaderMap>>,
}

/// On a failed response, when the site has `handle_errors`: the request as the client sent it (its
/// method and URI before any rewrite, its headers before any route changed them, no extensions: no
/// upgrade, no ready answer's marks), which the error routes run on. Made only when a request
/// fails, so that the others copy nothing.
#[derive(Clone)]
pub(crate) struct SentRequest(pub(crate) Box<http::request::Parts>);

/// A change to the response recorded on the way down the chain.
enum Hook {
    /// The deferred `header` of `list[index]` (values without placeholders).
    Headers { list: Arc<[Route]>, index: usize },
    /// A deferred `header` with placeholders, filled in when it was reached.
    Rendered(Vec<RenderedOp>),
    Encode {
        encode: Arc<Encode>,
        encoding: Encoding,
        head: bool,
    },
}

/// The hooks of a request, outermost first. Two fit in the `Ctx` itself (`encode` and a deferred
/// `header` is the usual most), so a site with `encode` allocates nothing for them; more go to a
/// `Vec`.
#[derive(Default)]
struct Hooks {
    inline: [Option<Hook>; 2],
    more: Vec<Hook>,
}

impl Hooks {
    fn push(&mut self, hook: Hook) {
        for slot in &mut self.inline {
            if slot.is_none() {
                *slot = Some(hook);
                return;
            }
        }
        self.more.push(hook);
    }

    /// The innermost hook left.
    fn pop(&mut self) -> Option<Hook> {
        if let Some(hook) = self.more.pop() {
            return Some(hook);
        }
        self.inline.iter_mut().rev().find_map(Option::take)
    }
}

/// Applies the hooks to the response, innermost first.
async fn finish(mut hooks: Hooks, mut response: Response<Body>) -> Response<Body> {
    while let Some(hook) = hooks.pop() {
        match hook {
            Hook::Headers { list, index } => {
                if let Handler::Header { ops, .. } = &list[index].handler {
                    for op in ops {
                        op.apply(None, response.headers_mut());
                    }
                }
            }
            Hook::Rendered(ops) => {
                for op in &ops {
                    op.apply(response.headers_mut());
                }
            }
            Hook::Encode { encode, encoding, head } => response = encode.apply(encoding, head, response).await,
        }
    }
    response
}

impl Ctx {
    pub fn new(conn: Arc<ConnInfo>, req: http::request::Parts, body: Body, client_ip: IpAddr) -> Ctx {
        let decoded = match percent_decode_str(req.uri.path()).decode_utf8_lossy() {
            std::borrow::Cow::Borrowed(_) => None,
            std::borrow::Cow::Owned(decoded) => Some(decoded),
        };
        Ctx {
            conn,
            orig_uri: req.uri.clone(),
            req,
            body: Some(body),
            decoded,
            match_path: Derived::Unset,
            clean_path: Derived::Unset,
            accept: None,
            client_ip,
            root: None,
            regexps: Vec::new(),
            file_match: None,
            pre_headers: HeaderMap::new(),
            hooks: Hooks::default(),
            encode: None,
            error: None,
            upstream_hooks: None,
            server_hooks: None,
            for_errors: false,
            body_too_large: false,
            sent_headers: None,
        }
    }

    /// A module's hook of type `T` among the server's composed hooks (`Hooks::get`): `None` when
    /// none is composed, or the request has no server (`hooks`).
    pub fn hook<T: 'static>(&self) -> Option<&'static T> {
        self.server_hooks.and_then(|hooks| hooks.get::<T>())
    }

    /// The decoded request path (current, after rewrites).
    pub fn path(&self) -> &str {
        self.decoded.as_deref().unwrap_or_else(|| self.req.uri.path())
    }

    /// The Host header (or the HTTP/2 and HTTP/3 authority), as sent.
    pub fn hostport(&self) -> &str {
        hostport_of(&self.req)
    }

    /// Accept-Encoding, parsed on first use.
    pub fn accept_encoding(&mut self) -> AcceptEncoding {
        *self
            .accept
            .get_or_insert_with(|| AcceptEncoding::parse(&self.req.headers))
    }

    /// The path lowercased and cleaned (`path` matchers), computed on first use.
    pub fn match_path(&mut self) -> &str {
        if let Derived::Unset = self.match_path {
            let path = self.path();
            let lower = path.bytes().any(|b| b.is_ascii_uppercase()) || !path.is_ascii();
            let derived = match (lower, needs_clean(path)) {
                (false, false) => Derived::SameAsPath,
                (false, true) => Derived::Own(clean_path(path, true)),
                (true, dirty) => {
                    let lowered = path.to_lowercase();
                    Derived::Own(if dirty { clean_path(&lowered, true) } else { lowered })
                }
            };
            self.match_path = derived;
        }
        match &self.match_path {
            Derived::Own(path) => path,
            _ => self.path(),
        }
    }

    /// The path cleaned, case kept (`path_regexp`), computed on first use.
    pub fn clean_path(&mut self) -> &str {
        if let Derived::Unset = self.clean_path {
            let path = self.path();
            let derived = if needs_clean(path) {
                Derived::Own(clean_path(path, true))
            } else {
                Derived::SameAsPath
            };
            self.clean_path = derived;
        }
        match &self.clean_path {
            Derived::Own(path) => path,
            _ => self.path(),
        }
    }

    /// Replaces path (decoded form, kept as given: no decode round trip; `None`: the path stays)
    /// and query of the request URI, in one string made once: the path percent-encoded where it
    /// has characters to escape, and the decoded form kept only where that changed it (otherwise
    /// the URI's own path is the decoded path, without a copy).
    pub fn set_path_and_query(&mut self, decoded_path: Option<&str>, query: Query<'_>) {
        let uri = &self.req.uri;
        let query = match query {
            Query::Set(query) => Some(query),
            Query::Keep => uri.query(),
        }
        .filter(|q| !q.is_empty());
        let path = decoded_path.unwrap_or_else(|| uri.path());
        let mut pq = String::with_capacity(path.len() + query.map_or(0, |q| q.len() + 1));
        if decoded_path.is_some() {
            for piece in utf8_percent_encode(path, PATH) {
                pq.push_str(piece);
            }
        } else {
            pq.push_str(path);
        }
        // Grew only by escapes: the URI's path is then not the decoded form.
        let escaped = pq.len() != path.len();
        if let Some(query) = query {
            pq.push('?');
            pq.push_str(query);
        }
        let Ok(pq) = PathAndQuery::from_maybe_shared(Bytes::from(pq)) else {
            return;
        };
        // The regexps matched on the path as it is keep that text once it changes.
        if decoded_path.is_some() && self.regexps.iter().any(|(_, caps)| caps.text.is_none()) {
            let text = self.clean_path_now().to_string();
            for (_, caps) in &mut self.regexps {
                caps.text.get_or_insert_with(|| text.clone());
            }
        }
        // Taken, not cloned: the clone of a `Bytes` made from a `Vec` allocates its shared header.
        let mut parts = std::mem::take(&mut self.req.uri).into_parts();
        // An authority without a scheme (a CONNECT target) takes no path: `from_parts` would
        // refuse it, so the URI stays as it is; otherwise it accepts (checked against http 1.x).
        if parts.scheme.is_some() || parts.authority.is_none() {
            parts.path_and_query = Some(pq);
        }
        self.req.uri = Uri::from_parts(parts).unwrap_or_default();
        let Some(decoded_path) = decoded_path else {
            return;
        };
        self.decoded = escaped.then(|| decoded_path.to_string());
        self.match_path = Derived::Unset;
        self.clean_path = Derived::Unset;
    }

    pub fn set_regexp(&mut self, name: Arc<str>, captures: RegexCaptures) {
        self.regexps.retain(|(n, _)| *n != name);
        self.regexps.push((name, captures));
    }

    /// The cleaned path as last computed (`clean_path`), without computing it: what a
    /// `path_regexp` matched when its captures say `None`.
    fn clean_path_now(&self) -> &str {
        match &self.clean_path {
            Derived::Own(path) => path,
            _ => self.path(),
        }
    }

    /// A group of what a regexp matcher captured, borrowed from the request.
    pub fn regexp(&self, name: &str, group: &str) -> Option<&str> {
        let (_, caps) = self.regexps.iter().find(|(n, _)| &**n == name)?;
        let index = match group.parse::<usize>() {
            Ok(i) => i,
            Err(_) => caps.names.iter().find(|(n, _)| n == group)?.1,
        };
        let (start, end) = (*caps.groups.get(index)?)?;
        caps.text
            .as_deref()
            .unwrap_or_else(|| self.clean_path_now())
            .get(start..end)
    }

    /// A response carrying the headers `header` set earlier (the response's own fields win).
    pub fn respond(&mut self, mut response: Response<Body>) -> Response<Body> {
        let pre = std::mem::take(&mut self.pre_headers);
        let headers = response.headers_mut();
        // HeaderMap iterates a field's values together; `None` names continue the previous field.
        let mut current: Option<(HeaderName, bool)> = None;
        for (name, value) in pre {
            if let Some(name) = name {
                let take = !headers.contains_key(&name);
                current = Some((name, take));
            }
            if let Some((name, true)) = &current {
                headers.append(name.clone(), value);
            }
        }
        response
    }

    /// A proxied response: the headers `header` set earlier come first, the upstream's are added.
    pub fn respond_appending(&mut self, mut response: Response<Body>) -> Response<Body> {
        // Nothing set earlier (most often): the response's own map, not one made anew.
        if self.pre_headers.is_empty() {
            return response;
        }
        let mut headers = std::mem::take(&mut self.pre_headers);
        let mut current: Option<HeaderName> = None;
        for (name, value) in std::mem::take(response.headers_mut()) {
            if let Some(name) = name {
                current = Some(name);
            }
            if let Some(name) = &current {
                headers.append(name.clone(), value);
            }
        }
        *response.headers_mut() = headers;
        response
    }

    pub fn status(&mut self, status: StatusCode) -> Response<Body> {
        let mut response = Response::new(empty());
        *response.status_mut() = status;
        self.respond(response)
    }

    /// A handler failed: its bare status, marked for `handle_errors` (`message`: see
    /// `HandlerError`).
    pub fn fail(&mut self, status: StatusCode, message: Option<Cow<'static, str>>) -> Response<Body> {
        let response = self.status(status);
        self.failed(response, message)
    }

    /// Before the routes change a request header: keeps them as sent, for `handle_errors`.
    fn keep_sent_headers(&mut self) {
        if self.for_errors && self.sent_headers.is_none() {
            self.sent_headers = Some(Box::new(self.req.headers.clone()));
        }
    }

    /// The request as sent, for the error routes (see `SentRequest`).
    fn sent_request(&self, response: &mut Response<Body>) {
        if !self.for_errors {
            return;
        }
        let (mut head, ()) = http::Request::new(()).into_parts();
        head.method = self.req.method.clone();
        head.uri = self.orig_uri.clone();
        head.version = self.req.version;
        head.headers = self.sent_headers.as_deref().unwrap_or(&self.req.headers).clone();
        response.extensions_mut().insert(SentRequest(Box::new(head)));
    }

    /// Marks a response as a handler's failure with its own status (and headers, such as a 405's
    /// `Allow`, which an error page keeps).
    pub fn failed(&self, mut response: Response<Body>, message: Option<Cow<'static, str>>) -> Response<Body> {
        self.sent_request(&mut response);
        self.mark_failed(&mut response, message, None);
        response
    }

    /// Whether a failure's mark is read: by the site's `handle_errors` routes (`for_errors`), or
    /// in those routes themselves, where a failure gives the bare answer (`handle_error`).
    fn marks_failures(&self) -> bool {
        self.for_errors || self.error.is_some()
    }

    /// The `Failed` mark, only where something reads it: on a site without `handle_errors` a 404
    /// costs no error, no `Arc` and no extensions map.
    fn mark_failed(&self, response: &mut Response<Body>, message: Option<Cow<'static, str>>, zone: Option<Arc<str>>) {
        if !self.marks_failures() {
            return;
        }
        let status = response.status();
        let message = message.unwrap_or_else(|| Cow::Borrowed(status.canonical_reason().unwrap_or("")));
        response.extensions_mut().insert(Failed(Arc::new(HandlerError {
            status,
            message,
            root: self.root.clone(),
            zone,
        })));
    }

    /// A `rate_limit` zone refused the request: 429 with `Retry-After`, marked for
    /// `handle_errors` with the zone's name.
    #[cfg(feature = "rate-limit")]
    pub fn fail_rate_limited(&mut self, zone: Arc<str>, wait: std::time::Duration) -> Response<Body> {
        self.pre_headers
            .insert(http::header::RETRY_AFTER, crate::ratelimit::retry_after(wait));
        let mut response = self.status(StatusCode::TOO_MANY_REQUESTS);
        self.sent_request(&mut response);
        self.mark_failed(&mut response, None, Some(zone));
        response
    }
}

/// The query a rewritten URI gets (`Ctx::set_path_and_query`).
#[derive(Debug, Clone, Copy)]
pub enum Query<'a> {
    /// The request's own stays.
    Keep,
    /// This one (empty: none).
    Set(&'a str),
}

/// A failed request's second chance: the site's `handle_errors` routes run on the request as the
/// client sent it (its method and URI before any rewrite, without its body), with the failure in
/// `{err.*}`. As in Caddy: with no block for the status, or when the error routes fail too, the
/// bare failure is the answer; the headers set before the failure (`header`, a 405's `Allow`) stay
/// unless the page sets its own — Caddy keeps only those set without `defer`, ours keep all, as on
/// a bare failure.
pub async fn handle_error(
    routes: &Arc<[Route]>,
    conn: Arc<ConnInfo>,
    request: http::request::Parts,
    client_ip: IpAddr,
    error: Arc<HandlerError>,
    bare: Response<Body>,
) -> Response<Body> {
    let mut ctx = Ctx::new(conn, request, empty(), client_ip);
    ctx.root = error.root.clone();
    ctx.error = Some(error);
    if !routes
        .iter()
        .any(|r| r.matcher.as_ref().is_none_or(|m| m.matches(&mut ctx)))
    {
        return bare;
    }
    let mut page = Next::start(routes.clone()).run(ctx).await;
    if page.extensions().get::<Failed>().is_some() {
        return bare;
    }
    let headers = page.headers_mut();
    let mut current: Option<(HeaderName, bool)> = None;
    for (name, value) in bare.into_parts().0.headers {
        if let Some(name) = name {
            let take = !headers.contains_key(&name);
            current = Some((name, take));
        }
        if let Some((name, true)) = &current {
            headers.append(name.clone(), value);
        }
    }
    page
}

/// The authority a request names: HTTP/2's and HTTP/3's `:authority` (or an HTTP/1.1 absolute
/// target), else its Host header (RFC 9113 §8.3.1, RFC 9112 §3.2.2). The server refuses a request
/// where the two name different hosts (`bad_host`).
pub fn hostport_of(parts: &http::request::Parts) -> &str {
    parts
        .uri
        .authority()
        .map(|a| a.as_str())
        .or_else(|| parts.headers.get(http::header::HOST).and_then(|v| v.to_str().ok()))
        .unwrap_or("")
}

/// Whether a request names its host in a way nothing should act on (answered 400): more than one
/// Host, a Host and an authority for different hosts (a proxy and the app behind it could each take
/// another), or a host that is neither a name nor an address — dots only (`..`), a `/` or `\`, user
/// information, a port that is not a number.
pub fn bad_host(parts: &http::request::Parts) -> bool {
    let mut hosts = parts.headers.get_all(http::header::HOST).iter();
    let header = hosts.next();
    if hosts.next().is_some() {
        return true;
    }
    let header = match header.map(|v| v.to_str()) {
        Some(Ok(text)) => Some(text),
        Some(Err(_)) => return true,
        None => None,
    };
    if let Some(header) = header
        && !valid_hostport(header)
    {
        return true;
    }
    match (parts.uri.authority(), header) {
        (Some(authority), _) if !valid_hostport(authority.as_str()) => true,
        (Some(authority), Some(header)) => !strip_port(authority.as_str()).eq_ignore_ascii_case(strip_port(header)),
        _ => false,
    }
}

/// A host (a name, an IPv4 address, or an IPv6 one in brackets) with an optional port; empty is
/// fine (HTTP/1.0 sends no Host). A name may hold what RFC 3986 allows in one, but for `%` escapes
/// (no browser sends them) and must not be dots only.
fn valid_hostport(hostport: &str) -> bool {
    if hostport.is_empty() {
        return true;
    }
    let (host_ok, port) = match hostport.strip_prefix('[') {
        Some(rest) => match rest.split_once(']') {
            Some((ip, after)) => (ip.parse::<std::net::Ipv6Addr>().is_ok(), after),
            None => return false,
        },
        None => {
            // What follows the name keeps its colon, as after an IPv6 address.
            let name = hostport.split(':').next().unwrap_or_default();
            let ok = !name.is_empty()
                && name.bytes().any(|c| c != b'.')
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&c));
            (ok, &hostport[name.len()..])
        }
    };
    host_ok
        && match port.strip_prefix(':') {
            None => port.is_empty(),
            Some(digits) => digits.len() <= 5 && digits.bytes().all(|c| c.is_ascii_digit()),
        }
}

pub fn strip_port(hostport: &str) -> &str {
    if let Some(rest) = hostport.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match hostport.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => hostport,
    }
}

pub fn decode_path(raw: &str) -> String {
    percent_decode_str(raw).decode_utf8_lossy().into_owned()
}

/// Characters escaped when a decoded path goes back into a URI.
const PATH: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'%')
    .add(b'^')
    .add(b'|')
    .add(b'\\')
    .add(b'[')
    .add(b']');

pub fn encode_path(decoded: &str) -> String {
    utf8_percent_encode(decoded, PATH).to_string()
}

/// A redirect target built from the request may not point off the site: a path that starts with
/// `//` or `/\` (browsers read `\` as `/`) would be taken as scheme-relative, `//evil.example/x`,
/// so the run of slashes and backslashes it starts with becomes one `/`. Browsers also drop ASCII
/// tabs and newlines anywhere in a URL (WHATWG URL parsing), so `/<TAB>/evil.example` is read as
/// `//evil.example`: they count as part of that run. Anything else — an absolute URL, a plain
/// path — is kept as it is.
pub fn same_site_location(location: String) -> String {
    match off_site_rest(&location) {
        Some(rest) => format!("/{rest}"),
        None => location,
    }
}

/// What follows the run of slashes that would take `location` off the site (it is to follow one
/// `/`); `None`: it stays as it is (`same_site_location`).
fn off_site_rest(location: &str) -> Option<&str> {
    if !location.starts_with('/') {
        return None;
    }
    let rest = location.trim_start_matches(['/', '\\', '\t', '\n', '\r']);
    let run = &location[..location.len() - rest.len()];
    (run.bytes().filter(|b| matches!(b, b'/' | b'\\')).count() > 1).then_some(rest)
}

/// The `Location` value of a redirect target: `same_site_location`, then `escape_controls`, written
/// straight into the value (one allocation, the value's own).
fn location_value(location: &str) -> Option<HeaderValue> {
    let mut out = HeaderText::new();
    let text = match off_site_rest(location) {
        Some(rest) => {
            out.push_str("/");
            rest
        }
        None => location,
    };
    let mut from = 0;
    for (i, b) in text.bytes().enumerate() {
        if b.is_ascii_control() {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            out.push_str(&text[from..i]);
            out.push_bytes(&[b'%', HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xF)]]);
            from = i + 1;
        }
    }
    out.push_str(&text[from..]);
    out.value()
}

/// A header value written piece by piece into a buffer on the stack (on the heap past 256 bytes)
/// and made once: one allocation, the value's own, where a `String` and `HeaderValue::from_str`
/// made two and a copy.
pub(crate) struct HeaderText {
    stack: [u8; 256],
    len: usize,
    heap: Vec<u8>,
}

impl HeaderText {
    pub(crate) fn new() -> HeaderText {
        HeaderText {
            stack: [0; 256],
            len: 0,
            heap: Vec::new(),
        }
    }

    pub(crate) fn push_str(&mut self, text: &str) {
        self.push_bytes(text.as_bytes());
    }

    pub(crate) fn push_bytes(&mut self, bytes: &[u8]) {
        if self.heap.is_empty() && self.len + bytes.len() <= self.stack.len() {
            self.stack[self.len..self.len + bytes.len()].copy_from_slice(bytes);
            self.len += bytes.len();
            return;
        }
        if self.heap.is_empty() {
            self.heap.reserve(2 * (self.len + bytes.len()));
            self.heap.extend_from_slice(&self.stack[..self.len]);
        }
        self.heap.extend_from_slice(bytes);
    }

    fn bytes(&self) -> &[u8] {
        if self.heap.is_empty() {
            &self.stack[..self.len]
        } else {
            &self.heap
        }
    }

    /// The value; `None` when the text has bytes a header value may not.
    pub(crate) fn value(&self) -> Option<HeaderValue> {
        HeaderValue::from_bytes(self.bytes()).ok()
    }
}

impl std::fmt::Write for HeaderText {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        self.push_str(text);
        Ok(())
    }
}

/// A number as a header value (`Content-Length`, `Age`): one allocation (`HeaderValue::from`
/// makes two, a buffer and its conversion).
pub(crate) fn header_number(n: u64) -> HeaderValue {
    use std::fmt::Write as _;
    let mut text = HeaderText::new();
    let _ = write!(text, "{n}");
    text.value().expect("digits")
}

/// A `Location` value with control characters percent-encoded: a raw tab or newline would be
/// dropped by the browser, which would then follow a different URL than the one checked.
fn escape_controls(location: String) -> String {
    if !location.bytes().any(|b| b.is_ascii_control()) {
        return location;
    }
    let controls = location.bytes().filter(u8::is_ascii_control).count();
    let mut out = String::with_capacity(location.len() + 2 * controls);
    for ch in location.chars() {
        if ch.is_ascii_control() {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            let b = ch as u8;
            out.push('%');
            out.push(HEX[usize::from(b >> 4)] as char);
            out.push(HEX[usize::from(b & 0xF)] as char);
        } else {
            out.push(ch);
        }
    }
    out
}

/// A header value: built once when it has no placeholders (cloning it is a reference count),
/// otherwise filled in per request.
#[derive(Debug, Clone)]
pub enum Value {
    Static(HeaderValue),
    Dynamic(Template),
}

impl Value {
    /// A value without placeholders is checked, then kept as an interned `'static` string (once
    /// however often the configuration is reloaded), so cloning it costs no reference count. One
    /// with bytes outside visible ASCII (obs-text) cannot be `'static` and is kept as it is.
    pub fn new(template: Template) -> Result<Value, String> {
        match template.as_static() {
            Some(text) => {
                let Ok(value) = HeaderValue::from_str(&text) else {
                    return Err(format!("invalid header value {text:?}"));
                };
                if text.bytes().all(|b| b == b'\t' || (32..127).contains(&b)) {
                    return Ok(Value::Static(HeaderValue::from_static(crate::files::intern(&text))));
                }
                Ok(Value::Static(value))
            }
            None => Ok(Value::Dynamic(template)),
        }
    }

    fn get(&self, ctx: Option<&Ctx>) -> Option<HeaderValue> {
        match self {
            Value::Static(value) => Some(value.clone()),
            Value::Dynamic(template) => template.with_rendered(ctx?, |text| HeaderValue::from_str(text).ok()),
        }
    }
}

/// A header operation of `header`, `request_header`, `header_up`, `header_down`.
#[derive(Debug, Clone)]
pub enum HeaderOp {
    Set(HeaderName, Value),
    Add(HeaderName, Value),
    /// Only when the field is not set yet.
    Default(HeaderName, Value),
    Delete(HeaderName),
    /// `-Prefix*`: every field starting with the (lowercase) prefix.
    DeletePrefix(String),
}

impl HeaderOp {
    pub fn needs_defer(&self) -> bool {
        matches!(
            self,
            HeaderOp::Delete(_) | HeaderOp::DeletePrefix(_) | HeaderOp::Default(..)
        )
    }

    /// Its value, if any, is the same for every request with the same path (src/memo.rs).
    pub fn depends_on_path_only(&self) -> bool {
        match self {
            HeaderOp::Set(_, value) | HeaderOp::Add(_, value) | HeaderOp::Default(_, value) => match value {
                Value::Static(_) => true,
                Value::Dynamic(template) => template.depends_on_path_only(),
            },
            HeaderOp::Delete(_) | HeaderOp::DeletePrefix(_) => true,
        }
    }

    /// Has a value with placeholders.
    pub fn is_dynamic(&self) -> bool {
        matches!(
            self,
            HeaderOp::Set(_, Value::Dynamic(_))
                | HeaderOp::Add(_, Value::Dynamic(_))
                | HeaderOp::Default(_, Value::Dynamic(_))
        )
    }

    pub fn render(&self, ctx: &Ctx) -> RenderedOp {
        let ctx = Some(ctx);
        match self {
            HeaderOp::Set(n, v) => RenderedOp::Set(n.clone(), v.get(ctx)),
            HeaderOp::Add(n, v) => RenderedOp::Add(n.clone(), v.get(ctx)),
            HeaderOp::Default(n, v) => RenderedOp::Default(n.clone(), v.get(ctx)),
            HeaderOp::Delete(n) => RenderedOp::Delete(n.clone()),
            HeaderOp::DeletePrefix(p) => RenderedOp::DeletePrefix(p.clone()),
        }
    }

    /// Applies the operation; dynamic values need `ctx` (without it they are skipped).
    pub fn apply(&self, ctx: Option<&Ctx>, headers: &mut HeaderMap) {
        match self {
            HeaderOp::Set(n, v) => {
                if let Some(v) = v.get(ctx) {
                    headers.insert(n.clone(), v);
                }
            }
            HeaderOp::Add(n, v) => {
                if let Some(v) = v.get(ctx) {
                    headers.append(n.clone(), v);
                }
            }
            HeaderOp::Default(n, v) => {
                if !headers.contains_key(n)
                    && let Some(v) = v.get(ctx)
                {
                    headers.insert(n.clone(), v);
                }
            }
            HeaderOp::Delete(n) => {
                headers.remove(n);
            }
            HeaderOp::DeletePrefix(prefix) => delete_prefix(headers, prefix),
        }
    }
}

fn delete_prefix(headers: &mut HeaderMap, prefix: &str) {
    let names: Vec<HeaderName> = headers
        .keys()
        .filter(|k| k.as_str().starts_with(prefix))
        .cloned()
        .collect();
    for name in names {
        headers.remove(name);
    }
}

/// A header operation with its placeholders filled in.
#[derive(Debug, Clone)]
pub enum RenderedOp {
    Set(HeaderName, Option<HeaderValue>),
    Add(HeaderName, Option<HeaderValue>),
    Default(HeaderName, Option<HeaderValue>),
    Delete(HeaderName),
    DeletePrefix(String),
}

impl RenderedOp {
    pub fn apply(&self, headers: &mut HeaderMap) {
        match self {
            RenderedOp::Set(n, Some(v)) => {
                headers.insert(n.clone(), v.clone());
            }
            RenderedOp::Add(n, Some(v)) => {
                headers.append(n.clone(), v.clone());
            }
            RenderedOp::Default(n, Some(v)) => {
                if !headers.contains_key(n) {
                    headers.insert(n.clone(), v.clone());
                }
            }
            RenderedOp::Delete(n) => {
                headers.remove(n);
            }
            RenderedOp::DeletePrefix(prefix) => delete_prefix(headers, prefix),
            // A value that is not a valid header value after filling in placeholders: skipped.
            RenderedOp::Set(_, None) | RenderedOp::Add(_, None) | RenderedOp::Default(_, None) => {}
        }
    }
}

pub fn apply_ops(ops: &[HeaderOp], ctx: &Ctx, headers: &mut HeaderMap) {
    for op in ops {
        op.apply(Some(ctx), headers);
    }
}

pub struct Route {
    pub matcher: Option<MatcherSet>,
    /// Routes of one `handle` group: only the first that matches runs.
    pub group: Option<u32>,
    pub handler: Handler,
}

/// What `respond` answers with: a text with no placeholders is made once, with its type.
pub struct RespondBody {
    pub template: Template,
    ready: Option<(Bytes, &'static str)>,
}

impl RespondBody {
    pub fn new(template: Template) -> RespondBody {
        let ready = template.as_static().map(|text| {
            let content_type = body_type(&text);
            let text = Bytes::from(text);
            // Shared from the start: every response's copy is a reference count.
            drop(text.clone());
            (text, content_type)
        });
        RespondBody { template, ready }
    }

    pub fn is_empty(&self) -> bool {
        self.template.is_empty()
    }

    /// The text has no placeholders: every request gets the same.
    pub(crate) fn is_ready(&self) -> bool {
        self.ready.is_some()
    }
}

/// The type of a `respond` body: JSON when it is an object or an array, else plain text.
fn body_type(text: &str) -> &'static str {
    let trimmed = text.trim();
    let json = trimmed.len() > 2
        && ((trimmed.starts_with('{') && trimmed.ends_with('}'))
            || (trimmed.starts_with('[') && trimmed.ends_with(']')))
        // Parsed for its validity alone: no tree is built.
        && serde_json::from_str::<serde::de::IgnoredAny>(trimmed).is_ok();
    if json {
        "application/json"
    } else {
        "text/plain; charset=utf-8"
    }
}

pub enum Handler {
    Root(Arc<FileStore>),
    Header {
        ops: Vec<HeaderOp>,
        deferred: bool,
        /// Some value has placeholders (deferred ones are then filled in before the chain runs on).
        dynamic: bool,
    },
    RequestHeader(Vec<HeaderOp>),
    /// `request_body { max_size }`: the request body may have at most this many bytes (0: any).
    RequestBody(u64),
    Redir {
        to: Template,
        status: StatusCode,
        html: bool,
    },
    Rewrite(Template),
    StripPrefix(String),
    Encode(Arc<Encode>),
    Subroute(Arc<[Route]>),
    Respond {
        /// `None`: 200, or in `handle_errors` routes the failure's status.
        status: Option<StatusCode>,
        body: RespondBody,
        close: bool,
    },
    /// `error`: the request fails with this status (src/handler.rs `HandlerError`).
    Error {
        status: StatusCode,
        message: Template,
    },
    Proxy(Arc<ReverseProxy>),
    Files(Arc<FileServer>),
    /// `rate_limit`: counts the request in its zones, and refuses it when one is exceeded.
    #[cfg(feature = "rate-limit")]
    RateLimit(Arc<crate::ratelimit::RateLimit>),
    /// A module's directive (src/module.rs `RouteHandler`): run where it stands, like `rate_limit`;
    /// `None` lets the chain go on.
    Extension(Arc<dyn crate::module::RouteHandler>),
    /// `cache`: answers from the proxy cache, or marks the request for the proxy to keep its answer.
    #[cfg(feature = "proxy-cache")]
    Cache(Arc<crate::cache::Cache>),
}

/// The rest of the chain: routes from `index` on, then the enclosing list's rest.
#[derive(Clone)]
pub struct Next {
    list: Arc<[Route]>,
    index: usize,
    skip_group: Option<u32>,
    outer: Option<Arc<Next>>,
}

impl Next {
    pub fn start(list: Arc<[Route]>) -> Next {
        Next {
            list,
            index: 0,
            skip_group: None,
            outer: None,
        }
    }

    /// The rest of the chain as a boxed future: what a handler that wraps the chain awaits
    /// (`answer`, the file server's `pass_thru`), since a future cannot contain itself.
    pub fn run(self, ctx: Ctx) -> BoxFuture<'static, Response<Body>> {
        Box::pin(self.walk(ctx))
    }

    /// Runs the chain on the request. The outermost call: every recursive one goes through `run`,
    /// so this future is awaited in place, in the connection's own task, without a box of its own.
    pub async fn walk(mut self, mut ctx: Ctx) -> Response<Body> {
        loop {
            let list = self.list.clone();
            let mut found = None;
            while self.index < list.len() {
                let route = &list[self.index];
                self.index += 1;
                let excluded = route.group.is_some() && route.group == self.skip_group;
                if !excluded && route.matcher.as_ref().is_none_or(|m| m.matches(&mut ctx)) {
                    found = Some(route);
                    break;
                }
            }
            let Some(route) = found else {
                match self.outer.take() {
                    Some(outer) => {
                        self = Arc::unwrap_or_clone(outer);
                        continue;
                    }
                    None => {
                        let hooks = std::mem::take(&mut ctx.hooks);
                        let response = ctx.status(StatusCode::OK);
                        return finish(hooks, response).await;
                    }
                }
            };
            // After a `handle` block ran, the others of its group are skipped.
            if route.group.is_some() {
                self.skip_group = route.group;
            }
            if route.handler.step(&mut ctx) {
                continue;
            }
            match &route.handler {
                Handler::Subroute(inner) => {
                    let outer = std::mem::replace(&mut self, Next::start(inner.clone()));
                    self.outer = Some(Arc::new(outer));
                    continue;
                }
                Handler::Header {
                    ops,
                    deferred: true,
                    dynamic,
                } => {
                    let hook = if *dynamic {
                        Hook::Rendered(ops.iter().map(|op| op.render(&ctx)).collect())
                    } else {
                        Hook::Headers {
                            list: list.clone(),
                            index: self.index - 1,
                        }
                    };
                    ctx.hooks.push(hook);
                    continue;
                }
                Handler::Encode(encode) => {
                    // The site's `encode`, for a proxied answer kept by `cache` (src/proxy.rs).
                    ctx.encode = Some(encode.clone());
                    let accept = ctx.accept_encoding();
                    if ctx.req.headers.contains_key(http::header::IF_NONE_MATCH) {
                        ctx.keep_sent_headers();
                    }
                    if let Some(encoding) = encode.choose(accept, &mut ctx.req.headers) {
                        let head = ctx.req.method == http::Method::HEAD;
                        ctx.hooks.push(Hook::Encode {
                            encode: encode.clone(),
                            encoding,
                            head,
                        });
                    }
                    continue;
                }
                #[cfg(feature = "rate-limit")]
                Handler::RateLimit(limit) => match limit.check(&mut ctx) {
                    None => continue,
                    Some((zone, wait)) => {
                        let hooks = std::mem::take(&mut ctx.hooks);
                        let response = ctx.fail_rate_limited(zone, wait);
                        return finish(hooks, response).await;
                    }
                },
                Handler::Extension(handler) => match handler.run(&mut ctx) {
                    None => continue,
                    Some(response) => {
                        let hooks = std::mem::take(&mut ctx.hooks);
                        let response = ctx.respond(response);
                        return finish(hooks, response).await;
                    }
                },
                #[cfg(feature = "proxy-cache")]
                Handler::Cache(cache) => match cache.check(&mut ctx).await {
                    None => continue,
                    Some(response) => {
                        let hooks = std::mem::take(&mut ctx.hooks);
                        return finish(hooks, response).await;
                    }
                },
                _ => {}
            }
            // A handler that answers; a `pass_thru` file server that goes on starts its own walk,
            // which applies the hooks recorded after this point.
            let hooks = std::mem::take(&mut ctx.hooks);
            let response = route.handler.answer(ctx, self).await;
            return finish(hooks, response).await;
        }
    }
}

/// `f` of a string buffer the thread keeps (let go of past 1 KiB): the rewritten target is
/// rendered into it and read from it, with no string of its own.
fn with_scratch<R>(f: impl FnOnce(&mut String) -> R) -> R {
    const KEPT: usize = 1024;
    thread_local! {
        static SCRATCH: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
    }
    SCRATCH.with(|cell| match cell.try_borrow_mut() {
        Ok(mut text) => {
            text.clear();
            let out = f(&mut text);
            if text.capacity() > KEPT {
                *text = String::new();
            }
            out
        }
        Err(_) => f(&mut String::new()),
    })
}

/// `rewrite`: the target's path and query replace the request's; a target without a query keeps
/// the request's, one with an empty path (`?q=1`) keeps the request's path, as in Caddy. The
/// target is rendered into the thread's buffer and the URI made from it in one string.
fn rewrite(ctx: &mut Ctx, to: &Template) {
    with_scratch(|target| {
        to.render_into(ctx, target);
        let (path, query) = match target.find('?') {
            Some(i) => (&target[..i], Query::Set(&target[i + 1..])),
            None => (target.as_str(), Query::Keep),
        };
        ctx.set_path_and_query((!path.is_empty()).then_some(path), query);
    });
}

/// The request body limited to `max` bytes (0: no limit, as in Caddy); several limits all hold.
/// A body that is already complete (none, or empty) is left as it is.
fn limit_body(ctx: &mut Ctx, max: u64) {
    if max == 0 {
        return;
    }
    let Some(body) = ctx.body.take_if(|body| !http_body::Body::is_end_stream(body)) else {
        return;
    };
    let limited = crate::guard::LimitedBody::new(body, max);
    ctx.body_too_large |= limited.announced();
    ctx.body = Some(crate::body::boxed(limited));
}

fn strip_prefix(ctx: &mut Ctx, prefix: &str) {
    let path = ctx.path();
    // Compared byte by byte, ASCII case-insensitively: `to_lowercase` may change the byte length of
    // a path with non-ASCII letters, and slicing by the prefix's length would then cut a character.
    let has_prefix = path.len() >= prefix.len()
        && path.is_char_boundary(prefix.len())
        && path.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes());
    if has_prefix {
        // The rest of the path, with its leading slash, in the thread's buffer: the URI is the one
        // string made.
        with_scratch(|stripped| {
            let rest = &ctx.path()[prefix.len()..];
            if !rest.starts_with('/') {
                stripped.push('/');
            }
            stripped.push_str(rest);
            ctx.set_path_and_query(Some(stripped), Query::Keep);
        });
    }
}

impl Handler {
    /// Changes the request or its context and lets the chain go on; false for handlers that answer
    /// or wrap the rest of the chain.
    fn step(&self, ctx: &mut Ctx) -> bool {
        match self {
            Handler::Root(store) => ctx.root = Some(store.clone()),
            Handler::Header {
                ops, deferred: false, ..
            } => {
                let mut pre = std::mem::take(&mut ctx.pre_headers);
                apply_ops(ops, ctx, &mut pre);
                ctx.pre_headers = pre;
            }
            Handler::RequestHeader(ops) => {
                ctx.keep_sent_headers();
                let mut headers = std::mem::take(&mut ctx.req.headers);
                apply_ops(ops, ctx, &mut headers);
                ctx.req.headers = headers;
                ctx.accept = None;
            }
            Handler::Rewrite(to) => rewrite(ctx, to),
            // `respond 103`: the headers set so far go out as Early Hints, the chain goes on (Caddy),
            // and they stay for the final response.
            Handler::Respond {
                status: Some(StatusCode::EARLY_HINTS),
                ..
            } => {
                if let Some(EarlyHints(hints)) = ctx.req.extensions.get::<EarlyHints>() {
                    let _ = hints.try_send(ctx.pre_headers.clone());
                }
            }
            Handler::StripPrefix(prefix) => strip_prefix(ctx, prefix),
            Handler::RequestBody(max) => limit_body(ctx, *max),
            _ => return false,
        }
        true
    }

    /// Answers (from `Next::walk`); for the other kinds it runs the rest of the chain itself, so
    /// calling it directly stays correct.
    async fn answer(&self, mut ctx: Ctx, next: Next) -> Response<Body> {
        match self {
            Handler::Header {
                ops,
                deferred: true,
                dynamic: false,
            } => {
                let mut response = next.run(ctx).await;
                for op in ops {
                    op.apply(None, response.headers_mut());
                }
                response
            }
            Handler::Header {
                ops,
                deferred: true,
                dynamic: true,
            } => {
                let rendered: Vec<RenderedOp> = ops.iter().map(|op| op.render(&ctx)).collect();
                let mut response = next.run(ctx).await;
                for op in &rendered {
                    op.apply(response.headers_mut());
                }
                response
            }
            Handler::Redir { to, status, html } => {
                if *html {
                    let location = escape_controls(same_site_location(to.render(&ctx)));
                    let escaped = crate::static_files::html_escape(&location);
                    let body = format!(
                        "<!DOCTYPE html>\n<html>\n\t<head>\n\t\t<title>Redirecting...</title>\n\t\t<script>window.location.replace(\"{escaped}\");</script>\n\t\t<meta http-equiv=\"refresh\" content=\"0; URL='{escaped}'\">\n\t</head>\n\t<body>Redirecting to <a href=\"{escaped}\">{escaped}</a>...</body>\n</html>\n"
                    );
                    let mut response = Response::new(full(body));
                    response
                        .headers_mut()
                        .insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
                    return ctx.respond(response);
                }
                let mut response = Response::new(empty());
                *response.status_mut() = *status;
                if let Some(value) = to.with_rendered(&ctx, location_value) {
                    response.headers_mut().insert(LOCATION, value);
                }
                // The same redirect for every request with this path: a ready answer (src/memo.rs).
                if to.depends_on_path_only() && crate::memo::keeps(&ctx.req) {
                    response.extensions_mut().insert(crate::memo::Redirected);
                }
                ctx.respond(response)
            }
            Handler::Encode(encode) => {
                ctx.encode = Some(encode.clone());
                let accept = ctx.accept_encoding();
                if ctx.req.headers.contains_key(http::header::IF_NONE_MATCH) {
                    ctx.keep_sent_headers();
                }
                let Some(encoding) = encode.choose(accept, &mut ctx.req.headers) else {
                    return next.run(ctx).await;
                };
                let head = ctx.req.method == http::Method::HEAD;
                let response = next.run(ctx).await;
                encode.apply(encoding, head, response).await
            }
            // Early Hints are not an answer (`step`).
            Handler::Respond {
                status: Some(StatusCode::EARLY_HINTS),
                ..
            } => {
                self.step(&mut ctx);
                next.run(ctx).await
            }
            Handler::Respond { status, body, close } => {
                let typed = !ctx.pre_headers.contains_key(CONTENT_TYPE);
                // A text with no placeholders was made once; another is copied from the thread's
                // buffer once, at its size.
                let (text, content_type) = match &body.ready {
                    Some((text, content_type)) => (text.clone(), *content_type),
                    None => body.template.with_rendered(&ctx, |text| {
                        let content_type = if typed { body_type(text) } else { "" };
                        (Bytes::copy_from_slice(text.as_bytes()), content_type)
                    }),
                };
                let filled = !text.is_empty();
                let mut response = Response::new(if filled { full(text) } else { empty() });
                *response.status_mut() = status
                    .or(ctx.error.as_ref().map(|e| e.status))
                    .unwrap_or(StatusCode::OK);
                if filled && typed {
                    response
                        .headers_mut()
                        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
                }
                if *close {
                    response
                        .headers_mut()
                        .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
                }
                ctx.respond(response)
            }
            Handler::Error { status, message } => {
                let message = message.render(&ctx);
                ctx.fail(*status, Some(Cow::Owned(message)))
            }
            // The proxy's future is large: boxed on its own, so the chain's stays small.
            Handler::Proxy(proxy) => Box::pin(proxy.serve(ctx)).await,
            Handler::Files(files) => files.serve(ctx, next).await,
            Handler::Subroute(list) => {
                let inner = Next {
                    list: list.clone(),
                    index: 0,
                    skip_group: None,
                    outer: Some(Arc::new(next)),
                };
                inner.run(ctx).await
            }
            #[cfg(feature = "rate-limit")]
            Handler::RateLimit(limit) => match limit.check(&mut ctx) {
                None => next.run(ctx).await,
                Some((zone, wait)) => ctx.fail_rate_limited(zone, wait),
            },
            Handler::Extension(handler) => match handler.run(&mut ctx) {
                None => next.run(ctx).await,
                Some(response) => ctx.respond(response),
            },
            #[cfg(feature = "proxy-cache")]
            Handler::Cache(cache) => match cache.check(&mut ctx).await {
                None => next.run(ctx).await,
                Some(response) => response,
            },
            // Not reached from `Next::walk` (it applies these itself); kept correct regardless.
            _ => {
                self.step(&mut ctx);
                next.run(ctx).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(path: &str) -> Ctx {
        let conn = Arc::new(ConnInfo {
            remote: "127.0.0.1:5000".parse().unwrap(),
            tls: false,
            trusted: false,
            sni: None,
            ja4: None,
        });
        let (parts, body) = http::Request::get(path).body(empty()).unwrap().into_parts();
        Ctx::new(conn, parts, body, "127.0.0.1".parse().unwrap())
    }

    #[test]
    fn hosts_are_names_or_addresses() {
        for good in [
            "",
            "example.com",
            "Example.COM:8443",
            "a-b_c.example",
            "127.0.0.1:80",
            "[::1]",
            "[2001:db8::1]:443",
            "xn--caf-dma.test",
            "localhost.",
            "host:",
        ] {
            assert!(valid_hostport(good), "{good:?}");
        }
        for bad in [
            "..",
            ".",
            "...:80",
            "a/b",
            "a\\b",
            "../etc",
            "user@host",
            "host:http",
            "host:1:2",
            "host:123456",
            "[::1",
            "[nope]",
            "[::1]x",
            "a%2fb",
            "café.test",
            ":80",
            "a b",
        ] {
            assert!(!valid_hostport(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_host_and_an_authority_must_agree() {
        let parts = |uri: &str, hosts: &[&str]| {
            let mut builder = http::Request::get(uri);
            for host in hosts {
                builder = builder.header(http::header::HOST, *host);
            }
            builder.body(()).unwrap().into_parts().0
        };
        // HTTP/1.1 origin form: the Host alone.
        assert!(!bad_host(&parts("/x", &["example.com"])));
        assert!(!bad_host(&parts("/x", &[])));
        assert!(bad_host(&parts("/x", &[".."])));
        assert!(bad_host(&parts("/x", &["a.test", "b.test"])), "two Hosts");
        // HTTP/2, HTTP/3 (or an absolute target): the authority wins and the Host must agree.
        let p = parts("https://a.test/x", &[]);
        assert!(!bad_host(&p));
        assert_eq!(hostport_of(&p), "a.test");
        let p = parts("https://a.test:8443/x", &["A.TEST"]);
        assert!(!bad_host(&p), "the same host, case and port aside");
        assert_eq!(hostport_of(&p), "a.test:8443");
        assert!(bad_host(&parts("https://a.test/x", &["admin.test"])));
        assert!(bad_host(&parts("https://user@a.test/x", &[])));
    }

    #[test]
    fn redirect_targets_stay_on_the_site() {
        let same = |s: &str| same_site_location(s.to_string());
        assert_eq!(same("/en/contact"), "/en/contact");
        assert_eq!(same("/"), "/");
        assert_eq!(same("//evil.example/x"), "/evil.example/x");
        assert_eq!(same(r"/\evil.example/x"), "/evil.example/x");
        assert_eq!(same(r"///\/evil.example"), "/evil.example");
        assert_eq!(same(r"/x/\y"), r"/x/\y", "only the start matters");
        // Tabs and newlines, which browsers drop, do not hide a second slash.
        assert_eq!(same("/\t/evil.example"), "/evil.example");
        assert_eq!(same("/\n\r/evil.example"), "/evil.example");
        assert_eq!(same("/\t\\evil.example"), "/evil.example");
        assert_eq!(same("/\t/evil.example/../../en/"), "/evil.example/../../en/");
        assert_eq!(same("/\tpage"), "/\tpage", "one slash: on the site");
        assert_eq!(escape_controls("/\tpage".into()), "/%09page");
        assert_eq!(escape_controls("/a b".into()), "/a b");
        assert_eq!(escape_controls("/\x7f\r\n\0д".into()), "/%7F%0D%0A%00д");
        // The value a redirect sends: the two, written at once.
        for to in [
            "/en/",
            "//evil.example/x",
            "/\\evil.example",
            "/\t/evil.example",
            "https://example.com/a b",
            "/\x7f\r\n\0д?q=1",
            "relative/path",
            "/",
            "",
        ] {
            let want = escape_controls(same_site_location(to.to_string()));
            assert_eq!(location_value(to).unwrap(), want.as_str(), "{to:?}");
        }
        let long = format!("/{}", "a".repeat(1000));
        assert_eq!(location_value(&long).unwrap(), long.as_str(), "past the stack buffer");
        assert_eq!(header_number(0), "0");
        assert_eq!(header_number(u64::MAX), "18446744073709551615");
        assert_eq!(
            same("https://example.com/"),
            "https://example.com/",
            "absolute URLs are kept"
        );
        assert_eq!(same(""), "");
    }

    #[test]
    fn prefixes_are_stripped_by_bytes_and_case_insensitively() {
        for (path, expected) in [
            ("/api/x", "/x"),
            ("/API/x", "/x"),
            ("/api", "/"),
            ("/apix", "/x"),
            ("/apİ/x", "/apİ/x"),
            ("/ap", "/ap"),
            ("/other/api", "/other/api"),
        ] {
            let mut c = ctx(&encode_path(path));
            strip_prefix(&mut c, "/api");
            assert_eq!(c.path(), expected, "{path}");
        }
        // `handle_path`: the query stays, escapes stay escaped in the URI and decoded in the path.
        let mut c = ctx("/api/a%20b/caf%C3%A9?x=1&y=2");
        strip_prefix(&mut c, "/api");
        assert_eq!(c.req.uri.path_and_query().unwrap(), "/a%20b/caf%C3%A9?x=1&y=2");
        assert_eq!(c.path(), "/a b/café");
        assert_eq!(c.req.uri.query(), Some("x=1&y=2"));
        let mut c = ctx("/api/plain?q");
        strip_prefix(&mut c, "/api");
        assert_eq!(c.req.uri.path_and_query().unwrap(), "/plain?q");
        assert_eq!(c.path(), "/plain");
        assert!(c.decoded.is_none(), "the URI's path is the decoded path");
    }

    #[test]
    fn rewrites_make_the_uri_once_and_keep_what_the_target_leaves() {
        let rewritten = |path: &str, to: &str| {
            let mut c = ctx(path);
            rewrite(&mut c, &Template::parse(to).unwrap());
            c
        };
        // A plain target: path and query replaced, the request's query dropped.
        let c = rewritten("/old?a=1", "/new?b=2");
        assert_eq!(c.req.uri.path_and_query().unwrap(), "/new?b=2");
        assert_eq!(c.path(), "/new");
        assert!(c.decoded.is_none());
        // No query in the target: the request's stays.
        let c = rewritten("/old?a=1", "/new");
        assert_eq!(c.req.uri.path_and_query().unwrap(), "/new?a=1");
        // An empty query in the target drops the request's.
        let c = rewritten("/old?a=1", "/new?");
        assert_eq!(c.req.uri.path_and_query().unwrap(), "/new");
        // Only a query: the path stays as it was, escapes and all, and so does its decoded form.
        let c = rewritten("/a%2Fb%20c?a=1", "?b=2");
        assert_eq!(c.req.uri.path_and_query().unwrap(), "/a%2Fb%20c?b=2");
        assert_eq!(c.path(), "/a/b c");
        // Placeholders: the path decoded, the query as sent.
        let c = rewritten("/en/page?q=%22x%22", "/index.php?p={path}&{query}");
        assert_eq!(c.req.uri.path_and_query().unwrap(), "/index.php?p=/en/page&q=%22x%22");
        assert_eq!(c.path(), "/index.php");
        // A target that is no URI (a space in the query) leaves the request as it is.
        let c = rewritten("/en/page%20one?q=1", "/index.php?p={path}");
        assert_eq!(c.req.uri.path_and_query().unwrap(), "/en/page%20one?q=1");
        assert_eq!(c.path(), "/en/page one");
        // Characters to escape in the target: escaped in the URI, kept in the path.
        let c = rewritten("/x", "/a b/café/%7E?k=v");
        assert_eq!(c.req.uri.path_and_query().unwrap(), "/a%20b/caf%C3%A9/%257E?k=v");
        assert_eq!(c.path(), "/a b/café/%7E");
        assert_eq!(c.decoded.as_deref(), Some("/a b/café/%7E"));
        // The derived paths follow the rewrite.
        let mut c = rewritten("/Old//x", "/New//y");
        assert_eq!(c.match_path(), "/new/y");
        assert_eq!(c.clean_path(), "/New/y");
        // An absolute target keeps scheme and authority of the request.
        let c = rewritten("http://a.test/old?a=1", "/new");
        assert_eq!(c.req.uri.to_string(), "http://a.test/new?a=1");
        assert_eq!(c.hostport(), "a.test");
    }

    #[test]
    fn regexp_captures_point_into_the_path_until_a_rewrite_changes_it() {
        let mut c = ctx("/blog/2024/hello.html");
        let re = regex::Regex::new(r"^/blog/(\d+)/(?P<slug>[^/]+)\.html$").unwrap();
        let m = crate::matcher::Matcher::regexp("post", re);
        assert!(m.matches(&mut c));
        assert_eq!(c.regexp("post", "1"), Some("2024"));
        assert_eq!(c.regexp("post", "slug"), Some("hello"));
        assert_eq!(c.regexp("post", "0"), Some("/blog/2024/hello.html"));
        assert_eq!(c.regexp("post", "3"), None);
        assert_eq!(c.regexp("other", "1"), None);
        assert!(c.regexps[0].1.text.is_none(), "no copy while the path stays");
        // Rewritten with the groups: they still read the path they matched.
        rewrite(&mut c, &Template::parse("/posts/{re.post.slug}-{re.post.1}").unwrap());
        assert_eq!(c.path(), "/posts/hello-2024");
        assert_eq!(c.regexp("post", "1"), Some("2024"));
        assert_eq!(c.regexp("post", "slug"), Some("hello"));
        assert_eq!(c.regexps[0].1.text.as_deref(), Some("/blog/2024/hello.html"));
        // Matched on a path that needed cleaning: the captures are in the cleaned one.
        let mut c = ctx("/blog//2025/./x.html");
        assert!(m.matches(&mut c));
        assert_eq!(c.regexp("post", "slug"), Some("x"));
        // `handle_path` strips from the path as sent (not cleaned), as Caddy does.
        strip_prefix(&mut c, "/blog");
        assert_eq!(c.path(), "//2025/./x.html");
        assert_eq!(c.regexp("post", "1"), Some("2025"));
        assert_eq!(c.regexp("post", "0"), Some("/blog/2025/x.html"));
    }

    #[test]
    fn failures_are_marked_only_where_something_reads_the_mark() {
        let mut c = ctx("/missing");
        let plain = c.fail(StatusCode::NOT_FOUND, None);
        assert_eq!(plain.status(), StatusCode::NOT_FOUND);
        assert!(
            plain.extensions().get::<Failed>().is_none(),
            "no handle_errors: nothing reads it"
        );
        assert!(plain.extensions().get::<SentRequest>().is_none());
        let mut c = ctx("/missing");
        c.for_errors = true;
        let marked = c.fail(StatusCode::NOT_FOUND, None);
        let Failed(error) = marked.extensions().get::<Failed>().unwrap();
        assert_eq!(error.status, StatusCode::NOT_FOUND);
        assert!(matches!(error.message, Cow::Borrowed("Not Found")));
        assert!(marked.extensions().get::<SentRequest>().is_some());
        let with_text = c.fail(StatusCode::FORBIDDEN, Some("Private area".into()));
        let Failed(error) = with_text.extensions().get::<Failed>().unwrap();
        assert_eq!(error.message, "Private area");
        // In the error routes themselves (`handle_error` reads the mark, the request is not kept).
        let mut c = ctx("/404.html");
        c.error = Some(error.clone());
        let again = c.fail(StatusCode::NOT_FOUND, None);
        assert!(again.extensions().get::<Failed>().is_some());
        assert!(again.extensions().get::<SentRequest>().is_none());
    }

    #[tokio::test]
    async fn hooks_apply_innermost_first_beyond_the_inline_two() {
        let mut hooks = Hooks::default();
        let op = |name: &str, value: &str| {
            vec![RenderedOp::Set(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                Some(HeaderValue::from_str(value).unwrap()),
            )]
        };
        for i in 0..4 {
            hooks.push(Hook::Rendered(op("x-order", &i.to_string())));
        }
        assert!(hooks.inline.iter().all(Option::is_some) && hooks.more.len() == 2);
        let mut order = Vec::new();
        while let Some(Hook::Rendered(ops)) = hooks.pop() {
            let RenderedOp::Set(_, Some(value)) = &ops[0] else {
                panic!()
            };
            order.push(value.to_str().unwrap().to_string());
        }
        assert_eq!(order, ["3", "2", "1", "0"]);
        // The outermost `header` is applied last, so its value is what the response has.
        let mut hooks = Hooks::default();
        hooks.push(Hook::Rendered(op("x-who", "outer")));
        hooks.push(Hook::Rendered(op("x-who", "inner")));
        let response = finish(hooks, Response::new(empty())).await;
        assert_eq!(response.headers()["x-who"], "outer");
        // The chain's own future is awaited unboxed by the connection: its size is what every
        // request puts on the connection's task; the handlers that recurse box theirs (`run`).
        let walk = Next::start(Arc::from(Vec::<Route>::new())).walk(ctx("/"));
        assert!(
            std::mem::size_of_val(&walk) < 16 * 1024,
            "{} bytes",
            std::mem::size_of_val(&walk)
        );
        assert_eq!(walk.await.status(), StatusCode::OK);
    }

    /// A `respond` body's type: JSON when it is an object or an array that parses, text else.
    #[test]
    fn a_respond_body_is_json_only_when_it_parses() {
        assert_eq!(body_type(r#"{"ok":true,"items":[1,2]}"#), "application/json");
        assert_eq!(body_type(" [1, 2] "), "application/json");
        assert_eq!(body_type("{not json}"), "text/plain; charset=utf-8");
        assert_eq!(
            body_type("{}"),
            "text/plain; charset=utf-8",
            "too short to be taken for JSON"
        );
        assert_eq!(body_type("ok"), "text/plain; charset=utf-8");
    }
}
