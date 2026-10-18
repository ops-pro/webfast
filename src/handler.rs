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
use http::header::{CONTENT_TYPE, LOCATION};
use http::uri::PathAndQuery;
use http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode, Uri};
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
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
}

impl ConnInfo {
    /// The same connection once its TLS handshake named `sni`.
    pub fn with_sni(&self, sni: Option<&str>) -> ConnInfo {
        ConnInfo {
            remote: self.remote,
            tls: self.tls,
            trusted: self.trusted,
            sni: sni.map(|name| name.to_ascii_lowercase().into_boxed_str()),
        }
    }
}

/// Groups of a `path_regexp` match: byte ranges into the matched path.
#[derive(Debug, Clone)]
pub struct RegexCaptures {
    pub text: String,
    pub groups: Vec<Option<(usize, usize)>>,
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
    /// text where there is one, such as a proxy's network error).
    pub message: String,
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
    hooks: Vec<Hook>,
    /// The site's `encode` the request passed, if any: what a kept proxied answer is compressed
    /// with (src/proxy.rs, src/cache.rs). An `Arc` clone: no allocation.
    pub encode: Option<Arc<Encode>>,
    /// In `handle_errors` routes: the failure they answer for.
    pub error: Option<Arc<HandlerError>>,
    /// The extensions' checks bound to upstreams (src/extensions.rs), for the proxy to run before it
    /// sends the request on; `None`: there are none, or the server asks itself.
    pub(crate) upstream_hooks: Option<&'static crate::extensions::UpstreamChecks>,
}

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

/// Applies the hooks to the response, innermost first.
async fn finish(hooks: Vec<Hook>, mut response: Response<Body>) -> Response<Body> {
    for hook in hooks.into_iter().rev() {
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
            hooks: Vec::new(),
            encode: None,
            error: None,
            upstream_hooks: None,
        }
    }

    /// The decoded request path (current, after rewrites).
    pub fn path(&self) -> &str {
        self.decoded.as_deref().unwrap_or_else(|| self.req.uri.path())
    }

    /// The Host header (or the HTTP/2 and HTTP/3 authority), as sent.
    pub fn hostport(&self) -> &str {
        hostport_of(&self.req)
    }

    /// The host name: lowercase, without the port.
    pub fn host(&self) -> String {
        strip_port(self.hostport()).to_ascii_lowercase()
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

    /// Replaces path (decoded form, kept as given: no decode round trip) and query of the request
    /// URI; the path is percent-encoded for the URI only where it has characters to escape.
    pub fn set_path_and_query(&mut self, decoded_path: String, query: Option<&str>) {
        let encoded: std::borrow::Cow<str> = utf8_percent_encode(&decoded_path, PATH).into();
        let query = query.filter(|q| !q.is_empty());
        let mut pq = String::with_capacity(encoded.len() + query.map_or(0, |q| q.len() + 1));
        pq.push_str(&encoded);
        if let Some(query) = query {
            pq.push('?');
            pq.push_str(query);
        }
        let Ok(pq) = PathAndQuery::from_maybe_shared(bytes::Bytes::from(pq)) else {
            return;
        };
        let mut parts = self.req.uri.clone().into_parts();
        parts.path_and_query = Some(pq);
        if let Ok(uri) = Uri::from_parts(parts) {
            self.req.uri = uri;
            self.decoded = Some(decoded_path);
            self.match_path = Derived::Unset;
            self.clean_path = Derived::Unset;
        }
    }

    pub fn set_regexp(&mut self, name: Arc<str>, captures: RegexCaptures) {
        self.regexps.retain(|(n, _)| *n != name);
        self.regexps.push((name, captures));
    }

    pub fn regexp(&self, name: &str, group: &str) -> Option<String> {
        let (_, caps) = self.regexps.iter().find(|(n, _)| &**n == name)?;
        let index = match group.parse::<usize>() {
            Ok(i) => i,
            Err(_) => caps.names.iter().find(|(n, _)| n == group)?.1,
        };
        let (start, end) = (*caps.groups.get(index)?)?;
        caps.text.get(start..end).map(str::to_string)
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
    pub fn fail(&mut self, status: StatusCode, message: Option<String>) -> Response<Body> {
        let response = self.status(status);
        self.failed(response, message)
    }

    /// Marks a response as a handler's failure with its own status (and headers, such as a 405's
    /// `Allow`, which an error page keeps).
    pub fn failed(&self, mut response: Response<Body>, message: Option<String>) -> Response<Body> {
        let status = response.status();
        let message = message.unwrap_or_else(|| status.canonical_reason().unwrap_or("").to_string());
        let root = self.root.clone();
        response.extensions_mut().insert(Failed(Arc::new(HandlerError {
            status,
            message,
            root,
            zone: None,
        })));
        response
    }

    /// A `rate_limit` zone refused the request: 429 with `Retry-After`, marked for
    /// `handle_errors` with the zone's name.
    #[cfg(feature = "rate-limit")]
    pub fn fail_rate_limited(&mut self, zone: Arc<str>, wait: std::time::Duration) -> Response<Body> {
        self.pre_headers
            .insert(http::header::RETRY_AFTER, crate::ratelimit::retry_after(wait));
        let mut response = self.status(StatusCode::TOO_MANY_REQUESTS);
        let status = StatusCode::TOO_MANY_REQUESTS;
        let message = status.canonical_reason().unwrap_or("").to_string();
        response.extensions_mut().insert(Failed(Arc::new(HandlerError {
            status,
            message,
            root: self.root.clone(),
            zone: Some(zone),
        })));
        response
    }
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

/// The Host header of a request head, or its URI authority (HTTP/2, HTTP/3).
pub fn hostport_of(parts: &http::request::Parts) -> &str {
    parts
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| parts.uri.authority().map(|a| a.as_str()))
        .unwrap_or("")
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
    if !location.starts_with('/') {
        return location;
    }
    let rest = location.trim_start_matches(['/', '\\', '\t', '\n', '\r']);
    let run = &location[..location.len() - rest.len()];
    if run.bytes().filter(|b| matches!(b, b'/' | b'\\')).count() > 1 {
        return format!("/{rest}");
    }
    location
}

/// A `Location` value with control characters percent-encoded: a raw tab or newline would be
/// dropped by the browser, which would then follow a different URL than the one checked.
fn escape_controls(location: String) -> String {
    if !location.bytes().any(|b| b.is_ascii_control()) {
        return location;
    }
    let mut out = String::with_capacity(location.len() + 8);
    for ch in location.chars() {
        if ch.is_ascii_control() {
            out.push_str(&format!("%{:02X}", ch as u32));
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
            Value::Dynamic(template) => HeaderValue::from_str(&template.render(ctx?)).ok(),
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
        body: Template,
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

    pub fn run(self, ctx: Ctx) -> BoxFuture<'static, Response<Body>> {
        Box::pin(self.walk(ctx))
    }

    async fn walk(mut self, mut ctx: Ctx) -> Response<Body> {
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

fn rewrite(ctx: &mut Ctx, to: &Template) {
    let mut target = to.render(ctx);
    // The query: the target's own, or the request's (from a cheap copy of the URI).
    let uri = ctx.req.uri.clone();
    let query = match target.find('?') {
        Some(i) => {
            let query = target[i + 1..].to_string();
            target.truncate(i);
            Some(query)
        }
        None => None,
    };
    if target.is_empty() {
        target = ctx.path().to_string();
    }
    ctx.set_path_and_query(target, query.as_deref().or(uri.query()));
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
    let too_large = ctx
        .req
        .extensions
        .get::<crate::guard::BodyTooLarge>()
        .cloned()
        .unwrap_or_default();
    ctx.req.extensions.insert(too_large.clone());
    ctx.body = Some(crate::body::boxed(crate::guard::LimitedBody::new(body, max, too_large)));
}

fn strip_prefix(ctx: &mut Ctx, prefix: &str) {
    let path = ctx.path().to_string();
    // Compared byte by byte, ASCII case-insensitively: `to_lowercase` may change the byte length of
    // a path with non-ASCII letters, and slicing by the prefix's length would then cut a character.
    let has_prefix = path.len() >= prefix.len()
        && path.is_char_boundary(prefix.len())
        && path.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes());
    if has_prefix {
        let rest = &path[prefix.len()..];
        let stripped = if rest.starts_with('/') {
            rest.to_string()
        } else {
            format!("/{rest}")
        };
        let uri = ctx.req.uri.clone();
        ctx.set_path_and_query(stripped, uri.query());
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
                let location = escape_controls(same_site_location(to.render(&ctx)));
                if *html {
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
                if let Ok(value) = HeaderValue::from_str(&location) {
                    response.headers_mut().insert(LOCATION, value);
                }
                ctx.respond(response)
            }
            Handler::Encode(encode) => {
                ctx.encode = Some(encode.clone());
                let accept = ctx.accept_encoding();
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
                let text = body.render(&ctx);
                let mut response = Response::new(if text.is_empty() { empty() } else { full(text.clone()) });
                *response.status_mut() = status
                    .or(ctx.error.as_ref().map(|e| e.status))
                    .unwrap_or(StatusCode::OK);
                if !text.is_empty() && !ctx.pre_headers.contains_key(CONTENT_TYPE) {
                    let trimmed = text.trim();
                    let json = trimmed.len() > 2
                        && ((trimmed.starts_with('{') && trimmed.ends_with('}'))
                            || (trimmed.starts_with('[') && trimmed.ends_with(']')))
                        && serde_json::from_str::<serde_json::Value>(trimmed).is_ok();
                    let content_type = if json {
                        "application/json"
                    } else {
                        "text/plain; charset=utf-8"
                    };
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
                ctx.fail(*status, Some(message))
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
        });
        let (parts, body) = http::Request::get(path).body(empty()).unwrap().into_parts();
        Ctx::new(conn, parts, body, "127.0.0.1".parse().unwrap())
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
    }
}
