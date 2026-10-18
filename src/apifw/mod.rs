//! OpenAPI request validation at the edge (Cargo feature `api-firewall`; on when
//! `WEB_API_FIREWALL_CONFIG` names its YAML file), after Wallarm API Firewall, built for speed: the
//! spec is compiled once — a router to operations, each with its parameters' readers and its
//! schemas as compiled validators — and a request costs a trie walk and the validators it needs.
//!
//! An API is a spec served under a base path (and hosts). Every request under it must be an
//! operation of the spec — an unknown path or method is a violation — with its parameters and
//! body as the spec says. In `block` mode a violation answers `block_status` (403) with an empty
//! body; in `log_only` it is logged and the request goes on; `off` checks nothing. Modes can be
//! set per operation (`endpoints`).
//!
//! An API bound to upstreams (`upstreams: [app:8787]`) is checked by each `reverse_proxy` sending
//! to one of them, just before the request goes, on the request as it goes there
//! (`check_upstream`, src/proxy.rs); the other APIs before the routes (`check`).
//!
//! What it does differently from Wallarm (see the report in the commit introducing it):
//! - one reading of everything: the body is read once, validated, and exactly those bytes go
//!   upstream; query strings and paths are decoded once, strictly — a broken percent-escape, an
//!   encoded `/`, dot segments or `//` are violations, not guessed at; a parameter that is not an
//!   array may not come twice;
//! - whether a request is under an API is decided on the path as the server's matchers see it
//!   (decoded, cleaned, case-insensitive), so `/API/x` or `/x/../api/y` cannot slip past it;
//! - compressed request bodies are refused (415) rather than inflated; bodies over
//!   `max_body_size` get 413;
//! - nothing fails open: a body type that is declared but not looked into (multipart, binary) is
//!   still checked for its type and size, one that is not declared is a violation.
//!
//! The spec is a file, or a source kept current: a URL, or a path asked of this server's own
//! routes (src/apifw/source.rs). Violations go to the event log (src/eventlog.rs).
//!
//! ```yaml
//! log: {output: /var/log/web/api-firewall.log}   # or stdout / stderr / discard; none: the server's log
//! apis:
//!   - spec: openapi.yaml           # relative to this file; YAML or JSON, OpenAPI 3.0 or 3.1
//!     upstreams: [app:8787]        # checked at the proxy to the app; none: before the routes
//!     # spec: {uri: /api/openapi.json, refresh: 1m, ttl: 24h}   a source (src/apifw/source.rs)
//!     base_path: /api              # the spec's paths are under it
//!     mode: block                  # block | log_only | off
//!     unknown_query_params: block  # block | allow
//!     strict_bodies: false         # true: objects may not carry properties the schema does not name
//!     max_body_size: 1MB
//!     endpoints:
//!       - {method: POST, path: /orders, mode: log_only}
//! ```

mod params;
mod router;
mod source;
mod spec;

pub use source::LocalFetch;

use crate::body::{Body, empty};
use crate::eventlog::{Event, EventLog, LogConfig};
use crate::guard::{BodyTooLarge, LimitedBody, TooLargeError};
use crate::handler::{decode_path, hostport_of, strip_port};
use crate::matcher::{clean_path, host_matches, needs_clean};
use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwapOption;
use bytes::Bytes;
use http::header::{CONTENT_ENCODING, CONTENT_TYPE};
use http::uri::Authority;
use http::{HeaderValue, Method, Response, StatusCode};
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::{Map, Value};
use spec::{BodyFormat, Credential, Location, Operation, Spec};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Block,
    LogOnly,
    Off,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    apis: Vec<ApiConfig>,
    /// Where violations are written (src/eventlog.rs); none: the server's log.
    log: Option<LogConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiConfig {
    spec: source::SpecConfig,
    #[serde(default)]
    base_path: String,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    upstreams: Vec<String>,
    #[serde(default = "block")]
    mode: Mode,
    #[serde(default = "block")]
    unknown_query_params: Mode,
    #[serde(default)]
    strict_bodies: bool,
    max_body_size: Option<String>,
    block_status: Option<u16>,
    #[serde(default)]
    reason_header: bool,
    #[serde(default)]
    pass_options: bool,
    #[serde(default)]
    endpoints: Vec<EndpointConfig>,
}

fn block() -> Mode {
    Mode::Block
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointConfig {
    path: String,
    method: Option<String>,
    mode: Mode,
}

struct Api {
    /// Where the spec comes from, for the log.
    name: String,
    /// Lowercase, without a trailing slash; empty: the whole site.
    base: String,
    hosts: Vec<String>,
    /// Empty: checked before the routes. Else checked by a `reverse_proxy` sending to one of
    /// these, just before the request goes (src/proxy.rs).
    upstreams: Vec<Authority>,
    mode: Mode,
    /// Per-operation modes: method (`None`: any), spec path, mode.
    endpoints: Vec<(Option<Method>, String, Mode)>,
    strict: bool,
    unknown_query: bool,
    max_body: usize,
    block_status: StatusCode,
    reason_header: bool,
    pass_options: bool,
    source: source::Source,
    /// The spec as last compiled; `None` until one is.
    compiled: ArcSwapOption<Compiled>,
    /// Milliseconds since the Unix epoch of the last successful look at the source.
    last_ok: AtomicU64,
    seen: Mutex<source::Seen>,
}

/// A spec compiled, and each of its operations' mode.
struct Compiled {
    spec: Spec,
    modes: Vec<Mode>,
}

/// A request that does not follow the spec.
struct Violation {
    /// Short, for the reason header: `query-parameter:limit`.
    reason: String,
    /// For the log.
    detail: String,
    /// `None`: the API's block status.
    status: Option<StatusCode>,
}

impl Violation {
    fn new(reason: impl Into<String>, detail: impl Into<String>) -> Violation {
        Violation {
            reason: reason.into(),
            detail: detail.into(),
            status: None,
        }
    }

    fn with_status(mut self, status: StatusCode) -> Violation {
        self.status = Some(status);
        self
    }
}

/// The APIs to check requests against.
pub struct ApiFirewall {
    apis: Vec<Arc<Api>>,
    log: EventLog,
}

impl ApiFirewall {
    /// Reads the YAML file at `path` and the specs it names as files (relative to it); specs
    /// from a uri are read once `start` runs.
    pub fn load(path: &Path) -> Result<ApiFirewall> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        ApiFirewall::from_yaml(&text, path.parent().unwrap_or(Path::new(".")))
            .with_context(|| format!("API firewall configuration {}", path.display()))
    }

    pub fn from_yaml(text: &str, base: &Path) -> Result<ApiFirewall> {
        let file: FileConfig = serde_yaml_ng::from_str(text)?;
        let mut apis = Vec::new();
        for config in file.apis {
            let source = source::Source::from_config(&config.spec, base)?;
            let api = api(config, source)?;
            if api.source.read_at_startup() {
                let source::Origin::File(path) = &api.source.origin else {
                    unreachable!("a file")
                };
                let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
                let compiled = api.compile(&bytes, true)?;
                api.install(compiled);
                api.seen.lock().unwrap_or_else(PoisonError::into_inner).digest = Some(*blake3::hash(&bytes).as_bytes());
            }
            apis.push(Arc::new(api));
        }
        Ok(ApiFirewall {
            apis,
            log: EventLog::new("api-firewall", file.log.as_ref(), base),
        })
    }

    /// An API from a spec given as text (tests, tools).
    pub fn from_spec(spec_text: &str, config_yaml: &str) -> Result<ApiFirewall> {
        let config: ApiConfig = serde_yaml_ng::from_str(config_yaml)?;
        let api = api(config, source::Source::inline())?;
        let compiled = api.compile(spec_text.as_bytes(), true)?;
        api.install(compiled);
        Ok(ApiFirewall {
            apis: vec![Arc::new(api)],
            log: EventLog::new("api-firewall", None, Path::new(".")),
        })
    }

    /// APIs, their operations, and APIs whose spec is read once the server runs (for the log).
    pub fn counts(&self) -> (usize, usize, usize) {
        let operations = self
            .apis
            .iter()
            .filter_map(|a| a.compiled.load_full())
            .map(|c| c.spec.operations.len())
            .sum();
        let later = self
            .apis
            .iter()
            .filter(|a| !a.source.read_at_startup() && a.compiled.load().is_none())
            .count();
        (self.apis.len(), operations, later)
    }

    /// Starts keeping the specs current (on the current tokio runtime): those from a uri are read
    /// now, and every source with a `refresh` looked at again that often. `local`: this server's
    /// own routes, for specs given as a path.
    pub fn start(&self, local: Option<LocalFetch>) -> Result<()> {
        let needs_client = self
            .apis
            .iter()
            .any(|a| matches!(a.source.origin, source::Origin::Url(_)));
        let client = if needs_client {
            Some(crate::fetch::client()?)
        } else {
            None
        };
        for api in &self.apis {
            if api.source.refresh.is_some() {
                tokio::spawn(refresh(api.clone(), client.clone(), local.clone()));
            }
        }
        Ok(())
    }

    /// One look at every API's source now (tests, tools).
    pub async fn look_now(&self, local: Option<&LocalFetch>) -> Vec<Result<()>> {
        let client = crate::fetch::client().ok();
        let mut out = Vec::new();
        for api in &self.apis {
            out.push(api.reload(client.as_ref(), local).await);
        }
        out
    }

    /// Whether an API is bound to upstreams (checked by the proxy, `check_upstream`).
    pub fn bound_to_upstreams(&self) -> bool {
        self.apis.iter().any(|a| !a.upstreams.is_empty())
    }

    /// The upstreams APIs are bound to (each must be one a `reverse_proxy` sends to).
    pub fn upstreams(&self) -> impl Iterator<Item = &Authority> {
        self.apis.iter().flat_map(|a| a.upstreams.iter())
    }

    /// Before the routes: checks a request against the first API without `upstreams` it is
    /// under. `Ok` with its body to go on (the same bytes if it was read), or the response to
    /// answer with. A violation is written to the event log (without the values of the query
    /// parameters a JWT check before it named, src/eventlog.rs `HiddenParams`).
    #[allow(clippy::result_large_err)]
    pub async fn check(
        &self,
        parts: &mut http::request::Parts,
        body: Body,
        client_ip: IpAddr,
    ) -> std::result::Result<Body, Response<Body>> {
        match self.api_for(parts, None) {
            Some(api) => self.check_api(api, parts, body, client_ip).await,
            None => Ok(body),
        }
    }

    /// At a `reverse_proxy` about to send the request to one of `upstreams`: checks it, as it
    /// goes there (after any rewrite), against the first API bound to one of them it is under.
    #[allow(clippy::result_large_err)]
    pub async fn check_upstream(
        &self,
        parts: &mut http::request::Parts,
        body: Body,
        client_ip: IpAddr,
        upstreams: &[Authority],
    ) -> std::result::Result<Body, Response<Body>> {
        match self.api_for(parts, Some(upstreams)) {
            Some(api) => self.check_api(api, parts, body, client_ip).await,
            None => Ok(body),
        }
    }

    #[allow(clippy::result_large_err)]
    async fn check_api(
        &self,
        api: &Api,
        parts: &mut http::request::Parts,
        body: Body,
        client_ip: IpAddr,
    ) -> std::result::Result<Body, Response<Body>> {
        if api.mode == Mode::Off && api.endpoints.iter().all(|(_, _, m)| *m == Mode::Off) {
            return Ok(body);
        }
        let (mode, outcome, body) = api.check(parts, body).await;
        let Err(violation) = outcome else {
            return Ok(body);
        };
        let status = violation.status.unwrap_or(api.block_status);
        // A body over the limit or not readable cannot be passed on: refused in any mode.
        let refused = mode == Mode::Block || matches!(status, StatusCode::PAYLOAD_TOO_LARGE | StatusCode::BAD_REQUEST);
        self.log.record(&Event {
            refused,
            status: status.as_u16(),
            client_ip,
            parts,
            reason: &violation.reason,
            detail: &violation.detail,
        });
        if !refused {
            return Ok(body);
        }
        let mut response = Response::new(empty());
        *response.status_mut() = status;
        if api.reason_header
            && let Ok(value) = HeaderValue::from_str(&violation.reason)
        {
            response.headers_mut().insert("apifw-validation-status", value);
        }
        Err(response)
    }

    /// The first API the request is under: before the routes (`at`: `None`) among those without
    /// upstreams, at a proxy among those bound to one of its upstreams.
    fn api_for(&self, parts: &http::request::Parts, at: Option<&[Authority]>) -> Option<&Api> {
        let bound = |api: &Api| match at {
            None => api.upstreams.is_empty(),
            Some(upstreams) => api.upstreams.iter().any(|u| upstreams.contains(u)),
        };
        // Nothing to decode for a request no API of this phase can be for.
        if !self.apis.iter().any(|api| bound(api)) {
            return None;
        }
        let decoded = decode_path(parts.uri.path()).to_lowercase();
        let path = if needs_clean(&decoded) {
            clean_path(&decoded, true)
        } else {
            decoded
        };
        let mut host: Option<String> = None;
        self.apis
            .iter()
            .find(|api| {
                if !bound(api) {
                    return false;
                }
                let under =
                    path.starts_with(&api.base) && matches!(path.as_bytes().get(api.base.len()), None | Some(b'/'));
                if !under {
                    return false;
                }
                if api.hosts.is_empty() {
                    return true;
                }
                let host = host.get_or_insert_with(|| strip_port(hostport_of(parts)).to_ascii_lowercase());
                api.hosts.iter().any(|h| host_matches(h, host))
            })
            .map(|api| &**api)
    }
}

fn api(config: ApiConfig, source: source::Source) -> Result<Api> {
    let base = config.base_path.trim_end_matches('/').to_ascii_lowercase();
    if !base.is_empty() && !base.starts_with('/') {
        bail!("base_path {:?}: starts with /", config.base_path);
    }
    let max_body = match &config.max_body_size {
        Some(text) => crate::config::parse_bytes(text).ok_or_else(|| anyhow!("max_body_size {text:?}"))? as usize,
        None => 1 << 20,
    };
    let block_status = StatusCode::from_u16(config.block_status.unwrap_or(403))
        .map_err(|_| anyhow!("block_status {:?}", config.block_status))?;
    let mut endpoints = Vec::new();
    for endpoint in &config.endpoints {
        let method = match &endpoint.method {
            Some(m) => Some(
                Method::from_bytes(m.to_ascii_uppercase().as_bytes()).map_err(|_| anyhow!("endpoint method {m:?}"))?,
            ),
            None => None,
        };
        endpoints.push((method, endpoint.path.clone(), endpoint.mode));
    }
    let mut upstreams = Vec::new();
    for upstream in &config.upstreams {
        upstreams.push(crate::config::upstream_authority(upstream).map_err(|e| anyhow!("upstream {upstream:?}: {e}"))?);
    }
    Ok(Api {
        name: source.describe(),
        base,
        hosts: config.hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
        upstreams,
        mode: config.mode,
        endpoints,
        strict: config.strict_bodies,
        unknown_query: config.unknown_query_params == Mode::Block,
        max_body,
        block_status,
        reason_header: config.reason_header,
        pass_options: config.pass_options,
        source,
        compiled: ArcSwapOption::empty(),
        last_ok: AtomicU64::new(0),
        seen: Mutex::new(source::Seen::default()),
    })
}

/// Keeps an API's spec current: a look every `refresh`, sooner after a failure (1 s, doubling
/// up to a minute, never later than `refresh`).
async fn refresh(api: Arc<Api>, client: Option<crate::fetch::Client>, local: Option<LocalFetch>) {
    let every = api.source.refresh.unwrap_or(Duration::from_secs(60));
    let mut backoff = Duration::from_secs(1);
    loop {
        let wait = match api.reload(client.as_ref(), local.as_ref()).await {
            Ok(()) => {
                backoff = Duration::from_secs(1);
                every
            }
            Err(e) => {
                tracing::warn!(spec = %api.name, error = %format!("{e:#}"), retry_secs = backoff.min(every).as_secs(), "cannot read the API spec; the last one stays");
                let wait = backoff.min(every);
                backoff = (backoff * 2).min(Duration::from_secs(60));
                wait
            }
        };
        tokio::time::sleep(wait).await;
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

impl Api {
    /// The spec to check against: `None` before one was compiled, or once `ttl` has passed
    /// without a successful look at its source.
    fn current(&self) -> Option<Arc<Compiled>> {
        let compiled = self.compiled.load_full()?;
        if let Some(ttl) = self.source.ttl
            && unix_millis().saturating_sub(self.last_ok.load(Ordering::Acquire)) > ttl.as_millis() as u64
        {
            return None;
        }
        Some(compiled)
    }

    /// Compiles a spec (YAML or JSON); with `strict`, endpoints that name no operation are an
    /// error (at startup), otherwise a warning (a spec read again).
    fn compile(&self, bytes: &[u8], strict: bool) -> Result<Compiled> {
        let text = std::str::from_utf8(bytes).context("the spec is not UTF-8")?;
        let document: Value = if text.trim_start().starts_with('{') {
            serde_json::from_str(text)?
        } else {
            serde_yaml_ng::from_str(text)?
        };
        let spec = spec::compile(document, self.strict).with_context(|| format!("OpenAPI document {}", self.name))?;
        let mut modes = vec![self.mode; spec.operations.len()];
        for (method, path, mode) in &self.endpoints {
            let mut matched = false;
            for (i, op) in spec.operations.iter().enumerate() {
                if op.path == *path && method.as_ref().is_none_or(|m| *m == op.method) {
                    modes[i] = *mode;
                    matched = true;
                }
            }
            if !matched {
                let method = method.as_ref().map_or("*", Method::as_str);
                if strict {
                    bail!("endpoint {method} {path}: no such operation in the spec");
                }
                tracing::warn!(spec = %self.name, endpoint = %format!("{method} {path}"), "endpoint: no such operation in the spec now");
            }
        }
        Ok(Compiled { spec, modes })
    }

    /// Puts a compiled spec in place (requests in flight keep the one they found).
    fn install(&self, compiled: Compiled) {
        tracing::info!(spec = %self.name, base = %self.base, operations = compiled.spec.operations.len(), mode = ?self.mode, "API firewall: spec compiled");
        self.compiled.store(Some(Arc::new(compiled)));
        self.last_ok.store(unix_millis(), Ordering::Release);
    }

    /// One look at the source: a changed spec is compiled (on a blocking thread) and put in
    /// place; an unchanged one only counts as seen.
    async fn reload(self: &Arc<Self>, client: Option<&crate::fetch::Client>, local: Option<&LocalFetch>) -> Result<()> {
        let seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner).now();
        let (bytes, next) = self
            .source
            .look(&seen, client, local, self.hosts.first().map(String::as_str))
            .await?;
        if let Some(bytes) = bytes {
            let digest = *blake3::hash(&bytes).as_bytes();
            if seen.digest != Some(digest) {
                let api = self.clone();
                let compiled = tokio::task::spawn_blocking(move || api.compile(&bytes, false))
                    .await
                    .map_err(|e| anyhow!("{e}"))??;
                self.install(compiled);
            }
            let mut stored = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
            *stored = next;
            stored.digest = Some(digest);
        } else {
            let mut stored = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
            let digest = stored.digest;
            *stored = next;
            stored.digest = digest;
        }
        self.last_ok.store(unix_millis(), Ordering::Release);
        Ok(())
    }

    /// The mode that applies, whether the request follows the spec, and its body.
    async fn check(
        &self,
        parts: &mut http::request::Parts,
        body: Body,
    ) -> (Mode, std::result::Result<(), Violation>, Body) {
        let Some(compiled) = self.current() else {
            let violation = Violation::new("spec:unavailable", "no spec yet, or not read again within its ttl")
                .with_status(StatusCode::SERVICE_UNAVAILABLE);
            return (self.mode, Err(violation), body);
        };
        let raw = parts.uri.path();
        if let Some(problem) = ambiguous(raw) {
            return (self.mode, Err(Violation::new("request-path:ambiguous", problem)), body);
        }
        let Some(decoded) = params::decode_strict(raw) else {
            return (
                self.mode,
                Err(Violation::new("request-path:encoding", "the path does not decode")),
                body,
            );
        };
        // Under the base (compared case-insensitively, as `api_for` decided).
        let rest = match decoded.get(self.base.len()..) {
            Some("") | None => "/",
            Some(rest) => rest,
        };
        if parts.method == Method::OPTIONS && self.pass_options && compiled.spec.router.knows_path(rest) {
            return (Mode::Off, Ok(()), body);
        }
        let found = compiled.spec.router.find(&parts.method, rest).or_else(|| {
            (parts.method == Method::HEAD)
                .then(|| compiled.spec.router.find(&Method::GET, rest))
                .flatten()
        });
        let Some(found) = found else {
            return (
                self.mode,
                Err(Violation::new(
                    "request:unknown-operation",
                    format!("no operation for {} {rest}", parts.method),
                )),
                body,
            );
        };
        let mode = compiled.modes[found.operation];
        if mode == Mode::Off {
            return (mode, Ok(()), body);
        }
        let op = &compiled.spec.operations[found.operation];
        if let Err(violation) = self.check_parameters(op, &found.params, parts) {
            return (mode, Err(violation), body);
        }
        let (outcome, body) = self.check_body(op, parts, body).await;
        (mode, outcome, body)
    }

    fn check_parameters(
        &self,
        op: &Operation,
        path_params: &[(std::sync::Arc<str>, String)],
        parts: &http::request::Parts,
    ) -> std::result::Result<(), Violation> {
        let query = params::query_pairs(parts.uri.query().unwrap_or(""))
            .ok_or_else(|| Violation::new("request-query:encoding", "the query string does not decode"))?;
        let needs_cookies = op.params.iter().any(|p| p.location == Location::Cookie)
            || op.security.iter().flatten().any(|c| matches!(c, Credential::Cookie(_)));
        let cookies = if needs_cookies {
            params::cookies(&parts.headers)
        } else {
            Vec::new()
        };
        for p in &op.params {
            let place = match p.location {
                Location::Path => "path",
                Location::Query => "query",
                Location::Header => "header",
                Location::Cookie => "cookie",
            };
            let reason = || format!("request-parameter:{place}:{}", p.name);
            let joined;
            let values: Vec<&str> = match p.location {
                Location::Path => path_params
                    .iter()
                    .filter(|(n, _)| **n == *p.name)
                    .map(|(_, v)| v.as_str())
                    .collect(),
                Location::Query => query
                    .iter()
                    .filter(|(k, _)| *k == p.name)
                    .map(|(_, v)| v.as_str())
                    .collect(),
                Location::Header => {
                    let mut all = Vec::new();
                    for value in parts.headers.get_all(p.name.as_str()) {
                        all.push(
                            value
                                .to_str()
                                .map_err(|_| Violation::new(reason(), "not visible ASCII"))?,
                        );
                    }
                    if all.is_empty() {
                        Vec::new()
                    } else {
                        joined = all.join(",");
                        vec![joined.as_str()]
                    }
                }
                Location::Cookie => cookies
                    .iter()
                    .filter(|(k, _)| *k == p.name)
                    .map(|(_, v)| v.as_str())
                    .collect(),
            };
            if values.is_empty() {
                if p.required {
                    return Err(Violation::new(reason(), "missing"));
                }
                continue;
            }
            let Some(validator) = &p.validator else { continue };
            let value = if p.json {
                if values.len() > 1 {
                    return Err(Violation::new(reason(), "given more than once"));
                }
                serde_json::from_str::<Value>(values[0]).map_err(|_| Violation::new(reason(), "not JSON"))?
            } else if p.kind.is_array() {
                let items: Vec<&str> = if p.repeated {
                    values
                } else {
                    if values.len() > 1 {
                        return Err(Violation::new(reason(), "given more than once"));
                    }
                    values[0].split(p.separator).collect()
                };
                p.kind
                    .read_all(items.into_iter())
                    .ok_or_else(|| Violation::new(reason(), "an item is not of its type"))?
            } else {
                if values.len() > 1 {
                    return Err(Violation::new(reason(), "given more than once"));
                }
                let raw = values[0];
                if raw.is_empty() && p.location == Location::Query && !p.allow_empty {
                    return Err(Violation::new(reason(), "empty"));
                }
                p.kind
                    .read(raw)
                    .ok_or_else(|| Violation::new(reason(), "not of its type"))?
            };
            if let Err(error) = validator.validate(&value) {
                return Err(Violation::new(reason(), schema_error(&error)));
            }
        }
        if self.unknown_query {
            for (key, _) in &query {
                let declared = op.params.iter().any(|p| {
                    p.location == Location::Query
                        && (p.name == *key || key.strip_prefix(p.name.as_str()).is_some_and(|r| r.starts_with('[')))
                });
                if !declared {
                    return Err(Violation::new(format!("request-parameter:query:{key}"), "not declared"));
                }
            }
        }
        if !op.security.is_empty() {
            let present = |c: &Credential| match c {
                Credential::Header(name, prefix) => parts.headers.get_all(name).iter().any(|v| {
                    v.to_str().is_ok_and(|s| match prefix {
                        Some(p) => s.len() > p.len() && s[..p.len()].eq_ignore_ascii_case(p),
                        None => !s.is_empty(),
                    })
                }),
                Credential::Query(name) => query.iter().any(|(k, v)| k == name && !v.is_empty()),
                Credential::Cookie(name) => cookies.iter().any(|(k, v)| k == name && !v.is_empty()),
                Credential::Unverifiable => true,
            };
            if !op.security.iter().any(|all| all.iter().all(present)) {
                return Err(Violation::new(
                    "security-requirements:missing",
                    "no credentials the operation asks for",
                ));
            }
        }
        Ok(())
    }

    async fn check_body(
        &self,
        op: &Operation,
        parts: &mut http::request::Parts,
        body: Body,
    ) -> (std::result::Result<(), Violation>, Body) {
        let Some(declared) = &op.body else {
            return (Ok(()), body);
        };
        let empty_body = http_body::Body::is_end_stream(&body);
        if empty_body {
            if declared.required {
                return (Err(Violation::new("request-body:missing", "required")), body);
            }
            return (Ok(()), body);
        }
        let media_type = parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(|v| v.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let Some(media) = declared.find(&media_type) else {
            return (
                Err(Violation::new(
                    format!("request-body:content-type:{media_type}"),
                    "not declared for the operation",
                )),
                body,
            );
        };
        if parts
            .headers
            .get_all(CONTENT_ENCODING)
            .iter()
            .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
        {
            return (
                Err(Violation::new(
                    "request-body:content-encoding",
                    "compressed request bodies are not taken",
                )
                .with_status(StatusCode::UNSUPPORTED_MEDIA_TYPE)),
                body,
            );
        }
        if media.format == BodyFormat::Unchecked {
            // Not read here: passed on under the size limit (the proxy answers 413 past it).
            let too_large = parts.extensions.get::<BodyTooLarge>().cloned().unwrap_or_default();
            parts.extensions.insert(too_large.clone());
            let limited = LimitedBody::new(body, self.max_body as u64, too_large.clone());
            if too_large.happened() {
                return (
                    Err(Violation::new("request-body:too-large", "over max_body_size")
                        .with_status(StatusCode::PAYLOAD_TOO_LARGE)),
                    crate::body::empty(),
                );
            }
            return (Ok(()), crate::body::boxed(limited));
        }
        let bytes = match read_body(body, self.max_body).await {
            Ok(bytes) => bytes,
            Err(violation) => return (Err(violation), crate::body::empty()),
        };
        let outcome = validate_body(media, &bytes);
        (outcome, crate::body::full(bytes))
    }
}

/// The whole body, at most `max` bytes (frame by frame: no adapter whose error conversions would
/// keep the request's future from being `Send`).
async fn read_body(mut body: Body, max: usize) -> std::result::Result<Bytes, Violation> {
    let too_large =
        || Violation::new("request-body:too-large", "over max_body_size").with_status(StatusCode::PAYLOAD_TOO_LARGE);
    let hint = http_body::Body::size_hint(&body);
    if hint.lower() > max as u64 {
        return Err(too_large());
    }
    let mut collected = bytes::BytesMut::with_capacity(hint.exact().map_or(0, |n| n as usize));
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    if collected.len() + data.len() > max {
                        return Err(too_large());
                    }
                    collected.extend_from_slice(&data);
                }
            }
            Err(error) => {
                if error.downcast_ref::<TooLargeError>().is_some() {
                    return Err(too_large());
                }
                return Err(
                    Violation::new("request-body:unread", error.to_string()).with_status(StatusCode::BAD_REQUEST)
                );
            }
        }
    }
    Ok(collected.freeze())
}

fn validate_body(media: &spec::Media, bytes: &Bytes) -> std::result::Result<(), Violation> {
    let reason = || format!("request-body:{}", media.range);
    let value = match media.format {
        BodyFormat::Json => serde_json::from_slice::<Value>(bytes).map_err(|_| Violation::new(reason(), "not JSON"))?,
        BodyFormat::Text => Value::String(
            std::str::from_utf8(bytes)
                .map_err(|_| Violation::new(reason(), "not UTF-8"))?
                .to_string(),
        ),
        BodyFormat::Form => {
            let text = std::str::from_utf8(bytes).map_err(|_| Violation::new(reason(), "not UTF-8"))?;
            let pairs = params::query_pairs(text).ok_or_else(|| Violation::new(reason(), "does not decode"))?;
            let mut object = Map::new();
            for (name, raw) in pairs {
                let kind = media.fields.iter().find(|(n, _)| *n == name).map(|(_, k)| k);
                match kind {
                    Some(kind) if kind.is_array() => {
                        let item = kind
                            .read_all(std::iter::once(raw.as_str()))
                            .and_then(|v| v.as_array().and_then(|a| a.first().cloned()))
                            .ok_or_else(|| Violation::new(reason(), format!("field {name}: not of its type")))?;
                        match object.entry(name).or_insert_with(|| Value::Array(Vec::new())) {
                            Value::Array(items) => items.push(item),
                            _ => unreachable!("arrays only"),
                        }
                    }
                    _ => {
                        if object.contains_key(&name) {
                            return Err(Violation::new(reason(), format!("field {name}: given more than once")));
                        }
                        let value = match kind {
                            Some(kind) => kind
                                .read(&raw)
                                .ok_or_else(|| Violation::new(reason(), format!("field {name}: not of its type")))?,
                            None => Value::String(raw),
                        };
                        object.insert(name, value);
                    }
                }
            }
            Value::Object(object)
        }
        BodyFormat::Unchecked => return Ok(()),
    };
    match &media.validator {
        Some(validator) => validator
            .validate(&value)
            .map_err(|error| Violation::new(reason(), schema_error(&error))),
        None => Ok(()),
    }
}

/// A schema error without the value it is about, which may be a password or personal data and
/// goes to the event log: where in the request, and the keyword that failed (with the property
/// names an object may not carry, a few and cut short).
fn schema_error(error: &jsonschema::ValidationError<'_>) -> String {
    let at = match error.instance_path().as_str() {
        "" => "/",
        path => path,
    };
    let keyword = error.kind().keyword();
    match error.kind() {
        jsonschema::error::ValidationErrorKind::AdditionalProperties { unexpected }
        | jsonschema::error::ValidationErrorKind::UnevaluatedProperties { unexpected } => {
            let names: Vec<String> = unexpected
                .iter()
                .take(5)
                .map(|n| n.chars().take(40).collect())
                .collect();
            format!("{at}: {keyword}: {}", names.join(", "))
        }
        _ => format!("{at}: {keyword}"),
    }
}

/// Why a raw path is ambiguous — read one way here and maybe another upstream — if it is.
fn ambiguous(raw: &str) -> Option<&'static str> {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return Some("an encoded / or \\");
    }
    if raw.contains("//") {
        return Some("an empty path segment");
    }
    let dot = |s: &str| {
        s == "."
            || s == ".."
            || s.eq_ignore_ascii_case("%2e")
            || s.eq_ignore_ascii_case("%2e%2e")
            || s.eq_ignore_ascii_case(".%2e")
            || s.eq_ignore_ascii_case("%2e.")
    };
    if raw.split('/').any(dot) {
        return Some("a dot segment");
    }
    None
}

#[cfg(test)]
mod tests;

impl crate::extensions::RequestCheck for ApiFirewall {
    async fn check(
        &self,
        req: &mut http::request::Parts,
        body: Body,
        client: crate::extensions::Client<'_>,
    ) -> crate::extensions::Checked {
        ApiFirewall::check(self, req, body, client.ip).await
    }
}

impl crate::extensions::UpstreamCheck for ApiFirewall {
    type Held = ();

    async fn check(
        &self,
        req: &mut http::request::Parts,
        body: Body,
        client: crate::extensions::Client<'_>,
        upstreams: &[Authority],
    ) -> std::result::Result<(Body, ()), Response<Body>> {
        self.check_upstream(req, body, client.ip, upstreams).await.map(|body| (body, ()))
    }

    fn bound(&self) -> bool {
        self.bound_to_upstreams()
    }

    fn upstreams(&self, out: &mut Vec<(Authority, &'static str)>) {
        out.extend(ApiFirewall::upstreams(self).map(|u| (u.clone(), "API firewall")));
    }
}
