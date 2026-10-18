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
//! ```yaml
//! apis:
//!   - spec: openapi.yaml           # relative to this file; YAML or JSON, OpenAPI 3.0 or 3.1
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
mod spec;

use crate::body::{Body, empty};
use crate::guard::{BodyTooLarge, LimitedBody, TooLargeError};
use crate::handler::{decode_path, hostport_of, strip_port};
use crate::matcher::{clean_path, host_matches, needs_clean};
use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use http::header::{CONTENT_ENCODING, CONTENT_TYPE};
use http::{HeaderValue, Method, Response, StatusCode};
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::{Map, Value};
use spec::{BodyFormat, Credential, Location, Operation, Spec};
use std::path::Path;

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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiConfig {
    spec: String,
    #[serde(default)]
    base_path: String,
    #[serde(default)]
    hosts: Vec<String>,
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
    /// The spec's file, for the log.
    name: String,
    /// Lowercase, without a trailing slash; empty: the whole site.
    base: String,
    hosts: Vec<String>,
    spec: Spec,
    mode: Mode,
    /// Each operation's mode.
    modes: Vec<Mode>,
    unknown_query: bool,
    max_body: usize,
    block_status: StatusCode,
    reason_header: bool,
    pass_options: bool,
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
    apis: Vec<Api>,
}

impl ApiFirewall {
    /// Reads the YAML file at `path` and compiles the specs it names (relative to it).
    pub fn load(path: &Path) -> Result<ApiFirewall> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        ApiFirewall::from_yaml(&text, path.parent().unwrap_or(Path::new(".")))
            .with_context(|| format!("API firewall configuration {}", path.display()))
    }

    pub fn from_yaml(text: &str, base: &Path) -> Result<ApiFirewall> {
        let file: FileConfig = serde_yaml_ng::from_str(text)?;
        let mut apis = Vec::new();
        for config in file.apis {
            let path = base.join(&config.spec);
            let spec = spec::load(&path, config.strict_bodies)?;
            apis.push(api(config, spec, path.display().to_string())?);
        }
        Ok(ApiFirewall { apis })
    }

    /// An API from a spec given as text (tests, tools).
    pub fn from_spec(spec_text: &str, config_yaml: &str) -> Result<ApiFirewall> {
        let config: ApiConfig = serde_yaml_ng::from_str(config_yaml)?;
        let document: Value = serde_yaml_ng::from_str(spec_text)?;
        let spec = spec::compile(document, config.strict_bodies)?;
        Ok(ApiFirewall {
            apis: vec![api(config, spec, "inline".into())?],
        })
    }

    /// APIs and their operations (for the startup log).
    pub fn counts(&self) -> (usize, usize) {
        (self.apis.len(), self.apis.iter().map(|a| a.spec.operations.len()).sum())
    }

    /// Checks a request: `Ok` with its body to go on (the same bytes if it was read), or the
    /// response to answer with.
    #[allow(clippy::result_large_err)]
    pub async fn check(
        &self,
        parts: &mut http::request::Parts,
        body: Body,
    ) -> std::result::Result<Body, Response<Body>> {
        let Some(api) = self.api_for(parts) else {
            return Ok(body);
        };
        if api.mode == Mode::Off && api.modes.iter().all(|m| *m == Mode::Off) {
            return Ok(body);
        }
        let (mode, outcome, body) = api.check(parts, body).await;
        match outcome {
            Ok(()) => Ok(body),
            Err(violation) => {
                let status = violation.status.unwrap_or(api.block_status);
                // A body over the limit or not readable cannot be passed on: refused in any mode.
                if mode == Mode::Block || matches!(status, StatusCode::PAYLOAD_TOO_LARGE | StatusCode::BAD_REQUEST) {
                    tracing::info!(
                        api = %api.name,
                        method = %parts.method,
                        path = %parts.uri.path(),
                        reason = %violation.reason,
                        detail = %violation.detail,
                        status = status.as_u16(),
                        "request refused by the API firewall"
                    );
                    let mut response = Response::new(empty());
                    *response.status_mut() = status;
                    if api.reason_header
                        && let Ok(value) = HeaderValue::from_str(&violation.reason)
                    {
                        response.headers_mut().insert("apifw-validation-status", value);
                    }
                    return Err(response);
                }
                tracing::warn!(
                    api = %api.name,
                    method = %parts.method,
                    path = %parts.uri.path(),
                    reason = %violation.reason,
                    detail = %violation.detail,
                    "request does not follow the API spec (log_only)"
                );
                Ok(body)
            }
        }
    }

    fn api_for(&self, parts: &http::request::Parts) -> Option<&Api> {
        let decoded = decode_path(parts.uri.path()).to_lowercase();
        let path = if needs_clean(&decoded) {
            clean_path(&decoded, true)
        } else {
            decoded
        };
        let mut host: Option<String> = None;
        self.apis.iter().find(|api| {
            let under = path.starts_with(&api.base) && matches!(path.as_bytes().get(api.base.len()), None | Some(b'/'));
            if !under {
                return false;
            }
            if api.hosts.is_empty() {
                return true;
            }
            let host = host.get_or_insert_with(|| strip_port(hostport_of(parts)).to_ascii_lowercase());
            api.hosts.iter().any(|h| host_matches(h, host))
        })
    }
}

fn api(config: ApiConfig, spec: Spec, name: String) -> Result<Api> {
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
    let mut modes = vec![config.mode; spec.operations.len()];
    for endpoint in &config.endpoints {
        let method = match &endpoint.method {
            Some(m) => Some(
                Method::from_bytes(m.to_ascii_uppercase().as_bytes()).map_err(|_| anyhow!("endpoint method {m:?}"))?,
            ),
            None => None,
        };
        let mut matched = false;
        for (i, op) in spec.operations.iter().enumerate() {
            if op.path == endpoint.path && method.as_ref().is_none_or(|m| *m == op.method) {
                modes[i] = endpoint.mode;
                matched = true;
            }
        }
        if !matched {
            bail!(
                "endpoint {} {}: no such operation in the spec",
                endpoint.method.as_deref().unwrap_or("*"),
                endpoint.path
            );
        }
    }
    tracing::info!(spec = %name, base = %base, operations = spec.operations.len(), mode = ?config.mode, "API firewall: spec compiled");
    Ok(Api {
        name,
        base,
        hosts: config.hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
        spec,
        mode: config.mode,
        modes,
        unknown_query: config.unknown_query_params == Mode::Block,
        max_body,
        block_status,
        reason_header: config.reason_header,
        pass_options: config.pass_options,
    })
}

impl Api {
    /// The mode that applies, whether the request follows the spec, and its body.
    async fn check(
        &self,
        parts: &mut http::request::Parts,
        body: Body,
    ) -> (Mode, std::result::Result<(), Violation>, Body) {
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
        if parts.method == Method::OPTIONS && self.pass_options && self.spec.router.knows_path(rest) {
            return (Mode::Off, Ok(()), body);
        }
        let found = self.spec.router.find(&parts.method, rest).or_else(|| {
            (parts.method == Method::HEAD)
                .then(|| self.spec.router.find(&Method::GET, rest))
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
        let mode = self.modes[found.operation];
        if mode == Mode::Off {
            return (mode, Ok(()), body);
        }
        let op = &self.spec.operations[found.operation];
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
                return Err(Violation::new(reason(), error.to_string()));
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
            .map_err(|error| Violation::new(reason(), error.to_string())),
        None => Ok(()),
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
