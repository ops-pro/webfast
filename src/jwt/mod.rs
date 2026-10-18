//! JWT validation at the edge (Cargo feature `jwt`; on when `WEB_JWT_CONFIG` names its YAML file),
//! after Istio's RequestAuthentication and Envoy's jwt_authn: providers (an issuer, its keys, where
//! the token is and what of it goes upstream) and rules (which requests need a token from which
//! providers). A request no rule matches is not looked at.
//!
//! What a request costs: matching the rules (path, method, host); with a token, a BLAKE3 hash and
//! a lookup in the verified-token cache — a token seen before is not decoded or verified again,
//! its claims' headers are kept ready. A new token: base64url, JSON, one signature check with a key
//! parsed when the keys were loaded. Keys are read in the background (src/jwt/jwks.rs).
//!
//! Like Istio, a rule with `allow_missing` lets requests without a token through (and checks those
//! that have one); without it a token is required. The headers claims are written to are taken
//! off every request first, so a client cannot send them itself.
//!
//! ```yaml
//! providers:
//!   keycloak:
//!     issuer: https://id.example.com/realms/main
//!     audiences: [api]
//!     jwks_uri: https://id.example.com/realms/main/protocol/openid-connect/certs
//!     output_claim_to_headers: [{header: X-User, claim: sub}]
//! rules:
//!   - match: {paths: ["/api/public/*"]}      # no providers: not checked
//!   - match: {paths: ["/api/*"]}
//!     providers: [keycloak]
//! ```

mod cache;
mod jwks;
mod token;

pub use jwks::{Alg, KeySet};

use crate::body::{Body, full};
use crate::handler::{decode_path, hostport_of, strip_port};
use crate::matcher::{PathPattern, clean_path, host_matches, needs_clean};
use anyhow::{Context, Result, anyhow, bail};
use http::header::{CONTENT_TYPE, COOKIE, WWW_AUTHENTICATE};
use http::{HeaderName, HeaderValue, Method, Response, StatusCode};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Tokens longer than this are refused unread.
const MAX_TOKEN: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    providers: BTreeMap<String, ProviderConfig>,
    #[serde(default)]
    rules: Vec<RuleConfig>,
    #[serde(default)]
    cache: CacheConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderConfig {
    issuer: String,
    #[serde(default)]
    audiences: Vec<String>,
    jwks_uri: Option<String>,
    jwks: Option<String>,
    jwks_file: Option<PathBuf>,
    #[serde(default)]
    from_headers: Vec<HeaderSource>,
    #[serde(default)]
    from_params: Vec<String>,
    #[serde(default)]
    from_cookies: Vec<String>,
    #[serde(default)]
    forward_original_token: bool,
    output_payload_to_header: Option<String>,
    #[serde(default)]
    output_claim_to_headers: Vec<ClaimHeader>,
    clock_skew: Option<String>,
    #[serde(default = "yes")]
    require_expiration: bool,
    max_lifetime: Option<String>,
    jwks_cache_duration: Option<String>,
    jwks_fetch_timeout: Option<String>,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderSource {
    name: String,
    #[serde(default)]
    prefix: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimHeader {
    header: String,
    claim: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleConfig {
    #[serde(default, rename = "match")]
    matcher: MatchConfig,
    #[serde(default)]
    providers: Vec<String>,
    #[serde(default)]
    allow_missing: bool,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct MatchConfig {
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    hosts: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheConfig {
    #[serde(default = "default_tokens")]
    tokens: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            tokens: default_tokens(),
        }
    }
}

fn default_tokens() -> usize {
    10_000
}

/// Where a provider's tokens are.
enum Source {
    Header { name: HeaderName, prefix: String },
    Param(String),
    Cookie(String),
}

struct Provider {
    issuer: String,
    audiences: Vec<String>,
    sources: Vec<Source>,
    forward: bool,
    payload_header: Option<HeaderName>,
    claim_headers: Vec<(HeaderName, Vec<String>)>,
    skew: u64,
    require_expiration: bool,
    max_lifetime: Option<u64>,
    keys: Arc<jwks::Keys>,
}

struct Rule {
    paths: Vec<PathPattern>,
    methods: Vec<Method>,
    hosts: Vec<String>,
    /// Indexes into `providers`; empty: requests matched are not checked.
    providers: Vec<usize>,
    allow_missing: bool,
}

/// A token found valid, and what it adds to the request.
struct Verified {
    provider: usize,
    /// The provider's key generation it was verified with.
    generation: u64,
    exp: Option<u64>,
    nbf: Option<u64>,
    headers: Vec<(HeaderName, HeaderValue)>,
}

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Missing,
    Malformed,
    UnknownIssuer,
    UnsupportedAlgorithm,
    UnknownKey,
    BadSignature,
    NoExpiration,
    Expired,
    NotYetValid,
    LifetimeTooLong,
    Audience,
}

impl Failure {
    /// Status and message as Envoy's jwt_authn gives them.
    fn answer(self) -> (StatusCode, &'static str) {
        match self {
            Failure::Missing => (StatusCode::UNAUTHORIZED, "Jwt is missing"),
            Failure::Expired => (StatusCode::UNAUTHORIZED, "Jwt is expired"),
            Failure::NotYetValid => (StatusCode::UNAUTHORIZED, "Jwt not yet valid"),
            Failure::UnknownIssuer => (StatusCode::UNAUTHORIZED, "Jwt issuer is not configured"),
            Failure::Audience => (StatusCode::FORBIDDEN, "Audiences in Jwt are not allowed"),
            _ => (StatusCode::UNAUTHORIZED, "Jwt verification fails"),
        }
    }
}

/// The configured providers and rules, and the verified-token cache.
pub struct JwtAuth {
    providers: Vec<Provider>,
    rules: Vec<Rule>,
    /// Request headers that only a verified token may set.
    reserved: Vec<HeaderName>,
    cache: cache::TokenCache<Verified>,
}

impl JwtAuth {
    /// Reads the YAML file at `path` (`jwks_file`s are relative to it) and loads the inline and
    /// file keys; keys from a `jwks_uri` are read once `start` runs.
    pub fn load(path: &Path) -> Result<JwtAuth> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        JwtAuth::from_yaml(&text, path.parent().unwrap_or(Path::new(".")))
            .with_context(|| format!("JWT configuration {}", path.display()))
    }

    pub fn from_yaml(text: &str, base: &Path) -> Result<JwtAuth> {
        let file: FileConfig = serde_yaml_ng::from_str(text)?;
        let names: Vec<&String> = file.providers.keys().collect();
        let mut providers = Vec::new();
        for (name, config) in &file.providers {
            providers.push(provider(name, config, base).with_context(|| format!("provider {name}"))?);
        }
        let mut rules = Vec::new();
        for (i, rule) in file.rules.iter().enumerate() {
            let mut indexes = Vec::new();
            for name in &rule.providers {
                let index = names
                    .iter()
                    .position(|n| *n == name)
                    .ok_or_else(|| anyhow!("rule {}: no provider {name:?}", i + 1))?;
                indexes.push(index);
            }
            let mut methods = Vec::new();
            for method in &rule.matcher.methods {
                methods.push(
                    Method::from_bytes(method.to_ascii_uppercase().as_bytes())
                        .map_err(|_| anyhow!("rule {}: invalid method {method:?}", i + 1))?,
                );
            }
            rules.push(Rule {
                paths: rule.matcher.paths.iter().map(|p| PathPattern::new(p)).collect(),
                methods,
                hosts: rule.matcher.hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
                providers: indexes,
                allow_missing: rule.allow_missing,
            });
        }
        let mut reserved: Vec<HeaderName> = Vec::new();
        for p in &providers {
            for name in p.payload_header.iter().chain(p.claim_headers.iter().map(|(h, _)| h)) {
                if !reserved.contains(name) {
                    reserved.push(name.clone());
                }
            }
        }
        Ok(JwtAuth {
            providers,
            rules,
            reserved,
            cache: cache::TokenCache::new(file.cache.tokens),
        })
    }

    /// Starts reading the keys of the providers that have a `jwks_uri` or `jwks_file` (on the
    /// current tokio runtime), first and then every `jwks_cache_duration`.
    pub fn start(&self) -> Result<()> {
        let client = jwks::client()?;
        for provider in &self.providers {
            if provider.keys.refreshed() {
                tokio::spawn(jwks::refresh(provider.keys.clone(), client.clone()));
            }
        }
        Ok(())
    }

    /// Providers, rules (for the startup log).
    pub fn counts(&self) -> (usize, usize) {
        (self.providers.len(), self.rules.len())
    }

    /// Checks the request: `Ok` to go on (with the claims' headers set, the token taken off unless
    /// forwarded), or the 401 / 403 to answer with. (A refusal is the rare way out: the response
    /// is returned as it is rather than boxed for every request.)
    #[allow(clippy::result_large_err)]
    pub async fn check(&self, parts: &mut http::request::Parts) -> std::result::Result<(), Response<Body>> {
        for name in &self.reserved {
            parts.headers.remove(name);
        }
        let Some(rule) = self.rule_for(parts) else {
            return Ok(());
        };
        if rule.providers.is_empty() {
            return Ok(());
        }
        let Some((token, header)) = self.extract(rule, parts) else {
            if rule.allow_missing {
                return Ok(());
            }
            return Err(refusal(Failure::Missing));
        };
        let now = unix_now();
        let key = cache::digest(token.as_bytes());
        let verified = match self.cache.get(&key) {
            Some(verified) if self.still_valid(&verified, rule, now) => verified,
            _ => match self.verify(&token, rule, now).await {
                Ok(verified) => {
                    let verified = Arc::new(verified);
                    self.cache.insert(key, verified.clone());
                    verified
                }
                Err(failure) => {
                    tracing::debug!(?failure, "JWT refused");
                    return Err(refusal(failure));
                }
            },
        };
        if !self.providers[verified.provider].forward
            && let Some(header) = header
        {
            parts.headers.remove(header);
        }
        for (name, value) in &verified.headers {
            parts.headers.insert(name.clone(), value.clone());
        }
        Ok(())
    }

    fn rule_for(&self, parts: &http::request::Parts) -> Option<&Rule> {
        let mut path: Option<String> = None;
        let mut host: Option<String> = None;
        self.rules.iter().find(|rule| {
            if !rule.methods.is_empty() && !rule.methods.contains(&parts.method) {
                return false;
            }
            if !rule.hosts.is_empty() {
                let host = host.get_or_insert_with(|| strip_port(hostport_of(parts)).to_ascii_lowercase());
                if !rule.hosts.iter().any(|h| host_matches(h, host)) {
                    return false;
                }
            }
            if !rule.paths.is_empty() {
                let path = path.get_or_insert_with(|| {
                    let decoded = decode_path(parts.uri.path()).to_lowercase();
                    if needs_clean(&decoded) {
                        clean_path(&decoded, true)
                    } else {
                        decoded
                    }
                });
                if !rule.paths.iter().any(|p| p.matches_path(path)) {
                    return false;
                }
            }
            true
        })
    }

    /// The first token found where the rule's providers look; with the header it came in.
    fn extract<'a>(&'a self, rule: &Rule, parts: &http::request::Parts) -> Option<(String, Option<&'a HeaderName>)> {
        for &index in &rule.providers {
            for source in &self.providers[index].sources {
                match source {
                    Source::Header { name, prefix } => {
                        for value in parts.headers.get_all(name) {
                            let Ok(value) = value.to_str() else { continue };
                            let value = value.trim();
                            if value.len() > prefix.len() && value[..prefix.len()].eq_ignore_ascii_case(prefix) {
                                let token = value[prefix.len()..].trim();
                                if !token.is_empty() {
                                    return Some((token.to_string(), Some(name)));
                                }
                            }
                        }
                    }
                    Source::Param(name) => {
                        if let Some(token) = query_param(parts.uri.query().unwrap_or(""), name) {
                            return Some((token, None));
                        }
                    }
                    Source::Cookie(name) => {
                        if let Some(token) = cookie(parts, name) {
                            return Some((token, None));
                        }
                    }
                }
            }
        }
        None
    }

    fn still_valid(&self, verified: &Verified, rule: &Rule, now: u64) -> bool {
        let provider = &self.providers[verified.provider];
        rule.providers.contains(&verified.provider)
            && verified.generation == provider.keys.generation()
            && verified.exp.is_none_or(|exp| now <= exp.saturating_add(provider.skew))
            && verified.nbf.is_none_or(|nbf| nbf <= now.saturating_add(provider.skew))
    }

    async fn verify(&self, token: &str, rule: &Rule, now: u64) -> std::result::Result<Verified, Failure> {
        if token.len() > MAX_TOKEN {
            return Err(Failure::Malformed);
        }
        let parsed = token::Parsed::new(token).ok_or(Failure::Malformed)?;
        let issuer = parsed
            .claims
            .get("iss")
            .and_then(Value::as_str)
            .ok_or(Failure::UnknownIssuer)?;
        let index = rule
            .providers
            .iter()
            .copied()
            .find(|&i| self.providers[i].issuer == issuer)
            .ok_or(Failure::UnknownIssuer)?;
        let provider = &self.providers[index];
        let alg = parsed.alg.ok_or(Failure::UnsupportedAlgorithm)?;
        let mut generation = provider.keys.generation();
        let check = |keys: &KeySet| keys.verify(parsed.kid.as_deref(), alg, parsed.signing_input, &parsed.signature);
        let mut checked = check(&provider.keys.current());
        if checked == jwks::Checked::NoKey && provider.keys.read_again().await {
            generation = provider.keys.generation();
            checked = check(&provider.keys.current());
        }
        match checked {
            jwks::Checked::Valid => {}
            jwks::Checked::NoKey => return Err(Failure::UnknownKey),
            jwks::Checked::BadSignature => return Err(Failure::BadSignature),
        }
        let claims = &parsed.claims;
        let exp = time_claim(claims, "exp")?;
        let nbf = time_claim(claims, "nbf")?;
        let iat = time_claim(claims, "iat")?;
        match exp {
            None if provider.require_expiration => return Err(Failure::NoExpiration),
            Some(exp) if now > exp.saturating_add(provider.skew) => return Err(Failure::Expired),
            _ => {}
        }
        if nbf.is_some_and(|nbf| nbf > now.saturating_add(provider.skew)) {
            return Err(Failure::NotYetValid);
        }
        if let Some(max) = provider.max_lifetime {
            let (Some(iat), Some(exp)) = (iat, exp) else {
                return Err(Failure::LifetimeTooLong);
            };
            if exp.saturating_sub(iat) > max {
                return Err(Failure::LifetimeTooLong);
            }
        }
        if !provider.audiences.is_empty() {
            let fits = |aud: &Value| aud.as_str().is_some_and(|a| provider.audiences.iter().any(|w| w == a));
            let ok = match claims.get("aud") {
                Some(Value::Array(list)) => list.iter().any(fits),
                Some(aud) => fits(aud),
                None => false,
            };
            if !ok {
                return Err(Failure::Audience);
            }
        }
        let mut headers = Vec::new();
        if let Some(name) = &provider.payload_header
            && let Ok(value) = HeaderValue::from_str(parsed.payload)
        {
            headers.push((name.clone(), value));
        }
        for (name, path) in &provider.claim_headers {
            if let Some(value) = claim_value(claims, path)
                && let Ok(value) = HeaderValue::from_str(&value)
            {
                headers.push((name.clone(), value));
            }
        }
        Ok(Verified {
            provider: index,
            generation,
            exp,
            nbf,
            headers,
        })
    }
}

fn provider(name: &str, config: &ProviderConfig, base: &Path) -> Result<Provider> {
    if config.issuer.is_empty() {
        bail!("issuer is empty");
    }
    let duration = |value: &Option<String>, default: Duration, what: &str| -> Result<Duration> {
        match value {
            Some(text) => crate::config::parse_duration(text).map_err(|e| anyhow!("{what}: {e}")),
            None => Ok(default),
        }
    };
    let skew = duration(&config.clock_skew, Duration::from_secs(60), "clock_skew")?;
    let max_lifetime = match &config.max_lifetime {
        Some(_) => Some(duration(&config.max_lifetime, Duration::ZERO, "max_lifetime")?.as_secs()),
        None => None,
    };
    let cache_duration = duration(
        &config.jwks_cache_duration,
        Duration::from_secs(600),
        "jwks_cache_duration",
    )?;
    let fetch_timeout = duration(&config.jwks_fetch_timeout, Duration::from_secs(5), "jwks_fetch_timeout")?;
    let (source, set) = match (&config.jwks_uri, &config.jwks, &config.jwks_file) {
        (Some(uri), None, None) => {
            let uri: http::Uri = uri.parse().map_err(|e| anyhow!("jwks_uri: {e}"))?;
            if !matches!(uri.scheme_str(), Some("https" | "http")) || uri.host().is_none() {
                bail!("jwks_uri: an http(s) URL");
            }
            (jwks::Source::Uri(uri), KeySet::default())
        }
        (None, Some(inline), None) => (jwks::Source::Inline, KeySet::parse(inline.as_bytes()).context("jwks")?),
        (None, None, Some(file)) => {
            let path = base.join(file);
            let bytes = std::fs::read(&path).with_context(|| format!("jwks_file {}", path.display()))?;
            let set = KeySet::parse(&bytes).with_context(|| format!("jwks_file {}", path.display()))?;
            (jwks::Source::File(path), set)
        }
        _ => bail!("one of jwks_uri, jwks, jwks_file"),
    };
    let header = |text: &str| -> Result<HeaderName> {
        HeaderName::from_bytes(text.as_bytes()).map_err(|_| anyhow!("invalid header name {text:?}"))
    };
    let mut sources = Vec::new();
    for h in &config.from_headers {
        sources.push(Source::Header {
            name: header(&h.name)?,
            prefix: h.prefix.clone(),
        });
    }
    sources.extend(config.from_params.iter().cloned().map(Source::Param));
    sources.extend(config.from_cookies.iter().cloned().map(Source::Cookie));
    if sources.is_empty() {
        sources.push(Source::Header {
            name: http::header::AUTHORIZATION,
            prefix: "Bearer ".into(),
        });
    }
    let mut claim_headers = Vec::new();
    for c in &config.output_claim_to_headers {
        claim_headers.push((header(&c.header)?, c.claim.split('.').map(str::to_string).collect()));
    }
    let payload_header = config.output_payload_to_header.as_deref().map(header).transpose()?;
    for name in claim_headers.iter().map(|(h, _)| h).chain(payload_header.iter()) {
        if sources
            .iter()
            .any(|s| matches!(s, Source::Header { name: n, .. } if n == name))
        {
            bail!("{name} carries the token and cannot also carry claims");
        }
    }
    let keys = Arc::new(jwks::Keys::new(
        name.to_string(),
        source,
        set,
        cache_duration,
        fetch_timeout,
    ));
    Ok(Provider {
        issuer: config.issuer.clone(),
        audiences: config.audiences.clone(),
        sources,
        forward: config.forward_original_token,
        payload_header,
        claim_headers,
        skew: skew.as_secs(),
        require_expiration: config.require_expiration,
        max_lifetime,
        keys,
    })
}

/// A NumericDate claim (seconds, possibly fractional); `Err` when present but not a number.
fn time_claim(claims: &Map<String, Value>, name: &str) -> std::result::Result<Option<u64>, Failure> {
    match claims.get(name) {
        None => Ok(None),
        Some(value) => match value.as_f64() {
            Some(seconds) if seconds >= 0.0 && seconds.is_finite() => Ok(Some(seconds as u64)),
            _ => Err(Failure::Malformed),
        },
    }
}

/// A claim by its path (`realm_access.roles`) as a header value: strings as they are, numbers and
/// booleans written out, arrays of those joined with commas; anything else is not passed on.
fn claim_value(claims: &Map<String, Value>, path: &[String]) -> Option<String> {
    let (first, rest) = path.split_first()?;
    let mut value = claims.get(first)?;
    for step in rest {
        value = value.as_object()?.get(step)?;
    }
    fn scalar(value: &Value) -> Option<String> {
        match value {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }
    match value {
        Value::Array(items) => Some(items.iter().map(scalar).collect::<Option<Vec<_>>>()?.join(",")),
        other => scalar(other),
    }
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        let key = percent_encoding::percent_decode_str(key).decode_utf8().ok()?;
        (key == name).then(|| {
            percent_encoding::percent_decode_str(&value.replace('+', " "))
                .decode_utf8_lossy()
                .into_owned()
        })
    })
}

fn cookie(parts: &http::request::Parts, name: &str) -> Option<String> {
    parts
        .headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            (key == name && !value.is_empty()).then(|| value.trim_matches('"').to_string())
        })
}

fn refusal(failure: Failure) -> Response<Body> {
    let (status, message) = failure.answer();
    let challenge = if failure == Failure::Missing {
        "Bearer"
    } else {
        "Bearer error=\"invalid_token\""
    };
    let mut response = Response::new(full(message));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(WWW_AUTHENTICATE, HeaderValue::from_static(challenge));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    response
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests;
