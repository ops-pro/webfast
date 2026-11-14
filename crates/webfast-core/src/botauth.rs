//! Web Bot Auth (Cargo feature `bot-auth`; on when `WEB_BOT_AUTH_CONFIG` names its YAML file):
//! crawlers and agents that sign their requests (HTTP Message Signatures, RFC 9421, with the tag
//! `web-bot-auth`: draft-meunier-web-bot-auth-architecture and the IETF webbotauth group's drafts
//! after it) are told from those that only say who they are in `User-Agent`.
//!
//! The file names the agents trusted and where their keys are — a key directory (a JWKS at
//! `/.well-known/http-message-signatures-directory` of the agent's host), or keys given here.
//! Nothing is fetched because a request says so: a signature by a key that is in no named
//! agent's directory is not looked at further.
//!
//! This check refuses nothing. A request whose signature holds is marked — the request header
//! `header` (`X-Verified-Bot`) is set to the agent's name, and `handler::VerifiedBot` put in its
//! extensions — and everything after it may act on that: a matcher (`header X-Verified-Bot *`:
//! the browser challenge's `except`, a `rate_limit` zone of its own), the request filter, the
//! upstream. The header is taken off every request first, so a client cannot send it. A
//! signature that does not hold is written to the event log (src/eventlog.rs) and the request
//! goes on as any other: unsigned is what most requests are.
//!
//! What a signature must say (the drafts' musts): `created`, `expires`, `keyid` (the key's JWK
//! thumbprint, RFC 7638) and `tag="web-bot-auth"`; it must cover `@authority` or `@target-uri`
//! (so it is for this host and no other), and `Signature-Agent` when the request has one. It
//! must not be expired, nor created in the future, nor valid for longer than `max_validity`
//! (24 h, as the drafts recommend). Not done: a store of the nonces seen (the drafts leave it to
//! the origin): within its validity a signed request can be sent again to the host it was for.
//!
//! ```yaml
//! header: X-Verified-Bot          # the request header a verified agent's name goes in
//! log: {output: /var/log/web/bot-auth.log}
//! agents:
//!   chatgpt:
//!     directory: https://chatgpt.com       # its key directory; a full URL is taken as it is
//!   our-monitor:
//!     jwks_file: monitor-keys.json         # or `jwks`: the keys themselves
//! ```
//!
//! What a request costs: without `Signature-Input`, one header lookup (and the removal of
//! `header`). With one: parsing two fields, building the signature base, one signature check
//! (Ed25519: 40 µs or so) with a key parsed when the keys were loaded.

use crate::body::Body;
use crate::handler::{VerifiedBot, hostport_of};
use crate::jwt::jwks::{self, Alg, Checked, KeySet, Keys};
use anyhow::{Context, Result, anyhow, bail};
use http::{HeaderName, HeaderValue};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SIGNATURE: HeaderName = HeaderName::from_static("signature");
const SIGNATURE_INPUT: HeaderName = HeaderName::from_static("signature-input");
const SIGNATURE_AGENT: HeaderName = HeaderName::from_static("signature-agent");

/// The tag of the signatures this check reads (the drafts' fixed value).
const TAG: &str = "web-bot-auth";

/// Where an agent's key directory is on its host (the registered well-known suffix).
const DIRECTORY: &str = "/.well-known/http-message-signatures-directory";

/// Components a signature may cover, at most: the base is built from every one of them.
const MAX_COMPONENTS: usize = 32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    agents: BTreeMap<String, AgentConfig>,
    #[serde(default = "default_header")]
    header: String,
    clock_skew: Option<String>,
    max_validity: Option<String>,
    /// Where signatures that do not hold are written (src/eventlog.rs); none: the server's log.
    log: Option<crate::eventlog::CheckLog>,
}

fn default_header() -> String {
    "X-Verified-Bot".to_string()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentConfig {
    /// The agent's key directory: its host (`https://chatgpt.com`: the well-known path is
    /// added), or the directory's own URL.
    directory: Option<String>,
    jwks: Option<String>,
    jwks_file: Option<PathBuf>,
    cache_duration: Option<String>,
    fetch_timeout: Option<String>,
}

struct Agent {
    name: Arc<str>,
    /// Its name as the header's value.
    value: HeaderValue,
    /// The host of its directory, lowercase: a `Signature-Agent` that names it asks for an
    /// early read when the key is not known (the agent rotated its keys).
    host: Option<String>,
    keys: Arc<Keys>,
}

/// Why a signature was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// `Signature-Input` or `Signature` could not be read.
    Malformed,
    /// Without `created`, `expires` or `keyid`.
    Incomplete,
    /// Neither `@authority` nor `@target-uri` is covered, or `Signature-Agent` is sent and not.
    Uncovered,
    /// A component this check cannot fill in.
    Component,
    Expired,
    NotYetValid,
    ValidityTooLong,
    /// The key is no named agent's.
    UnknownKey,
    BadSignature,
    /// Over a connection without TLS, from a peer that is no trusted proxy.
    Insecure,
}

impl Failure {
    fn code(self) -> &'static str {
        match self {
            Failure::Malformed => "malformed",
            Failure::Incomplete => "incomplete",
            Failure::Uncovered => "uncovered",
            Failure::Component => "unsupported-component",
            Failure::Expired => "expired",
            Failure::NotYetValid => "not-yet-valid",
            Failure::ValidityTooLong => "validity-too-long",
            Failure::UnknownKey => "unknown-key",
            Failure::BadSignature => "bad-signature",
            Failure::Insecure => "insecure",
        }
    }
}

/// The agents trusted, and their keys.
pub struct BotAuth {
    agents: Vec<Agent>,
    header: HeaderName,
    skew: u64,
    max_validity: u64,
    log: crate::eventlog::EventLog,
}

impl BotAuth {
    /// Reads the YAML file at `path` (`jwks_file`s are relative to it) and loads the keys given
    /// in it; those of a `directory` are read once `start` runs.
    pub fn load(path: &Path) -> Result<BotAuth> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        BotAuth::from_yaml(&text, path.parent().unwrap_or(Path::new(".")))
            .with_context(|| format!("bot authentication {}", path.display()))
    }

    pub fn from_yaml(text: &str, base: &Path) -> Result<BotAuth> {
        let file: FileConfig = crate::yaml::from_str(text)?;
        if file.agents.is_empty() {
            bail!("agents: none named");
        }
        let duration = |value: &Option<String>, default: Duration, what: &str| -> Result<Duration> {
            match value {
                Some(text) => crate::config::parse_duration(text).map_err(|e| anyhow!("{what}: {e}")),
                None => Ok(default),
            }
        };
        let mut agents = Vec::new();
        for (name, config) in &file.agents {
            agents.push(agent(name, config, base).with_context(|| format!("agent {name}"))?);
        }
        Ok(BotAuth {
            agents,
            header: HeaderName::from_bytes(file.header.as_bytes())
                .map_err(|_| anyhow!("header: {:?} is not a header name", file.header))?,
            skew: duration(&file.clock_skew, Duration::from_secs(60), "clock_skew")?.as_secs(),
            max_validity: duration(&file.max_validity, Duration::from_secs(24 * 3600), "max_validity")?.as_secs(),
            log: crate::eventlog::EventLog::of_check("bot-auth", file.log.as_ref(), base),
        })
    }

    /// Starts reading the keys of the agents that have a directory or a key file (on the current
    /// tokio runtime), first and then every `cache_duration`.
    pub fn start(&self) -> Result<()> {
        let client = jwks::client()?;
        for agent in &self.agents {
            if agent.keys.refreshed() {
                // Held weakly: once a reload has put another file in place and the last request
                // of this one is done, the task ends.
                tokio::spawn(jwks::refresh(Arc::downgrade(&agent.keys), client.clone()));
            }
        }
        Ok(())
    }

    /// The agents named (for the startup log).
    pub fn count(&self) -> usize {
        self.agents.len()
    }

    /// The header a verified agent's name goes in.
    pub fn header(&self) -> &HeaderName {
        &self.header
    }

    /// Takes the header off the request, then looks at its signature: one that holds marks the
    /// request with its agent. Never refuses.
    pub async fn check(&self, parts: &mut http::request::Parts, client: crate::extensions::Client<'_>) {
        parts.headers.remove(&self.header);
        crate::proxy::remove_lookalikes(&mut parts.headers, std::slice::from_ref(&self.header));
        if !parts.headers.contains_key(SIGNATURE_INPUT) {
            return;
        }
        let secure = client.conn.tls || client.conn.trusted;
        let https = client.conn.tls
            || (client.conn.trusted
                && parts
                    .headers
                    .get("x-forwarded-proto")
                    .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"https")));
        let verified = match self.read(parts, https, unix_now()) {
            Ok(Some(_)) if !secure => Err(Failure::Insecure),
            Ok(Some(signed)) => self.verify(&signed, parts).await,
            // No signature with this tag: some other use of HTTP signatures, not ours to judge.
            Ok(None) => return,
            Err(failure) => Err(failure),
        };
        match verified {
            Ok(agent) => {
                let agent = &self.agents[agent];
                parts.headers.insert(self.header.clone(), agent.value.clone());
                parts.extensions.insert(VerifiedBot(agent.name.clone()));
            }
            Err(failure) => {
                let kind = &crate::eventlog::SIGNATURE_NOT_TAKEN;
                self.log
                    .event(kind, crate::eventlog::Level::Info, parts, client.ip, |e| {
                        e.str("reason", failure.code());
                    });
            }
        }
    }

    /// The signature of the request with the tag, taken apart and its times checked, with the
    /// base it signs. `Ok(None)`: the request has none with this tag.
    fn read(&self, parts: &http::request::Parts, https: bool, now: u64) -> Result<Option<Signed>, Failure> {
        let inputs = field(parts, &SIGNATURE_INPUT).ok_or(Failure::Malformed)?;
        let Some((label, input)) = members(&inputs)
            .into_iter()
            .filter_map(|(label, value)| Some((label, Input::parse(value)?)))
            .find(|(_, input)| input.tag.as_deref() == Some(TAG))
        else {
            // One that names the tag and could not be read is ours, and malformed.
            return if inputs.contains(TAG) {
                Err(Failure::Malformed)
            } else {
                Ok(None)
            };
        };
        let (Some(created), Some(expires), Some(keyid)) = (input.created, input.expires, input.keyid.as_deref()) else {
            return Err(Failure::Incomplete);
        };
        if created > now.saturating_add(self.skew) {
            return Err(Failure::NotYetValid);
        }
        if now > expires.saturating_add(self.skew) {
            return Err(Failure::Expired);
        }
        if expires.saturating_sub(created) > self.max_validity {
            return Err(Failure::ValidityTooLong);
        }
        let covers = |name: &str| input.components.iter().any(|c| c.name == name);
        let agent = field(parts, &SIGNATURE_AGENT);
        if !(covers("@authority") || covers("@target-uri")) || (agent.is_some() && !covers("signature-agent")) {
            return Err(Failure::Uncovered);
        }
        let signatures = field(parts, &SIGNATURE).ok_or(Failure::Malformed)?;
        let signature = members(&signatures)
            .into_iter()
            .find(|(name, _)| *name == label)
            .and_then(|(_, value)| byte_sequence(value))
            .ok_or(Failure::Malformed)?;
        let base = signature_base(parts, &input, https, agent.as_deref()).ok_or(Failure::Component)?;
        Ok(Some(Signed {
            keyid: keyid.to_string(),
            alg: match input.alg.as_deref() {
                Some(name) => Some(algorithm(name).ok_or(Failure::Component)?),
                None => None,
            },
            base,
            signature,
            // The host `Signature-Agent` names, to know whose keys to read again.
            agent_host: agent.as_deref().and_then(agent_host),
        }))
    }

    /// The agent whose key made the signature.
    async fn verify(&self, signed: &Signed, parts: &http::request::Parts) -> Result<usize, Failure> {
        let _ = parts;
        let now = unix_now();
        let check = |keys: &KeySet| {
            keys.verify_thumbprint(
                &signed.keyid,
                signed.alg,
                now,
                signed.base.as_bytes(),
                &signed.signature,
            )
        };
        let mut unknown = true;
        for (index, agent) in self.agents.iter().enumerate() {
            match check(&agent.keys.current()) {
                Checked::Valid => return Ok(index),
                Checked::BadSignature => unknown = false,
                Checked::NoKey => {}
            }
        }
        if !unknown {
            return Err(Failure::BadSignature);
        }
        // A key not known of an agent that is: it may have a new one. Its directory is read
        // again (not more often than the keys' own limit allows), and the check made once more.
        if let Some(host) = &signed.agent_host
            && let Some((index, agent)) = self
                .agents
                .iter()
                .enumerate()
                .find(|(_, a)| a.host.as_deref() == Some(host.as_str()))
            && agent.keys.read_again().await
        {
            return match check(&agent.keys.current()) {
                Checked::Valid => Ok(index),
                Checked::BadSignature => Err(Failure::BadSignature),
                Checked::NoKey => Err(Failure::UnknownKey),
            };
        }
        Err(Failure::UnknownKey)
    }
}

fn agent(name: &str, config: &AgentConfig, base: &Path) -> Result<Agent> {
    let duration = |value: &Option<String>, default: Duration, what: &str| -> Result<Duration> {
        match value {
            Some(text) => crate::config::parse_duration(text).map_err(|e| anyhow!("{what}: {e}")),
            None => Ok(default),
        }
    };
    let cache_duration = duration(&config.cache_duration, Duration::from_secs(3600), "cache_duration")?;
    let fetch_timeout = duration(&config.fetch_timeout, Duration::from_secs(5), "fetch_timeout")?;
    let mut host = None;
    let (source, set) = match (&config.directory, &config.jwks, &config.jwks_file) {
        (Some(directory), None, None) => {
            let uri: http::Uri = directory.trim().parse().map_err(|e| anyhow!("directory: {e}"))?;
            let Some(authority) = uri.authority() else {
                bail!("directory: an https URL (https://agent.example)");
            };
            if !matches!(uri.scheme_str(), Some("https" | "http")) {
                bail!("directory: an https URL (https://agent.example)");
            }
            host = Some(authority.host().to_ascii_lowercase());
            // A host alone: its directory is at the well-known path.
            let uri = if matches!(uri.path(), "" | "/") && uri.query().is_none() {
                format!("{}://{authority}{DIRECTORY}", uri.scheme_str().unwrap_or("https"))
                    .parse()
                    .map_err(|e| anyhow!("directory: {e}"))?
            } else {
                uri
            };
            (jwks::Source::Uri(uri), KeySet::default())
        }
        (None, Some(inline), None) => (jwks::Source::Inline, KeySet::parse(inline.as_bytes()).context("jwks")?),
        (None, None, Some(file)) => {
            let path = base.join(file);
            let bytes = std::fs::read(&path).with_context(|| format!("jwks_file {}", path.display()))?;
            let set = KeySet::parse(&bytes).with_context(|| format!("jwks_file {}", path.display()))?;
            (jwks::Source::File(path), set)
        }
        _ => bail!("one of directory, jwks, jwks_file"),
    };
    Ok(Agent {
        name: Arc::from(name),
        value: HeaderValue::from_str(name).map_err(|_| anyhow!("its name is not a header value"))?,
        host,
        keys: Arc::new(Keys::new(name.to_string(), source, set, cache_duration, fetch_timeout)),
    })
}

/// A signature read from a request: what it signs, and with what.
struct Signed {
    keyid: String,
    alg: Option<Alg>,
    base: String,
    signature: Vec<u8>,
    agent_host: Option<String>,
}

/// The algorithms of HTTP Message Signatures (RFC 9421 §3.3) this check has keys for.
fn algorithm(name: &str) -> Option<Alg> {
    Some(match name {
        "ed25519" => Alg::EdDsa,
        "rsa-pss-sha512" => Alg::Ps512,
        "rsa-v1_5-sha256" => Alg::Rs256,
        "ecdsa-p256-sha256" => Alg::Es256,
        "ecdsa-p384-sha384" => Alg::Es384,
        _ => return None,
    })
}

/// A field's values, joined as RFC 9421 §2.1 has them: each trimmed, `, ` between them.
fn field(parts: &http::request::Parts, name: &HeaderName) -> Option<String> {
    let mut joined: Option<String> = None;
    for value in parts.headers.get_all(name) {
        let value = value.to_str().ok()?.trim();
        match &mut joined {
            Some(text) => {
                text.push_str(", ");
                text.push_str(value);
            }
            None => joined = Some(value.to_string()),
        }
    }
    joined
}

/// The members of a Dictionary (RFC 8941 §3.2) as its text has them: each key with its value
/// as written. Commas inside strings, byte sequences and inner lists are not separators.
fn members(text: &str) -> Vec<(&str, &str)> {
    fn member(text: &str) -> Option<(&str, &str)> {
        let text = text.trim();
        let (key, value) = text.split_once('=').unwrap_or((text, ""));
        Some((key.trim(), value.trim())).filter(|(key, _)| !key.is_empty())
    }
    let mut out = Vec::new();
    let (mut start, mut depth, mut quoted, mut escaped) = (0, 0u32, false, false);
    for (i, c) in text.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => depth = depth.saturating_sub(1),
            ',' if !quoted && depth == 0 => {
                out.extend(member(&text[start..i]));
                start = i + 1;
            }
            _ => {}
        }
    }
    out.extend(member(&text[start..]));
    out
}

/// A covered component: its name, and its identifier as written (with its parameters), which
/// is what the base repeats.
struct Component<'a> {
    name: &'a str,
    written: &'a str,
    /// `;key="…"`: one member of a field that is a Dictionary.
    key: Option<&'a str>,
    /// Another parameter (`;sf`, `;bs`, `;req`, `;tr`, `;name`): not filled in here.
    other: bool,
}

/// One signature's input: its covered components and parameters, and the text itself, which
/// the base ends with.
struct Input<'a> {
    written: &'a str,
    components: Vec<Component<'a>>,
    created: Option<u64>,
    expires: Option<u64>,
    keyid: Option<String>,
    alg: Option<String>,
    tag: Option<String>,
}

impl<'a> Input<'a> {
    /// `("@authority" "signature-agent";key="sig");created=1;keyid="…";tag="web-bot-auth"`.
    fn parse(written: &'a str) -> Option<Input<'a>> {
        let inner = written.strip_prefix('(')?;
        let close = closing(inner)?;
        let (list, parameters) = (&inner[..close], &inner[close + 1..]);
        let mut components = Vec::new();
        let mut rest = list.trim_start();
        while !rest.is_empty() {
            let name_end = 1 + rest.strip_prefix('"')?.find('"')?;
            // The identifier runs to the next space outside a string.
            let mut end = name_end + 1;
            let mut quoted = false;
            for (i, c) in rest[end..].char_indices() {
                match c {
                    '"' => quoted = !quoted,
                    ' ' if !quoted => break,
                    _ => {}
                }
                end = name_end + 1 + i + c.len_utf8();
            }
            let written = &rest[..end];
            let mut component = Component {
                name: &rest[1..name_end],
                written,
                key: None,
                other: false,
            };
            for (name, value) in parameters_of(&rest[name_end + 1..end]) {
                match name {
                    "key" => component.key = Some(value.strip_prefix('"')?.strip_suffix('"')?),
                    _ => component.other = true,
                }
            }
            components.push(component);
            if components.len() > MAX_COMPONENTS {
                return None;
            }
            rest = rest[end..].trim_start();
        }
        let mut input = Input {
            written,
            components,
            created: None,
            expires: None,
            keyid: None,
            alg: None,
            tag: None,
        };
        for (name, value) in parameters_of(parameters) {
            let text = || {
                value
                    .strip_prefix('"')
                    .and_then(|v| v.strip_suffix('"'))
                    .map(str::to_string)
            };
            match name {
                "created" => input.created = Some(value.parse().ok()?),
                "expires" => input.expires = Some(value.parse().ok()?),
                "keyid" => input.keyid = Some(text()?),
                "alg" => input.alg = Some(text()?),
                "tag" => input.tag = Some(text()?),
                _ => {}
            }
        }
        Some(input)
    }
}

/// Where the inner list that `text` continues ends: its `)` outside a string.
fn closing(text: &str) -> Option<usize> {
    let (mut quoted, mut escaped) = (false, false);
    for (i, c) in text.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ')' if !quoted => return Some(i),
            _ => {}
        }
    }
    None
}

/// `;a=1;b="x";c` as (name, value as written) pairs; a parameter without a value is `?1`.
fn parameters_of(text: &str) -> Vec<(&str, &str)> {
    fn parameter(text: &str) -> Option<(&str, &str)> {
        let text = text.trim();
        let (name, value) = text.split_once('=').unwrap_or((text, "?1"));
        Some((name.trim(), value.trim())).filter(|(name, _)| !name.is_empty())
    }
    let mut out = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, c) in text.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ';' if !quoted => {
                out.extend(parameter(&text[start..i]));
                start = i + 1;
            }
            _ => {}
        }
    }
    out.extend(parameter(&text[start..]));
    out
}

/// A Byte Sequence (`:base64:`, RFC 8941 §3.3.5), decoded.
fn byte_sequence(written: &str) -> Option<Vec<u8>> {
    let text = written.strip_prefix(':')?;
    let text = &text[..text.find(':')?];
    // The standard alphabet with padding, read by the decoder of the other one.
    let url: String = text
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    crate::jwt::decode_base64url(&url)
}

/// The host a `Signature-Agent` names: a Dictionary of strings (`sig="https://agent.example"`),
/// or, as it was first written, one string.
fn agent_host(field: &str) -> Option<String> {
    let value = match members(field).first() {
        Some((_, value)) if value.starts_with('"') => *value,
        _ => field.trim(),
    };
    let url = value.strip_prefix('"')?;
    let url = &url[..url.find('"')?];
    let uri: http::Uri = url.parse().ok()?;
    uri.host().map(str::to_ascii_lowercase)
}

/// The signature base (RFC 9421 §2.5): a line for every covered component, then the
/// signature's own parameters. `None`: a component that is not filled in here.
fn signature_base(parts: &http::request::Parts, input: &Input<'_>, https: bool, agent: Option<&str>) -> Option<String> {
    let mut base = String::with_capacity(256);
    for component in &input.components {
        base.push_str(component.written);
        base.push_str(": ");
        if component.other {
            return None;
        }
        match (component.name, component.key) {
            ("signature-agent", Some(key)) => {
                // One member of the Dictionary, as written.
                let field = agent?;
                let (_, value) = members(field).into_iter().find(|(name, _)| *name == key)?;
                base.push_str(value);
            }
            (_, Some(_)) => return None,
            ("@authority", None) => base.push_str(&authority(parts, https)),
            ("@method", None) => base.push_str(parts.method.as_str()),
            ("@scheme", None) => base.push_str(if https { "https" } else { "http" }),
            ("@path", None) => base.push_str(parts.uri.path()),
            ("@query", None) => {
                base.push('?');
                base.push_str(parts.uri.query().unwrap_or(""));
            }
            ("@request-target", None) => base.push_str(parts.uri.path_and_query().map_or("/", |pq| pq.as_str())),
            ("@target-uri", None) => {
                base.push_str(if https { "https://" } else { "http://" });
                base.push_str(&authority(parts, https));
                base.push_str(parts.uri.path_and_query().map_or("/", |pq| pq.as_str()));
            }
            (derived, None) if derived.starts_with('@') => return None,
            (name, None) => {
                let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
                base.push_str(&field(parts, &name)?);
            }
        }
        base.push('\n');
    }
    base.push_str("\"@signature-params\": ");
    base.push_str(input.written);
    Some(base)
}

/// `@authority` (RFC 9421 §2.2.3): the host in lowercase, the scheme's own port left out.
fn authority(parts: &http::request::Parts, https: bool) -> String {
    let hostport = hostport_of(parts).to_ascii_lowercase();
    let default = if https { ":443" } else { ":80" };
    match hostport.strip_suffix(default) {
        // `[::1]:443`, not the tail of an address without a port.
        Some(host) if !host.ends_with(':') && (host.ends_with(']') || !host.contains(':')) => host.to_string(),
        _ => hostport,
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl crate::extensions::RequestCheck for BotAuth {
    async fn check(
        &self,
        req: &mut http::request::Parts,
        body: Body,
        client: crate::extensions::Client<'_>,
    ) -> crate::extensions::Checked {
        BotAuth::check(self, req, client).await;
        Ok(body)
    }
}

#[cfg(test)]
mod tests;
