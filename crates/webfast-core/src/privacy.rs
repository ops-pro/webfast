//! What a log line may show of a request: one policy for every log of the process (the access
//! log, the request checks' and the modules' event logs), docs/logging.md "The model" and "The
//! policy".
//!
//! Every value a line carries has a **class** (`Class`): `secret` (credentials), `personal`
//! (about a person), `payload` (what the request carried), `public` (what the server decided).
//! Its **source** (`Source`: the query parameter, header, cookie or body field it came from) may
//! raise it — a `payload` value read from `Authorization` is a credential. An output does with
//! each class what its `Privacy` says (`Action`: show, truncate, hash, redact, drop), within the
//! bounds of the class: a secret is never shown, and one a person chose (a body's password) is
//! never hashed.
//!
//! The policy is the Caddyfile's global `log_policy` (read again by a reload) and the JWT check's
//! token parameters as it is loaded now (`set_token_params`); `install` puts it in place, and
//! every line is made under the one in place then.

use crate::caddyfile::Line;
use anyhow::{Result, anyhow, bail};
use arc_swap::ArcSwapOption;
use percent_encoding::percent_decode_str;
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

/// What a value is, for what a log may show of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// What the server decided: rule ids, status, decision, scores, the path.
    Public,
    /// What the request carried: query and body values, a rule's matched text.
    Payload,
    /// About a person: the client's address, a token's subject, the User-Agent.
    Personal,
    /// Credentials: tokens, `Authorization`, cookies, passwords.
    Secret,
}

/// What an output does with a value of a class, from the most shown to the least.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    Show,
    /// An address to its /24 (IPv4) or /48 (IPv6); another value is redacted.
    Truncate,
    /// A keyed HMAC-SHA256, 16 hexadecimal characters after `h:`: equal values, equal hashes.
    Hash,
    /// `REDACTED`, the key kept.
    Redact,
    /// Left out.
    Drop,
}

impl Action {
    fn parse(text: &str) -> Option<Action> {
        Some(match text {
            "show" => Action::Show,
            "truncate" => Action::Truncate,
            "hash" => Action::Hash,
            "redact" => Action::Redact,
            "drop" => Action::Drop,
            _ => return None,
        })
    }

    /// Whether `class` may take this action.
    fn allowed(self, class: Class) -> bool {
        match class {
            Class::Public => self == Action::Show,
            Class::Secret => matches!(self, Action::Hash | Action::Redact),
            Class::Payload => matches!(self, Action::Show | Action::Redact | Action::Drop),
            Class::Personal => true,
        }
    }
}

/// Where a value came from: what may raise its class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source<'a> {
    /// A query parameter, by its name as sent.
    Query(&'a str),
    /// A request header.
    Header(&'a str),
    /// A cookie: every cookie is a secret.
    Cookie(&'a str),
    /// A body field (`password`, `json.user.password`): by its last name.
    Body(&'a str),
    /// The names of a collection (`ARGS_NAMES`): a name is not its value.
    Names,
    /// A count of a collection's values.
    Count,
    /// A response header.
    ResponseHeader(&'a str),
    /// The response's body.
    ResponseBody,
    /// About a person whatever the field (the client's address, the User-Agent, a TLS
    /// fingerprint, where a rule matched in them): at least personal.
    Personal,
    /// Worked out by the server (a fingerprint, a length): the field's own class.
    Derived,
    /// A value of several others that cannot be taken apart (a raw body, all the headers at
    /// once): a secret whole.
    Opaque,
}

/// What an output does with each class, and how much of a payload it shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Privacy {
    pub personal: Action,
    pub payload: Action,
    pub secret: Action,
    /// Bytes of a payload value shown (cut at a character's boundary).
    pub payload_len: usize,
}

impl Default for Privacy {
    /// Today's lines, less the credentials.
    fn default() -> Privacy {
        Privacy {
            personal: Action::Show,
            payload: Action::Show,
            secret: Action::Redact,
            payload_len: 200,
        }
    }
}

impl Privacy {
    fn action(&self, class: Class) -> Action {
        match class {
            Class::Public => Action::Show,
            Class::Payload => self.payload,
            Class::Personal => self.personal,
            Class::Secret => self.secret,
        }
    }
}

/// An output's own privacy, over the policy's: each class it names, and the payload length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Overrides {
    pub personal: Option<Action>,
    pub payload: Option<Action>,
    pub secret: Option<Action>,
    pub payload_len: Option<usize>,
}

impl Overrides {
    /// The privacy of an output with these over `base`.
    pub fn over(&self, base: Privacy) -> Privacy {
        Privacy {
            personal: self.personal.unwrap_or(base.personal),
            payload: self.payload.unwrap_or(base.payload),
            secret: self.secret.unwrap_or(base.secret),
            payload_len: self.payload_len.unwrap_or(base.payload_len),
        }
    }

    /// `personal hash`, `payload show 120`, `secret redact`: one class per call.
    fn set(&mut self, class: &str, args: &[&str]) -> Result<()> {
        let (class_of, slot) = match class {
            "personal" => (Class::Personal, &mut self.personal),
            "payload" => (Class::Payload, &mut self.payload),
            "secret" => (Class::Secret, &mut self.secret),
            other => bail!("{other}: personal, payload or secret"),
        };
        let Some(action) = args.first().and_then(|a| Action::parse(a)) else {
            bail!("{class}: show, truncate, hash, redact or drop");
        };
        if !action.allowed(class_of) {
            bail!("{class} cannot be {}", args[0]);
        }
        *slot = Some(action);
        match (class_of, args.get(1)) {
            (Class::Payload, Some(len)) if action == Action::Show => {
                self.payload_len = Some(len.parse().map_err(|_| anyhow!("payload show: a length in bytes"))?);
            }
            (_, Some(_)) => bail!("{class} {}: one argument (a length only after `payload show`)", args[0]),
            _ => {}
        }
        Ok(())
    }

    /// A `privacy { personal hash; payload drop }` block (a site's `log`).
    pub fn parse_block(line: &Line) -> Result<Overrides> {
        let mut out = Overrides::default();
        for sub in line.block.as_deref().unwrap_or(&[]) {
            let args: Vec<&str> = sub.tokens[1..].iter().map(|t| t.text.as_str()).collect();
            out.set(sub.name(), &args)
                .map_err(|e| anyhow!("{}: privacy: {e}", sub.at))?;
        }
        Ok(out)
    }

    /// The same as a module's file has it: `privacy: { personal: hash, payload: "show 120" }`.
    pub fn from_map(map: &std::collections::BTreeMap<String, String>) -> Result<Overrides> {
        let mut out = Overrides::default();
        for (class, value) in map {
            let args: Vec<&str> = value.split_whitespace().collect();
            out.set(class, &args).map_err(|e| anyhow!("privacy: {e}"))?;
        }
        Ok(out)
    }
}

/// `privacy: {personal: hash, payload: show 120}` in a check's `log:`.
impl<'de> serde::Deserialize<'de> for Overrides {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Overrides, D::Error> {
        let map = std::collections::BTreeMap::<String, String>::deserialize(d)?;
        Overrides::from_map(&map).map_err(serde::de::Error::custom)
    }
}

/// A path pattern whose `*` segments take a class: `/reset/*`, `/users/*/orders`.
#[derive(Debug, Clone)]
struct PathClass {
    segments: Vec<Option<String>>,
    class: Class,
}

impl PathClass {
    fn parse(pattern: &str, class: Class) -> Result<PathClass> {
        if !pattern.starts_with('/') {
            bail!("path_classes: {pattern:?} is not a path");
        }
        let segments: Vec<Option<String>> = pattern[1..]
            .split('/')
            .map(|s| (s != "*").then(|| s.to_ascii_lowercase()))
            .collect();
        if !segments.iter().any(Option::is_none) {
            bail!("path_classes: {pattern:?} has no `*` segment");
        }
        Ok(PathClass { segments, class })
    }

    /// The class of each segment of `path`'s that a `*` covers.
    fn mark(&self, segments: &[&str], marks: &mut [Option<Class>]) {
        // A trailing empty pattern segment (`/s/*/`) asks for nothing more.
        let wanted: Vec<&Option<String>> = match self.segments.last() {
            Some(Some(last)) if last.is_empty() => self.segments[..self.segments.len() - 1].iter().collect(),
            _ => self.segments.iter().collect(),
        };
        if segments.len() < wanted.len() {
            return;
        }
        for (pattern, segment) in wanted.iter().zip(segments) {
            if let Some(literal) = pattern
                && !segment.eq_ignore_ascii_case(literal)
            {
                return;
            }
        }
        for (i, pattern) in wanted.iter().enumerate() {
            if pattern.is_none() && marks[i].is_none_or(|c| rank(c) < rank(self.class)) {
                marks[i] = Some(self.class);
            }
        }
    }
}

/// The more hidden of two classes.
fn rank(class: Class) -> u8 {
    match class {
        Class::Public => 0,
        Class::Payload => 1,
        Class::Personal => 2,
        Class::Secret => 3,
    }
}

/// The headers every policy holds secret.
const SECRET_HEADERS: &[&str] = &["authorization", "proxy-authorization", "cookie", "set-cookie"];
/// The body fields every policy holds secret, by their last name.
const SECRET_FIELDS: &[&str] = &[
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "pin",
];

/// The process's policy: the Caddyfile's `log_policy`.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Query parameters held secret, beside the JWT's `from_params`.
    pub secret_params: Vec<String>,
    /// Headers held secret, lower case, beside `SECRET_HEADERS`.
    pub secret_headers: Vec<String>,
    /// Body fields held secret by their last name, lower case, beside `SECRET_FIELDS`.
    pub secret_fields: Vec<String>,
    path_classes: Vec<PathClass>,
    /// What every output does, unless its own says otherwise.
    pub privacy: Privacy,
}

impl Policy {
    /// The global option `log_policy { … }`.
    pub fn parse(line: &Line) -> Result<Policy> {
        if line.tokens.len() > 1 {
            bail!("{}: log_policy takes a block, no arguments", line.at);
        }
        let mut policy = Policy::default();
        let mut overrides = Overrides::default();
        for sub in line.block.as_deref().unwrap_or(&[]) {
            let args: Vec<&str> = sub.tokens[1..].iter().map(|t| t.text.as_str()).collect();
            let at = &sub.at;
            match sub.name() {
                "secret_params" => policy.secret_params.extend(args.iter().map(|a| a.to_string())),
                "secret_headers" => policy
                    .secret_headers
                    .extend(args.iter().map(|a| a.to_ascii_lowercase())),
                "secret_fields" => policy.secret_fields.extend(args.iter().map(|a| a.to_ascii_lowercase())),
                "path_classes" => {
                    for entry in sub.block.as_deref().unwrap_or(&[]) {
                        let class = match entry.tokens.get(1).map(|t| t.text.as_str()) {
                            Some("secret") => Class::Secret,
                            Some("personal") => Class::Personal,
                            _ => bail!("{}: path_classes: `<path pattern> secret|personal`", entry.at),
                        };
                        policy
                            .path_classes
                            .push(PathClass::parse(entry.name(), class).map_err(|e| anyhow!("{}: {e}", entry.at))?);
                    }
                }
                class @ ("personal" | "payload" | "secret") => overrides
                    .set(class, &args)
                    .map_err(|e| anyhow!("{at}: log_policy: {e}"))?,
                other => bail!("{at}: log_policy: unknown {other:?}"),
            }
            if args.is_empty() && sub.block.is_none() {
                bail!("{at}: log_policy: {} takes its values", sub.name());
            }
        }
        policy.privacy = overrides.over(Privacy::default());
        Ok(policy)
    }

    /// The class of a value declared `declared`, raised by where it came from.
    pub fn class_of(&self, declared: Class, source: Source<'_>) -> Class {
        let raised = match source {
            Source::Query(name) => self.secret_param(name).then_some(Class::Secret),
            Source::Header(name) | Source::ResponseHeader(name) => self.secret_header(name).then_some(Class::Secret),
            Source::Cookie(_) | Source::Opaque => Some(Class::Secret),
            Source::Body(name) => self.secret_field(name).then_some(Class::Secret),
            Source::Names | Source::ResponseBody => Some(Class::Payload),
            Source::Personal => Some(Class::Personal),
            Source::Count | Source::Derived => None,
        };
        match (source, raised) {
            // A name or a response body is a payload, whatever the field was declared.
            (Source::Names | Source::ResponseBody, Some(class)) => class,
            (_, Some(class)) if rank(class) > rank(declared) => class,
            _ => declared,
        }
    }

    /// A query parameter held secret: the policy's or the JWT check's, the name decoded as the
    /// check reads it.
    pub fn secret_param(&self, name: &str) -> bool {
        let decoded = percent_decode_str(name).decode_utf8_lossy();
        let tokens = TOKEN_PARAMS.load();
        self.secret_params.iter().any(|p| *p == decoded)
            || tokens.as_deref().is_some_and(|t| t.iter().any(|p| *p == decoded))
    }

    pub fn secret_header(&self, name: &str) -> bool {
        SECRET_HEADERS.iter().any(|h| h.eq_ignore_ascii_case(name))
            || self.secret_headers.iter().any(|h| h.eq_ignore_ascii_case(name))
    }

    /// A body field by its last name (`json.user.password`: `password`).
    pub fn secret_field(&self, name: &str) -> bool {
        let last = name.rsplit(['.', '[', ']']).find(|s| !s.is_empty()).unwrap_or(name);
        SECRET_FIELDS.iter().any(|f| f.eq_ignore_ascii_case(last))
            || self.secret_fields.iter().any(|f| f.eq_ignore_ascii_case(last))
    }

    /// The class of what lies at `range` of a query string (`a=1&b=2`, the `?` left out): the
    /// most hidden of the parameters it touches, each by its `Source::Query` and, as a form's
    /// field may come in a query, by its name as a body field's. An empty range is the whole.
    pub fn query_class(&self, query: &str, range: std::ops::Range<usize>) -> Class {
        let range = if range.is_empty() { 0..query.len() } else { range };
        let mut class = Class::Payload;
        let mut start = 0;
        for pair in query.split('&') {
            let end = start + pair.len();
            // A parameter touched: its name or its value overlaps the range.
            if start < range.end && range.start <= end {
                let name = pair.split_once('=').map_or(pair, |(name, _)| name);
                let of = if self.secret_param(name) || self.secret_field(name) {
                    Class::Secret
                } else {
                    self.class_of(Class::Payload, Source::Query(name))
                };
                if rank(of) > rank(class) {
                    class = of;
                }
            }
            start = end + 1;
        }
        class
    }

    /// The class of what lies at `range` of a path: the most hidden of the segments it touches
    /// that `path_classes` covers, else a payload. An empty range is the whole.
    pub fn path_class(&self, path: &str, range: std::ops::Range<usize>) -> Class {
        if self.path_classes.is_empty() || !path.starts_with('/') {
            return Class::Payload;
        }
        let range = if range.is_empty() { 0..path.len() } else { range };
        let segments: Vec<&str> = path[1..].split('/').collect();
        let mut marks: Vec<Option<Class>> = vec![None; segments.len()];
        for pattern in &self.path_classes {
            pattern.mark(&segments, &mut marks);
        }
        let mut class = Class::Payload;
        let mut start = 1;
        for (segment, mark) in segments.iter().zip(&marks) {
            let end = start + segment.len();
            if let Some(of) = mark
                && start < range.end
                && range.start <= end
                && rank(*of) > rank(class)
            {
                class = *of;
            }
            start = end + 1;
        }
        class
    }

    /// The class of a URI's part at `range` (`/a/b?x=1`, or a `Referer`'s value with its scheme
    /// and host): its path's by `path_class`, its query's by `query_class`. An empty range is the
    /// whole.
    pub fn uri_class(&self, uri: &str, range: std::ops::Range<usize>) -> Class {
        let range = if range.is_empty() { 0..uri.len() } else { range };
        let (path, query) = match uri.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (uri, None),
        };
        // The path from its first `/` past the scheme and host, when there is one.
        let from = match path.find("://") {
            Some(scheme) => path[scheme + 3..].find('/').map_or(path.len(), |p| scheme + 3 + p),
            None => 0,
        };
        let mut class = if range.start < path.len() && range.end > from {
            let start = range.start.saturating_sub(from);
            let end = (range.end.min(path.len()) - from).max(start + 1);
            self.path_class(&path[from..], start..end)
        } else {
            Class::Payload
        };
        if let Some(query) = query {
            let at = path.len() + 1;
            if range.end > at {
                let of = self.query_class(query, range.start.saturating_sub(at)..range.end - at);
                if rank(of) > rank(class) {
                    class = of;
                }
            }
        }
        class
    }

    /// What `privacy` shows of `value`, of class `class` from `source`: `None` when it is
    /// dropped. Hidden whole first, then cut: no part of a secret is left.
    pub fn render<'a>(
        &self,
        value: &'a str,
        class: Class,
        source: Source<'_>,
        privacy: &Privacy,
    ) -> Option<Cow<'a, str>> {
        let mut action = privacy.action(class);
        // A secret a person chose (a password, a PIN) is never hashed: a hash of a value with
        // little entropy gives it away to whoever has the key.
        if class == Class::Secret && action == Action::Hash && matches!(source, Source::Body(_)) {
            action = Action::Redact;
        }
        Some(match action {
            Action::Show if class == Class::Payload => Cow::Borrowed(cut(value, privacy.payload_len)),
            Action::Show => Cow::Borrowed(value),
            Action::Truncate => match value.parse::<IpAddr>() {
                Ok(ip) => Cow::Owned(truncate(ip).to_string()),
                Err(_) => Cow::Borrowed(REDACTED),
            },
            Action::Hash => Cow::Owned(hash(value)),
            Action::Redact => Cow::Borrowed(REDACTED),
            Action::Drop => return None,
        })
    }

    /// A URI's path and query as `privacy` shows them: the path's segments a `path_classes`
    /// pattern covers, and each query parameter's value by its `Source::Query` (a payload
    /// otherwise, shown as sent — a URI is not cut).
    pub fn uri<'a>(&self, uri: &'a str, privacy: &Privacy) -> Cow<'a, str> {
        let (path, query) = match uri.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (uri, None),
        };
        let path = self.path(path, privacy);
        let query = query.map(|q| self.query(q, privacy));
        match (path, query) {
            (Cow::Borrowed(_), None | Some(Cow::Borrowed(_))) => Cow::Borrowed(uri),
            (path, query) => {
                let mut out = path.into_owned();
                if let Some(query) = query {
                    out.push('?');
                    out.push_str(&query);
                }
                Cow::Owned(out)
            }
        }
    }

    fn path<'a>(&self, path: &'a str, privacy: &Privacy) -> Cow<'a, str> {
        if self.path_classes.is_empty() || !path.starts_with('/') {
            return Cow::Borrowed(path);
        }
        let segments: Vec<&str> = path[1..].split('/').collect();
        let mut marks: Vec<Option<Class>> = vec![None; segments.len()];
        for pattern in &self.path_classes {
            pattern.mark(&segments, &mut marks);
        }
        if marks.iter().all(Option::is_none) {
            return Cow::Borrowed(path);
        }
        let mut out = String::with_capacity(path.len());
        for (segment, mark) in segments.iter().zip(&marks) {
            out.push('/');
            match mark {
                Some(class) if !segment.is_empty() => match self.render(segment, *class, Source::Derived, privacy) {
                    Some(shown) => out.push_str(&shown),
                    None => out.push_str(REDACTED),
                },
                _ => out.push_str(segment),
            }
        }
        Cow::Owned(out)
    }

    fn query<'a>(&self, query: &'a str, privacy: &Privacy) -> Cow<'a, str> {
        // Nothing a query could hide: the common case, no parameter looked at.
        if privacy.payload == Action::Show && self.secret_params.is_empty() && TOKEN_PARAMS.load().is_none() {
            return Cow::Borrowed(query);
        }
        let shown = |pair: &'a str| -> Option<Cow<'a, str>> {
            let (name, value) = pair.split_once('=')?;
            let class = self.class_of(Class::Payload, Source::Query(name));
            match privacy.action(class) {
                // The URI as sent where nothing is hidden: no copy.
                Action::Show if class == Class::Payload => None,
                _ => Some(match self.render(value, class, Source::Query(name), privacy) {
                    Some(value) => Cow::Owned(format!("{name}={value}")),
                    None => Cow::Borrowed(""),
                }),
            }
        };
        if !query.split('&').any(|p| shown(p).is_some()) {
            return Cow::Borrowed(query);
        }
        let mut out = String::with_capacity(query.len());
        for pair in query.split('&') {
            let part = shown(pair).unwrap_or(Cow::Borrowed(pair));
            if part.is_empty() {
                // A dropped value: the parameter goes with it.
                continue;
            }
            if !out.is_empty() {
                out.push('&');
            }
            out.push_str(&part);
        }
        Cow::Owned(out)
    }
}

pub const REDACTED: &str = "REDACTED";

/// Writes `ip`, a personal value, as `privacy` shows it (no string of its own when it is shown or
/// truncated); `false`: dropped, nothing written.
pub fn write_ip(out: &mut String, ip: IpAddr, privacy: &Privacy) -> bool {
    use std::fmt::Write as _;
    match privacy.personal {
        Action::Show => {
            let _ = write!(out, "{ip}");
        }
        Action::Truncate => {
            let _ = write!(out, "{}", truncate(ip));
        }
        Action::Hash => out.push_str(&hash(&ip.to_string())),
        Action::Redact => out.push_str(REDACTED),
        Action::Drop => return false,
    }
    true
}

/// `text` cut to at most `max` bytes, at a character's boundary.
pub fn cut(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// An address to its /24 or /48.
fn truncate(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            IpAddr::from([o[0], o[1], o[2], 0])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::from([s[0], s[1], s[2], 0, 0, 0, 0, 0])
        }
    }
}

/// The key of `hash`: `WEB_LOG_HASH_KEY`, else derived from the TLS ticket seed (the replicas
/// share it), else drawn at start. A reload keeps it.
static HASH_KEY: OnceLock<aws_lc_rs::hmac::Key> = OnceLock::new();

/// The hash key from `WEB_LOG_HASH_KEY` or the ticket seed (src/run.rs, once, before the
/// configuration); without either, one is drawn at the first hash.
pub fn set_hash_key(key: Option<&[u8]>, seed: Option<&[u8]>) {
    let material: Vec<u8> = match (key, seed) {
        (Some(key), _) => key.to_vec(),
        // Derived, never the seed itself: one key for two uses is one leak for both.
        (None, Some(seed)) => {
            let prk = aws_lc_rs::hkdf::Salt::new(aws_lc_rs::hkdf::HKDF_SHA256, b"webfast log hash v1").extract(seed);
            let mut out = [0u8; 32];
            let okm = prk.expand(&[b"log hash"], aws_lc_rs::hkdf::HKDF_SHA256);
            if let Ok(okm) = okm {
                let _ = okm.fill(&mut out);
            }
            out.to_vec()
        }
        (None, None) => return,
    };
    let _ = HASH_KEY.set(aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &material));
}

fn hash(value: &str) -> String {
    let key = HASH_KEY.get_or_init(|| {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        aws_lc_rs::hmac::Key::generate(aws_lc_rs::hmac::HMAC_SHA256, &rng).expect("a random hash key")
    });
    let tag = aws_lc_rs::hmac::sign(key, value.as_bytes());
    let mut out = String::with_capacity(18);
    out.push_str("h:");
    for b in &tag.as_ref()[..8] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The policy in place (the default until a configuration installs one).
static POLICY: ArcSwapOption<Policy> = ArcSwapOption::const_empty();

/// Puts `policy` in place for every line made from now on (at startup, and by a reload that went
/// through).
pub fn install(policy: Policy) {
    POLICY.store(Some(Arc::new(policy)));
}

/// The policy in place.
pub fn policy() -> Arc<Policy> {
    static DEFAULT: OnceLock<Arc<Policy>> = OnceLock::new();
    POLICY
        .load_full()
        .unwrap_or_else(|| Arc::clone(DEFAULT.get_or_init(|| Arc::new(Policy::default()))))
}

/// The query parameters a token may come in, as the JWT check is loaded now: secret in every log
/// (docs/logging.md, step 1).
static TOKEN_PARAMS: ArcSwapOption<Vec<String>> = ArcSwapOption::const_empty();

/// The JWT check's token parameters (`JwtAuth::hidden_params`), now.
pub fn set_token_params(names: &[String]) {
    TOKEN_PARAMS.store((!names.is_empty()).then(|| Arc::new(names.to_vec())));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_of(text: &str) -> Policy {
        let file =
            crate::caddyfile::parse_str(&format!("{{\n{text}\n}}\n"), std::path::Path::new("Caddyfile")).unwrap();
        let line = file
            .global
            .as_ref()
            .unwrap()
            .iter()
            .find(|l| l.name() == "log_policy")
            .unwrap();
        Policy::parse(line).unwrap()
    }

    #[test]
    fn a_part_of_a_composite_value_has_the_class_of_what_it_touches() {
        let p = policy_of("log_policy {\n secret_params sid\n path_classes {\n /reset/* secret\n }\n}");
        let q = "q=hello&sid=abc&password=pw";
        assert_eq!(p.query_class(q, 2..7), Class::Payload);
        assert_eq!(p.query_class(q, 12..15), Class::Secret, "the value of sid");
        assert_eq!(p.query_class(q, 5..10), Class::Secret, "across into sid");
        assert_eq!(p.query_class(q, 25..27), Class::Secret, "a secret field's name");
        assert_eq!(p.query_class(q, 0..0), Class::Secret, "the whole");
        assert_eq!(p.query_class("q=1", 0..0), Class::Payload);
        assert_eq!(p.path_class("/reset/tok123/x", 7..13), Class::Secret);
        assert_eq!(p.path_class("/reset/tok123/x", 14..15), Class::Payload);
        assert_eq!(p.uri_class("/a?q=1&sid=x", 0..0), Class::Secret);
        assert_eq!(p.uri_class("/a?q=1&sid=x", 0..2), Class::Payload);
        assert_eq!(p.uri_class("https://example.com/reset/t?q=1", 0..0), Class::Secret);
        assert_eq!(p.uri_class("https://example.com/a?q=1", 0..0), Class::Payload);
    }

    #[test]
    fn classes_are_raised_by_their_sources() {
        let p = policy_of("log_policy {\n secret_params sid\n secret_headers x-api-key\n secret_fields pincode\n}");
        assert_eq!(p.class_of(Class::Payload, Source::Query("sid")), Class::Secret);
        assert_eq!(
            p.class_of(Class::Payload, Source::Query("s%69d")),
            Class::Secret,
            "decoded"
        );
        assert_eq!(p.class_of(Class::Payload, Source::Query("q")), Class::Payload);
        assert_eq!(
            p.class_of(Class::Payload, Source::Header("Authorization")),
            Class::Secret
        );
        assert_eq!(p.class_of(Class::Payload, Source::Header("X-API-Key")), Class::Secret);
        assert_eq!(p.class_of(Class::Payload, Source::Header("accept")), Class::Payload);
        assert_eq!(p.class_of(Class::Payload, Source::Cookie("theme")), Class::Secret);
        assert_eq!(
            p.class_of(Class::Payload, Source::Body("json.user.password")),
            Class::Secret
        );
        assert_eq!(p.class_of(Class::Payload, Source::Body("pincode")), Class::Secret);
        assert_eq!(p.class_of(Class::Payload, Source::Body("city")), Class::Payload);
        assert_eq!(
            p.class_of(Class::Secret, Source::Names),
            Class::Payload,
            "a name is not its value"
        );
        assert_eq!(p.class_of(Class::Payload, Source::Count), Class::Payload);
        assert_eq!(p.class_of(Class::Payload, Source::Opaque), Class::Secret);
        assert_eq!(p.class_of(Class::Payload, Source::Personal), Class::Personal);
        assert_eq!(p.class_of(Class::Secret, Source::Personal), Class::Secret);
        assert_eq!(p.class_of(Class::Personal, Source::Derived), Class::Personal);
        assert_eq!(
            p.class_of(Class::Payload, Source::ResponseHeader("Set-Cookie")),
            Class::Secret
        );
    }

    #[test]
    fn actions_hide_first_then_cut() {
        let p = Policy::default();
        let mut privacy = Privacy::default();
        let token = "eyJ".to_string() + &"x".repeat(300);
        assert_eq!(
            p.render(&token, Class::Secret, Source::Query("t"), &privacy).unwrap(),
            REDACTED
        );
        privacy.payload_len = 5;
        assert_eq!(
            p.render("héllo world", Class::Payload, Source::Query("q"), &privacy)
                .unwrap(),
            "héll"
        );
        privacy.secret = Action::Hash;
        let one = p
            .render("tok-1", Class::Secret, Source::Header("authorization"), &privacy)
            .unwrap();
        assert!(one.starts_with("h:") && one.len() == 18, "{one}");
        assert_eq!(
            one,
            p.render("tok-1", Class::Secret, Source::Cookie("s"), &privacy).unwrap()
        );
        assert_ne!(
            one,
            p.render("tok-2", Class::Secret, Source::Cookie("s"), &privacy).unwrap()
        );
        assert_eq!(
            p.render("hunter2", Class::Secret, Source::Body("password"), &privacy)
                .unwrap(),
            REDACTED,
            "a password is never hashed"
        );
        privacy.personal = Action::Truncate;
        assert_eq!(
            p.render("203.0.113.9", Class::Personal, Source::Derived, &privacy)
                .unwrap(),
            "203.0.113.0"
        );
        assert_eq!(
            p.render("2001:db8:1:2::9", Class::Personal, Source::Derived, &privacy)
                .unwrap(),
            "2001:db8:1::"
        );
        privacy.payload = Action::Drop;
        assert!(p.render("x", Class::Payload, Source::Derived, &privacy).is_none());
        assert_eq!(
            p.render("rule-1", Class::Public, Source::Derived, &privacy).unwrap(),
            "rule-1"
        );
    }

    #[test]
    fn uris_by_their_parameters_and_paths() {
        let p = policy_of(
            "log_policy {\n secret_params sid\n path_classes {\n  /reset/* secret\n  /users/*/orders personal\n }\n}",
        );
        let privacy = Privacy::default();
        assert_eq!(p.uri("/a?q=1&sid=xyz&n=2", &privacy), "/a?q=1&sid=REDACTED&n=2");
        assert!(
            matches!(p.uri("/a?q=1", &privacy), Cow::Borrowed(_)),
            "nothing hidden: no copy"
        );
        assert_eq!(p.uri("/reset/abc123?x=1", &privacy), "/reset/REDACTED?x=1");
        assert_eq!(
            p.uri("/users/jane@example.com/orders", &privacy),
            "/users/jane@example.com/orders"
        );
        let hashed = Privacy {
            personal: Action::Hash,
            ..privacy
        };
        let shown = p.uri("/users/jane@example.com/orders", &hashed);
        assert!(shown.starts_with("/users/h:") && shown.ends_with("/orders"), "{shown}");
        let dropped = Privacy {
            payload: Action::Drop,
            ..privacy
        };
        assert_eq!(p.uri("/a?q=1&sid=xyz", &dropped), "/a?sid=REDACTED");
        set_token_params(&["wf_privacy_test".to_string()]);
        assert_eq!(p.uri("/a?wf_privacy_test=t", &privacy), "/a?wf_privacy_test=REDACTED");
        set_token_params(&[]);
    }

    #[test]
    fn the_option_and_its_bounds() {
        let p = policy_of("log_policy {\n personal hash\n payload show 80\n secret hash\n}");
        assert_eq!(
            p.privacy,
            Privacy {
                personal: Action::Hash,
                payload: Action::Show,
                secret: Action::Hash,
                payload_len: 80
            }
        );
        for bad in [
            "log_policy {\n secret show\n}",
            "log_policy {\n payload hash\n}",
            "log_policy {\n bogus x\n}",
            "log_policy {\n path_classes {\n  /no-star secret\n }\n}",
        ] {
            let file =
                crate::caddyfile::parse_str(&format!("{{\n{bad}\n}}\n"), std::path::Path::new("Caddyfile")).unwrap();
            let line = file
                .global
                .as_ref()
                .unwrap()
                .iter()
                .find(|l| l.name() == "log_policy")
                .unwrap();
            assert!(Policy::parse(line).is_err(), "{bad}");
        }
        let mut map = std::collections::BTreeMap::new();
        map.insert("payload".to_string(), "show 120".to_string());
        map.insert("personal".to_string(), "truncate".to_string());
        let o = Overrides::from_map(&map).unwrap();
        assert_eq!(o.payload_len, Some(120));
        assert_eq!(o.personal, Some(Action::Truncate));
    }
}
