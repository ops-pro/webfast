//! Events of the request checks (src/jwt, src/apifw, and modules such as the request filter): a
//! request refused, or let through in `log_only`, as one JSON line. A check declares its kinds of
//! event and their fields with their classes (`EventKind`, `Field`) and gives each event through
//! `EventLog::event`: the head (the request's id, address, method, host and URI) is made here, and
//! every field is shown as the log policy and the output's privacy say (src/privacy.rs). The
//! modules' `record_with`, which writes its fields as JSON already made, stays until they are on
//! the events too (docs/logging.md, step 3). With `log: {output: …}` in the check's file the lines go there —
//! a file (appended to, followed through logrotate), `stdout`, `stderr` or `discard` — through
//! the access log's writer threads (src/accesslog.rs: in batches, never making a request wait);
//! without it they go to stderr, where the server's own log goes, in the same shape and through
//! the same writer thread (a line through `tracing` is a write(2) of its own, one syscall per
//! refused request under an attack), when the server's log level lets them. Tokens are not
//! written (a query parameter a JWT may come in shows as `REDACTED`), and a schema error says
//! where and which keyword failed, not the value, which may be a password; the URI is otherwise
//! as the access log has it.

use crate::accesslog::{Output, Writer, json_escape, write_timestamp, writer};
use crate::handler::hostport_of;
use crate::privacy::{Class, Policy, Privacy, Source};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use std::borrow::Cow;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// `stdout`, `stderr`, `discard`, or a file (relative to the check's file).
    pub output: String,
}

/// A core check's `log:` (src/jwt, src/apifw): where, and what the lines show over the global
/// `log_policy` (src/privacy.rs). The modules' `LogConfig` gets its privacy with step 3 of
/// docs/logging.md.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CheckLog {
    /// `stdout`, `stderr`, `discard`, or a file (relative to the check's file).
    pub output: String,
    #[serde(default)]
    pub privacy: crate::privacy::Overrides,
}

/// Where a check's events go.
pub struct EventLog {
    logger: &'static str,
    sink: Sink,
    privacy: crate::privacy::Overrides,
}

/// The writer of the lines, resolved once, with the configuration.
enum Sink {
    /// No `log.output`: stderr, as the server's log, at its level (`info` for a refused request,
    /// `warn` for one let through).
    ServerLog(Option<&'static Writer>),
    /// `log.output` named it; `None`: `discard`.
    Configured(Option<&'static Writer>),
}

/// One request that did not pass a check.
/// Query parameters whose values the event log does not write (a JWT given as `?access_token=…`):
/// the JWT check leaves the names on the request for every log that follows.
#[derive(Debug, Clone)]
pub struct HiddenParams(pub Arc<[String]>);

/// The JWT check's token parameters (`JwtAuth::hidden_params`), now: what every log hides
/// (src/privacy.rs, where the policy holds them).
pub fn set_token_params(names: &[String]) {
    crate::privacy::set_token_params(names);
}

/// `uri` as the policy in place shows it with the default privacy, and with the values of the
/// query parameters `on_request` names (`HiddenParams`) as `REDACTED`.
pub fn redact_uri<'a>(uri: &'a str, on_request: &[String]) -> Cow<'a, str> {
    let policy = crate::privacy::policy();
    uri_as(uri, on_request, &policy, &policy.privacy)
}

/// `uri` under `policy` and `privacy`, the `on_request` parameters hidden too.
fn uri_as<'a>(
    uri: &'a str,
    on_request: &[String],
    policy: &crate::privacy::Policy,
    privacy: &crate::privacy::Privacy,
) -> Cow<'a, str> {
    match redacted(uri, on_request) {
        Cow::Borrowed(uri) => policy.uri(uri, privacy),
        Cow::Owned(hidden) => Cow::Owned(policy.uri(&hidden, privacy).into_owned()),
    }
}

/// A kind of event a check writes: its message, and its fields with their classes (anything else
/// written is a secret, and a debug build panics on it).
pub struct EventKind {
    pub msg: &'static str,
    /// Fields a module adds inside `request`, after the head's (`EventLog::event_with`).
    pub request: &'static [Field],
    pub fields: &'static [Field],
}

/// A field of an event, with its class; a list's items have fields of their own.
#[derive(Debug, Clone, Copy)]
pub struct Field {
    pub name: &'static str,
    pub class: Class,
    pub items: &'static [Field],
}

impl Field {
    const fn of(name: &'static str, class: Class) -> Field {
        Field {
            name,
            class,
            items: &[],
        }
    }
    /// What the server decided: a rule's id, a status, a reason.
    pub const fn public(name: &'static str) -> Field {
        Field::of(name, Class::Public)
    }
    /// About a person: a token's subject, a fingerprint.
    pub const fn personal(name: &'static str) -> Field {
        Field::of(name, Class::Personal)
    }
    /// What the request carried: written with its source only (`Fields::value`).
    pub const fn payload(name: &'static str) -> Field {
        Field::of(name, Class::Payload)
    }
    pub const fn secret(name: &'static str) -> Field {
        Field::of(name, Class::Secret)
    }
    /// A list of objects with `items` for fields (`Fields::list`).
    pub const fn list(name: &'static str, items: &'static [Field]) -> Field {
        Field {
            name,
            class: Class::Public,
            items,
        }
    }
    /// An object with `items` for fields (`Fields::object`).
    pub const fn object(name: &'static str, items: &'static [Field]) -> Field {
        Field::list(name, items)
    }
}

/// The level of an event: to the server's log (no `log.output`) only when its level shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
}

/// A request refused by a core check: `reason`, `detail` (where and which rule, never a value),
/// `status`.
pub static CHECK_REFUSED: EventKind = EventKind {
    msg: "request refused",
    request: &[],
    fields: CHECK_FIELDS,
};
/// The same let through in `log_only`.
pub static CHECK_LET_THROUGH: EventKind = EventKind {
    msg: "request let through (log_only)",
    request: &[],
    fields: CHECK_FIELDS,
};
/// A core check's kind of event and its level: a refusal is `info`, what `log_only` let through
/// `warn`.
pub fn check_kind(refused: bool) -> (&'static EventKind, Level) {
    if refused {
        (&CHECK_REFUSED, Level::Info)
    } else {
        (&CHECK_LET_THROUGH, Level::Warn)
    }
}

const CHECK_FIELDS: &[Field] = &[
    Field::public("reason"),
    Field::public("detail"),
    Field::public("status"),
];

/// The fields of an event as it is written: each shown as its class and source let it.
pub struct Fields<'a> {
    line: &'a mut String,
    declared: &'static [Field],
    policy: &'a Policy,
    privacy: &'a Privacy,
    /// No field written yet in this object (no comma before the next).
    first: bool,
    /// A value of this object was raised to `secret` by its source: the object's other payload
    /// values are hidden with it (a rule's free text repeats what it matched).
    raised: bool,
}

impl Fields<'_> {
    /// The declared class of `name`; one not declared is a secret (and a mistake).
    fn class(&self, name: &str) -> Class {
        match self.declared.iter().find(|f| f.name == name) {
            Some(field) => field.class,
            None => {
                debug_assert!(false, "an event field not declared: {name}");
                Class::Secret
            }
        }
    }

    fn key(&mut self, name: &str) {
        if !std::mem::take(&mut self.first) {
            self.line.push(',');
        }
        self.line.push('"');
        json_escape(self.line, name);
        self.line.push_str("\":");
    }

    fn put(&mut self, name: &str, text: &str, class: Class, source: Source<'_>) {
        if let Some(shown) = self.policy.render(text, class, source, self.privacy) {
            self.key(name);
            self.line.push('"');
            json_escape(self.line, &shown);
            self.line.push('"');
        }
    }

    /// A text field that is not a payload (public, personal, secret).
    pub fn str(&mut self, name: &str, text: &str) {
        let mut class = self.class(name);
        if class == Class::Payload {
            debug_assert!(false, "a payload field without its source: {name}");
            class = Class::Secret;
        }
        self.put(name, text, class, Source::Derived);
    }

    /// A number: public ones as JSON numbers, others as their class says.
    pub fn u64(&mut self, name: &str, value: u64) {
        match self.class(name) {
            Class::Public => {
                self.key(name);
                let _ = write!(self.line, "{value}");
            }
            class => self.put(name, &value.to_string(), class, Source::Derived),
        }
    }

    /// A value the request carried, with where it came from: its class raised by the source
    /// (an `Authorization` header's value is a secret).
    pub fn value(&mut self, name: &str, source: Source<'_>, text: &str) {
        let declared = self.class(name);
        let mut class = self.policy.class_of(declared, source);
        if class == Class::Payload && self.raised {
            class = Class::Secret;
        }
        if class == Class::Secret && declared == Class::Payload {
            self.raised = true;
        }
        self.put(name, text, class, source);
    }

    /// A list of texts not from the request (a rule's tags): JSON strings, as the field's class
    /// shows each.
    pub fn strs<T: AsRef<str>>(&mut self, name: &str, items: &[T]) {
        let mut class = self.class(name);
        if class == Class::Payload {
            debug_assert!(false, "a payload field without its source: {name}");
            class = Class::Secret;
        }
        self.key(name);
        self.line.push('[');
        let mut first = true;
        for item in items {
            if let Some(shown) = self.policy.render(item.as_ref(), class, Source::Derived, self.privacy) {
                if !std::mem::take(&mut first) {
                    self.line.push(',');
                }
                self.line.push('"');
                json_escape(self.line, &shown);
                self.line.push('"');
            }
        }
        self.line.push(']');
    }

    /// A list of public numbers (a rule's CRS references).
    pub fn numbers(&mut self, name: &str, items: impl IntoIterator<Item = u64>) {
        if self.class(name) != Class::Public {
            debug_assert!(false, "numbers are public: {name}");
            return;
        }
        self.key(name);
        self.line.push('[');
        for (i, n) in items.into_iter().enumerate() {
            if i > 0 {
                self.line.push(',');
            }
            let _ = write!(self.line, "{n}");
        }
        self.line.push(']');
    }

    /// An object, its fields written by `fields`.
    pub fn object(&mut self, name: &str, fields: impl FnOnce(&mut Fields<'_>)) {
        let declared = match self.declared.iter().find(|f| f.name == name) {
            Some(field) => field.items,
            None => {
                debug_assert!(false, "an event object not declared: {name}");
                return;
            }
        };
        self.key(name);
        self.line.push('{');
        let mut object = Fields {
            line: self.line,
            declared,
            policy: self.policy,
            privacy: self.privacy,
            first: true,
            raised: self.raised,
        };
        fields(&mut object);
        self.line.push('}');
    }

    /// The policy the line is made under: what a module asks of a name (`secret_field`) to give
    /// a value its source.
    pub fn policy(&self) -> &Policy {
        self.policy
    }

    /// A list of objects, each written by `items`.
    pub fn list(&mut self, name: &str, items: impl FnOnce(&mut List<'_, '_>)) {
        let declared = match self.declared.iter().find(|f| f.name == name) {
            Some(field) => field.items,
            None => {
                debug_assert!(false, "an event list not declared: {name}");
                return;
            }
        };
        self.key(name);
        self.line.push('[');
        let mut list = List {
            fields: self,
            declared,
            first: true,
        };
        items(&mut list);
        self.line.push(']');
    }
}

/// The items of a list being written.
pub struct List<'f, 'a> {
    fields: &'f mut Fields<'a>,
    declared: &'static [Field],
    first: bool,
}

impl List<'_, '_> {
    /// One object of the list, its fields written by `fields`.
    pub fn item(&mut self, fields: impl FnOnce(&mut Fields<'_>)) {
        if !std::mem::take(&mut self.first) {
            self.fields.line.push(',');
        }
        self.fields.line.push('{');
        let mut item = Fields {
            line: self.fields.line,
            declared: self.declared,
            policy: self.fields.policy,
            privacy: self.fields.privacy,
            first: true,
            raised: false,
        };
        fields(&mut item);
        self.fields.line.push('}');
    }
}

pub struct Event<'a> {
    /// Refused (answered with `status`), or let through (`log_only`).
    pub refused: bool,
    pub status: u16,
    pub client_ip: IpAddr,
    pub parts: &'a http::request::Parts,
    /// Short and fixed: `expired`, `request-body:application/json`…
    pub reason: &'a str,
    pub detail: &'a str,
}

impl EventLog {
    pub fn new(logger: &'static str, config: Option<&LogConfig>, base: &Path) -> EventLog {
        let sink = match config {
            Some(config) => Sink::Configured(writer(Output::parse(&config.output, base))),
            None => Sink::ServerLog(writer(Output::Stderr)),
        };
        EventLog {
            logger,
            sink,
            privacy: Default::default(),
        }
    }

    /// A core check's log: `config`'s output and privacy.
    pub fn of_check(logger: &'static str, config: Option<&CheckLog>, base: &Path) -> EventLog {
        let output = config.map(|c| LogConfig {
            output: c.output.clone(),
        });
        EventLog {
            privacy: config.map(|c| c.privacy).unwrap_or_default(),
            ..EventLog::new(logger, output.as_ref(), base)
        }
    }

    /// The writer of a line at `level`, if any output wants it.
    fn wanted(&self, level: Level) -> Option<&'static Writer> {
        match self.sink {
            Sink::Configured(writer) => writer,
            Sink::ServerLog(writer) => {
                let wanted = match level {
                    Level::Info => tracing::enabled!(tracing::Level::INFO),
                    Level::Warn => tracing::enabled!(tracing::Level::WARN),
                };
                writer.filter(|_| wanted)
            }
        }
    }

    /// An event of `kind` about the request `parts` from `client_ip`: its fields are written by
    /// `fields`, which runs only when an output wants the line.
    pub fn event(
        &self,
        kind: &EventKind,
        level: Level,
        parts: &http::request::Parts,
        client_ip: IpAddr,
        fields: impl FnOnce(&mut Fields<'_>),
    ) {
        self.event_with(kind, level, parts, client_ip, |_| {}, fields);
    }

    /// The same, with fields of the module's own inside `request` (`kind.request`: the country,
    /// the User-Agent), written by `request` after the head's.
    pub fn event_with(
        &self,
        kind: &EventKind,
        level: Level,
        parts: &http::request::Parts,
        client_ip: IpAddr,
        request: impl FnOnce(&mut Fields<'_>),
        fields: impl FnOnce(&mut Fields<'_>),
    ) {
        let Some(writer) = self.wanted(level) else { return };
        let policy = crate::privacy::policy();
        let privacy = self.privacy.over(policy.privacy);
        let mut line = String::with_capacity(320);
        let level = match level {
            Level::Info => "info",
            Level::Warn => "warn",
        };
        self.head(&mut line, level, kind.msg, client_ip, parts, &policy, &privacy);
        let mut inside = Fields {
            line: &mut line,
            declared: kind.request,
            policy: &policy,
            privacy: &privacy,
            first: false,
            raised: false,
        };
        request(&mut inside);
        line.push('}');
        let mut out = Fields {
            line: &mut line,
            declared: kind.fields,
            policy: &policy,
            privacy: &privacy,
            first: false,
            raised: false,
        };
        fields(&mut out);
        line.push_str("}\n");
        writer.write(line);
    }

    /// A core check's refusal (or what `log_only` let through).
    pub fn record(&self, event: &Event<'_>) {
        let (kind, level) = check_kind(event.refused);
        self.event(kind, level, event.parts, event.client_ip, |e| {
            e.str("reason", event.reason);
            e.str("detail", event.detail);
            e.u64("status", u64::from(event.status));
        });
    }

    /// The start every line shares, up to and not including the `}` that closes `request`:
    /// `{"level":…,"ts":…,"logger":…,"msg":…,"request":{"id":…,"client_ip":…,"method":…,"host":…,"uri":…`,
    /// the address and the URI as `policy` and `privacy` show them.
    #[allow(clippy::too_many_arguments)]
    fn head(
        &self,
        line: &mut String,
        level: &str,
        msg: &str,
        client_ip: IpAddr,
        parts: &http::request::Parts,
        policy: &Policy,
        privacy: &Privacy,
    ) {
        let uri = uri_as(
            parts.uri.path_and_query().map_or("/", |pq| pq.as_str()),
            parts.extensions.get::<HiddenParams>().map_or(&[][..], |h| &h.0),
            policy,
            privacy,
        );
        line.push_str(r#"{"level":""#);
        line.push_str(level);
        line.push_str(r#"","ts":"#);
        write_timestamp(line);
        let _ = write!(line, r#","logger":"{}","msg":"{msg}","request":{{"#, self.logger);
        if let Some(id) = parts.extensions.get::<crate::reqid::RequestId>() {
            crate::accesslog::write_id(line, id);
        }
        let mark = line.len();
        line.push_str(r#""client_ip":""#);
        if crate::privacy::write_ip(line, client_ip, privacy) {
            line.push_str(r#"","#);
        } else {
            line.truncate(mark);
        }
        line.push_str(r#""method":""#);
        json_escape(line, parts.method.as_str());
        line.push_str(r#"","host":""#);
        json_escape(line, hostport_of(parts));
        line.push_str(r#"","uri":""#);
        json_escape(line, &uri);
        line.push('"');
    }

    /// An event of a module with fields of its own (the request filter): the common head, then
    /// `request_fields` written inside `request` (each as `,"name":value`), then `fields` after it
    /// (the same shape), each already JSON. To the server's log, the same line at its level
    /// (`info`, or `warn` for a request let through).
    pub fn record_with(
        &self,
        level: &str,
        msg: &str,
        client_ip: IpAddr,
        parts: &http::request::Parts,
        request_fields: &dyn Fn(&mut String),
        fields: &dyn Fn(&mut String),
    ) {
        let writer = match self.sink {
            Sink::Configured(writer) => writer,
            Sink::ServerLog(writer) => {
                let wanted = if level == "warn" {
                    tracing::enabled!(tracing::Level::WARN)
                } else {
                    tracing::enabled!(tracing::Level::INFO)
                };
                writer.filter(|_| wanted)
            }
        };
        let Some(writer) = writer else { return };
        let policy = crate::privacy::policy();
        let privacy = self.privacy.over(policy.privacy);
        let mut line = String::with_capacity(512);
        self.head(&mut line, level, msg, client_ip, parts, &policy, &privacy);
        request_fields(&mut line);
        line.push('}');
        fields(&mut line);
        line.push_str("}\n");
        writer.write(line);
    }

    /// Whether events go to a file or stream of their own (else the server's log).
    pub fn has_output(&self) -> bool {
        matches!(self.sink, Sink::Configured(_))
    }
}

/// `uri` with the values of the `hidden` query parameters written as `REDACTED`. Names are
/// compared percent-decoded, as the JWT module reads them, so `access%5Ftoken` is hidden too.
fn redacted<'a>(uri: &'a str, hidden: &[String]) -> Cow<'a, str> {
    let Some((path, query)) = uri.split_once('?') else {
        return Cow::Borrowed(uri);
    };
    if hidden.is_empty() {
        return Cow::Borrowed(uri);
    }
    let hide = |pair: &str| {
        pair.split_once('=').is_some_and(|(key, _)| {
            let key = percent_decode_str(key).decode_utf8_lossy();
            hidden.iter().any(|h| *h == key)
        })
    };
    if !query.split('&').any(hide) {
        return Cow::Borrowed(uri);
    }
    let mut out = String::with_capacity(uri.len());
    out.push_str(path);
    for (i, pair) in query.split('&').enumerate() {
        out.push(if i == 0 { '?' } else { '&' });
        match pair.split_once('=') {
            Some((key, _)) if hide(pair) => {
                out.push_str(key);
                out.push_str("=REDACTED");
            }
            _ => out.push_str(pair),
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_json_lines_in_their_own_file_that_follows_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let log = EventLog::new(
            "jwt",
            Some(&LogConfig {
                output: "events.log".into(),
            }),
            dir.path(),
        );
        let (mut parts, ()) = http::Request::get("/api/x?q=1&access%5Ftoken=a.b.c&n=2")
            .header("host", "api.test")
            .body(())
            .unwrap()
            .into_parts();
        parts
            .extensions
            .insert(HiddenParams(Arc::from(vec!["access_token".to_string()])));
        let event = |refused, reason| Event {
            refused,
            status: 401,
            client_ip: "203.0.113.9".parse().unwrap(),
            parts: &parts,
            reason,
            detail: "line\nbreak \"quoted\"",
        };
        log.record(&event(true, "expired"));
        crate::accesslog::flush_all(std::time::Duration::from_secs(2));
        let path = dir.path().join("events.log");
        let text = std::fs::read_to_string(&path).unwrap();
        let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(first["logger"], "jwt");
        assert_eq!(first["msg"], "request refused");
        assert_eq!(first["request"]["client_ip"], "203.0.113.9");
        assert_eq!(first["request"]["uri"], "/api/x?q=1&access%5Ftoken=REDACTED&n=2");
        assert_eq!(first["detail"], "line\nbreak \"quoted\"");
        assert_eq!(first["status"], 401);
        // Rotated away (as logrotate does): the next line goes to a new file at the path.
        std::fs::rename(&path, dir.path().join("events.log.1")).unwrap();
        log.record(&event(false, "missing"));
        crate::accesslog::flush_all(std::time::Duration::from_secs(2));
        let text = std::fs::read_to_string(&path).unwrap();
        let line: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(line["msg"], "request let through (log_only)");
        assert_eq!(line["reason"], "missing");
        // A module's own fields, inside `request` and after it.
        log.record_with(
            "info",
            "request refused",
            "203.0.113.9".parse().unwrap(),
            &parts,
            &|line| line.push_str(r#","country":"NL""#),
            &|line| line.push_str(r#","decision":"block","hits":[]"#),
        );
        crate::accesslog::flush_all(std::time::Duration::from_secs(2));
        let text = std::fs::read_to_string(&path).unwrap();
        let line: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        assert_eq!(line["request"]["country"], "NL");
        assert_eq!(line["request"]["uri"], "/api/x?q=1&access%5Ftoken=REDACTED&n=2");
        assert_eq!(line["decision"], "block");
        assert_eq!(line["hits"], serde_json::json!([]));
    }

    static HITS: EventKind = EventKind {
        request: &[],
        msg: "request refused",
        fields: &[
            Field::public("decision"),
            Field::public("score"),
            Field::personal("ja4"),
            Field::list(
                "hits",
                &[Field::public("id"), Field::payload("matched"), Field::payload("data")],
            ),
        ],
    };

    /// Events through the API: each field as its class and source say, the head with the
    /// request's id, a hit raised to secret by its source hidden whole, nothing made for
    /// `discard`.
    #[test]
    fn events_are_classed_by_their_fields_and_sources() {
        let dir = tempfile::tempdir().unwrap();
        let log = EventLog::of_check(
            "ngfw",
            Some(&crate::yaml::from_str("output: events.log\nprivacy: {personal: hash, payload: show 4}\n").unwrap()),
            dir.path(),
        );
        let (mut parts, ()) = http::Request::get("/x?q=1")
            .header("host", "a.test")
            .body(())
            .unwrap()
            .into_parts();
        let id = crate::reqid::RequestId::next(&parts.headers, false);
        parts.extensions.insert(id.clone());
        log.event(&HITS, Level::Info, &parts, "203.0.113.9".parse().unwrap(), |e| {
            e.str("decision", "block");
            e.u64("score", 15);
            e.str("ja4", "t13d1516h2_8daaf6152771_02713d6af862");
            e.list("hits", |l| {
                l.item(|h| {
                    h.str("id", "942100");
                    h.value("matched", Source::Query("q"), "union select");
                    h.value("data", Source::Query("q"), "Matched union select");
                });
                l.item(|h| {
                    h.str("id", "920280");
                    h.value("matched", Source::Header("Authorization"), "Bearer eyJ.canary");
                    h.value("data", Source::Derived, "found Bearer eyJ.canary");
                });
            });
        });
        crate::accesslog::flush_all(std::time::Duration::from_secs(2));
        let text = std::fs::read_to_string(dir.path().join("events.log")).unwrap();
        assert!(!text.contains("canary"), "{text}");
        let line: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(line["msg"], "request refused");
        assert_eq!(line["request"]["id"], id.text());
        assert!(
            line["request"]["client_ip"].as_str().unwrap().starts_with("h:"),
            "{line}"
        );
        assert_eq!(line["request"]["uri"], "/x?q=1");
        assert_eq!(line["decision"], "block");
        assert_eq!(line["score"], 15);
        assert!(line["ja4"].as_str().unwrap().starts_with("h:"), "{line}");
        assert_eq!(line["hits"][0]["id"], "942100");
        assert_eq!(line["hits"][0]["matched"], "unio", "payload cut to the output's length");
        assert_eq!(line["hits"][1]["matched"], "REDACTED");
        assert_eq!(line["hits"][1]["data"], "REDACTED", "hidden with the hit's matched");
        // Discard: the fields are not even written.
        let discard = EventLog::new(
            "ngfw",
            Some(&LogConfig {
                output: "discard".into(),
            }),
            dir.path(),
        );
        discard.event(&HITS, Level::Info, &parts, "203.0.113.9".parse().unwrap(), |_| {
            panic!("fields written for discard")
        });
    }

    /// A field the kind did not declare: a mistake a debug build stops at.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "not declared")]
    fn an_undeclared_field_panics_in_debug() {
        let dir = tempfile::tempdir().unwrap();
        let log = EventLog::new(
            "ngfw",
            Some(&LogConfig {
                output: "out.log".into(),
            }),
            dir.path(),
        );
        let (parts, ()) = http::Request::get("/").body(()).unwrap().into_parts();
        log.event(&HITS, Level::Info, &parts, "203.0.113.9".parse().unwrap(), |e| {
            e.str("password", "x")
        });
    }

    /// A core check's `log: {privacy: …}`: the address as it says, the token still hidden.
    #[test]
    fn a_check_log_has_its_privacy() {
        let dir = tempfile::tempdir().unwrap();
        let config: CheckLog = crate::yaml::from_str("output: events.log\nprivacy: {personal: truncate}\n").unwrap();
        let log = EventLog::of_check("jwt", Some(&config), dir.path());
        let (mut parts, ()) = http::Request::get("/x?access_token=a.b.c")
            .body(())
            .unwrap()
            .into_parts();
        parts
            .extensions
            .insert(HiddenParams(Arc::from(vec!["access_token".to_string()])));
        log.record(&Event {
            refused: true,
            status: 401,
            client_ip: "203.0.113.9".parse().unwrap(),
            parts: &parts,
            reason: "missing",
            detail: "",
        });
        crate::accesslog::flush_all(std::time::Duration::from_secs(2));
        let text = std::fs::read_to_string(dir.path().join("events.log")).unwrap();
        let line: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(line["request"]["client_ip"], "203.0.113.0");
        assert_eq!(line["request"]["uri"], "/x?access_token=REDACTED");
        assert!(crate::yaml::from_str::<CheckLog>("output: x\nprivacy: {secret: show}\n").is_err());
    }
}
