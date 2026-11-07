//! Events of the request checks (src/jwt, src/apifw, and modules such as the request filter): a request refused, or let through
//! in `log_only`, as one JSON line (`record`; a module with fields of its own adds them with
//! `record_with`). With `log: {output: …}` in the check's file the lines go there —
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

/// Where a check's events go.
pub struct EventLog {
    logger: &'static str,
    sink: Sink,
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
        EventLog { logger, sink }
    }

    pub fn record(&self, event: &Event<'_>) {
        let writer = match self.sink {
            Sink::Configured(writer) => writer,
            Sink::ServerLog(writer) => {
                let wanted = if event.refused {
                    tracing::enabled!(tracing::Level::INFO)
                } else {
                    tracing::enabled!(tracing::Level::WARN)
                };
                writer.filter(|_| wanted)
            }
        };
        let Some(writer) = writer else { return };
        let uri = redacted(
            event.parts.uri.path_and_query().map_or("/", |pq| pq.as_str()),
            event.parts.extensions.get::<HiddenParams>().map_or(&[][..], |h| &h.0),
        );
        writer.write(self.line(event, &uri));
    }

    fn line(&self, event: &Event<'_>, uri: &str) -> String {
        let mut line = String::with_capacity(256);
        let msg = if event.refused {
            "request refused"
        } else {
            "request let through (log_only)"
        };
        self.head(
            &mut line,
            if event.refused { "info" } else { "warn" },
            msg,
            event.client_ip,
            event.parts,
            uri,
        );
        line.push_str(r#"},"reason":""#);
        json_escape(&mut line, event.reason);
        line.push_str(r#"","detail":""#);
        json_escape(&mut line, event.detail);
        let _ = writeln!(line, r#"","status":{}}}"#, event.status);
        line
    }

    /// The start every line shares, up to and not including the `}` that closes `request`:
    /// `{"level":…,"ts":…,"logger":…,"msg":…,"request":{"client_ip":…,"method":…,"host":…,"uri":…`.
    fn head(
        &self,
        line: &mut String,
        level: &str,
        msg: &str,
        client_ip: IpAddr,
        parts: &http::request::Parts,
        uri: &str,
    ) {
        line.push_str(r#"{"level":""#);
        line.push_str(level);
        line.push_str(r#"","ts":"#);
        write_timestamp(line);
        let _ = write!(
            line,
            r#","logger":"{}","msg":"{msg}","request":{{"client_ip":"{client_ip}","method":""#,
            self.logger,
        );
        json_escape(line, parts.method.as_str());
        line.push_str(r#"","host":""#);
        json_escape(line, hostport_of(parts));
        line.push_str(r#"","uri":""#);
        json_escape(line, uri);
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
        let uri = redacted(
            parts.uri.path_and_query().map_or("/", |pq| pq.as_str()),
            parts.extensions.get::<HiddenParams>().map_or(&[][..], |h| &h.0),
        );
        let mut line = String::with_capacity(512);
        self.head(&mut line, level, msg, client_ip, parts, &uri);
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
    let hide = |pair: &str| {
        pair.split_once('=')
            .is_some_and(|(key, _)| hidden.iter().any(|h| *h == percent_decode_str(key).decode_utf8_lossy()))
    };
    if hidden.is_empty() || !query.split('&').any(hide) {
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
}
