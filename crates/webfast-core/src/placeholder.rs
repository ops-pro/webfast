//! Placeholders (`{path}`, `{re.name.1}`, `{file_match.relative}`, …): parsed once with the
//! configuration, filled in per request.
//!
//! Like Caddy, `{…}` is a placeholder only when its key looks like one (letters, digits, `_ . - :`
//! and `[]`); anything else (`{"json": 1}`) is literal text, and `\{` / `\}` are literal braces.
//! Unlike Caddy, an unknown placeholder is a configuration error instead of an empty string.

use crate::handler::Ctx;
use http::HeaderName;

#[derive(Debug, Clone, Default)]
pub struct Template {
    parts: Vec<Part>,
    source: String,
    /// What `render` reserves: the literal text, and `PER_VAR` bytes for each placeholder.
    reserve: usize,
}

/// A guess at a placeholder's length (an address, a host, a short path or header).
const PER_VAR: usize = 24;

fn reserve_of(parts: &[Part]) -> usize {
    parts
        .iter()
        .map(|part| match part {
            Part::Text(t) => t.len(),
            Part::Var(_) => PER_VAR,
        })
        .sum()
}

#[derive(Debug, Clone)]
enum Part {
    Text(String),
    Var(Var),
}

#[derive(Debug, Clone)]
enum Var {
    Path,
    Dir,
    File,
    Query,
    Uri,
    Host,
    HostPort,
    Method,
    Scheme,
    Remote,
    RemoteHost,
    RemotePort,
    ClientIp,
    OrigUri,
    OrigPath,
    Header(HeaderName),
    Regexp {
        name: String,
        group: String,
    },
    FileRelative,
    FileAbsolute,
    FileType,
    FileRemainder,
    Env(String),
    /// In `handle_errors` routes: the failure's status, its text, its message.
    ErrorStatusCode,
    ErrorStatusText,
    ErrorMessage,
    /// In `handle_errors` routes: the `rate_limit` zone that refused the request.
    RateLimitZone,
}

/// A template that is a client address and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sole {
    /// `{client_ip}`
    ClientIp,
    /// `{remote_host}`
    RemoteHost,
}

impl Template {
    pub fn parse(text: &str) -> Result<Template, String> {
        let mut parts = Vec::new();
        let mut literal = String::new();
        let mut rest = text;
        while !rest.is_empty() {
            if let Some(after) = rest.strip_prefix("\\{") {
                literal.push('{');
                rest = after;
                continue;
            }
            if let Some(after) = rest.strip_prefix("\\}") {
                literal.push('}');
                rest = after;
                continue;
            }
            if let Some(after) = rest.strip_prefix('{')
                && let Some(end) = after.find('}')
                && looks_like_key(&after[..end])
            {
                let key = &after[..end];
                let var = var_of(key).ok_or_else(|| format!("unknown placeholder {{{key}}}"))?;
                if !literal.is_empty() {
                    parts.push(Part::Text(std::mem::take(&mut literal)));
                }
                parts.push(Part::Var(var));
                rest = &after[end + 1..];
                continue;
            }
            let ch = rest.chars().next().unwrap_or_default();
            literal.push(ch);
            rest = &rest[ch.len_utf8()..];
        }
        if !literal.is_empty() {
            parts.push(Part::Text(literal));
        }
        Ok(Template {
            reserve: reserve_of(&parts),
            parts,
            source: text.to_string(),
        })
    }

    pub fn literal(text: &str) -> Template {
        let parts = vec![Part::Text(text.to_string())];
        Template {
            reserve: reserve_of(&parts),
            parts,
            source: text.to_string(),
        }
    }

    /// The text when it has no placeholders.
    pub fn as_static(&self) -> Option<String> {
        let mut out = String::with_capacity(self.reserve);
        for part in &self.parts {
            match part {
                Part::Text(t) => out.push_str(t),
                Part::Var(_) => return None,
            }
        }
        Some(out)
    }

    /// Every placeholder comes from the request path (or what was matched from it, or the
    /// environment): two requests for the same path fill the template in the same way.
    pub fn depends_on_path_only(&self) -> bool {
        self.parts.iter().all(|part| match part {
            Part::Text(_) => true,
            Part::Var(var) => matches!(
                var,
                Var::Path
                    | Var::Dir
                    | Var::File
                    | Var::OrigPath
                    | Var::Regexp { .. }
                    | Var::FileRelative
                    | Var::FileAbsolute
                    | Var::FileType
                    | Var::FileRemainder
                    | Var::Env(_)
            ),
        })
    }

    /// The client address, when the template is that alone (no string needs to be made of it).
    pub fn sole_address(&self) -> Option<Sole> {
        match &self.parts[..] {
            [Part::Var(Var::ClientIp)] => Some(Sole::ClientIp),
            [Part::Var(Var::RemoteHost)] => Some(Sole::RemoteHost),
            _ => None,
        }
    }

    /// The text as written in the Caddyfile.
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// `f` of the filled-in text, rendered into a buffer the thread keeps (let go of past 1 KiB):
    /// for text that is only looked at, hashed or copied into a header value, no string of its own.
    pub fn with_rendered<R>(&self, ctx: &Ctx, f: impl FnOnce(&str) -> R) -> R {
        const KEPT: usize = 1024;
        thread_local! {
            static TEXT: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
        }
        TEXT.with(|cell| match cell.try_borrow_mut() {
            Ok(mut text) => {
                text.clear();
                self.render_into(ctx, &mut text);
                let out = f(&text);
                if text.capacity() > KEPT {
                    *text = String::new();
                }
                out
            }
            // `f` renders a template too: that one gets a string of its own.
            Err(_) => f(&self.render(ctx)),
        })
    }

    pub fn render(&self, ctx: &Ctx) -> String {
        let mut out = String::with_capacity(self.reserve);
        self.render_into(ctx, &mut out);
        out
    }

    /// Appends the filled-in text to `out`, each placeholder written in place (no string of its
    /// own).
    pub fn render_into(&self, ctx: &Ctx, out: &mut String) {
        for part in &self.parts {
            match part {
                Part::Text(t) => out.push_str(t),
                Part::Var(v) => write_value(v, ctx, out),
            }
        }
    }
}

fn looks_like_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else { return false };
    first.is_ascii_alphabetic()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | ':' | '[' | ']'))
}

fn var_of(key: &str) -> Option<Var> {
    // Caddyfile shorthands first, then the full names.
    let full = match key {
        "path" => "http.request.uri.path".to_string(),
        "dir" => "http.request.uri.path.dir".to_string(),
        "file" => "http.request.uri.path.file".to_string(),
        "query" => "http.request.uri.query".to_string(),
        "uri" => "http.request.uri".to_string(),
        "host" => "http.request.host".to_string(),
        "hostport" => "http.request.hostport".to_string(),
        "method" => "http.request.method".to_string(),
        "scheme" => "http.request.scheme".to_string(),
        "remote" => "http.request.remote".to_string(),
        "remote_host" => "http.request.remote.host".to_string(),
        "remote_port" => "http.request.remote.port".to_string(),
        "client_ip" => "http.vars.client_ip".to_string(),
        other => {
            if let Some(rest) = other.strip_prefix("header.") {
                format!("http.request.header.{rest}")
            } else if let Some(rest) = other.strip_prefix("re.") {
                format!("http.regexp.{rest}")
            } else if let Some(rest) = other.strip_prefix("file_match.") {
                format!("http.matchers.file.{rest}")
            } else if let Some(rest) = other.strip_prefix("err.") {
                format!("http.error.{rest}")
            } else {
                other.to_string()
            }
        }
    };
    Some(match full.as_str() {
        "http.request.uri.path" => Var::Path,
        "http.request.uri.path.dir" => Var::Dir,
        "http.request.uri.path.file" => Var::File,
        "http.request.uri.query" => Var::Query,
        "http.request.uri" => Var::Uri,
        "http.request.host" => Var::Host,
        "http.request.hostport" => Var::HostPort,
        "http.request.method" => Var::Method,
        "http.request.scheme" => Var::Scheme,
        "http.request.remote" => Var::Remote,
        "http.request.remote.host" => Var::RemoteHost,
        "http.request.remote.port" => Var::RemotePort,
        "http.vars.client_ip" => Var::ClientIp,
        "http.request.orig_uri" => Var::OrigUri,
        "http.request.orig_uri.path" => Var::OrigPath,
        "http.matchers.file.relative" => Var::FileRelative,
        "http.matchers.file.absolute" => Var::FileAbsolute,
        "http.matchers.file.type" => Var::FileType,
        "http.matchers.file.remainder" => Var::FileRemainder,
        "http.error.status_code" => Var::ErrorStatusCode,
        "http.error.status_text" => Var::ErrorStatusText,
        "http.error.message" => Var::ErrorMessage,
        "http.rate_limit.exceeded.name" => Var::RateLimitZone,
        other => {
            if let Some(name) = other.strip_prefix("http.request.header.") {
                Var::Header(HeaderName::from_bytes(name.as_bytes()).ok()?)
            } else if let Some(rest) = other.strip_prefix("http.regexp.") {
                let (name, group) = rest.split_once('.')?;
                if name.is_empty() || group.is_empty() || group.contains('.') {
                    return None;
                }
                Var::Regexp {
                    name: name.to_string(),
                    group: group.to_string(),
                }
            } else {
                Var::Env(other.strip_prefix("env.")?.to_string())
            }
        }
    })
}

/// A placeholder's value, appended to `out`.
fn write_value(var: &Var, ctx: &Ctx, out: &mut String) {
    use std::fmt::Write as _;
    fn path_and_query(uri: &http::Uri) -> &str {
        uri.path_and_query().map_or("/", |p| p.as_str())
    }
    match var {
        Var::Path => out.push_str(ctx.path()),
        Var::Dir => {
            let path = ctx.path();
            out.push_str(path.rfind('/').map_or("/", |i| &path[..=i]));
        }
        Var::File => out.push_str(ctx.path().rsplit('/').next().unwrap_or("")),
        Var::Query => out.push_str(ctx.req.uri.query().unwrap_or("")),
        Var::Uri => out.push_str(path_and_query(&ctx.req.uri)),
        Var::Host => {
            let host = crate::handler::strip_port(ctx.hostport());
            out.extend(host.chars().map(|c| c.to_ascii_lowercase()));
        }
        Var::HostPort => out.push_str(ctx.hostport()),
        Var::Method => out.push_str(ctx.req.method.as_str()),
        Var::Scheme => out.push_str(if ctx.conn.tls { "https" } else { "http" }),
        Var::Remote => {
            let _ = write!(out, "{}", ctx.conn.remote);
        }
        Var::RemoteHost => {
            let _ = write!(out, "{}", ctx.conn.remote.ip());
        }
        Var::RemotePort => {
            let _ = write!(out, "{}", ctx.conn.remote.port());
        }
        Var::ClientIp => {
            let _ = write!(out, "{}", ctx.client_ip);
        }
        Var::OrigUri => out.push_str(path_and_query(&ctx.orig_uri)),
        Var::OrigPath => {
            out.push_str(&percent_encoding::percent_decode_str(ctx.orig_uri.path()).decode_utf8_lossy());
        }
        Var::Header(name) => {
            let values = ctx.req.headers.get_all(name).iter().filter_map(|v| v.to_str().ok());
            for (i, value) in values.enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(value);
            }
        }
        Var::Regexp { name, group } => out.push_str(ctx.regexp(name, group).unwrap_or("")),
        Var::FileRelative => {
            if let Some(m) = &ctx.file_match {
                out.push_str(&m.relative);
            }
        }
        Var::FileAbsolute => {
            if let Some(m) = &ctx.file_match {
                let _ = write!(out, "{}{}", m.root.root.display(), m.relative);
            }
        }
        Var::FileType => {
            if let Some(m) = &ctx.file_match {
                out.push_str(m.kind);
            }
        }
        Var::FileRemainder => {}
        Var::Env(name) => {
            if let Ok(value) = std::env::var(name) {
                out.push_str(&value);
            }
        }
        Var::ErrorStatusCode => {
            if let Some(e) = &ctx.error {
                out.push_str(e.status.as_str());
            }
        }
        Var::ErrorStatusText => {
            out.push_str(
                ctx.error
                    .as_ref()
                    .and_then(|e| e.status.canonical_reason())
                    .unwrap_or(""),
            );
        }
        Var::ErrorMessage => {
            if let Some(e) = &ctx.error {
                out.push_str(&e.message);
            }
        }
        Var::RateLimitZone => out.push_str(ctx.error.as_ref().and_then(|e| e.zone.as_deref()).unwrap_or("")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_placeholders_and_literals() {
        let t = Template::parse("{path}/index.html").unwrap();
        assert_eq!(t.parts.len(), 2);
        assert!(Template::parse("{re.html.1}").is_ok());
        assert!(Template::parse("{http.request.header.X-Forwarded-For}").is_ok());
        assert_eq!(
            Template::parse("{\"ok\": true}").unwrap().as_static().unwrap(),
            "{\"ok\": true}"
        );
        assert_eq!(Template::parse("\\{path\\}").unwrap().as_static().unwrap(), "{path}");
        assert_eq!(Template::parse("ok").unwrap().as_static().unwrap(), "ok");
        assert!(Template::parse("{nope}").unwrap_err().contains("unknown placeholder"));
        assert!(Template::parse("{re.onlyname}").is_err());
        assert!(Template::parse("{err.status_code} {http.error.status_text} {err.message}").is_ok());
        assert!(Template::parse("{err.trace}").is_err());
    }

    #[test]
    fn every_value_is_written_in_place() {
        use crate::handler::ConnInfo;
        use std::sync::Arc;
        let conn = Arc::new(ConnInfo {
            remote: "127.0.0.1:5000".parse().unwrap(),
            tls: false,
            trusted: false,
            sni: None,
        });
        let (parts, body) = http::Request::get("/a%20b/c.html?x=1+2")
            .header("host", "Example.COM:8443")
            .header("x-a", "1")
            .header("x-a", http::HeaderValue::from_bytes(b"\xff").unwrap())
            .header("x-a", "2")
            .body(crate::body::empty())
            .unwrap()
            .into_parts();
        let ctx = Ctx::new(conn, parts, body, "10.1.2.3".parse().unwrap());
        let keys = [
            ("path", "/a b/c.html"),
            ("dir", "/a b/"),
            ("file", "c.html"),
            ("query", "x=1+2"),
            ("uri", "/a%20b/c.html?x=1+2"),
            ("host", "example.com"),
            ("hostport", "Example.COM:8443"),
            ("method", "GET"),
            ("scheme", "http"),
            ("remote", "127.0.0.1:5000"),
            ("remote_host", "127.0.0.1"),
            ("remote_port", "5000"),
            ("client_ip", "10.1.2.3"),
            ("http.request.orig_uri", "/a%20b/c.html?x=1+2"),
            ("http.request.orig_uri.path", "/a b/c.html"),
            ("header.X-A", "1,2"),
            ("header.X-None", ""),
            ("re.none.1", ""),
            ("file_match.relative", ""),
            ("err.status_code", ""),
            ("err.status_text", ""),
            ("env.WEBFAST_PLACEHOLDER_TEST_UNSET", ""),
        ];
        for (key, want) in keys {
            let template = Template::parse(&format!("<{{{key}}}>")).unwrap();
            assert_eq!(template.render(&ctx), format!("<{want}>"), "{{{key}}}");
        }
        let all: String = keys.iter().map(|(k, _)| format!("{{{k}}}|")).collect();
        let want: String = keys.iter().map(|(_, v)| format!("{v}|")).collect();
        let mut out = String::from("before:");
        Template::parse(&all).unwrap().render_into(&ctx, &mut out);
        assert_eq!(out, format!("before:{want}"));
    }
}
