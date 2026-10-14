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
    Regexp { name: String, group: String },
    FileRelative,
    FileAbsolute,
    FileType,
    FileRemainder,
    Env(String),
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
            parts,
            source: text.to_string(),
        })
    }

    pub fn literal(text: &str) -> Template {
        Template {
            parts: vec![Part::Text(text.to_string())],
            source: text.to_string(),
        }
    }

    /// The text when it has no placeholders.
    pub fn as_static(&self) -> Option<String> {
        let mut out = String::new();
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

    /// The text as written in the Caddyfile.
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    pub fn render(&self, ctx: &Ctx) -> String {
        let mut out = String::new();
        self.render_into(ctx, &mut out);
        out
    }

    /// Appends the filled-in text to `out` (the request path without a copy).
    pub fn render_into(&self, ctx: &Ctx, out: &mut String) {
        for part in &self.parts {
            match part {
                Part::Text(t) => out.push_str(t),
                Part::Var(Var::Path) => out.push_str(ctx.path()),
                Part::Var(v) => out.push_str(&value(v, ctx)),
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

fn value(var: &Var, ctx: &Ctx) -> String {
    match var {
        Var::Path => ctx.path().to_string(),
        Var::Dir => {
            let path = ctx.path();
            match path.rfind('/') {
                Some(i) => path[..=i].to_string(),
                None => "/".to_string(),
            }
        }
        Var::File => {
            let path = ctx.path();
            path.rsplit('/').next().unwrap_or("").to_string()
        }
        Var::Query => ctx.req.uri.query().unwrap_or("").to_string(),
        Var::Uri => ctx
            .req
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".into()),
        Var::Host => ctx.host(),
        Var::HostPort => ctx.hostport().to_string(),
        Var::Method => ctx.req.method.as_str().to_string(),
        Var::Scheme => (if ctx.conn.tls { "https" } else { "http" }).to_string(),
        Var::Remote => ctx.conn.remote.to_string(),
        Var::RemoteHost => ctx.conn.remote.ip().to_string(),
        Var::RemotePort => ctx.conn.remote.port().to_string(),
        Var::ClientIp => ctx.client_ip.to_string(),
        Var::OrigUri => ctx
            .orig_uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".into()),
        Var::OrigPath => crate::handler::decode_path(ctx.orig_uri.path()),
        Var::Header(name) => {
            let values: Vec<&str> = ctx
                .req
                .headers
                .get_all(name)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            values.join(",")
        }
        Var::Regexp { name, group } => ctx.regexp(name, group).unwrap_or_default(),
        Var::FileRelative => ctx.file_match.as_ref().map(|m| m.relative.clone()).unwrap_or_default(),
        Var::FileAbsolute => ctx.file_match.as_ref().map(|m| m.absolute()).unwrap_or_default(),
        Var::FileType => ctx.file_match.as_ref().map(|m| m.kind.to_string()).unwrap_or_default(),
        Var::FileRemainder => String::new(),
        Var::Env(name) => std::env::var(name).unwrap_or_default(),
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
    }
}
