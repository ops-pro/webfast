//! Request matchers: `path`, `path_regexp`, `file`, `not`, `host`, `method`, `header`,
//! `client_ip`, `remote_ip`, `protocol`. A matcher set matches when all its matchers do.
//!
//! Path matching follows Caddy: case-insensitive, on the decoded and cleaned path (`.`/`..`
//! resolved, doubled slashes merged, trailing slash kept); `*` at the end is a prefix match, at the
//! start a suffix match, at both ends a substring match, elsewhere a glob where `*` stops at `/`.
//! Everything that does not depend on the request is prepared with the configuration: the kind of
//! each path pattern, the compiled regexps and their group names; the lowercased, cleaned path is
//! computed once per request (src/handler.rs).

use crate::files::FileStore;
use crate::handler::{Ctx, FileMatch, RegexCaptures};
use crate::placeholder::Template;
use http::{HeaderName, Method};
use ipnet::IpNet;
use regex::Regex;
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct MatcherSet {
    pub matchers: Vec<Matcher>,
}

#[derive(Debug, Clone)]
pub enum Matcher {
    /// Any one pattern matching is enough.
    Path(Vec<PathPattern>),
    PathRegexp {
        name: Arc<str>,
        re: Regex,
        /// Named groups and their index, from the compiled regexp.
        names: Arc<[(String, usize)]>,
    },
    /// True when none of the sets match.
    Not(Vec<MatcherSet>),
    File(FileMatcher),
    Host(Vec<String>),
    Method(Vec<Method>),
    /// Field → acceptable values (empty: the field must be present); `!Field`: must be absent.
    Header(Vec<(HeaderName, bool, Vec<String>)>),
    ClientIp(Vec<IpNet>),
    RemoteIp(Vec<IpNet>),
    Protocol(String),
    /// `handle_errors <codes>`: the failure being handled has one of these statuses (inclusive
    /// ranges; `4xx` is 400–499).
    ErrorStatus(Vec<(u16, u16)>),
}

impl MatcherSet {
    pub fn matches(&self, ctx: &mut Ctx) -> bool {
        self.matchers.iter().all(|m| m.matches(ctx))
    }

    /// Decides by the request path alone (src/memo.rs).
    pub fn depends_on_path_only(&self) -> bool {
        self.matchers.iter().all(Matcher::depends_on_path_only)
    }

    /// The only path pattern of the set, if it has a `path` matcher with exactly one pattern
    /// (Caddy sorts directives of the same kind by this).
    pub fn single_path(&self) -> Option<&str> {
        self.matchers.iter().find_map(|m| match m {
            Matcher::Path(patterns) if patterns.len() == 1 => Some(patterns[0].raw.as_str()),
            _ => None,
        })
    }
}

impl Matcher {
    pub fn regexp(name: &str, re: Regex) -> Matcher {
        let names: Vec<(String, usize)> = re
            .capture_names()
            .enumerate()
            .filter_map(|(i, n)| n.map(|n| (n.to_string(), i)))
            .collect();
        Matcher::PathRegexp {
            name: Arc::from(name),
            re,
            names: names.into(),
        }
    }

    /// Decides by the request path alone: path, path_regexp, file with path placeholders, not.
    pub fn depends_on_path_only(&self) -> bool {
        match self {
            Matcher::Path(_) | Matcher::PathRegexp { .. } => true,
            Matcher::Not(sets) => sets.iter().all(MatcherSet::depends_on_path_only),
            Matcher::File(file) => file.try_files.iter().all(|t| t.template.depends_on_path_only()),
            Matcher::Host(_)
            | Matcher::Method(_)
            | Matcher::Header(_)
            | Matcher::ClientIp(_)
            | Matcher::RemoteIp(_)
            | Matcher::Protocol(_)
            | Matcher::ErrorStatus(_) => false,
        }
    }

    pub fn matches(&self, ctx: &mut Ctx) -> bool {
        match self {
            Matcher::Path(patterns) => {
                if patterns.iter().any(|p| p.keep_slashes) {
                    // Rare: a pattern with `//` compares against the path with doubled slashes kept.
                    let lower = ctx.path().to_lowercase();
                    let (merged, kept) = (clean_path(&lower, true), clean_path(&lower, false));
                    return patterns
                        .iter()
                        .any(|p| p.matches(if p.keep_slashes { &kept } else { &merged }));
                }
                let path = ctx.match_path();
                patterns.iter().any(|p| p.matches(path))
            }
            Matcher::PathRegexp { name, re, names } => {
                let path = ctx.clean_path();
                let Some(caps) = re.captures(path) else { return false };
                let groups = caps.iter().map(|g| g.map(|m| (m.start(), m.end()))).collect();
                let text = path.to_string();
                ctx.set_regexp(
                    name.clone(),
                    RegexCaptures {
                        text,
                        groups,
                        names: names.clone(),
                    },
                );
                true
            }
            Matcher::Not(sets) => !sets.iter().any(|s| s.matches(ctx)),
            Matcher::File(file) => file.matches(ctx),
            Matcher::Host(hosts) => {
                let host = ctx.host();
                hosts.iter().any(|h| host_matches(h, &host))
            }
            Matcher::Method(methods) => methods.contains(&ctx.req.method),
            Matcher::Header(fields) => fields.iter().all(|(name, negate, values)| {
                let mut present = ctx
                    .req
                    .headers
                    .get_all(name)
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .peekable();
                let found = if values.is_empty() {
                    present.peek().is_some()
                } else {
                    present.any(|v| values.iter().any(|want| value_matches(want, v)))
                };
                found != *negate
            }),
            Matcher::ClientIp(nets) => nets.iter().any(|n| n.contains(&ctx.client_ip)),
            Matcher::RemoteIp(nets) => nets.iter().any(|n| n.contains(&ctx.conn.remote.ip())),
            Matcher::Protocol(proto) => match proto.as_str() {
                "http" => !ctx.conn.tls,
                "https" => ctx.conn.tls,
                "http/1.0" => ctx.req.version == http::Version::HTTP_10,
                "http/1.1" => ctx.req.version == http::Version::HTTP_11,
                "http/1" | "http/1+" => ctx.req.version <= http::Version::HTTP_11,
                "http/2" => ctx.req.version == http::Version::HTTP_2,
                "http/2+" => ctx.req.version >= http::Version::HTTP_2,
                "http/3" | "http/3+" => ctx.req.version == http::Version::HTTP_3,
                _ => false,
            },
            Matcher::ErrorStatus(ranges) => ctx.error.as_ref().is_some_and(|e| {
                let status = e.status.as_u16();
                ranges.iter().any(|(low, high)| (*low..=*high).contains(&status))
            }),
        }
    }
}

/// A `path` pattern, prepared once: `*`, `prefix*`, `*suffix`, `*sub*`, exact, or a glob.
#[derive(Debug, Clone)]
pub struct PathPattern {
    /// As written, lowercased (Caddy sorts directives by its length).
    pub raw: String,
    kind: PatternKind,
    /// The pattern has `//`: it compares against the path with doubled slashes kept.
    keep_slashes: bool,
}

#[derive(Debug, Clone)]
enum PatternKind {
    Any,
    Exact,
    Prefix(String),
    Suffix(String),
    Contains(String),
    Glob,
}

impl PathPattern {
    pub fn new(pattern: &str) -> PathPattern {
        let raw = pattern.to_lowercase();
        let keep_slashes = raw.contains("//");
        let starts = raw.starts_with('*');
        let ends = raw.ends_with('*');
        let inner = raw.trim_start_matches('*').trim_end_matches('*').to_string();
        let kind = if raw == "*" {
            PatternKind::Any
        } else if inner.contains(['*', '?', '[']) {
            PatternKind::Glob
        } else {
            match (starts, ends) {
                (true, true) => PatternKind::Contains(inner),
                (true, false) => PatternKind::Suffix(inner),
                (false, true) => PatternKind::Prefix(inner),
                (false, false) => PatternKind::Exact,
            }
        };
        PathPattern {
            raw,
            kind,
            keep_slashes,
        }
    }

    /// `path` lowercased and cleaned.
    fn matches(&self, path: &str) -> bool {
        match &self.kind {
            PatternKind::Any => true,
            PatternKind::Exact => path == self.raw,
            PatternKind::Prefix(prefix) => path.starts_with(prefix.as_str()),
            PatternKind::Suffix(suffix) => path.ends_with(suffix.as_str()),
            PatternKind::Contains(inner) => path.contains(inner.as_str()),
            PatternKind::Glob => glob(self.raw.as_bytes(), path.as_bytes()),
        }
    }
}

/// One pattern against a lowercased path (as the matcher does it; for tests and tools).
pub fn path_matches(pattern: &str, lower_path: &str) -> bool {
    let pattern = PathPattern::new(pattern);
    pattern.matches(&clean_path(lower_path, !pattern.keep_slashes))
}

/// `path.Match`-style glob: `*` any run without `/`, `?` one character but `/`, `[…]` a class.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    match pattern.first() {
        None => text.is_empty(),
        Some(b'*') => {
            let rest = &pattern[1..];
            let mut i = 0;
            loop {
                if glob(rest, &text[i..]) {
                    return true;
                }
                if i >= text.len() || text[i] == b'/' {
                    return false;
                }
                i += 1;
            }
        }
        Some(b'?') => !text.is_empty() && text[0] != b'/' && glob(&pattern[1..], &text[1..]),
        Some(b'[') => {
            let Some(end) = pattern.iter().position(|&c| c == b']') else {
                return !text.is_empty() && text[0] == b'[' && glob(&pattern[1..], &text[1..]);
            };
            let Some(&c) = text.first() else { return false };
            let mut class = &pattern[1..end];
            let negate = class.first() == Some(&b'^');
            if negate {
                class = &class[1..];
            }
            let mut hit = false;
            let mut k = 0;
            while k < class.len() {
                if k + 2 < class.len() && class[k + 1] == b'-' {
                    hit |= class[k] <= c && c <= class[k + 2];
                    k += 3;
                } else {
                    hit |= class[k] == c;
                    k += 1;
                }
            }
            hit != negate && c != b'/' && glob(&pattern[end + 1..], &text[1..])
        }
        Some(b'\\') if pattern.len() > 1 => {
            !text.is_empty() && text[0] == pattern[1] && glob(&pattern[2..], &text[1..])
        }
        Some(&p) => !text.is_empty() && text[0] == p && glob(&pattern[1..], &text[1..]),
    }
}

/// Whether `clean_path(path, true)` would change it: no leading slash, `//`, `/./`, `/../`, or a
/// trailing `/.` or `/..`. Most paths are clean and skip the copy.
pub fn needs_clean(path: &str) -> bool {
    !path.starts_with('/')
        || path.contains("//")
        || path.contains("/./")
        || path.contains("/../")
        || path.ends_with("/.")
        || path.ends_with("/..")
}

/// `path.Clean` that keeps a trailing slash; `merge_slashes` folds `//` into `/`.
pub fn clean_path(path: &str, merge_slashes: bool) -> String {
    let trailing = path.len() > 1 && path.ends_with('/');
    let mut out: Vec<&str> = Vec::new();
    for (i, seg) in path.split('/').enumerate() {
        match seg {
            "" => {
                if i != 0 && !merge_slashes {
                    out.push("");
                }
            }
            "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut cleaned = String::with_capacity(path.len());
    for seg in &out {
        cleaned.push('/');
        cleaned.push_str(seg);
    }
    if cleaned.is_empty() || (trailing && !cleaned.ends_with('/')) {
        cleaned.push('/');
    }
    cleaned
}

/// Host patterns are lowercase; `*.example.com` matches one label.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host
            .strip_suffix(suffix)
            .and_then(|rest| rest.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.'));
    }
    pattern.eq_ignore_ascii_case(host)
}

/// Header value with `*` wildcards at the ends.
fn value_matches(want: &str, value: &str) -> bool {
    if want == "*" {
        return true;
    }
    let starts = want.starts_with('*');
    let ends = want.ends_with('*') && want.len() > 1;
    let inner = want.trim_start_matches('*').trim_end_matches('*');
    match (starts, ends) {
        (true, true) => value.contains(inner),
        (true, false) => value.ends_with(inner),
        (false, true) => value.starts_with(inner),
        (false, false) => value == want,
    }
}

/// A `try_files` candidate; `wants_dir` when the pattern itself ends in `/`.
#[derive(Debug, Clone)]
pub struct TryFile {
    pub template: Template,
    pub wants_dir: bool,
}

impl TryFile {
    pub fn new(template: Template) -> TryFile {
        let wants_dir = template.source().ends_with('/');
        TryFile { template, wants_dir }
    }
}

/// `file { root …; try_files … }`: the first candidate that exists. As in Caddy, the filled-in
/// candidate is cleaned (`path.Clean`, so a trailing slash goes) and only a pattern that itself ends
/// in `/` (`{path}/`) looks for a directory; any other must be a file — `{path}` never matches a
/// directory, not even the site root. Candidates are built in one buffer, no copy per candidate.
#[derive(Debug, Clone)]
pub struct FileMatcher {
    pub root: Option<Arc<FileStore>>,
    pub try_files: Vec<TryFile>,
}

impl FileMatcher {
    fn matches(&self, ctx: &mut Ctx) -> bool {
        let Some(store) = self.root.as_ref().or(ctx.root.as_ref()).cloned() else {
            return false;
        };
        let files = store.files();
        let mut candidate = String::with_capacity(ctx.path().len() + 16);
        for try_file in &self.try_files {
            candidate.clear();
            try_file.template.render_into(ctx, &mut candidate);
            normalize_candidate(&mut candidate, try_file.wants_dir);
            let kind = if try_file.wants_dir {
                files.is_dir(&candidate).then_some("directory")
            } else if candidate == "/" {
                None
            } else {
                files.contains(&candidate).then_some("file")
            };
            if let Some(kind) = kind {
                ctx.file_match = Some(FileMatch {
                    relative: candidate,
                    root: store,
                    kind,
                });
                return true;
            }
        }
        false
    }
}

/// Caddy's candidate form, in place: a leading slash, cleaned (dropping a trailing slash), then a
/// trailing slash for directory patterns only.
fn normalize_candidate(buf: &mut String, wants_dir: bool) {
    if needs_clean(buf) {
        let with_slash = if buf.starts_with('/') {
            buf.clone()
        } else {
            format!("/{buf}")
        };
        *buf = clean_path(&with_slash, true);
    }
    if buf.len() > 1 && buf.ends_with('/') {
        buf.pop();
    }
    if wants_dir && !buf.ends_with('/') {
        buf.push('/');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_patterns() {
        assert!(path_matches("/assets/*", "/assets/app.js"));
        assert!(path_matches("/assets/*", "/assets/"));
        assert!(!path_matches("/assets/*", "/assets"));
        assert!(path_matches("/api/stream/*", "/api/stream/chat"));
        assert!(path_matches("*/", "/en/"));
        assert!(!path_matches("*/", "/en"));
        assert!(path_matches("*.html", "/a/b.html"));
        assert!(path_matches("/healthz", "/healthz"));
        assert!(!path_matches("/healthz", "/healthz/x"));
        assert!(path_matches("/a/*/c", "/a/b/c"));
        assert!(!path_matches("/a/*/c", "/a/b/x/c"));
        assert!(path_matches("*mid*", "/x/mid/y"));
        assert!(path_matches("*", "/anything"));
        assert!(path_matches("/EN/*", "/en/x"), "patterns are lowercased");
        // Cleaning: no bypass with dot segments or doubled slashes.
        assert!(path_matches("/_internal/*", "/x/../_internal/a"));
        assert!(path_matches("/_internal/*", "//_internal//a"));
        assert!(path_matches("/a//b", "/a//b"), "a pattern with // keeps them");
    }

    #[test]
    fn cleaning() {
        assert_eq!(clean_path("/a/./b/../c/", true), "/a/c/");
        assert_eq!(clean_path("/../../x", true), "/x");
        assert_eq!(clean_path("//a//b", true), "/a/b");
        assert_eq!(clean_path("/", true), "/");
        assert_eq!(clean_path("", true), "/");
        assert_eq!(clean_path("/a//b", false), "/a//b");
        for clean in ["/", "/en/contact", "/a/b/", "/.well-known/x", "/a.b/c..d"] {
            assert!(!needs_clean(clean), "{clean}");
            assert_eq!(clean_path(clean, true), clean);
        }
        for dirty in ["", "a", "//a", "/a/./b", "/a/../b", "/a/.", "/a/.."] {
            assert!(needs_clean(dirty), "{dirty}");
        }
    }

    #[test]
    fn candidates() {
        let normalized = |s: &str, dir: bool| {
            let mut buf = s.to_string();
            normalize_candidate(&mut buf, dir);
            buf
        };
        assert_eq!(normalized("/en/", false), "/en");
        assert_eq!(normalized("/en/", true), "/en/");
        assert_eq!(normalized("/en/contact.html", false), "/en/contact.html");
        assert_eq!(normalized("//x/../en/a", false), "/en/a");
        assert_eq!(normalized("en/a", false), "/en/a");
        assert_eq!(normalized("/", false), "/");
    }

    #[test]
    fn hosts_and_globs() {
        assert!(host_matches("*.example.com", "www.example.com"));
        assert!(!host_matches("*.example.com", "a.b.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
        assert!(host_matches("example.com", "EXAMPLE.com"));
        assert!(glob(b"/x/[a-c]?", b"/x/bz"));
        assert!(!glob(b"/x/[^a-c]", b"/x/b"));
    }
}
