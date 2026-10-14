//! Ready answers for the site's files. The files never change while the server runs, so when a
//! site's routes decide by the request path alone (plus Accept-Encoding), the answer for every
//! path that serves a file — status 200 with all its headers, and the 304 for its ETag — is worked
//! out once at startup by running the real handler chain; a request for that path is then a table
//! lookup and a copy of a header map.
//!
//! Kept are only answers that `file_server` gave from a stored file unchanged (not compressed on
//! the fly). What a request's Accept-Encoding changes is decided by which of zstd, br and gzip it
//! accepts and how their q-values compare — 26 cases in all — so answers are prepared for each and
//! any Accept-Encoding finds its own. Everything else goes through the chain as before: other paths
//! or other spellings of them, ranges, If-Match, an If-None-Match that is not exactly the answer's
//! ETag, methods other than GET and HEAD.

use crate::body::{Body, empty, full};
use crate::encode::AcceptEncoding;
use crate::files::{FileEntry, FileStore};
use crate::handler::{ConnInfo, Ctx, Handler, HeaderOp, Next, Route, encode_path};
use crate::matcher::{Matcher, MatcherSet};
use http::header::{ACCEPT_ENCODING, ETAG, IF_MATCH, IF_NONE_MATCH, RANGE};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use rustc_hash::{FxHashMap, FxHashSet};
use std::net::SocketAddr;
use std::sync::Arc;

/// One Accept-Encoding value for every signature (src/encode.rs): q-values 0, 0.2, 0.5 or 1 for
/// each of zstd, br and gzip give every way they can be accepted and ordered.
fn every_preference() -> Vec<(u16, String)> {
    const Q: [f32; 4] = [0.0, 0.2, 0.5, 1.0];
    let mut out: Vec<(u16, String)> = Vec::new();
    for zstd in Q {
        for br in Q {
            for gzip in Q {
                let value = [("zstd", zstd), ("br", br), ("gzip", gzip)]
                    .iter()
                    .filter(|(_, q)| *q > 0.0)
                    .map(|(name, q)| format!("{name};q={q}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let mut headers = HeaderMap::new();
                if let Ok(header) = HeaderValue::from_str(&value) {
                    headers.insert(ACCEPT_ENCODING, header);
                }
                let signature = AcceptEncoding::parse(&headers).signature();
                if !out.iter().any(|(s, _)| *s == signature) {
                    out.push((signature, value));
                }
            }
        }
    }
    out
}

/// Marks a request sent through the chain to prepare answers: `file_server` then marks its
/// response with `FromFile`, and `reverse_proxy` answers 502 at once instead of calling the
/// upstream (such answers are never kept).
#[derive(Debug, Clone, Copy)]
pub struct Preparing;

/// Marks a response that `file_server` made from a stored file as it is, and names the file
/// (`encode` takes the mark off when it compresses the body). Only for `Preparing` requests:
/// inserting it costs an allocation, which other requests need not pay.
#[derive(Debug, Clone)]
pub struct FromFile(pub Arc<FileEntry>);

/// A path's answer for each prepared Accept-Encoding signature.
type PerSignature = Box<[Option<Arc<Answer>>]>;

pub struct Answers {
    /// The Accept-Encoding signatures answers were prepared for.
    signatures: Vec<u16>,
    /// Request path (as sent) → its answer for each signature, in that order. Looked up first, so a
    /// request without a ready answer costs one hash lookup.
    paths: FxHashMap<Box<str>, PerSignature>,
    /// Bytes of the header values kept for good (interned).
    strings: usize,
}

struct Answer {
    headers: HeaderMap,
    /// The file sent: its bytes are taken (or, kept in LZ4, decompressed) for each response, never
    /// copied into the answer.
    file: Arc<FileEntry>,
    etag: Option<HeaderValue>,
    /// The 304 for an If-None-Match of exactly `etag`.
    not_modified: Option<HeaderMap>,
}

impl Answer {
    /// The same answer (bodies compared by where they are first: a file's body is one buffer).
    fn same(&self, other: &Answer) -> bool {
        Arc::ptr_eq(&self.file, &other.file)
            && self.headers == other.headers
            && self.etag == other.etag
            && self.not_modified == other.not_modified
    }
}

impl Answers {
    /// The ready answer for this request, if there is one.
    pub fn answer(&self, request: &http::request::Parts) -> Option<Response<Body>> {
        let head = match request.method {
            Method::GET => false,
            Method::HEAD => true,
            _ => return None,
        };
        let answers = self.paths.get(request.uri.path())?;
        let headers = &request.headers;
        if headers.contains_key(RANGE) || headers.contains_key(IF_MATCH) {
            return None;
        }
        let signature = AcceptEncoding::parse(headers).signature();
        let variant = self.signatures.iter().position(|s| *s == signature)?;
        let answer = answers[variant].as_ref()?;
        if let Some(if_none_match) = headers.get(IF_NONE_MATCH) {
            // What browsers send back is the ETag they got; anything else takes the long way.
            let (Some(etag), Some(not_modified)) = (&answer.etag, &answer.not_modified) else {
                return None;
            };
            if if_none_match != etag {
                return None;
            }
            let mut response = Response::new(empty());
            *response.status_mut() = StatusCode::NOT_MODIFIED;
            *response.headers_mut() = not_modified.clone();
            return Some(response);
        }
        let mut response = Response::new(if head { empty() } else { full(answer.file.body()) });
        *response.headers_mut() = answer.headers.clone();
        Some(response)
    }

    /// Paths with a ready answer for today's browsers ("gzip, deflate, br, zstd").
    pub fn paths(&self) -> usize {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip, deflate, br, zstd"));
        let signature = AcceptEncoding::parse(&headers).signature();
        let Some(variant) = self.signatures.iter().position(|s| *s == signature) else {
            return 0;
        };
        self.paths.values().filter(|answers| answers[variant].is_some()).count()
    }

    /// Memory the answers hold, counted from their parts: header maps, the path table, the
    /// header values. Bodies are not counted: they are the files' own bytes.
    pub fn bytes(&self) -> u64 {
        use std::mem::size_of;
        fn map(headers: &HeaderMap) -> usize {
            let slots = headers.capacity();
            slots * (size_of::<http::HeaderName>() + size_of::<HeaderValue>() + 16) + slots.next_power_of_two() * 4
        }
        let mut seen = FxHashSet::default();
        let mut total = self.strings;
        for (path, answers) in &self.paths {
            total += path.len() + size_of::<(Box<str>, PerSignature)>() + 8;
            total += answers.len() * size_of::<Option<Arc<Answer>>>();
            for answer in answers.iter().flatten() {
                if seen.insert(Arc::as_ptr(answer)) {
                    total += size_of::<Answer>() + 16 + map(&answer.headers);
                    total += answer.not_modified.as_ref().map_or(0, map);
                }
            }
        }
        total as u64
    }

    /// Distinct answers held (several signatures often share one).
    pub fn answers(&self) -> usize {
        let mut seen = FxHashSet::default();
        for answer in self.paths.values().flat_map(|answers| answers.iter().flatten()) {
            seen.insert(Arc::as_ptr(answer));
        }
        seen.len()
    }

    /// Works the answers out by running `routes` for every path that may serve a file, the paths
    /// shared out over threads, one per CPU, each with its own runtime (it blocks until done);
    /// `None` when the routes look at more of a request than its path (then nothing can be
    /// prepared).
    pub fn prepare(routes: &Arc<[Route]>, tls: bool) -> Option<Answers> {
        if !decided_by_path(routes) {
            return None;
        }
        let mut stores = Vec::new();
        collect_stores(routes, &mut stores);
        let candidates = candidate_paths(&stores);
        let conn = Arc::new(ConnInfo {
            remote: SocketAddr::from(([127, 0, 0, 1], 0)),
            tls,
            trusted: false,
        });
        let (signatures, accepts): (Vec<u16>, Vec<String>) = every_preference().into_iter().unzip();
        let accepts: Arc<[String]> = accepts.into();
        let workers = std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .min(candidates.len())
            .max(1);
        let mut shares: Vec<Vec<String>> = vec![Vec::new(); workers];
        for (i, path) in candidates.into_iter().enumerate() {
            shares[i % workers].push(path);
        }
        // The threads only work answers out; what is kept is built here, so their memory (chain
        // runs, buffers) goes back whole when they end instead of being pinned by a few answers.
        let drafted = crate::files::on_every_cpu(&shares, |share| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime to prepare answers on");
            runtime.block_on(async {
                let mut drafts = Vec::new();
                for path in share {
                    let (answers, slots) = prepare_path(routes, &conn, path, &accepts).await;
                    if !answers.is_empty() {
                        drafts.push((path.clone(), answers, slots));
                    }
                }
                drafts
            })
        });
        let mut strings = FxHashMap::default();
        let mut paths = FxHashMap::default();
        for (path, drafts, slots) in drafted.into_iter().flatten() {
            let kept: Vec<Arc<Answer>> = drafts.iter().map(|draft| Arc::new(draft.kept(&mut strings))).collect();
            let answers: PerSignature = slots.iter().map(|slot| slot.map(|i| kept[i].clone())).collect();
            paths.insert(Box::from(path.as_str()), answers);
        }
        let strings = strings.keys().map(String::len).sum();
        Some(Answers {
            signatures,
            paths,
            strings,
        })
    }
}

impl Answer {
    /// The answer to keep: its header values made `'static` (interned in `strings`), allocated by
    /// the calling thread.
    fn kept(&self, strings: &mut FxHashMap<String, &'static str>) -> Answer {
        let headers = permanent(&self.headers, strings);
        Answer {
            etag: headers.get(ETAG).cloned(),
            not_modified: self.not_modified.as_ref().map(|h| permanent(h, strings)),
            headers,
            file: self.file.clone(),
        }
    }
}

/// A path's distinct answers, and for each Accept-Encoding preference which of them (the same
/// sibling chosen: the same answer).
async fn prepare_path(
    routes: &Arc<[Route]>,
    conn: &Arc<ConnInfo>,
    path: &str,
    accepts: &[String],
) -> (Vec<Answer>, Vec<Option<usize>>) {
    let mut answers: Vec<Answer> = Vec::new();
    let mut slots = Vec::with_capacity(accepts.len());
    for accept in accepts {
        let slot = prepare_one(routes, conn, path, accept).await.map(|answer| {
            answers.iter().position(|other| other.same(&answer)).unwrap_or_else(|| {
                answers.push(answer);
                answers.len() - 1
            })
        });
        slots.push(slot);
    }
    (answers, slots)
}

/// A draft: the chain's own header maps.
async fn prepare_one(routes: &Arc<[Route]>, conn: &Arc<ConnInfo>, path: &str, accept: &str) -> Option<Answer> {
    let response = run(routes, conn, path, accept, None).await?;
    if response.status() != StatusCode::OK {
        return None;
    }
    let file = response.extensions().get::<FromFile>()?.0.clone();
    let (parts, _) = response.into_parts();
    let headers = parts.headers;
    let etag = headers.get(ETAG).cloned();
    let mut not_modified = None;
    if let Some(etag) = &etag
        && let Some(response) = run(routes, conn, path, accept, Some(etag.clone())).await
        && response.status() == StatusCode::NOT_MODIFIED
        && response.extensions().get::<FromFile>().is_some()
    {
        not_modified = Some(response.into_parts().0.headers);
    }
    Some(Answer {
        headers,
        file,
        etag,
        not_modified,
    })
}

/// One GET through the chain, as a client would send it.
async fn run(
    routes: &Arc<[Route]>,
    conn: &Arc<ConnInfo>,
    path: &str,
    accept: &str,
    if_none_match: Option<HeaderValue>,
) -> Option<Response<Body>> {
    let mut request = Request::get(path);
    if !accept.is_empty() {
        request = request.header(ACCEPT_ENCODING, accept);
    }
    if let Some(etag) = if_none_match {
        request = request.header(IF_NONE_MATCH, etag);
    }
    let (mut parts, body) = request.body(empty()).ok()?.into_parts();
    parts.extensions.insert(Preparing);
    let ctx = Ctx::new(conn.clone(), parts, body, conn.remote.ip());
    Some(Next::start(routes.clone()).run(ctx).await)
}

/// The header map with every value made `'static` (interned; the answers live as long as the
/// process), so copying it for a response counts no references.
fn permanent(headers: &HeaderMap, strings: &mut FxHashMap<String, &'static str>) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        let value = match value.to_str() {
            Ok(text) => {
                let text = match strings.get(text) {
                    Some(interned) => *interned,
                    None => {
                        let interned: &'static str = Box::leak(text.to_owned().into_boxed_str());
                        strings.insert(text.to_owned(), interned);
                        interned
                    }
                };
                HeaderValue::from_static(text)
            }
            Err(_) => value.clone(),
        };
        out.append(name.clone(), value);
    }
    out
}

/// Request paths that may serve a stored file: the file's own path, without `.html`, and the
/// directory of an index file. Precompressed siblings are left out; the chain decides the rest.
fn candidate_paths(stores: &[Arc<FileStore>]) -> Vec<String> {
    let mut paths = FxHashSet::default();
    for store in stores {
        for file in store.paths() {
            let sibling = [".br", ".zst", ".gz"]
                .iter()
                .any(|suffix| file.strip_suffix(suffix).is_some_and(|base| store.file(base).is_some()));
            if sibling {
                continue;
            }
            paths.insert(encode_path(file));
            if let Some(stem) = file.strip_suffix(".html") {
                paths.insert(encode_path(stem));
            }
            for index in ["index.html", "index.txt"] {
                if let Some(dir) = file.strip_suffix(index)
                    && dir.ends_with('/')
                {
                    paths.insert(encode_path(dir));
                }
            }
        }
    }
    let mut paths: Vec<String> = paths.into_iter().collect();
    paths.sort();
    paths
}

/// Every file store the routes read from.
fn collect_stores(routes: &[Route], out: &mut Vec<Arc<FileStore>>) {
    fn add(out: &mut Vec<Arc<FileStore>>, store: &Arc<FileStore>) {
        if !out.iter().any(|s| Arc::ptr_eq(s, store)) {
            out.push(store.clone());
        }
    }
    fn from_matchers(set: &MatcherSet, out: &mut Vec<Arc<FileStore>>) {
        for matcher in &set.matchers {
            match matcher {
                Matcher::File(file) => {
                    if let Some(store) = &file.root {
                        add(out, store);
                    }
                }
                Matcher::Not(sets) => sets.iter().for_each(|s| from_matchers(s, out)),
                _ => {}
            }
        }
    }
    for route in routes {
        if let Some(set) = &route.matcher {
            from_matchers(set, out);
        }
        match &route.handler {
            Handler::Root(store) => add(out, store),
            Handler::Files(files) => {
                if let Some(store) = &files.root {
                    add(out, store);
                }
            }
            Handler::Subroute(list) => collect_stores(list, out),
            _ => {}
        }
    }
}

/// The routes reach their decisions and build their responses from the request path alone (and
/// Accept-Encoding, which the answers are keyed by): no matcher on host, method, headers or
/// addresses, no `request_header`, no placeholder other than path-derived ones. What a request is
/// answered with by a handler that ends the chain elsewhere (redirect, respond, proxy) does not
/// matter: those answers are never kept.
fn decided_by_path(routes: &[Route]) -> bool {
    routes.iter().all(|route| {
        route.matcher.as_ref().is_none_or(MatcherSet::depends_on_path_only)
            && match &route.handler {
                Handler::Header { ops, .. } => ops.iter().all(HeaderOp::depends_on_path_only),
                Handler::RequestHeader(_) => false,
                Handler::Rewrite(to) => to.depends_on_path_only(),
                Handler::Subroute(list) => decided_by_path(list),
                Handler::Root(_)
                | Handler::StripPrefix(_)
                | Handler::Encode(_)
                | Handler::Files(_)
                | Handler::Redir { .. }
                | Handler::Respond { .. }
                | Handler::Proxy(_) => true,
            }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_way_to_accept_and_order_three_encodings() {
        // Accepted subsets and their weak orders: 1 + 3·1 + 3·3 + 13.
        let preferences = every_preference();
        assert_eq!(preferences.len(), 26);
        let browsers = [
            "gzip, deflate, br, zstd",
            "gzip, deflate, br",
            "gzip, deflate",
            "",
            "br",
            "*",
        ];
        for value in browsers {
            let mut headers = HeaderMap::new();
            headers.insert(ACCEPT_ENCODING, HeaderValue::from_static(value));
            let signature = AcceptEncoding::parse(&headers).signature();
            assert!(preferences.iter().any(|(s, _)| *s == signature), "{value:?}");
        }
    }
}
