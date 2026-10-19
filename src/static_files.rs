//! `file_server`: files from memory with Caddy's semantics — index files, canonical trailing
//! slashes (308), precompressed siblings chosen by Accept-Encoding, `Vary: Accept-Encoding`, 405 for
//! methods other than GET/HEAD — and Go's `http.ServeContent` behaviour (If-None-Match → 304, If-Match
//! → 412, byte ranges → 206, several → multipart/byteranges, unsatisfiable → 416). The ETag is the
//! hash of the bytes sent; there is no Last-Modified (files in memory have no meaningful date).

use crate::body::{Body, empty, full};
use crate::encode::Encoding;
use crate::extensions::{Lookup, REPRESENTATIONS, Representation};
use crate::files::{FileEntry, FileStore};
use crate::handler::{Ctx, Next};
use crate::matcher::{clean_path, needs_clean};
use http::header::{
    ACCEPT_RANGES, ALLOW, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, IF_MATCH,
    IF_NONE_MATCH, IF_RANGE, LAST_MODIFIED, LOCATION, RANGE, VARY, X_CONTENT_TYPE_OPTIONS,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug)]
pub struct FileServer {
    pub root: Option<Arc<FileStore>>,
    pub index: Vec<String>,
    pub precompressed: Vec<Encoding>,
    /// Patterns: without `/` they match any path element, with `/` the path from the root.
    pub hide: Vec<String>,
    pub pass_thru: bool,
    pub canonical_uris: bool,
}

impl Default for FileServer {
    fn default() -> Self {
        FileServer {
            root: None,
            index: vec!["index.html".into(), "index.txt".into()],
            precompressed: Vec::new(),
            hide: Vec::new(),
            pass_thru: false,
            canonical_uris: true,
        }
    }
}

impl FileServer {
    pub async fn serve(&self, mut ctx: Ctx, next: Next) -> Response<Body> {
        let Some(store) = self.root.clone().or_else(|| ctx.root.clone()) else {
            return ctx.fail(StatusCode::NOT_FOUND, Some("filesystem not found".into()));
        };
        // One buffer for the file, directory and index lookups.
        let mut key = if needs_clean(ctx.path()) {
            clean_path(ctx.path(), true)
        } else {
            ctx.path().to_string()
        };
        let mut implicit_index = false;
        let mut found: Option<(String, Arc<FileEntry>)> = None;
        // The files as they are now: the same for every lookup of this request.
        let mut files = store.files();
        if !key.ends_with('/')
            && let Some(entry) = files.file(&key)
        {
            let entry = entry.clone();
            found = Some((key, entry));
        } else {
            if !key.ends_with('/') {
                key.push('/');
            }
            if files.is_dir(&key) {
                let dir_len = key.len();
                for index in &self.index {
                    key.truncate(dir_len);
                    key.push_str(index);
                    if self.hidden(&key) {
                        continue;
                    }
                    if let Some(entry) = files.file(&key) {
                        let entry = entry.clone();
                        found = Some((key, entry));
                        implicit_index = true;
                        break;
                    }
                }
            }
        }
        let Some((file, entry)) = found.filter(|(file, _)| !self.hidden(file)) else {
            drop(files);
            if self.pass_thru {
                return next.run(ctx).await;
            }
            return ctx.fail(StatusCode::NOT_FOUND, None);
        };

        if self.canonical_uris {
            // Only when the last path element was not rewritten (Caddy #4205: no redirect loops).
            let orig_uri = ctx.orig_uri.clone();
            let orig_path = percent_encoding::percent_decode_str(orig_uri.path()).decode_utf8_lossy();
            if base(&orig_path) == base(ctx.path()) {
                let to = if implicit_index && !orig_path.ends_with('/') {
                    Some(format!("{orig_path}/"))
                } else if !implicit_index && orig_path.ends_with('/') && orig_path.len() > 1 {
                    Some(orig_path[..orig_path.len() - 1].to_string())
                } else {
                    None
                };
                if let Some(to) = to {
                    // No path-based open redirects ("//evil.example", "/\evil.example").
                    let to = crate::handler::same_site_location(to);
                    let mut location = crate::handler::encode_path(&to);
                    if let Some(query) = ctx.req.uri.query() {
                        location.push('?');
                        location.push_str(query);
                    }
                    // Go's http.Redirect, which Caddy uses: a short HTML body for GET and HEAD.
                    let body = format!("<a href=\"{}\">Permanent Redirect</a>.\n\n", html_escape(&location));
                    let mut response = Response::new(full(body));
                    *response.status_mut() = StatusCode::PERMANENT_REDIRECT;
                    response
                        .headers_mut()
                        .insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
                    if let Ok(value) = HeaderValue::from_str(&location) {
                        response.headers_mut().insert(LOCATION, value);
                    }
                    return ctx.respond(response);
                }
            }
        }

        // Compression dictionaries (RFC 9842): the client holds an earlier version of this file, or
        // another of the site's, and takes `dcz`: the file as a delta to it, worked out once.
        let mut delta = None;
        if ctx.error.is_none()
            && entry.sha256.is_some()
            && let Some(hash) = offered_dictionary(&ctx.req)
            && let Some(dictionary) = store.dictionary(&hash)
            && !self.hidden(&dictionary.key)
        {
            drop(files);
            delta = self::delta(&entry, dictionary.bytes, hash).await;
            files = store.files();
        }

        let mut response = Response::new(empty());
        // Sized for this response and the site's headers added later: no regrowing.
        *response.headers_mut() = HeaderMap::with_capacity(24);
        response
            .headers_mut()
            .append(VARY, HeaderValue::from_static("Accept-Encoding"));
        // The representation sent: the file, a precompressed sibling, or — for a file without one —
        // a compressed variant made in the background (src/variants.rs); body, ETag, length are its.
        let mut variant: Option<Arc<FileEntry>> = None;
        // Encodings the client prefers to the one it gets, which a variant could give it.
        let mut wanted = [None::<crate::encode::Encoding>; 3];
        let mut chosen: &Arc<FileEntry> = &entry;
        let mut chosen_encoding = None;
        let mut sidecar_key = String::with_capacity(file.len() + 4);
        for encoding in ctx.accept_encoding().ranked(&self.precompressed) {
            sidecar_key.clear();
            sidecar_key.push_str(&file);
            sidecar_key.push_str(encoding.suffix());
            if let Some(sidecar) = files.file(&sidecar_key) {
                chosen = sidecar;
                chosen_encoding = Some(encoding);
                break;
            }
            match REPRESENTATIONS.lookup(&entry, encoding) {
                Lookup::Have(made) => {
                    variant = Some(made);
                    chosen_encoding = Some(encoding);
                    break;
                }
                Lookup::Missing => {
                    if let Some(slot) = wanted.iter_mut().find(|slot| slot.is_none()) {
                        *slot = Some(encoding);
                    }
                }
                Lookup::No => {}
            }
        }
        if let Some(made) = &variant {
            chosen = made;
        }
        if wanted[0].is_some() && ctx.error.is_none() {
            if ctx.req.extensions.get::<crate::memo::Preparing>().is_some() {
                // Not a ready answer: live requests come here and ask for the variant.
                ctx.req.extensions.insert(crate::memo::Unkept);
            } else if ctx.req.method == Method::GET || ctx.req.method == Method::HEAD {
                let encodings: Vec<_> = wanted.iter().flatten().copied().collect();
                REPRESENTATIONS.wanted(&entry, &store, &encodings);
            }
        }
        // The delta, when it is smaller than the best the client could get otherwise.
        if let Some((delta, etag)) = delta
            && delta.len() < chosen.len()
        {
            let content_type = entry.content_type.clone();
            drop(files);
            return serve_delta(ctx, response, delta, etag, content_type);
        }
        // Too large for memory (WEB_MAX_FILE_IN_MEMORY): opened now, sent as it is read.
        if let Some(path) = chosen.on_disk() {
            let path = path.to_path_buf();
            let content_type = entry.content_type.clone();
            drop(files);
            return serve_disk(ctx, response, path, chosen_encoding, content_type).await;
        }
        let etag = chosen.etag.clone();
        let length = chosen.length.clone();

        // In `handle_errors` routes the file is the error page: sent whole, with the failure's
        // status, whatever the method, preconditions and ranges (Caddy keeps the status but lets
        // them through: an error page cut to a range, or a bare 404 for a matching ETag).
        let error_status = ctx.error.as_ref().map(|e| e.status);
        let method = ctx.req.method.clone();
        if error_status.is_none() && method != Method::GET && method != Method::HEAD {
            response
                .headers_mut()
                .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
            *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
            let response = ctx.respond(response);
            return ctx.failed(response, None);
        }

        // Preconditions (RFC 9110 §13.2.2, as Go's http.ServeContent orders them). A 304 carries the
        // ETag but not Content-Type and Content-Encoding, so it is answered before they are set.
        let request = &ctx.req.headers;
        let if_match_failed = error_status.is_none()
            && request
                .get(IF_MATCH)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|list| !etag_list_matches(list, &etag, true));
        if !if_match_failed
            && error_status.is_none()
            && request
                .get(IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|list| etag_list_matches(list, &etag, false))
        {
            response.headers_mut().insert(ETAG, etag);
            *response.status_mut() = StatusCode::NOT_MODIFIED;
            if crate::memo::keeps(&ctx.req) {
                response.extensions_mut().insert(crate::memo::FromFile(chosen.clone()));
            }
            return ctx.respond(response);
        }
        let headers = response.headers_mut();
        headers.insert(ETAG, etag.clone());
        if let Some(encoding) = chosen_encoding {
            headers.insert(CONTENT_ENCODING, HeaderValue::from_static(encoding.name()));
        }
        if !ctx.pre_headers.contains_key(CONTENT_TYPE)
            && let Some(kind) = &entry.content_type
        {
            headers.insert(CONTENT_TYPE, kind.clone());
        }
        if if_match_failed {
            *response.status_mut() = StatusCode::PRECONDITION_FAILED;
            return ctx.respond(response);
        }

        // Ranges (Go's http.ServeContent: of the representation sent, also a compressed one).
        let total = chosen.len() as u64;
        let mut status = error_status.unwrap_or(StatusCode::OK);
        let range_allowed = error_status.is_none()
            && match request.get(IF_RANGE).and_then(|v| v.to_str().ok()) {
                Some(if_range) => {
                    let if_range = if_range.trim();
                    if_range.starts_with('"') && if_range == etag.to_str().unwrap_or_default()
                }
                None => true,
            };
        let range_header = request
            .get(RANGE)
            .and_then(|v| v.to_str().ok())
            .filter(|_| range_allowed);
        let mut ranges = match range_header.map(|h| parse_ranges(h, total)) {
            None => Vec::new(),
            Some(Ok(ranges)) => ranges,
            Some(Err(RangeError::NoOverlap)) if total == 0 => Vec::new(),
            Some(Err(RangeError::NoOverlap)) => {
                let value = format!("bytes */{total}");
                response
                    .headers_mut()
                    .insert(CONTENT_RANGE, HeaderValue::from_str(&value).expect("ascii"));
                return serve_error(&mut ctx, response, "invalid range: failed to overlap");
            }
            Some(Err(RangeError::Invalid)) => return serve_error(&mut ctx, response, "invalid range"),
        };
        // As Go: ranges that add up to more than the file are ignored. Also ignored (the whole file
        // is sent instead): more than MAX_RANGES, or ranges that overlap — a multipart answer is
        // built in memory, and one Range header could otherwise ask for 100 000 one-byte parts.
        if ranges.iter().map(|(_, len)| len).sum::<u64>() > total || !ranges_are_bounded(&ranges) {
            ranges.clear();
        }
        // The bytes, only when they are sent or cut into ranges (a file kept in LZ4 is decompressed
        // here; a HEAD needs only the headers).
        let mut body = if method != Method::HEAD || !ranges.is_empty() {
            chosen.body()
        } else {
            bytes::Bytes::new()
        };
        if ranges.len() == 1 {
            let (start, length) = ranges[0];
            body = body.slice(start as usize..(start + length) as usize);
            status = StatusCode::PARTIAL_CONTENT;
            let value = content_range(start, length, total);
            response
                .headers_mut()
                .insert(CONTENT_RANGE, HeaderValue::from_str(&value).expect("ascii"));
        } else if ranges.len() > 1 {
            let part_type = response
                .headers()
                .get(CONTENT_TYPE)
                .or_else(|| ctx.pre_headers.get(CONTENT_TYPE))
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let boundary = boundary();
            let mut multipart = Vec::new();
            for (i, (start, length)) in ranges.iter().enumerate() {
                let open = if i == 0 {
                    format!("--{boundary}\r\n")
                } else {
                    format!("\r\n--{boundary}\r\n")
                };
                multipart.extend_from_slice(open.as_bytes());
                multipart.extend_from_slice(
                    format!("Content-Range: {}\r\n", content_range(*start, *length, total)).as_bytes(),
                );
                if let Some(part_type) = &part_type {
                    multipart.extend_from_slice(format!("Content-Type: {part_type}\r\n").as_bytes());
                }
                multipart.extend_from_slice(b"\r\n");
                multipart.extend_from_slice(&body[*start as usize..(*start + *length) as usize]);
            }
            multipart.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            body = bytes::Bytes::from(multipart);
            status = StatusCode::PARTIAL_CONTENT;
            let value = format!("multipart/byteranges; boundary={boundary}");
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_str(&value).expect("ascii"));
        }
        response
            .headers_mut()
            .insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        *response.status_mut() = status;
        let length = if ranges.is_empty() {
            length
        } else {
            HeaderValue::from(body.len() as u64)
        };
        response.headers_mut().insert(CONTENT_LENGTH, length);
        if method != Method::HEAD {
            *response.body_mut() = full(body);
        }
        if status == StatusCode::OK && crate::memo::keeps(&ctx.req) {
            response.extensions_mut().insert(crate::memo::FromFile(chosen.clone()));
        }
        ctx.respond(response)
    }

    fn hidden(&self, file: &str) -> bool {
        self.hide.iter().any(|pattern| {
            if pattern.contains('/') {
                let pattern = if pattern.starts_with('/') {
                    pattern.clone()
                } else {
                    format!("/{pattern}")
                };
                crate::caddyfile::wildcard(&pattern, file)
                    || file.starts_with(&format!("{}/", pattern.trim_end_matches('/')))
            } else {
                file.split('/')
                    .any(|element| crate::caddyfile::wildcard(pattern, element))
            }
        })
    }
}

/// A file served from disk (WEB_MAX_FILE_IN_MEMORY): opened for this response, its ETag and length
/// from the file as it is now (so a file changed since it was found is still answered right), its
/// bytes read as they are sent (`DiskBody`). The preconditions are those of a file in memory; of
/// ranges at most one is served — a request for several gets the whole file, which RFC 9110
/// allows — so nothing is built in memory.
async fn serve_disk(
    mut ctx: Ctx,
    mut response: Response<Body>,
    path: PathBuf,
    encoding: Option<Encoding>,
    content_type: Option<HeaderValue>,
) -> Response<Body> {
    let error_status = ctx.error.as_ref().map(|e| e.status);
    let method = ctx.req.method.clone();
    if error_status.is_none() && method != Method::GET && method != Method::HEAD {
        response
            .headers_mut()
            .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        let response = ctx.respond(response);
        return ctx.failed(response, None);
    }
    let opening = path.clone();
    let opened = tokio::task::spawn_blocking(move || -> std::io::Result<_> {
        let file = std::fs::File::open(&opening)?;
        let metadata = file.metadata()?;
        Ok((file, metadata))
    })
    .await;
    let (mut file, metadata) = match opened {
        Ok(Ok(opened)) => opened,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => return ctx.fail(StatusCode::NOT_FOUND, None),
        Ok(Err(e)) => {
            tracing::warn!(path = %path.display(), error = %e, "cannot open a site file");
            return ctx.fail(StatusCode::INTERNAL_SERVER_ERROR, None);
        }
        Err(_) => return ctx.fail(StatusCode::INTERNAL_SERVER_ERROR, None),
    };
    let etag = HeaderValue::from_str(&crate::files::disk_etag(&metadata)).expect("ascii");
    let total = metadata.len();

    let request = &ctx.req.headers;
    let if_match_failed = error_status.is_none()
        && request
            .get(IF_MATCH)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|list| !etag_list_matches(list, &etag, true));
    if !if_match_failed
        && error_status.is_none()
        && request
            .get(IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|list| etag_list_matches(list, &etag, false))
    {
        response.headers_mut().insert(ETAG, etag);
        *response.status_mut() = StatusCode::NOT_MODIFIED;
        return ctx.respond(response);
    }
    let headers = response.headers_mut();
    headers.insert(ETAG, etag.clone());
    if let Some(encoding) = encoding {
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static(encoding.name()));
    }
    if !ctx.pre_headers.contains_key(CONTENT_TYPE)
        && let Some(kind) = content_type
    {
        headers.insert(CONTENT_TYPE, kind);
    }
    if if_match_failed {
        *response.status_mut() = StatusCode::PRECONDITION_FAILED;
        return ctx.respond(response);
    }

    let range_allowed = error_status.is_none()
        && match request.get(IF_RANGE).and_then(|v| v.to_str().ok()) {
            Some(if_range) => {
                let if_range = if_range.trim();
                if_range.starts_with('"') && if_range == etag.to_str().unwrap_or_default()
            }
            None => true,
        };
    let range_header = request
        .get(RANGE)
        .and_then(|v| v.to_str().ok())
        .filter(|_| range_allowed);
    let ranges = match range_header.map(|h| parse_ranges(h, total)) {
        None => Vec::new(),
        Some(Ok(ranges)) => ranges,
        Some(Err(RangeError::NoOverlap)) if total == 0 => Vec::new(),
        Some(Err(RangeError::NoOverlap)) => {
            let value = format!("bytes */{total}");
            response
                .headers_mut()
                .insert(CONTENT_RANGE, HeaderValue::from_str(&value).expect("ascii"));
            return serve_error(&mut ctx, response, "invalid range: failed to overlap");
        }
        Some(Err(RangeError::Invalid)) => return serve_error(&mut ctx, response, "invalid range"),
    };
    let (start, length, status) = match ranges[..] {
        [(start, length)] if start + length <= total => {
            let value = content_range(start, length, total);
            response
                .headers_mut()
                .insert(CONTENT_RANGE, HeaderValue::from_str(&value).expect("ascii"));
            (start, length, StatusCode::PARTIAL_CONTENT)
        }
        _ => (0, total, error_status.unwrap_or(StatusCode::OK)),
    };
    let headers = response.headers_mut();
    headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    headers.insert(CONTENT_LENGTH, HeaderValue::from(length));
    *response.status_mut() = status;
    if method != Method::HEAD && length > 0 {
        if start > 0 {
            use std::io::Seek;
            if let Err(e) = file.seek(std::io::SeekFrom::Start(start)) {
                tracing::warn!(path = %path.display(), error = %e, "cannot read a site file");
                return ctx.fail(StatusCode::INTERNAL_SERVER_ERROR, None);
            }
        }
        *response.body_mut() = crate::body::boxed(DiskBody::new(file, length));
    }
    ctx.respond(response)
}

/// A piece of a file being read on the blocking pool: the file back, and the bytes.
type Reading = tokio::task::JoinHandle<std::io::Result<(std::fs::File, Vec<u8>)>>;

/// How much of a file on disk is read at a time.
const PIECE: usize = 64 << 10;

/// `remaining` bytes of a file, read on the blocking pool a piece at a time — the next piece is
/// being read while the last one is sent.
struct DiskBody {
    remaining: u64,
    reading: Option<Reading>,
}

impl DiskBody {
    fn new(file: std::fs::File, remaining: u64) -> DiskBody {
        let mut body = DiskBody {
            remaining,
            reading: None,
        };
        body.read_next(file);
        body
    }

    /// Starts reading the next piece (none when everything has been read). The piece's buffer is
    /// allocated here, on the connection's thread, which also frees it once sent: allocated on the
    /// blocking pool's threads instead, each with a heap of its own, the pieces stayed in those
    /// heaps (16 downloads at once kept over 200 MB resident).
    fn read_next(&mut self, mut file: std::fs::File) {
        let want = (self.remaining.min(PIECE as u64)) as usize;
        if want == 0 {
            return;
        }
        let mut piece = vec![0u8; want];
        self.reading = Some(tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let mut filled = 0;
            while filled < want {
                match file.read(&mut piece[filled..])? {
                    0 => break,
                    n => filled += n,
                }
            }
            piece.truncate(filled);
            Ok((file, piece))
        }));
    }
}

impl http_body::Body for DiskBody {
    type Data = bytes::Bytes;
    type Error = crate::body::BoxError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<bytes::Bytes>, Self::Error>>> {
        use std::task::Poll;
        let Some(reading) = self.reading.as_mut() else {
            return Poll::Ready(None);
        };
        use std::future::Future;
        let read = std::task::ready!(std::pin::Pin::new(reading).poll(cx));
        self.reading = None;
        let (file, piece) = match read {
            Ok(Ok(read)) => read,
            Ok(Err(e)) => return Poll::Ready(Some(Err(Box::new(e)))),
            Err(e) => return Poll::Ready(Some(Err(Box::new(e)))),
        };
        if piece.is_empty() {
            return Poll::Ready(Some(Err("the file got shorter while it was being sent".into())));
        }
        self.remaining -= piece.len() as u64;
        self.read_next(file);
        Poll::Ready(Some(Ok(http_body::Frame::data(bytes::Bytes::from(piece)))))
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0 && self.reading.is_none()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(self.remaining)
    }
}

/// RFC 9842 (Compression Dictionary Transport): the SHA-256 of a dictionary the client holds.
pub const AVAILABLE_DICTIONARY: HeaderName = HeaderName::from_static("available-dictionary");

/// The dictionary a request offers for a delta (RFC 9842): the SHA-256 in `Available-Dictionary`,
/// when `Accept-Encoding` takes `dcz`, the request is for the whole file, and — as §9.3.3 asks —
/// its response is readable by the page that asked: same-origin, or a navigation (a cross-origin
/// request gets no delta; with CORS the answer's `Access-Control-Allow-Origin` is not known here).
fn offered_dictionary(request: &http::request::Parts) -> Option<[u8; 32]> {
    if (request.method != Method::GET && request.method != Method::HEAD) || request.headers.contains_key(RANGE) {
        return None;
    }
    let headers = &request.headers;
    let value = headers.get(AVAILABLE_DICTIONARY)?.to_str().ok()?.trim();
    let hash: [u8; 32] = base64_decode(value.strip_prefix(':')?.strip_suffix(':')?)?
        .try_into()
        .ok()?;
    let takes_dcz = headers
        .get_all(http::header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|item| {
            let mut parts = item.split(';');
            let coding = parts.next().unwrap_or("").trim();
            let refused = parts.any(|p| {
                let p = p.trim();
                p.strip_prefix("q=")
                    .is_some_and(|q| q.trim().parse::<f32>().is_ok_and(|q| q <= 0.0))
            });
            coding.eq_ignore_ascii_case("dcz") && !refused
        });
    let named = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let readable = matches!(
        (named("sec-fetch-site"), named("sec-fetch-mode")),
        (None, _) | (Some("same-origin"), _) | (_, Some("navigate"))
    );
    (takes_dcz && readable).then_some(hash)
}

/// Standard base64 with padding (RFC 4648), as in a structured field byte sequence.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let text = text.as_bytes();
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for quad in text.chunks(4) {
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut n = 0u32;
        for &c in &quad[..4 - pad] {
            n = (n << 6) | value(c)?;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

/// Deltas worked out, by file (its ETag) and dictionary: shared by every client that holds that
/// dictionary — after a deploy, all those that had the version before.
struct Deltas {
    by: rustc_hash::FxHashMap<(String, [u8; 32]), bytes::Bytes>,
    /// Oldest first, for making room.
    order: std::collections::VecDeque<(String, [u8; 32])>,
    bytes: usize,
}

/// What the deltas kept may take, over all sites.
const DELTAS: usize = 32 << 20;

static KEPT_DELTAS: std::sync::LazyLock<std::sync::Mutex<Deltas>> = std::sync::LazyLock::new(|| {
    std::sync::Mutex::new(Deltas {
        by: Default::default(),
        order: Default::default(),
        bytes: 0,
    })
});

/// `entry` as a `dcz` delta to `dictionary` (whose hash is `hash`), with its ETag: from those kept,
/// or worked out on the blocking pool (once per file and dictionary, whoever asks first waits).
async fn delta(entry: &FileEntry, dictionary: bytes::Bytes, hash: [u8; 32]) -> Option<(bytes::Bytes, HeaderValue)> {
    let file_etag = entry.etag.to_str().ok()?;
    let short = crate::files::base64url(&hash[..6]);
    let etag = HeaderValue::from_str(&format!("{}d{short}\"", file_etag.trim_end_matches('"'))).ok()?;
    let key = (file_etag.to_string(), hash);
    let kept = |deltas: &Deltas| deltas.by.get(&key).cloned();
    if let Some(found) = kept(&KEPT_DELTAS.lock().unwrap_or_else(std::sync::PoisonError::into_inner)) {
        return Some((found, etag));
    }
    let content = entry.body();
    let made = tokio::task::spawn_blocking(move || dcz(&content, &dictionary, &hash))
        .await
        .ok()??;
    let mut deltas = KEPT_DELTAS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if made.len() <= DELTAS / 8 && !deltas.by.contains_key(&key) {
        deltas.bytes += made.len();
        deltas.by.insert(key.clone(), made.clone());
        deltas.order.push_back(key);
        while deltas.bytes > DELTAS {
            let Some(oldest) = deltas.order.pop_front() else { break };
            if let Some(gone) = deltas.by.remove(&oldest) {
                deltas.bytes -= gone.len();
            }
        }
    }
    Some((made, etag))
}

/// The `dcz` encoding (RFC 9842 §5): a Zstandard skippable frame holding the dictionary's SHA-256,
/// then a Zstandard frame that uses the dictionary as a raw prefix, its window no larger than a
/// client must decode: the greater of 8 MB and 1.25 times the dictionary, at most 128 MB.
fn dcz(content: &[u8], dictionary: &[u8], hash: &[u8; 32]) -> Option<bytes::Bytes> {
    use zstd::zstd_safe::{CCtx, CParameter};
    let limit = (8u64 << 20).max(dictionary.len() as u64 * 5 / 4).min(128 << 20);
    let window_log = 63 - limit.leading_zeros();
    // Worked out once and kept: the strongest level for what a page loads, a little less beyond.
    let level = if content.len() <= 1 << 20 { 19 } else { 15 };
    let mut cctx = CCtx::create();
    cctx.set_parameter(CParameter::CompressionLevel(level)).ok()?;
    cctx.set_parameter(CParameter::WindowLog(window_log)).ok()?;
    cctx.ref_prefix(dictionary).ok()?;
    let mut frame = Vec::with_capacity(zstd::zstd_safe::compress_bound(content.len()));
    cctx.compress2(&mut frame, content).ok()?;
    let mut out = Vec::with_capacity(40 + frame.len());
    out.extend_from_slice(&[0x5e, 0x2a, 0x4d, 0x18, 0x20, 0x00, 0x00, 0x00]);
    out.extend_from_slice(hash);
    out.extend_from_slice(&frame);
    Some(bytes::Bytes::from(out))
}

/// A file as a `dcz` delta: its own ETag, `Vary` on the dictionary too, no ranges.
fn serve_delta(
    mut ctx: Ctx,
    mut response: Response<Body>,
    delta: bytes::Bytes,
    etag: HeaderValue,
    content_type: Option<HeaderValue>,
) -> Response<Body> {
    let headers = response.headers_mut();
    headers.insert(VARY, HeaderValue::from_static("Accept-Encoding, Available-Dictionary"));
    let fresh = ctx
        .req
        .headers
        .get(IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|list| etag_list_matches(list, &etag, false));
    headers.insert(ETAG, etag);
    if fresh {
        *response.status_mut() = StatusCode::NOT_MODIFIED;
        return ctx.respond(response);
    }
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static("dcz"));
    if !ctx.pre_headers.contains_key(CONTENT_TYPE)
        && let Some(kind) = content_type
    {
        headers.insert(CONTENT_TYPE, kind);
    }
    headers.insert(CONTENT_LENGTH, HeaderValue::from(delta.len() as u64));
    if ctx.req.method != Method::HEAD {
        *response.body_mut() = full(delta);
    }
    ctx.respond(response)
}

pub fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn base(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/";
    }
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

/// If-Match (strong comparison) / If-None-Match (weak comparison) against one ETag; no allocation.
pub(crate) fn etag_list_matches(list: &str, etag: &HeaderValue, strong: bool) -> bool {
    fn opaque(tag: &str) -> &str {
        tag.trim().trim_start_matches("W/")
    }
    let etag = etag.to_str().unwrap_or_default();
    let wanted = opaque(etag);
    list.split(',').map(str::trim).any(|candidate| {
        if candidate == "*" {
            return true;
        }
        if strong && (candidate.starts_with("W/") || etag.starts_with("W/")) {
            return false;
        }
        opaque(candidate) == wanted
    })
}

enum RangeError {
    Invalid,
    NoOverlap,
}

/// Go's `parseRange`: `(start, length)` pairs; ranges starting past the end are skipped, and only
/// when none is left the request does not overlap.
fn parse_ranges(header: &str, size: u64) -> Result<Vec<(u64, u64)>, RangeError> {
    let Some(spec) = header.strip_prefix("bytes=") else {
        return Err(RangeError::Invalid);
    };
    let mut ranges = Vec::new();
    let mut no_overlap = false;
    for item in spec.split(',') {
        let item = item.trim_matches([' ', '\t']);
        if item.is_empty() {
            continue;
        }
        let Some((start, end)) = item.split_once('-') else {
            return Err(RangeError::Invalid);
        };
        let (start, end) = (start.trim_matches([' ', '\t']), end.trim_matches([' ', '\t']));
        if start.is_empty() {
            if end.is_empty() || end.starts_with('-') {
                return Err(RangeError::Invalid);
            }
            let suffix: u64 = end.parse().map_err(|_| RangeError::Invalid)?;
            let suffix = suffix.min(size);
            ranges.push((size - suffix, suffix));
            continue;
        }
        let start: u64 = start.parse().map_err(|_| RangeError::Invalid)?;
        if start >= size {
            no_overlap = true;
            continue;
        }
        let length = if end.is_empty() {
            size - start
        } else {
            let end: u64 = end.parse().map_err(|_| RangeError::Invalid)?;
            if start > end {
                return Err(RangeError::Invalid);
            }
            end.min(size - 1) - start + 1
        };
        ranges.push((start, length));
    }
    if no_overlap && ranges.is_empty() {
        return Err(RangeError::NoOverlap);
    }
    Ok(ranges)
}

/// The most ranges one request is answered with as multipart/byteranges (Apache allows 200; a
/// browser or a PDF reader asks for a handful).
const MAX_RANGES: usize = 64;

/// At most MAX_RANGES, none of them overlapping (empty ranges are fine).
fn ranges_are_bounded(ranges: &[(u64, u64)]) -> bool {
    if ranges.len() > MAX_RANGES {
        return false;
    }
    let mut sorted: Vec<(u64, u64)> = ranges.iter().copied().filter(|(_, len)| *len > 0).collect();
    sorted.sort_unstable();
    sorted.windows(2).all(|pair| pair[0].0 + pair[0].1 <= pair[1].0)
}

fn content_range(start: u64, length: u64, total: u64) -> String {
    format!("bytes {start}-{}/{total}", (start + length).saturating_sub(1))
}

/// A random multipart boundary (60 hex digits, as Go's).
fn boundary() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seed = format!(
        "{nanos}-{}-{}",
        COUNTER.fetch_add(1, Ordering::Relaxed),
        std::process::id()
    );
    blake3::hash(seed.as_bytes()).to_hex()[..60].to_string()
}

/// Go's `serveError`: the validators and caching headers meant for the file go, the message is
/// sent as plain text.
fn serve_error(ctx: &mut Ctx, mut response: Response<Body>, message: &str) -> Response<Body> {
    for name in [CACHE_CONTROL, CONTENT_ENCODING, ETAG, LAST_MODIFIED] {
        response.headers_mut().remove(&name);
        ctx.pre_headers.remove(&name);
    }
    let text = format!("{message}\n");
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(CONTENT_LENGTH, HeaderValue::from(text.len() as u64));
    *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
    if ctx.req.method != Method::HEAD {
        *response.body_mut() = full(text);
    }
    ctx.respond(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        let r = |h: &str| parse_ranges(h, 100).ok();
        assert_eq!(r("bytes=0-9"), Some(vec![(0, 10)]));
        assert_eq!(r("bytes=90-"), Some(vec![(90, 10)]));
        assert_eq!(r("bytes=-10"), Some(vec![(90, 10)]));
        assert_eq!(r("bytes=-500"), Some(vec![(0, 100)]));
        assert_eq!(r("bytes=95-200"), Some(vec![(95, 5)]));
        assert_eq!(r("bytes=0-1, 5-6"), Some(vec![(0, 2), (5, 2)]));
        assert_eq!(r("bytes=0-1,200-"), Some(vec![(0, 2)]));
        assert!(matches!(parse_ranges("bytes=100-", 100), Err(RangeError::NoOverlap)));
        assert!(matches!(parse_ranges("items=0-1", 100), Err(RangeError::Invalid)));
        assert!(matches!(parse_ranges("bytes=5-1", 100), Err(RangeError::Invalid)));
        assert!(matches!(parse_ranges("bytes=x-1", 100), Err(RangeError::Invalid)));
        assert_eq!(content_range(0, 10, 100), "bytes 0-9/100");
    }

    #[test]
    fn too_many_or_overlapping_ranges_are_not_bounded() {
        assert!(ranges_are_bounded(&[(0, 2), (5, 2), (2, 3)]), "adjacent is fine");
        assert!(!ranges_are_bounded(&[(0, 10), (5, 10)]), "overlapping");
        assert!(!ranges_are_bounded(&[(0, 1), (0, 1)]), "the same byte twice");
        assert!(
            ranges_are_bounded(&[(0, 0), (0, 0), (0, 5)]),
            "empty ranges never overlap"
        );
        let many: Vec<(u64, u64)> = (0..MAX_RANGES as u64).map(|i| (i * 2, 1)).collect();
        assert!(ranges_are_bounded(&many));
        let too_many: Vec<(u64, u64)> = (0..=MAX_RANGES as u64).map(|i| (i * 2, 1)).collect();
        assert!(!ranges_are_bounded(&too_many));
    }

    #[test]
    fn etag_comparison() {
        let etag = HeaderValue::from_static("\"abc\"");
        assert!(etag_list_matches("\"abc\"", &etag, false));
        assert!(etag_list_matches("W/\"abc\"", &etag, false));
        assert!(!etag_list_matches("W/\"abc\"", &etag, true));
        assert!(etag_list_matches("\"x\", \"abc\"", &etag, false));
        assert!(etag_list_matches("*", &etag, true));
        assert!(!etag_list_matches("\"abd\"", &etag, false));
    }

    #[test]
    fn base_names() {
        assert_eq!(base("/en/"), "en");
        assert_eq!(base("/en/index.html"), "index.html");
        assert_eq!(base("/"), "/");
    }
}
