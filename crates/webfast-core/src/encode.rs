//! Content encodings: the client's preferences (shared with precompressed files) and the `encode`
//! directive, which compresses responses on the fly with zstd, Brotli or gzip.
//!
//! A body of known length (up to 1 MiB) is compressed in one go and sent with its Content-Length;
//! a stream is compressed frame by frame and flushed after each frame, so it reaches the client as
//! it is produced. As in Caddy: the encoding with the client's highest q-value wins,
//! ties go to the order the directive lists; strong ETags get `-<encoding>` appended (and that
//! suffix is taken off If-None-Match on the way in); `Cache-Control: no-transform`, an existing
//! Content-Encoding, 1xx/204/304 and bodies shorter than `minimum_length` are left alone.
//! Unlike Caddy, `text/event-stream` is never compressed, nor a response with `Incremental: ?1`
//! (RFC 10036; Caddy compresses it frame by frame).

use crate::body::{Body, BoxError};
use bytes::Bytes;
use http::header::{ACCEPT_RANGES, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, VARY};
use http::{HeaderMap, HeaderValue, Response, StatusCode};
use http_body::Frame;
use std::io::Write;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Encoding {
    Zstd,
    Br,
    Gzip,
}

impl Encoding {
    pub fn parse(name: &str) -> Option<Encoding> {
        match name {
            "zstd" => Some(Encoding::Zstd),
            "br" => Some(Encoding::Br),
            "gzip" => Some(Encoding::Gzip),
            _ => None,
        }
    }

    pub(crate) fn parse_ignore_case(name: &str) -> Option<Encoding> {
        [Encoding::Zstd, Encoding::Br, Encoding::Gzip]
            .into_iter()
            .find(|e| e.name().eq_ignore_ascii_case(name))
    }

    pub fn name(self) -> &'static str {
        match self {
            Encoding::Zstd => "zstd",
            Encoding::Br => "br",
            Encoding::Gzip => "gzip",
        }
    }

    /// The ninth character of an ETag for a representation made on the fly (`etag_with`).
    pub fn letter(self) -> char {
        match self {
            Encoding::Zstd => 'z',
            Encoding::Br => 'b',
            Encoding::Gzip => 'g',
        }
    }

    /// Suffix of a precompressed sibling file.
    pub fn suffix(self) -> &'static str {
        match self {
            Encoding::Zstd => ".zst",
            Encoding::Br => ".br",
            Encoding::Gzip => ".gz",
        }
    }
}

/// Accept-Encoding, parsed without allocating: the q-value of each encoding this server knows, at
/// its first acceptable mention (q=0 and unknown names are left out). Nothing is accepted for a
/// WebSocket upgrade.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptEncoding {
    q: [f32; 3],
}

impl AcceptEncoding {
    pub fn parse(headers: &HeaderMap) -> AcceptEncoding {
        let mut out = AcceptEncoding::default();
        let Some(header) = headers.get(http::header::ACCEPT_ENCODING).and_then(|v| v.to_str().ok()) else {
            return out;
        };
        if headers
            .get(http::header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
        {
            return out;
        }
        for item in header.split(',') {
            let mut parts = item.split(';');
            let Some(encoding) = Encoding::parse_ignore_case(parts.next().unwrap_or("").trim()) else {
                continue;
            };
            let mut q = 1.0f32;
            if let Some(param) = parts.next() {
                let param = param.trim();
                if param.len() > 2
                    && param[..2].eq_ignore_ascii_case("q=")
                    && let Ok(v) = param[2..].parse::<f32>()
                    && (0.0..=1.0).contains(&v)
                {
                    q = v;
                }
            }
            if q < 0.00001 {
                continue;
            }
            let slot = &mut out.q[encoding as usize];
            if *slot == 0.0 {
                *slot = q;
            }
        }
        out
    }

    /// What decides every choice made from these preferences, in 9 bits: which of the three
    /// encodings are acceptable, and for each pair which has the higher q-value or that they tie
    /// (as `ranked` compares). Equal signatures rank any offer the same way (src/memo.rs).
    pub fn signature(&self) -> u16 {
        let mut signature = 0u16;
        for (i, q) in self.q.iter().enumerate() {
            if *q > 0.0 {
                signature |= 1 << i;
            }
        }
        for (shift, (a, b)) in [(3, (0, 1)), (5, (0, 2)), (7, (1, 2))] {
            let (qa, qb) = (self.q[a], self.q[b]);
            let relation = if qa > qb + 0.00001 {
                1
            } else if qb > qa + 0.00001 {
                2
            } else {
                0
            };
            signature |= relation << shift;
        }
        signature
    }

    /// The acceptable ones among `offered`, best first: q-value descending, ties in `offered` order.
    pub fn ranked(&self, offered: &[Encoding]) -> impl Iterator<Item = Encoding> + use<> {
        let mut items = [(Encoding::Zstd, 0.0f32); 3];
        let mut len = 0;
        for &encoding in offered {
            let q = self.q[encoding as usize];
            if q > 0.0 && len < items.len() && !items[..len].iter().any(|(e, _)| *e == encoding) {
                items[len] = (encoding, q);
                len += 1;
            }
        }
        for i in 1..len {
            let mut j = i;
            while j > 0 && items[j].1 > items[j - 1].1 + 0.00001 {
                items.swap(j, j - 1);
                j -= 1;
            }
        }
        items.into_iter().take(len).map(|(encoding, _)| encoding)
    }
}

/// Caddy's default list of compressible types (`*` at the end: any parameters or subtype tail),
/// the common ones first: `types_match` stops at the first that fits, and nearly every response
/// is text, JSON, a script, XML, an SVG or a font.
pub const DEFAULT_TYPES: &[&str] = &[
    "text/*",
    "application/json*",
    "application/javascript*",
    "application/xml*",
    "image/svg+xml*",
    "font/*",
    "application/atom+xml*",
    "application/eot*",
    "application/font*",
    "application/geo+json*",
    "application/graphql+json*",
    "application/graphql-response+json*",
    "application/ld+json*",
    "application/manifest+json*",
    "application/opentype*",
    "application/otf*",
    "application/rss+xml*",
    "application/truetype*",
    "application/ttf*",
    "application/vnd.api+json*",
    "application/vnd.ms-fontobject*",
    "application/wasm*",
    "application/x-httpd-cgi*",
    "application/x-javascript*",
    "application/x-opentype*",
    "application/x-otf*",
    "application/x-perl*",
    "application/x-protobuf*",
    "application/x-ttf*",
    "application/xhtml+xml*",
    "image/vnd.microsoft.icon*",
    "image/x-icon*",
    "multipart/bag*",
    "multipart/mixed*",
];

/// Bodies up to this size (by Content-Length) are compressed whole.
const BUFFER_LIMIT: u64 = 1 << 20;

/// Bodies larger than this are compressed on the blocking pool, so the worker thread meanwhile
/// serves other requests (Brotli on a megabyte takes milliseconds).
const INLINE_LIMIT: usize = 64 << 10;

#[derive(Debug, Clone)]
pub struct Encode {
    pub formats: Vec<Encoding>,
    pub gzip_level: u32,
    pub zstd_level: i32,
    pub br_level: u32,
    pub minimum_length: u64,
    pub types: Vec<String>,
    pub statuses: Vec<(u16, u16)>,
}

impl Default for Encode {
    fn default() -> Self {
        Encode {
            formats: vec![Encoding::Zstd, Encoding::Gzip],
            gzip_level: 5,
            zstd_level: 3,
            br_level: 4,
            minimum_length: 512,
            types: DEFAULT_TYPES.iter().map(|s| s.to_string()).collect(),
            statuses: Vec::new(),
        }
    }
}

impl Encode {
    /// The encoding for this request, and its If-None-Match with our ETag suffix taken off.
    pub fn choose(&self, accept: AcceptEncoding, headers: &mut HeaderMap) -> Option<Encoding> {
        let encoding = accept.ranked(&self.formats).next()?;
        // The If-None-Match our ETag for this encoding was made from (`etag_with`); nothing is
        // built unless it is one.
        if let Some(inm) = headers.get(http::header::IF_NONE_MATCH).and_then(|v| v.to_str().ok())
            && let Some(base) = etag_base(inm, encoding.letter())
            && let Some(value) = quoted(base)
        {
            headers.insert(http::header::IF_NONE_MATCH, value);
        }
        Some(encoding)
    }

    /// Compresses the response if it qualifies.
    pub async fn apply(&self, encoding: Encoding, head_request: bool, response: Response<Body>) -> Response<Body> {
        if head_request || !self.qualifies(&response) {
            return response;
        }
        let (mut parts, body) = response.into_parts();
        // No longer the stored file's bytes (src/memo.rs keeps no answer for it).
        parts.extensions.remove::<crate::memo::FromFile>();
        let headers = &mut parts.headers;
        let known_length = headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|len| *len <= BUFFER_LIMIT);
        headers.remove(CONTENT_LENGTH);
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static(encoding.name()));
        if !has_vary(headers, "accept-encoding") {
            headers.append(VARY, HeaderValue::from_static("Accept-Encoding"));
        }
        headers.remove(ACCEPT_RANGES);
        if let Some(etag) = headers.get(ETAG).and_then(|v| v.to_str().ok())
            && !etag.starts_with("W/")
            && let Some(value) = etag_with(etag, encoding.letter())
        {
            headers.insert(ETAG, value);
        }
        let levels = Levels::of(self);
        if known_length.is_some() {
            // A body known at once (a file, a ready answer) is taken as it is; only a stream is
            // collected.
            let data = match body.into_bytes_if_ready() {
                Ok(bytes) => Ok(bytes),
                Err(body) => http_body_util::BodyExt::collect(body)
                    .await
                    .map(|collected| collected.to_bytes())
                    .map_err(|e| std::io::Error::other(e.to_string())),
            };
            let compressed = match data {
                // The encoder is taken where it is used: a blocking thread keeps its own pool.
                Ok(data) if data.len() > INLINE_LIMIT => tokio::task::spawn_blocking(move || {
                    Encoder::new(encoding, levels, Some(data.len())).compress_all(&data)
                })
                .await
                .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string()))),
                Ok(data) => Encoder::new(encoding, levels, Some(data.len())).compress_all(&data),
                Err(e) => Err(e),
            };
            return match compressed {
                Ok(bytes) => {
                    parts
                        .headers
                        .insert(CONTENT_LENGTH, crate::handler::header_number(bytes.len() as u64));
                    Response::from_parts(parts, crate::body::full(bytes))
                }
                Err(e) => {
                    tracing::warn!(error = %e, "response body failed while compressing");
                    let mut response = Response::new(crate::body::empty());
                    *response.status_mut() = StatusCode::BAD_GATEWAY;
                    response
                }
            };
        }
        Response::from_parts(
            parts,
            crate::body::boxed(EncodedBody {
                inner: body,
                encoder: Some(Encoder::new(encoding, levels, None)),
            }),
        )
    }

    fn qualifies(&self, response: &Response<Body>) -> bool {
        let status = response.status();
        if status.is_informational() || status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED {
            return false;
        }
        if !self.statuses.is_empty()
            && !self
                .statuses
                .iter()
                .any(|(lo, hi)| (*lo..=*hi).contains(&status.as_u16()))
        {
            return false;
        }
        let headers = response.headers();
        if headers.contains_key(CONTENT_ENCODING) {
            return false;
        }
        if headers
            .get_all(CACHE_CONTROL)
            .iter()
            .any(|v| contains_ignore_case(v.as_bytes(), b"no-transform"))
        {
            return false;
        }
        let Some(content_type) = headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()) else {
            return false;
        };
        if starts_with_ignore_case(content_type, "text/event-stream") || incremental(headers) {
            return false;
        }
        if !types_match(self.types.iter().map(String::as_str), content_type) {
            return false;
        }
        if let Some(length) = headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            && length < self.minimum_length
        {
            return false;
        }
        true
    }
}

/// `etag` (strong, with its quotes) for a representation in the encoding `letter` names: a ninth
/// character on an ETag of ours (src/files.rs), `.` and the letter on any other (an upstream's).
pub fn etag_with(etag: &str, letter: char) -> Option<HeaderValue> {
    let inner = etag.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = crate::handler::HeaderText::new();
    out.push_str("\"");
    out.push_str(inner);
    if !crate::files::is_own_etag(inner) {
        out.push_str(".");
    }
    out.push_str(letter.encode_utf8(&mut [0; 4]));
    out.push_str("\"");
    out.value()
}

/// `"<text>"` as a header value, written at once.
fn quoted(text: &str) -> Option<HeaderValue> {
    let mut out = crate::handler::HeaderText::new();
    out.push_str("\"");
    out.push_str(text);
    out.push_str("\"");
    out.value()
}

/// The ETag `etag_with` made `tagged` from, when it is one in the encoding `letter` names;
/// `None` for any other (a client holding another representation, or none of ours).
pub fn etag_without(tagged: &str, letter: char) -> Option<String> {
    etag_base(tagged, letter).map(|base| format!("\"{base}\""))
}

/// The inside of the ETag `etag_without` gives, without its quotes.
fn etag_base(tagged: &str, letter: char) -> Option<&str> {
    let inner = tagged.strip_prefix('"')?.strip_suffix('"')?;
    let base = inner.strip_suffix(letter)?;
    if let Some(base) = base.strip_suffix('.') {
        return Some(base);
    }
    crate::files::is_own_etag(base).then_some(base)
}
/// Whether `content_type` is of one of `patterns` (lowercase, `*` at the end for any rest), in any
/// ASCII case, with no lowercase copy of it made: a type without capitals (most are sent so) is
/// compared as it is, byte for byte.
pub(crate) fn types_match<'a>(patterns: impl IntoIterator<Item = &'a str>, content_type: &str) -> bool {
    types_match_as(patterns, content_type, !has_capitals(content_type))
}

fn has_capitals(text: &str) -> bool {
    text.bytes().any(|b| b.is_ascii_uppercase())
}

/// `text.starts_with(prefix)`, byte for byte when `as_is`, otherwise ASCII case aside.
fn starts_as(text: &str, prefix: &str, as_is: bool) -> bool {
    if as_is {
        text.starts_with(prefix)
    } else {
        starts_with_ignore_case(text, prefix)
    }
}

fn types_match_as<'a>(patterns: impl IntoIterator<Item = &'a str>, content_type: &str, as_is: bool) -> bool {
    let mut patterns = patterns.into_iter();
    if as_is {
        patterns.any(|pattern| {
            type_is(pattern, content_type, |text: &str, prefix: &str| {
                text.starts_with(prefix)
            })
        })
    } else {
        patterns.any(|pattern| type_is(pattern, content_type, starts_with_ignore_case))
    }
}

/// `pattern` alone, followed by its parameters, or (with `*`) by any rest: `starts` compares.
#[inline(always)]
fn type_is(pattern: &str, content_type: &str, starts: impl Fn(&str, &str) -> bool) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => starts(content_type, prefix),
        None => {
            starts(content_type, pattern) && matches!(content_type.as_bytes().get(pattern.len()), None | Some(b';'))
        }
    }
}

/// `types_match` for one pattern.
#[cfg(test)]
pub(crate) fn type_matches(pattern: &str, content_type: &str) -> bool {
    types_match([pattern], content_type)
}

/// `text.starts_with(prefix)`, ASCII case aside.
pub(crate) fn starts_with_ignore_case(text: &str, prefix: &str) -> bool {
    text.as_bytes()
        .get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix.as_bytes()))
}

/// Whether `needle` (not empty) is in `text`, ASCII case aside.
pub(crate) fn contains_ignore_case(text: &[u8], needle: &[u8]) -> bool {
    text.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

/// Compresses at the encoding's highest level, for work done once in the background (the proxy
/// cache's worker, src/cache.rs; the files' compressed variants, src/variants.rs). The result is
/// kept in memory, counted by its length: it holds no more than that (see `exact`).
pub fn compress_best(encoding: Encoding, data: &[u8]) -> std::io::Result<Bytes> {
    // Text at these levels comes out at a fifth to a tenth: room for a quarter, grown when that is
    // not enough.
    let mut out = Vec::with_capacity(data.len() / 4 + 64);
    match encoding {
        Encoding::Gzip => {
            let mut encoder = flate2::write::GzEncoder::new(&mut out, flate2::Compression::best());
            encoder.write_all(data)?;
            encoder.finish()?;
        }
        // What `zstd::stream::encode_all` does, into the buffer made here.
        Encoding::Zstd => zstd::stream::copy_encode(data, &mut out, 19)?,
        Encoding::Br => {
            let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 11, 22);
            writer.write_all(data)?;
        }
    }
    Ok(exact(out))
}

/// The buffer's bytes in an allocation of their size. `Bytes::from(Vec)` keeps the vector's whole
/// capacity — up to twice the length after it grew by doubling — for as long as the bytes are
/// kept, and memory budgets count the length only: past an eighth more, the bytes are copied out.
pub(crate) fn exact(buffer: Vec<u8>) -> Bytes {
    if buffer.capacity() - buffer.len() > buffer.len() / 8 {
        Bytes::copy_from_slice(&buffer)
    } else {
        Bytes::from(buffer)
    }
}

/// Room for what compressing a whole body of `len` bytes on the fly gives (header, data and
/// trailer come in several writes): about half for text at the default levels, grown in the rare
/// case that is too little. The bytes go out to the client and are dropped: the spare room is not
/// kept.
fn room_for(len: usize) -> usize {
    len / 2 + 64
}

/// Whether a response says each part of it is to reach the client as it comes: `Incremental: ?1`
/// (RFC 10036, the standard form of NGINX's `X-Accel-Buffering: no`). Neither compressed nor kept
/// by the cache, as an event stream: both may hold a body back (a known length is compressed
/// whole). `?0`, or a value that is no Structured Fields boolean, says nothing.
pub fn incremental(headers: &HeaderMap) -> bool {
    headers.get_all(INCREMENTAL).iter().any(|v| {
        v.to_str()
            .is_ok_and(|v| v.split(';').next().is_some_and(|item| item.trim() == "?1"))
    })
}

pub(crate) const INCREMENTAL: http::header::HeaderName = http::header::HeaderName::from_static("incremental");

/// Whether a body of `content_type` is worth compressing: Caddy's list (`DEFAULT_TYPES`), never
/// an event stream.
pub fn compressible(content_type: &str) -> bool {
    let as_is = !has_capitals(content_type);
    !starts_as(content_type, "text/event-stream", as_is)
        && types_match_as(DEFAULT_TYPES.iter().copied(), content_type, as_is)
}

pub fn has_vary(headers: &HeaderMap, field: &str) -> bool {
    headers
        .get_all(VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|v| v.trim().eq_ignore_ascii_case(field) || v.trim() == "*")
}

/// The directive's levels, copied for an encoder made on the blocking pool.
#[derive(Clone, Copy)]
struct Levels {
    gzip: u32,
    zstd: i32,
    br: u32,
}

impl Levels {
    fn of(config: &Encode) -> Levels {
        Levels {
            gzip: config.gzip_level,
            zstd: config.zstd_level,
            br: config.br_level,
        }
    }
}

/// A compressor's state is far larger than the body it is for — deflate's tables run to hundreds
/// of KB, zstd's workspace to megabytes — and making one per response cost more than the
/// compressing (measured on an 8 KiB body). So each thread keeps one gzip state and one zstd
/// context, reset between uses: `Encoder::new` takes it, `finish` gives it back. More than one at
/// a time on a thread (streams in flight) are made as before and freed when done; one dropped
/// mid-stream (the client went) is freed too. A blocking thread has a pool of its own, which goes
/// when the thread ends. Brotli's encoder cannot be reset: it is made per response, its window
/// and size hint fitted to the body (`brotli_params`).
struct Pool {
    gzip: Option<Gzip>,
    zstd: Option<zstd::zstd_safe::CCtx<'static>>,
}

thread_local! {
    static POOL: std::cell::RefCell<Pool> = const { std::cell::RefCell::new(Pool { gzip: None, zstd: None }) };
}

/// A streaming compressor: each `write` returns what the input produced, flushed; `finish` what
/// is left, and returns the state to the thread's `Pool`. `None` inside once finished.
enum Encoder {
    Gzip(Option<Gzip>),
    Zstd(Option<Zstd>),
    Br(Option<Box<brotli::CompressorWriter<Vec<u8>>>>),
}

/// gzip as a raw deflate stream with the member's header and trailer written here: flate2's
/// `GzEncoder` cannot be reset, its `DeflateEncoder` can, and the trailer is only a CRC-32 and
/// the length.
struct Gzip {
    deflate: flate2::write::DeflateEncoder<Vec<u8>>,
    crc: flate2::Crc,
    level: u32,
}

impl Gzip {
    fn new(level: u32) -> Gzip {
        Gzip {
            deflate: flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(level)),
            crc: flate2::Crc::new(),
            level,
        }
    }

    /// The member's header into the (empty) buffer: no modification time, no name, unknown OS, the
    /// XFL flag for the fastest and best levels, as flate2 writes it.
    fn start(&mut self) {
        let xfl = match self.level {
            9.. => 2,
            0..=1 => 4,
            _ => 0,
        };
        self.deflate
            .get_mut()
            .extend_from_slice(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, xfl, 255]);
    }

    fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.crc.update(data);
        self.deflate.write_all(data)
    }

    fn flush(&mut self) -> std::io::Result<Bytes> {
        self.deflate.flush()?;
        Ok(Bytes::from(std::mem::take(self.deflate.get_mut())))
    }

    /// The rest of the member with its trailer; the state is reset for the next.
    fn finish(&mut self) -> std::io::Result<Bytes> {
        let mut out = self.deflate.reset(Vec::new())?;
        out.extend_from_slice(&self.crc.sum().to_le_bytes());
        out.extend_from_slice(&self.crc.amount().to_le_bytes());
        self.crc.reset();
        Ok(Bytes::from(out))
    }
}

/// zstd on its context directly (the crate's writer cannot be reused after a frame): a whole body
/// in one call, which sizes the workspace to it; a stream frame by frame.
struct Zstd {
    cctx: zstd::zstd_safe::CCtx<'static>,
    out: Vec<u8>,
}

fn zstd_error(code: usize) -> std::io::Error {
    std::io::Error::other(zstd::zstd_safe::get_error_name(code))
}

/// `out` after what it holds, with room for the next call (zstd writes into the capacity only).
fn room(out: &mut Vec<u8>) -> zstd::zstd_safe::OutBuffer<'_, Vec<u8>> {
    let len = out.len();
    if len == out.capacity() {
        out.reserve(len.max(1024));
    }
    zstd::zstd_safe::OutBuffer::around_pos(out, len)
}

/// A context whose frame is complete, back to the thread's pool (when it has none).
fn pool_zstd(cctx: zstd::zstd_safe::CCtx<'static>) {
    POOL.with_borrow_mut(|pool| {
        if pool.zstd.is_none() {
            pool.zstd = Some(cctx);
        }
    });
}

impl Zstd {
    /// The thread's context, or a new one; at `level`, its session reset.
    fn new(level: i32) -> Option<Zstd> {
        use zstd::zstd_safe::{CCtx, CParameter, ResetDirective};
        let mut cctx = POOL
            .with_borrow_mut(|pool| pool.zstd.take())
            .unwrap_or_else(CCtx::create);
        cctx.reset(ResetDirective::SessionOnly).ok()?;
        cctx.set_parameter(CParameter::CompressionLevel(level)).ok()?;
        Some(Zstd { cctx, out: Vec::new() })
    }

    /// `data` through the stream, then flushed: what came out is in `out`.
    fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        use zstd::zstd_safe::InBuffer;
        self.out.reserve(room_for(data.len()));
        let mut input = InBuffer::around(data);
        while input.pos() < data.len() {
            let mut output = room(&mut self.out);
            self.cctx.compress_stream(&mut output, &mut input).map_err(zstd_error)?;
        }
        loop {
            let mut output = room(&mut self.out);
            if self.cctx.flush_stream(&mut output).map_err(zstd_error)? == 0 {
                return Ok(());
            }
        }
    }

    /// Ends the frame: what is left in `out`.
    fn finish(&mut self) -> std::io::Result<()> {
        loop {
            let mut output = room(&mut self.out);
            if self.cctx.end_stream(&mut output).map_err(zstd_error)? == 0 {
                return Ok(());
            }
        }
    }

    /// A whole body in one call, the frame with its size: zstd fits the window and the workspace
    /// to it. The output has `compress_bound` of room, which the call needs.
    fn compress_all(&mut self, data: &[u8]) -> std::io::Result<Bytes> {
        let mut out = Vec::with_capacity(zstd::zstd_safe::compress_bound(data.len()));
        self.cctx.compress2(&mut out, data).map_err(zstd_error)?;
        Ok(Bytes::from(out))
    }
}

/// Brotli at `level` for a body of `len` bytes when known: a window no larger than it needs (16 to
/// 22 bits; the default is 22, 4 MiB, for every body) and the size hint, by which the encoder
/// picks its hasher.
fn brotli_params(level: u32, len: Option<usize>) -> brotli::enc::BrotliEncoderParams {
    let mut params = brotli::enc::BrotliEncoderInitParams();
    params.quality = level as i32;
    if let Some(len) = len {
        // The least number of bits that spans the body (16 for one of 65 536 bytes).
        let bits = (usize::BITS - len.saturating_sub(1).leading_zeros()) as i32;
        params.lgwin = bits.clamp(16, 22);
        params.size_hint = len;
    }
    params
}

impl Encoder {
    /// For a body of `len` bytes, or a stream (`None`).
    fn new(encoding: Encoding, levels: Levels, len: Option<usize>) -> Encoder {
        match encoding {
            Encoding::Gzip => {
                let mut gzip = POOL
                    .with_borrow_mut(|pool| pool.gzip.take())
                    .filter(|gzip| gzip.level == levels.gzip)
                    .unwrap_or_else(|| Gzip::new(levels.gzip));
                gzip.start();
                Encoder::Gzip(Some(gzip))
            }
            Encoding::Zstd => Encoder::Zstd(Zstd::new(levels.zstd)),
            Encoding::Br => Encoder::Br(Some(Box::new(brotli::CompressorWriter::with_params(
                Vec::new(),
                4096,
                &brotli_params(levels.br, len),
            )))),
        }
    }

    fn write(&mut self, data: &[u8]) -> std::io::Result<Bytes> {
        // No room made ahead for gzip and Brotli (measured): they hand a flushed part over in one
        // write of its size, so the empty buffer takes exactly that, and `Bytes` of a full vector
        // needs no allocation of its own — spare room would cost both.
        match self {
            Encoder::Gzip(Some(e)) => {
                e.write(data)?;
                e.flush()
            }
            Encoder::Zstd(Some(e)) => {
                e.write(data)?;
                Ok(Bytes::from(std::mem::take(&mut e.out)))
            }
            Encoder::Br(Some(e)) => {
                e.write_all(data)?;
                e.flush()?;
                Ok(Bytes::from(std::mem::take(e.get_mut())))
            }
            _ => Err(std::io::Error::other("encoder already finished")),
        }
    }

    /// A whole body: no intermediate flushes.
    fn compress_all(&mut self, data: &[u8]) -> std::io::Result<Bytes> {
        match self {
            Encoder::Gzip(Some(e)) => {
                e.deflate.get_mut().reserve(room_for(data.len()));
                e.write(data)?;
            }
            // One call, the frame complete: nothing to end, the context goes back as it is.
            Encoder::Zstd(e) => {
                let Some(mut zstd) = e.take() else {
                    return Err(std::io::Error::other("encoder already finished"));
                };
                let out = zstd.compress_all(data)?;
                pool_zstd(zstd.cctx);
                return Ok(out);
            }
            Encoder::Br(Some(e)) => {
                e.get_mut().reserve(room_for(data.len()));
                e.write_all(data)?;
            }
            _ => return Err(std::io::Error::other("encoder already finished")),
        }
        self.finish()
    }

    /// What is left; the state goes back to the thread's pool.
    fn finish(&mut self) -> std::io::Result<Bytes> {
        match self {
            Encoder::Gzip(e) => match e.take() {
                Some(mut gzip) => {
                    let out = gzip.finish()?;
                    POOL.with_borrow_mut(|pool| {
                        if pool.gzip.is_none() {
                            pool.gzip = Some(gzip);
                        }
                    });
                    Ok(out)
                }
                None => Ok(Bytes::new()),
            },
            Encoder::Zstd(e) => match e.take() {
                Some(mut zstd) => {
                    zstd.finish()?;
                    pool_zstd(zstd.cctx);
                    Ok(Bytes::from(zstd.out))
                }
                None => Ok(Bytes::new()),
            },
            Encoder::Br(e) => match e.take() {
                Some(e) => Ok(Bytes::from(e.into_inner())),
                None => Ok(Bytes::new()),
            },
        }
    }
}

struct EncodedBody {
    inner: Body,
    encoder: Option<Encoder>,
}

impl http_body::Body for EncodedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        loop {
            let Some(encoder) = self.encoder.as_mut() else {
                return Poll::Ready(None);
            };
            let _ = encoder;
            match ready!(Pin::new(&mut self.inner).poll_frame(cx)) {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => {
                        if data.is_empty() {
                            continue;
                        }
                        let encoder = self.encoder.as_mut().expect("checked above");
                        match encoder.write(&data) {
                            Ok(out) if out.is_empty() => continue,
                            Ok(out) => return Poll::Ready(Some(Ok(Frame::data(out)))),
                            Err(e) => return Poll::Ready(Some(Err(Box::new(e)))),
                        }
                    }
                    // Trailers after compressed data would be confusing; drop them.
                    Err(_) => continue,
                },
                Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                None => {
                    let mut encoder = self.encoder.take().expect("checked above");
                    return match encoder.finish() {
                        Ok(out) if out.is_empty() => Poll::Ready(None),
                        Ok(out) => Poll::Ready(Some(Ok(Frame::data(out)))),
                        Err(e) => Poll::Ready(Some(Err(Box::new(e)))),
                    };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use std::io::Read;

    fn headers(accept: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(http::header::ACCEPT_ENCODING, HeaderValue::from_str(accept).unwrap());
        h
    }

    fn accepted(headers: &HeaderMap, offered: &[Encoding]) -> Vec<Encoding> {
        AcceptEncoding::parse(headers).ranked(offered).collect()
    }

    #[test]
    fn types_match_in_any_case() {
        assert!(type_matches("text/*", "Text/HTML; charset=UTF-8"));
        assert!(type_matches("application/json", "APPLICATION/JSON"));
        assert!(type_matches("application/json", "application/json;charset=utf-8"));
        assert!(!type_matches("application/json", "application/jsonx"));
        assert!(!type_matches("application/json", "application/js"));
        assert!(!type_matches("text/*", "tex"));
        assert!(type_matches("text/*", "text/"));
        assert!(starts_with_ignore_case("TEXT/Event-Stream", "text/event-stream"));
        assert!(!starts_with_ignore_case("text/event", "text/event-stream"));
        assert!(contains_ignore_case(b"public, No-Transform", b"no-transform"));
        assert!(!contains_ignore_case(b"no-trans", b"no-transform"));
        assert!(compressible("Text/Html"));
        assert!(!compressible("Text/Event-Stream"));
        // A type that is not ASCII at the pattern's end is no panic.
        assert!(!type_matches("text/html", "text/htmд"));
    }

    #[test]
    fn preference_order() {
        let offered = [Encoding::Zstd, Encoding::Br, Encoding::Gzip];
        assert_eq!(accepted(&headers("gzip, deflate, br, zstd"), &offered), offered);
        assert_eq!(
            accepted(&headers("gzip, deflate, br"), &offered),
            [Encoding::Br, Encoding::Gzip]
        );
        assert_eq!(
            accepted(&headers("br;q=0.5, gzip"), &offered),
            [Encoding::Gzip, Encoding::Br]
        );
        assert_eq!(accepted(&headers("zstd;q=0, gzip"), &offered), [Encoding::Gzip]);
        assert_eq!(
            accepted(&headers("GZIP;Q=0.4, Br"), &offered),
            [Encoding::Br, Encoding::Gzip]
        );
        assert_eq!(
            accepted(&headers("br, gzip"), &[Encoding::Gzip, Encoding::Br]),
            [Encoding::Gzip, Encoding::Br]
        );
        assert!(accepted(&headers("identity"), &offered).is_empty());
        assert!(accepted(&HeaderMap::new(), &offered).is_empty());
    }

    /// `compressed` decoded (gzip: the whole member, trailer checked).
    fn decode(encoding: Encoding, compressed: &[u8]) -> Vec<u8> {
        let mut plain = Vec::new();
        match encoding {
            Encoding::Gzip => {
                flate2::read::GzDecoder::new(compressed)
                    .read_to_end(&mut plain)
                    .unwrap();
            }
            Encoding::Zstd => plain = zstd::stream::decode_all(compressed).unwrap(),
            Encoding::Br => {
                brotli::Decompressor::new(compressed, 4096)
                    .read_to_end(&mut plain)
                    .unwrap();
            }
        }
        plain
    }

    /// A stream (no Content-Length) compressed frame by frame.
    async fn roundtrip(encoding: Encoding) -> Vec<u8> {
        let config = Encode {
            formats: vec![encoding],
            ..Encode::default()
        };
        let text = "hello world ".repeat(100);
        let mut response = Response::new(crate::body::full(text.clone()));
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        response.headers_mut().insert(ETAG, HeaderValue::from_static("\"abc\""));
        let response = config.apply(encoding, false, response).await;
        assert_eq!(response.headers()[CONTENT_ENCODING], encoding.name());
        assert_eq!(
            response.headers()[ETAG],
            format!("\"abc.{}\"", encoding.letter()).as_str()
        );
        let compressed = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(decode(encoding, &compressed), text.as_bytes());
        compressed.to_vec()
    }

    /// A body of `len` bytes with its Content-Length, compressed whole with `config`.
    async fn whole(config: &Encode, encoding: Encoding, len: usize) -> usize {
        let text: Vec<u8> = b"abc ".iter().copied().cycle().take(len).collect();
        let mut response = Response::new(crate::body::full(text.clone()));
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from(text.len()));
        let response = config.apply(encoding, false, response).await;
        let length: usize = response.headers()[CONTENT_LENGTH].to_str().unwrap().parse().unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(length, body.len());
        assert_eq!(decode(encoding, &body), text);
        body.len()
    }

    #[tokio::test]
    async fn compresses_and_decompresses() {
        for encoding in [Encoding::Gzip, Encoding::Zstd, Encoding::Br] {
            let compressed = roundtrip(encoding).await;
            assert!(compressed.len() < 200, "{encoding:?}: {}", compressed.len());
        }
    }

    #[tokio::test]
    async fn pooled_encoders_give_whole_members_use_after_use() {
        // All on one thread: from the second body on, the gzip state and the zstd context come
        // from the pool, reset — a stream after a whole body and the other way round.
        let config = Encode::default();
        for encoding in [Encoding::Gzip, Encoding::Zstd, Encoding::Br] {
            for len in [600, 3000, 600] {
                whole(&config, encoding, len).await;
                roundtrip(encoding).await;
            }
            // Over INLINE_LIMIT: on the blocking pool, with a pool of its own.
            let compressed = whole(&config, encoding, INLINE_LIMIT + 1000).await;
            assert!(compressed < INLINE_LIMIT / 10, "{encoding:?}: {compressed}");
        }
        // Another gzip level: the pooled state is not at it, and a new one is made.
        let louder = Encode {
            gzip_level: 9,
            ..Encode::default()
        };
        whole(&louder, Encoding::Gzip, 3000).await;
        whole(&config, Encoding::Gzip, 3000).await;
    }

    #[test]
    fn default_types_start_with_the_common_ones() {
        assert_eq!(
            DEFAULT_TYPES[..3],
            ["text/*", "application/json*", "application/javascript*"]
        );
        assert_eq!(DEFAULT_TYPES.len(), 34, "Caddy's list, whole");
        let mut sorted = DEFAULT_TYPES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), DEFAULT_TYPES.len(), "no type twice");
    }

    #[tokio::test]
    async fn known_length_is_compressed_whole() {
        let config = Encode {
            formats: vec![Encoding::Br],
            ..Encode::default()
        };
        let text = "abc ".repeat(400);
        let mut response = Response::new(crate::body::full(text.clone()));
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from(text.len()));
        let response = config.apply(Encoding::Br, false, response).await;
        let length: usize = response.headers()[CONTENT_LENGTH].to_str().unwrap().parse().unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(length, body.len());
        let mut plain = Vec::new();
        brotli::Decompressor::new(&body[..], 4096)
            .read_to_end(&mut plain)
            .unwrap();
        assert_eq!(plain, text.as_bytes());
    }

    #[test]
    fn skips_what_does_not_qualify() {
        let config = Encode::default();
        let mut small = Response::new(crate::body::full("x"));
        small
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        small
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_static("1"));
        assert!(!config.qualifies(&small));
        let mut image = Response::new(crate::body::empty());
        image
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));
        assert!(!config.qualifies(&image));
        let mut sse = Response::new(crate::body::empty());
        sse.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
        assert!(!config.qualifies(&sse));
        let mut json = Response::new(crate::body::empty());
        json.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        assert!(config.qualifies(&json));
        // RFC 10036: `?1` (with parameters too) streams as it comes; `?0` or no boolean, no word.
        for (value, compressed) in [
            ("?1", false),
            ("?1;x=1", false),
            (" ?1 ", false),
            ("?0", true),
            ("1", true),
        ] {
            json.headers_mut().insert(INCREMENTAL, HeaderValue::from_static(value));
            assert_eq!(config.qualifies(&json), compressed, "Incremental: {value}");
        }
    }

    #[test]
    fn strips_etag_suffix_from_if_none_match() {
        let config = Encode {
            formats: vec![Encoding::Br],
            ..Encode::default()
        };
        let mut h = headers("br");
        h.insert(http::header::IF_NONE_MATCH, HeaderValue::from_static("\"abc.b\""));
        assert_eq!(config.choose(AcceptEncoding::parse(&h), &mut h), Some(Encoding::Br));
        assert_eq!(h[http::header::IF_NONE_MATCH], "\"abc\"");
    }

    #[test]
    fn etags_of_encoded_representations_get_a_letter_and_give_it_back() {
        // Ours: a ninth character; an upstream's: a dot and the letter.
        assert_eq!(etag_with("\"AAAAAAAA\"", 'b').unwrap(), "\"AAAAAAAAb\"");
        assert_eq!(etag_with("\"p1\"", 'z').unwrap(), "\"p1.z\"");
        assert_eq!(
            etag_with("\"0123456789abcdef0123\"", 'g').unwrap(),
            "\"0123456789abcdef0123.g\""
        );
        assert!(etag_with("W/\"weak\"", 'b').is_none(), "not a strong ETag");
        // Back: only for the encoding asked, and only what etag_with made.
        assert_eq!(etag_without("\"AAAAAAAAb\"", 'b').as_deref(), Some("\"AAAAAAAA\""));
        assert_eq!(etag_without("\"AAAAAAAAb\"", 'g'), None, "another representation");
        assert_eq!(etag_without("\"AAAAAAAA\"", 'b'), None, "the identity, not encoded");
        assert_eq!(etag_without("\"p1.z\"", 'z').as_deref(), Some("\"p1\""));
        assert_eq!(etag_without("\"p1.z\"", 'b'), None);
        assert_eq!(etag_without("\"AAAAAAAAdBBBBBBBB\"", 'b'), None, "a delta's, not ours");
        assert_eq!(etag_without("W/\"AAAAAAAAb\"", 'b'), None);
    }
}
