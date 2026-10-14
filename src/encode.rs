//! Content encodings: the client's preferences (shared with precompressed files) and the `encode`
//! directive, which compresses responses on the fly with zstd, Brotli or gzip.
//!
//! A body of known length (up to 1 MiB) is compressed in one go and sent with its Content-Length;
//! a stream is compressed frame by frame and flushed after each frame, so it reaches the client as
//! it is produced. As in Caddy: the encoding with the client's highest q-value wins,
//! ties go to the order the directive lists; strong ETags get `-<encoding>` appended (and that
//! suffix is taken off If-None-Match on the way in); `Cache-Control: no-transform`, an existing
//! Content-Encoding, 1xx/204/304 and bodies shorter than `minimum_length` are left alone.
//! Unlike Caddy, `text/event-stream` is never compressed.

use crate::body::{Body, BoxError};
use bytes::Bytes;
use http::header::{ACCEPT_RANGES, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, VARY};
use http::{HeaderMap, HeaderValue, Response, StatusCode};
use http_body::Frame;
use std::io::Write;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    fn parse_ignore_case(name: &str) -> Option<Encoding> {
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

/// Caddy's default list of compressible types (`*` at the end: any parameters or subtype tail).
pub const DEFAULT_TYPES: &[&str] = &[
    "application/atom+xml*",
    "application/eot*",
    "application/font*",
    "application/geo+json*",
    "application/graphql+json*",
    "application/graphql-response+json*",
    "application/javascript*",
    "application/json*",
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
    "application/xml*",
    "font/*",
    "image/svg+xml*",
    "image/vnd.microsoft.icon*",
    "image/x-icon*",
    "multipart/bag*",
    "multipart/mixed*",
    "text/*",
];

/// Bodies up to this size (by Content-Length) are compressed whole.
const BUFFER_LIMIT: u64 = 1 << 20;

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
        if let Some(inm) = headers.get(http::header::IF_NONE_MATCH).and_then(|v| v.to_str().ok())
            && !inm.starts_with("W/")
        {
            let suffix = format!("-{}\"", encoding.name());
            if let Some(stripped) = inm.strip_suffix(&suffix)
                && let Ok(value) = HeaderValue::from_str(&format!("{stripped}\""))
            {
                headers.insert(http::header::IF_NONE_MATCH, value);
            }
        }
        Some(encoding)
    }

    /// Compresses the response if it qualifies.
    pub async fn apply(&self, encoding: Encoding, head_request: bool, response: Response<Body>) -> Response<Body> {
        if head_request || !self.qualifies(&response) {
            return response;
        }
        let (mut parts, body) = response.into_parts();
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
            && let Ok(value) = HeaderValue::from_str(&format!("{}-{}\"", etag.trim_end_matches('"'), encoding.name()))
        {
            headers.insert(ETAG, value);
        }
        let mut encoder = Encoder::new(encoding, self);
        if known_length.is_some() {
            let compressed = match http_body_util::BodyExt::collect(body).await {
                Ok(collected) => encoder.compress_all(&collected.to_bytes()),
                Err(e) => Err(std::io::Error::other(e.to_string())),
            };
            return match compressed {
                Ok(bytes) => {
                    parts
                        .headers
                        .insert(CONTENT_LENGTH, HeaderValue::from(bytes.len() as u64));
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
                encoder: Some(encoder),
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
        if headers.get_all(CACHE_CONTROL).iter().any(|v| {
            v.to_str()
                .is_ok_and(|v| v.to_ascii_lowercase().contains("no-transform"))
        }) {
            return false;
        }
        let Some(content_type) = headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()) else {
            return false;
        };
        let content_type = content_type.to_ascii_lowercase();
        if content_type.starts_with("text/event-stream") {
            return false;
        }
        if !self.types.iter().any(|t| type_matches(t, &content_type)) {
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

fn type_matches(pattern: &str, content_type: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => content_type.starts_with(prefix),
        None => content_type == pattern || content_type.starts_with(&format!("{pattern};")),
    }
}

pub fn has_vary(headers: &HeaderMap, field: &str) -> bool {
    headers
        .get_all(VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|v| v.trim().eq_ignore_ascii_case(field) || v.trim() == "*")
}

/// A streaming compressor: each `write` returns what the input produced, flushed.
enum Encoder {
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    Zstd(Option<zstd::stream::write::Encoder<'static, Vec<u8>>>),
    Br(Option<Box<brotli::CompressorWriter<Vec<u8>>>>),
}

impl Encoder {
    fn new(encoding: Encoding, config: &Encode) -> Encoder {
        match encoding {
            Encoding::Gzip => Encoder::Gzip(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::new(config.gzip_level),
            )),
            Encoding::Zstd => Encoder::Zstd(zstd::stream::write::Encoder::new(Vec::new(), config.zstd_level).ok()),
            Encoding::Br => Encoder::Br(Some(Box::new(brotli::CompressorWriter::new(
                Vec::new(),
                4096,
                config.br_level,
                22,
            )))),
        }
    }

    fn write(&mut self, data: &[u8]) -> std::io::Result<Bytes> {
        fn out(buffer: &mut Vec<u8>) -> Bytes {
            Bytes::from(std::mem::take(buffer))
        }
        match self {
            Encoder::Gzip(e) => {
                e.write_all(data)?;
                e.flush()?;
                Ok(out(e.get_mut()))
            }
            Encoder::Zstd(Some(e)) => {
                e.write_all(data)?;
                e.flush()?;
                Ok(out(e.get_mut()))
            }
            Encoder::Br(Some(e)) => {
                e.write_all(data)?;
                e.flush()?;
                Ok(out(e.get_mut()))
            }
            _ => Err(std::io::Error::other("encoder already finished")),
        }
    }

    /// A whole body: no intermediate flushes.
    fn compress_all(&mut self, data: &[u8]) -> std::io::Result<Bytes> {
        match self {
            Encoder::Gzip(e) => e.write_all(data)?,
            Encoder::Zstd(Some(e)) => e.write_all(data)?,
            Encoder::Br(Some(e)) => e.write_all(data)?,
            _ => return Err(std::io::Error::other("encoder already finished")),
        }
        self.finish()
    }

    fn finish(&mut self) -> std::io::Result<Bytes> {
        match self {
            Encoder::Gzip(e) => {
                e.try_finish()?;
                Ok(Bytes::from(std::mem::take(e.get_mut())))
            }
            Encoder::Zstd(e) => match e.take() {
                Some(e) => Ok(Bytes::from(e.finish()?)),
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
            format!("\"abc-{}\"", encoding.name()).as_str()
        );
        let compressed = response.into_body().collect().await.unwrap().to_bytes();
        let mut plain = Vec::new();
        match encoding {
            Encoding::Gzip => {
                flate2::read::GzDecoder::new(&compressed[..])
                    .read_to_end(&mut plain)
                    .unwrap();
            }
            Encoding::Zstd => plain = zstd::stream::decode_all(&compressed[..]).unwrap(),
            Encoding::Br => {
                brotli::Decompressor::new(&compressed[..], 4096)
                    .read_to_end(&mut plain)
                    .unwrap();
            }
        }
        assert_eq!(plain, text.as_bytes());
        compressed.to_vec()
    }

    #[tokio::test]
    async fn compresses_and_decompresses() {
        for encoding in [Encoding::Gzip, Encoding::Zstd, Encoding::Br] {
            let compressed = roundtrip(encoding).await;
            assert!(compressed.len() < 200, "{encoding:?}: {}", compressed.len());
        }
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
    }

    #[test]
    fn strips_etag_suffix_from_if_none_match() {
        let config = Encode {
            formats: vec![Encoding::Br],
            ..Encode::default()
        };
        let mut h = headers("br");
        h.insert(http::header::IF_NONE_MATCH, HeaderValue::from_static("\"abc-br\""));
        assert_eq!(config.choose(AcceptEncoding::parse(&h), &mut h), Some(Encoding::Br));
        assert_eq!(h[http::header::IF_NONE_MATCH], "\"abc\"");
    }
}
