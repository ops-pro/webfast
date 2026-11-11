//! The request's id (docs/logging.md, "The request's id"): what ties together the lines one
//! request writes — the access log's, the request checks', the modules' — in every output,
//! whatever each one hides of the address and the URI.
//!
//! A request carries a reference, not text: 64 bits drawn once per process, and the number of the
//! thread that took the request with that thread's count of requests (no lock, no random draw).
//! The text, 32 hexadecimal characters (a W3C trace id's shape), is made from it where it is
//! written, the same every time. A peer trusted for the client's address (`trusted_proxies`) may
//! give it in `X-Request-Id`; from anyone else that header is ignored, or a client could tie its
//! lines to another's. A trusted `traceparent` gives the trace's id, a field of its own: one trace
//! covers many requests.

use http::HeaderMap;
use http::HeaderValue;
use std::cell::Cell;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// The longest `X-Request-Id` taken from a trusted peer.
const MAX_GIVEN: usize = 128;

/// One request's id, in its extensions (src/server.rs) when something may write it.
#[derive(Debug, Clone)]
pub struct RequestId {
    /// The thread's number (high 24 bits) and its count of requests.
    local: u64,
    /// `X-Request-Id` from a trusted peer: the id as given.
    given: Option<HeaderValue>,
    /// `traceparent`'s trace id from a trusted peer.
    trace: Option<u128>,
}

/// Drawn once per process: what makes the ids of two processes differ.
fn process() -> u64 {
    static PROCESS: OnceLock<u64> = OnceLock::new();
    *PROCESS.get_or_init(|| {
        let mut bytes = [0u8; 8];
        aws_lc_rs::rand::fill(&mut bytes).expect("random bytes");
        u64::from_be_bytes(bytes)
    })
}

thread_local! {
    /// This thread's number (taken at its first request) and its count of requests.
    static THREAD: Cell<Option<(u64, u64)>> = const { Cell::new(None) };
}

impl RequestId {
    /// The next id of this thread; with `trusted` (the peer is a trusted proxy), the id and the
    /// trace a proxy before it gave.
    pub fn next(headers: &HeaderMap, trusted: bool) -> RequestId {
        static THREADS: AtomicU64 = AtomicU64::new(0);
        let local = THREAD.with(|cell| {
            let (thread, count) = cell
                .get()
                .unwrap_or_else(|| (THREADS.fetch_add(1, Ordering::Relaxed) & 0xff_ffff, 0));
            cell.set(Some((thread, count.wrapping_add(1))));
            (thread << 40) | (count & 0xff_ffff_ffff)
        });
        let (given, trace) = if trusted {
            (
                headers
                    .get("x-request-id")
                    .filter(|v| {
                        !v.is_empty() && v.len() <= MAX_GIVEN && v.as_bytes().iter().all(|b| b.is_ascii_graphic())
                    })
                    .cloned(),
                headers.get("traceparent").and_then(|v| trace_id(v.as_bytes())),
            )
        } else {
            (None, None)
        };
        RequestId { local, given, trace }
    }

    /// Writes the id: as given by a trusted peer, or 32 hexadecimal characters. A given one is
    /// visible ASCII; the caller escapes it for JSON (`"` and `\` may be in it).
    pub fn write(&self, out: &mut String) {
        match &self.given {
            Some(given) => out.push_str(given.to_str().unwrap_or("")),
            None => push_hex(out, process(), self.local),
        }
    }

    /// Whether a trusted peer gave the id (then it may need escaping in JSON; an own one is hex).
    pub fn is_given(&self) -> bool {
        self.given.is_some()
    }

    /// The id as text (`{http.request.id}`).
    pub fn text(&self) -> String {
        let mut out = String::with_capacity(32);
        self.write(&mut out);
        out
    }

    /// The trace's id, 32 hexadecimal characters, when a trusted peer gave a `traceparent`.
    pub fn write_trace(&self, out: &mut String) -> bool {
        match self.trace {
            Some(trace) => {
                push_hex(out, (trace >> 64) as u64, trace as u64);
                true
            }
            None => false,
        }
    }
}

/// `high` and `low` as 32 lower-case hexadecimal digits (`write!` with `{:016x}` costs several
/// times as much, on every line).
fn push_hex(out: &mut String, high: u64, low: u64) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = [0u8; 32];
    for (i, slot) in text.iter_mut().enumerate() {
        let word = if i < 16 { high } else { low };
        let shift = 60 - 4 * (i % 16);
        *slot = DIGITS[((word >> shift) & 0xf) as usize];
    }
    out.push_str(std::str::from_utf8(&text).expect("ASCII"));
}

/// The trace id of a `traceparent` (`00-<32 hex>-<16 hex>-<2 hex>`, W3C Trace Context), not all
/// zeros.
fn trace_id(value: &[u8]) -> Option<u128> {
    let text = std::str::from_utf8(value).ok()?.trim();
    let mut parts = text.split('-');
    let version = parts.next()?;
    let trace = parts.next()?;
    let parent = parts.next()?;
    let flags = parts.next()?;
    let hex = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !hex(version, 2) || version == "ff" || !hex(trace, 32) || !hex(parent, 16) || !hex(flags, 2) {
        return None;
    }
    // Version 00 has exactly four parts; a later one may add more.
    if version == "00" && parts.next().is_some() {
        return None;
    }
    u128::from_str_radix(trace, 16).ok().filter(|t| *t != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_differ_and_keep_their_text() {
        let headers = HeaderMap::new();
        let one = RequestId::next(&headers, false);
        let two = RequestId::next(&headers, false);
        assert_eq!(one.text().len(), 32);
        assert!(one.text().bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(one.text(), two.text());
        assert_eq!(one.text(), one.clone().text(), "the same text every time");
        assert_eq!(one.text()[..16], two.text()[..16], "the process's part");
        let other = std::thread::spawn(move || RequestId::next(&HeaderMap::new(), false).text())
            .join()
            .unwrap();
        assert_ne!(other[16..22], one.text()[16..22], "another thread's number");
    }

    #[test]
    fn a_trusted_peer_gives_the_id_and_the_trace() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", HeaderValue::from_static("lb-42"));
        headers.insert(
            "traceparent",
            HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        let trusted = RequestId::next(&headers, true);
        assert_eq!(trusted.text(), "lb-42");
        let mut trace = String::new();
        assert!(trusted.write_trace(&mut trace));
        assert_eq!(trace, "4bf92f3577b34da6a3ce929d0e0e4736");
        let untrusted = RequestId::next(&headers, false);
        assert_eq!(untrusted.text().len(), 32);
        assert!(!untrusted.write_trace(&mut String::new()));
        // Not taken: too long, not visible ASCII, a malformed or all-zero trace.
        headers.insert("x-request-id", HeaderValue::from_str(&"a".repeat(200)).unwrap());
        headers.insert(
            "traceparent",
            HeaderValue::from_static("00-00000000000000000000000000000000-00f067aa0ba902b7-01"),
        );
        let refused = RequestId::next(&headers, true);
        assert_eq!(refused.text().len(), 32);
        assert!(!refused.write_trace(&mut String::new()));
        assert!(trace_id(b"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01").is_none());
        assert!(trace_id(b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-x").is_none());
    }
}
