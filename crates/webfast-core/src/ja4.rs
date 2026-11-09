//! JA4, the TLS client's fingerprint (FoxIO's JA4: TLS Client Fingerprinting, BSD 3-Clause;
//! technical_details/JA4.md): read from the bytes the client sent first, its ClientHello, once
//! per connection. `t13d1516h2_8daaf6152771_e5627efa2ab1`: the transport, the TLS version, SNI
//! or not, the counts of ciphers and extensions, the first ALPN's first and last characters;
//! then SHA-256 (12 hex) of the sorted ciphers; then of the sorted extensions (without SNI and
//! ALPN) and the signature algorithms in their order. GREASE values are left out everywhere.
//!
//! Only JA4 itself: the JA4+ methods (JA4S, JA4H, JA4T …) are under another license.
//!
//! A hello that cannot be read (cut short, not TLS, past the bound the caller keeps) gives no
//! fingerprint: absence is never a signal.

use std::fmt;

/// A JA4 fingerprint: always 36 ASCII characters, held inline.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ja4([u8; 36]);

impl Ja4 {
    /// A fingerprint as written (`t13d1516h2_8daaf6152771_e5627efa2ab1`): 36 characters, its
    /// parts where they belong, lowercase hex; `None` for anything else.
    pub fn parse(text: &str) -> Option<Ja4> {
        let bytes: [u8; 36] = text.as_bytes().try_into().ok()?;
        let hex = |range: std::ops::Range<usize>| bytes[range].iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        let shape = matches!(bytes[0], b't' | b'q' | b'd')
            && bytes[1..3].iter().all(u8::is_ascii_alphanumeric)
            && matches!(bytes[3], b'd' | b'i')
            && bytes[4..8].iter().all(u8::is_ascii_digit)
            && bytes[8..10].iter().all(u8::is_ascii_alphanumeric)
            && bytes[10] == b'_'
            && hex(11..23)
            && bytes[23] == b'_'
            && hex(24..36);
        shape.then_some(Ja4(bytes))
    }

    pub fn as_str(&self) -> &str {
        // Built from ASCII alone (`fingerprint`).
        std::str::from_utf8(&self.0).unwrap_or("")
    }

    /// Its first part, `t13d1516h2`: transport, version, SNI, the counts, ALPN.
    pub fn a(&self) -> &str {
        &self.as_str()[..10]
    }
}

impl fmt::Display for Ja4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Ja4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ja4({})", self.as_str())
    }
}

/// What JA4 takes of a ClientHello, GREASE left out.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Hello {
    /// The highest of `supported_versions`, else the hello's own version.
    pub version: u16,
    pub sni: bool,
    pub ciphers: Vec<u16>,
    /// In the order the client sent them.
    pub extensions: Vec<u16>,
    /// In the order the client sent them.
    pub signature_algorithms: Vec<u16>,
    /// The first ALPN protocol, when there is one.
    pub alpn: Option<Vec<u8>>,
}

/// A GREASE value (RFC 8701): `0x?a?a` with both bytes equal.
fn grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.bytes.len() < n {
            return None;
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Option<usize> {
        self.take(3)
            .map(|b| usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
    }

    /// A vector with a length prefix of `width` bytes.
    fn vec(&mut self, width: usize) -> Option<Reader<'a>> {
        let len = match width {
            1 => usize::from(self.u8()?),
            _ => usize::from(self.u16()?),
        };
        self.take(len).map(|bytes| Reader { bytes })
    }

    fn u16s(mut self) -> Option<Vec<u16>> {
        if !self.bytes.len().is_multiple_of(2) {
            return None;
        }
        let mut out = Vec::with_capacity(self.bytes.len() / 2);
        while !self.bytes.is_empty() {
            out.push(self.u16()?);
        }
        Some(out)
    }
}

/// The handshake bytes of the TLS records at the start of `wire`, up to the first ClientHello's
/// end; `None` until they are all there, or when `wire` is not TLS handshake records.
fn handshake(wire: &[u8]) -> Option<Vec<u8>> {
    let mut records = Reader { bytes: wire };
    let mut joined: Vec<u8> = Vec::new();
    loop {
        // A record: type 22 (handshake), a version, a length.
        if records.u8()? != 22 {
            return None;
        }
        records.u16()?;
        let len = usize::from(records.u16()?);
        joined.extend_from_slice(records.take(len)?);
        if joined.len() >= 4 {
            let need = 4 + (usize::from(joined[1]) << 16 | usize::from(joined[2]) << 8 | usize::from(joined[3]));
            if joined.len() >= need {
                joined.truncate(need);
                return Some(joined);
            }
        }
    }
}

/// The ClientHello at the start of `wire` (the bytes as the client sent them), its records
/// joined; `None` when they are not all there or are not a ClientHello.
pub fn parse(wire: &[u8]) -> Option<Hello> {
    let handshake = handshake(wire)?;
    let mut message = Reader { bytes: &handshake };
    if message.u8()? != 1 {
        return None; // not a ClientHello
    }
    let len = message.u24()?;
    let mut body = Reader {
        bytes: message.take(len)?,
    };
    let legacy_version = body.u16()?;
    body.take(32)?; // random
    body.vec(1)?; // session id
    let ciphers: Vec<u16> = body.vec(2)?.u16s()?.into_iter().filter(|c| !grease(*c)).collect();
    body.vec(1)?; // compression methods
    let mut hello = Hello {
        version: legacy_version,
        ciphers,
        ..Hello::default()
    };
    // Extensions are optional (a hello of TLS 1.2 and before may have none).
    if body.bytes.is_empty() {
        return Some(hello);
    }
    let mut extensions = body.vec(2)?;
    let mut supported: Option<u16> = None;
    while !extensions.bytes.is_empty() {
        let kind = extensions.u16()?;
        let mut data = extensions.vec(2)?;
        if grease(kind) {
            continue;
        }
        hello.extensions.push(kind);
        match kind {
            0x0000 => hello.sni = true,
            0x0010 => {
                let mut list = data.vec(2)?;
                if !list.bytes.is_empty() {
                    let first = list.vec(1)?;
                    hello.alpn = Some(first.bytes.to_vec());
                }
            }
            0x000d => hello.signature_algorithms = data.vec(2)?.u16s()?,
            0x002b => {
                let versions = data.vec(1)?.u16s()?;
                supported = versions.into_iter().filter(|v| !grease(*v)).max();
            }
            _ => {}
        }
    }
    if let Some(version) = supported {
        hello.version = version;
    }
    Some(hello)
}

fn version_code(version: u16) -> &'static [u8; 2] {
    match version {
        0x0304 => b"13",
        0x0303 => b"12",
        0x0302 => b"11",
        0x0301 => b"10",
        0x0300 => b"s3",
        0x0002 => b"s2",
        0xfeff => b"d1",
        0xfefd => b"d2",
        0xfefc => b"d3",
        _ => b"00",
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// The first ALPN's first and last characters; its hex digits when either is no ASCII letter
/// or digit; `00` without one.
fn alpn_code(alpn: Option<&[u8]>) -> [u8; 2] {
    match alpn {
        Some(value) if !value.is_empty() => {
            let (first, last) = (value[0], value[value.len() - 1]);
            if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
                [first, last]
            } else {
                [HEX[usize::from(first >> 4)], HEX[usize::from(last & 0x0f)]]
            }
        }
        _ => *b"00",
    }
}

fn count(n: usize) -> [u8; 2] {
    let n = n.min(99) as u8;
    [b'0' + n / 10, b'0' + n % 10]
}

/// `0a0b,0c0d`: each value's four hex digits, comma-separated.
fn list(values: &[u16], out: &mut String) {
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        for shift in [12, 8, 4, 0] {
            out.push(HEX[usize::from(value >> shift & 0xf)] as char);
        }
    }
}

/// The first 12 hex digits of the text's SHA-256; `000000000000` for no values.
fn hash12(text: &str, empty: bool, out: &mut [u8]) {
    if empty {
        out.fill(b'0');
        return;
    }
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, text.as_bytes());
    for (i, byte) in digest.as_ref().iter().take(6).enumerate() {
        out[2 * i] = HEX[usize::from(byte >> 4)];
        out[2 * i + 1] = HEX[usize::from(byte & 0xf)];
    }
}

/// The sorted ciphers' list, and the sorted extensions (SNI and ALPN out) with the signature
/// algorithms: the texts JA4's two hashes are of, and JA4_r's last parts.
fn texts(hello: &Hello) -> (String, String) {
    let mut ciphers = hello.ciphers.clone();
    ciphers.sort_unstable();
    let mut extensions: Vec<u16> = hello
        .extensions
        .iter()
        .copied()
        .filter(|e| *e != 0x0000 && *e != 0x0010)
        .collect();
    extensions.sort_unstable();
    let mut b = String::with_capacity(ciphers.len() * 5);
    list(&ciphers, &mut b);
    let mut c = String::with_capacity((extensions.len() + hello.signature_algorithms.len()) * 5 + 1);
    list(&extensions, &mut c);
    if !hello.signature_algorithms.is_empty() {
        c.push('_');
        list(&hello.signature_algorithms, &mut c);
    }
    (b, c)
}

/// The first part: `t13d1516h2` (`quic`: `q` for the transport).
fn part_a(hello: &Hello, quic: bool) -> [u8; 10] {
    let mut a = [0u8; 10];
    a[0] = if quic { b'q' } else { b't' };
    a[1..3].copy_from_slice(version_code(hello.version));
    a[3] = if hello.sni { b'd' } else { b'i' };
    a[4..6].copy_from_slice(&count(hello.ciphers.len()));
    a[6..8].copy_from_slice(&count(hello.extensions.len()));
    a[8..10].copy_from_slice(&alpn_code(hello.alpn.as_deref()));
    a
}

/// JA4 of `hello`.
pub fn fingerprint(hello: &Hello, quic: bool) -> Ja4 {
    let mut out = [b'_'; 36];
    out[..10].copy_from_slice(&part_a(hello, quic));
    let (b, c) = texts(hello);
    hash12(&b, hello.ciphers.is_empty(), &mut out[11..23]);
    let no_extensions = !hello.extensions.iter().any(|e| *e != 0x0000 && *e != 0x0010);
    hash12(&c, no_extensions, &mut out[24..36]);
    Ja4(out)
}

/// JA4_r, the raw form: the first part, then the sorted lists the hashes are of.
pub fn raw(hello: &Hello, quic: bool) -> String {
    let a = part_a(hello, quic);
    let (b, c) = texts(hello);
    let mut out = String::with_capacity(11 + b.len() + 1 + c.len());
    out.push_str(std::str::from_utf8(&a).unwrap_or(""));
    out.push('_');
    out.push_str(&b);
    out.push('_');
    out.push_str(&c);
    out
}

/// The fingerprint of the hello at the start of `wire`, if it can be read.
pub fn of_wire(wire: &[u8]) -> Option<Ja4> {
    parse(wire).map(|hello| fingerprint(&hello, false))
}

/// What is kept of a connection's first bytes: a ClientHello with a post-quantum key share is
/// some 2 KiB, one record holds 16 KiB.
const RECORDED: usize = 16 * 1024;

/// A TCP stream that keeps a copy of the first bytes read from it, for the fingerprint of the
/// ClientHello the TLS handshake reads: the same bytes, read once, by the handshake itself (no
/// `peek`, which would wake again and again on a hello that arrives in parts). `fingerprint`
/// after the handshake reads them and stops the recording; each read after costs a branch.
pub struct Recorded<S> {
    inner: S,
    first: Option<Vec<u8>>,
}

impl<S> Recorded<S> {
    pub fn new(inner: S) -> Recorded<S> {
        Recorded {
            inner,
            first: Some(Vec::new()),
        }
    }

    /// The fingerprint of what was read so far; the copy is dropped and no more is kept.
    pub fn fingerprint(&mut self) -> Option<Ja4> {
        self.first.take().and_then(|bytes| of_wire(&bytes))
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Recorded<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let this = &mut *self;
        let polled = std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Some(first) = this.first.as_mut() {
            let new = &buf.filled()[before..];
            let room = RECORDED.saturating_sub(first.len());
            first.extend_from_slice(&new[..new.len().min(room)]);
        }
        polled
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Recorded<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example of technical_details/JA4.md: its ciphers, extensions (in the order sent),
    /// signature algorithms and ALPN.
    fn spec_hello() -> Hello {
        Hello {
            version: 0x0304,
            sni: true,
            ciphers: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d,
                0x002f, 0x0035,
            ],
            extensions: vec![
                0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01,
                0x000b, 0x000a, 0x0015,
            ],
            signature_algorithms: vec![0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
            alpn: Some(b"h2".to_vec()),
        }
    }

    #[test]
    fn the_spec_example_gives_its_fingerprint_and_raw_form() {
        let hello = spec_hello();
        assert_eq!(
            fingerprint(&hello, false).as_str(),
            "t13d1516h2_8daaf6152771_e5627efa2ab1"
        );
        assert_eq!(
            raw(&hello, false),
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
        );
        // Without signature algorithms the list ends without an underscore (the spec's value).
        let mut no_sigs = hello.clone();
        no_sigs.signature_algorithms.clear();
        assert_eq!(&fingerprint(&no_sigs, false).as_str()[24..], "6d807ffa2a79");
        assert_eq!(fingerprint(&hello, true).a(), "q13d1516h2");
        let parsed = Ja4::parse("t13d1516h2_8daaf6152771_e5627efa2ab1").unwrap();
        assert_eq!(parsed, fingerprint(&hello, false));
        for bad in [
            "",
            "t13d1516h2_8daaf6152771_e5627efa2ab",
            "t13d1516h2_8daaf6152771_e5627efa2ab1x",
            "x13d1516h2_8daaf6152771_e5627efa2ab1",
            "t13d1516h2-8daaf6152771_e5627efa2ab1",
            "t13d1516h2_8DAAF6152771_e5627efa2ab1",
            "t13x1516h2_8daaf6152771_e5627efa2ab1",
        ] {
            assert_eq!(Ja4::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn empty_lists_are_zeros_and_alpn_follows_the_spec() {
        let hello = Hello {
            version: 0x0303,
            ..Hello::default()
        };
        assert_eq!(
            fingerprint(&hello, false).as_str(),
            "t12i000000_000000000000_000000000000"
        );
        for (alpn, code) in [
            (&b"http/1.1"[..], *b"h1"),
            (b"h", *b"hh"),
            (b"\xab", *b"ab"),
            (b"\x20", *b"20"),
            (b"\xab\xcd", *b"ad"),
            (b"\x20\x61", *b"21"),
            (b"\x30\xab", *b"3b"),
            (b"\x61\x20", *b"60"),
            (b"\x30\x31\xab\xcd", *b"3d"),
            (b"\x30\xab\xcd\x31", *b"01"),
        ] {
            assert_eq!(alpn_code(Some(alpn)), code, "{alpn:?}");
        }
        assert_eq!(alpn_code(Some(b"")), *b"00");
        assert_eq!(alpn_code(None), *b"00");
        assert_eq!(count(150), *b"99");
    }

    /// The spec's hello as a client sends it: GREASE in every list, in one record or split over
    /// two.
    fn wire(split: Option<usize>) -> Vec<u8> {
        let hello = spec_hello();
        let mut ext = Vec::new();
        let mut push_ext = |kind: u16, data: &[u8]| {
            ext.extend_from_slice(&kind.to_be_bytes());
            ext.extend_from_slice(&(data.len() as u16).to_be_bytes());
            ext.extend_from_slice(data);
        };
        push_ext(0x0a0a, &[]); // GREASE
        for kind in &hello.extensions {
            let data: Vec<u8> = match kind {
                0x0000 => {
                    let name = b"www.example.com";
                    let mut d = ((name.len() + 3) as u16).to_be_bytes().to_vec();
                    d.push(0);
                    d.extend_from_slice(&(name.len() as u16).to_be_bytes());
                    d.extend_from_slice(name);
                    d
                }
                0x0010 => {
                    let mut d = 12u16.to_be_bytes().to_vec();
                    d.push(2);
                    d.extend_from_slice(b"h2");
                    d.push(8);
                    d.extend_from_slice(b"http/1.1");
                    d
                }
                0x000d => {
                    let mut d = ((hello.signature_algorithms.len() * 2) as u16).to_be_bytes().to_vec();
                    for s in &hello.signature_algorithms {
                        d.extend_from_slice(&s.to_be_bytes());
                    }
                    d
                }
                0x002b => vec![6, 0x3a, 0x3a, 0x03, 0x04, 0x03, 0x03],
                _ => vec![],
            };
            push_ext(*kind, &data);
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7; 32]);
        body.push(0);
        let ciphers: Vec<u16> = std::iter::once(0x2a2a).chain(hello.ciphers.iter().copied()).collect();
        body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        for c in ciphers {
            body.extend_from_slice(&c.to_be_bytes());
        }
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut message = vec![1];
        message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        let record = |payload: &[u8]| {
            let mut r = vec![22, 0x03, 0x01];
            r.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            r.extend_from_slice(payload);
            r
        };
        match split {
            None => record(&message),
            Some(at) => [record(&message[..at]), record(&message[at..])].concat(),
        }
    }

    #[test]
    fn a_hello_off_the_wire_reads_as_the_spec_says_grease_left_out() {
        let expected = "t13d1516h2_8daaf6152771_e5627efa2ab1";
        assert_eq!(of_wire(&wire(None)).unwrap().as_str(), expected);
        for at in [3, 40, 100] {
            assert_eq!(of_wire(&wire(Some(at))).unwrap().as_str(), expected, "split at {at}");
        }
        // Bytes after the hello (the next flight) change nothing.
        let mut more = wire(None);
        more.extend_from_slice(&[0x14, 3, 3, 0, 1, 1]);
        assert_eq!(of_wire(&more).unwrap().as_str(), expected);
    }

    /// The recording keeps what the reader read, as it read it, and stops at `fingerprint`.
    #[tokio::test]
    async fn a_recorded_stream_fingerprints_what_was_read_through_it() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let hello = wire(Some(40));
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut recorded = Recorded::new(server);
        // The hello in three writes, read in small pieces.
        let (a, rest) = hello.split_at(7);
        let (b, c) = rest.split_at(50);
        for part in [a, b, c] {
            client.write_all(part).await.unwrap();
        }
        let mut got = vec![0u8; hello.len()];
        let mut at = 0;
        while at < got.len() {
            let n = recorded.read(&mut got[at..(at + 13).min(hello.len())]).await.unwrap();
            at += n;
        }
        assert_eq!(got, hello, "the reader gets the bytes as they are");
        assert_eq!(
            recorded.fingerprint().map(|f| f.to_string()).as_deref(),
            Some("t13d1516h2_8daaf6152771_e5627efa2ab1")
        );
        assert_eq!(recorded.fingerprint(), None, "taken once; nothing kept after");
        client.write_all(b"later").await.unwrap();
        let mut later = [0u8; 5];
        recorded.read_exact(&mut later).await.unwrap();
        assert_eq!(&later, b"later");
        assert!(recorded.first.is_none(), "no copy after the fingerprint");
    }

    /// A real handshake (rustls on both sides) through `Recorded`: it completes, the fingerprint
    /// is that of rustls's own hello (TLS 1.3, SNI, ALPN `h2`), and data goes both ways after.
    #[tokio::test]
    async fn a_rustls_handshake_through_the_recording_gives_the_clients_fingerprint() {
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let provider = || Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());
        let mut server = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], key)
            .unwrap();
        server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certified.cert.der().clone()).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let accepting = tokio::spawn(async move { acceptor.accept(Recorded::new(server_io)).await.unwrap() });
        let mut client = connector
            .connect("localhost".try_into().unwrap(), client_io)
            .await
            .unwrap();
        let mut server = accepting.await.unwrap();
        let ja4 = server.get_mut().0.fingerprint().expect("the hello was read");
        assert!(ja4.a().starts_with("t13d"), "{ja4}");
        assert!(ja4.a().ends_with("h2"), "{ja4}");
        assert_eq!(ja4.as_str().len(), 36);

        client.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        server.write_all(b"pong").await.unwrap();
        server.flush().await.unwrap();
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pong");
    }

    #[test]
    fn what_is_cut_short_or_not_a_hello_gives_none() {
        let full = wire(None);
        for cut in [0, 1, 4, 5, 9, 60, full.len() - 1] {
            assert_eq!(of_wire(&full[..cut]), None, "cut at {cut}");
        }
        assert_eq!(of_wire(b"GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(of_wire(&[22, 3, 1, 0, 4, 2, 0, 0, 0]), None, "a ServerHello");
        // Garbage of every length: no panic.
        let mut x: u32 = 7;
        for len in 0..300 {
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                    (x >> 16) as u8
                })
                .collect();
            let _ = of_wire(&bytes);
            let mut framed = vec![22, 3, 1, (len >> 8) as u8, len as u8];
            framed.extend_from_slice(&bytes);
            let _ = of_wire(&framed);
        }
    }
}
