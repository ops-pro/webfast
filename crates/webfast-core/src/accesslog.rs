//! Access logs (`log` in a site block): one line per request when its response body is finished,
//! JSON in Caddy's shape (`logger: http.log.access`, `msg: handled request`) or a console line.
//! Request headers are not logged (they carry cookies and other personal data).
//!
//! Lines are written in batches: the request formats its line (no JSON library, one string) and
//! hands it to the output's writer thread, which wakes every `WEB_LOG_FLUSH_MS` (10 ms), takes
//! what has queued up and writes it with one call. A request never waits for the terminal or the log collector; if the
//! queue is full (the output is stuck), lines are dropped and counted rather than slowing requests.

use bytes::Bytes;
use http::{HeaderValue, Method, Uri};
use http_body::Frame;
use std::fmt::Write as _;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    Stdout,
    Stderr,
    Discard,
    /// Appended to; opened again when the path no longer names the file that is open (logrotate
    /// moved or removed it), so rotation needs no signal.
    File(&'static Path),
}

impl Output {
    /// `stdout`, `stderr`, `discard`, or a file path (relative ones under `base`).
    pub fn parse(text: &str, base: &Path) -> Output {
        match text {
            "stdout" => Output::Stdout,
            "stderr" => Output::Stderr,
            "discard" => Output::Discard,
            path => Output::File(Box::leak(base.join(path).into_boxed_path())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Console,
}

/// Two small enums: copied into each request that logs, so that no count on the site is touched.
#[derive(Debug, Clone, Copy)]
pub struct AccessLog {
    pub output: Output,
    pub format: Format,
}

/// What is known about a request when it arrives (cheap copies: no strings are built until the
/// line is written).
pub struct RequestInfo {
    pub remote: SocketAddr,
    pub client_ip: IpAddr,
    pub proto: &'static str,
    pub method: Method,
    pub host: Option<HeaderValue>,
    pub uri: Uri,
    pub started: Instant,
}

/// How many lines may wait for a writer thread.
const QUEUE_LINES: usize = 65_536;

/// How often the writer threads wake up: `WEB_LOG_FLUSH_MS` (1–10 000), 10 ms by default (larger
/// batches showed in the p99 latency).
fn batch_interval() -> Duration {
    let ms = std::env::var("WEB_LOG_FLUSH_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|ms| (1..=10_000).contains(ms))
        .unwrap_or(10);
    Duration::from_millis(ms)
}

enum Message {
    Line(String),
    Flush(SyncSender<()>),
}

/// The queue of one output's writer thread.
pub(crate) struct Writer {
    queue: SyncSender<Message>,
    dropped: AtomicU64,
}

impl Writer {
    /// Queues `line` (newline included); dropped and counted when the queue is full (the output
    /// is stuck), so that no request waits on it.
    pub(crate) fn write(&self, line: String) {
        if let Err(TrySendError::Full(_)) = self.queue.try_send(Message::Line(line)) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

static STDOUT: OnceLock<Writer> = OnceLock::new();
static STDERR: OnceLock<Writer> = OnceLock::new();
/// One writer per log file.
static FILES: Mutex<Vec<(&'static Path, &'static Writer)>> = Mutex::new(Vec::new());
/// Writer threads started so far (flushed on shutdown).
static STARTED: Mutex<Vec<Output>> = Mutex::new(Vec::new());

/// The writer of an output, started on first use; `None` for `discard`. A file's is found in a
/// list under a lock: resolved once, where the output is configured (src/eventlog.rs), not per
/// line.
pub(crate) fn writer(output: Output) -> Option<&'static Writer> {
    let cell = match output {
        Output::Stdout => &STDOUT,
        Output::Stderr => &STDERR,
        Output::Discard => return None,
        Output::File(path) => {
            let mut files = FILES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some((_, writer)) = files.iter().find(|(p, _)| *p == path) {
                return Some(writer);
            }
            let writer: &'static Writer = Box::leak(Box::new(start_writer(output)));
            files.push((path, writer));
            return Some(writer);
        }
    };
    Some(cell.get_or_init(|| start_writer(output)))
}

fn start_writer(output: Output) -> Writer {
    let (queue, receiver) = sync_channel(QUEUE_LINES);
    std::thread::Builder::new()
        .name("log-writer".into())
        .spawn(move || write_batches(output, receiver))
        .expect("a log writer thread");
    if let Ok(mut started) = STARTED.lock() {
        started.push(output);
    }
    Writer {
        queue,
        dropped: AtomicU64::new(0),
    }
}

/// Queues `line` (newline included) for `output`; dropped and counted when its queue is full.
pub fn write_line(output: Output, line: String) {
    if let Some(writer) = writer(output) {
        writer.write(line);
    }
}

/// A log file, open for appending, and which file it is (device and inode).
type OpenFile = Option<(std::fs::File, Option<(u64, u64)>)>;

#[cfg(unix)]
fn file_id(metadata: Option<std::fs::Metadata>) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    metadata.map(|m| (m.dev(), m.ino()))
}

#[cfg(not(unix))]
fn file_id(_: Option<std::fs::Metadata>) -> Option<(u64, u64)> {
    None
}

/// Appends `bytes` to the file at `path`, opening it again first when it is no longer the one
/// open (rotated away or removed), or when there is nothing to compare with.
fn append(path: &Path, open: &mut OpenFile, bytes: &[u8]) -> std::io::Result<()> {
    let current = file_id(std::fs::metadata(path).ok());
    let stale = match open {
        Some((_, Some(id))) => current != Some(*id),
        _ => true,
    };
    if stale {
        let file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        let id = file_id(file.metadata().ok());
        *open = Some((file, id));
    }
    let (file, _) = open.as_mut().expect("opened above");
    file.write_all(bytes)
}

fn write_batches(output: Output, receiver: Receiver<Message>) {
    let mut batch: Vec<u8> = Vec::with_capacity(64 * 1024);
    let interval = batch_interval();
    let mut file: OpenFile = None;
    let mut failing = false;
    loop {
        // Sleeping rather than blocking in recv: senders then never have to wake this thread.
        std::thread::sleep(interval);
        let mut acks = Vec::new();
        let mut closed = false;
        loop {
            match receiver.try_recv() {
                Ok(Message::Line(line)) => batch.extend_from_slice(line.as_bytes()),
                Ok(Message::Flush(ack)) => acks.push(ack),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    closed = true;
                    break;
                }
            }
        }
        if !batch.is_empty() {
            let written = match output {
                Output::Stdout => std::io::stdout().lock().write_all(&batch),
                Output::Stderr => std::io::stderr().lock().write_all(&batch),
                Output::Discard => Ok(()),
                Output::File(path) => append(path, &mut file, &batch),
            };
            // Said once when writing starts failing, and once when it works again.
            match (written, failing) {
                (Err(e), false) => {
                    tracing::warn!(?output, error = %e, "cannot write the log; its lines are lost until it can");
                    failing = true;
                    file = None;
                }
                (Ok(()), true) => {
                    tracing::info!(?output, "the log is written again");
                    failing = false;
                }
                _ => {}
            }
            batch.clear();
            if batch.capacity() > 1 << 20 {
                batch.shrink_to(64 * 1024);
            }
        }
        for ack in acks {
            let _ = ack.send(());
        }
        if closed {
            return;
        }
    }
}

/// Writes out every queued line (at shutdown); waits at most `timeout`.
pub fn flush_all(timeout: Duration) {
    let outputs = STARTED.lock().map(|s| s.clone()).unwrap_or_default();
    for output in outputs {
        let Some(writer) = writer(output) else { continue };
        let (ack, done) = sync_channel(1);
        if writer.queue.send(Message::Flush(ack)).is_ok() {
            let _ = done.recv_timeout(timeout);
        }
        let dropped = writer.dropped.load(Ordering::Relaxed);
        if dropped > 0 {
            tracing::warn!(
                ?output,
                dropped,
                "access log lines dropped: the output could not keep up"
            );
        }
    }
}

impl AccessLog {
    fn write(&self, info: &RequestInfo, status: u16, size: u64) {
        if self.output == Output::Discard {
            return;
        }
        write_line(self.output, self.line(info, status, size));
    }

    /// The log line, newline included.
    fn line(&self, info: &RequestInfo, status: u16, size: u64) -> String {
        let duration = info.started.elapsed();
        let host = info.host.as_ref().and_then(|h| h.to_str().ok()).unwrap_or("");
        let uri = info.uri.path_and_query().map_or("/", |pq| pq.as_str());
        // The fixed part of a JSON line is about 300 bytes; host and URI on top (escaping may
        // still grow it, which is rare).
        let mut line = String::with_capacity(320 + host.len() + uri.len());
        match self.format {
            Format::Json => {
                line.push_str(r#"{"level":"info","ts":"#);
                write_timestamp(&mut line);
                line.push_str(r#","logger":"http.log.access","msg":"handled request","request":{"remote_ip":""#);
                let _ = write!(line, "{}", info.remote.ip());
                line.push_str(r#"","remote_port":""#);
                let _ = write!(line, "{}", info.remote.port());
                line.push_str(r#"","client_ip":""#);
                let _ = write!(line, "{}", info.client_ip);
                line.push_str(r#"","proto":""#);
                line.push_str(info.proto);
                line.push_str(r#"","method":""#);
                json_escape(&mut line, info.method.as_str());
                line.push_str(r#"","host":""#);
                json_escape(&mut line, host);
                line.push_str(r#"","uri":""#);
                json_escape(&mut line, uri);
                line.push_str(r#""},"duration":"#);
                write_seconds(&mut line, duration.as_secs(), duration.subsec_nanos(), 9);
                let _ = writeln!(line, r#","size":{size},"status":{status}}}"#);
            }
            Format::Console => {
                let _ = write!(
                    line,
                    "{} {} {} {host} {uri} {status} {size} ",
                    info.client_ip, info.proto, info.method
                );
                // Milliseconds to three places, rounded, from the microseconds.
                let micros = (duration.as_nanos() + 500) / 1000;
                let _ = writeln!(line, "{}.{:03}ms", micros / 1000, micros % 1000);
            }
        }
        line
    }
}

/// The time now as Caddy's `ts`: Unix seconds with the fraction to the microsecond.
pub(crate) fn write_timestamp(out: &mut String) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    write_seconds(out, now.as_secs(), now.subsec_nanos(), 6);
}

/// `secs.fraction`, the fraction to `digits` places (at most 9) with the trailing zeros dropped
/// but one: the JSON number a float would give, written from the integers (formatting an `f64`
/// in its shortest form costs more than the rest of the line).
pub(crate) fn write_seconds(out: &mut String, secs: u64, nanos: u32, digits: usize) {
    let digits = digits.clamp(1, 9);
    let mut frac = nanos / 10u32.pow(9 - digits as u32);
    let mut text = [b'0'; 9];
    for slot in text[..digits].iter_mut().rev() {
        *slot = b'0' + (frac % 10) as u8;
        frac /= 10;
    }
    let mut kept = digits;
    while kept > 1 && text[kept - 1] == b'0' {
        kept -= 1;
    }
    let _ = write!(out, "{secs}.");
    out.push_str(std::str::from_utf8(&text[..kept]).expect("digits"));
}

/// JSON string contents: quotes, backslashes and control characters escaped (the access log's and
/// the modules' own JSON lines).
pub fn json_escape(out: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// A request's log line in waiting: counts the bytes of the response body's frames as they are
/// shown to it, and writes the line when told the body ended, or when dropped. Carried by the
/// response body's own wrapper (src/guard.rs `Tracked`), not a body of its own.
pub struct Logged {
    log: AccessLog,
    info: Option<RequestInfo>,
    status: u16,
    size: u64,
}

impl Logged {
    pub fn new(log: AccessLog, info: RequestInfo, status: u16) -> Logged {
        Logged {
            log,
            info: Some(info),
            status,
            size: 0,
        }
    }

    /// A frame of the response body went out.
    pub fn count(&mut self, frame: &Frame<Bytes>) {
        if let Some(data) = frame.data_ref() {
            self.size += data.len() as u64;
        }
    }

    /// The body ended: the line is written (once).
    pub fn finish(&mut self) {
        if let Some(info) = self.info.take() {
            self.log.write(&info, self.status, self.size);
        }
    }
}

impl Drop for Logged {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_lines_are_valid_and_escaped() {
        let mut out = String::new();
        json_escape(&mut out, "a\"b\\c\nd\u{1}");
        assert_eq!(out, "a\\\"b\\\\c\\nd\\u0001");
        let info = RequestInfo {
            remote: "10.0.0.2:4000".parse().unwrap(),
            client_ip: "203.0.113.9".parse().unwrap(),
            proto: "HTTP/1.1",
            method: Method::GET,
            host: Some(HeaderValue::from_static("example.com")),
            uri: Uri::from_static("/en/?q=%22x%22"),
            started: Instant::now(),
        };
        let log = AccessLog {
            output: Output::Discard,
            format: Format::Json,
        };
        let line = log.line(&info, 200, 1234);
        assert!(line.ends_with('\n'));
        let parsed: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(parsed["logger"], "http.log.access");
        assert_eq!(parsed["request"]["host"], "example.com");
        assert_eq!(parsed["request"]["uri"], "/en/?q=%22x%22");
        assert_eq!(parsed["request"]["client_ip"], "203.0.113.9");
        assert_eq!(parsed["request"]["remote_port"], "4000");
        assert_eq!(parsed["status"], 200);
        assert_eq!(parsed["size"], 1234);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
        let ts = parsed["ts"].as_f64().unwrap();
        assert!(ts <= now && ts > now - 5.0, "{ts} against {now}");
        let duration = parsed["duration"].as_f64().unwrap();
        assert!((0.0..1.0).contains(&duration), "{duration}");
        let console = AccessLog {
            output: Output::Discard,
            format: Format::Console,
        };
        let line = console.line(&info, 200, 1234);
        let rest = line
            .strip_prefix("203.0.113.9 HTTP/1.1 GET example.com /en/?q=%22x%22 200 1234 ")
            .unwrap();
        let ms = rest.strip_suffix("ms\n").unwrap();
        assert_eq!(
            ms.split('.').nth(1).map(str::len),
            Some(3),
            "{ms:?}: milliseconds to three places"
        );
        assert!(ms.parse::<f64>().unwrap() < 1000.0, "{ms}");
    }

    #[test]
    fn seconds_are_written_as_a_float_would_be() {
        let written = |secs, nanos, digits| {
            let mut out = String::new();
            write_seconds(&mut out, secs, nanos, digits);
            out
        };
        assert_eq!(written(1760788800, 123_000_000, 6), "1760788800.123");
        assert_eq!(written(1760788800, 123_456_789, 6), "1760788800.123456");
        assert_eq!(written(0, 0, 6), "0.0");
        assert_eq!(written(0, 123_456_789, 9), "0.123456789");
        assert_eq!(written(0, 123_000, 9), "0.000123");
        assert_eq!(written(7, 999_999_999, 3), "7.999");
        assert_eq!(written(3, 500_000_000, 1), "3.5");
        // The same number a float gives.
        let d = Duration::new(12, 345_678_000);
        assert_eq!(written(12, 345_678_000, 9).parse::<f64>().unwrap(), d.as_secs_f64());
    }
}
