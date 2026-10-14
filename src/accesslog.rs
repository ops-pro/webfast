//! Access logs (`log` in a site block): one line per request when its response body is finished,
//! JSON in Caddy's shape (`logger: http.log.access`, `msg: handled request`) or a console line.
//! Request headers are not logged (they carry cookies and other personal data).
//!
//! Lines are written in batches: the request formats its line (no JSON library, one string) and
//! hands it to the output's writer thread, which wakes every `WEB_LOG_FLUSH_MS` (10 ms), takes
//! what has queued up and writes it with one call. A request never waits for the terminal or the log collector; if the
//! queue is full (the output is stuck), lines are dropped and counted rather than slowing requests.

use crate::body::{Body, BoxError};
use bytes::Bytes;
use http::{HeaderValue, Method, Uri};
use http_body::{Frame, SizeHint};
use std::fmt::Write as _;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    Stdout,
    Stderr,
    Discard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Console,
}

#[derive(Debug)]
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

struct Writer {
    queue: SyncSender<Message>,
    dropped: AtomicU64,
}

static STDOUT: OnceLock<Writer> = OnceLock::new();
static STDERR: OnceLock<Writer> = OnceLock::new();
/// Writer threads started so far (flushed on shutdown).
static STARTED: Mutex<Vec<Output>> = Mutex::new(Vec::new());

fn writer(output: Output) -> Option<&'static Writer> {
    let cell = match output {
        Output::Stdout => &STDOUT,
        Output::Stderr => &STDERR,
        Output::Discard => return None,
    };
    Some(cell.get_or_init(|| {
        let (queue, receiver) = sync_channel(QUEUE_LINES);
        std::thread::Builder::new()
            .name(format!("access-log-{output:?}").to_lowercase())
            .spawn(move || write_batches(output, receiver))
            .expect("access log thread");
        if let Ok(mut started) = STARTED.lock() {
            started.push(output);
        }
        Writer {
            queue,
            dropped: AtomicU64::new(0),
        }
    }))
}

fn write_batches(output: Output, receiver: Receiver<Message>) {
    let mut batch: Vec<u8> = Vec::with_capacity(64 * 1024);
    let interval = batch_interval();
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
            let _ = match output {
                Output::Stdout => std::io::stdout().lock().write_all(&batch),
                Output::Stderr => std::io::stderr().lock().write_all(&batch),
                Output::Discard => Ok(()),
            };
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
        let Some(writer) = writer(self.output) else { return };
        let line = self.line(info, status, size);
        if let Err(TrySendError::Full(_)) = writer.queue.try_send(Message::Line(line)) {
            writer.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The log line, newline included.
    fn line(&self, info: &RequestInfo, status: u16, size: u64) -> String {
        let duration = info.started.elapsed().as_secs_f64();
        let host = info.host.as_ref().and_then(|h| h.to_str().ok()).unwrap_or("");
        let uri = info.uri.path_and_query().map_or("/", |pq| pq.as_str());
        let mut line = String::with_capacity(320);
        match self.format {
            Format::Json => {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0);
                let _ = write!(
                    line,
                    r#"{{"level":"info","ts":{ts},"logger":"http.log.access","msg":"handled request","request":{{"remote_ip":"{}","remote_port":"{}","client_ip":"{}","proto":"{}","method":""#,
                    info.remote.ip(),
                    info.remote.port(),
                    info.client_ip,
                    info.proto,
                );
                json_escape(&mut line, info.method.as_str());
                line.push_str(r#"","host":""#);
                json_escape(&mut line, host);
                line.push_str(r#"","uri":""#);
                json_escape(&mut line, uri);
                let _ = writeln!(line, r#""}},"duration":{duration},"size":{size},"status":{status}}}"#);
            }
            Format::Console => {
                let _ = writeln!(
                    line,
                    "{} {} {} {host} {uri} {status} {size} {:.3}ms",
                    info.client_ip,
                    info.proto,
                    info.method,
                    duration * 1000.0
                );
            }
        }
        line
    }
}

/// JSON string contents: quotes, backslashes and control characters escaped.
fn json_escape(out: &mut String, text: &str) {
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

/// Counts the bytes of a response body and writes the log line when the body ends or is dropped.
pub struct LoggedBody {
    inner: Body,
    log: Arc<AccessLog>,
    info: Option<RequestInfo>,
    status: u16,
    size: u64,
}

impl LoggedBody {
    pub fn new(inner: Body, log: Arc<AccessLog>, info: RequestInfo, status: u16) -> LoggedBody {
        LoggedBody {
            inner,
            log,
            info: Some(info),
            status,
            size: 0,
        }
    }

    fn finish(&mut self) {
        if let Some(info) = self.info.take() {
            self.log.write(&info, self.status, self.size);
        }
    }
}

impl http_body::Body for LoggedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let polled = ready!(Pin::new(&mut self.inner).poll_frame(cx));
        match &polled {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    self.size += data.len() as u64;
                }
            }
            Some(Err(_)) | None => self.finish(),
        }
        Poll::Ready(polled)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for LoggedBody {
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
        let console = AccessLog {
            output: Output::Discard,
            format: Format::Console,
        };
        assert!(
            console
                .line(&info, 200, 1234)
                .starts_with("203.0.113.9 HTTP/1.1 GET example.com /en/")
        );
    }
}
