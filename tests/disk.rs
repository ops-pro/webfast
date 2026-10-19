//! Files larger than WEB_MAX_FILE_IN_MEMORY, served from disk: whole, by range, conditionally,
//! as their precompressed siblings; changed or gone on disk without a rescan, still answered
//! right; never in memory nor in the ready answers.

use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::path::Path;
use std::time::Duration;
use webfast::server;

/// Over this, a file is served from disk in these tests.
const MAX_IN_MEMORY: u64 = 1 << 20;

/// Bytes that do not repeat in a way that hides a misplaced range.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut w = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    w.write_all(data).unwrap();
    w.finish().unwrap()
}

fn load(root: &Path) -> webfast::config::Config {
    let text = format!(
        ":0 {{\n\troot * {}\n\tfile_server {{\n\t\tprecompressed gzip\n\t}}\n}}\n",
        root.display()
    );
    let file = webfast::caddyfile::parse_str(&text, Path::new("Caddyfile")).unwrap();
    let watch = webfast::watch::Watch::default();
    webfast::load_parsed_reusing(&file, 1 << 26, None, Some(MAX_IN_MEMORY), watch, &[]).unwrap()
}

struct Got {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Got {
    fn header(&self, name: &str) -> &str {
        self.headers.get(name).map_or("", |v| v.to_str().unwrap())
    }
}

async fn send(port: u16, method: Method, path: &str, headers: &[(&str, &str)]) -> Got {
    let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let mut request = Request::builder()
        .method(method)
        .uri(format!("http://127.0.0.1:{port}{path}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = client
        .request(request.body(Full::new(Bytes::new())).unwrap())
        .await
        .unwrap();
    let (status, headers) = (response.status(), response.headers().clone());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Got { status, headers, body }
}

#[tokio::test]
async fn large_files_are_served_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let big = noise(3 << 20, 7);
    std::fs::write(dir.path().join("big.bin"), &big).unwrap();
    // Text over the limit, with a precompressed sibling far under it.
    let text = "a line of text that repeats\n".repeat(80_000).into_bytes();
    let text_gz = gzip(&text);
    std::fs::write(dir.path().join("big.txt"), &text).unwrap();
    std::fs::write(dir.path().join("big.txt.gz"), &text_gz).unwrap();
    std::fs::write(dir.path().join("small.txt"), b"in memory").unwrap();

    let config = load(dir.path());
    assert_eq!(config.files.disk, 2, "big.bin and big.txt (its .gz is small)");
    assert!(config.files.stored < MAX_IN_MEMORY, "{:?}", config.files);
    let routes = config.servers[0].sites[0].routes.clone();
    let answers = webfast::memo::Answers::prepare(&routes, false).unwrap();
    assert_eq!(answers.paths(), 1, "only small.txt has a ready answer");
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();

    // Whole, and HEAD.
    let got = send(port, Method::GET, "/big.bin", &[]).await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.body.len(), big.len());
    assert!(got.body == big, "the bytes as they are on disk");
    assert_eq!(got.header("content-length"), big.len().to_string());
    assert_eq!(got.header("accept-ranges"), "bytes");
    let etag = got.header("etag").to_string();
    assert_eq!(etag.len(), 10, "8 characters of base64url in quotes: {etag}");
    let head = send(port, Method::HEAD, "/big.bin", &[]).await;
    assert_eq!(head.header("content-length"), big.len().to_string());
    assert!(head.body.is_empty());

    // Ranges: one is served, several get the whole file.
    let part = send(port, Method::GET, "/big.bin", &[("range", "bytes=1000-1999")]).await;
    assert_eq!(part.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(part.header("content-range"), format!("bytes 1000-1999/{}", big.len()));
    assert_eq!(&part.body[..], &big[1000..2000]);
    let tail = send(port, Method::GET, "/big.bin", &[("range", "bytes=-10")]).await;
    assert_eq!(&tail.body[..], &big[big.len() - 10..]);
    let several = send(port, Method::GET, "/big.bin", &[("range", "bytes=0-1,5-6")]).await;
    assert_eq!((several.status, several.body.len()), (StatusCode::OK, big.len()));
    let beyond = send(port, Method::GET, "/big.bin", &[("range", "bytes=99999999-")]).await;
    assert_eq!(beyond.status, StatusCode::RANGE_NOT_SATISFIABLE);

    // Conditional requests with its ETag.
    let fresh = send(port, Method::GET, "/big.bin", &[("if-none-match", &etag)]).await;
    assert_eq!((fresh.status, fresh.body.len()), (StatusCode::NOT_MODIFIED, 0));
    let resumed = send(
        port,
        Method::GET,
        "/big.bin",
        &[("if-range", &etag), ("range", "bytes=10-19")],
    )
    .await;
    assert_eq!(resumed.status, StatusCode::PARTIAL_CONTENT);
    let stale = send(
        port,
        Method::GET,
        "/big.bin",
        &[("if-range", "\"other\""), ("range", "bytes=10-19")],
    )
    .await;
    assert_eq!((stale.status, stale.body.len()), (StatusCode::OK, big.len()));
    let posted = send(port, Method::POST, "/big.bin", &[]).await;
    assert_eq!(
        (posted.status, posted.header("allow")),
        (StatusCode::METHOD_NOT_ALLOWED, "GET, HEAD")
    );

    // The precompressed sibling (small: from memory) for the file on disk.
    let compressed = send(port, Method::GET, "/big.txt", &[("accept-encoding", "gzip")]).await;
    assert_eq!(compressed.header("content-encoding"), "gzip");
    assert!(compressed.body == text_gz);
    let plain = send(port, Method::GET, "/big.txt", &[]).await;
    assert!(plain.body == text);
    assert_eq!(plain.header("content-type"), "text/plain; charset=utf-8");

    // Changed on disk, with nothing watching: answered as it is now.
    let other = noise(2 << 20, 9);
    std::fs::write(dir.path().join("big.bin"), &other).unwrap();
    let changed = send(port, Method::GET, "/big.bin", &[]).await;
    assert!(changed.body == other);
    assert_eq!(changed.header("content-length"), other.len().to_string());
    assert_ne!(changed.header("etag"), etag);
    std::fs::remove_file(dir.path().join("big.bin")).unwrap();
    assert_eq!(
        send(port, Method::GET, "/big.bin", &[]).await.status,
        StatusCode::NOT_FOUND
    );

    let small = send(port, Method::GET, "/small.txt", &[]).await;
    assert_eq!(&small.body[..], b"in memory");
    running.shutdown(Duration::from_secs(1)).await;
}
