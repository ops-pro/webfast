//! Compressed variants (feature `compress-files`): a compressible file without a precompressed
//! sibling is answered as before the first time, then from a variant made in the background — with
//! an ETag of its own, conditional requests and ranges as for a sibling. Nothing is made at
//! startup, only what is asked for.
#![cfg(feature = "compress-files")]

use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};
use webfast::server;

/// A script of `lines` lines; `seed` makes its content its own.
fn script(lines: usize, seed: &str) -> Vec<u8> {
    let mut out = String::new();
    for i in 0..lines {
        out.push_str(&format!(
            "export function {seed}{i}(event) {{ return render(event.target, {i}, \"{seed}\"); }}\n"
        ));
    }
    out.into_bytes()
}

fn unbrotli(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    brotli::Decompressor::new(data, 4096).read_to_end(&mut out).unwrap();
    out
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

async fn get(port: u16, path: &str, headers: &[(&str, &str)]) -> Got {
    let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let mut request = Request::get(format!("http://127.0.0.1:{port}{path}"));
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

async fn start(root: &Path, encode: bool) -> (server::Running, u16) {
    let text = format!(
        ":0 {{\n\troot * {}\n\t{}\n\tfile_server {{\n\t\tprecompressed br zstd gzip\n\t}}\n}}\n",
        root.display(),
        if encode { "encode zstd br gzip" } else { "" }
    );
    let file = webfast::caddyfile::parse_str(&text, Path::new("Caddyfile")).unwrap();
    let running = server::start(webfast::load_parsed(&file, 1 << 26).unwrap())
        .await
        .unwrap();
    let port = running.bound[0].1.port();
    (running, port)
}

/// GETs `path` with `headers` until `done` holds, for up to 30 s (the variant is made in the
/// background, at Brotli's highest level).
async fn until(port: u16, path: &str, headers: &[(&str, &str)], done: impl Fn(&Got) -> bool) -> Got {
    let started = Instant::now();
    loop {
        let got = get(port, path, headers).await;
        if done(&got) {
            return got;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "{path}: still {:?}",
            got.headers
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn files_without_a_sibling_get_a_variant_once_asked_for() {
    let dir = tempfile::tempdir().unwrap();
    let app = script(400, "app");
    let page = script(400, "page");
    std::fs::write(dir.path().join("app.js"), &app).unwrap();
    std::fs::write(dir.path().join("page.js"), &page).unwrap();
    std::fs::write(dir.path().join("photo.png"), vec![7u8; 4096]).unwrap();
    let (running, port) = start(dir.path(), true).await;
    assert_eq!(webfast::variants::stored(), (0, 0), "nothing made at startup");
    let br = [("accept-encoding", "br")];

    // The first answer: `encode` on the fly (its ETag is the file's with the letter b).
    let first = get(port, "/app.js", &br).await;
    assert_eq!(first.header("content-encoding"), "br");
    let first_etag = first.header("etag");
    assert!(
        first_etag.len() == 11 && first_etag.ends_with("b\""),
        "ours plus the letter: {first_etag}"
    );
    assert_eq!(unbrotli(&first.body), app);

    // Then the variant: its own ETag, made at the highest level.
    let variant = until(port, "/app.js", &br, |got| got.header("etag").len() == 10).await;
    assert_eq!(variant.status, StatusCode::OK);
    assert_eq!(variant.header("content-encoding"), "br");
    assert_eq!(variant.header("vary"), "Accept-Encoding");
    assert_eq!(unbrotli(&variant.body), app);
    assert!(
        variant.body.len() * 10 <= app.len() * 9,
        "kept only when it saves a tenth"
    );
    let etag = variant.header("etag").to_string();
    let again = get(port, "/app.js", &[("accept-encoding", "br"), ("if-none-match", &etag)]).await;
    assert_eq!(again.status, StatusCode::NOT_MODIFIED);
    let range = get(port, "/app.js", &[("accept-encoding", "br"), ("range", "bytes=0-9")]).await;
    assert_eq!(range.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        &range.body[..],
        &variant.body[..10],
        "a range of the variant, as of a sibling"
    );
    // Once the ready answers are worked out again, the same answer comes from them.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let ready = get(port, "/app.js", &br).await;
    assert_eq!((ready.header("etag"), &ready.body), (etag.as_str(), &variant.body));

    // Not compressible: nothing asked for.
    let photo = get(port, "/photo.png", &br).await;
    assert_eq!(photo.header("content-encoding"), "");

    // Without `encode`: the file as it is, then the variant.
    let plain_dir = tempfile::tempdir().unwrap();
    std::fs::write(plain_dir.path().join("page.js"), &page).unwrap();
    let (plain, plain_port) = start(plain_dir.path(), false).await;
    let first = get(plain_port, "/page.js", &br).await;
    assert_eq!((first.header("content-encoding"), &first.body[..]), ("", &page[..]));
    let variant = until(plain_port, "/page.js", &br, |got| {
        got.header("content-encoding") == "br"
    })
    .await;
    assert_eq!(unbrotli(&variant.body), page);
    let (variants, bytes) = webfast::variants::stored();
    assert!(variants >= 2 && bytes > 0, "{variants} variants, {bytes} bytes");

    running.shutdown(Duration::from_secs(1)).await;
    plain.shutdown(Duration::from_secs(1)).await;
}
