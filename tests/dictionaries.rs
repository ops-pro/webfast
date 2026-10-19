//! Compression dictionaries (RFC 9842, `dcz`): a client that holds an earlier version of a file as
//! a dictionary gets the new one as a delta to it — from the files on disk, or from a version a
//! rescan replaced — and nothing changes for clients without one.

use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::path::Path;
use std::time::{Duration, Instant};
use webfast::server;

/// A script of `lines` lines, `version` changing a few of them.
fn script(lines: usize, version: u32) -> Vec<u8> {
    let mut out = String::new();
    for i in 0..lines {
        let changed = if i % 97 == 0 { version } else { 0 };
        out.push_str(&format!(
            "export function handler{i}(event) {{ return render(event.target, {i}, {changed}); }}\n"
        ));
    }
    out.into_bytes()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data)
        .as_ref()
        .try_into()
        .unwrap()
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Decodes a `dcz` body with `dictionary`.
fn undo_dcz(body: &[u8], dictionary: &[u8]) -> Vec<u8> {
    assert_eq!(
        &body[..8],
        &[0x5e, 0x2a, 0x4d, 0x18, 0x20, 0, 0, 0],
        "the skippable frame"
    );
    assert_eq!(&body[8..40], &sha256(dictionary), "the dictionary's hash");
    let mut dctx = zstd::zstd_safe::DCtx::create();
    dctx.ref_prefix(dictionary).unwrap();
    let mut out = Vec::with_capacity(1 << 22);
    dctx.decompress(&mut out, &body[40..]).unwrap();
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

fn caddyfile(root: &Path) -> String {
    format!(
        ":0 {{
	root * {}
	header /assets/* Use-As-Dictionary \"match=\\\"/assets/app-*.js\\\"\"
	file_server
}}
",
        root.display()
    )
}

const BROWSER: &str = "gzip, deflate, br, zstd, dcb, dcz";

#[tokio::test]
async fn a_new_version_goes_as_a_delta_to_the_old_one() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("assets")).unwrap();
    let (v1, v2) = (script(3000, 1), script(3000, 2));
    std::fs::write(dir.path().join("assets/app-v1.js"), &v1).unwrap();
    std::fs::write(dir.path().join("assets/app-v2.js"), &v2).unwrap();
    let file = webfast::caddyfile::parse_str(&caddyfile(dir.path()), Path::new("Caddyfile")).unwrap();
    let running = server::start(webfast::load_parsed(&file, 1 << 26).unwrap())
        .await
        .unwrap();
    let port = running.bound[0].1.port();
    let offer = format!(":{}:", base64(&sha256(&v1)));

    // The dictionary itself, as a browser first gets it.
    let first = get(port, "/assets/app-v1.js", &[("accept-encoding", "gzip, br, zstd")]).await;
    assert_eq!(first.header("use-as-dictionary"), "match=\"/assets/app-*.js\"");

    let with_dictionary = [
        ("accept-encoding", BROWSER),
        ("available-dictionary", offer.as_str()),
        ("sec-fetch-site", "same-origin"),
        ("sec-fetch-mode", "cors"),
    ];
    let delta = get(port, "/assets/app-v2.js", &with_dictionary).await;
    assert_eq!(delta.status, StatusCode::OK);
    assert_eq!(delta.header("content-encoding"), "dcz");
    assert_eq!(delta.header("vary"), "Accept-Encoding, Available-Dictionary");
    assert_eq!(delta.header("content-type"), "text/javascript; charset=utf-8");
    assert_eq!(undo_dcz(&delta.body, &v1), v2);
    let plain_zstd = zstd::bulk::compress(&v2, 19).unwrap();
    assert!(
        delta.body.len() * 10 < plain_zstd.len(),
        "a delta of {} bytes against {} for zstd alone",
        delta.body.len(),
        plain_zstd.len()
    );

    // Kept: the same bytes again; its own ETag, which revalidates.
    let again = get(port, "/assets/app-v2.js", &with_dictionary).await;
    assert_eq!(again.body, delta.body);
    let etag = delta.header("etag").to_string();
    // Ours (8), `d`, and 8 of the dictionary's hash.
    assert!(etag.len() == 19 && etag.as_bytes()[9] == b'd', "{etag}");
    let mut revalidate = with_dictionary.to_vec();
    revalidate.push(("if-none-match", &etag));
    assert_eq!(
        get(port, "/assets/app-v2.js", &revalidate).await.status,
        StatusCode::NOT_MODIFIED
    );

    // No delta: without dcz, for a hash the server does not know, cross-site, for a range.
    for headers in [
        vec![
            ("accept-encoding", "gzip, br, zstd"),
            ("available-dictionary", offer.as_str()),
        ],
        vec![
            ("accept-encoding", BROWSER),
            ("available-dictionary", ":AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:"),
        ],
        vec![
            ("accept-encoding", BROWSER),
            ("available-dictionary", offer.as_str()),
            ("sec-fetch-site", "cross-site"),
            ("sec-fetch-mode", "cors"),
        ],
        vec![
            ("accept-encoding", BROWSER),
            ("available-dictionary", offer.as_str()),
            ("range", "bytes=0-9"),
        ],
    ] {
        let got = get(port, "/assets/app-v2.js", &headers).await;
        assert_ne!(got.header("content-encoding"), "dcz", "{headers:?}");
    }
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn a_version_replaced_on_disk_still_serves_as_a_dictionary() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("assets")).unwrap();
    let (v1, v2) = (script(2000, 1), script(2000, 2));
    // The same path, rewritten by a deploy: the old version is gone from disk.
    std::fs::write(dir.path().join("assets/app-main.js"), &v1).unwrap();
    let file = webfast::caddyfile::parse_str(&caddyfile(dir.path()), Path::new("Caddyfile")).unwrap();
    let watch = webfast::watch::Watch {
        mode: webfast::watch::Mode::Poll,
        poll: Duration::from_millis(200),
    };
    let config = webfast::load_parsed_reusing(&file, 1 << 26, None, None, watch, &[]).unwrap();
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();
    std::fs::write(dir.path().join("assets/app-main.js"), &v2).unwrap();
    let started = Instant::now();
    while get(port, "/assets/app-main.js", &[]).await.body != v2 {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the new version was picked up"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let offer = format!(":{}:", base64(&sha256(&v1)));
    let delta = get(
        port,
        "/assets/app-main.js",
        &[("accept-encoding", BROWSER), ("available-dictionary", offer.as_str())],
    )
    .await;
    assert_eq!(delta.header("content-encoding"), "dcz");
    assert_eq!(undo_dcz(&delta.body, &v1), v2);
    running.shutdown(Duration::from_secs(1)).await;
}
