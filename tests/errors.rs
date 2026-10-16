//! `handle_errors` and `error`, answered as Caddy 2.11 answers the same Caddyfile (compat/ checks it
//! against Caddy itself), and the few places where webfast differs on purpose.

use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use webfast::server::{self, Running};

const NOT_FOUND_PAGE: &str = "<h1>not here</h1>\n";

fn site() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("404.html"), NOT_FOUND_PAGE).unwrap();
    std::fs::write(dir.path().join("index.html"), "hello\n").unwrap();
    dir
}

/// An address nothing listens on.
fn dead_upstream() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

async fn start(text: &str) -> Running {
    let file = webfast::caddyfile::parse_str(text, Path::new("Caddyfile")).unwrap();
    let config = webfast::load_parsed(&file, 1 << 24).unwrap();
    server::start(config).await.unwrap()
}

struct Got {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Got {
    fn header(&self, name: &str) -> &str {
        self.headers.get(name).map(|v| v.to_str().unwrap()).unwrap_or("")
    }
}

async fn send(running: &Running, method: Method, path: &str, headers: &[(&str, &str)]) -> Got {
    let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let port = running.bound[0].1.port();
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
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Got {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn caddyfile(root: &Path, down: SocketAddr) -> String {
    format!(
        ":0 {{
	root * {root}
	header X-Plain 1
	header {{
		X-Deferred 1
		defer
	}}
	rewrite /rw /elsewhere
	@private path /private/*
	error @private \"Private area\" 403
	error /teapot 418
	error /boom \"boom\"
	reverse_proxy /down/* {down}
	file_server
	handle_errors 404 {{
		header X-In-404 1
		rewrite * /404.html
		file_server
	}}
	handle_errors 403 {{
		header @private X-Only-Header 1
	}}
	handle_errors 418 {{
		respond \"teapot {{err.status_code}} [{{err.message}}] {{uri}}\" 299
	}}
	handle_errors 5xx {{
		respond \"{{err.status_code}} {{err.status_text}} [{{err.message}}] {{uri}} {{method}}\"
	}}
	handle_errors {{
		respond \"catch-all {{http.error.status_code}} [{{err.message}}] {{uri}}\"
	}}
}}
",
        root = root.display()
    )
}

#[tokio::test]
async fn error_routes_answer_as_caddy_does() {
    let site = site();
    let running = start(&caddyfile(site.path(), dead_upstream())).await;

    // file_server's 404: the page, with the failure's status, whatever the method; the URI as the
    // client sent it, before the rewrite.
    for (method, path) in [(Method::GET, "/nope"), (Method::POST, "/nope"), (Method::GET, "/rw")] {
        let got = send(&running, method.clone(), path, &[]).await;
        assert_eq!(got.status, StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(got.body, NOT_FOUND_PAGE, "{method} {path}");
        assert_eq!(got.header("content-type"), "text/html; charset=utf-8");
        assert_eq!(got.header("x-in-404"), "1", "the error block's own header");
        assert_eq!(got.header("x-plain"), "1", "set before the failure, kept");
        assert_eq!(got.header("x-deferred"), "1", "kept too (Caddy drops deferred ones)");
        assert_eq!(got.header("vary"), "Accept-Encoding");
        assert!(!got.header("etag").is_empty());
    }
    let head = send(&running, Method::HEAD, "/nope", &[]).await;
    assert_eq!(head.status, StatusCode::NOT_FOUND);
    assert_eq!(head.header("content-length"), NOT_FOUND_PAGE.len().to_string());
    assert!(head.body.is_empty());

    // `error` with a message; a block that only sets a header lets the next matching one answer.
    let private = send(&running, Method::GET, "/private/x", &[]).await;
    assert_eq!(private.status, StatusCode::FORBIDDEN);
    assert_eq!(private.body, "catch-all 403 [Private area] /private/x");
    assert_eq!(private.header("x-only-header"), "1");
    assert_eq!(private.header("content-type"), "text/plain; charset=utf-8");

    // A status without a message: `{err.message}` is empty; `respond`'s own status wins.
    let teapot = send(&running, Method::GET, "/teapot", &[]).await;
    assert_eq!(teapot.status.as_u16(), 299);
    assert_eq!(teapot.body, "teapot 418 [] /teapot");

    // A message without a status: 500.
    let boom = send(&running, Method::GET, "/boom", &[]).await;
    assert_eq!(boom.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(boom.body, "500 Internal Server Error [boom] /boom GET");

    // The proxy's failures; their message is the status text (Caddy's names the network error).
    let down = send(&running, Method::GET, "/down/x?q=1", &[]).await;
    assert_eq!(down.status, StatusCode::BAD_GATEWAY);
    assert_eq!(down.body, "502 Bad Gateway [Bad Gateway] /down/x?q=1 GET");
    let posted = send(&running, Method::POST, "/down/y", &[]).await;
    assert_eq!(posted.body, "502 Bad Gateway [Bad Gateway] /down/y POST");

    // file_server's 405 keeps its Allow.
    let not_allowed = send(&running, Method::POST, "/index.html", &[]).await;
    assert_eq!(not_allowed.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(not_allowed.header("allow"), "GET, HEAD");
    assert_eq!(not_allowed.body, "catch-all 405 [Method Not Allowed] /index.html");

    // An error page is sent whole: no 304 for its ETag, no ranges (Caddy answers an empty 404 and
    // a cut page).
    let etag = send(&running, Method::GET, "/404.html", &[])
        .await
        .header("etag")
        .to_string();
    for header in [("if-none-match", etag.as_str()), ("range", "bytes=0-3")] {
        let got = send(&running, Method::GET, "/nope", &[header]).await;
        assert_eq!((got.status, got.body.as_str()), (StatusCode::NOT_FOUND, NOT_FOUND_PAGE));
        assert!(got.headers.get("content-range").is_none());
    }

    // What is not a failure is not handled: a file, and `respond` with an error status.
    let index = send(&running, Method::GET, "/", &[]).await;
    assert_eq!((index.status, index.body.as_str()), (StatusCode::OK, "hello\n"));
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn without_a_block_for_the_status_or_when_the_error_routes_fail_the_bare_status_stays() {
    let site = site();
    let root = site.path().display();
    let down = dead_upstream();
    let running = start(&format!(
        ":0 {{
	root * {root}
	respond /teapot 418
	reverse_proxy /down/* {down}
	error /gone 410
	file_server
	handle_errors 404 {{
		respond \"only 404\"
	}}
	handle_errors 410 {{
		rewrite * /missing-too.html
		file_server
	}}
}}
"
    ))
    .await;
    let down = send(&running, Method::GET, "/down/x", &[]).await;
    assert_eq!((down.status, down.body.as_str()), (StatusCode::BAD_GATEWAY, ""));
    let gone = send(&running, Method::GET, "/gone", &[]).await;
    assert_eq!((gone.status, gone.body.as_str()), (StatusCode::GONE, ""));
    let missing = send(&running, Method::GET, "/missing", &[]).await;
    assert_eq!(
        (missing.status, missing.body.as_str()),
        (StatusCode::NOT_FOUND, "only 404")
    );
    // `respond` with an error status is an answer, not a failure.
    let teapot = send(&running, Method::GET, "/teapot", &[]).await;
    assert_eq!((teapot.status.as_u16(), teapot.body.as_str()), (418, ""));
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn error_pages_can_be_compressed_and_failures_without_handle_errors_are_bare() {
    let site = site();
    std::fs::write(site.path().join("404.html"), "<p>gone</p>".repeat(200)).unwrap();
    let root = site.path().display();
    let running = start(&format!(
        ":0 {{
	root * {root}
	encode gzip
	file_server
	handle_errors {{
		encode gzip
		rewrite * /404.html
		file_server
	}}
}}
"
    ))
    .await;
    let got = send(&running, Method::GET, "/nope", &[("accept-encoding", "gzip")]).await;
    assert_eq!(got.status, StatusCode::NOT_FOUND);
    assert_eq!(got.header("content-encoding"), "gzip");
    running.shutdown(Duration::from_secs(1)).await;

    let running = start(&format!(":0 {{\n\troot * {root}\n\tfile_server\n}}\n")).await;
    let got = send(&running, Method::GET, "/nope", &[]).await;
    assert_eq!((got.status, got.body.as_str()), (StatusCode::NOT_FOUND, ""));
    running.shutdown(Duration::from_secs(1)).await;
}
