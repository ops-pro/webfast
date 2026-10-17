//! `rate_limit` (feature `rate-limit`): zones by key, the first zone exceeded refuses with 429 and
//! `Retry-After`, `handle_errors` answers it, ready answers stay for paths outside the zones, the
//! state outlives a reload.
#![cfg(feature = "rate-limit")]

use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::path::Path;
use std::time::Duration;
use webfast::server::{self, Running};

fn load(text: &str, running: Option<&Running>) -> anyhow::Result<webfast::config::Config> {
    let file = webfast::caddyfile::parse_str(text, Path::new("Caddyfile"))?;
    let stores = running.map(Running::stores).unwrap_or_default();
    webfast::load_parsed_reusing(&file, 1 << 24, None, None, webfast::watch::Watch::default(), &stores)
}

struct Got {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
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

fn caddyfile(root: &Path) -> String {
    format!(
        "{{
	servers {{
		trusted_proxies static 127.0.0.1/8
	}}
}}
:0 {{
	root * {root}
	rate_limit {{
		zone api {{
			match {{
				path /api/*
			}}
			key {{client_ip}}
			events 100
			window 1m
		}}
		zone login {{
			match {{
				method POST
				path /api/login
			}}
			key {{client_ip}}
			events 2
			window 1m
		}}
		zone files {{
			match {{
				path /downloads/*
			}}
			key static
			events 3
			window 1m
		}}
	}}
	respond /api/* \"api\"
	file_server
	handle_errors 429 {{
		respond \"slow down ({{http.rate_limit.exceeded.name}}, {{err.status_code}})\"
	}}
}}
",
        root = root.display()
    )
}

fn site() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), "home").unwrap();
    std::fs::create_dir(dir.path().join("downloads")).unwrap();
    std::fs::write(dir.path().join("downloads/file.txt"), "a file").unwrap();
    dir
}

#[tokio::test]
async fn the_first_zone_exceeded_refuses_with_429() {
    let dir = site();
    let mut running = server::start(load(&caddyfile(dir.path()), None).unwrap())
        .await
        .unwrap();
    let port = running.bound[0].1.port();
    let client = |ip: &'static str| [("x-forwarded-for", ip)];

    // Two logins pass, the third is refused by the tighter zone, with its name.
    for _ in 0..2 {
        let got = send(port, Method::POST, "/api/login", &client("203.0.113.1")).await;
        assert_eq!(got.status, StatusCode::OK);
    }
    let refused = send(port, Method::POST, "/api/login", &client("203.0.113.1")).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(&refused.body[..], b"slow down (login, 429)");
    let wait: u64 = refused.headers["retry-after"].to_str().unwrap().parse().unwrap();
    assert!((1..=30).contains(&wait), "one login per 30 s: {wait}");
    // Another client has its own budget; the same client's other API calls go on.
    let other = send(port, Method::POST, "/api/login", &client("203.0.113.2")).await;
    assert_eq!(other.status, StatusCode::OK);
    let api = send(port, Method::GET, "/api/items", &client("203.0.113.1")).await;
    assert_eq!(api.status, StatusCode::OK);

    // A static key: one budget for everyone, and those paths get no ready answer.
    let routes = running_routes(&caddyfile(dir.path()));
    let answers = webfast::memo::Answers::prepare(&routes, false).expect("the zones decide by the path");
    assert_eq!(answers.paths(), 2, "/ and /index.html: /downloads/ is in a zone");
    for ip in ["198.51.100.1", "198.51.100.2", "198.51.100.3"] {
        assert_eq!(
            send(port, Method::GET, "/downloads/file.txt", &client(ip)).await.status,
            StatusCode::OK
        );
    }
    let fourth = send(port, Method::GET, "/downloads/file.txt", &client("198.51.100.4")).await;
    assert_eq!(fourth.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        send(port, Method::GET, "/", &client("198.51.100.4")).await.status,
        StatusCode::OK
    );

    // A reload with the same zones keeps their counts.
    running
        .reload(load(&caddyfile(dir.path()), Some(&running)).unwrap())
        .await
        .unwrap();
    let still = send(port, Method::POST, "/api/login", &client("203.0.113.1")).await;
    assert_eq!(still.status, StatusCode::TOO_MANY_REQUESTS);
    running.shutdown(Duration::from_secs(1)).await;
}

fn running_routes(text: &str) -> std::sync::Arc<[webfast::handler::Route]> {
    load(text, None).unwrap().servers.remove(0).sites.remove(0).routes
}

#[tokio::test]
async fn zones_that_look_beyond_the_path_cost_the_site_its_ready_answers() {
    let dir = site();
    let root = dir.path().display();
    let by_header = format!(
        ":0 {{\n\troot * {root}\n\trate_limit {{\n\t\tzone bots {{\n\t\t\tmatch {{\n\t\t\t\theader User-Agent *bot*\n\t\t\t}}\n\t\t\tkey static\n\t\t\tevents 1\n\t\t\twindow 1m\n\t\t}}\n\t}}\n\tfile_server\n}}\n"
    );
    assert!(webfast::memo::Answers::prepare(&running_routes(&by_header), false).is_none());
    // A zone for POST only takes no GET: the ready answers stay (/, /index.html, the download).
    let posts = by_header.replace("header User-Agent *bot*", "method POST");
    assert_eq!(
        webfast::memo::Answers::prepare(&running_routes(&posts), false)
            .unwrap()
            .paths(),
        3
    );
}

#[test]
fn what_the_plugin_does_not_have_is_refused() {
    for (block, message) in [
        (
            "zone a {\n\t\t\tkey static\n\t\t\tevents 1\n\t\t\twindow 1m\n\t\t}\n\t\tdistributed",
            "not supported",
        ),
        (
            "zone a {\n\t\t\tkey static\n\t\t\tevents 1\n\t\t}",
            "requires both a window and maximum events",
        ),
        (
            "zone a {\n\t\t\tkey static\n\t\t\tevents 1\n\t\t\twindow 1m\n\t\t\tburst 5\n\t\t}",
            "unsupported zone option",
        ),
    ] {
        let text = format!(":0 {{\n\trate_limit {{\n\t\t{block}\n\t}}\n\trespond ok\n}}\n");
        let error = load(&text, None).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(error.contains(message), "{block}: {error}");
    }
    let error = load(":0 {\n\trate_limit /api/* {\n\t}\n\trespond ok\n}\n", None)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(error.contains("takes no arguments"), "{error}");
}
