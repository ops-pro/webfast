//! `respond`: the body and its type, for a text made once (no placeholders) and one filled in
//! per request (src/handler.rs `RespondBody`).

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::path::Path;
use std::time::Duration;
use webfast_core::server;

#[tokio::test]
async fn respond_types_its_text_whether_made_once_or_per_request() {
    let text = ":0 {
	handle /static-json {
		respond `{\"a\": [1, 2]}` 201
	}
	handle /dynamic-json {
		respond `{\"path\": \"{path}\"}`
	}
	handle /static-text {
		respond \"plain [not json\"
	}
	handle /dynamic-text {
		respond \"at {path}\"
	}
	handle /typed {
		header Content-Type text/html
		respond \"<p>{path}</p>\"
	}
	handle /empty {
		respond 204
	}
}
";
    let file = webfast_core::caddyfile::parse_str(text, Path::new("Caddyfile")).unwrap();
    let running = server::start(webfast_core::load_parsed(&file, 1 << 24).unwrap())
        .await
        .unwrap();
    let port = running.bound[0].1.port();
    let client: Client<HttpConnector, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let cases = [
        ("/static-json", 201, "application/json", r#"{"a": [1, 2]}"#),
        ("/dynamic-json", 200, "application/json", r#"{"path": "/dynamic-json"}"#),
        ("/static-text", 200, "text/plain; charset=utf-8", "plain [not json"),
        ("/dynamic-text", 200, "text/plain; charset=utf-8", "at /dynamic-text"),
        ("/typed", 200, "text/html", "<p>/typed</p>"),
        ("/empty", 204, "", ""),
    ];
    // Twice: the text made once is the same on every request.
    for _ in 0..2 {
        for (path, status, content_type, body) in cases {
            let request = Request::get(format!("http://127.0.0.1:{port}{path}"))
                .body(Empty::new())
                .unwrap();
            let response = client.request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::from_u16(status).unwrap(), "{path}");
            let got_type = response
                .headers()
                .get("content-type")
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default();
            assert_eq!(got_type, content_type, "{path}");
            let got = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&got[..], body.as_bytes(), "{path}");
        }
    }
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn a_site_that_answers_every_request_alike_answers_ready_as_the_chain_does() {
    // The same routes, ready and through the chain (a matcher that takes every request keeps the
    // routes from being prepared, and changes nothing else).
    let routes = "\theader X-Fixed one\n\theader -Server\n\theader +X-Many a\n\theader +X-Many b\n\trespond `{\"ok\": true}` 202\n";
    let ready = format!("http://ready.test:0 {{\n{routes}}}\n");
    let chain = format!(
        "http://chain.test:0 {{\n\t@all path *\n\theader @all X-Fixed one\n{}}}\n",
        routes.replacen("\theader X-Fixed one\n", "", 1)
    );
    let load = |text: &str| {
        let file = webfast_core::caddyfile::parse_str(text, Path::new("Caddyfile")).unwrap();
        webfast_core::load_parsed(&file, 1 << 24).unwrap()
    };
    let config = load(&ready);
    let prepared = webfast_core::memo::Answers::prepare(&config.servers[0].sites[0].routes, false).expect("ready");
    assert_eq!(
        (prepared.answers(), prepared.paths()),
        (1, 0),
        "one answer for every path"
    );
    assert!(
        webfast_core::memo::Answers::prepare(&load(&chain).servers[0].sites[0].routes, false)
            .is_none_or(|a| a.answers() == 0),
        "behind a matcher: not prepared"
    );
    let ready = server::start(config).await.unwrap();
    let chain = server::start(load(&chain)).await.unwrap();
    let client: Client<HttpConnector, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let answer = |running: &server::Running, method: &'static str, path: &'static str| {
        let port = running.bound[0].1.port();
        let host = if std::ptr::eq(running, &ready) {
            "ready.test"
        } else {
            "chain.test"
        };
        let client = client.clone();
        async move {
            let request = Request::builder()
                .method(method)
                .uri(format!("http://127.0.0.1:{port}{path}"))
                .header("host", host)
                .header("accept-encoding", "gzip")
                .body(Empty::new())
                .unwrap();
            let response = client.request(request).await.unwrap();
            let status = response.status();
            let mut headers = response.headers().clone();
            headers.remove("date");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            (status, headers, body)
        }
    };
    for (method, path) in [
        ("GET", "/"),
        ("GET", "/a/b?c=d"),
        ("HEAD", "/x"),
        ("POST", "/form"),
        ("DELETE", "/"),
    ] {
        let got = answer(&ready, method, path).await;
        assert_eq!(got, answer(&chain, method, path).await, "{method} {path}");
        assert_eq!(got.0, StatusCode::ACCEPTED);
        assert_eq!(got.1.get("x-fixed").unwrap(), "one");
        assert_eq!(got.1.get_all("x-many").iter().count(), 2);
        assert_eq!(got.1.get("content-type").unwrap(), "application/json");
    }
    ready.shutdown(Duration::from_secs(1)).await;
    chain.shutdown(Duration::from_secs(1)).await;
}
