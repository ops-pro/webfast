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
use webfast::server;

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
    let file = webfast::caddyfile::parse_str(text, Path::new("Caddyfile")).unwrap();
    let running = server::start(webfast::load_parsed(&file, 1 << 24).unwrap())
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
