//! The binary's composition (src/compose.rs) end to end: a server booted by the core's harness with
//! the modules as this crate composes them. The browser challenge answers a `challenge` directive
//! with its page; the request filter, loaded as WEB_NGFW_CONFIG would load it, refuses a scanner.
//! The modules' own tests are in webfast-modules; this one shows that the wiring holds.

#![cfg(any(feature = "ngfw", feature = "challenge"))]

use http::StatusCode;
use webfast_core::harness;

const CADDYFILE: &str = r#"{
	auto_https off
	admin off
}

:0 {
	handle /guarded/* {
		challenge
		respond "ok guarded"
	}
	respond "ok"
}
"#;

const BROWSER: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36";

#[tokio::test]
async fn the_composed_modules_answer() {
    let dir = tempfile::tempdir().unwrap();
    let server = harness::start(webfast::compose::composition(), CADDYFILE, |config| {
        let _ = (&dir, &config);
        #[cfg(feature = "ngfw")]
        {
            let ngfw = webfast_ngfw::Ngfw::load_str("mode: block\nlog: { output: discard }\n", dir.path())
                .expect("the filter loads");
            config.modules.insert(std::sync::Arc::new(ngfw));
        }
    })
    .await;

    let plain = server
        .get("/", &[("user-agent", BROWSER), ("accept", "text/html")])
        .await;
    assert_eq!(plain.status, StatusCode::OK);
    assert_eq!(plain.text(), "ok");

    #[cfg(feature = "challenge")]
    {
        let asked = server
            .get("/guarded/page", &[("user-agent", BROWSER), ("accept", "text/html")])
            .await;
        assert_eq!(asked.status, StatusCode::SERVICE_UNAVAILABLE, "the challenge page");
        assert!(asked.text().contains("data-nonce=\""), "a nonce on the page");
        let endpoint = server
            .send(
                "POST",
                "/.well-known/c-wf",
                &[("content-type", "application/x-www-form-urlencoded")],
                b"nonce=x&answer=y",
            )
            .await;
        assert!(
            matches!(endpoint.status, StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN),
            "the endpoint is served and rejects a bad nonce: {}",
            endpoint.status
        );
    }

    #[cfg(feature = "ngfw")]
    {
        let scanner = server
            .get("/", &[("user-agent", "sqlmap/1.7.2#stable (https://sqlmap.org)")])
            .await;
        assert_eq!(scanner.status, StatusCode::FORBIDDEN, "the filter refuses a scanner");
    }

    server.shutdown().await;
}
